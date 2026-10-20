"""A challenge answered keeps the route of the first request: an https URL
behind a CONNECT proxy is answered over the same tunnel and TLS, a ``-p``
request over a CONNECT to its origin. A 407 is answered with the proxy
credential only when the proxy sent it: never an origin's, reached directly
or through a tunnel.

A CONNECT proxy on 127.0.0.1 records what it relayed, so a request that left
the tunnel's TLS (or the CONNECT's target) shows in what it saw.
"""

import base64
import re
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from test_curl_challenge import _Server
from test_curl_options import pki  # noqa: F401  (fixture reused)
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)

DIGEST = 'Digest realm="r", nonce="n0nce", qop="auth"'
BASIC = 'Basic realm="r"'
PROXY_CREDENTIAL = "Basic " + base64.b64encode(b"puser:ppass").decode()


def _read_head(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        data += chunk
    return data


class ConnectProxy:
    """A proxy that relays each CONNECT to the target it names. ``credential``
    is the ``Proxy-Authorization`` a CONNECT must carry (else 407). ``heads``
    are the request heads it received; ``tunnels`` one record per relayed
    CONNECT, ``sent`` the bytes the client sent through it."""

    def __init__(self, credential=None):
        self.credential = credential
        self.heads = []
        self.tunnels = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.url = "http://127.0.0.1:%d" % self.port
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self.listener.close()

    def _accept(self):
        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        client.settimeout(10)
        try:
            while True:
                head = _read_head(client)
                if head is None:
                    return
                text = head.decode("latin-1")
                self.heads.append(text)
                if not text.startswith("CONNECT "):
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return
                if self.credential and "Proxy-Authorization: %s" % self.credential not in text:
                    client.sendall(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                        b'Proxy-Authenticate: Basic realm="p"\r\nContent-Length: 0\r\n\r\n'
                    )
                    continue
                self._relay(client, text.split()[1])
                return
        except OSError:
            pass
        finally:
            client.close()

    def _relay(self, client, target):
        host, _, port = target.rpartition(":")
        upstream = socket.create_connection((host, int(port)), timeout=10)
        tunnel = {"target": target, "sent": bytearray()}
        self.tunnels.append(tunnel)
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        def back():
            try:
                while True:
                    data = upstream.recv(65536)
                    if not data:
                        break
                    client.sendall(data)
            except OSError:
                pass

        threading.Thread(target=back, daemon=True).start()
        try:
            while True:
                data = client.recv(65536)
                if not data:
                    break
                tunnel["sent"] += data
                upstream.sendall(data)
        except OSError:
            pass
        finally:
            upstream.close()


class _TLSServer(HTTPServer):
    def __init__(self, address, handler, context):
        HTTPServer.__init__(self, address, handler)
        self.context = context

    def get_request(self):
        request, address = HTTPServer.get_request(self)
        request.settimeout(5)
        return self.context.wrap_socket(request, server_side=True), address

    def handle_error(self, request, client_address):
        pass


class _Origin(_Server):
    """The 401 origin of test_curl_challenge, recording the cookie and the
    custom header of every request."""

    seen = []

    def do_GET(self):
        _Origin.seen.append((self.headers.get("Cookie"), self.headers.get("X-Secret")))
        _Server.do_GET(self)


class _Origin407(BaseHTTPRequestHandler):
    """An origin that answers 407 with a proxy challenge, recording the
    ``Proxy-Authorization`` it was sent."""

    seen = []
    offer = BASIC

    def do_GET(self):
        _Origin407.seen.append(self.headers.get("Proxy-Authorization"))
        self.send_response(407)
        self.send_header("Proxy-Authenticate", _Origin407.offer)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _stop(server):
    server.shutdown()
    server.server_close()


@pytest.fixture()
def tls_context(pki):  # noqa: F811
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pki / "server.pem"), str(pki / "server.key"))
    return context


@pytest.fixture()
def connect_proxy():
    made = []

    def make(credential=None):
        made.append(ConnectProxy(credential))
        return made[-1]

    yield make
    for proxy in made:
        proxy.close()


@pytest.fixture()
def tls_origin(tls_context):
    """An https origin on 127.0.0.1 answering 401 (``_Server.offer``)."""
    _Server.requests, _Origin.seen = [], []
    server = _serve(_TLSServer(("127.0.0.1", 0), _Origin, tls_context))
    yield server.server_address[1]
    _stop(server)


@pytest.fixture()
def plain_origin():
    _Server.requests, _Origin.seen = [], []
    server = _serve(HTTPServer(("127.0.0.1", 0), _Origin))
    yield server.server_address[1]
    _stop(server)


def _connects(proxy):
    return [head.split("\r\n")[0] for head in proxy.heads]


def _assert_nothing_in_the_clear(proxy, *secrets):
    for tunnel in proxy.tunnels:
        for secret in secrets:
            assert secret not in tunnel["sent"], (secret, bytes(tunnel["sent"][:200]))


@pytest.mark.parametrize(
    "flags, offer",
    [
        (["--digest"], DIGEST),
        (["--anyauth"], DIGEST),
        (["--anyauth"], BASIC),
    ],
    ids=["digest", "anyauth-digest", "anyauth-basic"],
)
def test_a_401_for_an_https_url_is_answered_inside_the_same_tunnel_and_tls(
    flags, offer, tls_origin, connect_proxy, pki, monkeypatch, capsysbinary  # noqa: F811
):
    _Server.offer = [offer]
    proxy = connect_proxy()
    argv = ["-sS", "--cacert", str(pki / "ca.pem"), "-x", proxy.url, *flags, "-u", "me:pw"]
    argv += ["-b", "sid=SESSION1", "-H", "X-Secret: HEADER1", "https://127.0.0.1:%d/secret" % tls_origin]
    rc, out = _fallback(monkeypatch, capsysbinary, argv)
    assert rc == 0 and out.out == b"welcome", out.err
    assert _connects(proxy) == ["CONNECT 127.0.0.1:%d HTTP/1.1" % tls_origin] * 2, "both are CONNECTs to the origin"
    assert [bytes(t["sent"][:1]) for t in proxy.tunnels] == [b"\x16"] * 2, "both carry a TLS handshake"
    _assert_nothing_in_the_clear(proxy, b"SESSION1", b"HEADER1", b"Authorization", b"me:pw", b"bWU6cHc=")
    assert _Server.requests[0] is None and _Server.requests[1], "the answer carries the credential"
    assert _Origin.seen == [("sid=SESSION1", "HEADER1")] * 2, "inside TLS, the origin gets both requests whole"


@pytest.mark.parametrize(
    "flags, offer", [(["--digest"], DIGEST), (["--anyauth"], BASIC)], ids=["digest", "anyauth-basic"]
)
def test_p_answers_a_401_over_a_connect_to_the_origin(
    flags, offer, plain_origin, connect_proxy, monkeypatch, capsysbinary
):
    _Server.offer = [offer]
    proxy = connect_proxy()
    argv = ["-sS", "-p", "-x", proxy.url, *flags, "-u", "me:pw", "http://127.0.0.1:%d/secret" % plain_origin]
    rc, out = _fallback(monkeypatch, capsysbinary, argv)
    assert rc == 0 and out.out == b"welcome", out.err
    assert _connects(proxy) == ["CONNECT 127.0.0.1:%d HTTP/1.1" % plain_origin] * 2, "never the proxy's own address"
    assert len(proxy.tunnels) == 2 and _Server.requests[0] is None and _Server.requests[1]
    _assert_nothing_in_the_clear(proxy, b"Proxy-Authorization")


def test_a_407_then_a_401_each_connection_is_a_connect_to_the_origin_and_tls(
    tls_origin, connect_proxy, pki, monkeypatch, capsysbinary  # noqa: F811
):
    _Server.offer = [BASIC]
    proxy = connect_proxy(PROXY_CREDENTIAL)
    argv = ["-sS", "--cacert", str(pki / "ca.pem"), "-x", "http://puser:ppass@127.0.0.1:%d" % proxy.port]
    argv += ["--proxy-anyauth", "--anyauth", "-u", "me:pw", "https://127.0.0.1:%d/secret" % tls_origin]
    rc, out = _fallback(monkeypatch, capsysbinary, argv)
    assert rc == 0 and out.out == b"welcome", out.err
    assert _connects(proxy) == ["CONNECT 127.0.0.1:%d HTTP/1.1" % tls_origin] * 4
    answered = ["Proxy-Authorization: " in head for head in proxy.heads]
    assert answered == [False, True, False, True], "each new connection meets the proxy's 407 and answers it"
    assert not [head for head in proxy.heads if re.search(r"(?im)^Authorization:", head)], "the origin's, never"
    assert [bytes(t["sent"][:1]) for t in proxy.tunnels] == [b"\x16"] * 2
    _assert_nothing_in_the_clear(proxy, b"Authorization", b"cHVzZXI6cHBhc3M=", b"bWU6cHc=")
    assert _Server.requests[0] is None and _Server.requests[1]


# --------------------------------------------------------------------------- #
# the proxy credential goes to the proxy only
# --------------------------------------------------------------------------- #


@pytest.fixture()
def origin407():
    _Origin407.seen = []
    server = _serve(HTTPServer(("127.0.0.1", 0), _Origin407))
    yield server.server_address[1]
    _stop(server)


def _status(monkeypatch, capsysbinary, argv):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-o", "/dev/null", "-w", "%{http_code}"] + argv)
    return rc, out.out


@pytest.mark.parametrize(
    "flag, offer", [("--proxy-anyauth", BASIC), ("--proxy-digest", DIGEST)], ids=["anyauth-basic", "digest"]
)
@pytest.mark.parametrize("bypass", ["--noproxy", "NO_PROXY"])
def test_an_origin_reached_directly_gets_no_proxy_credential(flag, offer, bypass, origin407, monkeypatch, capsysbinary):
    _Origin407.offer = offer
    argv = ["-x", "http://puser:ppass@127.0.0.1:9", flag]
    if bypass == "--noproxy":
        argv += ["--noproxy", "127.0.0.1"]
    else:
        monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    rc, status = _status(monkeypatch, capsysbinary, argv + ["http://127.0.0.1:%d/x" % origin407])
    assert (rc, status) == (0, b"407"), "the origin's 407 is the response"
    assert _Origin407.seen == [None], "one request, and no Proxy-Authorization"


def test_a_redirect_hop_that_bypasses_the_proxy_gets_no_proxy_credential(origin407, monkeypatch, capsysbinary):
    class _Redirect(BaseHTTPRequestHandler):
        seen = []

        def do_GET(self):
            _Redirect.seen.append(self.path)
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:%d/x" % origin407)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    proxy = _serve(HTTPServer(("127.0.0.1", 0), _Redirect))
    try:
        argv = ["-L", "-x", "http://puser:ppass@127.0.0.1:%d" % proxy.server_address[1], "--proxy-anyauth"]
        rc, status = _status(monkeypatch, capsysbinary, argv + ["--noproxy", "127.0.0.1", "http://a.test/start"])
    finally:
        _stop(proxy)
    assert (rc, status) == (0, b"407") and _Redirect.seen == ["http://a.test/start"]
    assert _Origin407.seen == [None]


@pytest.mark.parametrize("tls", [False, True], ids=["p", "https"])
def test_an_origin_inside_a_tunnel_gets_no_proxy_credential(
    tls, connect_proxy, tls_context, pki, monkeypatch, capsysbinary  # noqa: F811
):
    _Origin407.seen, _Origin407.offer = [], BASIC
    if tls:
        server = _serve(_TLSServer(("127.0.0.1", 0), _Origin407, tls_context))
    else:
        server = _serve(HTTPServer(("127.0.0.1", 0), _Origin407))
    proxy = connect_proxy()
    port = server.server_address[1]
    argv = ["--cacert", str(pki / "ca.pem"), "-x", "http://puser:ppass@127.0.0.1:%d" % proxy.port, "--proxy-anyauth"]
    try:
        rc, status = _status(
            monkeypatch,
            capsysbinary,
            argv + (["https://127.0.0.1:%d/x" % port] if tls else ["-p", "http://127.0.0.1:%d/x" % port]),
        )
    finally:
        _stop(server)
    assert (rc, status) == (0, b"407"), "the origin's 407 is the response"
    assert _Origin407.seen == [None] and len(proxy.tunnels) == 1
    _assert_nothing_in_the_clear(proxy, b"Proxy-Authorization")


def test_the_proxys_own_407_is_still_answered(monkeypatch, capsysbinary):
    class _Plain(BaseHTTPRequestHandler):
        seen = []

        def do_GET(self):
            _Plain.seen.append(self.headers.get("Proxy-Authorization"))
            if self.headers.get("Proxy-Authorization") == PROXY_CREDENTIAL:
                body = b"via-proxy"
                self.send_response(200)
            else:
                body = b""
                self.send_response(407)
                self.send_header("Proxy-Authenticate", BASIC)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    proxy = _serve(HTTPServer(("127.0.0.1", 0), _Plain))
    try:
        argv = ["-s", "-x", "http://puser:ppass@127.0.0.1:%d" % proxy.server_address[1], "--proxy-anyauth"]
        rc, out = _fallback(monkeypatch, capsysbinary, argv + ["http://a.test/x"])
    finally:
        _stop(proxy)
    assert rc == 0 and out.out == b"via-proxy" and _Plain.seen == [None, PROXY_CREDENTIAL]
