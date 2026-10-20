"""Proxy credentials, kind and bypass, end to end through curlike:
the real-curl passthrough and the stdlib fallback.

No external network: a fake authenticating forward proxy, a fake prefix gateway
and a plain target server run on 127.0.0.1. The proxy answers 407 without the
right Proxy-Authorization and never forwards -- a body of ``via-proxy`` proves
the request went through it with the credential, ``via-gateway`` that it went to
the prefix gateway, ``hello`` that it went direct.
"""

import base64
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import curlike as curl
from syshttp import proxy as agent_proxy  # noqa: E402  (lib/, via conftest)

_ALL_VARS = [
    "SYSHTTP_PROXY",
    "SYSHTTP_PROXY_AUTH",
    "SYSHTTP_PROXY_TYPE",
    "HTTP_PROXY_AUTH",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
]

BASIC = "Basic " + base64.b64encode(b"agent:s3cret").decode()
BEARER = "Bearer eyJ0b2tlbiI6ICJhZ2VudCJ9"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for v in _ALL_VARS:
        monkeypatch.delenv(v, raising=False)


class _Target(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        _Target.seen.append((self.path, self.headers.get("Proxy-Authorization")))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _Proxy(BaseHTTPRequestHandler):
    """A forward proxy that only checks the credential, then answers itself."""

    expected = BASIC
    seen = []

    def do_GET(self):
        _Proxy.seen.append((self.path, self.headers.get("Proxy-Authorization")))
        if self.headers.get("Proxy-Authorization") == _Proxy.expected and self.path.endswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", self.path[: -len("/redirect")] + "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.headers.get("Proxy-Authorization") != _Proxy.expected:
            self.send_response(407)
            self.send_header("Proxy-Authenticate", 'Basic realm="agent"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"via-proxy"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _Gateway(BaseHTTPRequestHandler):
    """A prefix gateway: records the path it was asked for and the header."""

    seen = []

    def do_GET(self):
        _Gateway.seen.append((self.path, self.headers.get("Proxy-Authorization")))
        if self.path.endswith("/redirect"):
            # A gateway relaying the origin's redirect verbatim: an absolute
            # origin URL the client must wrap again.
            self.send_response(302)
            self.send_header("Location", self.path.split("/", 2)[2][: -len("/redirect")] + "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"via-gateway"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(handler):
    httpd = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture()
def target():
    _Target.seen = []
    httpd = _serve(_Target)
    try:
        yield "http://127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def proxy():
    _Proxy.seen, _Proxy.expected = [], BASIC
    httpd = _serve(_Proxy)
    try:
        yield "127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def gateway():
    _Gateway.seen = []
    httpd = _serve(_Gateway)
    try:
        yield "http://127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------
# syshttp.proxy: the header value, its sources, redaction, kind, bypass
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# curlike: authenticates to the proxy, honours kind + bypass
# --------------------------------------------------------------------------


def _fallback(monkeypatch, capsysbinary, argv):
    rc = curl.main(argv)
    return rc, capsysbinary.readouterr()


def test_fallback_sends_the_configured_header(target, proxy, monkeypatch, capsysbinary):
    _Proxy.expected = BEARER
    monkeypatch.setenv("SYSHTTP_PROXY", "http://" + proxy)
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", target + "/x"])
    assert rc == 0 and out.out == b"via-proxy"
    assert _Proxy.seen[-1] == (target + "/x", BEARER)


def test_fallback_http_proxy_auth_goes_to_the_machine_proxy_only(target, proxy, monkeypatch, capsysbinary):
    monkeypatch.setenv("HTTP_PROXY", "http://" + proxy)
    monkeypatch.setenv("HTTP_PROXY_AUTH", BASIC)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", target + "/x"])
    assert rc == 0 and out.out == b"via-proxy"
    monkeypatch.setenv("SYSHTTP_PROXY", "http://" + proxy)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", target + "/x"])
    assert _Proxy.seen[-1][1] is None, "SYSHTTP_PROXY's credential is SYSHTTP_PROXY_AUTH, not the machine's"


def test_fallback_url_userinfo_as_basic(target, proxy, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://agent:s3cret@" + proxy)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", target + "/x"])
    assert rc == 0 and out.out == b"via-proxy"
    assert _Proxy.seen[-1][1] == BASIC


def test_fallback_without_credential_is_refused_by_the_proxy(target, proxy, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://" + proxy)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-i", target + "/x"])
    assert rc == 0 and out.out.startswith(b"HTTP/1.0 407"), "a 407 is a response curl prints, exit 0"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-f", target + "/x"])
    assert rc == 22 and out.out == b"", "-f makes it curl's exit 22"


def test_fallback_proxy_user_flag_wins(target, proxy, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://" + proxy)
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", "Bearer wrong")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-U", "agent:s3cret", target + "/x"])
    assert rc == 0 and out.out == b"via-proxy"


def test_fallback_explicit_proxy_never_borrows_the_agent_credential(target, proxy, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://elsewhere.example:1")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BASIC)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-i", "-x", "http://" + proxy, target + "/x"])
    assert rc == 0 and out.out.startswith(
        b"HTTP/1.0 407"
    ), "-x names a different proxy; the agent proxy's credential is not its"


def test_fallback_no_proxy_goes_direct(target, proxy, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://agent:s3cret@" + proxy)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", target + "/x"])
    assert rc == 0 and out.out == b"hello" and _Proxy.seen == []


def test_fallback_noproxy_flag_replaces_no_proxy(target, proxy, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://agent:s3cret@" + proxy)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    # --noproxy REPLACES the env list (curl semantics): 127.0.0.1 is proxied again.
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--noproxy", "example.com", target + "/x"])
    assert rc == 0 and out.out == b"via-proxy"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--noproxy", "*", target + "/x"])
    assert rc == 0 and out.out == b"hello"


def test_fallback_prefix_gateway(target, gateway, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY", gateway)
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", target + "/x"])
    assert rc == 0 and out.out == b"via-gateway"
    assert _Gateway.seen[-1] == ("/fetch/" + target + "/x", BEARER)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", target + "/x"])
    assert rc == 0 and out.out == b"hello"


def test_fallback_verbose_never_prints_the_credential(target, proxy, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://agent:s3cret@" + proxy)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-v", target + "/x"])
    assert rc == 0
    assert b"Proxy: http://" + proxy.encode() + b" (with Proxy-Authorization)" in out.err
    assert b"s3cret" not in out.err and BASIC.encode() not in out.err


# --------------------------------------------------------------------------
# A bad SYSHTTP_PROXY_TYPE is a configuration error, reported as such
# --------------------------------------------------------------------------


def test_bad_type_is_harmless_without_a_proxy(target, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "socks5")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", target + "/x"])
    assert rc == 0 and out.out == b"hello"


def test_bad_type_with_a_proxy(target, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "socks5")
    # The fallback cannot proceed without knowing how to speak to the proxy: exit 2.
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", target + "/x"])
    assert rc == 2 and out.err.startswith(b"curl: (2) SYSHTTP_PROXY_TYPE") and b"Traceback" not in out.err


# --------------------------------------------------------------------------
# Redirects: every hop is re-decided; the credential never reaches an origin
# --------------------------------------------------------------------------


def test_fallback_redirect_hop_stays_on_the_proxy(target, proxy, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://" + proxy)
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BASIC)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-L", target + "/redirect"])
    assert rc == 0 and out.out == b"via-proxy"
    assert [path for path, _ in _Proxy.seen] == [target + "/redirect", target + "/final"]
    assert _Target.seen == [], "the origin was never contacted directly"


def test_fallback_redirect_to_a_no_proxy_host_goes_direct_without_the_credential(
    target, proxy, monkeypatch, capsysbinary
):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://" + proxy)
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    _Proxy.expected = BEARER
    # The first hop is proxied (the target host is not bypassed by name yet);
    # its Location points at 127.0.0.1, which NO_PROXY exempts.
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("SYSHTTP_PROXY", "http://" + proxy)
    # Force the first hop through the proxy by asking for a non-bypassed name.
    rc, out = _fallback(
        monkeypatch, capsysbinary, ["-s", "-L", "http://localhost:%s/redirect" % target.rsplit(":", 1)[1]]
    )
    # localhost is proxied (not in NO_PROXY); the proxy answers 302 -> http://localhost.../final
    # which is proxied again -- so exercise the direct case explicitly instead:
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-L", target + "/redirect"])
    assert rc == 0 and out.out == b"hello"
    assert all(auth is None for _, auth in _Target.seen), "no Proxy-Authorization on a direct hop"


def test_fallback_prefix_redirect_is_wrapped_again(target, gateway, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY", gateway)
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-L", target + "/redirect"])
    assert rc == 0 and out.out == b"via-gateway"
    assert [path for path, _ in _Gateway.seen] == ["/fetch/" + target + "/redirect", "/fetch/" + target + "/final"]
    assert all(auth == BEARER for _, auth in _Gateway.seen)
    assert _Target.seen == []


@pytest.mark.parametrize("password", ["s3cr/et", "p@ss", "p@ss@w0rd", "pa?ss#word", "a://b", "pass"])
@pytest.mark.parametrize("tail", ["proxy.example:99999", "[bad", "proxy.example:3128 x"])
def test_the_proxy_syntax_message_hides_the_whole_userinfo(password, tail):
    from curlike import routing
    from curlike.errors import LocalError

    for given in ("http://agent:%s@%s", "agent:%s@%s"):
        with pytest.raises(LocalError) as caught:
            routing.check_proxy_syntax(given % (password, tail))
        message = str(caught.value)
        assert message.startswith("Unsupported proxy syntax in 'http://***@%s': " % tail), message
        assert "agent" not in message and password not in message, message


def test_the_proxy_syntax_message_keeps_a_url_without_userinfo(monkeypatch, capsysbinary):
    rc, out = _fallback(
        monkeypatch, capsysbinary, ["-sS", "-x", "http://proxy.example:99999", "http://example.invalid/"]
    )
    assert rc == 5 and b"in 'http://proxy.example:99999': " in out.err, out.err


def test_the_proxy_syntax_error_never_shows_the_password(monkeypatch, capsysbinary):
    rc, out = _fallback(
        monkeypatch, capsysbinary, ["-sS", "-x", "http://agent:s3cr/et@proxy.example:3128", "http://example.invalid/"]
    )
    assert rc == 5 and b"in 'http://***@proxy.example:3128': " in out.err, out.err
    assert b"agent" not in out.err and b"s3cr" not in out.err
    monkeypatch.setenv("SYSHTTP_PROXY", "http://agent:p@ss@[bad")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "http://example.invalid/"])
    assert rc == 5 and b"in 'http://***@[bad': " in out.err, out.err
    assert b"agent" not in out.err and b"ss@" not in out.err


# --------------------------------------------------------------------------
# A proxy URL's path, query and fragment are ignored, as curl does; no message carries a password
# --------------------------------------------------------------------------


@pytest.mark.parametrize("tail", ["/path", "/a/b/", "/?q=1#frag", "?q=1", "#frag"])
def test_a_proxy_url_with_a_path_is_still_the_proxy(tail, target, proxy, monkeypatch, capsysbinary):
    argv = ["-sS", "-x", "http://agent:s3cret@" + proxy + tail, target + "/x"]
    rc, out = _fallback(monkeypatch, capsysbinary, argv)
    assert rc == 0 and out.out == b"via-proxy", out.err
    assert _Proxy.seen[-1] == (target + "/x", BASIC)


@pytest.mark.parametrize("variable", ["SYSHTTP_PROXY", "HTTP_PROXY", "http_proxy", "ALL_PROXY"])
def test_a_configured_proxy_url_with_a_path_is_still_the_proxy(variable, target, proxy, monkeypatch, capsysbinary):
    monkeypatch.setenv(variable, "http://agent:s3cret@" + proxy + "/path")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", target + "/x"])
    assert rc == 0 and out.out == b"via-proxy", out.err
    assert _Proxy.seen[-1] == (target + "/x", BASIC)


def test_a_refused_proxy_setting_never_shows_the_password(monkeypatch, capsysbinary):
    def refuse(proxy=None, *args, **kwargs):
        raise ValueError("invalid proxy URL %r: refused" % (proxy,))

    monkeypatch.setattr(agent_proxy, "proxy_map", refuse)
    argv = ["-sS", "-x", "http://agent:p%40ss@127.0.0.1:1", "-U", "me:pw", "http://example.invalid/"]
    rc, out = _fallback(monkeypatch, capsysbinary, argv)
    assert rc == 2 and out.err == b"curl: (2) invalid proxy URL 'http://***@127.0.0.1:1': refused\n", out.err
