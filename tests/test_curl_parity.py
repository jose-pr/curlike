"""The fallback against the real curl: the same command line, the same fake
servers, compared on what a caller sees -- the exit code, the ``curl: (N)``
error code and stdout (``-w`` included).

Both sides run through the shim, ``python -m curlike``, as a subprocess:
with the real curl's directory on PATH it passes the command through (adding
the configured proxy), with an empty PATH it serves it itself. Skipped when no real curl is
installed. The servers are raw sockets on 127.0.0.1, so each failure is
exact: a reply cut short, a reset, a proxy refusing or dropping the CONNECT.

Where curl versions disagree, the fallback answers as the version
``HTTPLIB_CURL_COMPAT`` names (``curlike.compat``): the comparison sets it to
the real curl's own version, so every scenario is exact for any curl.
"""

import base64
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from curlike import shim as curl
from fake_socks import FakeSocks  # noqa: E402  (tests/)
from test_curl_options import _openssl, pki  # noqa: F401  (fixture reused)

REAL_CURL = curl.find_real_curl()
pytestmark = pytest.mark.skipif(not REAL_CURL, reason="no real curl to compare the fallback with")

BASIC = "Basic " + base64.b64encode(b"agent:s3cret").decode()
_PROXY_VARS = re.compile(r"(?i)(.*_proxy|agents_proxy.*|no_proxy|curl_ca_bundle|net_.*)$")


# --------------------------------------------------------------------------- #
# Raw servers: each handler gets the connection and the request head.
# --------------------------------------------------------------------------- #
def _read_head(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            break
        buf += chunk
    return buf


def _header(head, name):
    m = re.search(rb"(?im)^" + name.encode() + rb":\s*(.*?)\r$", head)
    return m.group(1).decode() if m else None


def _respond(conn, status, body=b"", extra=()):
    head = "HTTP/1.1 %s\r\nContent-Length: %d\r\n%s\r\n" % (status, len(body), "".join(h + "\r\n" for h in extra))
    conn.sendall(head.encode() + body)


def _reset(conn):
    """Close with a TCP RST rather than a FIN."""
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")


def _origin(conn, head):
    path = head.split(b" ")[1] if b" " in head else b"/"
    if path.endswith(b"/to-http"):
        port = conn.getsockname()[1]
        return _respond(conn, "302 Found", extra=["Location: http://127.0.0.1:%d/landed" % port])
    if _header(head, "Proxy-Authorization") or _header(head, "X-Proxy-Token"):
        return _respond(conn, "200 OK", b"leaked")  # a proxy credential reached the origin
    if path.endswith(b"/404"):
        return _respond(conn, "404 Not Found", b"nope")
    if path.endswith(b"/500"):
        return _respond(conn, "500 Internal Server Error", b"boom")
    if path.endswith(b"/loop"):
        return _respond(conn, "302 Found", extra=["Location: /loop"])
    _respond(conn, "200 OK", b"hello")


def _empty(conn, head):
    pass


def _truncated(conn, head):
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello")


def _not_http(conn, head):
    conn.sendall(b"garbage here\r\n\r\n")


def _bad_status(conn, head):
    conn.sendall(b"HTTP/1.1 abc OK\r\nContent-Length: 2\r\n\r\nok")


def _reset_mid_body(conn, head):
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhel")
    time.sleep(0.2)
    _reset(conn)


def _reset_at_once(conn, head):
    _reset(conn)


def _bad_chunk(conn, head):
    conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n")


def _chunks_cut(conn, head):
    conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")


def _plain_at_once(conn, head):
    """Speaks HTTP the moment a client connects, whatever it sends (a TLS
    ClientHello included)."""
    conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    time.sleep(0.5)


_plain_at_once.eager = True


def _echo(conn, head):
    """Answers with what it was asked: the request line, Host, Authorization
    and the client's address -- a 401 first for /auth without credentials."""
    lines = head.split(b"\r\n")
    # Read the whole body: closing with unread data is a reset, not an answer.
    pending = int(_header(head, "Content-Length") or 0) - (len(head) - head.find(b"\r\n\r\n") - 4)
    while pending > 0:
        chunk = conn.recv(min(pending, 65536))
        if not chunk:
            break
        pending -= len(chunk)
    if b"/auth" in lines[0] and not _header(head, "Authorization"):
        return _respond(conn, "401 Unauthorized", b"", ['WWW-Authenticate: Basic realm="x"'])
    peer = conn.getpeername()
    body = b"%s|host=%s|auth=%s|from=%s:%d|x=%s" % (
        lines[0],
        (_header(head, "Host") or "").encode(),
        (_header(head, "Authorization") or "").encode(),
        peer[0].encode(),
        _port_note(peer[1]) if b"/port" in lines[0] else 0,
        _x_headers(head),
    )
    if _header(head, "Cookie"):
        body += b"|cookie=" + _header(head, "Cookie").encode()
    _respond(conn, "200 OK", body)


def _port_note(port):
    """1 for a client port inside the --local-port scenario's range: which one
    is free differs between two runs back to back (TIME_WAIT)."""
    return 1 if 47310 <= port <= 47330 else port


def _x_headers(head):
    """The ``X-`` headers of a request head, sorted: what a test asked for,
    without the User-Agent and connection headers each curl writes its own way."""
    lines = [line for line in head.split(b"\r\n")[1:] if line.lower().startswith(b"x-")]
    return b",".join(sorted(line.replace(b": ", b":") for line in lines))


def _header_proxy(conn, head):
    """A proxy that shows what it received: for plain proxying, the request's
    X- headers; for a CONNECT followed by plain HTTP (-p), the CONNECT's X-
    headers and the inner request's; a CONNECT followed by TLS is tunnelled
    to the target, so the origin shows what reached it."""
    first = head.split(b"\r\n", 1)[0]
    if not first.startswith(b"CONNECT"):
        return _respond(conn, "200 OK", b"proxy-saw=" + _x_headers(head))
    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    opening = conn.recv(65536)
    if opening[:1] == b"\x16":  # a TLS ClientHello: tunnel it
        host, port = first.split(b" ")[1].decode().rsplit(":", 1)
        upstream = socket.create_connection((host, int(port)), timeout=5)
        upstream.sendall(opening)
        return _pipe(conn, upstream)
    while b"\r\n\r\n" not in opening:
        more = conn.recv(65536)
        if not more:
            break
        opening += more
    _respond(conn, "200 OK", b"connect-saw=" + _x_headers(head) + b"|inner-saw=" + _x_headers(opening))


def _stalls(conn, head):
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
    time.sleep(6)


def _longer_than_said(conn, head):
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nokEXTRA")


def _sixty_k(conn, head):
    _respond(conn, "200 OK", b"z" * 60000)


def _no_colon(conn, head):
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nthis line has no colon\r\n\r\nok")


def _range_ignored(conn, head):
    """Answers every request with the whole body, Range or not."""
    _respond(conn, "200 OK", b"0123456789")


def _range_416(conn, head):
    _respond(conn, "416 Range Not Satisfiable", extra=["Content-Range: bytes */10"])


def _bad_gzip(conn, head):
    _respond(conn, "200 OK", b"this is not gzip", ["Content-Encoding: gzip"])


def _unknown_encoding(conn, head):
    _respond(conn, "200 OK", b"plain", ["Content-Encoding: x-unknown"])


def _many_headers(conn, head):
    _respond(conn, "200 OK", b"ok", ["X-H%d: %d" % (i, i) for i in range(150)])


def _huge_header(conn, head):
    _respond(conn, "200 OK", b"ok", ["X-Huge: " + "a" * 200000])


def _big_body(conn, head):
    _respond(conn, "200 OK", b"x" * 100)


def _closes_on_upload(conn, head):
    """Reads the head of an upload, then resets: the body cannot be sent."""
    _reset(conn)


def _silent(conn, head):
    time.sleep(4)


def _pipe(a, b):
    def forward(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    back = threading.Thread(target=forward, args=(b, a), daemon=True)
    back.start()
    forward(a, b)
    back.join(5)


def _digest_ok(header, method):
    """Whether ``header`` answers _digest_proxy's challenge (agent / s3cret)."""
    import hashlib

    if not header or not header.lower().startswith("digest "):
        return False
    fields = dict(re.findall(r'(\w+)="?([^",]*)"?', header[7:]))

    def md5(text):
        return hashlib.md5(text.encode()).hexdigest()

    ha1, ha2 = md5("agent:proxy:s3cret"), md5("%s:%s" % (method, fields.get("uri", "")))
    if fields.get("qop"):
        want = md5(
            ":".join([ha1, fields.get("nonce", ""), fields.get("nc", ""), fields.get("cnonce", ""), fields["qop"], ha2])
        )
    else:
        want = md5("%s:%s:%s" % (ha1, fields.get("nonce", ""), ha2))
    return fields.get("username") == "agent" and fields.get("response") == want


def _digest_proxy(offer_basic=False):
    """A proxy that wants Digest (MD5, qop=auth) -- or Basic too, when it
    offers both -- on plain requests and on CONNECT, answering each 407 on the
    same connection; once authenticated it tunnels or answers itself."""

    def handle(conn, head):
        while True:
            first = head.split(b"\r\n", 1)[0].decode()
            method, target = first.split(" ")[:2]
            auth = _header(head, "Proxy-Authorization")
            if _digest_ok(auth, method) or (offer_basic and auth == BASIC):
                break
            challenge = ['Proxy-Authenticate: Digest realm="proxy", nonce="n0nce", qop="auth", algorithm=MD5']
            if offer_basic:
                challenge.append('Proxy-Authenticate: Basic realm="proxy"')
            _respond(conn, "407 Proxy Authentication Required", b"auth", challenge)
            head = _read_head(conn)
            if not head:
                return
        if method == "CONNECT":
            host, port = target.rsplit(":", 1)
            upstream = socket.create_connection((host, int(port)), timeout=5)
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            return _pipe(conn, upstream)
        _respond(conn, "200 OK", b"via-proxy")

    return handle


def _proxy(require=BASIC, connect_status=None, plain_status=None, drop_connect=False, header="Proxy-Authorization"):
    """A forward proxy: ``require`` is the Proxy-Authorization it wants (407
    otherwise) in ``header``; ``connect_status`` answers every CONNECT, ``drop_connect``
    closes on it; a CONNECT it accepts is tunnelled to the target."""

    def handle(conn, head):
        method, target = head.split(b"\r\n", 1)[0].decode().split(" ")[:2]
        auth = _header(head, header)
        if method == "CONNECT":
            if drop_connect:
                return
            if connect_status:
                return _respond(conn, connect_status, b"denied")
            if require and auth != require:
                return _respond(
                    conn, "407 Proxy Authentication Required", b"auth", ['Proxy-Authenticate: Basic realm="x"']
                )
            host, port = target.rsplit(":", 1)
            try:
                upstream = socket.create_connection((host, int(port)), timeout=5)
            except OSError:
                return  # as a proxy that cannot reach the target drops the CONNECT
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            return _pipe(conn, upstream)
        if plain_status:
            return _respond(conn, plain_status, b"proxy-says-no")
        if require and auth != require:
            return _respond(conn, "407 Proxy Authentication Required", b"auth", ['Proxy-Authenticate: Basic realm="x"'])
        _respond(conn, "200 OK", b"via-proxy")

    return handle


class _Servers(object):
    def __init__(self):
        self.sockets = []

    def serve(self, handler, tls=None):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(50)
        self.sockets.append(listener)

        def one(conn):
            try:
                if tls is not None:
                    conn = tls.wrap_socket(conn, server_side=True)
                handler(conn, b"" if getattr(handler, "eager", False) else _read_head(conn))
            except (OSError, ValueError):
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

        def accept():
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                threading.Thread(target=one, args=(conn,), daemon=True).start()

        threading.Thread(target=accept, daemon=True).start()
        return "http://127.0.0.1:%d" % listener.getsockname()[1]

    def close(self):
        for s in self.sockets:
            s.close()


def _revocation_and_pins(certs, tmp):
    """CRLs from the test CA -- one revoking the server's certificate (serial
    2), one revoking nothing -- and the server key as a pin and a file."""
    openssl = _openssl()
    work = tmp / "ca"
    work.mkdir()

    def run(*argv, **kwargs):
        return subprocess.run([openssl, *argv], cwd=str(work), check=True, capture_output=True, **kwargs).stdout

    (work / "ca.cnf").write_text(
        "[ca]\ndefault_ca = d\n[d]\ndatabase = index.txt\ncrlnumber = crlnumber\n"
        "default_md = sha256\ndefault_crl_days = 30\n",
        encoding="ascii",
    )
    out = {}
    for name, index in (
        ("crl_clean", ""),
        ("crl_revoked", "R\t351231000000Z\t260101000000Z\t02\tunknown\t/CN=127.0.0.1\n"),
    ):
        (work / "index.txt").write_text(index, encoding="ascii")
        (work / "crlnumber").write_text("01\n", encoding="ascii")
        run(
            "ca",
            "-gencrl",
            "-config",
            "ca.cnf",
            "-keyfile",
            str(certs / "ca.key"),
            "-cert",
            str(certs / "ca.pem"),
            "-out",
            name + ".pem",
        )
        out[name] = str(work / (name + ".pem"))
    run("x509", "-in", str(certs / "server.pem"), "-pubkey", "-noout", "-out", "server-pub.pem")
    der = run("pkey", "-pubin", "-in", "server-pub.pem", "-outform", "DER")
    out["pin"] = "sha256//" + base64.b64encode(__import__("hashlib").sha256(der).digest()).decode()
    out["pubkey"] = str(work / "server-pub.pem")
    return out


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def world(request, tmp_path_factory):
    """Every server the scenarios name, by name; ``tls`` is the https
    origin (``None`` without openssl to make its certificate), ``ca`` the
    flags that trust it."""
    servers = _Servers()
    w = {
        name: servers.serve(handler)
        for name, handler in (
            ("origin", _origin),
            ("empty", _empty),
            ("truncated", _truncated),
            ("not_http", _not_http),
            ("bad_status", _bad_status),
            ("reset_mid_body", _reset_mid_body),
            ("reset_at_once", _reset_at_once),
            ("bad_chunk", _bad_chunk),
            ("chunks_cut", _chunks_cut),
            ("silent", _silent),
            ("proxy", _proxy()),
            ("open_proxy", _proxy(require=None)),
            ("proxy_403", _proxy(connect_status="403 Forbidden")),
            ("proxy_502", _proxy(connect_status="502 Bad Gateway", plain_status="502 Bad Gateway")),
            ("proxy_drops", _proxy(drop_connect=True)),
            ("digest_proxy", _digest_proxy()),
            ("digest_or_basic_proxy", _digest_proxy(offer_basic=True)),
            ("echo", _echo),
            ("header_proxy", _header_proxy),
            ("stalls", _stalls),
            ("longer_than_said", _longer_than_said),
            ("sixty_k", _sixty_k),
            ("no_colon", _no_colon),
            ("plain_at_once", _plain_at_once),
            ("range_ignored", _range_ignored),
            ("range_416", _range_416),
            ("bad_gzip", _bad_gzip),
            ("unknown_encoding", _unknown_encoding),
            ("many_headers", _many_headers),
            ("huge_header", _huge_header),
            ("big_body", _big_body),
            ("closes_on_upload", _closes_on_upload),
            ("token_proxy", _proxy(header="X-Proxy-Token")),
        )
    }
    w["dead"] = "http://127.0.0.1:%d" % _closed_port()
    socks = {mode: FakeSocks(mode) for mode in ("ok", "auth", "refuse", "unreachable", "drop")}
    w.update({"socks_" + mode: "127.0.0.1:%d" % s.port for mode, s in socks.items()})
    w["tmp"] = tmp_path_factory.mktemp("parity")
    (w["tmp"] / "partial").write_bytes(b"012")
    (w["tmp"] / "garbage.pem").write_text("not a certificate\n")
    (w["tmp"] / "upload.bin").write_bytes(b"u" * (8 << 20))
    try:
        certs = request.getfixturevalue("pki")
    except pytest.skip.Exception:
        certs = None
    if certs is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(certs / "server.pem"), str(certs / "server.key"))
        w["tls"] = servers.serve(_origin, tls=context).replace("http://", "https://")
        w["ca"] = ["--cacert", str(certs / "ca.pem")]
        w["certs"] = certs
        mutual = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        mutual.load_cert_chain(str(certs / "server.pem"), str(certs / "server.key"))
        mutual.load_verify_locations(str(certs / "ca.pem"))
        mutual.verify_mode = ssl.CERT_REQUIRED
        w["tls_mutual"] = servers.serve(_origin, tls=mutual).replace("http://", "https://")
        w.update(_revocation_and_pins(certs, w["tmp"]))
        # HTTPS proxies: TLS to the proxy, then the usual proxy behaviour.
        w["https_proxy"] = servers.serve(_proxy(require=None), tls=context).replace("http://", "https://")
        w["https_proxy_auth"] = servers.serve(_proxy(), tls=context).replace("http://", "https://")
        w["https_proxy_mutual"] = servers.serve(_proxy(require=None), tls=mutual).replace("http://", "https://")
    else:
        w["tls"], w["ca"], w["certs"], w["tls_mutual"] = None, [], None, None
        w.update(
            crl_revoked=None,
            crl_clean=None,
            pin=None,
            pubkey=None,
            https_proxy=None,
            https_proxy_auth=None,
            https_proxy_mutual=None,
        )
    yield w
    servers.close()


# --------------------------------------------------------------------------- #
# Running both sides.
# --------------------------------------------------------------------------- #
def _schannel():
    try:
        out = subprocess.run([REAL_CURL, "-V"], capture_output=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return b"Schannel" in out


SCHANNEL = bool(REAL_CURL) and _schannel()


def _real_version():
    from curlike.compat import installed_version

    found = installed_version() if REAL_CURL else None
    return "%d.%d.%d" % found if found else "auto"


#: The fallback answers as this curl (HTTPLIB_CURL_COMPAT).
REAL_VERSION = _real_version()
EMPTY_PATH = None


def _run(argv, env, real):
    """``(exit code, curl: (N) code or None, stdout)`` from the shim."""
    global EMPTY_PATH
    if EMPTY_PATH is None:
        import tempfile

        EMPTY_PATH = tempfile.mkdtemp()
    e = {k: v for k, v in os.environ.items() if not _PROXY_VARS.match(k)}
    e.update(env)
    e["PATH"] = (os.path.dirname(REAL_CURL) + os.pathsep + os.environ.get("PATH", "")) if real else EMPTY_PATH
    if not real:
        e["HTTPLIB_CURL_COMPAT"] = REAL_VERSION  # the fallback answers as this real curl
    if real and SCHANNEL:
        # Schannel cannot check revocation for a private test CA: a
        # certificate the CA signs would fail as "revocation status unknown".
        argv = ["--ssl-no-revoke"] + argv
    try:
        p = subprocess.run(
            [sys.executable, "-m", "curlike"] + argv, capture_output=True, env=e, timeout=30, stdin=subprocess.DEVNULL
        )
    except subprocess.TimeoutExpired:
        return "timeout", None, b"", b""
    m = re.search(rb"curl: \((\d+)\)", p.stderr)
    return p.returncode, int(m.group(1)) if m else None, p.stdout, p.stderr


# --------------------------------------------------------------------------- #
# Scenarios: (id, argv from the world, env, needs the TLS origin, allowed).
# ``allowed`` maps a real exit code to the fallback's where curl versions
# disagree: the comparison accepts the fallback's code, in stdout too.
# --------------------------------------------------------------------------- #
S = lambda w: (w["tls"] or "https://127.0.0.1:1") + "/"  # noqa: E731
P = lambda w, name: w[name]  # noqa: E731
X = "http://example.invalid/"

SCENARIOS = [
    # Responses: a status is not an error unless -f.
    ("200", lambda w: [w["origin"] + "/"], {}, False, {}),
    ("404", lambda w: [w["origin"] + "/404"], {}, False, {}),
    ("404 -f", lambda w: ["-f", w["origin"] + "/404"], {}, False, {}),
    ("500 --fail-with-body", lambda w: ["--fail-with-body", w["origin"] + "/500"], {}, False, {}),
    ("redirect loop", lambda w: ["-L", "--max-redirs", "2", w["origin"] + "/loop"], {}, False, {}),
    # Connecting.
    ("refused", lambda w: [w["dead"] + "/"], {}, False, {}),
    ("no such host", lambda w: ["http://nonexistent.invalid/"], {}, False, {}),
    ("timeout", lambda w: ["-m", "1", w["silent"] + "/"], {}, False, {}),
    # The reply.
    ("empty reply", lambda w: [w["empty"] + "/"], {}, False, {}),
    ("not HTTP", lambda w: [w["not_http"] + "/"], {}, False, {}),
    ("bad status line", lambda w: [w["bad_status"] + "/"], {}, False, {}),
    ("reset before reply", lambda w: [w["reset_at_once"] + "/"], {}, False, {}),
    ("truncated body", lambda w: [w["truncated"] + "/"], {}, False, {}),
    ("truncated body -s", lambda w: ["-s", w["truncated"] + "/"], {}, False, {}),
    ("reset mid-body", lambda w: [w["reset_mid_body"] + "/"], {}, False, {}),
    ("bad chunk", lambda w: [w["bad_chunk"] + "/"], {}, False, {}),
    ("chunks cut", lambda w: [w["chunks_cut"] + "/"], {}, False, {}),
    ("-w on empty reply", lambda w: ["-w", "[%{http_code} %{exitcode}]", w["empty"] + "/"], {}, False, {}),
    (
        "-w on truncated",
        lambda w: ["-w", "[%{http_code} %{exitcode} %{size_download}]", w["truncated"] + "/"],
        {},
        False,
        {},
    ),
    # Every HTTP-relevant code in curl's exit-code list.
    ("8: header line without a colon", lambda w: [w["no_colon"] + "/"], {}, False, {}),
    (
        "33: resume, range ignored",
        lambda w: ["-C", "-", "-o", _copy(w, "partial"), w["range_ignored"] + "/"],
        {},
        False,
        {},
    ),
    ("36: resume past the end", lambda w: ["-C", "-", "-o", _copy(w, "partial"), w["range_416"] + "/"], {}, False, {}),
    ("55: upload reset", lambda w: ["-T", str(w["tmp"] / "upload.bin"), w["closes_on_upload"] + "/up"], {}, False, {}),
    ("61: bad gzip --compressed", lambda w: ["--compressed", w["bad_gzip"] + "/"], {}, False, {}),
    ("61: bad gzip without --compressed", lambda w: [w["bad_gzip"] + "/"], {}, False, {}),
    ("unknown encoding --compressed", lambda w: ["--compressed", w["unknown_encoding"] + "/"], {}, False, {}),
    ("63: --max-filesize", lambda w: ["--max-filesize", "10", w["big_body"] + "/"], {}, False, {}),
    ("150 headers", lambda w: ["-w", "[%{num_headers}]", w["many_headers"] + "/"], {}, False, {}),
    ("100: a 200 KB header", lambda w: [w["huge_header"] + "/"], {}, False, {}),
    ("3: no host", lambda w: ["-w", "[%{exitcode}]", "http:///x"], {}, False, {}),
    # Flags the fallback took on from curl's list (one request each, so what
    # the server saw is compared too).
    ("-0 sends HTTP/1.0", lambda w: ["-0", w["echo"] + "/v"], {}, False, {}),
    ("-0 with -w", lambda w: ["-0", "-w", "[%{http_version} %{http_code}]", w["origin"] + "/"], {}, False, {}),
    ("-0 upload", lambda w: ["-0", "-T", str(w["tmp"] / "partial"), w["echo"] + "/up"], {}, False, {}),
    # SOCKS: the proxy carries the connection; the request is the origin's.
    ("socks5, an address", lambda w: ["-x", "socks5://" + w["socks_ok"], w["echo"] + "/s"], {}, False, {}),
    (
        "socks5, a name resolved here",
        lambda w: [
            "-x",
            "socks5://" + w["socks_ok"],
            "--resolve",
            "named.test:%s:127.0.0.1" % w["echo"].rsplit(":", 1)[1],
            w["echo"].replace("127.0.0.1", "named.test") + "/s",
        ],
        {},
        False,
        {},
    ),
    (
        "socks5h, the proxy resolves",
        lambda w: ["-x", "socks5h://" + w["socks_ok"], _localhost(w, "echo")],
        {},
        False,
        {},
    ),
    ("socks4", lambda w: ["-x", "socks4://" + w["socks_ok"], _localhost(w, "echo")], {}, False, {}),
    ("socks4a", lambda w: ["-x", "socks4a://" + w["socks_ok"], _localhost(w, "echo")], {}, False, {}),
    ("socks:// is socks4", lambda w: ["-x", "socks://" + w["socks_ok"], w["echo"] + "/s"], {}, False, {}),
    ("--socks5", lambda w: ["--socks5", w["socks_ok"], w["echo"] + "/s"], {}, False, {}),
    ("--socks5-hostname", lambda w: ["--socks5-hostname", w["socks_ok"], _localhost(w, "echo")], {}, False, {}),
    ("--socks4", lambda w: ["--socks4", w["socks_ok"], w["echo"] + "/s"], {}, False, {}),
    (
        "--socks4a overrides -x",
        lambda w: ["-x", P(w, "dead"), "--socks4a", w["socks_ok"], _localhost(w, "echo")],
        {},
        False,
        {},
    ),
    (
        "socks5 credentials in the URL",
        lambda w: ["-x", "socks5h://agent:s3cret@" + w["socks_auth"], _localhost(w, "echo")],
        {},
        False,
        {},
    ),
    (
        "socks5 credentials from -U",
        lambda w: ["-x", "socks5h://" + w["socks_auth"], "-U", "agent:s3cret", _localhost(w, "echo")],
        {},
        False,
        {},
    ),
    (
        "--socks5-basic",
        lambda w: ["--socks5-basic", "-x", "socks5h://agent:s3cret@" + w["socks_auth"], w["echo"] + "/s"],
        {},
        False,
        {},
    ),
    (
        "socks5 wrong password",
        lambda w: ["-x", "socks5h://agent:bad@" + w["socks_auth"], w["echo"] + "/s"],
        {},
        False,
        {},
    ),
    ("socks5 no credentials", lambda w: ["-x", "socks5h://" + w["socks_auth"], w["echo"] + "/s"], {}, False, {}),
    ("socks5 refused", lambda w: ["-x", "socks5h://" + w["socks_refuse"], w["echo"] + "/s"], {}, False, {}),
    ("socks5 unreachable", lambda w: ["-x", "socks5h://" + w["socks_unreachable"], w["echo"] + "/s"], {}, False, {}),
    ("socks4 refused", lambda w: ["-x", "socks4://" + w["socks_refuse"], w["echo"] + "/s"], {}, False, {}),
    ("socks dropped", lambda w: ["-x", "socks5h://" + w["socks_drop"], w["echo"] + "/s"], {}, False, {}),
    ("socks proxy refused", lambda w: ["-x", "socks5h://" + w["dead"].split("//")[1], w["echo"] + "/s"], {}, False, {}),
    (
        "socks proxy not resolvable",
        lambda w: ["-x", "socks5h://nonexistent.invalid:1080", w["echo"] + "/s"],
        {},
        False,
        {},
    ),
    (
        "socks5, target not resolvable here",
        lambda w: ["-x", "socks5://" + w["socks_ok"], "http://nonexistent.invalid/"],
        {},
        False,
        {},
    ),
    (
        "socks5h, target not resolvable there",
        lambda w: ["-x", "socks5h://" + w["socks_ok"], "http://nonexistent.invalid/"],
        {},
        False,
        {},
    ),
    (
        "socks -w",
        lambda w: ["-x", "socks5h://" + w["socks_refuse"], "-w", "[%{http_code} %{exitcode}]", w["echo"] + "/s"],
        {},
        False,
        {},
    ),
    ("socks5h to https", lambda w: w["ca"] + ["-x", "socks5h://" + w["socks_ok"], S(w)], {}, True, {}),
    (
        "--preproxy to an HTTP proxy",
        lambda w: [
            "--preproxy",
            "socks5h://" + w["socks_ok"],
            "-x",
            P(w, "header_proxy"),
            "--proxy-header",
            "X-P: 1",
            X,
        ],
        {},
        False,
        {},
    ),
    ("--preproxy alone", lambda w: ["--preproxy", "socks5h://" + w["socks_ok"], w["echo"] + "/s"], {}, False, {}),
    ("agent proxy is SOCKS", lambda w: [_localhost(w, "echo")], {"HTTPLIB_PROXY": "@socks5h"}, False, {}),
    # HTTPS proxies: TLS to the proxy, verified by the --proxy-* TLS options.
    ("https proxy, http target", lambda w: ["-x", w["https_proxy"], "--proxy-cacert", _ca(w), X], {}, True, {}),
    ("https proxy, --proxy-insecure", lambda w: ["-x", w["https_proxy"], "--proxy-insecure", X], {}, True, {}),
    ("https proxy, untrusted", lambda w: ["-x", w["https_proxy"], X], {}, True, {}),
    ("https proxy, --cacert is not for it", lambda w: w["ca"] + ["-x", w["https_proxy"], X], {}, True, {}),
    (
        "https proxy, name mismatch",
        lambda w: ["-x", w["https_proxy"].replace("127.0.0.1", "localhost"), "--proxy-cacert", _ca(w), X],
        {},
        True,
        {},
    ),
    (
        "https proxy, https target",
        lambda w: w["ca"] + ["-x", w["https_proxy"], "--proxy-cacert", _ca(w), S(w)],
        {},
        True,
        {},
    ),
    # Ubuntu's curl 8.5 reports 35 ("SSL_ERROR_SYSCALL") for this, newer ones 60;
    # where it changed was not measured.
    (
        "https proxy, https target untrusted",
        lambda w: ["-x", w["https_proxy"], "--proxy-cacert", _ca(w), S(w)],
        {},
        True,
        {35: 60},
    ),
    ("https proxy, -k is not for it", lambda w: ["-k", "-x", w["https_proxy"], S(w)], {}, True, {}),
    ("https proxy, both insecure", lambda w: ["-k", "--proxy-insecure", "-x", w["https_proxy"], S(w)], {}, True, {}),
    (
        "https proxy, -p http target",
        lambda w: ["-p", "-x", w["https_proxy"], "--proxy-cacert", _ca(w), w["echo"] + "/t"],
        {},
        True,
        {},
    ),
    (
        "https proxy, credentials",
        lambda w: ["-x", w["https_proxy_auth"], "--proxy-cacert", _ca(w), "-U", "agent:s3cret", X],
        {},
        True,
        {},
    ),
    ("https proxy, 407", lambda w: ["-x", w["https_proxy_auth"], "--proxy-cacert", _ca(w), X], {}, True, {}),
    (
        "https proxy, CONNECT with credentials",
        lambda w: w["ca"] + ["-x", w["https_proxy_auth"], "--proxy-cacert", _ca(w), "-U", "agent:s3cret", S(w)],
        {},
        True,
        {},
    ),
    (
        "https proxy, CONNECT 407",
        lambda w: w["ca"] + ["-x", w["https_proxy_auth"], "--proxy-cacert", _ca(w), S(w)],
        {},
        True,
        {},
    ),
    (
        "--proxy-pinnedpubkey match",
        lambda w: ["-x", w["https_proxy"], "--proxy-insecure", "--proxy-pinnedpubkey", w["pin"], X],
        {},
        True,
        {},
    ),
    (
        "--proxy-pinnedpubkey mismatch",
        lambda w: ["-x", w["https_proxy"], "--proxy-insecure", "--proxy-pinnedpubkey", "sha256//" + "A" * 43 + "=", X],
        {},
        True,
        {},
    ),
    (
        "--proxy-crlfile revoked",
        lambda w: ["-x", w["https_proxy"], "--proxy-cacert", _ca(w), "--proxy-crlfile", w["crl_revoked"], X],
        {},
        True,
        {},
    ),
    (
        "--proxy-cacert missing",
        lambda w: ["-x", w["https_proxy"], "--proxy-cacert", str(w["tmp"] / "none.pem"), X],
        {},
        True,
        {},
    ),
    ("--proxy-tlsv1", lambda w: ["-x", w["https_proxy"], "--proxy-cacert", _ca(w), "--proxy-tlsv1", X], {}, True, {}),
    (
        "--proxy-cert",
        lambda w: [
            "-x",
            w["https_proxy_mutual"],
            "--proxy-cacert",
            _ca(w),
            "--proxy-cert",
            str(w["certs"] / "client.pem"),
            "--proxy-key",
            str(w["certs"] / "client.key"),
            X,
        ],
        {},
        True,
        {},
    ),
    (
        "https proxy wants a client certificate",
        lambda w: ["-x", w["https_proxy_mutual"], "--proxy-cacert", _ca(w), X],
        {},
        True,
        {55: 56},
    ),  # the same race as "client certificate required"
    ("agent proxy over https", lambda w: ["--proxy-insecure", X], {"HTTPLIB_PROXY": "@https_proxy"}, True, {}),
    # Proxy Digest: nothing up front, the 407 answered once.
    (
        "--proxy-digest",
        lambda w: ["-x", P(w, "digest_proxy"), "--proxy-digest", "-U", "agent:s3cret", X],
        {},
        False,
        {},
    ),
    (
        "--proxy-digest wrong password",
        lambda w: ["-x", P(w, "digest_proxy"), "--proxy-digest", "-U", "agent:bad", X],
        {},
        False,
        {},
    ),
    (
        "--proxy-digest credentials in the URL",
        lambda w: ["-x", P(w, "digest_proxy").replace("//", "//agent:s3cret@"), "--proxy-digest", X],
        {},
        False,
        {},
    ),
    (
        "--proxy-anyauth picks Digest",
        lambda w: ["-x", P(w, "digest_or_basic_proxy"), "--proxy-anyauth", "-U", "agent:s3cret", X],
        {},
        False,
        {},
    ),
    (
        "--proxy-anyauth, Digest only",
        lambda w: ["-x", P(w, "digest_proxy"), "--proxy-anyauth", "-U", "agent:s3cret", X],
        {},
        False,
        {},
    ),
    ("Basic to a Digest proxy", lambda w: ["-x", P(w, "digest_proxy"), "-U", "agent:s3cret", X], {}, False, {}),
    (
        "--proxy-digest over CONNECT",
        lambda w: w["ca"] + ["-x", P(w, "digest_proxy"), "--proxy-digest", "-U", "agent:s3cret", S(w)],
        {},
        True,
        {},
    ),
    (
        "--proxy-digest over CONNECT, wrong password",
        lambda w: w["ca"] + ["-x", P(w, "digest_proxy"), "--proxy-digest", "-U", "agent:bad", S(w)],
        {},
        True,
        {},
    ),
    (
        "--proxy-anyauth over CONNECT",
        lambda w: w["ca"] + ["-x", P(w, "digest_or_basic_proxy"), "--proxy-anyauth", "-U", "agent:s3cret", S(w)],
        {},
        True,
        {},
    ),
    (
        "--proxy-digest with -p",
        lambda w: ["-p", "-x", P(w, "digest_proxy"), "--proxy-digest", "-U", "agent:s3cret", w["echo"] + "/d"],
        {},
        False,
        {},
    ),
    # --proto, --proto-redir, --proto-default.
    ("--proto =https on http", lambda w: ["--proto", "=https", w["echo"] + "/p"], {}, False, {}),
    ("--proto -all,https", lambda w: ["--proto", "-all,https", w["echo"] + "/p"], {}, False, {}),
    ("--proto =http,https", lambda w: ["--proto", "=http,https", w["echo"] + "/p"], {}, False, {}),
    ("--proto -http", lambda w: ["--proto", "-http", w["echo"] + "/p"], {}, False, {}),
    ("--proto +ftp", lambda w: ["--proto", "+ftp", w["echo"] + "/p"], {}, False, {}),
    ("--proto unknown name", lambda w: ["--proto", "=bogus", w["echo"] + "/p"], {}, False, {}),
    ("--proto =https -w", lambda w: ["--proto", "=https", "-w", "[%{exitcode}]", w["echo"] + "/p"], {}, False, {}),
    ("--proto-redir =https", lambda w: ["-L", "--proto-redir", "=https", w["origin"] + "/to-http"], {}, False, {}),
    (
        "--proto-redir -all,http",
        lambda w: ["-L", "--proto-redir", "-all,http", w["origin"] + "/to-http"],
        {},
        False,
        {},
    ),
    (
        "--proto =http blocks the https hop",
        lambda w: ["-L", "--proto", "=https", w["origin"] + "/to-http"],
        {},
        False,
        {},
    ),
    ("--proto-default http", lambda w: ["--proto-default", "http", w["echo"].split("//")[1] + "/x"], {}, False, {}),
    ("--proto-default unknown", lambda w: ["--proto-default", "bogus", w["echo"].split("//")[1] + "/x"], {}, False, {}),
    (
        "--proto-default https to a plain port",
        lambda w: ["--proto-default", "https", "-m", "10", w["plain_at_once"].split("//")[1] + "/x"],
        {},
        False,
        {},
    ),
    # Dot segments: resolved as curl does, unless --path-as-is.
    ("dot segments /a/../b", lambda w: [w["echo"] + "/a/../b"], {}, False, {}),
    ("dot segments /a/./b/.", lambda w: [w["echo"] + "/a/./b/."], {}, False, {}),
    ("dot segments /../x", lambda w: [w["echo"] + "/../x"], {}, False, {}),
    ("dot segments, query untouched", lambda w: [w["echo"] + "/a/b/../../c?q=/../"], {}, False, {}),
    ("--path-as-is", lambda w: ["--path-as-is", w["echo"] + "/a/../b"], {}, False, {}),
    # -j and the no-ops.
    ("-j drops session cookies", lambda w: ["-j", "-b", _write(w, "jar.txt", _JAR), w["echo"] + "/c"], {}, False, {}),
    (
        "-b, curl's matching rules",
        lambda w: ["-b", _write(w, "rules.txt", _RULES_JAR), w["echo"] + "/adminx/y"],
        {},
        False,
        {},
    ),
    ("-b keeps session cookies", lambda w: ["-b", _write(w, "jar.txt", _JAR), w["echo"] + "/c"], {}, False, {}),
    (
        "no-ops",
        lambda w: [
            "--fail-early",
            "--expect100-timeout",
            "1",
            "--tcp-fastopen",
            "--false-start",
            "--happy-eyeballs-timeout-ms",
            "100",
            "--random-file",
            "x",
            "--egd-file",
            "x",
            w["echo"] + "/n",
        ],
        {},
        False,
        {},
    ),
    ("-i through a CONNECT", lambda w: w["ca"] + ["-i", "-x", P(w, "open_proxy"), S(w)], {}, True, {}),
    (
        "-i --suppress-connect-headers",
        lambda w: w["ca"] + ["-i", "--suppress-connect-headers", "-x", P(w, "open_proxy"), S(w)],
        {},
        True,
        {},
    ),
    # --proxy-header: to the proxy only -- the plain request to it, or the CONNECT.
    (
        "--proxy-header, plain proxying",
        lambda w: ["-x", P(w, "header_proxy"), "--proxy-header", "X-P: 1", "-H", "X-O: 2", X],
        {},
        False,
        {},
    ),
    (
        "--proxy-header on the CONNECT (-p)",
        lambda w: ["-p", "-x", P(w, "header_proxy"), "--proxy-header", "X-P: 1", "-H", "X-O: 2", w["echo"] + "/x"],
        {},
        False,
        {},
    ),
    (
        "--proxy-header never reaches the origin",
        lambda w: w["ca"] + ["-x", P(w, "header_proxy"), "--proxy-header", "X-Proxy-Token: t", S(w)],
        {},
        True,
        {},
    ),
    (
        "--proxy-header, bypassed host",
        lambda w: ["-x", P(w, "header_proxy"), "--noproxy", "127.0.0.1", "--proxy-header", "X-P: 1", w["echo"] + "/b"],
        {},
        False,
        {},
    ),
    (
        "--proxy-header empty and from a file",
        lambda w: [
            "-x",
            P(w, "header_proxy"),
            "--proxy-header",
            "X-E;",
            "--proxy-header",
            "@" + _write(w, "ph.txt", "X-F: 3\n"),
            X,
        ],
        {},
        False,
        {},
    ),
    ("--proxy-basic", lambda w: ["-x", P(w, "proxy"), "--proxy-basic", "-U", "agent:s3cret", X], {}, False, {}),
    ("--request-target *", lambda w: ["--request-target", "*", "-X", "OPTIONS", w["echo"] + "/x"], {}, False, {}),
    ("--request-target", lambda w: ["--request-target", "/other?q=1", w["echo"] + "/x"], {}, False, {}),
    ("-p tunnels http", lambda w: ["-p", "-x", P(w, "open_proxy"), w["echo"] + "/tunnelled"], {}, False, {}),
    ("-p, proxy refuses", lambda w: ["-p", "-x", P(w, "proxy_403"), w["echo"] + "/t"], {}, False, {}),
    (
        "-p with a credential",
        lambda w: ["-p", "-x", P(w, "proxy"), "-U", "agent:s3cret", w["echo"] + "/t"],
        {},
        False,
        {},
    ),
    ("--anyauth", lambda w: ["--anyauth", "-u", "a:b", w["echo"] + "/auth"], {}, False, {}),
    ("--anyauth, no challenge", lambda w: ["--anyauth", "-u", "a:b", w["echo"] + "/open"], {}, False, {}),
    ("--interface IP", lambda w: ["--interface", "127.0.0.1", w["echo"] + "/i"], {}, False, {}),
    ("--interface no such name", lambda w: ["--interface", "nosuchif0", w["echo"] + "/i"], {}, False, {}),
    ("--local-port", lambda w: ["--local-port", "47310-47330", w["echo"] + "/port"], {}, False, {}),
    ("--local-port bad", lambda w: ["--local-port", "x", w["echo"] + "/i"], {}, False, {}),
    ("--limit-rate", lambda w: ["--limit-rate", "40K", w["sixty_k"] + "/"], {}, False, {}),
    ("--speed-limit", lambda w: ["--speed-limit", "1000", "--speed-time", "2", w["stalls"] + "/"], {}, False, {}),
    ("--ignore-content-length", lambda w: ["--ignore-content-length", w["longer_than_said"] + "/"], {}, False, {}),
    ("--crlfile, not revoked", lambda w: w["ca"] + ["--crlfile", w["crl_clean"], S(w)], {}, True, {}),
    ("--crlfile, revoked", lambda w: w["ca"] + ["--crlfile", w["crl_revoked"], S(w)], {}, True, {}),
    ("--crlfile missing", lambda w: w["ca"] + ["--crlfile", str(w["tmp"] / "missing.crl"), S(w)], {}, True, {}),
    ("--pinnedpubkey match", lambda w: w["ca"] + ["--pinnedpubkey", w["pin"], S(w)], {}, True, {}),
    ("--pinnedpubkey file", lambda w: w["ca"] + ["--pinnedpubkey", w["pubkey"], S(w)], {}, True, {}),
    (
        "--pinnedpubkey mismatch",
        lambda w: w["ca"] + ["--pinnedpubkey", "sha256//" + "A" * 43 + "=", S(w)],
        {},
        True,
        {},
    ),
    ("--pinnedpubkey with -k", lambda w: ["-k", "--pinnedpubkey", "sha256//" + "A" * 43 + "=", S(w)], {}, True, {}),
    # The URL and local files.
    ("malformed URL", lambda w: ["-w", "[%{exitcode}]", "http://[::1/"], {}, False, {}),
    ("malformed URL -g", lambda w: ["-g", "-w", "[%{exitcode}]", "http://[::1/"], {}, False, {}),
    ("IPv6 host", lambda w: ["-w", "[%{exitcode}]", "http://[::1]:%d/" % _closed_port()], {}, False, {}),
    ("glob: unmatched brace", lambda w: ["-w", "[%{exitcode}]", w["origin"] + "/{a,b"], {}, False, {}),
    ("glob: unmatched close", lambda w: ["-w", "[%{exitcode}]", w["origin"] + "/a]"], {}, False, {}),
    ("glob: bad range", lambda w: ["-w", "[%{exitcode}]", w["origin"] + "/[a"], {}, False, {}),
    ("glob off", lambda w: ["-g", w["origin"] + "/{a,b}"], {}, False, {}),
    ("port out of range", lambda w: ["-w", "[%{exitcode}]", "http://127.0.0.1:99999/"], {}, False, {}),
    ("unknown scheme", lambda w: ["-w", "[%{exitcode}]", "foo://127.0.0.1/"], {}, False, {}),
    ("no URL", lambda w: [], {}, False, {}),
    ("-o into a missing dir", lambda w: ["-o", str(w["tmp"] / "no" / "x"), w["origin"] + "/"], {}, False, {}),
    ("-T missing", lambda w: ["-T", str(w["tmp"] / "missing.bin"), w["origin"] + "/"], {}, False, {}),
    ("-d @missing", lambda w: ["-d", "@" + str(w["tmp"] / "missing.bin"), w["origin"] + "/"], {}, False, {}),
    ("-F @missing", lambda w: ["-F", "f=@" + str(w["tmp"] / "missing.bin"), w["origin"] + "/"], {}, False, {}),
    ("-H @missing", lambda w: ["-H", "@" + str(w["tmp"] / "missing.txt"), w["origin"] + "/"], {}, False, {}),
    ("--cacert missing", lambda w: ["--cacert", str(w["tmp"] / "missing.pem"), S(w)], {}, True, {}),
    (
        "--netrc-file missing",
        lambda w: ["--netrc-file", str(w["tmp"] / "missing.netrc"), w["origin"] + "/"],
        {},
        False,
        {},
    ),
    ("-w @missing", lambda w: ["-w", "@" + str(w["tmp"] / "missing.txt"), w["origin"] + "/"], {}, False, {}),
    # TLS.
    ("TLS trusted", lambda w: w["ca"] + [S(w)], {}, True, {}),
    ("TLS untrusted", lambda w: [S(w)], {}, True, {}),
    ("TLS -k", lambda w: ["-k", S(w)], {}, True, {}),
    (
        "35: TLS to a plain-HTTP port",
        lambda w: ["-m", "10", w["plain_at_once"].replace("http://", "https://") + "/"],
        {},
        False,
        {},
    ),
    ("60: name does not match", lambda w: w["ca"] + [S(w).replace("127.0.0.1", "localhost")], {}, True, {}),
    ("77: --cacert not a bundle", lambda w: ["--cacert", str(w["tmp"] / "garbage.pem"), S(w)], {}, True, {}),
    # The server's "certificate required" alert races curl's first write: 56
    # when curl reads it, 55 when the reset reaches its send first.
    ("client certificate required", lambda w: w["ca"] + [w["tls_mutual"] + "/"], {}, True, {55: 56}),
    (
        "client certificate given",
        lambda w: w["ca"]
        + ["--cert", str(w["certs"] / "client.pem"), "--key", str(w["certs"] / "client.key"), w["tls_mutual"] + "/"],
        {},
        True,
        {},
    ),
    # A proxy, plain http: its answer is the response.
    ("proxy credential", lambda w: ["-x", P(w, "proxy"), "-U", "agent:s3cret", X], {}, False, {}),
    ("proxy credential in its URL", lambda w: ["-x", P(w, "proxy").replace("//", "//agent:s3cret@"), X], {}, False, {}),
    ("proxy 407", lambda w: ["-x", P(w, "proxy"), X], {}, False, {}),
    ("proxy 407 -f", lambda w: ["-f", "-x", P(w, "proxy"), X], {}, False, {}),
    ("proxy wrong credential", lambda w: ["-x", P(w, "proxy"), "-U", "agent:bad", X], {}, False, {}),
    ("proxy 502 -f", lambda w: ["-f", "-x", P(w, "proxy_502"), X], {}, False, {}),
    ("proxy refused", lambda w: ["-x", P(w, "dead"), X], {}, False, {}),
    ("proxy not resolvable", lambda w: ["-x", "http://nonexistent.invalid:3128", X], {}, False, {}),
    ("proxy empty reply", lambda w: ["-x", P(w, "empty"), X], {}, False, {}),
    ("proxy URL malformed", lambda w: ["-w", "[%{exitcode}]", "-x", "http://not a url", X], {}, False, {}),
    ("proxy port out of range", lambda w: ["-x", "http://127.0.0.1:99999", X], {}, False, {}),
    # A proxy, https: the CONNECT.
    ("CONNECT refused", lambda w: ["-x", P(w, "dead"), S(w)], {}, False, {}),
    ("CONNECT proxy not resolvable", lambda w: ["-x", "http://nonexistent.invalid:3128", S(w)], {}, False, {}),
    ("CONNECT 407", lambda w: w["ca"] + ["-x", P(w, "proxy"), S(w)], {}, False, {}),
    ("CONNECT 407 -f", lambda w: w["ca"] + ["-f", "-x", P(w, "proxy"), S(w)], {}, False, {}),
    (
        "CONNECT 407 -w",
        lambda w: w["ca"] + ["-w", "[%{http_code} %{exitcode}]", "-x", P(w, "proxy"), S(w)],
        {},
        False,
        {},
    ),
    ("CONNECT wrong credential", lambda w: w["ca"] + ["-x", P(w, "proxy"), "-U", "agent:bad", S(w)], {}, False, {}),
    ("CONNECT 403", lambda w: w["ca"] + ["-x", P(w, "proxy_403"), S(w)], {}, False, {}),
    ("CONNECT 403 -f", lambda w: w["ca"] + ["-f", "-x", P(w, "proxy_403"), S(w)], {}, False, {}),
    ("CONNECT 502", lambda w: w["ca"] + ["-x", P(w, "proxy_502"), S(w)], {}, False, {}),
    ("CONNECT dropped", lambda w: w["ca"] + ["-x", P(w, "proxy_drops"), S(w)], {}, False, {}),
    ("CONNECT empty reply", lambda w: w["ca"] + ["-x", P(w, "empty"), S(w)], {}, False, {}),
    (
        "CONNECT target unreachable",
        lambda w: ["-x", P(w, "open_proxy"), "https://127.0.0.1:%d/" % _closed_port()],
        {},
        False,
        {},
    ),
    ("CONNECT tunnelled", lambda w: w["ca"] + ["-x", P(w, "proxy"), "-U", "agent:s3cret", S(w)], {}, True, {}),
    ("CONNECT tunnelled, untrusted", lambda w: ["-x", P(w, "proxy"), "-U", "agent:s3cret", S(w)], {}, True, {}),
    # The agent proxy (HTTPLIB_PROXY): the shim hands it to real curl as
    # --proxy / --proxy-header; the fallback applies it itself.
    ("agent proxy", lambda w: [X], {"HTTPLIB_PROXY": "@proxy", "HTTPLIB_PROXY_AUTH": BASIC}, False, {}),
    (
        "agent proxy, wrong credential",
        lambda w: [X],
        {"HTTPLIB_PROXY": "@proxy", "HTTPLIB_PROXY_AUTH": "Basic eA=="},
        False,
        {},
    ),
    (
        "agent proxy, wrong credential -f",
        lambda w: ["-f", X],
        {"HTTPLIB_PROXY": "@proxy", "HTTPLIB_PROXY_AUTH": "Basic eA=="},
        False,
        {},
    ),
    ("agent proxy, no credential", lambda w: [X], {"HTTPLIB_PROXY": "@proxy"}, False, {}),
    ("agent proxy, userinfo credential", lambda w: [X], {"HTTPLIB_PROXY": "@proxy+userinfo"}, False, {}),
    ("agent proxy refused", lambda w: [X], {"HTTPLIB_PROXY": "@dead"}, False, {}),
    ("agent proxy not resolvable", lambda w: [X], {"HTTPLIB_PROXY": "http://nonexistent.invalid:3128"}, False, {}),
    ("agent proxy malformed", lambda w: [X], {"HTTPLIB_PROXY": "not a url"}, False, {}),
    (
        "agent proxy CONNECT 407",
        lambda w: w["ca"] + [S(w)],
        {"HTTPLIB_PROXY": "@proxy", "HTTPLIB_PROXY_AUTH": "Basic eA=="},
        False,
        {},
    ),
    (
        "agent proxy CONNECT 407 -f",
        lambda w: w["ca"] + ["-f", S(w)],
        {"HTTPLIB_PROXY": "@proxy", "HTTPLIB_PROXY_AUTH": "Basic eA=="},
        False,
        {},
    ),
    (
        "agent proxy bearer CONNECT 407",
        lambda w: w["ca"] + [S(w)],
        {"HTTPLIB_PROXY": "@proxy", "HTTPLIB_PROXY_AUTH": "Bearer t"},
        False,
        {},
    ),
    (
        "agent proxy CONNECT tunnelled",
        lambda w: w["ca"] + [S(w)],
        {"HTTPLIB_PROXY": "@proxy", "HTTPLIB_PROXY_AUTH": BASIC},
        True,
        {},
    ),
    # HTTPLIB_PROXY_AUTH_HEADER: the credential in a header of that name, to
    # the proxy only -- on the CONNECT for https, never through the tunnel.
    (
        "agent proxy custom header",
        lambda w: [X],
        {"HTTPLIB_PROXY": "@token_proxy", "HTTPLIB_PROXY_AUTH": BASIC, "HTTPLIB_PROXY_AUTH_HEADER": "X-Proxy-Token"},
        False,
        {},
    ),
    (
        "agent proxy custom header CONNECT",
        lambda w: w["ca"] + [S(w)],
        {"HTTPLIB_PROXY": "@token_proxy", "HTTPLIB_PROXY_AUTH": BASIC, "HTTPLIB_PROXY_AUTH_HEADER": "X-Proxy-Token"},
        True,
        {},
    ),
    (
        "agent proxy custom header never reaches the origin",
        lambda w: w["ca"] + [S(w)],
        {"HTTPLIB_PROXY": "@open_proxy", "HTTPLIB_PROXY_AUTH": BASIC, "HTTPLIB_PROXY_AUTH_HEADER": "X-Proxy-Token"},
        True,
        {},
    ),
    ("agent proxy dropped CONNECT", lambda w: w["ca"] + [S(w)], {"HTTPLIB_PROXY": "@proxy_drops"}, False, {}),
]


def _ca(world):
    return str(world["certs"] / "ca.pem")


#: A Secure cookie (sent to 127.0.0.1 over http: a secure context), a leading-dot
#: domain (never covers an IP address), a path that is a prefix of the URL's
#: but not a path-match (/admin vs /adminx), and an HttpOnly row.
_RULES_JAR = (
    "127.0.0.1\tFALSE\t/\tTRUE\t4102444800\tsecure\t1\n"
    ".0.0.1\tTRUE\t/\tFALSE\t4102444800\tdotted\t2\n"
    "127.0.0.1\tFALSE\t/admin\tFALSE\t4102444800\tadmin\t3\n"
    "127.0.0.1\tFALSE\t/adminx\tFALSE\t4102444800\tadminx\t4\n"
    "#HttpOnly_127.0.0.1\tFALSE\t/\tFALSE\t4102444800\thidden\t5\n"
)


_JAR = "127.0.0.1\tFALSE\t/\tFALSE\t0\tsession\tyes\n" "127.0.0.1\tFALSE\t/\tFALSE\t4102444800\tlasting\tyes\n"


def _localhost(world, name):
    """The server ``name`` addressed as localhost (so the name, not an
    address, is what a SOCKS client has to resolve or pass on)."""
    return world[name].replace("127.0.0.1", "localhost") + "/s"


def _write(world, name, text):
    path = world["tmp"] / name
    path.write_text(text, encoding="ascii")
    return str(path)


def _copy(world, name):
    """A fresh copy of a prepared file (each run may rewrite it)."""
    import shutil
    import uuid

    target = world["tmp"] / ("%s-%s" % (name, uuid.uuid4().hex[:8]))
    shutil.copy(str(world["tmp"] / name), str(target))
    return str(target)


#: Where a Schannel curl answers for Schannel rather than for curl (the
#: OpenSSL / LibreSSL builds agree with the fallback).
SCHANNEL_OWN = {
    "77: --cacert not a bundle": "it ignores a CA file it cannot read and fails verification (60)",
    "client certificate given": "it cannot load a PEM client certificate (58)",
    "--crlfile, revoked": "the --ssl-no-revoke this harness needs for it turns revocation checks off",
    "--proxy-cert": "it cannot load a PEM client certificate (58)",
    "https proxy, http target": "it checks the https:// proxy's revocation and curl has no option to relax that",
    "https proxy, https target": "it checks the https:// proxy's revocation and curl has no option to relax that",
    "https proxy, -p http target": "it checks the https:// proxy's revocation and curl has no option to relax that",
    "https proxy, credentials": "it checks the https:// proxy's revocation and curl has no option to relax that",
    "https proxy, 407": "it checks the https:// proxy's revocation and curl has no option to relax that",
    "https proxy, CONNECT with credentials": "it checks the https:// proxy's revocation and curl has no option to relax that",
    "https proxy, CONNECT 407": "it checks the https:// proxy's revocation and curl has no option to relax that",
    "--proxy-tlsv1": "it checks the https:// proxy's revocation and curl has no option to relax that",
    "https proxy wants a client certificate": "it checks the https:// proxy's revocation and curl has no option to relax that",
}


def _env(world, env):
    out = {}
    for key, value in env.items():
        if value == "@proxy+userinfo":
            value = world["proxy"].replace("//", "//agent:s3cret@")
        elif value == "@https_proxy":
            value = world["https_proxy"]
        elif value == "@socks5h":
            value = "socks5h://" + world["socks_ok"]
        elif value.startswith("@"):
            value = world[value[1:]]
        out[key] = value
    return out


@pytest.mark.parametrize("name,argv,env,tls,allowed", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_the_fallback_answers_as_curl_does(world, name, argv, env, tls, allowed):
    if tls and not world["tls"]:
        pytest.skip("no openssl to make the TLS origin's certificate with")
    if SCHANNEL and name in SCHANNEL_OWN:
        pytest.skip("Schannel's own behaviour: %s" % SCHANNEL_OWN[name])

    def command():
        # Built once per side: a scenario may prepare a file each run rewrites.
        args = ["-sS"] + argv(world)
        return args[1:] if args[1:2] == ["-s"] else args  # -s alone, when asked

    environment = _env(world, env)
    real = _run(command(), environment, real=True)
    fallback = _run(command(), environment, real=False)
    code, err_code, out = real[:3]
    if code in allowed:
        # A known difference (a race between two outcomes): what the fallback answers instead.
        out = out.replace(b"%d]" % code, b"%d]" % allowed[code])
        code = allowed[code]
        err_code = code if err_code is not None else None
    assert (fallback[0], fallback[1], fallback[2]) == (
        code,
        err_code,
        out,
    ), "%s\n real curl: rc=%s stderr=%r stdout=%r\n fallback:  rc=%s stderr=%r stdout=%r" % (
        name,
        real[0],
        real[3][:300],
        real[2][:120],
        fallback[0],
        fallback[3][-300:],
        fallback[2][:120],
    )


def test_a_url_glob_is_refused_not_sent_as_typed(world):
    """curl makes one transfer per expansion of ``{a,b}`` / ``[1-3]``; the
    fallback makes one, so it refuses the pattern (exit 2) instead of sending
    the braces literally. ``-g`` sends them as typed, in both."""
    for url in ("/{a,b}", "/file[1-3].txt", "/x[a-c:2]"):
        rc, code, out, err = _run(["-sS", world["origin"] + url], {}, real=False)
        assert rc == 2 and b"pass -g" in err, err


# --------------------------------------------------------------------------- #
# -w's timings, addresses and %{json}: times differ run to run, so they are
# checked for curl's format and order; everything else is compared exactly.
# --------------------------------------------------------------------------- #
_TIMES = (
    "time_namelookup",
    "time_connect",
    "time_appconnect",
    "time_pretransfer",
    "time_posttransfer",
    "time_starttransfer",
    "time_total",
    "time_redirect",
)
_SAME = (
    "exitcode",
    "http_code",
    "remote_ip",
    "remote_port",
    "local_ip",
    "num_connects",
    "size_header",
    "size_delivered",
    "http_connect",
    "proxy_used",
    "num_retries",
    "url.host",
    "url.port",
    "url.path",
    "urle.path",
    "referer",
    "conn_id",
    "xfer_id",
)
_NUMBERS = ("local_port", "speed_download", "speed_upload", "size_request")


@pytest.mark.parametrize(
    "name,argv,tls",
    [
        ("http", lambda w: [w["origin"] + "/t"], False),
        ("https", lambda w: w["ca"] + [S(w)], True),
        ("through a proxy", lambda w: ["-x", P(w, "open_proxy"), X], False),
        ("https through a CONNECT", lambda w: w["ca"] + ["-x", P(w, "open_proxy"), S(w)], True),
        ("refused", lambda w: [P(w, "dead") + "/"], False),
        ("with a referer", lambda w: ["-e", "http://ref.example/", w["origin"] + "/t"], False),
    ],
)
def test_write_out_timings_and_addresses(world, name, argv, tls):
    if tls and not world["tls"]:
        pytest.skip("no openssl to make the TLS origin's certificate with")
    names = _TIMES + _SAME + _NUMBERS
    fmt = "|".join("%{" + v + "}" for v in names)
    args = ["-s", "-o", os.devnull, "-w", fmt] + argv(world)
    real = dict(zip(names, _run(args, {}, real=True)[2].decode().split("|")))
    fallback = dict(zip(names, _run(args, {}, real=False)[2].decode().split("|")))
    assert set(real) == set(fallback) == set(names), (real, fallback)
    for key in _TIMES:
        if real[key] == "":  # a variable this curl does not know yet: empty on both sides
            assert fallback[key] == "", (key, fallback[key])
    for side in (real, fallback):
        for key in _TIMES:
            assert real[key] == "" or re.match(r"^\d+\.\d{6}$", side[key]), (key, side[key])
        for key in _NUMBERS:
            assert re.match(r"^-?\d+$", side[key]), (key, side[key])
        if side["exitcode"] == "0":
            chain = [
                float(side[k])
                for k in ("time_namelookup", "time_connect", "time_pretransfer", "time_starttransfer", "time_total")
            ]
            assert chain == sorted(chain), (name, chain)
    assert {k: fallback[k] for k in _SAME} == {k: real[k] for k in _SAME}, name


def test_write_out_json_has_curls_keys(world):
    import json

    args = ["-s", "-o", os.devnull, "-w", "%{json}", world["origin"] + "/t"]
    real = json.loads(_run(args, {}, real=True)[2])
    fallback = json.loads(_run(args, {}, real=False)[2])
    assert set(real) <= set(fallback), sorted(set(real) - set(fallback))
    for key in (
        "http_code",
        "exitcode",
        "remote_ip",
        "remote_port",
        "num_connects",
        "size_download",
        "url.host",
        "scheme",
        "method",
    ):
        assert fallback[key] == real[key], (key, fallback[key], real[key])
    assert type(fallback["time_total"]) is float and type(fallback["local_port"]) is int
