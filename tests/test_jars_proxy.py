"""Cookies under the configured proxy: curlike's -c writes the ORIGIN's
cookies (the URL the caller asked for) under a prefix gateway, never the
gateway's.

Loopback only: the origin listens on 127.0.0.1, the proxy and the gateway on
127.0.0.2 (``localhost`` where that is not routed), so a jar keyed by host
can tell them apart.
"""

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from test_proxy_auth import BEARER, _clean_env, _fallback  # noqa: F401  (autouse fixture reused)
from syshttp.cookies import CookieSpec
from syshttp.jar import MemoryCookieJar, MemoryTokenJar


def _other_host():
    """A second loopback name for the proxy and the gateway: 127.0.0.2 where
    the system routes it (Linux, Windows), else ``localhost`` -- macOS has no
    loopback alias beyond 127.0.0.1 unless one is configured."""
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.2", 0))
        return "127.0.0.2"
    except OSError:
        return "localhost"
    finally:
        probe.close()


ORIGIN_HOST, OTHER_HOST = "127.0.0.1", _other_host()
#: What each name binds: ``localhost`` is served on 127.0.0.1.
_BIND = {"localhost": "127.0.0.1"}


def _answer(handler, body, cookie=True):
    handler.send_response(200)
    if cookie:
        handler.send_header("Set-Cookie", "sid=abc; Path=/")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class _Origin(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        _Origin.seen.append((self.path, dict(self.headers)))
        if self.path.endswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        _answer(self, b"origin")

    def log_message(self, *a):
        pass


class _Proxy(BaseHTTPRequestHandler):
    """A connect proxy that checks the credential and answers for the origin."""

    seen = []

    def do_GET(self):
        _Proxy.seen.append((self.path, dict(self.headers)))
        if self.headers.get("Proxy-Authorization") != BEARER:
            self.send_response(407)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        _answer(self, b"proxy")

    def log_message(self, *a):
        pass


class _Gateway(BaseHTTPRequestHandler):
    """A prefix gateway (/fetch/<url>) relaying the origin's answer verbatim,
    including a redirect to an absolute origin URL."""

    seen = []

    def do_GET(self):
        _Gateway.seen.append((self.path, dict(self.headers)))
        inner = self.path.split("/", 2)[2]
        if inner.endswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", inner[: -len("/redirect")] + "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        _answer(self, b"gateway")

    def log_message(self, *a):
        pass


class _Server(HTTPServer):
    """HTTPServer without the reverse lookup `server_bind` does on the bound
    address (`socket.getfqdn`): on Windows that takes ~5 s for 127.0.0.2,
    which has no reverse record, per fixture."""

    def server_bind(self):
        import socketserver

        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "localhost", self.server_address[1]


def _serve(handler, host):
    handler.seen = []
    httpd = _Server((_BIND.get(host, host), 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture()
def origin():
    httpd = _serve(_Origin, ORIGIN_HOST)
    try:
        yield "http://%s:%d" % (ORIGIN_HOST, httpd.server_address[1])
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def proxy(monkeypatch):
    httpd = _serve(_Proxy, OTHER_HOST)
    monkeypatch.setenv("SYSHTTP_PROXY", "http://%s:%d" % (OTHER_HOST, httpd.server_address[1]))
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    try:
        yield
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def gateway(monkeypatch):
    httpd = _serve(_Gateway, OTHER_HOST)
    monkeypatch.setenv("SYSHTTP_PROXY", "http://%s:%d" % (OTHER_HOST, httpd.server_address[1]))
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    try:
        yield
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------
# the session
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# curlike
# --------------------------------------------------------------------------


def test_curl_c_writes_the_origin_cookies_under_a_prefix_gateway(origin, gateway, tmp_path, monkeypatch, capsysbinary):
    jar = tmp_path / "jar.txt"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-c", str(jar), origin + "/x"])
    assert rc == 0 and out.out == b"gateway"
    rows = [l.split("\t") for l in jar.read_text(encoding="utf-8").splitlines() if not l.startswith("#")]
    assert rows == [[ORIGIN_HOST, "FALSE", "/", "FALSE", "0", "sid", "abc"]]
    # -b sends them back, to the gateway, for the origin.
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-b", str(jar), origin + "/y"])
    assert rc == 0 and _Gateway.seen[-1][1].get("Cookie") == "sid=abc"
