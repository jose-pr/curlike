"""A caller's ssl.SSLContext for the fallback: mutual TLS and a pinned
protocol version through the curl command line, the flags it replaces
refused.

The server is a loopback HTTPS server that requires a client certificate from
the test CA in tests/data (test material, never real credentials)."""

import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import curlike

DATA = Path(__file__).parent / "data"


class _WhoAmI(BaseHTTPRequestHandler):
    def do_GET(self):
        peer = self.connection.getpeercert() or {}
        cn = next((v for rdn in peer.get("subject", ()) for k, v in rdn if k == "commonName"), "")
        body = ("%s %s" % (cn, self.connection.version())).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def mtls_server():
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(DATA / "server.pem", DATA / "server.key")
    server_ctx.load_verify_locations(DATA / "ca.pem")
    server_ctx.verify_mode = ssl.CERT_REQUIRED
    httpd = HTTPServer(("127.0.0.1", 0), _WhoAmI)
    httpd.socket = server_ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield "https://127.0.0.1:%d/" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _client(identity=True):
    ctx = ssl.create_default_context(cafile=str(DATA / "ca.pem"))
    if identity:
        ctx.load_cert_chain(DATA / "client-rsa.pem", DATA / "client-rsa.key")
    return ctx


def test_the_fallback_presents_the_contexts_client_certificate(mtls_server, capsysbinary):
    assert curlike.main(["-s", mtls_server], ssl_context=_client()) == 0
    assert capsysbinary.readouterr().out.split()[0] == b"client-rsa"


def test_the_contexts_own_settings_reach_the_handshake(mtls_server, capsysbinary):
    ctx = _client()
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    assert curlike.main(["-s", mtls_server], ssl_context=ctx) == 0
    assert capsysbinary.readouterr().out == b"client-rsa TLSv1.2"


def test_without_the_context_the_test_ca_is_unknown(mtls_server, capsysbinary):
    """The OS trust store does not know the test CA: curl's 60."""
    assert curlike.main(["-s", mtls_server]) == 60


@pytest.mark.parametrize("flag", [["-k"], ["--cacert", "x.pem"], ["--ciphers", "ALL"], ["--tlsv1.2"]])
def test_a_flag_the_context_replaces_is_a_conflict(flag, capsysbinary):
    assert curlike.main(["-s", *flag, "https://h/"], ssl_context=_client()) == 2
    err = capsysbinary.readouterr().err
    assert err.startswith(b"curl: (2) ssl_context replaces " + flag[0].encode())


def test_a_proxy_flag_the_proxy_context_replaces_is_a_conflict(capsysbinary):
    assert curlike.main(["-s", "--proxy-insecure", "https://h/"], proxy_ssl_context=_client()) == 2
    assert b"proxy_ssl_context replaces --proxy-insecure" in capsysbinary.readouterr().err


def test_a_context_must_be_an_ssl_context():
    with pytest.raises(TypeError, match="ssl.SSLContext"):
        curlike.run_fallback(["https://h/"], ssl_context="ca.pem")


def test_a_pin_holds_under_the_callers_context(mtls_server, capsysbinary):
    assert curlike.main(["-s", "--pinnedpubkey", "sha256//" + "A" * 43 + "=", mtls_server], ssl_context=_client()) == 90


class _TLSProxy(BaseHTTPRequestHandler):
    """An https:// proxy answering a plain request (no CONNECT) itself."""

    def do_GET(self):
        body = b"via " + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def tls_proxy():
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(DATA / "server.pem", DATA / "server.key")
    httpd = HTTPServer(("127.0.0.1", 0), _TLSProxy)
    httpd.socket = server_ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield "https://127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_the_proxy_context_decides_the_proxy_handshake(tls_proxy, capsysbinary):
    argv = ["-s", "-x", tls_proxy, "http://origin.invalid/x"]
    assert curlike.main(argv, proxy_ssl_context=_client(identity=False)) == 0
    assert capsysbinary.readouterr().out == b"via http://origin.invalid/x"
    assert curlike.main(argv) == 60, "the OS trust store does not know the test CA"
