"""Server-key pins are enforced on every connection a transfer opens: a proxy
connection reopened after a 407, and a ``--unix-socket`` one."""

import http.client
import socketserver
import ssl
import threading

import pytest

from curlike import connector
from curlike.tls import ProxyTLS
from test_curl_options import pki  # noqa: F401  (fixture reused)
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)


def test_a_reopened_proxy_connection_is_pin_checked(monkeypatch):
    checked = []

    class _Context:
        def wrap_socket(self, raw, server_hostname=None):
            return "tls:" + raw

    monkeypatch.setattr(connector, "_check_pins", lambda sock, pins: checked.append((sock, pins)))
    pins = {b"digest"}
    klass = connector.Connector().connection_class(http.client.HTTPConnection, proxy_tls=ProxyTLS(_Context(), pins))
    conn = klass("proxy.test", 3128)
    conn._create_connection = lambda address, timeout=None, source=None: "raw"
    conn._reopen()
    assert checked == [("tls:raw", pins)]


@pytest.mark.skipif(not hasattr(__import__("socket"), "AF_UNIX"), reason="no AF_UNIX sockets here")
def test_unix_socket_enforces_the_pin_and_the_tls_name(pki, tmp_path, monkeypatch, capsysbinary):
    import os
    import tempfile

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pki / "server.pem"), str(pki / "server.key"))

    class _Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.rfile.readline()
            while self.rfile.readline().strip():
                pass
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    class _Server(socketserver.UnixStreamServer):
        def get_request(self):
            request, address = super().get_request()
            return context.wrap_socket(request, server_side=True), address

        def handle_error(self, request, client_address):
            pass

    sock_dir = tempfile.mkdtemp(dir="/tmp" if os.name == "posix" else None)
    path = os.path.join(sock_dir, "s.sock")
    server = _Server(path, _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        ca = str(pki / "ca.pem")
        base = ["-s", "--cacert", ca, "--unix-socket", path, "https://127.0.0.1/x"]
        rc, out = _fallback(monkeypatch, capsysbinary, base)
        assert rc == 0 and out.out == b"ok"
        rc, _ = _fallback(monkeypatch, capsysbinary, ["--pinnedpubkey", "sha256//" + "A" * 43 + "="] + base)
        assert rc == 90, "the pin holds over a Unix socket"
    finally:
        server.shutdown()
        server.server_close()


def test_a_connect_carries_one_host_line(monkeypatch, capsysbinary):
    import socket

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    heads = []

    def serve():
        conn, _ = listener.accept()
        data = b""
        while b"\r\n\r\n" not in data:
            data += conn.recv(65536)
        heads.append(data)
        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        rc, _ = _fallback(
            monkeypatch,
            capsysbinary,
            ["-s", "-x", "http://127.0.0.1:%d" % listener.getsockname()[1], "https://target.test/"],
        )
    finally:
        thread.join(5)
        listener.close()
    assert rc == 7 and heads and heads[0].lower().count(b"\r\nhost:") == 1, heads
    assert heads[0].startswith(b"CONNECT target.test:443 HTTP/1.1\r\nHost: target.test:443\r\n")
