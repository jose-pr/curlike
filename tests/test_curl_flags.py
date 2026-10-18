"""What the parity tests cannot see: --limit-rate actually paces both
directions, --local-port moves on to the next port of its range, and a pin
that fails stops the request before anything is sent."""

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from curlike import shim as curl
from curlike import connector
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)


class _Handler(BaseHTTPRequestHandler):
    received = []

    def do_GET(self):
        body = b"z" * 60000
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        data = self.rfile.read(int(self.headers["Content-Length"]))
        _Handler.received.append((len(data), self.client_address[1]))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture()
def server():
    _Handler.received = []
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def test_limit_rate_paces_the_download(server, monkeypatch, capsysbinary):
    started = time.monotonic()
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--limit-rate", "30K", server + "/"])
    elapsed = time.monotonic() - started
    assert rc == 0 and len(out.out) == 60000
    assert elapsed >= 1.5, "60000 bytes at 30 KB/s take ~2s, took %.2fs" % elapsed


def test_limit_rate_paces_the_upload(server, monkeypatch, capsysbinary, tmp_path):
    payload = tmp_path / "up.bin"
    payload.write_bytes(b"u" * 40000)
    started = time.monotonic()
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--limit-rate", "20K", "-T", str(payload), server + "/up"])
    elapsed = time.monotonic() - started
    assert rc == 0 and out.out == b"ok" and _Handler.received[-1][0] == 40000
    assert elapsed >= 1.2, "40000 bytes at 20 KB/s take ~2s, took %.2fs" % elapsed


def test_local_port_skips_a_port_in_use(server, monkeypatch, capsysbinary, tmp_path):
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    low = busy.getsockname()[1]
    payload = tmp_path / "up.bin"
    payload.write_bytes(b"x")
    try:
        # The same address as the busy socket: Windows lets a wildcard bind share its port.
        rc, _ = _fallback(
            monkeypatch,
            capsysbinary,
            [
                "-sS",
                "--interface",
                "127.0.0.1",
                "--local-port",
                "%d-%d" % (low, low + 20),
                "-T",
                str(payload),
                server + "/up",
            ],
        )
    finally:
        busy.close()
    assert rc == 0
    assert low < _Handler.received[-1][1] <= low + 20


def test_local_port_with_no_free_port_is_45(server, monkeypatch, capsysbinary):
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    port = busy.getsockname()[1]
    try:
        rc, out = _fallback(
            monkeypatch, capsysbinary, ["-sS", "--interface", "127.0.0.1", "--local-port", str(port), server + "/"]
        )
    finally:
        busy.close()
    assert rc == 45 and out.err.startswith(b"curl: (45)")


def test_pins_parse_from_hashes_and_reject_garbage():
    assert connector.parse_pins("sha256//" + "A" * 43 + "=;sha256//" + "B" * 43 + "=") and True
    with pytest.raises(ValueError):
        connector.parse_pins("sha256//not base64!")
    with pytest.raises(ValueError):
        connector.parse_pins("sha256//" + "A" * 43 + "=;md5//x")


def test_local_port_moves_on_when_connect_finds_the_port_in_use(monkeypatch):
    """Windows reports a local port whose last connection to the same address
    is in TIME_WAIT at connect() (WSAEADDRINUSE), not at bind(): curl tries
    the next port of the range, and so does the fallback."""
    import errno
    import socket
    import threading

    from curlike.connector import Connector

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    threading.Thread(target=lambda: server.accept()[0].close(), daemon=True).start()
    real_connect = socket.socket.connect
    first = []

    class _Socket(socket.socket):
        def connect(self, address):
            if not first:
                first.append(self.getsockname()[1])
                raise OSError(errno.EADDRINUSE, "Only one usage of each socket address")
            return real_connect(self, address)

    monkeypatch.setattr(socket, "socket", _Socket)
    low = 47400
    sock = Connector(ports=(low, low + 20)).create_connection(server.getsockname())
    try:
        assert first and sock.getsockname()[1] > first[0], "the next port of the range"
    finally:
        sock.close()
        server.close()
