"""The request head as curl writes it (defaults, repeated and removed -H,
UTF-8 values) and response header bytes written back as they came."""

import socket
import threading

import pytest

import curlike
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)


class _Raw(object):
    """A server that records each request head and answers ``reply``."""

    def __init__(self, reply):
        self.reply = reply
        self.heads = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.url = "http://127.0.0.1:%d" % self.listener.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            data = b""
            while b"\r\n\r\n" not in data:
                piece = conn.recv(65536)
                if not piece:
                    break
                data += piece
            self.heads.append(data)
            conn.sendall(self.reply)
            conn.close()

    def lines(self):
        return self.heads[-1].split(b"\r\n")[:-2]


@pytest.fixture()
def raw():
    servers = []

    def make(reply=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"):
        servers.append(_Raw(reply))
        return servers[-1]

    yield make
    for server in servers:
        server.listener.close()


def test_the_default_request_is_curls(raw, monkeypatch, capsysbinary):
    server = raw()
    rc, _ = _fallback(monkeypatch, capsysbinary, ["-s", server.url + "/x"])
    lines = server.lines()
    assert rc == 0 and lines[0] == b"GET /x HTTP/1.1"
    assert b"Accept: */*" in lines and b"User-Agent: curl/8.22.0" in lines
    assert not [line for line in lines if line.lower().startswith(b"accept-encoding")]
    assert b"Connection: close" in lines


def test_a_repeated_h_sends_every_line_and_replaces_only_its_default(raw, monkeypatch, capsysbinary):
    server = raw()
    _fallback(monkeypatch, capsysbinary, ["-s", "-H", "X-A: 1", "-H", "X-A: 2", "-H", "Accept: text/plain", server.url])
    lines = server.lines()
    assert lines.count(b"X-A: 1") == 1 and lines.count(b"X-A: 2") == 1
    assert b"Accept: text/plain" in lines and b"Accept: */*" not in lines


@pytest.mark.parametrize(
    "removed,extra",
    [("Host", []), ("Connection", []), ("Accept-Encoding", ["--compressed"]), ("Content-Type", ["-d", "a=1"])],
)
def test_h_with_no_value_removes_what_the_stack_would_add(removed, extra, raw, monkeypatch, capsysbinary):
    server = raw()
    _fallback(monkeypatch, capsysbinary, ["-s", *extra, "-H", removed + ":", server.url])
    assert not [line for line in server.lines()[1:] if line.lower().startswith(removed.lower().encode() + b":")]


def test_header_values_go_out_as_utf8(raw, monkeypatch, capsysbinary):
    server = raw()
    _fallback(monkeypatch, capsysbinary, ["-s", "-H", "X-N: café", "-A", "agent-é", server.url])
    assert "X-N: café".encode("utf-8") in server.lines()
    assert "User-Agent: agent-é".encode("utf-8") in server.lines()


LATIN = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nX-Latin: caf\xe9\r\n\r\nok"


def test_response_header_bytes_come_back_as_they_were(raw, tmp_path, monkeypatch, capsysbinary):
    server = raw(LATIN)
    dump = tmp_path / "h"
    rc, out = _fallback(
        monkeypatch, capsysbinary, ["-s", "-i", "-D", str(dump), "-w", "[%header{x-latin}]", server.url]
    )
    assert out.out.startswith(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nX-Latin: caf\xe9\r\n\r\nok")
    assert out.out.endswith(b"[caf\xe9]")
    assert dump.read_bytes() == b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nX-Latin: caf\xe9\r\n\r\n"


def test_a_write_out_file_is_read_and_written_as_bytes(raw, tmp_path, monkeypatch, capsysbinary):
    server = raw()
    fmt = tmp_path / "fmt"
    fmt.write_bytes(b"[\xff\xfe%{http_code}]")
    rc, out = _fallback(
        monkeypatch,
        capsysbinary,
        ["-s", "-o", "NUL" if __import__("os").name == "nt" else "/dev/null", "-w", "@" + str(fmt), server.url],
    )
    assert rc == 0 and out.out == b"[\xff\xfe200]"


@pytest.mark.parametrize("path", ["/a b", "/a\x01b", "/a\x7fb"])
def test_a_url_curl_rejects_is_3_and_nothing_is_sent(path, raw, monkeypatch, capsysbinary):
    server = raw()
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", server.url + path])
    assert rc == 3 and b"URL rejected" in out.err and server.heads == []


def test_a_non_ascii_url_is_percent_encoded_as_utf8(raw, monkeypatch, capsysbinary):
    server = raw()
    rc, _ = _fallback(monkeypatch, capsysbinary, ["-s", server.url + "/café?q=é"])
    assert rc == 0 and server.lines()[0] == b"GET /caf%C3%A9?q=%C3%A9 HTTP/1.1"
