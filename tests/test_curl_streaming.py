"""The body is delivered as it arrives, not after it is all read: -N hands
pieces on at once, --max-filesize stops a body of unknown length at the cap,
--compressed decodes piece by piece, -T reads its file as it sends it."""

import gzip
import subprocess
import sys
import threading
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from curlike.delivery import Decoder, EncodingError
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)


class _Handler(BaseHTTPRequestHandler):
    proceed = threading.Event()
    uploaded = None

    def do_GET(self):
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Length", "10")
            self.end_headers()
            self.wfile.write(b"first")
            self.wfile.flush()
            _Handler.proceed.wait(10)
            self.wfile.write(b"-last")
        elif self.path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for _ in range(3):
                self.wfile.write(b"64\r\n" + b"x" * 100 + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif self.path == "/cut":
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"short")
        elif self.path == "/gzip":
            body = gzip.compress(b"hello ") + gzip.compress(b"world")
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/gzip-cut":
            body = gzip.compress(b"hello world" * 100)[:-8]
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    def do_PUT(self):
        _Handler.uploaded = (self.headers.get("Content-Length"), self.rfile.read(int(self.headers["Content-Length"])))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture()
def server():
    _Handler.proceed = threading.Event()
    _Handler.uploaded = None
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d" % srv.server_address[1]
    finally:
        _Handler.proceed.set()
        srv.shutdown()
        srv.server_close()


def test_n_hands_the_first_bytes_on_before_the_body_ends(server):
    proc = subprocess.Popen(
        [sys.executable, "-m", "curlike", "-sN", server + "/stream"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        assert proc.stdout.read(5) == b"first"  # blocks forever if the body is held back
        _Handler.proceed.set()
        assert proc.stdout.read() == b"-last"
    finally:
        _Handler.proceed.set()
        proc.stdout.close()
        proc.stderr.close()
        proc.wait(10)


def test_max_filesize_stops_a_body_of_unknown_length(server, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--max-filesize", "150", server + "/chunked"])
    assert rc == 63 and b"Maximum file size exceeded" in out.err
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--max-filesize", "1000", server + "/chunked"])
    assert rc == 0 and out.out == b"x" * 300


def test_o_prints_no_progress_line(server, tmp_path, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-o", str(tmp_path / "f"), server + "/x"])
    assert rc == 0 and out.err == b"" and (tmp_path / "f").read_bytes() == b"ok"


def test_compressed_members_follow_one_another(server, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--compressed", server + "/gzip"])
    assert rc == 0 and out.out == b"hello world"


def test_a_gzip_body_cut_short_is_61(server, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--compressed", server + "/gzip-cut"])
    assert rc == 61 and b"(61) Error while processing content unencoding" in out.err


def test_a_file_is_uploaded_as_it_is_read(server, tmp_path, monkeypatch, capsysbinary):
    path = tmp_path / "big.bin"
    data = bytes(range(256)) * 2000  # 512000 bytes
    path.write_bytes(data)
    rc, _ = _fallback(monkeypatch, capsysbinary, ["-s", "-T", str(path), server + "/up"])
    assert rc == 0 and _Handler.uploaded == (str(len(data)), data)


@pytest.mark.parametrize("wrap", [zlib.compress, lambda d: zlib.compress(d)[2:-4], gzip.compress])
def test_the_decoder_takes_the_body_in_any_pieces(wrap):
    plain = b"abcdefghij" * 500
    packed = wrap(plain)
    name = "gzip" if wrap is gzip.compress else "deflate"
    decoder = Decoder([("Content-Encoding", name)])
    out = b"".join(decoder.feed(packed[i : i + 7]) for i in range(0, len(packed), 7)) + decoder.finish()
    assert out == plain


def test_the_decoder_refuses_what_it_cannot_undo():
    with pytest.raises(EncodingError):
        Decoder([("Content-Encoding", "br")])
    assert Decoder([("Content-Encoding", "identity")]).feed(b"as is") == b"as is"


def test_remove_on_error_removes_a_file_this_run_overwrote(server, tmp_path, monkeypatch, capsysbinary):
    target = tmp_path / "out"
    target.write_bytes(b"OLD CONTENT")
    rc, _ = _fallback(monkeypatch, capsysbinary, ["-s", "--remove-on-error", "-o", str(target), server + "/cut"])
    assert rc == 18 and not target.exists()
    target.write_bytes(b"OLD CONTENT")
    rc, _ = _fallback(monkeypatch, capsysbinary, ["-s", "-o", str(target), server + "/cut"])
    assert rc == 18 and target.read_bytes() == b"short", "without the flag what arrived stays"


def test_no_process_wide_setting_is_changed(server, monkeypatch, capsysbinary):
    import http.client
    import socket

    before = http.client._MAXLINE, http.client._MAXHEADERS, socket.getaddrinfo
    port = server.rsplit(":", 1)[1]
    rc, _ = _fallback(
        monkeypatch,
        capsysbinary,
        ["-s", "--resolve", "named.test:%s:127.0.0.1" % port, "http://named.test:%s/x" % port],
    )
    assert rc == 0
    assert (http.client._MAXLINE, http.client._MAXHEADERS, socket.getaddrinfo) == before
