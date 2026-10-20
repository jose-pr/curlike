"""--compressed: curl's limit of five content encodings (exit 61 beyond), and
decoding in bounded pieces, so a small body of nested gzip cannot grow in
memory without limit."""

import gzip
import os
import threading
import tracemalloc
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from curlike.delivery import PIECE, Decoder
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)

MIB = 1 << 20


class _Encoded(BaseHTTPRequestHandler):
    """Answers every request with ``body`` and one ``Content-Encoding`` line
    per entry of ``encodings``."""

    encodings = []
    body = b""

    def _answer(self):
        self.send_response(200)
        for value in _Encoded.encodings:
            self.send_header("Content-Encoding", value)
        self.send_header("Content-Length", str(len(_Encoded.body)))
        self.send_header("Connection", "close")
        self.end_headers()

    def do_GET(self):
        self._answer()
        self.wfile.write(_Encoded.body)

    def do_HEAD(self):
        self._answer()

    def log_message(self, *a):
        pass


@pytest.fixture()
def encoded():
    """``encoded(body, *encodings)`` serves that response; yields its URL."""
    servers = []

    def serve(body, *encodings):
        _Encoded.body, _Encoded.encodings = body, list(encodings)
        if not servers:
            servers.append(HTTPServer(("127.0.0.1", 0), _Encoded))
            threading.Thread(target=servers[0].serve_forever, daemon=True).start()
        return "http://127.0.0.1:%d/" % servers[0].server_address[1]

    yield serve
    for server in servers:
        server.shutdown()
        server.server_close()


def _layers(body, count):
    for _ in range(count):
        body = gzip.compress(body, 1)
    return body


def _bomb(mebibytes):
    """Zeros, gzipped twice: a few hundred bytes that expand about 1000 times
    in each layer."""
    inner = zlib.compressobj(9, zlib.DEFLATED, 31)
    packed = bytearray()
    zeros = bytes(MIB)
    for _ in range(mebibytes):
        packed += inner.compress(zeros)
    packed += inner.flush()
    return gzip.compress(bytes(packed), 9)


def test_a_nested_gzip_bomb_is_decoded_in_bounded_memory(encoded, monkeypatch, capsysbinary):
    mebibytes = 128
    body = _bomb(mebibytes)
    assert len(body) < 4096
    url = encoded(body, "gzip, gzip")
    argv = ["-s", "--compressed", "-o", os.devnull, "-w", "%{size_download} %{size_delivered}", url]
    assert _fallback(monkeypatch, capsysbinary, argv)[0] == 0  # warm: lazy imports are not the decoder's
    tracemalloc.start()
    try:
        rc, out = _fallback(monkeypatch, capsysbinary, argv)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert rc == 0 and out.out == b"%d %d" % (len(body), mebibytes * MIB)
    assert peak < 4 * MIB, "peak %d bytes for a %d-byte body" % (peak, len(body))


@pytest.mark.parametrize(
    "encodings, layers, rc",
    [
        (["gzip, gzip, gzip, gzip, gzip"], 5, 0),
        (["gzip, gzip, gzip", "gzip, gzip"], 5, 0),
        (["gzip, gzip, gzip, gzip, gzip, gzip"], 6, 61),
        (["gzip, gzip, gzip", "gzip, gzip, gzip"], 6, 61),
        (["identity, gzip, gzip, gzip, gzip, gzip"], 5, 61),
        (["identity, identity, identity, identity, identity, identity"], 0, 61),
        (["foo, gzip, gzip, gzip, gzip, gzip"], 5, 61),
    ],
    ids=[
        "five",
        "five-in-two-lines",
        "six",
        "six-in-two-lines",
        "five-and-identity",
        "six-identity",
        "unknown-and-five",
    ],
)
def test_at_most_five_content_encodings(encodings, layers, rc, encoded, monkeypatch, capsysbinary):
    url = encoded(_layers(b"hello", layers), *encodings)
    got, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--compressed", url])
    assert got == rc
    if rc:
        assert out.out == b"" and out.err == b"curl: (61) Reject response exceeding limit of 5 content encodings\n"
    else:
        assert out.out == b"hello"


def test_the_limit_holds_for_a_head_request_and_only_under_compressed(encoded, monkeypatch, capsysbinary):
    body = _layers(b"hello", 6)
    url = encoded(body, ", ".join(["gzip"] * 6))
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--compressed", "-I", url])
    assert rc == 61 and b"(61) Reject response exceeding limit of 5 content encodings" in out.err
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", url])
    assert rc == 0 and out.out == body, "without --compressed nothing is decoded"


@pytest.mark.parametrize("size", [1, PIECE - 1, PIECE, PIECE + 1, 3 * PIECE, MIB])
@pytest.mark.parametrize("layers", [1, 2])
def test_the_decoder_hands_on_pieces_of_at_most_piece_bytes(size, layers):
    plain = bytes(size)  # one long run: output stays inside zlib when the input has ended
    decoder = Decoder([("Content-Encoding", ", ".join(["gzip"] * layers))])
    pieces = list(decoder.feed(_layers(plain, layers)))
    decoder.finish()
    assert b"".join(pieces) == plain and max(map(len, pieces)) <= PIECE
