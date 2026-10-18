"""The curl shim's fallback at its edges, against a loopback origin: exit
codes are curl's (an HTTP status is a response, -f is 22, transport 6/7/28),
-I prints headers, -m/-u/-e/--compressed/--max-redirs are honoured, several
-d join, a body gets the form Content-Type, -H removes and sends empty, -b
sends only the rows that apply to the URL, -c keeps HttpOnly and expiry, -V
answers, an unsupported flag is `curl: (2) …` and never a traceback.
"""
import gzip
import io
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from curlike import shim as curl
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)


class _Edge(BaseHTTPRequestHandler):
    seen = []

    def _reply(self, status, body=b"", extra=()):
        self.send_response(status)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        _Edge.seen.append((self.command, self.path, dict(self.headers), body))
        if self.path == "/404":
            return self._reply(404, b"nope")
        if self.path == "/redirect":
            return self._reply(302, b"", [("Location", "/x")])
        if self.path == "/loop":
            return self._reply(302, b"", [("Location", "/loop")])
        if self.path == "/gz":
            return self._reply(200, gzip.compress(b"unzipped"), [("Content-Encoding", "gzip")])
        if self.path == "/setcookie":
            return self._reply(200, b"ok", [
                ("Set-Cookie", "sid=abc; Path=/; HttpOnly; Max-Age=3600"),
                ("Set-Cookie", "flash=1; Path=/"),
            ])
        if self.path == "/echo":
            payload = json.dumps({
                "method": self.command, "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body.decode("utf-8", "replace"),
            }).encode()
            return self._reply(200, payload, [("Content-Type", "application/json")])
        return self._reply(200, b"hello")

    do_GET = do_POST = do_HEAD = do_PUT = _handle

    def log_message(self, *a):
        pass


class _Server(HTTPServer):
    def server_bind(self):
        import socketserver

        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "localhost", self.server_address[1]


@pytest.fixture()
def origin():
    _Edge.seen = []
    httpd = _Server(("127.0.0.1", 0), _Edge)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _echo(out):
    return json.loads(out.out.decode("utf-8"))


# --------------------------------------------------------------------------- #
# exit codes
# --------------------------------------------------------------------------- #


def test_an_http_error_status_is_a_response_not_a_failure(origin, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", origin + "/404"])
    assert rc == 0 and out.out == b"nope"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-i", origin + "/redirect"])
    assert rc == 0 and out.out.startswith(b"HTTP/1.1 302")


def test_fail_flag_is_exit_22_without_a_body(origin, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "-f", origin + "/404"])
    assert rc == 22 and out.out == b""
    assert b"curl: (22) The requested URL returned error: 404" in out.err
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-f", origin + "/x"])
    assert rc == 0 and out.out == b"hello"


def test_transport_failures_use_curl_exit_codes(monkeypatch, capsysbinary):
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "http://127.0.0.1:%d/x" % port])
    assert rc == 7 and out.err.startswith(b"curl: (7) Failed to connect")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "http://nonexistent.invalid/x"])
    assert rc == 6 and out.err.startswith(b"curl: (6) Could not resolve host")


def test_unsupported_flag_is_exit_2_one_line(origin, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--http2", origin + "/x"])
    assert rc == 2 and out.err.strip() == b"curl: (2) Unsupported options: --http2"


def test_version_answers(monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-V"])
    assert rc == 0 and out.out.startswith(b"curl ") and b"shim" in out.out


# --------------------------------------------------------------------------- #
# headers, body, flags
# --------------------------------------------------------------------------- #


def test_head_prints_the_headers_by_itself(origin, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-I", origin + "/x"])
    assert rc == 0 and out.out.startswith(b"HTTP/1.1 200") and b"hello" not in out.out
    assert _Edge.seen[-1][0] == "HEAD"


def test_several_d_join_and_a_body_gets_the_form_content_type(origin, tmp_path, monkeypatch, capsysbinary):
    f = tmp_path / "part.txt"
    f.write_bytes(b"c=3\r\n")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-d", "a=1", "-d", "b=2", "-d", "@" + str(f), origin + "/echo"])
    seen = _echo(out)
    assert rc == 0 and seen["method"] == "POST" and seen["body"] == "a=1&b=2&c=3"
    assert seen["headers"]["content-type"] == "application/x-www-form-urlencoded"
    # An explicit Content-Type is kept; --data-binary keeps the file's bytes.
    rc, out = _fallback(monkeypatch, capsysbinary, [
        "-s", "-H", "Content-Type: application/json", "--data-binary", "@" + str(f), origin + "/echo"])
    seen = _echo(out)
    assert seen["headers"]["content-type"] == "application/json" and seen["body"] == "c=3\r\n"


def test_d_from_stdin(origin, monkeypatch, capsysbinary):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"from=stdin")))
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-d", "@-", origin + "/echo"])
    assert rc == 0 and _echo(out)["body"] == "from=stdin"


def test_header_removal_and_empty_forms(origin, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, [
        "-s", "-H", "User-Agent:", "-H", "X-Empty;", "-H", "accept-encoding: br", origin + "/echo"])
    headers = _echo(out)["headers"]
    assert rc == 0
    assert "user-agent" not in headers, "`Name:` removes the header, the shim's default included"
    assert headers["x-empty"] == "", "`Name;` sends it empty"
    assert headers["accept-encoding"] == "br", "case-insensitive: one Accept-Encoding, the caller's"


def test_user_referer_compressed_and_max_time(origin, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, [
        "-s", "-m", "5", "-u", "me:pw", "-e", "http://ref/", "--compressed", origin + "/echo"])
    headers = _echo(out)["headers"]
    assert rc == 0
    assert headers["authorization"] == "Basic bWU6cHc="
    assert headers["referer"] == "http://ref/"
    assert headers["accept-encoding"] == "gzip, deflate"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--compressed", origin + "/gz"])
    assert rc == 0 and out.out == b"unzipped", "the body is decoded"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", origin + "/gz"])
    assert gzip.decompress(out.out) == b"unzipped", "without --compressed the bytes come as sent"


def test_location_follows_and_max_redirs_caps(origin, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-L", origin + "/redirect"])
    assert rc == 0 and out.out == b"hello"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "-L", "--max-redirs", "2", origin + "/loop"])
    assert rc != 0 and sum(1 for c, p, h, b in _Edge.seen if p == "/loop") <= 4


# --------------------------------------------------------------------------- #
# cookies: -b filtered, -c faithful
# --------------------------------------------------------------------------- #


def test_b_sends_only_the_rows_that_apply(origin, tmp_path, monkeypatch, capsysbinary):
    later = str(int(time.time()) + 3600)
    jar = tmp_path / "jar.txt"
    jar.write_text("\n".join([
        "# Netscape HTTP Cookie File",
        "\t".join(["127.0.0.1", "FALSE", "/", "FALSE", "0", "host", "1"]),
        "\t".join(["#HttpOnly_127.0.0.1", "FALSE", "/", "FALSE", later, "hidden", "2"]),
        "\t".join(["other.example", "FALSE", "/", "FALSE", "0", "foreign", "3"]),
        "\t".join(["127.0.0.1", "FALSE", "/admin", "FALSE", "0", "elsewhere", "4"]),
        "\t".join(["127.0.0.1", "FALSE", "/", "TRUE", "0", "onlyhttps", "5"]),
        "\t".join(["127.0.0.1", "FALSE", "/", "FALSE", "1000000000", "expired", "6"]),
        "\t".join([".0.0.1", "TRUE", "/", "FALSE", "0", "sub", "7"]),
    ]) + "\n", encoding="utf-8")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-b", str(jar), origin + "/echo"])
    assert rc == 0
    cookie = _echo(out)["headers"]["cookie"]
    # As curl 8.17 / 8.22 send this jar: a Secure cookie goes to 127.0.0.1 over
    # http (a secure context), .0.0.1 does not cover an IP address, and the
    # order is curl's (longest path, domain, name first).
    assert cookie == "onlyhttps=5; hidden=2; host=1", cookie


def test_c_writes_httponly_and_expiry_on_top_of_b(origin, tmp_path, monkeypatch, capsysbinary):
    jar = tmp_path / "jar.txt"
    jar.write_text("\t".join(["127.0.0.1", "FALSE", "/", "FALSE", "0", "flash", "old"]) + "\n", encoding="utf-8")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-b", str(jar), "-c", str(jar), origin + "/setcookie"])
    assert rc == 0
    rows = {r.split("\t")[5]: r.split("\t") for r in jar.read_text(encoding="utf-8").splitlines() if not r.startswith("# ")}
    assert rows["sid"][0] == "#HttpOnly_127.0.0.1" and int(rows["sid"][4]) > int(time.time()) + 3000
    assert rows["flash"][6] == "1", "the response's value replaces the jar's"
    # ... and the file reads back: the HttpOnly row is sent, the session row too.
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-b", str(jar), origin + "/echo"])
    assert sorted(_echo(out)["headers"]["cookie"].split("; ")) == ["flash=1", "sid=abc"]

