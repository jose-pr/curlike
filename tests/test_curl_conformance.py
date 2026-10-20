"""Small conformance points of output files, cookie arguments, bodies and
usage errors, each measured against curl 8.21."""

import base64
import io
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import curlike
from curlike import download
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)


class _Server(BaseHTTPRequestHandler):
    """/cd/<name> answers with that Content-Disposition; any other path echoes
    the request as JSON, setting the cookie ``hop`` on /cookie."""

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path.startswith("/cd/"):
            payload = b"data"
            self.send_response(200)
            self.send_header("Content-Disposition", base64.b64decode(self.path[4:]).decode())
        else:
            payload = json.dumps(
                {
                    "method": self.command,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": body.decode("latin-1"),
                }
            ).encode()
            self.send_response(200)
            if self.path.startswith("/cookie"):
                self.send_header("Set-Cookie", "hop=1; Path=/")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_HEAD = _answer

    def log_message(self, *a):
        pass


@pytest.fixture()
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Server)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _seen(out):
    return json.loads(out.out)


def _disposition(value):
    return "/cd/" + base64.b64encode(value.encode()).decode()


@pytest.mark.parametrize(
    "header,expected",
    [
        ('attachment; filename="a/b/c.txt"', "c.txt"),
        ("attachment; xfilename=evil.txt; filename=good.txt", "good.txt"),
        ('attachment; filename="..\\\\up.txt"', "up.txt"),
    ],
)
def test_j_takes_the_file_name_from_a_parameter_start_without_directories(
    header, expected, server, tmp_path, monkeypatch, capsysbinary
):
    monkeypatch.chdir(tmp_path)
    rc, _ = _fallback(
        monkeypatch, capsysbinary, ["-s", "-OJ", "--output-dir", str(tmp_path), server + _disposition(header)]
    )
    assert rc == 0 and (tmp_path / expected).read_bytes() == b"data"


@pytest.mark.parametrize(
    "name,expected",
    [
        ("C:evil", "C_evil"),
        ("a:b", "a_b"),
        ("CON", "_CON"),
        ("nul.txt", "_nul.txt"),
        ('x<y>"z|?*', "x_y__z___"),
        ("ok.txt", "ok.txt"),
    ],
)
def test_the_windows_file_name_curl_makes(name, expected):
    assert download.windows_name(name) == expected


def test_a_jar_that_cannot_be_written_does_not_fail_the_transfer(server, tmp_path, monkeypatch, capsysbinary):
    rc, out = _fallback(
        monkeypatch, capsysbinary, ["-s", "-c", str(tmp_path / "no" / "such" / "jar"), server + "/cookie"]
    )
    assert rc == 0 and out.out


def test_an_etag_file_that_cannot_be_created_is_26_before_anything_is_sent(server, tmp_path, monkeypatch, capsysbinary):
    rc, out = _fallback(
        monkeypatch, capsysbinary, ["-s", "--etag-save", str(tmp_path / "no" / "such" / "etag"), server + "/x"]
    )
    assert rc == 26 and b"curl: no transfer performed" in out.err and out.out == b""


def test_b_is_a_file_unless_it_holds_an_equals_sign(server, tmp_path, monkeypatch, capsysbinary):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "x=y").write_text("# Netscape HTTP Cookie File\n")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-b", "nofile", server + "/x"])
    assert "cookie" not in _seen(out)["headers"], "a name with no '=' is a (missing) file: nothing is sent"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-b", "x=y", server + "/x"])
    assert _seen(out)["headers"]["cookie"] == "x=y", "with an '=' it is the cookie, though a file has that name"


def test_b_dash_reads_the_jar_from_stdin(server, monkeypatch, capsysbinary):
    jar = "127.0.0.1\tFALSE\t/\tFALSE\t0\tfrom\tstdin\n"
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(jar.encode())))
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-b", "-", server + "/x"])
    assert _seen(out)["headers"]["cookie"] == "from=stdin"


def test_c_dash_writes_the_jar_to_stdout_after_the_body(server, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-c", "-", server + "/cookie"])
    assert rc == 0 and out.out.index(b'"method"') < out.out.index(b"# Netscape HTTP Cookie File")
    assert b"127.0.0.1\tFALSE\t/\tFALSE\t0\thop\t1" in out.out


def test_i_with_x_sends_that_method_and_reads_the_headers_only(server, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-i", "-I", "-X", "POST", server + "/x"])
    assert rc == 0 and out.out.startswith(b"HTTP/1.0 200") and b'"method"' not in out.out


def test_a_data_file_that_is_not_there_is_curls_three_lines(server, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-d", "@no-such-file", server + "/x"])
    assert rc == 26 and out.err.splitlines() == [
        b"curl: Failed to open no-such-file",
        b"curl: option -d: error encountered when reading a file",
        b"curl: try 'curl --help' or 'curl --manual' for more information",
    ]


def test_t_sends_no_content_type_and_adds_no_name_to_a_url_with_a_query(server, tmp_path, monkeypatch, capsysbinary):
    path = tmp_path / "up.txt"
    path.write_text("hi")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-T", str(path), server + "/?q=1"])
    seen = _seen(out)
    assert seen["path"] == "/?q=1" and "content-type" not in seen["headers"]
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-T", str(path), server + "/dir/"])
    assert _seen(out)["path"] == "/dir/up.txt"


def test_o_with_no_name_in_the_url_is_curl_response(server, tmp_path, monkeypatch, capsysbinary):
    monkeypatch.chdir(tmp_path)
    rc, _ = _fallback(monkeypatch, capsysbinary, ["-s", "-O", server + "/"])
    assert rc == 0 and (tmp_path / "curl_response").is_file()


@pytest.mark.parametrize(
    "argv,line",
    [
        (["http://a/", "http://b/"], b"curl: (2) more than one URL (http://b/): the fallback makes one transfer"),
        (["--no-such-flag", "http://a/"], b"curl: option --no-such-flag: is unknown"),
        (["-m"], b"curl: option -m: requires parameter"),
    ],
)
def test_a_usage_error_is_curls_two_lines(argv, line, capsysbinary):
    rc = curlike.main(argv)
    assert rc == 2
    assert capsysbinary.readouterr().err.splitlines() == [
        line,
        b"curl: try 'curl --help' or 'curl --manual' for more information",
    ]


def test_json_writes_empty_addresses_when_nothing_connected(capsysbinary):
    closed = __import__("socket").socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    rc = curlike.main(["-s", "-w", "%{json}", "http://127.0.0.1:%d/" % port])
    data = json.loads(capsysbinary.readouterr().out)
    assert rc == 7 and data["remote_ip"] == "" and data["local_ip"] == ""


def test_the_form_pieces_curl_understands(server, tmp_path, monkeypatch, capsysbinary):
    (tmp_path / "semi;colon.txt").write_text("s")
    (tmp_path / "a.json").write_text("{}")
    monkeypatch.chdir(tmp_path)
    rc, out = _fallback(
        monkeypatch,
        capsysbinary,
        ["-s", "-F", 'f=@"semi;colon.txt";type=text/plain;charset=utf-8', "-F", "g=@a.json", server + "/x"],
    )
    body = _seen(out)["body"]
    assert 'filename="semi;colon.txt"' in body and "Content-Type: text/plain;charset=utf-8" in body
    assert 'filename="a.json"' in body and "Content-Type: application/octet-stream" in body
