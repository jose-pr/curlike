"""curl shim: real-curl-first path + PATH-stripped stdlib fallback returns 200.

No real internet: the fallback is exercised against a local HTTP fixture server
bound to 127.0.0.1; the real-curl path is mocked (shutil.which + subprocess.run).
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from curlike import shim as curl


# --------------------------------------------------------------------------
# Local HTTP fixture (127.0.0.1, ephemeral port) -- no external network.
# --------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    def _reply(self, body=b"ok"):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/notfound":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._reply(b"hello")

    def do_HEAD(self):
        self._reply()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._reply(b"posted")

    def log_message(self, *a):  # silence
        pass


@pytest.fixture()
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    try:
        yield "http://127.0.0.1:%d" % port
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------
# 1. Real-curl-first path.
# --------------------------------------------------------------------------
def test_prefers_real_system_curl(monkeypatch):
    calls = {}

    monkeypatch.setattr(curl, "find_real_curl", lambda *a: "/usr/bin/curl")

    class _Res:
        returncode = 0

    def _fake_run(cmd, *a, **k):
        calls["cmd"] = cmd
        return _Res()

    monkeypatch.setattr(curl.subprocess, "run", _fake_run)

    rc = curl.main(["https://example.com"])
    assert rc == 0
    # It delegated to the real curl binary with the original argv.
    assert calls["cmd"][0] == "/usr/bin/curl"
    assert calls["cmd"][1:] == ["https://example.com"]


def test_real_curl_exit_code_propagates(monkeypatch):
    monkeypatch.setattr(curl, "find_real_curl", lambda *a: "/usr/bin/curl")

    class _Res:
        returncode = 22

    monkeypatch.setattr(curl.subprocess, "run", lambda *a, **k: _Res())
    assert curl.main(["https://example.com"]) == 22


# --------------------------------------------------------------------------
# 2. PATH-stripped fallback (no real curl) -> pure-stdlib urllib path.
# --------------------------------------------------------------------------
def test_fallback_get_returns_200(server, monkeypatch, capsysbinary):
    # Simulate curl absent from PATH.
    monkeypatch.setattr(curl, "find_real_curl", lambda *a: None)
    rc = curl.main([server + "/"])
    assert rc == 0
    out = capsysbinary.readouterr().out
    assert b"hello" in out


def test_fallback_head_returns_200_no_body(server, monkeypatch, capsysbinary):
    monkeypatch.setattr(curl, "find_real_curl", lambda *a: None)
    rc = curl.main(["-I", server + "/"])
    assert rc == 0
    out = capsysbinary.readouterr().out
    # -i/-I: with -I curl prints headers only; include is not set so with -I the
    # shim writes no body. Status line appears only with -i/-I include; here -I
    # sets head, body suppressed.
    assert b"hello" not in out


def test_fallback_include_headers(server, monkeypatch, capsysbinary):
    monkeypatch.setattr(curl, "find_real_curl", lambda *a: None)
    rc = curl.main(["-i", server + "/"])
    assert rc == 0
    out = capsysbinary.readouterr().out
    assert out.startswith(b"HTTP/1.1 200")
    assert b"hello" in out


def test_fallback_post_data(server, monkeypatch, capsysbinary):
    monkeypatch.setattr(curl, "find_real_curl", lambda *a: None)
    rc = curl.main(["-d", "k=v", server + "/submit"])
    assert rc == 0
    out = capsysbinary.readouterr().out
    assert b"posted" in out


def test_fallback_404_is_a_response_and_fail_makes_it_22(server, monkeypatch, capsysbinary):
    """curl's exit codes: an HTTP status is a printed response (exit 0);
    -f turns a 4xx/5xx into exit 22 with no body."""
    monkeypatch.setattr(curl, "find_real_curl", lambda *a: None)
    assert curl.main(["-s", server + "/notfound"]) == 0
    assert curl.main(["-s", "-f", server + "/notfound"]) == 22


def test_fallback_output_to_file(server, monkeypatch, tmp_path):
    monkeypatch.setattr(curl, "find_real_curl", lambda *a: None)
    dest = tmp_path / "body.txt"
    rc = curl.main(["-s", "-o", str(dest), server + "/"])
    assert rc == 0
    assert dest.read_bytes() == b"hello"


# --------------------------------------------------------------------------
# 3. Unsupported flags must fail loud (never silently mis-behave).
# --------------------------------------------------------------------------
def test_unsupported_flag_is_refused_out_loud(monkeypatch, capsysbinary):
    """An unsupported flag is curl's exit 2 with one line on stderr -- never
    a traceback, never a silent mis-handling."""
    monkeypatch.setattr(curl, "find_real_curl", lambda *a: None)
    assert curl.main(["--http2", "https://example.com"]) == 2
    err = capsysbinary.readouterr().err
    assert err.strip() == b"curl: (2) Unsupported options: --http2"
    with pytest.raises(NotImplementedError):
        curl.run_fallback(["--http2", "https://example.com"])


# --------------------------------------------------------------------------
# 4. certifi shim reachable from the shim's lib/ (SSL context path).
# --------------------------------------------------------------------------
def test_ssl_context_insecure(monkeypatch):
    from curlike.tls import build_ssl_context

    ctx = build_ssl_context(insecure=True)
    import ssl

    assert ctx.verify_mode == ssl.CERT_NONE
