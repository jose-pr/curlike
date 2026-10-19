"""``-c`` stores what a server may set: a ``Domain`` the host does not
domain-match is dropped (syshttp's RFC 6265 rules)."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)


class _Planter(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Set-Cookie", "own=1; Path=/")
        self.send_header("Set-Cookie", "foreign=1; Domain=example.com; Path=/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def test_a_cookie_for_another_domain_is_not_stored(tmp_path, monkeypatch, capsysbinary):
    server = HTTPServer(("127.0.0.1", 0), _Planter)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        jar = tmp_path / "jar.txt"
        url = "http://127.0.0.1:%d/" % server.server_address[1]
        rc, _ = _fallback(monkeypatch, capsysbinary, ["-s", "-c", str(jar), url])
    finally:
        server.shutdown()
        server.server_close()
    assert rc == 0
    names = [l.split("\t")[5] for l in jar.read_text(encoding="utf-8").splitlines() if l and not l.startswith("#")]
    assert names == ["own"]


def test_a_cookie_without_a_path_gets_the_request_directory(tmp_path, monkeypatch, capsysbinary):
    class _NoPath(_Planter):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Set-Cookie", "dp=1")
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), _NoPath)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        jar = tmp_path / "jar.txt"
        url = "http://127.0.0.1:%d/a/b" % server.server_address[1]
        rc, _ = _fallback(monkeypatch, capsysbinary, ["-s", "-c", str(jar), url])
    finally:
        server.shutdown()
        server.server_close()
    rows = [l.split("\t") for l in jar.read_text(encoding="utf-8").splitlines() if l and not l.startswith("#")]
    assert rc == 0 and [(r[2], r[5]) for r in rows] == [("/a", "dp")]
