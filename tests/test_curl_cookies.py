"""``-c`` stores what a server may set: a ``Domain`` the host does not
domain-match is dropped (syshttp's RFC 6265 rules)."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)


def _syshttp_has_domain_rules():
    """Whether the installed syshttp drops a foreign ``Domain`` (0.1.0.dev8 on)."""
    from syshttp.cookies import set_cookie_specs

    return not set_cookie_specs(["f=1; Domain=example.com"], "127.0.0.1")


class _Planter(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Set-Cookie", "own=1; Path=/")
        self.send_header("Set-Cookie", "foreign=1; Domain=example.com; Path=/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.mark.skipif(not _syshttp_has_domain_rules(), reason="needs syshttp's RFC 6265 cookie rules (0.1.0.dev8)")
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
