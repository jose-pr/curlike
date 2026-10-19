"""A server's 401 answered once: Digest (MD5, SHA-256), Basic under --anyauth;
a rejected credential is not sent again, and a challenge nothing here can
answer is the response."""

import hashlib
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)


class _Server(BaseHTTPRequestHandler):
    requests = []
    offer = ['Digest realm="r\\"x", nonce="n0nce", qop="auth", algorithm=MD5']

    def do_GET(self):
        auth = self.headers.get("Authorization")
        _Server.requests.append(auth)
        if auth and self._valid(auth):
            body = b"welcome"
            self.send_response(200)
        else:
            body = b"denied"
            self.send_response(401)
            for challenge in _Server.offer:
                self.send_header("WWW-Authenticate", challenge)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _valid(self, auth):
        if auth.startswith("Basic "):
            import base64

            return base64.b64decode(auth[6:]) == b"me:pw"
        fields = {
            key: quoted or plain
            for key, quoted, plain in re.findall(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))', auth[7:])
        }
        algorithm = fields.get("algorithm", "MD5")
        digest = {"MD5": hashlib.md5, "SHA-256": hashlib.sha256}[algorithm]

        def h(text):
            return digest(text.encode()).hexdigest()

        realm = fields["realm"].replace('\\"', '"')
        ha1, ha2 = h("me:%s:pw" % realm), h("GET:%s" % fields["uri"])
        want = h(":".join([ha1, "n0nce", fields["nc"], fields["cnonce"], "auth", ha2]))
        return fields["response"] == want

    def log_message(self, *a):
        pass


@pytest.fixture()
def server():
    _Server.requests = []
    _Server.offer = ['Digest realm="r\\"x", nonce="n0nce", qop="auth", algorithm=MD5']
    srv = HTTPServer(("127.0.0.1", 0), _Server)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d/p" % srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize("algorithm", ["MD5", "SHA-256"])
def test_digest_answers_the_challenge(algorithm, server, monkeypatch, capsysbinary):
    _Server.offer = ['Digest realm="r\\"x", nonce="n0nce", qop="auth", algorithm=%s' % algorithm]
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--digest", "-u", "me:pw", server])
    assert rc == 0 and out.out == b"welcome"
    assert len(_Server.requests) == 2 and _Server.requests[0] is None


def test_a_rejected_password_is_sent_once_and_the_401_is_the_response(server, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--digest", "-u", "me:bad", server])
    assert rc == 0 and out.out == b"denied"
    assert len(_Server.requests) == 2, "the request, and one answer to the challenge"


def test_anyauth_falls_back_to_basic(server, monkeypatch, capsysbinary):
    _Server.offer = ['Basic realm="x"']
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--anyauth", "-u", "me:pw", server])
    assert rc == 0 and out.out == b"welcome" and len(_Server.requests) == 2


@pytest.mark.parametrize("offer", [["Negotiate"], ["Bearer realm=x"], ['Basic realm="x"']])
def test_a_challenge_nothing_answers_is_the_response(offer, server, monkeypatch, capsysbinary):
    _Server.offer = offer
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--digest", "-u", "me:pw", server])
    assert rc == 0 and out.out == b"denied" and len(_Server.requests) == 1


def test_the_credential_does_not_follow_a_redirect_to_another_origin(monkeypatch, capsysbinary):
    class _Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", _Redirect.target)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    first = HTTPServer(("127.0.0.1", 0), _Redirect)
    second = HTTPServer(("127.0.0.1", 0), _Server)
    _Server.requests = []
    _Server.offer = ["Digest realm=\"r\", nonce=\"n0nce\", qop=\"auth\""]
    _Redirect.target = "http://127.0.0.1:%d/p" % second.server_address[1]
    for srv in (first, second):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = "http://127.0.0.1:%d/" % first.server_address[1]
        rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-L", "--digest", "-u", "me:pw", url])
        assert out.out == b"denied" and _Server.requests == [None]
        rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--location-trusted", "--digest", "-u", "me:pw", url])
        assert out.out == b"welcome"
    finally:
        for srv in (first, second):
            srv.shutdown()
            srv.server_close()
