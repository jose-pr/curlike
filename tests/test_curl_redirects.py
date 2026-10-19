"""-L as curl follows it (expected values recorded from curl 8.21): credentials
go to the next hop only on the same origin unless --location-trusted, a -b
FILE's cookies are re-chosen per hop from the jar, and the method/body rules
of 301/302/303/307/308, --post30x and -X hold."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)


class _Hop(BaseHTTPRequestHandler):
    """/r/<code>/<target>: redirect to <target> (a full URL, %-free); anything
    else records method, body, Authorization and Cookie."""

    seen = {}

    def _any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        if self.path.startswith("/r/"):
            code, target = self.path[3:6], self.path[7:]
            self.send_response(int(code))
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/c/"):  # a cookie, then on to the target
            self.send_response(302)
            self.send_header("Set-Cookie", "hop=1; Path=/")
            self.send_header("Location", self.path[3:])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        _Hop.seen[self.server.server_address[1]] = {
            "method": self.command,
            "body": body.decode(),
            "auth": self.headers.get("Authorization"),
            "cookie": self.headers.get("Cookie"),
        }
        self.send_response(200)
        if self.path == "/fin":
            self.send_header("Set-Cookie", "fin=1; Path=/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = do_PUT = do_HEAD = _any

    def log_message(self, *a):
        pass


@pytest.fixture()
def hosts():
    """Two origins (two ports on 127.0.0.1)."""
    _Hop.seen = {}
    servers = [HTTPServer(("127.0.0.1", 0), _Hop) for _ in range(2)]
    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        yield ["http://127.0.0.1:%d" % s.server_address[1] for s in servers]
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()


def _landed(url):
    return _Hop.seen.get(int(url.rsplit(":", 1)[1]), {})


CREDENTIALS = {
    "-u": (["-u", "me:pw"], "auth"),
    "-H Authorization": (["-H", "Authorization: Bearer hdr"], "auth"),
    "--oauth2-bearer": (["--oauth2-bearer", "tok"], "auth"),
    "-H Cookie": (["-H", "Cookie: h=1"], "cookie"),
    "-b string": (["-b", "b=1"], "cookie"),
}


@pytest.mark.parametrize("label", sorted(CREDENTIALS))
@pytest.mark.parametrize("trusted", [False, True])
def test_credentials_follow_only_the_same_origin(label, trusted, hosts, monkeypatch, capsysbinary):
    flags, field = CREDENTIALS[label]
    a, b = hosts
    extra = ["--location-trusted"] if trusted else []
    _fallback(monkeypatch, capsysbinary, ["-s", "-L", *extra, *flags, "%s/r/302/%s/landed" % (a, a)])
    assert _landed(a)[field], "same origin: kept"
    _fallback(monkeypatch, capsysbinary, ["-s", "-L", *extra, *flags, "%s/r/302/%s/landed" % (a, b)])
    assert bool(_landed(b)[field]) is trusted, "another origin: only with --location-trusted"


def test_a_cookie_file_is_rechosen_per_hop(hosts, tmp_path, monkeypatch, capsysbinary):
    a, b = hosts
    jar = tmp_path / "jar.txt"
    jar.write_text(
        "\n".join(
            "\t".join(row)
            for row in [
                ["127.0.0.1", "FALSE", "/", "FALSE", "0", "shared", "1"],
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _fallback(monkeypatch, capsysbinary, ["-s", "-L", "-b", str(jar), "%s/r/302/%s/landed" % (a, b)])
    assert _landed(b)["cookie"] == "shared=1", "the jar's rows apply to the next host by the jar's rules"


# (flags) -> the landing hop's method/body for 301 302 303 307 308, as curl 8.21 does it.
METHODS = [
    ([], ["GET/", "GET/", "GET/", "POST/x=1", "POST/x=1"]),
    (["--post301", "--post302", "--post303"], ["POST/x=1"] * 5),
    (["-X", "PUT"], ["PUT/", "PUT/", "PUT/", "PUT/x=1", "PUT/x=1"]),
]


@pytest.mark.parametrize("flags, expected", METHODS)
def test_redirect_methods_and_bodies(flags, expected, hosts, monkeypatch, capsysbinary):
    a, _b = hosts
    got = []
    for code in (301, 302, 303, 307, 308):
        _Hop.seen = {}
        rc, _ = _fallback(
            monkeypatch, capsysbinary, ["-s", "-L", "-d", "x=1", *flags, "%s/r/%d/%s/landed" % (a, code, a)]
        )
        hop = _landed(a)
        got.append("%s/%s" % (hop.get("method"), hop.get("body")))
    assert got == expected


def _jar_rows(path):
    return sorted(
        (cols[0], cols[5])
        for cols in (line.split("	") for line in path.read_text(encoding="utf-8").splitlines())
        if len(cols) == 7
    )


def test_a_hops_cookies_reach_the_next_hop_and_the_jar(hosts, tmp_path, monkeypatch, capsysbinary):
    a, b = hosts
    jar = tmp_path / "jar.txt"
    rc, _ = _fallback(monkeypatch, capsysbinary, ["-s", "-L", "-c", str(jar), "%s/c/%s/fin" % (a, b)])
    assert rc == 0 and _landed(b)["cookie"] == "hop=1"
    assert _jar_rows(jar) == [("127.0.0.1", "fin"), ("127.0.0.1", "hop")]


def test_the_last_responses_cookie_is_filed_under_the_last_host(hosts, tmp_path, monkeypatch, capsysbinary):
    a, b = hosts
    other = b.replace("127.0.0.1", "localhost")
    jar = tmp_path / "jar.txt"
    rc, _ = _fallback(monkeypatch, capsysbinary, ["-s", "-L", "-c", str(jar), "%s/r/302/%s/fin" % (a, other)])
    assert rc == 0 and _jar_rows(jar) == [("localhost", "fin")]


def test_credentials_come_back_with_the_first_origin(hosts, monkeypatch, capsysbinary):
    a, b = hosts
    away = "%s/r/302/%s/r/302/%s/landed" % (a, b, a)
    _fallback(monkeypatch, capsysbinary, ["-s", "-L", "-u", "me:pw", away])
    assert _landed(a)["auth"], "a hop back to the first origin carries the credentials again"
    assert not _landed(b).get("auth"), "and the hop in between did not"


def test_more_hops_than_urllib_allowed(hosts, monkeypatch, capsysbinary):
    a, _b = hosts
    chain = "%s/r/302/" * 12 + "%s/landed"
    rc, _ = _fallback(monkeypatch, capsysbinary, ["-s", "-L", chain % ((a,) * 13)])
    assert rc == 0 and _landed(a)["method"] == "GET"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "-L", "--max-redirs", "3", chain % ((a,) * 13)])
    assert rc == 47 and b"Maximum (3) redirects followed" in out.err
