"""The curl fallback's download, auth, TLS, connection and alias options.
Expected values were recorded from curl 8.21 against the same kind of
loopback server (range, ETag, Last-Modified, Content-Disposition, Digest)."""
import base64
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from test_curl_options import pki, tls_origin  # noqa: F401  (fixtures reused)
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)

BODY = b"0123456789abcdefghij"
LM = "Tue, 01 Sep 2026 10:00:00 GMT"
LM_TS = 1788256800
ETAG = '"v1"'


class _Files(BaseHTTPRequestHandler):
    """/f: 20 bytes with ranges, ETag, Last-Modified; /norange ignores
    ranges; /cd names the file ../evil/named.txt; /digest wants Digest;
    /404; /echo reports method, Host and Authorization."""

    seen = []

    def _any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        _Files.seen.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}, body))
        auth = self.headers.get("Authorization") or ""
        if self.path.startswith("/digest"):
            if not auth.startswith("Digest "):
                return self._send(401, b"", [("WWW-Authenticate", 'Digest realm="r", nonce="abc", qop="auth"')])
            return self._send(200, auth.split('username="', 1)[1].split('"', 1)[0].encode())
        if self.path.startswith("/echo"):
            who = base64.b64decode(auth[6:]).decode() if auth.startswith("Basic ") else "-"
            return self._send(200, ("%s %s %s" % (self.command, self.headers.get("Host"), who)).encode())
        if self.path.startswith("/404"):
            return self._send(404, b"missing")
        if self.path.startswith("/norange"):
            return self._send(200, BODY)
        if self.headers.get("If-None-Match") == ETAG or self.headers.get("If-Modified-Since") == LM:
            return self._send(304, b"")
        rng = self.headers.get("Range")
        if rng and rng.startswith("bytes="):
            start = int(rng[6:].split("-")[0] or 0)
            if start >= len(BODY):
                return self._send(416, b"", [("Content-Range", "bytes */%d" % len(BODY))])
            return self._send(206, BODY[start:], [("Content-Range", "bytes %d-%d/%d" % (start, len(BODY) - 1, len(BODY)))])
        extra = [("Content-Disposition", 'attachment; filename="../evil/named.txt"')] if self.path.startswith("/cd") else []
        return self._send(200, BODY, extra)

    def _send(self, code, body, extra=()):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Last-Modified", LM)
        self.send_header("ETag", ETAG)
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_HEAD = _any

    def log_message(self, *a):
        pass


@pytest.fixture()
def files():
    _Files.seen = []
    httpd = HTTPServer(("127.0.0.1", 0), _Files)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _run(monkeypatch, capsysbinary, tmp_path, argv):
    monkeypatch.chdir(tmp_path)
    return _fallback(monkeypatch, capsysbinary, argv)


# --------------------------------------------------------------------------- #
# downloads
# --------------------------------------------------------------------------- #


def test_remote_header_name_strips_directories_and_never_overwrites(files, tmp_path, monkeypatch, capsysbinary):
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "-O", "-J", files + "/cd"])
    assert rc == 0 and (tmp_path / "named.txt").read_bytes() == BODY and not (tmp_path / "evil").exists()
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "-O", "-J", files + "/cd"])
    assert rc == 23 and b"refusing to overwrite" in out.err


def test_remote_time_sets_the_mtime(files, tmp_path, monkeypatch, capsysbinary):
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "-O", "-R", files + "/f.bin"])
    assert rc == 0 and int(os.path.getmtime(tmp_path / "f.bin")) == LM_TS


def test_resume(files, tmp_path, monkeypatch, capsysbinary):
    part = tmp_path / "part"
    part.write_bytes(BODY[:5])
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "-C", "-", "-o", "part", files + "/f"])
    assert rc == 0 and part.read_bytes() == BODY and _Files.seen[-1][2]["range"] == "bytes=5-"
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "-C", "-", "-o", "part", files + "/f"])
    assert rc == 0 and part.read_bytes() == BODY, "a 416 to a complete file: done"
    part.write_bytes(BODY[:5])
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "-C", "-", "-o", "part", files + "/norange"])
    assert rc == 33 and part.read_bytes() == BODY[:5] and b"Cannot resume" in out.err
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "-C", "7", files + "/f"])
    assert rc == 0 and out.out == BODY[7:]


def test_time_condition(files, tmp_path, monkeypatch, capsysbinary):
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "-z", LM, "-o", "o", files + "/f"])
    assert rc == 0 and not (tmp_path / "o").exists() and _Files.seen[-1][2]["if-modified-since"] == LM
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "-z", "-" + LM, "-o", "o", files + "/f"])
    assert rc == 0 and not (tmp_path / "o").exists(), "a value starting with - is a value; curl finds it unmet"
    assert _Files.seen[-1][2]["if-unmodified-since"] == LM
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-S", "-z", "notadate", "-o", "o", files + "/f"])
    assert rc == 0 and (tmp_path / "o").read_bytes() == BODY and b"Illegal date format" in out.err


def test_etags(files, tmp_path, monkeypatch, capsysbinary):
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "--etag-save", "e.txt", "-o", "o", files + "/f"])
    assert rc == 0 and (tmp_path / "e.txt").read_bytes() == b'"v1"\n'
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "--etag-compare", "e.txt", "-o", "o2", files + "/f"])
    assert rc == 0 and not (tmp_path / "o2").exists() and _Files.seen[-1][2]["if-none-match"] == '"v1"'
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "--etag-compare", "nope.txt", "-o", "o3", files + "/f"])
    assert rc == 0 and _Files.seen[-1][2]["if-none-match"] == '""'


def test_existing_files(files, tmp_path, monkeypatch, capsysbinary):
    (tmp_path / "f.bin").write_bytes(b"old")
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "--no-clobber", "-O", files + "/f.bin"])
    assert rc == 0 and (tmp_path / "f.bin").read_bytes() == b"old" and (tmp_path / "f.bin.1").read_bytes() == BODY
    _Files.seen = []
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "--skip-existing", "-O", files + "/f.bin"])
    assert rc == 0 and _Files.seen == [], "nothing is even requested"


def test_max_filesize_and_remove_on_error(files, tmp_path, monkeypatch, capsysbinary):
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "--max-filesize", "10", "-o", "o", files + "/f"])
    assert rc == 63 and not (tmp_path / "o").exists() and b"(63) Maximum file size exceeded" in out.err
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "--max-filesize", "1k", "-o", "o", files + "/f"])
    assert rc == 0
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "--fail-with-body", "--remove-on-error", "-o", "gone", files + "/404"])
    assert rc == 22 and not (tmp_path / "gone").exists()


# --------------------------------------------------------------------------- #
# auth
# --------------------------------------------------------------------------- #


def _echo_user(out):
    return out.out.decode().rsplit(" ", 1)[-1]


def test_credential_precedence(files, tmp_path, monkeypatch, capsysbinary):
    port = files.rsplit(":", 1)[1]
    home = tmp_path / "home"
    home.mkdir()
    for name in (".netrc", "_netrc"):
        (home / name).write_text("machine 127.0.0.1 login huser password hpw\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    netrc = tmp_path / "rc"
    netrc.write_text("machine other login x password y\ndefault login duser password dpw\n", encoding="utf-8")
    userinfo = "http://uuser:upw@127.0.0.1:%s/echo" % port
    cases = [
        ([userinfo], "uuser:upw"),
        (["-u", "cli:cpw", userinfo], "cli:cpw"),
        (["--netrc-file", str(netrc), files + "/echo"], "duser:dpw"),
        (["-n", files + "/echo"], "huser:hpw"),
        (["-n", userinfo], "uuser:upw"),
        (["--netrc-optional", files + "/echo"], "huser:hpw"),
        (["-n", "-u", "cli:cpw", files + "/echo"], "cli:cpw"),
    ]
    for argv, expected in cases:
        rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-s", *argv])
        assert rc == 0 and _echo_user(out) == expected, argv


def test_netrc_failures(files, tmp_path, monkeypatch, capsysbinary):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "-n", files + "/echo"])
    assert rc == 26 and b".netrc error: no such file" in out.err
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "--netrc-file", str(tmp_path / "nope"), files + "/echo"])
    assert rc == 2
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "--netrc-optional", files + "/echo"])
    assert rc == 0 and _echo_user(out) == "-"


def test_digest(files, tmp_path, monkeypatch, capsysbinary):
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "--digest", "-u", "me:pw", files + "/digest"])
    assert rc == 0 and out.out == b"me"
    assert "authorization" not in _Files.seen[0][2], "nothing sent before the challenge"


# --------------------------------------------------------------------------- #
# connection control
# --------------------------------------------------------------------------- #


def test_resolve_and_connect_to_keep_the_host(files, tmp_path, monkeypatch, capsysbinary):
    port = files.rsplit(":", 1)[1]
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "--resolve", "fake.example:%s:127.0.0.1" % port,
                                                         "http://fake.example:%s/echo" % port])
    assert rc == 0 and out.out.split()[1] == ("fake.example:%s" % port).encode()
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "--connect-to", "fake.example:80:127.0.0.1:%s" % port,
                                                         "http://fake.example/echo"])
    assert rc == 0 and out.out.split()[1] == b"fake.example"
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "--connect-to", "::127.0.0.1:%s" % port, "http://any.example/echo"])
    assert rc == 0 and out.out.split()[1] == b"any.example"
    assert socket.getaddrinfo.__module__ == "socket", "restored after the transfer"


def test_address_family(files, tmp_path, monkeypatch, capsysbinary):
    port = files.rsplit(":", 1)[1]
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "-4", "http://localhost:%s/echo" % port])
    assert rc == 0
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "-6", "--connect-timeout", "3", "http://localhost:%s/echo" % port])
    assert rc in (6, 7), "the server listens on IPv4 only"


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="no AF_UNIX sockets here")
def test_unix_socket(tmp_path, monkeypatch, capsysbinary):
    import socketserver

    path = str(tmp_path / "s.sock")

    class _UnixHTTP(socketserver.UnixStreamServer):
        def get_request(self):
            request, _ = super().get_request()
            return request, ("local", 0)

    server = _UnixHTTP(path, _Files)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "--unix-socket", path, "http://docker/echo"])
        assert rc == 0 and out.out.split()[1] == b"docker"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.skipif(hasattr(socket, "AF_UNIX"), reason="AF_UNIX available")
def test_unix_socket_refused_without_af_unix(tmp_path, monkeypatch, capsysbinary):
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "--unix-socket", "x.sock", "http://docker/echo"])
    assert rc == 2 and b"AF_UNIX" in out.err


def test_values_starting_with_a_dash(files, tmp_path, monkeypatch, capsysbinary):
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "-d", "-1", files + "/echo"])
    assert rc == 0 and _Files.seen[-1][3] == b"-1"
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "-H", "-x", files + "/echo"])
    assert rc == 2, "curl takes -x as the header value, and an invalid header is a usage error"


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #


def test_tls_versions_and_ciphers(pki, tls_origin, tmp_path, monkeypatch, capsysbinary):
    ca = ["--cacert", str(pki / "ca.pem")]
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-s", *ca, "--tlsv1.2", "--tls-max", "1.2", tls_origin + "/x"])
    assert rc == 0
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-s", *ca, "--tlsv1.3", tls_origin + "/x"])
    assert rc == 0
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", *ca, "--tlsv1.3", "--tls-max", "1.2", tls_origin + "/x"])
    assert rc == 35, "no version both ends accept: a failed handshake, not a certificate problem"
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", *ca, "--ciphers", "NOT-A-CIPHER", tls_origin + "/x"])
    assert rc == 59 and b"(59) failed setting cipher list" in out.err
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-s", *ca, "--tls-max", "9", tls_origin + "/x"])
    assert rc == 2


# --------------------------------------------------------------------------- #
# aliases, no-ops, --stderr, short aliases of refused flags
# --------------------------------------------------------------------------- #


def test_aliases_and_no_ops(files, tmp_path, monkeypatch, capsysbinary):
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "--data-ascii", "a=1", files + "/echo"])
    assert rc == 0 and _Files.seen[-1][3] == b"a=1"
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "--show-headers", files + "/echo"])
    assert rc == 0 and b"ETag: " in out.out
    for flag in ("--ssl-no-revoke", "--ssl-revoke-best-effort", "--ca-native", "--proxy-ca-native", "--no-keepalive",
                 "--tcp-nodelay", "--no-alpn", "--no-npn", "--no-sessionid", "--styled-output"):
        rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-s", flag, files + "/echo"])
        assert rc == 0, flag
    rc, _ = _run(monkeypatch, capsysbinary, tmp_path, ["-s", "--keepalive-time", "30", files + "/echo"])
    assert rc == 0


def test_stderr_goes_to_a_file(tmp_path, monkeypatch, capsysbinary):
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-sS", "--stderr", "err.txt", "http://127.0.0.1:1/x"])
    assert rc == 7 and out.err == b"" and "curl: (7)" in (tmp_path / "err.txt").read_text(encoding="utf-8")


@pytest.mark.parametrize("short, long", [("-K", "--config"), ("-Z", "--parallel"), ("-a", "--append"),
                                         ("-B", "--use-ascii"), ("-Q", "--quote")])
def test_short_aliases_of_refused_flags_are_refused_in_one_line(short, long, tmp_path, monkeypatch, capsysbinary):
    argv = [short, "x"] if short in ("-K", "-Q") else [short]
    rc, out = _run(monkeypatch, capsysbinary, tmp_path, ["-s", *argv, "http://127.0.0.1:1/"])
    assert rc == 2 and out.err.strip() == ("curl: (2) Unsupported options: %s" % long).encode()
