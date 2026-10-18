"""The fallback's option groups beyond the basics: TLS (--cacert, --capath,
--cert / --key / --pass), request shaping (--json, -G, --data-urlencode,
--url-query, -F, -T, -r, --oauth2-bearer, --basic), output (-O,
--output-dir, --create-dirs, --fail-with-body), --retry, the no-ops, curl's
default scheme -- and the mixin composition itself.

The TLS tests build a throwaway CA, server and client certificates with the
`openssl` binary (Git for Windows ships one) and skip where there is none.
"""

import base64
import email
import email.policy
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from curlike import transfer
from curlike.args import Group
from curlike.options import CurlCmd, build_parser
from curlike.tls import split_cert
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)

# --------------------------------------------------------------------------- #
# origins
# --------------------------------------------------------------------------- #


class _Echo(BaseHTTPRequestHandler):
    """Echoes the request as JSON; /flaky fails with 503 `_Echo.flaky` times."""

    flaky = 0
    retry_after = None

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path.startswith("/flaky") and _Echo.flaky > 0:
            _Echo.flaky -= 1
            self.send_response(503)
            if _Echo.retry_after is not None:
                self.send_header("Retry-After", _Echo.retry_after)
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"busy")
            return
        if self.path.startswith("/404"):
            self.send_response(404)
            self.send_header("Content-Length", "7")
            self.end_headers()
            self.wfile.write(b"missing")
            return
        payload = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": base64.b64encode(body).decode("ascii"),
                "client": getattr(self, "client_cn", None),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = _handle

    def log_message(self, *a):
        pass


class _Quiet(HTTPServer):
    def handle_error(self, request, client_address):
        pass  # a refused TLS handshake is the point of some tests


def _serve(handler, context=None):
    httpd = _Quiet(("127.0.0.1", 0), handler)
    if context is not None:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture()
def echo():
    _Echo.flaky, _Echo.retry_after = 0, None
    httpd = _serve(_Echo)
    try:
        yield "http://127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _seen(out):
    data = json.loads(out.out.decode("utf-8").split("\n")[0] if out.out.startswith(b"{") else out.out)
    data["body"] = base64.b64decode(data["body"])
    return data


# --------------------------------------------------------------------------- #
# the composition
# --------------------------------------------------------------------------- #


def test_no_field_is_shadowed_by_a_method():
    """A field is an attribute of the parsed object: one named like a group's
    method would replace it (and break every caller of that method)."""
    for action in build_parser()._actions:
        if action.dest == "help":
            continue
        assert not callable(getattr(CurlCmd, action.dest, None)), action.dest


def test_the_groups_compose_in_order():
    """The refused flags are checked first; the help reads request, body, output..."""
    groups = [
        k.__name__
        for k in CurlCmd.__mro__
        if isinstance(k, type) and issubclass(k, Group) and k not in (Group, CurlCmd)
    ]
    assert groups[0] == "UnsupportedArgs" and groups[-4:] == ["BodyArgs", "AuthArgs", "RequestArgs", "ShimArgs"]
    lines = [ln.strip() for ln in build_parser().format_help().splitlines()]
    # "-X METHOD, --request METHOD" before 3.13, "-X, --request METHOD" after.
    where = [
        next(i for i, ln in enumerate(lines) if ln.startswith(flag + " ") or ln.startswith(flag + ","))
        for flag in ("-X", "-d", "-o", "-b")
    ]
    assert where == sorted(where)


def test_a_refused_flag_wins_over_a_conflict(monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["--http2", "-f", "--fail-with-body", "http://h/"])
    assert rc == 2 and out.err.strip() == b"curl: (2) Unsupported options: --http2"


def test_refused_flags_are_hidden_from_help():
    text = build_parser().format_help()
    assert "--http2" not in text and "--json" in text and "Pure Python curl-like tool" in text


# --------------------------------------------------------------------------- #
# request shaping
# --------------------------------------------------------------------------- #


def test_json_sets_both_headers_and_concatenates(echo, tmp_path, monkeypatch, capsysbinary):
    part = tmp_path / "part.json"
    part.write_bytes(b',"b":2}')
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--json", '{"a":1', "--json", "@" + str(part), echo + "/j"])
    seen = _seen(out)
    assert rc == 0 and seen["method"] == "POST" and seen["body"] == b'{"a":1,"b":2}'
    assert seen["headers"]["content-type"] == "application/json" and seen["headers"]["accept"] == "application/json"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--json", "{}", "-H", "Accept: text/plain", echo])
    assert _seen(out)["headers"]["accept"] == "text/plain", "-H wins"


def test_data_urlencode_forms_in_command_line_order(echo, tmp_path, monkeypatch, capsysbinary):
    f = tmp_path / "v.txt"
    f.write_bytes(b"x y&z")
    rc, out = _fallback(
        monkeypatch,
        capsysbinary,
        [
            "-s",
            "--data-urlencode",
            "a b",
            "-d",
            "raw=1",
            "--data-urlencode",
            "=c d",
            "--data-urlencode",
            "n=e=f",
            "--data-urlencode",
            "file@" + str(f),
            echo,
        ],
    )
    assert rc == 0 and _seen(out)["body"] == b"a%20b&raw=1&c%20d&n=e%3Df&file=x%20y%26z"


def test_get_moves_the_data_into_the_query(echo, monkeypatch, capsysbinary):
    rc, out = _fallback(
        monkeypatch, capsysbinary, ["-s", "-G", "-d", "q=1", "--data-urlencode", "s=a b", echo + "/find"]
    )
    seen = _seen(out)
    assert rc == 0 and seen["method"] == "GET" and seen["path"] == "/find?q=1&s=a%20b" and seen["body"] == b""


def test_url_query_encodes_or_keeps(echo, monkeypatch, capsysbinary):
    rc, out = _fallback(
        monkeypatch, capsysbinary, ["-s", "--url-query", "a=b c", "--url-query", "+raw=%41", echo + "/q?x=1"]
    )
    assert rc == 0 and _seen(out)["path"] == "/q?x=1&a=b%20c&raw=%41"


def test_bearer_basic_and_range(echo, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--oauth2-bearer", "tok", "-r", "0-9", echo])
    headers = _seen(out)["headers"]
    assert rc == 0 and headers["authorization"] == "Bearer tok" and headers["range"] == "bytes=0-9"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--basic", "-u", "me:pw", echo])
    assert _seen(out)["headers"]["authorization"] == "Basic bWU6cHc="


def test_form_builds_multipart(echo, tmp_path, monkeypatch, capsysbinary):
    upload = tmp_path / "photo.png"
    upload.write_bytes(b"\x89PNG-bytes")
    note = tmp_path / "note.txt"
    note.write_bytes(b"from a file")
    rc, out = _fallback(
        monkeypatch,
        capsysbinary,
        [
            "-s",
            "-F",
            "field=value",
            "-F",
            "file=@%s" % upload,
            "-F",
            "text=<%s" % note,
            "-F",
            "doc=@%s;type=text/markdown;filename=renamed.md" % note,
            "--form-string",
            "lit=@not-a-file",
            echo,
        ],
    )
    seen = _seen(out)
    assert rc == 0 and seen["method"] == "POST"
    ctype = seen["headers"]["content-type"]
    assert ctype.startswith("multipart/form-data; boundary=")
    message = email.message_from_bytes(
        ("Content-Type: %s\r\n\r\n" % ctype).encode() + seen["body"], policy=email.policy.HTTP
    )
    parts = {p.get_param("name", header="content-disposition"): p for p in message.iter_parts()}
    assert parts["field"].get_payload(decode=True) == b"value" and parts["field"].get_filename() is None
    assert parts["file"].get_filename() == "photo.png" and parts["file"].get_content_type() == "image/png"
    assert parts["file"].get_payload(decode=True) == b"\x89PNG-bytes"
    assert parts["text"].get_payload(decode=True) == b"from a file" and parts["text"].get_filename() is None
    assert parts["doc"].get_filename() == "renamed.md" and parts["doc"].get_content_type() == "text/markdown"
    assert parts["lit"].get_payload(decode=True) == b"@not-a-file"


def test_form_and_data_together_is_exit_2(echo, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-F", "a=1", "-d", "b=2", echo])
    assert rc == 2 and out.err.startswith(b"curl: (2) You can only select one HTTP request method!")


def test_upload_file_puts_and_names_the_url(echo, tmp_path, monkeypatch, capsysbinary):
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x00payload")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-T", str(f), echo + "/dir/"])
    seen = _seen(out)
    assert rc == 0 and seen["method"] == "PUT" and seen["path"] == "/dir/data.bin" and seen["body"] == b"\x00payload"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-T", str(f), "-X", "POST", echo + "/exact"])
    assert _seen(out)["method"] == "POST" and _seen(out)["path"] == "/exact"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "-T", str(tmp_path / "nope"), echo + "/"])
    assert rc == 26 and out.err.startswith(b"curl: (26)")


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #


def test_remote_name_output_dir_and_create_dirs(echo, tmp_path, monkeypatch, capsysbinary):
    monkeypatch.chdir(tmp_path)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-O", echo + "/files/report.json"])
    assert rc == 0 and (tmp_path / "report.json").is_file()
    rc, out = _fallback(
        monkeypatch,
        capsysbinary,
        [
            "-s",
            "--create-dirs",
            "--output-dir",
            str(tmp_path / "a" / "b"),
            "-O",
            "-w",
            "%{filename_effective}",
            echo + "/x.json",
        ],
    )
    assert rc == 0 and (tmp_path / "a" / "b" / "x.json").is_file()
    assert out.out.decode() == os.path.join(str(tmp_path / "a" / "b"), "x.json")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "-O", echo + "/"])
    assert rc == 23 and b"Remote file name has no length" in out.err


def test_fail_with_body_keeps_the_body(echo, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--fail-with-body", echo + "/404"])
    assert rc == 22 and out.out == b"missing" and b"curl: (22)" in out.err
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-f", "--fail-with-body", echo + "/404"])
    assert rc == 2 and b"either --fail or --fail-with-body" in out.err


def test_no_ops_are_accepted(echo, monkeypatch, capsysbinary):
    for flag in (
        "-g",
        "--globoff",
        "--http1.1",
        "-N",
        "--no-buffer",
        "-#",
        "--progress-bar",
        "--no-progress-meter",
        "-q",
        "--disable",
    ):
        rc, out = _fallback(monkeypatch, capsysbinary, [flag, "-s", echo + "/x"])
        assert rc == 0 and _seen(out)["path"] == "/x", flag


def test_scheme_defaults_to_http_and_others_are_refused(echo, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", echo[len("http://") :] + "/bare"])
    assert rc == 0 and _seen(out)["path"] == "/bare"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "ftp://example.com/f"])
    assert rc == 2 and out.err.strip() == b"curl: (2) Unsupported protocol: ftp"


# --------------------------------------------------------------------------- #
# --retry
# --------------------------------------------------------------------------- #


@pytest.fixture()
def naps(monkeypatch):
    slept = []
    monkeypatch.setattr(transfer, "sleep", slept.append)
    return slept


def test_retry_a_transient_status_with_backoff(echo, naps, monkeypatch, capsysbinary):
    _Echo.flaky = 2
    rc, out = _fallback(monkeypatch, capsysbinary, ["--retry", "3", echo + "/flaky"])
    assert rc == 0 and _seen(out)["path"] == "/flaky" and naps == [1.0, 2.0]
    assert b"Warning: Problem : HTTP error. Will retry in 1 second. 3 retries left." in out.err
    assert b"Will retry in 2 seconds. 2 retries left." in out.err


def test_retry_gives_up_with_the_last_answer(echo, naps, monkeypatch, capsysbinary):
    _Echo.flaky = 5
    rc, out = _fallback(
        monkeypatch, capsysbinary, ["-s", "--retry", "1", "--retry-delay", "3", "-w", "%{http_code}", echo + "/flaky"]
    )
    assert rc == 0 and out.out == b"busy503" and naps == [3.0]


def test_retry_after_is_honoured(echo, naps, monkeypatch, capsysbinary):
    _Echo.flaky, _Echo.retry_after = 1, "7"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--retry", "2", echo + "/flaky"])
    assert rc == 0 and naps == [7.0]


def test_retry_connrefused_and_all_errors(echo, naps, monkeypatch, capsysbinary):
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    dead = "http://127.0.0.1:%d/x" % port
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--retry", "2", dead])
    assert rc == 7 and naps == [], "a refused connection is not transient by default"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--retry", "2", "--retry-connrefused", dead])
    assert rc == 7 and naps == [1.0, 2.0]
    del naps[:]
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-f", "--retry", "1", "--retry-all-errors", echo + "/404"])
    assert rc == 22 and naps == [1.0]
    del naps[:]
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-f", "--retry", "1", echo + "/404"])
    assert rc == 22 and naps == [], "a 404 is not transient"


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #


def _openssl():
    found = shutil.which("openssl")
    if found:
        return found
    git = shutil.which("git")
    if git:
        candidate = Path(git).resolve().parents[1] / "usr" / "bin" / "openssl.exe"
        if candidate.is_file():
            return str(candidate)
    return None


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A CA, a server certificate for 127.0.0.1 and a client certificate,
    made with the openssl binary; skipped without one."""
    openssl = _openssl()
    if not openssl:
        pytest.skip("no openssl binary to make test certificates with")
    d = tmp_path_factory.mktemp("pki")

    def run(*argv):
        subprocess.run([openssl, *argv], cwd=str(d), check=True, capture_output=True)

    run(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "3650",
        "-subj",
        "/CN=net-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
    )
    for name, cn, extra in (
        ("server", "127.0.0.1", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"),
        ("client", "net-test-client", "extendedKeyUsage=clientAuth\n"),
    ):
        (d / (name + ".ext")).write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "authorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n" + extra,
            encoding="ascii",
        )
        run(
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            name + ".key",
            "-out",
            name + ".csr",
            "-subj",
            "/CN=" + cn,
        )
        run(
            "x509",
            "-req",
            "-in",
            name + ".csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-set_serial",
            "2" if name == "server" else "3",
            "-out",
            name + ".pem",
            "-days",
            "3650",
            "-extfile",
            name + ".ext",
        )
    run("pkey", "-in", "client.key", "-aes256", "-passout", "pass:s3cret", "-out", "client-enc.key")
    (d / "client-combined.pem").write_bytes((d / "client.pem").read_bytes() + (d / "client.key").read_bytes())
    (d / "client-combined-enc.pem").write_bytes((d / "client.pem").read_bytes() + (d / "client-enc.key").read_bytes())
    digest = subprocess.run(
        [openssl, "x509", "-hash", "-noout", "-in", str(d / "ca.pem")], check=True, capture_output=True, text=True
    ).stdout.strip()
    (d / "capath").mkdir()
    shutil.copy(str(d / "ca.pem"), str(d / "capath" / (digest + ".0")))
    return d


class _TLSEcho(_Echo):
    def setup(self):
        _Echo.setup(self)
        cert = self.connection.getpeercert() or {}
        self.client_cn = next((v for rdn in cert.get("subject", ()) for k, v in rdn if k == "commonName"), None)


@pytest.fixture()
def tls_origin(pki):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pki / "server.pem"), str(pki / "server.key"))
    context.load_verify_locations(str(pki / "ca.pem"))
    context.verify_mode = ssl.CERT_OPTIONAL
    httpd = _serve(_TLSEcho, context)
    try:
        yield "https://127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_cacert_and_capath_verify_the_server(pki, tls_origin, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--cacert", str(pki / "ca.pem"), tls_origin + "/x"])
    assert rc == 0 and _seen(out)["client"] is None
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--capath", str(pki / "capath"), tls_origin + "/x"])
    assert rc == 0
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", tls_origin + "/x"])
    assert rc == 60, "the test CA is not in the OS trust store"
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-k", tls_origin + "/x"])
    assert rc == 0


@pytest.mark.parametrize(
    "flags",
    [
        ["--cert", "{d}/client.pem", "--key", "{d}/client.key"],
        ["-E", "{d}/client-combined.pem"],
        ["--cert", "{d}/client.pem", "--key", "{d}/client-enc.key", "--pass", "s3cret"],
        ["--cert", "{d}/client-combined-enc.pem:s3cret"],
        ["--cert", "{d}/client-combined.pem", "--cert-type", "pem", "--key-type", "PEM"],
    ],
)
def test_client_certificate(flags, pki, tls_origin, monkeypatch, capsysbinary):
    argv = [f.format(d=pki) for f in flags]
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--cacert", str(pki / "ca.pem"), *argv, tls_origin + "/x"])
    assert rc == 0, out.err
    assert _seen(out)["client"] == "net-test-client"


def test_unusable_tls_files_are_curls_codes(pki, tls_origin, echo, monkeypatch, capsysbinary, tmp_path):
    # A --cacert naming nothing is refused before anything else (curl 8.18+): 2, no -w.
    rc, out = _fallback(
        monkeypatch, capsysbinary, ["-sS", "-w", "%{exitcode}", "--cacert", str(pki / "nope.pem"), tls_origin]
    )
    assert rc == 2 and out.out == b""
    assert out.err.strip() == ("curl: The file '%s' provided to --cacert does not exist" % (pki / "nope.pem")).encode()
    # One that is not a CA bundle fails at the handshake: 77, -w written.
    (tmp_path / "garbage.pem").write_text("not a certificate\n")
    rc, out = _fallback(
        monkeypatch, capsysbinary, ["-sS", "-w", "%{exitcode}", "--cacert", str(tmp_path / "garbage.pem"), tls_origin]
    )
    assert rc == 77 and out.out == b"77" and out.err.startswith(b"curl: (77)")
    # ...and never fails a plain-http transfer, which has no handshake.
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--cacert", str(tmp_path / "garbage.pem"), echo + "/plain"])
    assert rc == 0, out.err
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--capath", str(pki / "nope"), tls_origin])
    assert rc == 77
    rc, out = _fallback(
        monkeypatch, capsysbinary, ["-sS", "--cacert", str(pki / "ca.pem"), "--cert", str(pki / "nope.pem"), tls_origin]
    )
    assert rc == 58 and out.err.startswith(b"curl: (58)")
    rc, out = _fallback(
        monkeypatch,
        capsysbinary,
        [
            "-sS",
            "--cacert",
            str(pki / "ca.pem"),
            "--cert",
            str(pki / "client.pem"),
            "--key",
            str(pki / "client-enc.key"),
            "--pass",
            "wrong",
            tls_origin,
        ],
    )
    assert rc == 58
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--cert-type", "P12", "--cert", "x.p12", tls_origin])
    assert rc == 2 and out.err.strip() == b"curl: (2) Unsupported --cert-type: P12 (the fallback reads PEM only)"


def test_curl_ca_bundle_is_honoured(pki, tls_origin, monkeypatch, capsysbinary):
    monkeypatch.setenv("CURL_CA_BUNDLE", str(pki / "ca.pem"))
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", tls_origin + "/x"])
    assert rc == 0, "curl's own override replaces the OS store, as --cacert does"


# --------------------------------------------------------------------------- #
# shared with syshttp: one implementation for the session and the fallback
# --------------------------------------------------------------------------- #


def test_set_cookie_specs_and_cookie_applies():
    from syshttp.cookies import CookieSpec, cookie_applies, set_cookie_specs

    now = 1_000_000_000.0
    specs = dict(
        (c.name, (c, gone))
        for c, gone in set_cookie_specs(
            [
                "sid=abc; Path=/app; HttpOnly; Secure; Max-Age=60",
                "old=x; Max-Age=0",
                "gone=; Path=/",
                "dom=1; Domain=.example.com",
            ],
            "api.example.com",
            now=now,
        )
    )
    sid, gone = specs["sid"]
    assert not gone and sid.http_only and sid.secure and sid.expires == int(now) + 60 and sid.path == "/app"
    assert specs["old"][1] and specs["gone"][1], "Max-Age=0 and an empty value expire the cookie"
    assert cookie_applies(sid, "https://api.example.com/app/x", now=now)
    assert not cookie_applies(sid, "http://api.example.com/app/x", now=now), "Secure: https only"
    assert not cookie_applies(sid, "https://api.example.com/other", now=now), "path prefix"
    assert not cookie_applies(sid, "https://api.example.com/app", now=now + 61), "expired"
    assert cookie_applies(specs["dom"][0], "http://a.b.example.com/", now=now), "a leading dot covers subdomains"
    flagged = CookieSpec(
        domain="example.com", path="/", secure=False, expires=None, name="f", value="1", subdomains=True
    )
    assert cookie_applies(flagged, "http://www.example.com/") and not cookie_applies(
        CookieSpec("example.com", "/", False, None, "h", "1"), "http://www.example.com/"
    )


def test_netscape_round_trip_keeps_httponly_and_the_flag(tmp_path):
    from syshttp.cookies import CookieSpec, load_netscape, save_netscape

    jar = tmp_path / "jar.txt"
    rows = [
        CookieSpec("h.example", "/", True, 4102444800, "a", "1", http_only=True),
        CookieSpec("example.com", "/", False, None, "b", "2", subdomains=True),
    ]
    save_netscape(rows, jar)
    text = jar.read_text(encoding="utf-8")
    assert "#HttpOnly_h.example\tFALSE\t/\tTRUE\t4102444800\ta\t1" in text
    assert "example.com\tTRUE\t/\tFALSE\t0\tb\t2" in text
    assert load_netscape(jar) == rows


def test_one_proxy_plan_for_both_paths(monkeypatch):
    from syshttp import proxy as agent_proxy

    monkeypatch.setenv("SYSHTTP_PROXY", "http://agent:pw@gw.example:8080")
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
    plan = agent_proxy.plan()
    assert plan.proxy == "http://gw.example:8080" and plan.endpoint == "/fetch/"
    assert plan.gateway_base == "http://gw.example:8080/fetch/" and plan.authorization.startswith("Basic ")
    mine = agent_proxy.plan(proxy="http://mine:1", proxy_user="u:p")
    assert mine.endpoint is None and mine.gateway_base is None, "-x is always a connect proxy"
    assert mine.authorization == agent_proxy.basic_authorization("u", "p")
    assert agent_proxy.plan(noproxy="*").bypasses("https://anything/")


def test_split_cert():
    assert split_cert("c.pem") == ("c.pem", None)
    assert split_cert("c.pem:pw") == ("c.pem", "pw")
    assert split_cert("c.pem:pw:with:colons") == ("c.pem", "pw:with:colons")
    assert split_cert(r"we\:ird.pem:pw") == ("we:ird.pem", "pw")
    if os.name == "nt":
        assert split_cert(r"C:\certs\c.pem:pw") == (r"C:\certs\c.pem", "pw")
        assert split_cert("C:/certs/c.pem") == ("C:/certs/c.pem", None)
