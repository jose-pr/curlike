"""HTTPLIB_CURL_SSL_REVOKE: a real curl on Windows' Schannel checks certificate
revocation and fails (exit 60, "the revocation status is unknown") when a
certificate's revocation list is missing or unreachable -- which OpenSSL
curls never check. The shim adds --ssl-revoke-best-effort for such a curl
unless told otherwise or the caller chose a revocation flag itself."""

import os
import shutil
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from curlike import shim as curl
from curlike import compat
from test_curl_options import pki  # noqa: F401  (fixture reused)
from test_proxy_auth import _capture_real_curl, _clean_env  # noqa: F401


@pytest.fixture(autouse=True)
def _windows_schannel_curl(monkeypatch):
    monkeypatch.delenv("HTTPLIB_CURL_SSL_REVOKE", raising=False)
    monkeypatch.setattr(curl.os, "name", "nt")
    monkeypatch.setattr(compat, "describe", lambda path: ((8, 21, 0), True))


def test_schannel_gets_best_effort_by_default(monkeypatch):
    calls = _capture_real_curl(monkeypatch)
    assert curl.main(["-qs", "https://example.com/"]) == 0
    assert calls[0][1:] == ["-qs", "--ssl-revoke-best-effort", "https://example.com/"], "after a leading -q"


@pytest.mark.parametrize(
    "value,added", [("false", ["--ssl-no-revoke"]), ("true", []), ("BEST-EFFORT", ["--ssl-revoke-best-effort"])]
)
def test_the_setting(monkeypatch, value, added):
    calls = _capture_real_curl(monkeypatch)
    monkeypatch.setenv("HTTPLIB_CURL_SSL_REVOKE", value)
    curl.main(["-s", "https://example.com/"])
    assert calls[0][1:] == added + ["-s", "https://example.com/"]


def test_the_callers_own_flag_wins(monkeypatch):
    calls = _capture_real_curl(monkeypatch)
    curl.main(["--ssl-no-revoke", "https://example.com/"])
    assert calls[0][1:] == ["--ssl-no-revoke", "https://example.com/"]


@pytest.mark.parametrize("described", [((8, 21, 0), False), ((7, 69, 1), True), (None, True)])
def test_only_a_schannel_curl_that_has_the_flag(monkeypatch, described):
    calls = _capture_real_curl(monkeypatch)
    monkeypatch.setattr(compat, "describe", lambda path: described)
    curl.main(["-s", "https://example.com/"])
    assert calls[0][1:] == ["-s", "https://example.com/"]


def test_never_off_windows(monkeypatch):
    calls = _capture_real_curl(monkeypatch)
    monkeypatch.setattr(curl.os, "name", "posix")
    curl.main(["-s", "https://example.com/"])
    assert calls[0][1:] == ["-s", "https://example.com/"]


def test_an_unknown_value_is_exit_2(monkeypatch, capsys):
    _capture_real_curl(monkeypatch)
    monkeypatch.setenv("HTTPLIB_CURL_SSL_REVOKE", "maybe")
    assert curl.main(["-s", "https://example.com/"]) == 2
    assert "HTTPLIB_CURL_SSL_REVOKE=maybe" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# The real thing: Git's Schannel curl against a certificate with no
# revocation list (the test CA has no distribution point).
# --------------------------------------------------------------------------- #
class _Ok(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def _schannel_curl():
    real = compat.find_real_curl()
    if not real or os.name != "nt":
        return None
    out = subprocess.run([real, "-V"], capture_output=True).stdout
    return real if b"Schannel" in out else None


@pytest.mark.skipif(not _schannel_curl(), reason="needs a Schannel curl (Windows)")
def test_a_missing_revocation_list_passes_through_the_shim(pki, monkeypatch):
    monkeypatch.undo()  # the real os.name and curl -V
    httpd = HTTPServer(("127.0.0.1", 0), _Ok)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pki / "server.pem"), str(pki / "server.key"))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = "https://127.0.0.1:%d/" % httpd.server_address[1]
    try:
        argv = ["-sS", "--cacert", str(pki / "ca.pem"), url]
        bare = subprocess.run([_schannel_curl()] + argv, capture_output=True)
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("HTTPLIB_")}
        shimmed = subprocess.run([sys.executable, "-m", "curlike"] + argv, capture_output=True, env=env)
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert bare.returncode == 60 and b"revocation" in bare.stderr
    assert shimmed.returncode == 0 and shimmed.stdout == b"ok", shimmed.stderr
