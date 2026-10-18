"""The curl shim's -w/--write-out and -q/--disable: the fallback reports the
variables scripts and agents use, formatted as real curl formats them (checked
against curl 8.21), writes them however the transfer ends, and refuses a
variable it cannot report before anything is sent; -q is a no-op there, and
the real-curl passthrough keeps a leading -q first, the only place curl
honours it.
"""

import re
import socket

import pytest

from curlike import shim as curl
from test_curl_edges import _Edge, origin  # noqa: F401  (fixture reused)
from test_proxy_auth import BEARER, _capture_real_curl, _clean_env, _fallback  # noqa: F401


def _w(monkeypatch, capsysbinary, fmt, *argv):
    return _fallback(monkeypatch, capsysbinary, ["-s", "-w", fmt, *argv])


# --------------------------------------------------------------------------- #
# -q / --disable
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("flag", [["-q"], ["--disable"], ["-qs"]])
def test_q_is_a_no_op_in_the_fallback(flag, origin, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, [*flag, "-s", origin + "/x"])
    assert rc == 0 and out.out == b"hello"


@pytest.mark.parametrize("lead", ["-q", "--disable", "-qs"])
def test_real_curl_keeps_a_leading_q_first(lead, monkeypatch):
    calls = _capture_real_curl(monkeypatch)
    monkeypatch.setenv("SYSHTTP_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    curl.main([lead, "https://api.example.com/"])
    assert calls[-1][1] == lead
    assert calls[-1][2:4] == ["--proxy", "http://proxy.example:3128"]
    # A -q that is not first is curl's to ignore: argv stays as typed.
    curl.main(["-s", "-q", "https://api.example.com/"])
    assert calls[-1][1] == "--proxy" and calls[-1][-3:] == ["-s", "-q", "https://api.example.com/"]


# --------------------------------------------------------------------------- #
# -w variables
# --------------------------------------------------------------------------- #


def test_status_probe_with_dev_null(origin, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "-o", "/dev/null", "-w", "%{http_code}", origin + "/x"])
    assert rc == 0 and out.out == b"200" and out.err == b""


def test_response_variables(origin, monkeypatch, capsysbinary):
    rc, out = _w(
        monkeypatch,
        capsysbinary,
        "[%{response_code}|%{http_version}|%{scheme}|%{method}|%{content_type}|%{size_download}|%{num_headers}|%{exitcode}|%{errormsg}]",
        origin + "/echo",
    )
    body, _, tail = out.out.decode().rpartition("[")
    code, version, scheme, method, ctype, size, nheaders, exitcode, errormsg = tail.rstrip("]").split("|")
    assert rc == 0 and code == "200" and version == "1"  # http.server answers HTTP/1.0
    assert scheme == "http" and method == "GET" and ctype == "application/json"
    assert int(size) == len(body.encode()) and int(nheaders) >= 3
    assert exitcode == "0" and errormsg == ""


def test_redirects_url_effective_and_redirect_url(origin, monkeypatch, capsysbinary):
    rc, out = _w(monkeypatch, capsysbinary, "[%{url_effective}|%{num_redirects}|%{redirect_url}]", origin + "/redirect")
    assert rc == 0 and out.out == ("[%s/redirect|0|%s/x]" % (origin, origin)).encode()
    rc, out = _fallback(
        monkeypatch,
        capsysbinary,
        ["-s", "-L", "-w", "[%{url}|%{url_effective}|%{num_redirects}|%{redirect_url}]", origin + "/redirect"],
    )
    assert rc == 0 and out.out == ("hello[%s/redirect|%s/x|1|]" % (origin, origin)).encode()


def test_url_effective_writes_an_empty_path_as_slash(origin, monkeypatch, capsysbinary):
    rc, out = _w(monkeypatch, capsysbinary, "%{url_effective}", origin)
    assert rc == 0 and out.out.endswith((origin + "/").encode())


def test_method_and_size_upload_are_the_last_requests(origin, monkeypatch, capsysbinary):
    rc, out = _w(monkeypatch, capsysbinary, "[%{method}|%{size_upload}]", "-d", "a=1", origin + "/echo")
    assert rc == 0 and out.out.endswith(b"[POST|3]")
    # A 302 turns the POST into a body-less GET, as curl reports it.
    rc, out = _w(monkeypatch, capsysbinary, "[%{method}|%{size_upload}]", "-L", "-d", "a=1", origin + "/redirect")
    assert rc == 0 and out.out == b"hello[GET|0]"


def test_headers(origin, monkeypatch, capsysbinary):
    rc, out = _w(monkeypatch, capsysbinary, "[%header{SET-COOKIE}|%header{missing}]", origin + "/setcookie")
    assert rc == 0 and out.out == b"ok[sid=abc; Path=/; HttpOnly; Max-Age=3600|]", "the first value, any case"
    rc, out = _w(monkeypatch, capsysbinary, "%{header_json}", origin + "/setcookie")
    text = out.out.decode()[len("ok") :]
    assert text.startswith('{"') and text.endswith("\n}") and ',\n"' in text
    assert '"set-cookie":["sid=abc; Path=/; HttpOnly; Max-Age=3600","flash=1; Path=/"]' in text


def test_times_are_six_decimal_seconds(origin, monkeypatch, capsysbinary):
    rc, out = _w(monkeypatch, capsysbinary, "%{time_starttransfer} %{time_total}", origin + "/x")
    start, total = out.out.decode()[len("hello") :].split()
    assert re.fullmatch(r"\d+\.\d{6}", start) and re.fullmatch(r"\d+\.\d{6}", total)
    assert float(start) <= float(total)


def test_filename_effective_and_urlnum(origin, tmp_path, monkeypatch, capsysbinary):
    target = tmp_path / "out.txt"
    rc, out = _w(monkeypatch, capsysbinary, "[%{filename_effective}|%{urlnum}]", "-o", str(target), origin + "/x")
    assert rc == 0 and out.out == ("[%s|0]" % target).encode() and target.read_bytes() == b"hello"


def test_every_declared_variable_has_a_value(origin, monkeypatch, capsysbinary):
    from curlike.writeout import WRITE_OUT_VARIABLES

    fmt = "".join("%%{%s}" % name for name in sorted(WRITE_OUT_VARIABLES))
    rc, out = _w(monkeypatch, capsysbinary, fmt, origin + "/x")
    assert rc == 0 and b"%{" not in out.out


# --------------------------------------------------------------------------- #
# written however the transfer ends
# --------------------------------------------------------------------------- #


def test_transport_failure_is_000_and_the_exit_code(monkeypatch, capsysbinary):
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    rc, out = _w(
        monkeypatch,
        capsysbinary,
        "[%{http_code}|%{http_version}|%{exitcode}|%{errormsg}]",
        "http://127.0.0.1:%d/x" % port,
    )
    assert rc == 7 and out.err == b""
    assert out.out.startswith(b"[000|0|7|Failed to connect")


def test_fail_reports_the_status_and_22(origin, monkeypatch, capsysbinary):
    rc, out = _w(
        monkeypatch, capsysbinary, "[%{http_code}|%{exitcode}|%{errormsg}|%{size_download}]", "-f", origin + "/404"
    )
    assert rc == 22 and out.out == b"[404|22|The requested URL returned error: 404|0]"


def test_unwritable_output_is_exit_23(origin, tmp_path, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "-o", str(tmp_path), "-w", "%{exitcode}", origin + "/x"])
    assert rc == 23 and out.out == b"23"
    assert out.err.strip() == b"curl: (23) client returned ERROR on write of 5 bytes"


# --------------------------------------------------------------------------- #
# the format language
# --------------------------------------------------------------------------- #


def test_escapes_and_literals_as_curl_reads_them(origin, monkeypatch, capsysbinary):
    rc, out = _w(monkeypatch, capsysbinary, "a\\nb\\tc\\rd\\\\e\\qf%%g%zh%{j", origin + "/x")
    assert rc == 0 and out.out == b"helloa\nb\tc\rd\\\\e\\qf%g%zh%{j"


def test_stream_switch_and_onerror(origin, monkeypatch, capsysbinary):
    rc, out = _w(monkeypatch, capsysbinary, "%{stderr}to-err%{stdout}to-out", origin + "/x")
    assert out.out == b"helloto-out" and out.err == b"to-err"
    rc, out = _w(monkeypatch, capsysbinary, "ok%{onerror}err", origin + "/x")
    assert out.out == b"hellook"
    rc, out = _w(monkeypatch, capsysbinary, "ok%{onerror}err[%{exitcode}]", "http://nonexistent.invalid/x")
    assert rc == 6 and out.out == b"okerr[6]"


def test_format_from_a_file(origin, tmp_path, monkeypatch, capsysbinary):
    fmt = tmp_path / "fmt.txt"
    fmt.write_text("code=%{http_code}\\n", encoding="utf-8")
    rc, out = _w(monkeypatch, capsysbinary, "@" + str(fmt), "-o", "/dev/null", origin + "/x")
    assert rc == 0 and out.out == b"code=200\n"


@pytest.mark.parametrize(
    "fmt, named",
    [
        ("%{ssl_verify_result}", "%{ssl_verify_result}"),
        ("%{certs}", "%{certs}"),
        ("%output{f.txt}x", "%output{f.txt}"),
    ],
)
def test_an_unreportable_variable_is_refused_before_sending(fmt, named, origin, monkeypatch, capsysbinary):
    _Edge.seen = []
    rc, out = _w(monkeypatch, capsysbinary, fmt, origin + "/x")
    assert rc == 2 and out.out == b""
    assert out.err.strip() == ("curl: (2) Unsupported --write-out variable: %s" % named).encode()
    assert _Edge.seen == [], "nothing was sent"
