"""An output the fallback cannot write: curl's exit 23, in curl's words.

Run as a child process over a real pipe that the reader closes, and against an
output path that is a directory. curl has several messages for exit 23, and
which one it prints depends on where the write failed: the C library keeps
4096 bytes for a stdout that is not a terminal, so a small body fails only at
the final flush ("Failed writing body") while a larger one fails in the write
itself ("passed N returned M"). The expected text below is what curl 8.18
(Linux) and 8.21 (Windows) print for these invocations; with a real curl
installed, each case is also compared with it line for line.

A failed write leaves Python's stdout unusable, so before this was handled a
later ``-w``, or the flush at interpreter exit, ended the run with a traceback
and exit 120.
"""

import io
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import curlike as curl
from curlike import output, realcurl, writeout

LIB = Path(output.__file__).resolve().parents[2]
REAL_CURL = curl.find_real_curl()
GENERIC = "Failed writing received data to disk/application"
REPORT = ["-sS", "-w", "%{stderr}[%{exitcode}|%{errormsg}]\n"]


def _serve(listener):
    """``/n<size>``: that many bytes after a pause, so a reader that closes at
    once is gone before the first write. The header block is fixed: a status
    line of 17 bytes, one Content-Length line and the blank line."""
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        with conn:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                head += chunk
            method, path = head.split(b" ")[:2] if b" " in head else (b"GET", b"/n0")
            body = b"y" * int(path.rsplit(b"n", 1)[1])
            time.sleep(0.4)
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body))
                if method != b"HEAD":
                    conn.sendall(body)
            except OSError:
                pass


@pytest.fixture(scope="module")
def origin():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    threading.Thread(target=_serve, args=(listener,), daemon=True).start()
    yield "http://127.0.0.1:%d" % listener.getsockname()[1]
    listener.close()


def _run(command, argv, take=0, keep=False):
    """``command`` over a pipe whose reader takes ``take`` bytes and closes
    (``keep``: reads it all). ``(exit code, stderr lines)``."""
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy") and k != "SYSHTTP_PROXY"}
    env["PYTHONPATH"] = os.pathsep.join([str(LIB), env.get("PYTHONPATH", "")])
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1"
    env.pop("COLUMNS", None)  # with no terminal either, curl wraps its notices at 79
    proc = subprocess.Popen(
        [*command, *argv], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
    )
    try:
        if keep:
            proc.stdout.read()
        elif take:
            proc.stdout.read(take)
        proc.stdout.close()
        err = proc.stderr.read().decode("utf-8", "replace")
        code = proc.wait(timeout=60)
    finally:
        proc.stderr.close()
        if proc.poll() is None:
            proc.kill()
    return code, [line for line in err.splitlines() if line.strip()]


FALLBACK = [sys.executable, "-c", "import sys, curlike; sys.exit(curlike.main())"]
SHORT = "Failure writing output to destination, passed %d returned %d"
REFUSED = "client returned ERROR on write of %d bytes"

# (name, argv before the URL, path, stdout is kept open, what curl prints, %{errormsg})
# "DIR" in argv and in a printed line stands for a directory, which cannot be
# opened as a file. With a header block of 38 + the digits of the length.
CASES = [
    ("body 5", [], "/n5", False, ["curl: Failed writing body"], GENERIC),
    ("body 4095", [], "/n4095", False, ["curl: Failed writing body"], GENERIC),
    ("body 4096", [], "/n4096", False, ["curl: (23) " + SHORT % (4096, 0)], SHORT % (4096, 0)),
    ("body 20000", [], "/n20000", False, ["curl: (23) " + SHORT % (16384, 0)], SHORT % (16384, 0)),
    ("-i body 5", ["-i"], "/n5", False, ["curl: Failed writing body"], GENERIC),
    ("-i filling the buffer", ["-i"], "/n4055", False, ["curl: Failed writing body"], GENERIC),
    ("-i one byte over", ["-i"], "/n4056", False, ["curl: (23) " + SHORT % (4056, 4055)], SHORT % (4056, 4055)),
    ("-i body 20000", ["-i"], "/n20000", False, ["curl: (23) " + SHORT % (16384, 4054)], SHORT % (16384, 4054)),
    ("-I", ["-I"], "/n5", False, ["curl: Failed writing body"], GENERIC),
    (
        "-D -",
        ["-D", "-"],
        "/n5",
        False,
        ["curl: Failed writing headers to -", "curl: (23) " + REFUSED % 17],
        REFUSED % 17,
    ),
    (
        "-D - with -o",
        ["-D", "-", "-o", os.devnull],
        "/n5",
        False,
        ["curl: Failed writing headers to -", "curl: (23) " + REFUSED % 17],
        REFUSED % 17,
    ),
    ("-o DIR, no body", ["-o", "DIR"], "/n0", True, [], GENERIC),
    ("-o DIR", ["-o", "DIR"], "/n5", True, ["curl: (23) " + REFUSED % 5], REFUSED % 5),
    ("-o DIR, body 20000", ["-o", "DIR"], "/n20000", True, ["curl: (23) " + REFUSED % 16384], REFUSED % 16384),
    ("-i -o DIR", ["-i", "-o", "DIR"], "/n5", True, ["curl: (23) " + REFUSED % 17], REFUSED % 17),
    (
        "-D DIR",
        ["-D", "DIR", "-o", os.devnull],
        "/n5",
        True,
        ["curl: Failed to open DIR", "curl: (23) " + GENERIC],
        GENERIC,
    ),
    (
        "-o DIR -D DIR",
        ["-D", "DIR", "-o", "DIR"],
        "/n5",
        True,
        ["curl: Failed to open DIR", "curl: (23) " + GENERIC],
        GENERIC,
    ),
]
IDS = [case[0] for case in CASES]


def _argv(argv, path, origin, directory):
    return [*REPORT, *[directory if a == "DIR" else a for a in argv], origin + path]


@pytest.mark.parametrize("name,argv,path,keep,printed,errormsg", CASES, ids=IDS)
def test_the_words_are_curls(name, argv, path, keep, printed, errormsg, origin, tmp_path):
    rc, err = _run(FALLBACK, _argv(argv, path, origin, str(tmp_path)), keep=keep)
    expected = []
    for line in printed:
        if "DIR" in line:  # a path of any length: wrapped as curl wraps its notices
            expected += output.notice_lines(line[len("curl: ") :].replace("DIR", str(tmp_path)))
        else:
            expected.append(line)
    assert (rc, err) == (23, expected + ["[23|%s]" % errormsg])


#: The last curl release that changed how these messages are worded or printed.
NEWEST_CHANGE = (8, 17, 0)


@pytest.mark.skipif(not REAL_CURL, reason="no real curl to compare the fallback with")
@pytest.mark.parametrize("name,argv,path,keep,printed,errormsg", CASES, ids=IDS)
def test_the_real_curl_prints_the_same(name, argv, path, keep, printed, errormsg, origin, tmp_path):
    """The curl installed, when it is as new as the one curlike answers as."""
    version = realcurl.describe(REAL_CURL)[0]
    if version is None or version < NEWEST_CHANGE:
        pytest.skip("curl %s words these messages as releases before %d.%d did" % (version, *NEWEST_CHANGE[:2]))
    argv = _argv(argv, path, origin, str(tmp_path))
    assert _run(FALLBACK, argv, keep=keep) == _run([REAL_CURL], argv, keep=keep), version


MID_TRANSFER = re.compile(r"^curl: \(23\) Failure writing output to destination, passed \d+ returned \d+$")


@pytest.mark.parametrize(
    "extra,lines",
    [
        ([], 1),
        (["-w", "[%{exitcode}]"], 1),  # the write-out has nowhere to go
        (["-w", "%{stderr}[%{exitcode}]"], 2),
        (["-i"], 1),
    ],
    ids=["body", "write-out to stdout", "write-out to stderr", "-i"],
)
def test_a_reader_that_leaves_mid_transfer(extra, lines, origin):
    rc, err = _run(FALLBACK, ["-sS", *extra, origin + "/n4194304"], take=16)
    assert rc == 23 and len(err) == lines, err
    assert MID_TRANSFER.match(err[0]), err
    if lines == 2:
        assert err[1] == "[23]"


def test_silent_prints_nothing(origin):
    assert _run(FALLBACK, ["-s", origin + "/n20000"]) == (23, [])
    assert _run(FALLBACK, ["-s", origin + "/n5"]) == (23, [])


def test_a_write_out_that_cannot_be_written_does_not_fail_the_transfer(origin):
    """The body went to a file; only -w had stdout. curl loses it and exits 0."""
    assert _run(FALLBACK, ["-sS", "-o", os.devnull, "-w", "%{http_code}", origin + "/n5"]) == (0, [])


class _Gone(object):
    """A captured stdout whose reader went away: no descriptor to redirect."""

    def __init__(self):
        self.buffer = self

    def write(self, data):
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self):
        raise BrokenPipeError(32, "Broken pipe")

    def fileno(self):
        raise io.UnsupportedOperation("fileno")


@pytest.fixture
def gone(monkeypatch):
    """Call it in the test body for a dead stdout: pytest installs its own
    stdout at the start of each phase, so one set here would not last. The
    null-device streams that replace the dead one are closed afterwards."""
    made = []
    discard = output.discard_stdout

    def tracking():
        discard()
        made.append(sys.stdout)

    monkeypatch.setattr(output, "discard_stdout", tracking)
    yield lambda: monkeypatch.setattr(sys, "stdout", _Gone())
    for stream in made:
        stream.close()


def test_what_fits_the_buffer_fails_only_at_the_flush(gone):
    gone()
    out = output.Stdout()
    assert out.write(b"x" * 4095) == 4095
    assert isinstance(sys.stdout, _Gone), "nothing was sent yet"
    assert out.flush() is False
    assert not isinstance(sys.stdout, _Gone), "stdout now points at the null device"


@pytest.mark.parametrize(
    "held,size,taken",
    [
        ([100, 3996], 10, 0),  # exactly full is still held; nothing more fits before it is sent
        ([100], 16384, 3996),  # the write tops the buffer up, and that is all of it that got in
        ([100], 3997, 3996),
        ([], 4096, 0),  # nothing held: a full block is sent at once
        ([], 16384, 0),
    ],
    ids=["full", "tops up", "one byte over", "a block", "a chunk"],
)
def test_a_write_that_overflows_reports_what_the_buffer_took(held, size, taken, gone):
    gone()
    out = output.Stdout()
    for n in held:
        assert out.write(b"h" * n) == n
    assert isinstance(sys.stdout, _Gone), "nothing was sent yet"
    assert out.write(b"x" * size) == taken


def test_a_stdout_that_works_gets_every_byte(capsysbinary):
    out = output.Stdout()
    sent = [b"h" * 41, b"a" * 4055, b"b" * 16384, b"c" * 5000, b"d"]
    for data in sent:
        assert out.write(data) == len(data)
    assert out.flush() is True
    assert capsysbinary.readouterr().out == b"".join(sent)


def test_a_notice_is_wrapped_as_curl_wraps_it(monkeypatch):
    """How curl 8.21 printed a ``-D`` path of this length (109 characters) and
    shape, stderr a pipe."""
    monkeypatch.delenv("COLUMNS", raising=False)
    monkeypatch.setattr(output.os, "get_terminal_size", lambda fd: (_ for _ in ()).throw(OSError()))
    path = "C:\\Users\\user\\AppData\\Local\\Temp\\a_rather_long_directory_name_that_goes_past_the_width_of_a_terminal_k213xm1_"
    assert output.notice_lines("Failed to open " + path) == [
        "curl: Failed to open ",
        "curl: C:\\Users\\user\\AppData\\Local\\Temp\\a_rather_long_directory_name_that_goes_p",
        "curl: ast_the_width_of_a_terminal_k213xm1_",
    ]
    assert output.notice_lines("Failed writing body") == ["curl: Failed writing body"]
    monkeypatch.setenv("COLUMNS", "30")
    assert output.notice_lines("Failed writing headers to -") == ["curl: Failed writing headers ", "curl: to -"]


def test_write_out_to_a_dead_stdout_is_skipped(gone):
    gone()
    writeout._write_stream("stdout", "[0]")  # no exception
    assert not isinstance(sys.stdout, _Gone)
