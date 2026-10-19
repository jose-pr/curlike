"""URL hooks: an SYSHTTP_HOOKS_<KEY> pattern matched on the caller's URL runs
a wrapper program in curl's place (the overlay's launcher) -- under a prefix gateway too,
where the wire URL is the gateway's and must not be what is matched.
"""

import json
import os
import sys
from pathlib import Path

import pytest

import curlike as curl
from syshttp import hooks
from test_jars_proxy import _Gateway, gateway, origin  # noqa: F401  (fixtures reused)
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)

CALLS = []


def answer(session, method, url, kwargs):
    import requests

    resp = requests.Response()
    resp.status_code = 299
    resp._content = b"from-hook"
    resp.url = url
    return resp


@pytest.fixture(autouse=True)
def _no_calls():
    CALLS.clear()


# --------------------------------------------------------------------------
# the declaration
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# syshttp
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# curlike
# --------------------------------------------------------------------------


def test_requested_url_from_argv():
    assert (
        curl.requested_url(["-s", "-H", "X: --url", "example.com/a"]) == "http://example.com/a"
    ), "curl's default scheme"
    assert curl.requested_url(["--url", "http://h/b", "-o", "f"]) == "http://h/b"
    assert curl.requested_url(["-sx", "http://proxy/", "http://h/c"]) == "http://h/c"
    assert curl.requested_url(["-s"]) is None


WRAPPER = """
import json, os, subprocess, sys
from pathlib import Path
argv = sys.argv[1:]
curl_argv = argv[argv.index("--") + 1:] if "--" in argv else argv
Path(os.environ["WRAPPER_LOG"]).write_text(json.dumps({
    "argv": argv, "curl": os.environ.get("SYSHTTP_HOOK_CURL"), "skip": os.environ.get("SYSHTTP_HOOK_SKIP"),
    "url": os.environ.get("SYSHTTP_HOOK_URL"), "key": os.environ.get("SYSHTTP_HOOK_KEY"),
}))
sys.exit(subprocess.run([sys.executable, "-m", "curlike", "-H", "X-Hooked: wrapper", *curl_argv]).returncode)
"""


def test_curl_hook_with_only_a_py_target_leaves_curlike_alone(origin, gateway, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_HOOKS_P", ".")
    monkeypatch.setenv("SYSHTTP_HOOKS_P_PY", "test_url_hooks:answer")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", origin + "/x"])
    assert rc == 0 and out.out == b"gateway"
