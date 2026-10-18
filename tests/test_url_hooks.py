"""URL hooks: an HTTPLIB_HOOKS_<KEY> pattern matched on the caller's URL runs
a wrapper program in the curl shim's place -- under a prefix gateway too,
where the wire URL is the gateway's and must not be what is matched.
"""

import json
import os
import sys
from pathlib import Path

import pytest

from curlike import shim as curl
from httplib import hooks
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
# httplib
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# the curl shim
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
    "argv": argv, "curl": os.environ.get("HTTPLIB_HOOK_CURL"), "skip": os.environ.get("HTTPLIB_HOOK_SKIP"),
    "url": os.environ.get("HTTPLIB_HOOK_URL"), "key": os.environ.get("HTTPLIB_HOOK_KEY"),
}))
sys.exit(subprocess.run([sys.executable, "-m", "curlike", "-H", "X-Hooked: wrapper", *curl_argv]).returncode)
"""


def test_curl_hook_runs_the_wrapper_which_calls_the_shim_back(origin, gateway, tmp_path, monkeypatch, capsysbinary):
    wrapper = tmp_path / "wrap.py"
    wrapper.write_text(WRAPPER, encoding="utf-8")
    log = tmp_path / "log.json"
    monkeypatch.setenv("WRAPPER_LOG", str(log))
    monkeypatch.setenv("HTTPLIB_HOOKS_W", "^" + origin.replace(".", r"\.") + "/hooked")
    # A command line with the wrapper's own arguments; the shim's argv follows.
    monkeypatch.setenv("HTTPLIB_HOOKS_W_CURL", "'%s' fetch --" % wrapper)
    monkeypatch.setenv("HTTPLIB_PYTHON", sys.executable)
    entry = str(tmp_path / "curl")
    rc = curl.main(["-s", origin + "/hooked"], entry=entry)
    assert rc == 0
    seen = json.loads(log.read_text(encoding="utf-8"))
    assert seen["argv"] == ["fetch", "--", "-s", origin + "/hooked"]
    assert seen["curl"] == entry and seen["skip"] == "W"
    assert seen["url"] == origin + "/hooked" and seen["key"] == "W"
    path, headers = _Gateway.seen[-1]
    assert path == "/fetch/" + origin + "/hooked" and headers.get("X-Hooked") == "wrapper"
    # An unmatched URL never runs the wrapper.
    log.unlink()
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", origin + "/plain"])
    assert rc == 0 and out.out == b"gateway" and not log.exists()


def test_curl_hook_with_only_a_py_target_leaves_the_shim_alone(origin, gateway, monkeypatch, capsysbinary):
    monkeypatch.setenv("HTTPLIB_HOOKS_P", ".")
    monkeypatch.setenv("HTTPLIB_HOOKS_P_PY", "test_url_hooks:answer")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", origin + "/x"])
    assert rc == 0 and out.out == b"gateway"
