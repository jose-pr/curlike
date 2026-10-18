"""HTTPLIB_PROXY_AUTH_HEADER names the header the proxy credential rides in
(the fallback, real curl's --proxy-header); HTTPLIB_CURL=0 runs the real curl
as typed."""

import subprocess
import sys
from pathlib import Path

import pytest

from curlike import shim as curl
from httplib import proxy as agent_proxy
from test_jars_proxy import _Gateway, gateway, origin  # noqa: F401  (fixtures reused)
from test_proxy_auth import BEARER, _capture_real_curl, _clean_env, _fallback  # noqa: F401


def test_fallback_uses_the_configured_header_name(origin, gateway, monkeypatch, capsysbinary):
    monkeypatch.setenv("HTTPLIB_PROXY_AUTH_HEADER", "X-Proxy-Token")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", origin + "/x"])
    assert rc == 0 and out.out == b"gateway"
    seen = _Gateway.seen[-1][1]
    assert seen.get("X-Proxy-Token") == BEARER and "Proxy-Authorization" not in seen


def test_real_curl_gets_the_configured_header_name(monkeypatch):
    monkeypatch.setenv("HTTPLIB_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("HTTPLIB_PROXY_AUTH", BEARER)
    monkeypatch.setenv("HTTPLIB_PROXY_AUTH_HEADER", "X-Proxy-Token")
    calls = _capture_real_curl(monkeypatch)
    assert curl.main(["https://api.example.com/"]) == 0
    assert calls[-1][1:] == [
        "--proxy",
        "http://proxy.example:3128",
        "--proxy-header",
        "X-Proxy-Token: " + BEARER,
        "https://api.example.com/",
    ]


def test_net_curl_off_runs_the_real_curl_as_typed(monkeypatch):
    monkeypatch.setenv("HTTPLIB_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("HTTPLIB_PROXY_AUTH", BEARER)
    monkeypatch.setenv("HTTPLIB_HOOKS_ALL", ".")
    monkeypatch.setenv("HTTPLIB_HOOKS_ALL_CURL", "never-run-me")
    calls = _capture_real_curl(monkeypatch)
    for value in ("0", "n", "No", "false", "OFF"):
        monkeypatch.setenv("HTTPLIB_CURL", value)
        assert curl.main(["-s", "https://api.example.com/"]) == 0
        assert calls[-1] == ["/usr/bin/curl", "-s", "https://api.example.com/"], value
    # The default, and any other value, is the shim: the proxy is applied.
    for value in ("1", "y", "yes", "on", "whatever"):
        monkeypatch.setenv("HTTPLIB_CURL", value)
        assert curl.shim_enabled()
    monkeypatch.delenv("HTTPLIB_CURL")
    assert curl.shim_enabled()


def test_net_curl_off_without_a_real_curl_is_exit_2(monkeypatch, capsysbinary):
    monkeypatch.setenv("HTTPLIB_CURL", "0")
    monkeypatch.setattr(curl, "find_real_curl", lambda *a: None)
    assert curl.main(["-s", "https://api.example.com/"]) == 2
    assert capsysbinary.readouterr().err.startswith(b"curl: (2) HTTPLIB_CURL=0 asks for the real curl")
