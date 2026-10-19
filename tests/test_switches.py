"""SYSHTTP_PROXY_AUTH_HEADER names the header the proxy credential rides in."""

import subprocess
import sys
from pathlib import Path

import pytest

import curlike as curl
from syshttp import proxy as agent_proxy
from test_jars_proxy import _Gateway, gateway, origin  # noqa: F401  (fixtures reused)
from test_proxy_auth import BEARER, _clean_env, _fallback  # noqa: F401


def test_fallback_uses_the_configured_header_name(origin, gateway, monkeypatch, capsysbinary):
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH_HEADER", "X-Proxy-Token")
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", origin + "/x"])
    assert rc == 0 and out.out == b"gateway"
    seen = _Gateway.seen[-1][1]
    assert seen.get("X-Proxy-Token") == BEARER and "Proxy-Authorization" not in seen
