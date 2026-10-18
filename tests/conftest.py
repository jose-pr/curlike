"""No test sees an HTTPLIB_* variable or the system proxy of the machine running it, and the
fallback answers as the newest curl measured whatever curl the machine has
(the parity tests set the real curl's own)."""

import os

import pytest


@pytest.fixture(autouse=True)
def _clean_settings(monkeypatch):
    for name in list(os.environ):
        if name.startswith("HTTPLIB_"):
            monkeypatch.delenv(name)
    # Nor the machine's system proxy configuration: tests that need one fake it.
    from httplib import proxy

    monkeypatch.setattr(proxy, "system_proxy_map", lambda: None)


@pytest.fixture(autouse=True)
def _newest_curl(monkeypatch, _clean_settings):
    from curlike import compat

    monkeypatch.setenv(compat.var(), "%d.%d.%d" % compat.NEWEST)
    monkeypatch.setattr(compat, "_cached", {})
