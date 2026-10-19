"""No test sees an SYSHTTP_* variable or the system proxy of the machine running it, and the
fallback answers as the newest curl measured whatever curl the machine has
(the parity tests set the real curl's own)."""

import os

import pytest


@pytest.fixture(autouse=True)
def _clean_settings(monkeypatch):
    for name in list(os.environ):
        if name.startswith("SYSHTTP_"):
            monkeypatch.delenv(name)
    # Nor the machine's system proxy configuration: tests that need one fake it.
    from syshttp import proxy

    monkeypatch.setattr(proxy, "system_proxy_map", lambda: None)
    # Nor its certificate store and smart cards when a server asks for a client
    # certificate; the OS still verifies servers.
    import sslcontext

    real = sslcontext.system_context

    def system_context(*, selector=None, **kwargs):
        if selector is None or selector is True:
            selector = sslcontext.ClientCertificateSelector([])
        return real(selector=selector, **kwargs)

    monkeypatch.setattr(sslcontext, "system_context", system_context)


@pytest.fixture(autouse=True)
def _newest_curl(monkeypatch, _clean_settings):
    from curlike import compat

    monkeypatch.setenv(compat.var(), "%d.%d.%d" % compat.NEWEST)
    monkeypatch.setattr(compat, "_cached", {})
