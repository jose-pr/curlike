"""No test sees an SYSHTTP_* variable or the system proxy of the machine running it."""

import os

import pytest


@pytest.fixture(autouse=True)
def _clean_settings(monkeypatch):
    for name in list(os.environ):
        if name.startswith("SYSHTTP_"):
            monkeypatch.delenv(name)
    # Nor the machine's system proxy configuration: tests that need one fake it.
    import proxylib
    from syshttp import proxy

    monkeypatch.setattr(proxy, "system_map", lambda: None)
    # proxylib's bad-proxy marks are process-wide: one test's dead port is
    # another's live one.
    proxylib.clear_caches()
    # Nor its certificate store and smart cards when a server asks for a client
    # certificate; the OS still verifies servers.
    import sslcontext

    real = sslcontext.system_context

    def system_context(*, selector=None, **kwargs):
        if selector is None or selector is True:
            selector = sslcontext.ClientCertificateSelector([])
        return real(selector=selector, **kwargs)

    monkeypatch.setattr(sslcontext, "system_context", system_context)


def pytest_report_header(config):
    """The curl the parity tests compare with: its version line, so a CI log shows it."""
    from curlike import realcurl

    path = realcurl.find_real_curl()
    if not path:
        return "real curl: none (the parity tests skip)"
    version, schannel = realcurl.describe(path)
    return "real curl: %s %s%s" % (
        path,
        "%d.%d.%d" % version if version else "unknown version",
        " (Schannel)" if schannel else "",
    )
