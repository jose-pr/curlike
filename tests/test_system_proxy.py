"""The system's proxy configuration in curlike: the real curl is handed the
proxy it names for the URL asked for (curl reads only the *_proxy
variables), the fallback goes through it, a proxy variable wins over it, and
--crlfile keeps a context that can check CRLs."""

import ssl

import pytest

from curlike import shim as curl
from syshttp import proxy as agent_proxy
from test_proxy_auth import BEARER, _capture_real_curl, _fallback, _Proxy, proxy, target  # noqa: F401


class _Entry:
    def __init__(self, url):
        self.url = url


class _FakeSystem:
    def __init__(self, route):
        self.route = route
        self.asked = []

    def __getitem__(self, url):
        self.asked.append(url)
        return [None] if self.route is None else [_Entry(self.route)]


@pytest.fixture()
def no_proxy_vars(monkeypatch):
    for name in (
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ):
        monkeypatch.delenv(name, raising=False)


def test_the_real_curl_gets_the_systems_proxy(monkeypatch, no_proxy_vars):
    fake = _FakeSystem("http://pac.example:3128")
    monkeypatch.setattr(agent_proxy, "system_proxy_map", lambda: fake)
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    calls = _capture_real_curl(monkeypatch)
    assert curl.main(["-s", "https://api.example.com/x"]) == 0
    assert calls[-1][1:] == [
        "--proxy",
        "http://pac.example:3128",
        "--proxy-header",
        "Proxy-Authorization: " + BEARER,
        "-s",
        "https://api.example.com/x",
    ]
    assert fake.asked == ["https://api.example.com/x"], "asked for the URL the caller typed"


def test_a_direct_answer_or_a_variable_leaves_the_real_curl_alone(monkeypatch, no_proxy_vars):
    calls = _capture_real_curl(monkeypatch)
    monkeypatch.setattr(agent_proxy, "system_proxy_map", lambda: _FakeSystem(None))
    curl.main(["-s", "https://api.example.com/"])
    assert calls[-1][1:] == ["-s", "https://api.example.com/"], "DIRECT"
    fake = _FakeSystem("http://pac.example:3128")
    monkeypatch.setattr(agent_proxy, "system_proxy_map", lambda: fake)
    monkeypatch.setenv("HTTPS_PROXY", "http://global.example:3128")
    curl.main(["-s", "https://api.example.com/"])
    assert calls[-1][1:] == ["-s", "https://api.example.com/"], "curl reads HTTPS_PROXY itself"
    assert fake.asked == []


def test_the_fallback_goes_through_the_systems_proxy(target, proxy, monkeypatch, capsysbinary, no_proxy_vars):
    _Proxy.expected = BEARER
    monkeypatch.setattr(agent_proxy, "system_proxy_map", lambda: _FakeSystem("http://" + proxy))
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", target + "/x"])
    assert rc == 0 and out.out == b"via-proxy"
    assert _Proxy.seen[-1] == (target + "/x", BEARER)


def test_crlfile_keeps_a_context_that_checks_crls(monkeypatch):
    """truststore ignores OpenSSL's CRL flags, so --crlfile must not get the
    OS verifier's context."""
    from pathlib import Path

    from curlike import tls

    monkeypatch.setattr(tls, "new_os_context", lambda *a, **k: pytest.fail("the OS verifier ignores CRL flags"))
    pem = Path(__file__).parent / "data" / "ca.pem"  # load_verify_locations reads PEM; the type is what matters
    ctx = tls.build_ssl_context(False, crlfile=str(pem))
    assert type(ctx) is ssl.SSLContext and ctx.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN
