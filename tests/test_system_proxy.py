"""The system's proxy configuration in curlike: the real curl is handed the
proxy it names for the URL asked for (curl reads only the *_proxy
variables), the fallback goes through it, a proxy variable wins over it, and
--crlfile keeps a context that can check CRLs."""

import socket
import ssl

import proxylib
import pytest

import curlike as curl
from syshttp import proxy as agent_proxy
from test_proxy_auth import BEARER, _fallback, _Proxy, proxy, target  # noqa: F401


class _FakeSystem:
    """The system's answer: a PAC result for every URL, or DIRECT."""

    def __init__(self, route):
        self.route = route
        self.asked = []

    def __getitem__(self, url):
        self.asked.append(url)
        return proxylib.Proxy.parse_pac_result(self.route or "DIRECT")


def _dead_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


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


def test_the_fallback_goes_through_the_systems_proxy(target, proxy, monkeypatch, capsysbinary, no_proxy_vars):
    _Proxy.expected = BEARER
    monkeypatch.setattr(
        agent_proxy, "system_map", lambda: _FakeSystem("PROXY %s; PROXY 127.0.0.1:%d" % (proxy, _dead_port()))
    )
    monkeypatch.setenv("HTTP_PROXY_AUTH", BEARER)
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
    monkeypatch.setattr(tls, "load_crls", lambda ctx, path: None)  # the file here is a certificate
    ctx = tls.build_ssl_context(False, crlfile=str(pem))
    assert type(ctx) is ssl.SSLContext and ctx.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN


def test_insecure_never_uses_the_os_verifier(monkeypatch):
    """-k verifies nothing; macOS's verifier (truststore) still evaluates the
    chain under CERT_NONE, so -k gets a plain ssl context."""
    from curlike import tls

    monkeypatch.setattr(tls, "new_os_context", lambda *a, **k: pytest.fail("-k must not get the OS verifier"))
    ctx = tls.build_ssl_context(True)
    assert type(ctx) is ssl.SSLContext and ctx.verify_mode == ssl.CERT_NONE and not ctx.check_hostname


@pytest.mark.parametrize("cert", [None, "client-rsa.pem"])
def test_cert_turns_off_the_os_stores_client_certificates(monkeypatch, cert):
    """A server asking for a client certificate gets one from the OS store,
    unless --cert names one: then that one is sent, never a store's."""
    from pathlib import Path

    from curlike import tls

    asked = []
    real = tls.new_os_context

    def new_os_context(*a, **k):
        asked.append(k.get("client_certificates", True))
        return real(*a, **k)

    monkeypatch.setattr(tls, "new_os_context", new_os_context)
    data = Path(__file__).parent / "data"
    tls.build_ssl_context(False, cert=cert and str(data / cert), key=cert and str(data / "client-rsa.key"))
    assert asked == [cert is None]


def _unreachable(monkeypatch):
    """The system names two proxies, and neither answers."""
    first, second = _dead_port(), _dead_port()
    route = "PROXY 127.0.0.1:%d; PROXY 127.0.0.1:%d" % (first, second)
    monkeypatch.setattr(agent_proxy, "system_map", lambda: _FakeSystem(route))
    return "no proxy of the list is reachable: 127.0.0.1:%d, 127.0.0.1:%d" % (first, second)


def test_the_fallback_exits_7_when_no_system_proxy_answers(monkeypatch, capsysbinary, no_proxy_vars):
    message = _unreachable(monkeypatch)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "http://api.example.com/x"])
    assert rc == 7
    assert ("curl: (7) " + message).encode() in out.err
