"""The DNS flags (--dns-servers, --dns-ipv4-addr / --dns-ipv6-addr,
--dns-interface, --doh-url), resolved by netimps. A fake nameserver (UDP)
and a fake DNS-over-HTTPS endpoint answer ``*.test`` with 127.0.0.1 and
``missing.*`` with NXDOMAIN; the origin is reached by that name.

--doh-url is also compared with real curl (DoH is built in; the
--dns-servers family needs c-ares, which no curl here has). Skipped without
the netimps the flags require (0.4.1)."""
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from curlike import shim as curl
from test_curl_options import pki  # noqa: F401  (fixture reused)
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)

from curlike import netconn  # noqa: E402  (lib/, via conftest)

netimps = pytest.importorskip("netimps")
pytestmark = pytest.mark.skipif(netconn._too_old(netimps) or not hasattr(netimps, "resolve_doh"),
                                reason="needs %s" % netconn.NETIMPS_FOR_DNS)


def _name(data, pos):
    labels = []
    while data[pos]:
        labels.append(data[pos + 1:pos + 1 + data[pos]].decode())
        pos += 1 + data[pos]
    return ".".join(labels), pos + 1


def answer(query):
    """A reply: 127.0.0.1 for an A question under .test, NXDOMAIN for
    missing.*, no record otherwise."""
    ident = struct.unpack("!H", query[:2])[0]
    name, end = _name(query, 12)
    qtype = struct.unpack("!H", query[end:end + 2])[0]
    question = query[12:end + 4]
    if name.startswith("missing"):
        return struct.pack("!HHHHHH", ident, 0x8183, 1, 0, 0, 0) + question
    if qtype != 1 or not name.endswith(".test"):
        return struct.pack("!HHHHHH", ident, 0x8180, 1, 0, 0, 0) + question
    record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
    return struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + question + record


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("origin %s" % self.headers.get("Host", "").split(":")[0]).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _DoH(BaseHTTPRequestHandler):
    def do_POST(self):
        out = answer(self.rfile.read(int(self.headers["Content-Length"])))
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def _serve(handler, context=None):
    httpd = HTTPServer(("127.0.0.1", 0), handler)
    if context is not None:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture(scope="module")
def world(pki):
    origin = _serve(_Origin)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pki / "server.pem"), str(pki / "server.key"))
    doh = _serve(_DoH, context)
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind(("127.0.0.1", 0))
    peers = []

    def serve_dns():
        while True:
            try:
                data, peer = dns.recvfrom(4096)
            except OSError:
                return
            peers.append(peer)
            dns.sendto(answer(data), peer)

    threading.Thread(target=serve_dns, daemon=True).start()
    yield {
        "port": origin.server_address[1],
        "ns": "127.0.0.1:%d" % dns.getsockname()[1],
        "doh": "https://127.0.0.1:%d/dns-query" % doh.server_address[1],
        "ca": str(pki / "ca.pem"),
        "peers": peers,
    }
    dns.close()
    for httpd in (origin, doh):
        httpd.shutdown()
        httpd.server_close()


def test_dns_servers_resolve_the_name(world, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--dns-servers", world["ns"],
                                                     "http://host.test:%d/" % world["port"]])
    assert rc == 0 and out.out == b"origin host.test", out.err


def test_an_unknown_name_is_6(world, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--dns-servers", world["ns"],
                                                     "http://missing.test:%d/" % world["port"]])
    assert rc == 6 and out.err.startswith(b"curl: (6) Could not resolve host: missing.test")


def test_the_dns_source_address_is_used(world, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--dns-servers", world["ns"], "--dns-ipv4-addr",
                                                     "127.0.0.1", "http://source.test:%d/" % world["port"]])
    assert rc == 0 and world["peers"][-1][0] == "127.0.0.1"


def test_a_dead_nameserver_is_6(world, monkeypatch, capsysbinary):
    dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dead.bind(("127.0.0.1", 0))
    try:
        rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--connect-timeout", "1", "--dns-servers",
                                                         "127.0.0.1:%d" % dead.getsockname()[1],
                                                         "http://host.test:%d/" % world["port"]])
    finally:
        dead.close()
    assert rc == 6


def test_an_address_needs_no_lookup(world, monkeypatch, capsysbinary):
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--dns-servers", "127.0.0.1:1",
                                                     "http://127.0.0.1:%d/" % world["port"]])
    assert rc == 0


def test_without_netimps_the_flag_is_refused(world, monkeypatch, capsysbinary):
    monkeypatch.setitem(sys.modules, "netimps", None)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--dns-servers", world["ns"],
                                                     "http://host.test:%d/" % world["port"]])
    assert rc == 2 and b"needs netimps: pip install 'netimps>=0.4.1'" in out.err


def test_an_older_netimps_is_refused(world, monkeypatch, capsysbinary):
    """A 0.3 has every name the flags call, with the old call shapes."""
    import types

    old = types.SimpleNamespace(__version__="0.3.4", resolve_wire=None, resolve_doh=None, resolve=None)
    monkeypatch.setitem(sys.modules, "netimps", old)
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--dns-servers", world["ns"],
                                                     "http://host.test:%d/" % world["port"]])
    assert rc == 2 and b"needs netimps: pip install 'netimps>=0.4.1'" in out.err
    assert netconn._too_old(types.SimpleNamespace(__version__="0.4.1")) is False
    assert netconn._too_old(types.SimpleNamespace(__version__="0.5.0.dev3")) is False
    assert netconn._too_old(types.SimpleNamespace()) is False  # no version: the names decide
    assert netconn._too_old(types.SimpleNamespace(__version__="0.0.0+unknown")) is False  # a source tree


# --------------------------------------------------------------------------- #
# --doh-url, the fallback against real curl.
# --------------------------------------------------------------------------- #
REAL = curl.find_real_curl()


def _run(argv, real):
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    env["PATH"] = os.path.dirname(REAL) + os.pathsep + env.get("PATH", "") if real else str(Path(__file__).parent)
    p = subprocess.run([sys.executable, "-m", "curlike"] + argv, capture_output=True, env=env,
                       timeout=60, stdin=subprocess.DEVNULL)
    return p.returncode, p.stdout


@pytest.mark.skipif(not REAL, reason="no real curl to compare with")
@pytest.mark.parametrize("name,argv", [
    ("trusted with --cacert", lambda w: ["--doh-url", w["doh"], "--cacert", w["ca"], "http://host.test:%d/" % w["port"]]),
    ("--doh-insecure", lambda w: ["--doh-url", w["doh"], "--doh-insecure", "http://host.test:%d/" % w["port"]]),
    ("untrusted", lambda w: ["--doh-url", w["doh"], "http://host.test:%d/" % w["port"]]),
    ("NXDOMAIN", lambda w: ["--doh-url", w["doh"], "--doh-insecure", "http://missing.test:%d/" % w["port"]]),
    ("unreachable", lambda w: ["--doh-url", "https://127.0.0.1:1/dns-query", "http://host.test:%d/" % w["port"]]),
    ("http endpoint", lambda w: ["--doh-url", w["doh"].replace("https", "http"), "http://host.test:%d/" % w["port"]]),
    ("an address", lambda w: ["--doh-url", w["doh"], "--doh-insecure", "http://127.0.0.1:%d/" % w["port"]]),
])
def test_doh_answers_as_curl_does(world, name, argv):
    args = ["-sS", "--ssl-no-revoke"] + argv(world) if b"Schannel" in subprocess.run(
        [REAL, "-V"], capture_output=True).stdout else ["-sS"] + argv(world)
    real, fallback = _run(args, True), _run(args, False)
    assert fallback == real, "%s: real %r, fallback %r" % (name, real, fallback)
