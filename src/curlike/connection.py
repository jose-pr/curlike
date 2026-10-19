"""Connection options: proxy steering, timeouts, redirects, ``--retry``, and
the protocol no-ops (``-g``, ``--http1.1``, ``-q``)."""

import errno
import socket
import time
from typing import List, Optional

from syshttp.retry import TRANSIENT_STATUSES

from ._duho import Meta, Arg
from .args import Group
from .errors import EXIT_CONNECT, EXIT_RESOLVE, EXIT_RESOLVE_PROXY, EXIT_TIMEOUT
from .connector import Connector, parse_local_port, parse_pins, resolve_interface
from .netconn import DnsOverride, make_resolver, unix_socket_handlers


def _interface_addresses(name):
    """One address per family of the interface ``name`` (netimps), for
    --dns-interface; none found is curl's 45."""
    from .connector import EXIT_INTERFACE
    from .errors import LocalError
    from .netconn import _netimps

    netimps = _netimps('--dns-interface', ('get_interfaces', 'resolve_wire'))
    found = {}
    for iface in netimps.get_interfaces():
        if iface.name == name:
            for ip in iface.ips:
                address = str(getattr(ip, 'ip', ip))
                found.setdefault(':' in address, address)
    if not found:
        raise LocalError(EXIT_INTERFACE, "Couldn't bind to interface '%s'" % name)
    return list(found.values())


def parse_rate(spec, flag):
    """curl's ``RATE[k|m|g]`` (bytes per second, 1024-based suffixes)."""
    m = __import__('re').match(r'^\s*(\d+(?:\.\d+)?)\s*([kKmMgG]?)\s*$', spec or '')
    if not m:
        raise ValueError('%s: expected a number with an optional k/m/g suffix, got %r' % (flag, spec))
    return float(m.group(1)) * 1024 ** ' kmg'.index(m.group(2).lower() or ' ')


#: curl's longest backoff between retries, in seconds.
MAX_RETRY_SLEEP = 600


def _refused(reason):
    if isinstance(reason, ConnectionRefusedError):
        return True
    return getattr(reason, 'errno', None) in (errno.ECONNREFUSED, 10061) or 'refused' in str(reason)


class ConnectionArgs(Group):
    """Proxy, timeouts, redirects and retries."""

    proxy: Optional[str] = None
    "Use proxy"
    ("-x", "--proxy")

    proxy_user: Arg[Optional[str], Meta(metavar='USER[:PASS]')] = None
    "Proxy user and password"
    ("-U", "--proxy-user")

    socks4: Arg[Optional[str], Meta(metavar='HOST[:PORT]')] = None
    "Use this SOCKS4 proxy (overrides -x)"
    ("--socks4",)

    socks4a: Arg[Optional[str], Meta(metavar='HOST[:PORT]')] = None
    "Use this SOCKS4a proxy, which resolves the name (overrides -x)"
    ("--socks4a",)

    socks5: Arg[Optional[str], Meta(metavar='HOST[:PORT]')] = None
    "Use this SOCKS5 proxy, resolving the name here (overrides -x)"
    ("--socks5",)

    socks5_hostname: Arg[Optional[str], Meta(metavar='HOST[:PORT]')] = None
    "Use this SOCKS5 proxy, which resolves the name (overrides -x)"
    ("--socks5-hostname",)

    socks5_basic: bool = False
    "Offer SOCKS5 username/password auth (what the fallback does; a no-op)"
    ("--socks5-basic",)

    preproxy: Arg[Optional[str], Meta(metavar='[PROTOCOL://]HOST[:PORT]')] = None
    "Reach the -x proxy through this SOCKS proxy"
    ("--preproxy",)

    proxy_header: Arg[Optional[List[str]], Meta(metavar='HEADER')] = None
    "Header for the proxy only (Name: value, Name; for empty, @file); repeatable"
    ("--proxy-header",)

    proxy_basic: bool = False
    "Use Basic for -U (the default; a no-op)"
    ("--proxy-basic",)

    proxy_digest: bool = False
    "Answer the proxy's 407 with Digest for -U (nothing sent up front)"
    ("--proxy-digest",)

    proxy_anyauth: bool = False
    "Answer the proxy's 407 with what it asks: Digest, else Basic"
    ("--proxy-anyauth",)

    noproxy: Arg[Optional[str], Meta(metavar='HOSTS')] = None
    "Hosts that bypass the proxy (* for all); replaces NO_PROXY"
    ("--noproxy",)

    proxytunnel: bool = False
    "Tunnel through the proxy with CONNECT for http URLs too"
    ("-p", "--proxytunnel")

    http1_0: bool = False
    "Send HTTP/1.0 requests"
    ("-0", "--http1.0")

    interface: Arg[Optional[str], Meta(metavar='NAME')] = None
    "Connect from this IP address, interface (if!NAME) or host (host!NAME)"
    ("--interface",)

    local_port: Arg[Optional[str], Meta(metavar='PORT[-PORT]')] = None
    "Connect from this local port, or the first free one of a range"
    ("--local-port",)

    limit_rate: Arg[Optional[str], Meta(metavar='RATE')] = None
    "Transfer at most RATE bytes per second (k, m, g suffixes)"
    ("--limit-rate",)

    speed_limit: Arg[Optional[int], Meta(metavar='BYTES')] = None
    "Abort below this many bytes per second for --speed-time seconds (exit 28)"
    ("-Y", "--speed-limit")

    speed_time: Arg[Optional[int], Meta(metavar='SECONDS')] = None
    "How long the transfer may stay below --speed-limit (default 30)"
    ("-y", "--speed-time")

    dns_servers: Arg[Optional[str], Meta(metavar='ADDRESSES')] = None
    "Resolve names with these nameservers (IP[:PORT],...; needs netimps)"
    ("--dns-servers",)

    dns_ipv4_addr: Arg[Optional[str], Meta(metavar='ADDRESS')] = None
    "Send IPv4 DNS queries from this address (needs netimps)"
    ("--dns-ipv4-addr",)

    dns_ipv6_addr: Arg[Optional[str], Meta(metavar='ADDRESS')] = None
    "Send IPv6 DNS queries from this address (needs netimps)"
    ("--dns-ipv6-addr",)

    dns_interface: Arg[Optional[str], Meta(metavar='INTERFACE')] = None
    "Send DNS queries from this interface's addresses (needs netimps)"
    ("--dns-interface",)

    doh_url: Arg[Optional[str], Meta(metavar='URL')] = None
    "Resolve names with DNS over HTTPS at this https URL (needs netimps)"
    ("--doh-url",)

    doh_insecure: bool = False
    "Do not verify the DNS-over-HTTPS server's certificate"
    ("--doh-insecure",)

    # No-ops for one HTTP/1.1 transfer, each true of this client: one URL (no
    # --fail-early), no Expect: 100-continue, no TCP Fast Open, TLS False
    # Start or Happy Eyeballs, no entropy file read, no CONNECT headers shown.
    fail_early: bool = False
    "Stop at the first failed transfer (a no-op: one transfer)"
    ("--fail-early",)

    expect100_timeout: Arg[Optional[str], Meta(metavar='SECONDS')] = None
    "Wait for 100-continue (a no-op: Expect: 100-continue is never sent)"
    ("--expect100-timeout",)

    tcp_fastopen: bool = False
    "TCP Fast Open (a no-op)"
    ("--tcp-fastopen",)

    false_start: bool = False
    "TLS False Start (a no-op)"
    ("--false-start",)

    happy_eyeballs_timeout_ms: Arg[Optional[str], Meta(metavar='MS')] = None
    "Happy Eyeballs delay (a no-op: addresses are tried in turn)"
    ("--happy-eyeballs-timeout-ms",)

    random_file: Arg[Optional[str], Meta(metavar='FILE')] = None
    "Entropy file (a no-op, as in curl itself)"
    ("--random-file",)

    egd_file: Arg[Optional[str], Meta(metavar='FILE')] = None
    "EGD socket (a no-op, as in curl itself)"
    ("--egd-file",)

    suppress_connect_headers: bool = False
    "Leave the proxy's CONNECT reply out of -i / -D output"
    ("--suppress-connect-headers",)

    ignore_content_length: bool = False
    "Read the body until the server closes, whatever Content-Length says"
    ("--ignore-content-length",)

    location: bool = False
    "Follow redirects"
    ("-L", "--location")

    max_redirs: Optional[int] = None
    "Maximum number of redirects to follow with -L"
    ("--max-redirs",)

    location_trusted: bool = False
    "With -L, keep sending credentials (Authorization, Cookie) to other hosts"
    ("--location-trusted",)

    post301: bool = False
    "Keep POST on a 301 redirect (default: GET)"
    ("--post301",)

    post302: bool = False
    "Keep POST on a 302 redirect (default: GET)"
    ("--post302",)

    post303: bool = False
    "Keep POST on a 303 redirect (default: GET)"
    ("--post303",)

    timeout: Optional[float] = None
    "Give up when nothing is received for this many seconds (not a curl option)"
    ("--timeout",)

    max_time: Optional[float] = None
    "Maximum time in seconds for the whole request"
    ("-m", "--max-time")

    connect_timeout: Optional[float] = None
    "Connect timeout in seconds"
    ("--connect-timeout",)

    retry: Arg[Optional[int], Meta(metavar='NUM')] = None
    "Retry a transient failure (timeout, HTTP 408/429/500/502/503/504) NUM times"
    ("--retry",)

    retry_delay: Arg[Optional[float], Meta(metavar='SECONDS')] = None
    "Wait this long between retries (default: 1s, doubling)"
    ("--retry-delay",)

    retry_max_time: Arg[Optional[float], Meta(metavar='SECONDS')] = None
    "Retry only within this many seconds"
    ("--retry-max-time",)

    retry_connrefused: bool = False
    "Also retry a refused connection"
    ("--retry-connrefused",)

    retry_all_errors: bool = False
    "Retry on any error (with -f, an HTTP error status too)"
    ("--retry-all-errors",)

    ipv4: bool = False
    "Resolve names to IPv4 addresses only"
    ("-4", "--ipv4")

    ipv6: bool = False
    "Resolve names to IPv6 addresses only"
    ("-6", "--ipv6")

    resolve: Arg[Optional[List[str]], Meta(metavar='HOST:PORT:ADDR[,ADDR]')] = None
    "Resolve HOST:PORT to these addresses (the Host header and TLS name stay HOST)"
    ("--resolve",)

    connect_to: Arg[Optional[List[str]], Meta(metavar='HOST1:PORT1:HOST2:PORT2')] = None
    "Connect to HOST2:PORT2 for requests to HOST1:PORT1 (empty parts: any / unchanged)"
    ("--connect-to",)

    unix_socket: Arg[Optional[str], Meta(metavar='PATH')] = None
    "Connect through this Unix domain socket instead of the network"
    ("--unix-socket",)

    no_keepalive: bool = False
    "No TCP keepalive (a no-op: each transfer is one connection)"
    ("--no-keepalive",)

    keepalive_time: Arg[Optional[int], Meta(metavar='SECONDS')] = None
    "TCP keepalive interval (a no-op)"
    ("--keepalive-time",)

    tcp_nodelay: bool = False
    "TCP_NODELAY (a no-op)"
    ("--tcp-nodelay",)

    # No-ops: the fallback reads no config file, never globs, and speaks HTTP/1.1.
    disable: bool = False
    "Skip the curl config file (a no-op: the fallback reads none)"
    ("-q", "--disable")

    globoff: bool = False
    "No URL globbing (a no-op: none is done)"
    ("-g", "--globoff")

    http1_1: bool = False
    "Use HTTP/1.1 (a no-op: it always does)"
    ("--http1.1",)

    def dns_override(self):
        """The :class:`DnsOverride` the DNS flags ask for, or ``None``."""
        sources = [a for a in (self.dns_ipv4_addr, self.dns_ipv6_addr) if a]
        if self.dns_interface:
            sources += _interface_addresses(self.dns_interface)
        if not (self.dns_servers or sources or self.doh_url):
            return None
        servers = [s.strip() for s in (self.dns_servers or '').split(',') if s.strip()]
        context = None
        if self.doh_url:
            from .tls import build_ssl_context
            from .errors import LocalError

            try:
                context = build_ssl_context(self.doh_insecure, cacert=self.cacert, capath=self.capath)
            except LocalError:
                context = build_ssl_context(self.doh_insecure)
        return DnsOverride(servers, sources, self.doh_url, context, self.connect_timeout or self.max_time)

    def effective_proxy(self):
        """The proxy URL: a --socks* flag (they override -x), else -x."""
        for kind, value in (
            ('socks5h', self.socks5_hostname),
            ('socks5', self.socks5),
            ('socks4a', self.socks4a),
            ('socks4', self.socks4),
        ):
            if value:
                return value if '://' in value else '%s://%s' % (kind, value)
        return self.proxy

    def proxy_headers(self):
        """``{name: value}`` for --proxy-header (``@file`` read, ``Name;`` empty);
        a removal (``Name:``) has no internal header to remove here."""
        from .request import _header_lines

        out = {}
        for header in _header_lines(self.proxy_header or []):
            if ':' in header:
                name, value = header.split(':', 1)
                if value.strip():
                    out[name.strip()] = value.strip()
            elif header.endswith(';') and header[:-1].strip():
                out[header[:-1].strip()] = ''
            else:
                self.usage_error('Invalid header: %s' % header)
        return out

    def connector(self):
        """The :class:`Connector` the transfer's connections share; an
        ``--interface`` that names nothing usable is curl's 45."""
        source = resolve_interface(self.interface) if self.interface else None
        ports = parse_local_port(self.local_port) if self.local_port else None
        pins = parse_pins(self.pinnedpubkey) if getattr(self, 'pinnedpubkey', None) else None
        family = socket.AF_INET if self.ipv4 else socket.AF_INET6 if self.ipv6 else 0
        resolver = make_resolver(family, self.resolve or (), self.connect_to or (), self.dns_override())
        return Connector(source, ports, pins, http10=self.http1_0, limits=self, resolver=resolver)

    def rate(self):
        """--limit-rate in bytes per second, or ``None``."""
        return parse_rate(self.limit_rate, '--limit-rate') if self.limit_rate else None

    def low_speed(self):
        """``(bytes per second, seconds)`` for --speed-limit / --speed-time
        (either alone implies the other's default: 1 B/s, 30 s), or ``None``."""
        if self.speed_limit is None and self.speed_time is None:
            return None
        return (
            self.speed_limit if self.speed_limit is not None else 1,
            self.speed_time if self.speed_time is not None else 30,
        )

    def connection_handlers(self, context):
        """urllib handlers replacing the TCP ones (--unix-socket), or []."""
        return unix_socket_handlers(self.unix_socket, context) if self.unix_socket else []

    def start_clock(self):
        """Start ``-m``'s clock: the whole attempt, redirect hops included."""
        self._deadline = time.monotonic() + self.max_time if self.max_time else None

    def _left(self):
        deadline = getattr(self, '_deadline', None)
        if deadline is None:
            return None
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout('timed out')
        return left

    def connect_limit(self):
        """How long a connection (and its TLS handshake) may take: the
        smaller of ``--connect-timeout`` and what is left of ``-m``; ``None``
        is no bound."""
        bounds = [b for b in (self.connect_timeout, self._left()) if b]
        return min(bounds) if bounds else None

    def read_limit(self):
        """How long one read may wait: what is left of ``-m``, the idle
        ``--timeout`` and ``-y``'s window, whichever is shortest; ``None`` is
        no bound."""
        low = self.low_speed()
        bounds = [b for b in (self._left(), self.timeout, low[1] if low else None) if b]
        return min(bounds) if bounds else None

    def retry_reason_for_error(self, code, reason):
        """curl's wording when a transport failure is worth another attempt,
        else ``None``."""
        if code in (EXIT_TIMEOUT, EXIT_RESOLVE, EXIT_RESOLVE_PROXY) or isinstance(reason, socket.timeout):
            return ': timeout'  # curl words a failed lookup so too
        if code == EXIT_CONNECT and self.retry_connrefused and _refused(reason):
            return ': connection refused'
        if self.retry_all_errors:
            return '(retrying all errors)'
        return None

    def retry_reason_for_status(self, status):
        """... and when an HTTP response is (a transient status, or -- with
        --retry-all-errors -- one that -f makes an error)."""
        if status in TRANSIENT_STATUSES:
            return ': HTTP error'
        if self.retry_all_errors and self.fails_on(status):
            return '(retrying all errors)'
        return None

    def retry_wait(self, backoff, after):
        """Seconds before the next attempt: the server's Retry-After (0 is none),
        else --retry-delay, else the doubling backoff."""
        if after:
            return after
        return self.retry_delay if self.retry_delay else backoff

    def retry_after_too_late(self, after):
        """Whether waiting out a Retry-After of ``after`` seconds would pass
        ``--retry-max-time``, counted from the first attempt."""
        started = getattr(self, 'retry_started', None)
        if not (after and self.retry_max_time and started is not None):
            return False
        return after > self.retry_max_time - (time.monotonic() - started)
