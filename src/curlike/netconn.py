"""Where connections go: ``-4`` / ``-6``, ``--resolve``, ``--connect-to``
and ``--unix-socket``.

The first three steer name resolution only -- ``socket.getaddrinfo`` is
wrapped for the length of the transfer -- so the request keeps the host the
caller named: its ``Host`` header, TLS server name and certificate check are
the URL's, as in curl. ``--unix-socket`` replaces the TCP connection with one
to a Unix domain socket (the Docker API's ``/var/run/docker.sock``)."""
import contextlib
import http.client
import ipaddress
import re
import socket
import threading
import urllib.request

#: The netimps release the DNS and interface flags are tested with: its
#: keyword-only options are what the calls below pass.
NETIMPS_FOR_DNS = 'netimps>=0.4.1'
_NETIMPS_FLOOR = (0, 4, 1)


def _too_old(netimps):
    """Whether ``netimps`` reports a release older than the floor. One that
    reports no usable version is let through, and the names ``_netimps``
    checks still have to be there: imported from a source tree with no
    package metadata, netimps reports ``0.0.0+unknown``."""
    found = re.match(r'(\d+)\.(\d+)\.(\d+)', str(getattr(netimps, '__version__', '') or ''))
    version = tuple(int(part) for part in found.groups()) if found else None
    return version is not None and version != (0, 0, 0) and version < _NETIMPS_FLOOR


def _netimps(flag, needs):
    """netimps, at least the release in ``NETIMPS_FOR_DNS`` and with ``needs``
    on it, or ``NotImplementedError`` naming the flag and the release to
    install (exit 2, like any flag not honoured)."""
    try:
        import netimps
    except ImportError:
        netimps = None
    if netimps is None or _too_old(netimps) or not all(hasattr(netimps, name) for name in needs):
        raise NotImplementedError("%s needs netimps: pip install '%s'" % (flag, NETIMPS_FOR_DNS))
    return netimps


class DnsOverride(object):
    """Names resolved by netimps instead of the OS -- curl's ``--dns-servers``
    (``ns``), ``--dns-ipv4-addr`` / ``--dns-ipv6-addr`` / ``--dns-interface``
    (``sources``) and ``--doh-url`` (``doh_url``, its TLS ``doh_context``).
    A name with no address is ``None``: the caller's ``gaierror``, curl's 6.
    The DoH request's own name lookup goes to the OS (a thread-local guard),
    as curl's does."""

    def __init__(self, servers=None, sources=None, doh_url=None, doh_context=None, timeout=None):
        flag = '--doh-url' if doh_url else '--dns-servers' if servers else '--dns-ipv4-addr / --dns-ipv6-addr'
        self.netimps = _netimps(flag, ('resolve_doh',) if doh_url else ('resolve_wire',))
        self.servers = servers or None
        self.sources = sources or None
        self.doh_url = doh_url
        self.doh_context = doh_context
        self.timeout = timeout or 5.0
        self.cache = {}
        self.local = threading.local()

    def addresses(self, name, family):
        """The addresses of ``name`` for ``family`` (0: IPv4 then IPv6), or
        ``None`` while the DoH request itself is resolving."""
        if getattr(self.local, 'busy', False):
            return None
        key = (name.lower().rstrip('.'), family)
        if key not in self.cache:
            rdtypes = ['a'] if family == socket.AF_INET else ['aaaa'] if family == socket.AF_INET6 else ['a', 'aaaa']
            found = []
            self.local.busy = True
            try:
                for rdtype in rdtypes:
                    try:
                        found += [str(a) for a in self._lookup(key[0], rdtype)]
                    except (self.netimps.ResolutionError, ValueError):
                        continue
            finally:
                self.local.busy = False
            self.cache[key] = found
        return self.cache[key]

    def _lookup(self, name, rdtype):
        if self.doh_url:
            return self.netimps.resolve_doh(name, self.doh_url, rdtype=rdtype, timeout=self.timeout,
                                            fetch=self._fetch)
        return self.netimps.resolve(name, rdtype, ns=self.servers, source=self.sources, timeout=self.timeout,
                                    backends=['dnspython', 'wire'])

    def _fetch(self, url, body, headers, timeout):
        """The DoH request: https only (curl asks nothing over http), verified
        as the transfer is (--cacert / --capath) unless --doh-insecure, and
        direct, never through a proxy."""
        if not url.lower().startswith('https://'):
            raise ValueError('--doh-url must be https: %s' % url)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=self.doh_context))
        request = urllib.request.Request(url, data=body, headers=headers, method='POST')
        with opener.open(request, timeout=timeout) as response:
            kind = response.headers.get('Content-Type', '').split(';')[0].strip().lower()
            if kind != 'application/dns-message':
                raise ValueError('%s answered %s, not application/dns-message' % (url, kind or 'nothing'))
            return response.read()


def _is_address(name):
    try:
        ipaddress.ip_address(name.strip('[]').split('%')[0])
        return True
    except ValueError:
        return False


def parse_resolve(entry):
    """``HOST:PORT:ADDR[,ADDR...]`` (curl's ``--resolve``) ->
    ``((host, port), [addr, ...])``; an IPv6 address may be bracketed."""
    parts = entry.split(':', 2)  # only the addresses may hold colons (IPv6)
    if len(parts) != 3 or not parts[0] or not parts[1].isdigit() or not parts[2]:
        raise ValueError('--resolve: expected HOST:PORT:ADDR[,ADDR], got %r' % entry)
    host, port, addrs = parts
    return (host.lower(), int(port)), [a.strip().strip('[]') for a in addrs.split(',') if a.strip()]


def parse_connect_to(entry):
    """``HOST1:PORT1:HOST2:PORT2`` (curl's ``--connect-to``; any part may be
    empty: empty HOST1/PORT1 match anything, empty HOST2/PORT2 keep the
    original) -> ``((host1, port1), (host2, port2))``."""
    parts = entry.split(':')
    if len(parts) != 4:
        raise ValueError('--connect-to: expected HOST1:PORT1:HOST2:PORT2, got %r' % entry)
    h1, p1, h2, p2 = parts
    return (h1.lower(), int(p1) if p1 else None), (h2, int(p2) if p2 else None)


@contextlib.contextmanager
def resolving(family=0, resolve=(), connect_to=(), dns=None):
    """``socket.getaddrinfo`` as ``-4`` / ``-6`` (``family``), ``--resolve``,
    ``--connect-to`` and the DNS flags (``dns``, a :class:`DnsOverride`) ask,
    restored afterwards."""
    table = dict(parse_resolve(e) for e in resolve)
    remaps = [parse_connect_to(e) for e in connect_to]
    if not (family or table or remaps or dns):
        yield
        return
    real = socket.getaddrinfo

    def getaddrinfo(host, port, fam=0, type=0, proto=0, flags=0):
        name = host.decode('idna') if isinstance(host, bytes) else (host or '')
        number = int(port) if isinstance(port, (int, str)) and str(port).isdigit() else port
        for (h1, p1), (h2, p2) in remaps:
            if h1 in ('', name.lower()) and p1 in (None, number):
                name, number = h2 or name, p2 or number
                break
        wanted = family or fam
        fixed = table.get((name.lower(), number))
        if fixed:
            out = []
            for addr in fixed:
                v6 = ':' in addr
                if wanted and wanted != (socket.AF_INET6 if v6 else socket.AF_INET):
                    continue
                sockaddr = (addr, number, 0, 0) if v6 else (addr, number)
                out.append((socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', sockaddr))
            if out:
                return out
        if dns is not None and name and not _is_address(name):
            found = dns.addresses(name, wanted)
            if found is not None:
                if not found:
                    raise socket.gaierror(socket.EAI_NONAME, 'Could not resolve host: %s' % name)
                return [(socket.AF_INET6 if ':' in a else socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
                         (a, number, 0, 0) if ':' in a else (a, number)) for a in found]
        return real(name, number, wanted, type, proto, flags)

    socket.getaddrinfo = getaddrinfo
    try:
        yield
    finally:
        socket.getaddrinfo = real


def unix_socket_handlers(path, context):
    """urllib handlers whose connections go to the Unix socket ``path``
    (TLS on top for https, with the URL's host as the server name)."""
    if not hasattr(socket, 'AF_UNIX'):
        raise NotImplementedError('--unix-socket: this Python has no AF_UNIX sockets')

    def _unix(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None and self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(self.timeout)
        sock.connect(path)
        return sock

    class UnixHTTPConnection(http.client.HTTPConnection):
        def connect(self):
            self.sock = _unix(self)

    class UnixHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            self.sock = self._context.wrap_socket(_unix(self), server_hostname=self.host)

    class UnixHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(UnixHTTPConnection, req)

    class UnixHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(UnixHTTPSConnection, req, context=context)

    return [UnixHTTPHandler(), UnixHTTPSHandler(context=context)]
