"""How each connection is made: its source address and port
(``--interface``, ``--local-port``), the headers its proxy CONNECT carries
(the proxy credential, and ``-p``'s CONNECT for http too), and the server key
it must present (``--pinnedpubkey``) -- one connection class per request,
built by :class:`Connector`, opened by :class:`ConnectHTTPHandler` /
:class:`ConnectHTTPSHandler` in place of urllib's own."""
import base64
import errno
import hashlib
import http.client
import io
import ipaddress
import socket
import ssl
import struct
import time
import urllib.parse
import urllib.request

from .errors import EXIT_USAGE, EarlyExit, LocalError

EXIT_INTERFACE = 45
EXIT_PINNED = 90
EXIT_PROXY = 97

#: socket.create_connection's "no timeout given" marker (private to socket).
_DEFAULT_TIMEOUT = getattr(socket, "_GLOBAL_DEFAULT_TIMEOUT", None)

#: Proxy URL schemes that are SOCKS, by the protocol each speaks: curl's
#: ``socks://`` is SOCKS4; ``socks5`` resolves the name locally, ``socks5h``
#: and ``socks4a`` let the proxy resolve it.
SOCKS_SCHEMES = {'socks': 'socks4', 'socks4': 'socks4', 'socks4a': 'socks4a', 'socks5': 'socks5',
                 'socks5h': 'socks5h'}


class Socks(object):
    """One SOCKS proxy: ``kind`` (``socks4``/``socks4a``/``socks5``/``socks5h``),
    ``host``, ``port`` (1080 by default) and the ``user``/``password`` SOCKS5
    sends (SOCKS4 sends the user as its id)."""

    def __init__(self, url, user=None, password=None):
        parts = urllib.parse.urlsplit(url if '://' in url else 'socks4://' + url)
        self.kind = SOCKS_SCHEMES[parts.scheme.lower()]
        self.host = parts.hostname
        self.port = parts.port or 1080
        if user is None and parts.username is not None:
            user = urllib.parse.unquote(parts.username)
            password = urllib.parse.unquote(parts.password or '')
        self.user, self.password = user, password

    @staticmethod
    def is_socks(url):
        return bool(url) and url.split('://', 1)[0].lower() in SOCKS_SCHEMES and '://' in url


def _exact(sock, count):
    data = b''
    while len(data) < count:
        piece = sock.recv(count - len(data))
        if not piece:
            raise ConnectionResetError('Connection was reset')
        data += piece
    return data


def _local_address(socks, host, port, family=0):
    """``host`` resolved here, as socks4 / socks5 ask; not resolvable: curl's
    6, or 97 before 8.20 (``compat``)."""
    try:
        return socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror:
        from .compat import socks_unresolved

        raise LocalError(*socks_unresolved(host, socks.host))


def socks_handshake(sock, socks, host, port):
    """Ask ``socks`` (connected as ``sock``) for ``host``:``port``. A refusal,
    an auth failure or a broken handshake is curl's 97."""
    try:
        if socks.kind in ('socks4', 'socks4a'):
            _socks4(sock, socks, host, port)
        else:
            _socks5(sock, socks, host, port)
    except OSError as exc:
        raise LocalError(EXIT_PROXY, 'Recv failure: %s' % (getattr(exc, 'strerror', None) or exc))


def _socks4(sock, socks, host, port):
    user = (socks.user or '').encode('utf-8') + b'\x00'
    try:
        address = socket.inet_aton(str(ipaddress.IPv4Address(host)))
        name = b''
    except ValueError:
        if socks.kind == 'socks4a':
            address, name = b'\x00\x00\x00\x01', host.encode('idna') + b'\x00'
        else:
            address, name = socket.inet_aton(_local_address(socks, host, port, socket.AF_INET)), b''
    sock.sendall(struct.pack('!BBH', 4, 1, port) + address + user + name)
    reply = _exact(sock, 8)
    if reply[1] != 0x5a:
        bound = '%s:%d' % (socket.inet_ntoa(reply[4:8]), struct.unpack('!H', reply[2:4])[0])
        raise LocalError(EXIT_PROXY, '[SOCKS] cannot complete SOCKS4 connection to %s. (%d), request rejected or '
                                     'failed.' % (bound, reply[1]))


def _socks5(sock, socks, host, port):
    methods = b'\x00\x02' if socks.user is not None else b'\x00'
    sock.sendall(b'\x05' + bytes([len(methods)]) + methods)
    chosen = _exact(sock, 2)[1]
    if chosen == 0x02:
        user, password = (socks.user or '').encode('utf-8'), (socks.password or '').encode('utf-8')
        sock.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
        status = _exact(sock, 2)
        if status[1] != 0:
            raise LocalError(EXIT_PROXY, 'User was rejected by the SOCKS5 server (%d %d).' % (status[0], status[1]))
    elif chosen != 0x00:
        raise LocalError(EXIT_PROXY, 'No authentication method was acceptable.')
    try:
        literal = ipaddress.ip_address(host.strip('[]'))
    except ValueError:
        literal = None
    if literal is None and socks.kind == 'socks5':
        literal = ipaddress.ip_address(_local_address(socks, host, port))
    if literal is None:
        name = host.encode('idna')
        target = b'\x03' + bytes([len(name)]) + name
    elif literal.version == 4:
        target = b'\x01' + literal.packed
    else:
        target = b'\x04' + literal.packed
    sock.sendall(b'\x05\x01\x00' + target + struct.pack('!H', port))
    head = _exact(sock, 4)
    if head[1] != 0:
        raise LocalError(EXIT_PROXY, 'cannot complete SOCKS5 connection to %s. (%d)' % (host, head[1]))
    kind = head[3]
    _exact(sock, {1: 4, 4: 16}.get(kind, 0) or _exact(sock, 1)[0])
    _exact(sock, 2)

#: A bind that failed because of the address or port, not the peer: the next
#: port of a --local-port range is tried.
_BIND_ERRNOS = {errno.EADDRINUSE, errno.EADDRNOTAVAIL, errno.EACCES, 10013, 10048, 10049}


def parse_local_port(spec):
    """``N`` or ``N-M`` (curl's ``--local-port``) -> ``(low, high)``."""
    low, _, high = (spec or '').partition('-')
    try:
        low, high = int(low), int(high or low)
    except ValueError:
        low = high = -1
    if not 0 < low <= high <= 65535:
        raise EarlyExit(EXIT_USAGE, "option --local-port: is badly used here\n"
                                    "curl: try 'curl --help' or 'curl --manual' for more information")
    return low, high


def _interface_address(name):
    """The first address (IPv4 first) of the interface ``name``, via netimps
    when it is installed; ``None`` otherwise."""
    try:
        import netimps
    except ImportError:
        return None
    for iface in netimps.get_interfaces():
        if iface.name == name:
            addresses = [ipaddress.ip_address(str(getattr(ip, 'ip', ip))) for ip in iface.ips]
            addresses.sort(key=lambda a: a.version)
            if addresses:
                return str(addresses[0])
    return None


def resolve_interface(spec):
    """The source address ``--interface`` names: an IP address, an interface
    (``if!NAME``, or a bare name that is one), or a host name (``host!NAME``,
    or a bare name that is not an interface). Unusable: curl's 45."""
    kind, name = None, spec
    for prefix in ('if!', 'host!'):
        if spec.startswith(prefix):
            kind, name = prefix[:-1], spec[len(prefix):]
    try:
        return str(ipaddress.ip_address(name.strip('[]')))
    except ValueError:
        pass
    if kind in (None, 'if'):
        found = _interface_address(name)
        if found:
            return found
        if kind == 'if':
            raise LocalError(EXIT_INTERFACE, "Couldn't bind to interface '%s'" % name)
    try:
        return socket.getaddrinfo(name, None, 0, socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror:
        raise LocalError(EXIT_INTERFACE, "Couldn't bind to '%s'" % name)


def _tlv(der, pos):
    """``(content start, content end)`` of the DER element at ``pos``."""
    length = der[pos + 1]
    start = pos + 2
    if length & 0x80:
        count = length & 0x7f
        length = int.from_bytes(der[start:start + count], 'big')
        start += count
    return start, start + length


def subject_public_key_info(cert_der):
    """The DER ``SubjectPublicKeyInfo`` of an X.509 certificate -- what curl's
    ``--pinnedpubkey`` hashes -- found by walking the TBSCertificate: an
    optional ``[0]`` version, then serial, signature, issuer, validity,
    subject, and the key."""
    start, _ = _tlv(cert_der, 0)              # Certificate
    pos, _ = _tlv(cert_der, start)            # TBSCertificate's content
    if cert_der[pos] == 0xa0:                 # [0] version
        pos = _tlv(cert_der, pos)[1]
    for _ in range(5):                        # serial .. subject
        pos = _tlv(cert_der, pos)[1]
    return cert_der[pos:_tlv(cert_der, pos)[1]]


def parse_pins(spec):
    """``--pinnedpubkey``: ``sha256//BASE64[;sha256//BASE64...]``, or a file
    holding the key (PEM ``PUBLIC KEY`` or DER) -> the set of SHA-256
    digests a server key may have."""
    if spec.startswith('sha256//'):
        pins = set()
        for part in spec.split(';'):
            part = part.strip()
            if not part.startswith('sha256//'):
                raise ValueError('--pinnedpubkey: expected sha256//BASE64[;sha256//BASE64], got %r' % spec)
            try:
                pins.add(base64.b64decode(part[len('sha256//'):], validate=True))
            except ValueError:
                raise ValueError('--pinnedpubkey: %r is not base64' % part)
        return pins
    try:
        with open(spec, 'rb') as handle:
            data = handle.read()
    except OSError as exc:
        raise LocalError(EXIT_PINNED, 'SSL: unable to read the pinned public key %s (%s)' % (spec, exc))
    if b'-----BEGIN PUBLIC KEY-----' in data:
        body = data.split(b'-----BEGIN PUBLIC KEY-----', 1)[1].split(b'-----END PUBLIC KEY-----', 1)[0]
        data = base64.b64decode(b''.join(body.split()))
    return {hashlib.sha256(data).digest()}


class TLSInTLS(object):
    """A TLS session carried inside another (the origin's, inside the one to
    an https:// proxy): ``ssl.SSLObject`` over memory BIOs, pumped through
    the outer socket -- an ``SSLSocket`` cannot itself be wrapped again.
    Offers what http.client uses of a socket."""

    def __init__(self, outer, context, server_hostname):
        self.outer = outer
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_hostname=server_hostname)
        self._pump(self.tls.do_handshake)

    def _pump(self, operation, *args):
        while True:
            try:
                result = operation(*args)
            except ssl.SSLWantReadError:
                self._flush()
                data = self.outer.recv(65536)
                if data:
                    self.incoming.write(data)
                else:
                    self.incoming.write_eof()
                continue
            except ssl.SSLWantWriteError:
                self._flush()
                continue
            self._flush()
            return result

    def _flush(self):
        data = self.outgoing.read()
        if data:
            self.outer.sendall(data)

    def sendall(self, data):
        view = memoryview(data)
        while view:
            sent = self._pump(self.tls.write, view)
            view = view[sent:]

    def send(self, data):
        return self._pump(self.tls.write, data)

    def recv(self, size=65536):
        try:
            return self._pump(self.tls.read, size)
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            return b''

    def recv_into(self, buffer, size=0):
        data = self.recv(size or len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def makefile(self, mode='rb', buffering=-1, **kwargs):
        return io.BufferedReader(_Reader(self), buffering if buffering and buffering > 0 else io.DEFAULT_BUFFER_SIZE)

    def getpeercert(self, binary_form=False):
        return self.tls.getpeercert(binary_form)

    def settimeout(self, timeout):
        self.outer.settimeout(timeout)

    def gettimeout(self):
        return self.outer.gettimeout()

    def setsockopt(self, *args):
        return self.outer.setsockopt(*args)

    def fileno(self):
        return self.outer.fileno()

    def close(self):
        self.outer.close()


class _Reader(io.RawIOBase):
    def __init__(self, transport):
        self.transport = transport

    def readable(self):
        return True

    def readinto(self, buffer):
        return self.transport.recv_into(buffer)


class ProxyAuth(object):
    """--proxy-digest / --proxy-anyauth: nothing up front; the proxy's 407
    is answered once, with Digest (or, for anyauth, Basic when that is all it
    offers)."""

    def __init__(self, user, password, anyauth=False):
        self.user, self.password, self.anyauth = user, password, anyauth

    def answer(self, challenges, method, uri):
        """The ``Proxy-Authorization`` for ``challenges`` (the 407's
        ``Proxy-Authenticate`` values), or ``None`` when none is ours."""
        for challenge in challenges:
            if challenge.strip().lower().startswith('digest'):
                return digest_authorization(challenge, self.user, self.password, method, uri)
        if self.anyauth and any(c.strip().lower().startswith('basic') for c in challenges):
            token = base64.b64encode(('%s:%s' % (self.user, self.password)).encode('utf-8')).decode('ascii')
            return 'Basic ' + token
        return None


def digest_authorization(challenge, user, password, method, uri):
    """RFC 7616 Digest (MD5 / SHA-256, ``qop=auth`` when offered) for one
    challenge."""
    import os

    fields = urllib.request.parse_keqv_list(urllib.request.parse_http_list(challenge.split(None, 1)[1]))
    algorithm = (fields.get('algorithm') or 'MD5').upper()
    digest = {'MD5': hashlib.md5, 'SHA-256': hashlib.sha256}.get(algorithm.replace('-SESS', ''))
    if digest is None:
        return None

    def h(text):
        return digest(text.encode('utf-8')).hexdigest()

    realm, nonce = fields.get('realm', ''), fields.get('nonce', '')
    ha1 = h('%s:%s:%s' % (user, realm, password))
    cnonce = os.urandom(8).hex()
    if algorithm.endswith('-SESS'):
        ha1 = h('%s:%s:%s' % (ha1, nonce, cnonce))
    ha2 = h('%s:%s' % (method, uri))
    qops = [q.strip() for q in fields.get('qop', '').split(',') if q.strip()]
    parts = ['username="%s"' % user, 'realm="%s"' % realm, 'nonce="%s"' % nonce, 'uri="%s"' % uri]
    if 'auth' in qops:
        response = h('%s:%s:00000001:%s:auth:%s' % (ha1, nonce, cnonce, ha2))
        parts += ['cnonce="%s"' % cnonce, 'nc=00000001', 'qop=auth']
    else:
        response = h('%s:%s:%s' % (ha1, nonce, ha2))
    parts.append('response="%s"' % response)
    if fields.get('opaque'):
        parts.append('opaque="%s"' % fields['opaque'])
    if fields.get('algorithm'):
        parts.append('algorithm=%s' % fields['algorithm'])
    return 'Digest ' + ', '.join(parts)


def _check_pins(sock, pins):
    if pins is None:
        return
    der = sock.getpeercert(binary_form=True)
    if not der or hashlib.sha256(subject_public_key_info(der)).digest() not in pins:
        sock.close()
        raise LocalError(EXIT_PINNED, 'SSL: public key does not match pinned public key')


def _reply_head(response):
    """A CONNECT reply's status line and headers, as -i shows them."""
    version = {10: '1.0', 11: '1.1'}.get(response.version, '1.1')
    head = 'HTTP/%s %d %s\r\n' % (version, response.status, response.reason)
    head += ''.join('%s: %s\r\n' % item for item in response.headers.items())
    return (head + '\r\n').encode('latin-1')


class Connector(object):
    """What every connection of one transfer shares: ``source`` (an address
    or ``None``), ``ports`` (``(low, high)`` or ``None``), ``pins`` (SHA-256
    digests of acceptable server keys, or ``None``), ``http10`` (``-0``:
    HTTP/1.0 requests)."""

    def __init__(self, source=None, ports=None, pins=None, http10=False):
        self.source = source
        self.connect_replies = []  # each CONNECT reply of the attempt, for -i / -D
        self.transfer = None  # the attempt's Transfer: where -w's timings and addresses go
        self.ports = ports
        self.pins = pins
        self.http10 = http10

    @property
    def binds(self):
        return self.source is not None or self.ports is not None

    def create_connection(self, address, timeout=_DEFAULT_TIMEOUT, source_address=None):
        """``socket.create_connection``, done here: the name looked up (timed),
        each address tried in turn -- from the chosen source, each port of the
        range while the bind is what fails (none left: 45) -- and the attempt's
        Transfer told when the lookup and the connect finished, which
        addresses the connection has, and that one more was made."""
        host, port = address
        record = self.transfer
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        if record is not None:
            record.t_namelookup = time.monotonic()
        low, high = self.ports or (0, 0)
        last = bind_error = None
        for family, kind, proto, _, sockaddr in infos:
            for local_port in range(low, high + 1):
                sock = socket.socket(family, kind, proto)
                try:
                    if timeout is not _DEFAULT_TIMEOUT:
                        sock.settimeout(timeout)
                    if self.binds:
                        try:
                            sock.bind((self.source or ('::' if family == socket.AF_INET6 else ''), local_port))
                        except OSError as exc:
                            bind_error = exc
                            raise
                    sock.connect(sockaddr)
                except OSError as exc:
                    sock.close()
                    last = exc
                    if exc is bind_error and self.ports and (getattr(exc, 'errno', None) in _BIND_ERRNOS
                                                             or getattr(exc, 'winerror', None) in _BIND_ERRNOS):
                        continue  # the next port of the range
                    break  # the next address
                if record is not None:
                    record.t_connect = time.monotonic()
                    record.remote = sock.getpeername()[:2]
                    record.local = sock.getsockname()[:2]
                    record.connects += 1
                return sock
        if last is not None and last is bind_error:
            what = '%s port %d-%d' % (self.source or '*', low, high) if self.ports else "'%s'" % self.source
            raise LocalError(EXIT_INTERFACE, "Couldn't bind to %s: %s" % (what, last))
        raise last if last is not None else OSError('getaddrinfo returned no address for %s' % host)

    def check_pin(self, sock):
        _check_pins(sock, self.pins)

    def socks_connection(self, socks, address, timeout=_DEFAULT_TIMEOUT, source_address=None):
        """A connection to ``address`` through ``socks``: TCP to the proxy
        (from this connector's source), then the handshake."""
        sock = self.create_connection((socks.host, socks.port), timeout, source_address)
        try:
            socks_handshake(sock, socks, address[0], address[1])
        except Exception:
            sock.close()
            raise
        return sock

    def connection_class(self, base, tunnel_headers=None, socks=None, proxy_tls=None, proxy_auth=None):
        """``base`` (``HTTPConnection`` / ``HTTPSConnection``) bound to this
        connector, its CONNECT carrying ``tunnel_headers`` too, its TCP
        connection made through ``socks`` (a :class:`Socks`) when given."""
        connector = self

        def _appconnect():
            if connector.transfer is not None:
                connector.transfer.t_appconnect = time.monotonic()

        class Connection(base):
            if connector.http10:
                # http.client's own HTTP/1.0 mode: the request line, and no
                # chunked upload.
                _http_vsn = 10
                _http_vsn_str = 'HTTP/1.0'

            def __init__(self, *args, **kwargs):
                base.__init__(self, *args, **kwargs)
                if socks is not None:
                    self._create_connection = lambda address, timeout=_DEFAULT_TIMEOUT, source=None: (
                        connector.socks_connection(socks, address, timeout, source))
                else:
                    self._create_connection = connector.create_connection

            def _send_output(self, message_body=None, encode_chunked=False):
                # The request leaves now (-w time_pretransfer); its head is
                # counted (size_request); once sent, time_posttransfer.
                record = connector.transfer
                if self.sock is None and self.auto_open:
                    self.connect()  # http.client connects inside the first send: connect first
                if record is not None:
                    record.t_pretransfer = time.monotonic()
                    record.size_request += len(b"\r\n".join(self._buffer + [b"", b""]))
                base._send_output(self, message_body, encode_chunked)
                if record is not None:
                    record.t_posttransfer = time.monotonic()

            def set_tunnel(self, host, port=None, headers=None):
                merged = dict(headers or {})
                merged.update(tunnel_headers or {})
                base.set_tunnel(self, host, port, merged)

            def _tunnel(self):
                """The CONNECT, done here rather than by http.client: each reply
                is kept for -i / -D (curl prints it before the response), and
                a 407 is answered once when --proxy-digest / --proxy-anyauth
                ask (http.client's own drops the challenge). A refusal raises
                as http.client's does."""
                target = '%s:%d' % (self._tunnel_host, self._tunnel_port)
                authorization = None
                for _ in range(2):
                    lines = ['CONNECT %s HTTP/1.1' % target, 'Host: %s' % target]
                    lines += ['%s: %s' % item for item in self._tunnel_headers.items()]
                    if authorization:
                        lines.append('Proxy-Authorization: %s' % authorization)
                    self.send(('\r\n'.join(lines) + '\r\n\r\n').encode('latin-1'))
                    response = self.response_class(self.sock, method='CONNECT')
                    response.begin()
                    connector.connect_replies.append(_reply_head(response))
                    if connector.transfer is not None:
                        connector.transfer.connect_status = response.status
                    if response.status == 200:
                        return
                    challenges = response.headers.get_all('Proxy-Authenticate') or []
                    if proxy_auth is None or response.status != 407 or authorization or not challenges:
                        break
                    authorization = proxy_auth.answer(challenges, 'CONNECT', target)
                    if authorization is None:
                        break
                    if response.length:
                        response.read()  # the 407's body, before the same connection is reused
                    if response.will_close:
                        self.sock.close()
                        self.sock = None
                        self._reopen()
                self.close()
                raise OSError('Tunnel connection failed: %d %s' % (response.status, response.reason.strip()))

            def _reopen(self):
                raw = self._create_connection((self.host, self.port), self.timeout, self.source_address)
                self.sock = proxy_tls.context.wrap_socket(raw, server_hostname=self.host) if proxy_tls else raw

            def connect(self):
                if proxy_tls is None:
                    base.connect(self)
                    if isinstance(self, http.client.HTTPSConnection):
                        connector.check_pin(self.sock)
                        _appconnect()
                    return
                # An https:// proxy: TLS to it (its own context), then the
                # CONNECT through that, then the origin's TLS inside it.
                raw = self._create_connection((self.host, self.port), self.timeout, self.source_address)
                self.sock = proxy_tls.context.wrap_socket(raw, server_hostname=self.host)
                _check_pins(self.sock, proxy_tls.pins)
                if self._tunnel_host:
                    self._tunnel()
                    if isinstance(self, http.client.HTTPSConnection):
                        self.sock = TLSInTLS(self.sock, self._context, self._tunnel_host)
                        connector.check_pin(self.sock)
                        _appconnect()

        return Connection


class ConnectHTTPHandler(urllib.request.HTTPHandler):
    """urllib's HTTP handler, connecting through a :class:`Connector`."""

    def __init__(self, connector):
        urllib.request.HTTPHandler.__init__(self)
        self.connector = connector

    def http_open(self, req):
        klass = self.connector.connection_class(http.client.HTTPConnection, getattr(req, 'tunnel_headers', None),
                                                getattr(req, 'socks_via', None), getattr(req, 'proxy_tls', None),
                                                getattr(req, 'proxy_auth', None))
        return self.do_open(klass, req)


class ConnectHTTPSHandler(urllib.request.HTTPSHandler):
    """urllib's HTTPS handler, connecting through a :class:`Connector`; the
    proxy credential set as ``req.tunnel_headers`` rides on the CONNECT and
    nowhere else (urllib itself moves only a header named
    ``Proxy-Authorization`` there)."""

    def __init__(self, connector, context):
        urllib.request.HTTPSHandler.__init__(self, context=context)
        self.connector = connector

    def https_open(self, req):
        klass = self.connector.connection_class(http.client.HTTPSConnection, getattr(req, 'tunnel_headers', None),
                                                getattr(req, 'socks_via', None), getattr(req, 'proxy_tls', None),
                                                getattr(req, 'proxy_auth', None))
        kwargs = {'context': self._context}
        if hasattr(self, '_check_hostname'):  # Python < 3.12
            kwargs['check_hostname'] = self._check_hostname
        return self.do_open(klass, req, **kwargs)
