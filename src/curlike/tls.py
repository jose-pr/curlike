"""TLS options: how the server is verified (the OS trust store, ``--cacert``
/ ``--capath``, or not at all with ``-k``) and the client certificate
(``--cert`` / ``--key`` / ``--pass``, PEM)."""

import os
import re
import shutil
import ssl
import tempfile
from typing import Optional

from syshttp.tls import new_os_context

from ._duho import Meta, Arg
from .args import Group
from .errors import EXIT_CACERT, EXIT_CRL, EXIT_CLIENT_CERT, EXIT_USAGE, EarlyExit, LocalError

EXIT_CIPHER = 59
#: --tls-max values -> the highest version allowed.
TLS_MAX = {'1.0': 'TLSv1', '1.1': 'TLSv1_1', '1.2': 'TLSv1_2', '1.3': 'TLSv1_3', 'default': None}


def split_cert(value):
    """curl's ``--cert <file[:password]>``: the first ``:`` starts the
    password; ``\\:`` is a literal colon in the name and, on Windows, a
    drive (``C:\\`` / ``C:/``) is part of it, as curl reads it."""
    name, i = [], 0
    while i < len(value):
        char = value[i]
        if char == '\\' and value[i + 1 : i + 2] == ':':
            name.append(':')
            i += 2
            continue
        drive = os.name == 'nt' and i == 1 and value[0].isalpha() and value[2:3] in ('\\', '/')
        if char == ':' and not drive:
            return ''.join(name), value[i + 1 :]
        name.append(char)
        i += 1
    return ''.join(name), None


def _pem_only(option, value):
    if value and value.upper() != 'PEM':
        raise NotImplementedError('Unsupported %s: %s (the fallback reads PEM only)' % (option, value))


#: curl's own override of the CA bundle, honoured like ``--cacert``.
CA_BUNDLE_VAR = 'CURL_CA_BUNDLE'


_CRL_BLOCK = re.compile(r'-----BEGIN X509 CRL-----.*?-----END X509 CRL-----', re.DOTALL)


def load_crls(ctx, path):
    """Load only the CRLs of the PEM file ``path`` into ``ctx``, as curl does:
    a certificate in the file is not trusted by it. A file with no CRL, or one
    that cannot be read, raises ``OSError`` / ``ssl.SSLError``."""
    with open(path, encoding='ascii', errors='replace') as handle:
        blocks = _CRL_BLOCK.findall(handle.read())
    if not blocks:
        raise ssl.SSLError('no CRL found in the file')
    # OpenSSL reads CRLs from a file only.
    scratch = tempfile.mkdtemp(prefix='curlike-crl-')
    try:
        crls = os.path.join(scratch, 'crls.pem')
        with open(crls, 'w', encoding='ascii', newline='\n') as handle:
            handle.write('\n'.join(blocks) + '\n')
        ctx.load_verify_locations(cafile=crls)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def build_ssl_context(
    insecure,
    cacert=None,
    capath=None,
    cert=None,
    key=None,
    passphrase=None,
    min_version=None,
    max_version=None,
    ciphers=None,
    crlfile=None,
):
    """An SSL context. The server is verified against ``cacert`` / ``capath``
    when given, else ``$CURL_CA_BUNDLE`` (both replace the trust store, as in
    curl), else the OS trust store -- ``syshttp.tls``, the store the requests
    session verifies against too; ``insecure`` (-k) verifies nothing.
    ``cert`` (``file[:password]``, may hold the key) / ``key`` /
    ``passphrase`` present a client certificate. ``min_version`` /
    ``max_version`` (``ssl.TLSVersion``) bound the protocol; ``ciphers`` is
    an OpenSSL cipher list (TLS 1.2 and below). A file that cannot be used
    raises :class:`LocalError`: 77 for the CA side, 58 for the client
    certificate; 59 is an unusable cipher list."""
    if not (cacert or capath):
        cacert = os.environ.get(CA_BUNDLE_VAR) or None
    if insecure:
        # A plain ssl context: nothing is verified, so the OS verifier has no
        # part, and macOS's (truststore) still evaluates the chain under CERT_NONE.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif cacert or capath:
        if capath and not os.path.isdir(capath):
            raise LocalError(
                EXIT_CACERT, 'error setting certificate verify locations: CApath: %s (not a directory)' % capath
            )
        try:
            ctx = new_os_context(cafile=cacert, capath=capath)
        except (OSError, ssl.SSLError) as exc:
            raise LocalError(
                EXIT_CACERT,
                'error setting certificate verify locations: CAfile: %s CApath: %s (%s)'
                % (cacert or 'none', capath or 'none', exc),
            )
    elif crlfile:
        # The OS verifier (truststore) ignores OpenSSL's CRL flags: a CRL
        # check needs OpenSSL to verify, over the system's store.
        ctx = ssl.create_default_context()
    else:
        # A client certificate of the caller's own is the one sent: the OS
        # store offers none then.
        ctx = new_os_context(client_certificates=not cert)
    if crlfile and not insecure:
        # curl's --crlfile: the chain is checked against these lists (82 when
        # the file cannot be loaded; a revoked certificate fails as 60).
        try:
            load_crls(ctx, crlfile)
        except (OSError, ssl.SSLError) as exc:
            raise LocalError(EXIT_CRL, 'failed to load CRL file: %s (%s)' % (crlfile, exc))
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
    # Python 3.13 turns on strict X.509 checks that curl and older Pythons do
    # not make (a leaf with no Authority Key Identifier fails them).
    strict = getattr(ssl, 'VERIFY_X509_STRICT', 0)
    if ctx.verify_flags & strict:
        ctx.verify_flags &= ~strict
    if min_version is not None:
        ctx.minimum_version = min_version
    if max_version is not None:
        ctx.maximum_version = max_version
    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError as exc:
            raise LocalError(EXIT_CIPHER, 'failed setting cipher list: %s (%s)' % (ciphers, exc))
    if cert:
        certfile, password = split_cert(cert)
        if passphrase is not None:
            password = passphrase
        try:
            ctx.load_cert_chain(certfile, keyfile=key or None, password=password)
        except (OSError, ssl.SSLError) as exc:
            raise LocalError(
                EXIT_CLIENT_CERT,
                'could not load PEM client certificate %s%s (%s)' % (certfile, ', key %s' % key if key else '', exc),
            )
    return ctx


class ProxyTLS(object):
    """TLS to an ``https://`` proxy: its ``context`` (from the ``--proxy-*``
    options, never the origin's) and the ``pins`` its key must match."""

    def __init__(self, context, pins=None):
        self.context = context
        self.pins = pins


class UnusableContext(object):
    """Stands in for the SSL context when its files could not be loaded.
    urllib builds HTTPS connections with it as with any context; the
    handshake -- after the TCP connect and any CONNECT, where curl loads
    them -- raises the :class:`LocalError` (77 / 58). A plain-http transfer
    never touches it."""

    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True
    post_handshake_auth = None

    def __init__(self, error):
        self.error = error

    def wrap_socket(self, sock, *args, **kwargs):
        raise self.error

    def wrap_bio(self, *args, **kwargs):
        raise self.error


#: The origin flags a caller's ``ssl_context`` replaces: (attribute, flag).
ORIGIN_TLS_FLAGS = (
    ('insecure', '-k'),
    ('cacert', '--cacert'),
    ('capath', '--capath'),
    ('cert', '--cert'),
    ('key', '--key'),
    ('pass_', '--pass'),
    ('ciphers', '--ciphers'),
    ('crlfile', '--crlfile'),
    ('tlsv1', '--tlsv1'),
    ('tlsv1_0', '--tlsv1.0'),
    ('tlsv1_1', '--tlsv1.1'),
    ('tlsv1_2', '--tlsv1.2'),
    ('tlsv1_3', '--tlsv1.3'),
    ('tls_max', '--tls-max'),
)
#: The same for a caller's ``proxy_ssl_context``.
PROXY_TLS_FLAGS = (
    ('proxy_insecure', '--proxy-insecure'),
    ('proxy_cacert', '--proxy-cacert'),
    ('proxy_capath', '--proxy-capath'),
    ('proxy_cert', '--proxy-cert'),
    ('proxy_key', '--proxy-key'),
    ('proxy_pass', '--proxy-pass'),
    ('proxy_ciphers', '--proxy-ciphers'),
    ('proxy_crlfile', '--proxy-crlfile'),
    ('proxy_tlsv1', '--proxy-tlsv1'),
)


class TLSArgs(Group):
    """Server verification and the client certificate."""

    # A caller's own contexts (``curlike.run_fallback(ssl_context=...)``),
    # used as given in place of the ones the flags would build. Not options.
    caller_ssl_context = None
    caller_proxy_ssl_context = None

    crlfile: Arg[Optional[str], Meta(metavar='FILE')] = None
    "Check the server's chain against this certificate revocation list (PEM)"
    ("--crlfile",)

    # The same, for an https:// proxy (never taken from the origin's options).
    proxy_insecure: bool = False
    "Do not verify the https:// proxy's certificate"
    ("--proxy-insecure",)

    proxy_cacert: Arg[Optional[str], Meta(metavar='FILE')] = None
    "Verify the https:// proxy against this CA bundle (PEM)"
    ("--proxy-cacert",)

    proxy_capath: Arg[Optional[str], Meta(metavar='DIR')] = None
    "Verify the https:// proxy against this hashed CA directory"
    ("--proxy-capath",)

    proxy_cert: Arg[Optional[str], Meta(metavar='FILE[:PASSWORD]')] = None
    "Client certificate for the https:// proxy (PEM)"
    ("--proxy-cert",)

    proxy_cert_type: Arg[Optional[str], Meta(metavar='TYPE')] = None
    "--proxy-cert type: PEM only"
    ("--proxy-cert-type",)

    proxy_key: Arg[Optional[str], Meta(metavar='FILE')] = None
    "Private key for --proxy-cert (PEM)"
    ("--proxy-key",)

    proxy_key_type: Arg[Optional[str], Meta(metavar='TYPE')] = None
    "--proxy-key type: PEM only"
    ("--proxy-key-type",)

    proxy_pass: Arg[Optional[str], Meta(metavar='PHRASE')] = None
    "Passphrase for --proxy-key"
    ("--proxy-pass",)

    proxy_ciphers: Arg[Optional[str], Meta(metavar='LIST')] = None
    "OpenSSL cipher list for the https:// proxy"
    ("--proxy-ciphers",)

    proxy_crlfile: Arg[Optional[str], Meta(metavar='FILE')] = None
    "Check the https:// proxy's chain against this revocation list (PEM)"
    ("--proxy-crlfile",)

    proxy_pinnedpubkey: Arg[Optional[str], Meta(metavar='HASHES|FILE')] = None
    "Require the https:// proxy's key: sha256//BASE64[;...] or a key file (exit 90)"
    ("--proxy-pinnedpubkey",)

    proxy_tlsv1: bool = False
    "TLS 1.0 or later to the https:// proxy"
    ("--proxy-tlsv1",)

    pinnedpubkey: Arg[Optional[str], Meta(metavar='HASHES|FILE')] = None
    "Require the server key: sha256//BASE64[;...] or a public key file (exit 90)"
    ("--pinnedpubkey",)

    insecure: bool = False
    "Allow insecure server connections"
    ("-k", "--insecure")

    cacert: Arg[Optional[str], Meta(metavar='FILE')] = None
    "Verify the server against this CA bundle (PEM) instead of the OS trust store"
    ("--cacert",)

    capath: Arg[Optional[str], Meta(metavar='DIR')] = None
    "Verify the server against this hashed CA directory instead of the OS trust store"
    ("--capath",)

    cert: Arg[Optional[str], Meta(metavar='FILE[:PASSWORD]')] = None
    "Client certificate (PEM; may hold the key too)"
    ("-E", "--cert")

    cert_type: Arg[Optional[str], Meta(metavar='TYPE')] = None
    "Client certificate type: PEM only"
    ("--cert-type",)

    key: Arg[Optional[str], Meta(metavar='FILE')] = None
    "Private key for --cert (PEM)"
    ("--key",)

    key_type: Arg[Optional[str], Meta(metavar='TYPE')] = None
    "Private key type: PEM only"
    ("--key-type",)

    pass_: Arg[Optional[str], Meta(metavar='PHRASE')] = None
    "Passphrase for the private key"
    ("--pass",)

    tlsv1: bool = False
    "TLS 1.0 or later"
    ("-1", "--tlsv1")

    tlsv1_0: bool = False
    "TLS 1.0 or later"
    ("--tlsv1.0",)

    tlsv1_1: bool = False
    "TLS 1.1 or later"
    ("--tlsv1.1",)

    tlsv1_2: bool = False
    "TLS 1.2 or later"
    ("--tlsv1.2",)

    tlsv1_3: bool = False
    "TLS 1.3 or later"
    ("--tlsv1.3",)

    tls_max: Arg[Optional[str], Meta(metavar='VERSION')] = None
    "Highest TLS version: 1.0, 1.1, 1.2, 1.3 or default"
    ("--tls-max",)

    ciphers: Arg[Optional[str], Meta(metavar='LIST')] = None
    "OpenSSL cipher list (TLS 1.2 and below)"
    ("--ciphers",)

    # No-ops, each true of this client: no revocation checks or session
    # reuse, no ALPN/NPN offered, and the OS trust store is its default.
    ssl_no_revoke: bool = False
    "Skip certificate revocation checks (a no-op: none are made)"
    ("--ssl-no-revoke",)

    ssl_revoke_best_effort: bool = False
    "Ignore revocation-check failures (a no-op: none are made)"
    ("--ssl-revoke-best-effort",)

    ca_native: bool = False
    "Use the OS certificate store (a no-op: the default)"
    ("--ca-native",)

    proxy_ca_native: bool = False
    "Use the OS certificate store for the proxy (a no-op)"
    ("--proxy-ca-native",)

    no_sessionid: bool = False
    "No TLS session reuse (a no-op: none is done)"
    ("--no-sessionid",)

    no_alpn: bool = False
    "No ALPN (a no-op: none is offered)"
    ("--no-alpn",)

    no_npn: bool = False
    "No NPN (a no-op: none is offered)"
    ("--no-npn",)

    def _check(self):
        _pem_only('--cert-type', self.cert_type)
        _pem_only('--key-type', self.key_type)
        _pem_only('--proxy-cert-type', self.proxy_cert_type)
        _pem_only('--proxy-key-type', self.proxy_key_type)
        if self.tls_max is not None and self.tls_max not in TLS_MAX:
            raise ValueError('--tls-max: expected one of %s, got %r' % (', '.join(TLS_MAX), self.tls_max))

    def tls_versions(self):
        """``(minimum, maximum)`` as ``ssl.TLSVersion`` (``None``: the default)."""
        floor = None
        for flag, name in (
            (self.tlsv1_3, 'TLSv1_3'),
            (self.tlsv1_2, 'TLSv1_2'),
            (self.tlsv1_1, 'TLSv1_1'),
            (self.tlsv1_0 or self.tlsv1, 'TLSv1'),
        ):
            if flag:
                floor = getattr(ssl.TLSVersion, name)
                break
        top = TLS_MAX.get(self.tls_max) if self.tls_max else None
        return floor, getattr(ssl.TLSVersion, top) if top else None

    def check_files(self):
        """curl's parse-time check: a ``--cacert`` / ``--crlfile`` / ``--netrc-file`` naming
        no file is exit 2 before anything else."""
        named = (
            ('--cacert', self.cacert),
            ('--crlfile', self.crlfile),
            ('--proxy-cacert', self.proxy_cacert),
            ('--proxy-crlfile', self.proxy_crlfile),
            ('--netrc-file', getattr(self, 'netrc_file', None)),
        )
        missing = [path for _, path in named if path and not os.path.exists(path)]
        if not missing:
            return
        for flag, path in named:
            if path and not os.path.exists(path):
                raise EarlyExit(EXIT_USAGE, "The file '%s' provided to %s does not exist" % (path, flag))

    def use_contexts(self, ssl_context=None, proxy_ssl_context=None):
        """Use a caller's contexts in place of the flags'. A flag the context
        replaces (``-k``, ``--cacert``, ``--cert``, ``--ciphers``, ``--tlsv1.2``,
        ...) given beside it is a ``ValueError`` naming it: the command would
        otherwise ignore it."""
        for context, flags, what in (
            (ssl_context, ORIGIN_TLS_FLAGS, 'ssl_context'),
            (proxy_ssl_context, PROXY_TLS_FLAGS, 'proxy_ssl_context'),
        ):
            if context is None:
                continue
            if not isinstance(context, ssl.SSLContext):
                raise TypeError('%s must be an ssl.SSLContext, not %s' % (what, type(context).__name__))
            given = [flag for attr, flag in flags if getattr(self, attr, None)]
            if given:
                raise ValueError('%s replaces %s: give one or the other' % (what, ', '.join(given)))
        self.caller_ssl_context = ssl_context
        self.caller_proxy_ssl_context = proxy_ssl_context

    def proxy_tls(self):
        """:class:`ProxyTLS` for an https:// proxy; a file that cannot be used
        fails at the proxy's handshake, as the origin's do at its own."""
        if self.caller_proxy_ssl_context is not None:
            context = self.caller_proxy_ssl_context
        else:
            context = self._proxy_context()
        from .connector import parse_pins

        pins = parse_pins(self.proxy_pinnedpubkey) if self.proxy_pinnedpubkey else None
        return ProxyTLS(context, pins)  # a pin file is read at the proxy's handshake

    def _proxy_context(self):
        try:
            return build_ssl_context(
                self.proxy_insecure,
                cacert=self.proxy_cacert,
                capath=self.proxy_capath,
                cert=self.proxy_cert,
                key=self.proxy_key,
                passphrase=self.proxy_pass,
                min_version=ssl.TLSVersion.TLSv1 if self.proxy_tlsv1 else None,
                ciphers=self.proxy_ciphers,
                crlfile=self.proxy_crlfile,
            )
        except LocalError as exc:
            return UnusableContext(exc)

    def ssl_context(self):
        if self.caller_ssl_context is not None:
            return self.caller_ssl_context
        floor, top = self.tls_versions()
        return build_ssl_context(
            self.insecure,
            cacert=self.cacert,
            capath=self.capath,
            cert=self.cert,
            key=self.key,
            passphrase=self.pass_,
            min_version=floor,
            max_version=top,
            ciphers=self.ciphers,
            crlfile=self.crlfile,
        )
