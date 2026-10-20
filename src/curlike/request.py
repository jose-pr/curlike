"""Request options: the URL and its query, the method, and the headers --
the ones options imply, then ``-H`` on top."""

import re
import urllib.parse
from typing import List, Optional

from ._duho import Meta, Arg
from .args import Group, read_failure, read_source, url_encoded
from .errors import EXIT_PROTOCOL, EXIT_READ, EXIT_URL, EXIT_USAGE, EarlyExit, LocalError

#: The curl release the command answers as (``%{curl_version}``, the User-Agent).
CURL_VERSION = (8, 22, 0)
USER_AGENT = "curl/%d.%d.%d" % CURL_VERSION

#: The schemes the fallback speaks.
SCHEMES = ('http', 'https')
#: Schemes curl speaks and the fallback does not: refused out loud (exit 2),
#: as any flag it lacks. A scheme curl does not know either is curl's own
#: exit 1.
CURL_SCHEMES = frozenset(
    [
        'dict',
        'file',
        'ftp',
        'ftps',
        'gopher',
        'gophers',
        'imap',
        'imaps',
        'ipfs',
        'ipns',
        'ldap',
        'ldaps',
        'mqtt',
        'pop3',
        'pop3s',
        'rtmp',
        'rtsp',
        'scp',
        'sftp',
        'smb',
        'smbs',
        'smtp',
        'smtps',
        'telnet',
        'tftp',
        'ws',
        'wss',
    ]
)


#: An IPv6 literal host, which curl does not take for a glob range.
_IPV6_HOST = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/@]*@)?\[[0-9a-fA-F:.]+(?:%[^\]]*)?\]')


def check_glob(url):
    """curl expands ``{a,b}`` and ``[1-3]`` in a URL into one transfer each
    unless ``-g``; the fallback makes one transfer, so a pattern is refused
    out loud (exit 2) rather than sent as typed. A broken one is curl's own
    exit 3 at parse time (no ``-w``). An IPv6 literal host is not a range."""
    host = _IPV6_HOST.match(url)
    start = host.end() if host else 0
    depth = None
    for index in range(start, len(url)):
        char = url[index]
        if char in '{[':
            if depth is not None:
                raise EarlyExit(EXIT_URL, '(3) nested brace in position %d:' % (index + 1))
            depth = (char, index)
        elif char in '}]':
            if depth is None or '{['.index(depth[0]) != '}]'.index(char):
                raise EarlyExit(EXIT_URL, '(3) unmatched close brace/bracket in position %d:' % (index + 1))
            if char == ']' and not re.match(r'^(?:[a-zA-Z]-[a-zA-Z]|\d+-\d+)(?::\d+)?$', url[depth[1] + 1 : index]):
                raise EarlyExit(EXIT_URL, '(3) bad range in position %d:' % (depth[1] + 2))
            raise NotImplementedError(
                'URL globbing (%s in the URL) makes several transfers, which the fallback does not do: '
                'pass -g to send the URL as typed' % url[depth[1] : index + 1]
            )
    if depth is not None:
        if depth[0] == '{':
            raise EarlyExit(EXIT_URL, '(3) unmatched brace in position %d:' % (len(url) + 1))
        # A range opens with a letter or a digit; anything else is no range at all.
        what = (
            'bad range in position'
            if url[depth[1] + 1 : depth[1] + 2].isalnum()
            else 'bad range specification in position'
        )
        raise EarlyExit(EXIT_URL, '(3) %s %d:' % (what, depth[1] + 2))


_URL_REFUSED = re.compile('[\x00-\x20\x7f]')


def encode_non_ascii(url):
    """``url`` with every non-ASCII character in its path, query and
    fragment as the percent-encoded bytes of its UTF-8, and a non-ASCII host
    name in IDNA form, as curl sends them."""
    if url.isascii():
        return url
    parts = urllib.parse.urlsplit(url)
    netloc = parts.netloc
    if not netloc.isascii():
        userinfo, at, hostport = netloc.rpartition('@')
        host, colon, port = hostport.rpartition(':') if not hostport.endswith(']') else (hostport, '', '')
        try:
            host = host.encode('idna').decode('ascii')
        except UnicodeError:
            raise LocalError(EXIT_URL, 'URL rejected: Bad hostname')
        netloc = userinfo + at + host + colon + port
    quoted = parts._replace(
        netloc=netloc,
        path=urllib.parse.quote(parts.path, safe="/%:@!$&'()*+,;=~-._"),
        query=urllib.parse.quote(parts.query, safe="/%:@!$&'()*+,;=~-._?"),
        fragment=urllib.parse.quote(parts.fragment, safe="/%:@!$&'()*+,;=~-._?"),
    )
    return urllib.parse.urlunsplit(quoted)


def check_url(url):
    """curl's verdict on a URL before anything is sent: 1 for a scheme
    curl does not speak, 3 for one it cannot parse (a broken IPv6 literal, a
    port out of range, no host). A scheme curl speaks and the fallback does
    not raises ``NotImplementedError``."""
    scheme = url.split('://', 1)[0].lower()
    if _URL_REFUSED.search(url):
        raise LocalError(EXIT_URL, 'URL rejected: Malformed input to a URL function')
    if scheme not in SCHEMES:
        if scheme in CURL_SCHEMES:
            raise NotImplementedError('Unsupported protocol: %s' % scheme)
        raise LocalError(EXIT_PROTOCOL, 'Protocol "%s" not supported' % scheme)
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise LocalError(
            EXIT_URL,
            'URL rejected: %s' % ('Bad IPv6 address' if 'IPv6' in str(exc) else 'Malformed input to a URL function'),
        )
    try:
        parts.port
    except ValueError:
        raise LocalError(EXIT_URL, 'URL rejected: Port number was not a decimal number between 0 and 65535')
    if not parts.hostname:
        raise LocalError(EXIT_URL, 'URL rejected: No host part in the URL')


#: Every protocol curl knows, for --proto's names (``all`` is all of them).
ALL_PROTOCOLS = frozenset(SCHEMES) | CURL_SCHEMES

#: Where a redirect may go by default (curl: http, https, ftp, ftps).
DEFAULT_REDIRECT_PROTOCOLS = frozenset(['http', 'https', 'ftp', 'ftps'])


def parse_protocols(spec, flag, start):
    """curl's protocol list (``--proto`` / ``--proto-redir``): comma-separated
    names, each ``+`` (add; the default), ``-`` (remove) or ``=`` (exactly
    these, from nothing), ``all`` for every protocol; ``start`` is the set
    before the list. An unknown name is curl's parse-time 2."""
    allowed = set(start)
    for token in (spec or '').split(','):
        token = token.strip()
        if not token:
            continue
        op, name = (token[0], token[1:]) if token[0] in '+-=' else ('+', token)
        name = name.strip().lower()
        names = set(ALL_PROTOCOLS) if name == 'all' else {name}
        if name != 'all' and name not in ALL_PROTOCOLS:
            raise EarlyExit(
                EXIT_USAGE,
                "option %s: is badly used here\n"
                "curl: try 'curl --help' or 'curl --manual' for more information" % flag,
            )
        if op == '=':
            allowed = set(names)
        elif op == '-':
            allowed -= names
        else:
            allowed |= names
    return allowed


def remove_dot_segments(path):
    """RFC 3986's remove_dot_segments, what curl does to a URL's path unless
    --path-as-is: ``/a/../b`` -> ``/b``, ``/a/./b/.`` -> ``/a/b/``."""
    out = []
    segments = path.split('/')
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == '..':
            if len(out) > 1:
                out.pop()
            if last:
                out.append('')
        elif segment == '.':
            if last:
                out.append('')
        else:
            out.append(segment)
    joined = '/'.join(out)
    return joined if joined.startswith('/') or not path.startswith('/') else '/' + joined


def normalize_path(url):
    """``url`` with its path's dot segments resolved (query and fragment as
    they are)."""
    parts = urllib.parse.urlsplit(url)
    if '.' not in parts.path:
        return url
    return urllib.parse.urlunsplit(parts._replace(path=remove_dot_segments(parts.path)))


def _header_lines(values):
    """``-H`` values with each ``@file`` replaced by its lines (curl's
    header file: one header per line, blank lines skipped). A file that is
    not there is curl's exit 26, before anything is sent."""
    for value in values:
        if not value.startswith('@'):
            yield value
            continue
        try:
            text = read_source(value[1:]).decode('utf-8', errors='replace')
        except OSError:
            raise read_failure(value[1:], '-H')
        for line in text.splitlines():
            if line.strip():
                yield line


def default_scheme(url, scheme='http'):
    """``url`` with curl's default scheme (``http``, or --proto-default's)
    when it names none; ``scheme:///host/path`` read as
    ``scheme://host/path``, as curl does."""
    if '://' not in url:
        return '%s://%s' % (scheme, url)
    scheme, rest = url.split('://', 1)
    return '%s://%s' % (scheme, rest.lstrip('/')) if rest.startswith('/') else url


def add_query(url, pieces):
    """``url`` with ``pieces`` appended to its query (``?`` or ``&``)."""
    pieces = [piece for piece in pieces if piece]
    if not pieces:
        return url
    base, hashmark, fragment = url.partition('#')
    return base + ('&' if '?' in base else '?') + '&'.join(pieces) + hashmark + fragment


def has_header(headers, name):
    """Is ``name`` among ``headers`` (any case)?"""
    return any(k.lower() == name.lower() for k in headers)


class HeaderValues(str):
    """A header given more than once by ``-H``: ``values`` are sent as one
    line each (the string itself is the last one)."""

    def __new__(cls, values):
        value = str.__new__(cls, values[-1])
        value.values = list(values)
        return value


def _set_header(headers, key, value):
    """Set ``key`` case-insensitively (one entry per name, the caller's case)."""
    for existing in list(headers):
        if existing.lower() == key.lower():
            del headers[existing]
    headers[key] = value


class RequestArgs(Group):
    """URL, method and headers."""

    url_positional: Arg[Optional[str], Meta(metavar='URL', nargs='?')] = None
    "URL to fetch"
    ("url_positional",)

    url: Optional[str] = None
    "URL to fetch (option)"
    ("--url",)

    request: Arg[Optional[str], Meta(metavar='METHOD')] = None
    "Request method (default GET; POST with a body, PUT with -T, HEAD with -I)"
    ("-X", "--request")

    get: bool = False
    "Send the -d / --data-urlencode data as the query of a GET"
    ("-G", "--get")

    url_query: Arg[Optional[List[str]], Meta(metavar='DATA')] = None
    "Add to the URL query (the --data-urlencode forms; +DATA as it stands)"
    ("--url-query",)

    header: Optional[List[str]] = None
    "Custom header (Name: value sets, Name: removes, Name; sends it empty)"
    ("-H", "--header")

    user_agent: Optional[str] = None
    "Set User-Agent"
    ("-A", "--user-agent")

    referer: Arg[Optional[str], Meta(metavar='URL')] = None
    "Referer header"
    ("-e", "--referer")

    range: Arg[Optional[str], Meta(metavar='RANGE')] = None
    "Ask for a byte range (Range: bytes=RANGE)"
    ("-r", "--range")

    compressed: bool = False
    "Ask for a compressed response and decode it"
    ("--compressed",)

    proto: Arg[Optional[str], Meta(metavar='PROTOCOLS')] = None
    "Allow only these protocols (+name, -name, =name, all; comma-separated)"
    ("--proto",)

    proto_redir: Arg[Optional[str], Meta(metavar='PROTOCOLS')] = None
    "Allow only these protocols on a redirect (default http,https,ftp,ftps)"
    ("--proto-redir",)

    proto_default: Arg[Optional[str], Meta(metavar='PROTOCOL')] = None
    "The scheme of a URL that names none (default http)"
    ("--proto-default",)

    path_as_is: bool = False
    "Send /../ and /./ in the path as typed (default: resolved, as curl does)"
    ("--path-as-is",)

    request_target: Arg[Optional[str], Meta(metavar='TARGET')] = None
    "Send this request target (e.g. '*' for OPTIONS) instead of the URL's path"
    ("--request-target",)

    def target_url(self):
        """The URL to request: ``--url`` or the positional, ``http://`` when
        it names no scheme (as curl), ``--url-query`` appended. Any scheme but
        http/https is refused (:func:`check_url`); no URL at all is curl's
        usage error."""
        url = self.url or self.url_positional
        if not url:
            raise EarlyExit(
                EXIT_USAGE, "(2) no URL specified\ncurl: try 'curl --help' or 'curl --manual' for more information"
            )
        if self.proto_default is not None and self.proto_default.lower() not in ALL_PROTOCOLS:
            raise EarlyExit(
                1,
                "option --proto-default: a specified protocol is unsupported by libcurl\n"
                "curl: try 'curl --help' or 'curl --manual' for more information",
            )
        url = default_scheme(url, (self.proto_default or 'http').lower())
        if not self.globoff:
            check_glob(url)
        check_url(url)
        self.check_protocol(url)
        url = encode_non_ascii(url)
        url = self.remember_auth_url(url)  # user:pw@ -> credentials
        if not self.path_as_is:
            url = normalize_path(url)
        return add_query(url, [url_encoded(q, self.read_data, raw_plus=True) for q in self.url_query or []])

    def check_protocol(self, url, redirect=False):
        """curl's exit 1 for a URL --proto (or, on a redirect, --proto-redir)
        does not allow."""
        scheme = url.split('://', 1)[0].lower()
        allowed = parse_protocols(self.proto, '--proto', ALL_PROTOCOLS)
        if redirect:
            allowed &= parse_protocols(self.proto_redir, '--proto-redir', DEFAULT_REDIRECT_PROTOCOLS)
        if scheme not in allowed:
            raise LocalError(
                EXIT_PROTOCOL, 'Protocol "%s" is disabled%s' % (scheme, ' (in redirect)' if redirect else '')
            )

    def request_method(self, has_body, uploading):
        """-I is HEAD; else -X; else GET with -G, PUT with -T, POST with a
        body, GET."""
        if self.request:  # -I -X POST sends POST and reads the headers only
            return self.request
        if self.head:
            return 'HEAD'
        if self.get:
            return 'GET'
        if uploading:
            return 'PUT'
        return 'POST' if has_body else 'GET'

    def referer_url(self):
        """The ``-e`` URL; ``URL;auto`` also sets every redirect hop's Referer
        to the page it came from (see :meth:`referer_auto`)."""
        text = self.referer or ''
        return text[: -len(';auto')] if text.endswith(';auto') else text

    def referer_auto(self):
        """Whether ``-e`` ends in ``;auto``."""
        return (self.referer or '').endswith(';auto')

    def request_headers(self):
        """``(headers, removed)``. The implied headers first -- User-Agent,
        the ``Authorization`` the auth options imply (``AuthArgs``), -e's
        Referer, --compressed's Accept-Encoding, -r's Range, the body's
        (``--json``) -- then ``-H`` on top: ``Name: v`` sets, ``Name:`` removes
        the header (a default included), ``Name;`` sends it empty; ``@file``
        (``@-`` stdin) is one header per line of the file."""
        headers = {'User-Agent': self.user_agent or USER_AGENT, 'Accept': '*/*'}
        authorization = self.authorization()
        if authorization:
            headers['Authorization'] = authorization
        referer = self.referer_url()
        if referer:
            headers['Referer'] = referer
        if self.compressed:
            headers['Accept-Encoding'] = 'gzip, deflate'
        if self.range:
            headers['Range'] = 'bytes=' + self.range
        headers.update(self.body_headers())
        removed = set()
        given = {}  # lower-cased name -> every value -H gave it, in order
        for header in _header_lines(self.header or []):
            if ':' in header:
                key, value = header.split(':', 1)
                key, value = key.strip(), value.strip()
                if not value:
                    _set_header(headers, key, None)
                    del headers[key]
                    removed.add(key.lower())
                    given.pop(key.lower(), None)
                    continue
            elif header.endswith(';') and header[:-1].strip():
                key, value = header[:-1].strip(), ''
            else:
                self.usage_error('Invalid header: %s' % header)
            removed.discard(key.lower())
            given.setdefault(key.lower(), []).append(value)
            _set_header(headers, key, value)
            if len(given[key.lower()]) > 1:
                headers[key] = HeaderValues(given[key.lower()])
        return headers, removed

    def query_url(self, url, body):
        """-G: ``url`` with the body moved into its query."""
        return add_query(url, [body.decode('utf-8')]) if body else url
