"""The urllib side of the proxy decision: :func:`plan` (one proxy for a
transfer, from syshttp's proxy map), the handler that applies it to every
hop, and the caller's view of a URL a prefix gateway rewrote."""

import base64
import re
import urllib.parse
import urllib.request

import proxylib
from syshttp import proxy as agent_proxy
from syshttp.env import HTTPEnv

from .errors import EXIT_RESOLVE_PROXY, LocalError

# The variables curl reads for its proxy, after <P>_PROXY (curl's own order).
_FALLBACK_VARS = ('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy')


def configured_text(env=None):
    """The proxy as configured (``<P>_PROXY``, else the first ``*_PROXY``
    variable), as typed, or ``None``: what curl's exit 5 checks."""
    env = HTTPEnv() if env is None else env
    return env.get(agent_proxy.PROXY) or env.conventional(*_FALLBACK_VARS)


def userinfo(url):
    """``(user, password)`` from a proxy URL's userinfo, percent-decoded, or ``None``."""
    if not url:
        return None
    parts = urllib.parse.urlsplit(url if '://' in url else 'http://' + url)
    if parts.username is None:
        return None
    return urllib.parse.unquote(parts.username), urllib.parse.unquote(parts.password or '')


def _rules(no_proxy):
    """curl's ``NO_PROXY`` as proxylib rules: loopback is not bypassed
    unless listed, as in curl."""
    text = (no_proxy or '').strip()
    if not text:
        return None
    return proxylib.BypassRules.parse(text if text == '*' else text + ',<-loopback>')


class ProxyPlan:
    """One proxy for a transfer, applied to every hop.

    ``proxy`` -- the proxy URL without credentials (for a prefix gateway, its
    ``scheme://host[:port]``); ``uri`` -- the same with its userinfo;
    ``authorization`` / ``auth_header`` -- the credential header, or
    ``None``; ``endpoint`` -- ``None`` for a proxy, a gateway's ``/endpoint``;
    ``no_proxy`` -- the bypass list in force, re-checked for every hop."""

    __slots__ = ('proxy', 'uri', 'authorization', 'endpoint', 'no_proxy', 'auth_header', '_rules')

    def __init__(self, proxy, authorization, endpoint, no_proxy, auth_header=None, uri=None):
        self.proxy = proxy
        self.uri = uri or proxy
        self.authorization = authorization
        self.endpoint = endpoint
        self.no_proxy = no_proxy
        self.auth_header = auth_header or agent_proxy.DEFAULT_AUTH_HEADER
        self._rules = _rules(no_proxy)

    def bypasses(self, url):
        if self._rules is None:
            return False
        try:
            return self._rules.matches(url)
        except ValueError:
            return False  # a URL that does not parse: the transfer reports it

    @property
    def gateway_base(self):
        """``<proxy><endpoint>`` of a prefix gateway, or ``None``."""
        return prefix_url('', self.proxy, self.endpoint) if self.endpoint is not None else None

    @classmethod
    def of(cls, entry, no_proxy):
        """The plan for one proxylib ``Proxy`` entry."""
        header = value = None
        for header, value in entry.headers.items():
            break
        if value is None and entry.username is not None:
            header = agent_proxy.DEFAULT_AUTH_HEADER
            token = ('%s:%s' % (entry.username, entry.password or '')).encode('utf-8')
            value = 'Basic ' + base64.b64encode(token).decode('ascii')
        if entry.is_gateway:
            scheme = entry.scheme[len('prefix+') :]
            authority = entry.url.split('://', 1)[1][: -len(entry.path)]
            return cls('%s://%s' % (scheme, authority), value, entry.path, no_proxy, header)
        return cls(entry.url, value, None, no_proxy, header, uri=entry.uri())


def prefix_url(target, proxy, endpoint):
    """``<proxy><endpoint><target>``: the URL a prefix gateway is asked for."""
    return proxy.rstrip('/') + endpoint + target


def proxy_url(text):
    """``text`` as curl reads a proxy URL: its path, query and fragment are
    ignored. A gateway (``prefix+http://``) keeps its path, the endpoint."""
    if not text:
        return text
    try:
        parts = urllib.parse.urlsplit(text if '://' in text else 'http://' + text)
    except ValueError:
        return text  # check_proxy_syntax reports it
    if parts.scheme.lower().startswith('prefix+') or (
        parts.path in ('', '/') and not parts.query and not parts.fragment
    ):
        return text
    return urllib.parse.urlunsplit(parts._replace(path='', query='', fragment=''))


def _proxy_variables(env):
    """The variables that hold a proxy URL, ``<P>_PROXY`` first."""
    return [name for name in (env.name(agent_proxy.PROXY),) + _FALLBACK_VARS if name]


def _userinfo_text(url):
    """What precedes the last ``@`` of ``url`` as typed (a password may hold
    ``/``, ``?``, ``#`` or ``@``), or ``''``."""
    scheme = _SCHEME.match(url or '')
    return (url or '')[len(scheme.group(0)) if scheme else 0 :].rpartition('@')[0]


def plan(proxy=None, noproxy=None, proxy_user=None, *, url, env=None):
    """The :class:`ProxyPlan` for a transfer to ``url``, or ``None`` for
    direct: syshttp's proxy map (``-x`` / ``-U`` as given), the first
    reachable entry of a list (``proxylib.NoReachableProxyError`` when none
    answers and it holds no DIRECT). The bypass list (``--noproxy``, else
    ``NO_PROXY``) is the plan's, checked per hop. A proxy URL is read as curl
    reads it (:func:`proxy_url`); the ``ValueError`` for a setting that
    cannot be used never carries a credential."""
    env = HTTPEnv() if env is None else env
    no_proxy = noproxy if noproxy is not None else env.conventional('NO_PROXY', 'no_proxy')
    typed = [proxy]
    try:
        environ = dict(env.environ)
        for name in _proxy_variables(env):
            typed.append(environ.get(name))
            if environ.get(name):
                environ[name] = proxy_url(environ[name].strip())
        # No bypass in the map, loopback included (curl proxies it): a plan is
        # kept for the redirect hops, whose hosts the plan's own list decides.
        entry = first_entry(
            agent_proxy.proxy_map(proxy_url(proxy), '<-loopback>', proxy_user, env=HTTPEnv(env.prefix, environ)), url
        )
    except ValueError as exc:
        message = str(exc)
        for secret in [_userinfo_text(text) for text in typed] + [proxy_user or '']:
            for form in filter(None, (secret, repr(secret)[1:-1])):
                message = message.replace(form, '***')
        raise ValueError(message) from None
    return None if entry is None else ProxyPlan.of(entry, no_proxy)


def first_entry(proxymap, url):
    """The entry of ``proxymap``'s answer for ``url`` a single-route client
    uses: the only one, or of a list the first that accepts a connection
    (``proxylib.Probed``; ``NoReachableProxyError`` when none does and the
    list holds no DIRECT). A lone proxy is not probed: connecting to it is
    the transfer's own business, with curl's own errors."""
    entries = proxylib.lookup(proxymap, url)
    if len(entries) > 1:
        try:
            entries = proxylib.lookup(proxylib.Probed(proxylib.SimpleProxyMap(list(entries))), url)
        except proxylib.NoReachableProxyError:
            names = ', '.join(e.url.split('://', 1)[1] for e in entries if e is not None)
            raise proxylib.NoReachableProxyError('no proxy of the list is reachable: %s' % names) from None
    return entries[0]


_SCHEME = re.compile(r'[A-Za-z][A-Za-z0-9+.-]*://')


def _hide_userinfo(url):
    """``url`` with everything before its last ``@`` replaced by ``***``: a
    password may hold ``/``, ``?``, ``#`` or ``@``, so no URL parser says
    where it ends, and a path's ``@`` only hides more."""
    scheme = _SCHEME.match(url)
    head = scheme.group(0) if scheme else ''
    _userinfo, at, rest = url[len(head) :].rpartition('@')
    return '%s***@%s' % (head, rest) if at else url


def check_proxy_syntax(url):
    """curl's exit 5 for a proxy URL it cannot parse -- ``-x`` or the configured
    proxy alike, whether or not the request would use it: a broken IPv6
    literal, a port out of range, no host, or a host with spaces or control
    characters in it. The message names the URL with its userinfo hidden."""
    if not url:
        return
    reason = None
    try:
        parts = urllib.parse.urlsplit(url if '://' in url else 'http://' + url)
    except ValueError:
        reason = 'Bad IPv6 address'
    else:
        try:
            parts.port
        except ValueError:
            reason = 'Port number was not a decimal number between 0 and 65535'
        if reason is None:
            authority = parts.netloc.rpartition('@')[2]
            if not parts.hostname or any(c.isspace() or ord(c) < 32 for c in authority):
                reason = 'Malformed input to a URL function'
    if reason is not None:
        shown = _hide_userinfo(url if _SCHEME.match(url) else 'http://' + url)
        raise LocalError(EXIT_RESOLVE_PROXY, "Unsupported proxy syntax in '%s': %s" % (shown, reason))


def caller_url(url, plan):
    """``url`` as the caller would name it: a prefix gateway's
    ``<proxy><endpoint>`` stripped, an empty path written ``/`` (curl's
    ``url_effective``)."""
    base = plan.gateway_base if plan is not None else None
    if base and url.startswith(base):
        url = url[len(base) :]
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url  # one curl rejected (exit 3): reported as typed
    return url if parts.path else urllib.parse.urlunsplit(parts._replace(path='/'))


class AgentProxyHandler(urllib.request.BaseHandler):
    """Applies the plan to EVERY request the opener sends -- the first one
    and each redirect hop -- since urllib builds a fresh ``Request`` per hop
    that carries neither the proxy nor an unredirected header. Per hop: a
    bypassed host goes direct; a ``connect`` proxy is set on the request
    (what ``ProxyHandler`` does after its own env/registry checks, which are
    deliberately not consulted here); a prefix gateway rewrites the URL to
    ``<proxy><endpoint><url>`` unless the gateway already wrote it in its own
    namespace. The credential never reaches an origin: for http it is an
    UNREDIRECTED header (sent to the proxy, never copied into the next hop);
    for https through a ``connect`` proxy it rides on the CONNECT alone
    (``connector.ConnectHTTPSHandler``) -- urllib itself moves only a header named
    ``Proxy-Authorization`` there and would send any other name
    (``<P>_PROXY_AUTH_HEADER``) through the tunnel to the origin."""

    handler_order = 90  # before the (empty) ProxyHandler at 100

    def __init__(
        self, plan, tunnel_http=False, headers=None, socks=None, preproxy=None, proxy_tls=None, proxy_auth=None
    ):
        self.plan = plan
        self.tunnel_http = tunnel_http  # -p: CONNECT for http URLs too
        self.headers = dict(headers or {})  # --proxy-header: to the proxy only
        self.socks = socks  # the plan's proxy when it is SOCKS (connector.Socks)
        self.preproxy = preproxy  # --preproxy: SOCKS to reach the HTTP proxy
        self.proxy_tls = proxy_tls  # an https:// proxy's TLS (tls.ProxyTLS)
        self.proxy_auth = proxy_auth  # --proxy-digest / --proxy-anyauth (challenge.ChallengeAuth)

    def _apply(self, req):
        if getattr(req, 'routed', False):
            return req  # a handler that answers a challenge re-opens the request: its route stands
        req.routed = True
        plan = self.plan
        if plan.bypasses(req.full_url):
            return req
        if self.socks is not None:
            # SOCKS carries the TCP connection; the request stays the origin's.
            req.socks_via = self.socks
            return req
        if self.preproxy is not None:
            req.socks_via = self.preproxy
        if plan.endpoint is None:
            proxy_parts = urllib.parse.urlsplit(plan.proxy)
            if proxy_parts.scheme.lower() == 'https':
                req.proxy_tls = self.proxy_tls
            if self.tunnel_http and req.type == 'http':
                # -p: connect to the proxy, CONNECT to the origin, then the
                # origin's own request (its path and Host) through the tunnel.
                if not req.has_header('Host'):
                    req.add_unredirected_header('Host', req.host)
                req._tunnel_host, req.host = req.host, proxy_parts.netloc
            else:
                req.set_proxy(proxy_parts.netloc, proxy_parts.scheme)
        elif not req.full_url.startswith(plan.gateway_base):
            req.full_url = prefix_url(req.full_url, plan.proxy, plan.endpoint)
        for_proxy = dict(self.headers)
        if plan.authorization and self.proxy_auth is None:
            for_proxy[plan.auth_header] = plan.authorization
        if self.proxy_auth is not None:
            req.proxy_auth = self.proxy_auth  # answers the CONNECT's 407
        if plan.endpoint is None and getattr(req, '_tunnel_host', None):
            req.tunnel_headers = for_proxy  # on the CONNECT alone
        else:
            req.to_proxy = plan.endpoint is None  # its 407 is the proxy's; inside a tunnel it is the origin's
            for name, value in for_proxy.items():
                req.add_unredirected_header(name, value)
        return req

    http_request = _apply
    https_request = _apply
