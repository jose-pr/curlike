"""The urllib side of the proxy decision: the handler that applies an
``httplib.proxy.ProxyPlan`` -- the same plan the session's adapter applies --
to every hop, and the caller's view of a URL a prefix gateway rewrote."""

import re
import urllib.parse
import urllib.request

from httplib import proxy as agent_proxy

from .errors import EXIT_RESOLVE_PROXY, LocalError


def check_proxy_syntax(url):
    """curl's exit 5 for a proxy URL it cannot parse -- ``-x`` or the configured
    proxy alike, whether or not the request would use it: a broken IPv6
    literal, a port out of range, no host, or a host with spaces or control
    characters in it. The message names the URL with any password hidden."""
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
        shown = re.sub(r'(//[^:@/]*):[^@/]*@', r'\1:***@', url)
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
        self.proxy_auth = proxy_auth  # --proxy-digest / --proxy-anyauth (connector.ProxyAuth)

    def _apply(self, req):
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
            req.full_url = agent_proxy.prefix_url(req.full_url, plan.proxy, plan.endpoint)
        for_proxy = dict(self.headers)
        if plan.authorization and self.proxy_auth is None:
            for_proxy[plan.auth_header] = plan.authorization
        if self.proxy_auth is not None:
            req.proxy_auth = self.proxy_auth  # answers the CONNECT's 407
        if plan.endpoint is None and getattr(req, '_tunnel_host', None):
            req.tunnel_headers = for_proxy  # on the CONNECT alone
        else:
            for name, value in for_proxy.items():
                req.add_unredirected_header(name, value)
        return req

    http_request = _apply
    https_request = _apply
