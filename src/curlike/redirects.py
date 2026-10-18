"""``-L`` as curl follows it -- urllib's own redirect handler copies every
request header into the next hop and refuses to redirect a POST on a 307/308,
where curl strips credentials on an origin change and keeps method and body.

Checked against curl 8.21:

* **Credentials** -- ``Authorization`` (``-u``, ``--oauth2-bearer``, ``-H``)
  and ``Cookie`` (``-H``, a ``-b`` string) go to the next hop only while the
  scheme, host and port stay the same, unless ``--location-trusted``. Cookies
  from a ``-b`` FILE are the cookie engine's: re-chosen for every hop from the
  jar, by the jar's own rules.
* **Method** -- 301 / 302 turn a POST into a GET (``--post301`` /
  ``--post302`` keep it), 303 turns anything but HEAD into a GET (``--post303``
  keeps a POST), 307 / 308 keep method and body. A method forced with ``-X``
  stays forced, as curl does.
* The proxy credential is never involved: it is an unredirected header the
  proxy handler adds per hop.
"""
import urllib.parse
import urllib.request

from .request import normalize_path
from .routing import caller_url

#: Request headers that describe a body, dropped when the next hop has none.
_BODY_HEADERS = ('content-length', 'content-type')
#: Credentials that follow a redirect only to the same origin.
_CREDENTIALS = ('authorization', 'cookie')


def origin(url):
    """``(scheme, host, port)`` with the scheme's default port filled in."""
    parts = urllib.parse.urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    scheme = parts.scheme.lower()
    return scheme, (parts.hostname or '').lower(), port or {'http': 80, 'https': 443}.get(scheme)


class CurlRedirectHandler(urllib.request.HTTPRedirectHandler):
    """urllib's redirect handler with curl's rules for what the next hop
    carries (see the module docstring). ``args`` is the parsed command,
    ``plan`` the proxy plan (to compare URLs as the caller wrote them, not a
    prefix gateway's rewrites)."""

    def __init__(self, args, plan):
        self.args = args
        self.plan = plan

    # Python < 3.11 has no 308 handler: follow it like the others.
    http_error_308 = urllib.request.HTTPRedirectHandler.http_error_302

    def _keeps_post(self, code):
        return {301: self.args.post301, 302: self.args.post302, 303: self.args.post303}.get(code, False)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if code not in (301, 302, 303, 307, 308):
            return None
        newurl = newurl.replace(' ', '%20')
        self.args.check_protocol(newurl, redirect=True)  # --proto / --proto-redir: exit 1
        if not self.args.path_as_is:
            newurl = normalize_path(newurl)
        method = req.get_method()
        if self.args.request:  # -X: curl keeps a forced method on every hop
            new_method = method
        elif code in (307, 308):
            new_method = method
        elif code == 303:
            new_method = method if method == 'HEAD' or (method == 'POST' and self._keeps_post(code)) else 'GET'
        else:  # 301, 302
            new_method = 'GET' if method == 'POST' and not self._keeps_post(code) else method
        keep_body = new_method == method and (code in (307, 308) or (method == 'POST' and self._keeps_post(code)))
        data = req.data if keep_body else None
        new_headers = {}
        for name, value in req.headers.items():
            if data is None and name.lower() in _BODY_HEADERS:
                continue
            new_headers[name] = value
        same_origin = origin(caller_url(req.full_url, self.plan)) == origin(caller_url(newurl, self.plan))
        if not (same_origin or self.args.location_trusted):
            new_headers = {k: v for k, v in new_headers.items() if k.lower() not in _CREDENTIALS}
        if self.args.cookie_from_jar():
            # The cookie engine: this hop's cookies, chosen from the jar.
            new_headers = {k: v for k, v in new_headers.items() if k.lower() != 'cookie'}
            jar_cookie = self.args.cookie_header(caller_url(newurl, self.plan))
            if jar_cookie:
                new_headers['Cookie'] = jar_cookie
        return urllib.request.Request(newurl, data=data, headers=new_headers, origin_req_host=req.origin_req_host,
                                      unverifiable=True, method=new_method)
