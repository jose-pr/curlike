"""``-L`` as curl follows it: what the next hop carries.

Checked against curl 8.21:

* **Credentials** -- ``Authorization`` (``-u``, ``--oauth2-bearer``, ``-H``)
  and ``Cookie`` (``-H``, a ``-b`` string) go to a hop only while its scheme,
  host and port are the first request's, unless ``--location-trusted``. A user
  ``Host`` goes only to the first request's host, trusted or not. Every hop is
  built from the first request's headers, so a hop back to the first origin
  carries them again. Cookies from the cookie engine are chosen again for
  every hop, by the jar's own rules.
* **Method** -- 301 / 302 turn a POST into a GET (``--post301`` /
  ``--post302`` keep it), 303 turns anything but HEAD into a GET (``--post303``
  keeps a POST), 307 / 308 keep method and body. A method forced with ``-X``
  stays forced, as curl does.
* The proxy credential is never involved: it is an unredirected header the
  proxy handler adds per hop.
"""

import urllib.parse
import urllib.request

from .errors import EXIT_PROTOCOL, EXIT_URL, LocalError
from .request import _URL_REFUSED, encode_non_ascii, normalize_path
from .routing import caller_url

#: The statuses that name another URL to fetch.
REDIRECT_CODES = (301, 302, 303, 307, 308)
#: curl's default for ``--max-redirs``.
DEFAULT_MAX_REDIRS = 50
#: Request headers that describe a body, dropped when the next hop has none.
_BODY_HEADERS = ('content-length', 'content-type')
#: Headers that follow a redirect only to the same origin.
_ORIGIN_ONLY = ('authorization', 'cookie')
#: The schemes this command can fetch.
_FETCHABLE = ('http', 'https')


def origin(url):
    """``(scheme, host, port)`` with the scheme's default port filled in."""
    parts = urllib.parse.urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    scheme = parts.scheme.lower()
    return scheme, (parts.hostname or '').lower(), port or {'http': 80, 'https': 443}.get(scheme)


def _without_credentials(url):
    """``url`` without its ``user:password@``, as curl sends a Referer."""
    parts = urllib.parse.urlsplit(url)
    if '@' not in parts.netloc:
        return url
    return urllib.parse.urlunsplit(parts._replace(netloc=parts.netloc.rsplit('@', 1)[1]))


def max_redirs(args):
    """The hop limit: ``--max-redirs`` (``-1`` is unlimited, as ``None`` here), else 50."""
    limit = DEFAULT_MAX_REDIRS if args.max_redirs is None else args.max_redirs
    return None if limit < 0 else limit


class Follow(object):
    """The request for the next hop of a redirect. ``args`` is the parsed
    command, ``plan`` the proxy plan (to compare URLs as the caller wrote
    them, not a prefix gateway's rewrites)."""

    def __init__(self, args, plan):
        self.args = args
        self.plan = plan
        self.referer = None  # the Referer of the last hop, under ``-e URL;auto``
        self.first = None  # (url, headers) of the first request

    def _keeps_post(self, code):
        return {301: self.args.post301, 302: self.args.post302, 303: self.args.post303}.get(code, False)

    def next_request(self, req, previous_url, code, location):
        """The request that follows ``req`` (sent as ``previous_url``) after a
        ``code`` answer naming ``location``."""
        newurl = urllib.parse.urljoin(previous_url, location).replace(' ', '%20')
        if _URL_REFUSED.search(newurl):
            raise LocalError(EXIT_URL, 'The redirect target URL could not be parsed: Malformed input to a URL function')
        newurl = encode_non_ascii(newurl)
        self.args.check_protocol(newurl, redirect=True)  # --proto / --proto-redir: exit 1
        scheme = newurl.split('://', 1)[0].lower()
        if scheme not in _FETCHABLE:
            raise LocalError(EXIT_PROTOCOL, 'Protocol "%s" not supported or disabled in libcurl' % scheme)
        if not self.args.path_as_is:
            newurl = normalize_path(newurl)
        if self.first is None:
            self.first = (previous_url, dict(req.headers))
        method = req.get_method()
        if self.args.request or code in (307, 308):  # -X: curl keeps a forced method on every hop
            new_method = method
        elif code == 303:
            new_method = method if method == 'HEAD' or (method == 'POST' and self._keeps_post(code)) else 'GET'
        else:  # 301, 302
            new_method = 'GET' if method == 'POST' and not self._keeps_post(code) else method
        keep_body = new_method == method and (code in (307, 308) or (method == 'POST' and self._keeps_post(code)))
        data = req.data if keep_body else None
        new_headers = {}
        for name, value in self.first[1].items():
            if data is None and name.lower() in _BODY_HEADERS:
                continue
            new_headers[name] = value
        trusted = self.args.location_trusted
        first_url = caller_url(self.first[0], self.plan)
        same_origin = origin(first_url) == origin(caller_url(newurl, self.plan))
        if not (same_origin or trusted):
            new_headers = {k: v for k, v in new_headers.items() if k.lower() not in _ORIGIN_ONLY}
        if origin(first_url)[1] != origin(caller_url(newurl, self.plan))[1]:
            new_headers = {k: v for k, v in new_headers.items() if k.lower() != 'host'}
        if getattr(self.args, 'cookie_managed', True):
            # The -b string and the engine's cookies, chosen for this hop.
            new_headers = {k: v for k, v in new_headers.items() if k.lower() != 'cookie'}
            hop_cookie = self.args.cookie_header(caller_url(newurl, self.plan), literal=same_origin or trusted)
            if hop_cookie:
                new_headers['Cookie'] = hop_cookie
        if self.args.referer_auto():
            new_headers['Referer'] = _without_credentials(previous_url)
            self.referer = new_headers['Referer']
        hop = urllib.request.Request(
            newurl,
            data=data,
            headers=new_headers,
            origin_req_host=req.origin_req_host,
            unverifiable=True,
            method=new_method,
        )
        hop.curl_removed = getattr(req, 'curl_removed', frozenset())
        return hop
