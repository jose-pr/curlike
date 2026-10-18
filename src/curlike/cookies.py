"""Cookie options: ``-b`` (a string, or a Netscape jar filtered to the URL)
and ``-c`` (the response's cookies written back as a jar) -- on
``httplib.cookies``, the same reading, matching and writing the session
toolkit uses."""
import os
import urllib.parse
from pathlib import Path
from typing import Optional

from httplib.cookies import cookie_applies, load_netscape, save_netscape, set_cookie_specs

from .args import Group


class CookieArgs(Group):
    """``-b`` / ``-c``."""

    cookie: Optional[str] = None
    "Cookie string or file to read cookies from"
    ("-b", "--cookie")

    cookie_jar: Optional[str] = None
    "Write cookies to this file after operation"
    ("-c", "--cookie-jar")

    junk_session_cookies: bool = False
    "Ignore the session cookies (no expiry) of the -b file"
    ("-j", "--junk-session-cookies")

    def _jar(self):
        """The -b file's cookies, its session cookies dropped under -j."""
        return [c for c in load_netscape(Path(self.cookie)) if c.expires or not self.junk_session_cookies]

    def cookie_from_jar(self):
        """Is ``-b`` a cookie FILE (the cookie engine: cookies chosen per
        URL), not a literal string?"""
        return bool(self.cookie) and os.path.exists(self.cookie)

    def cookie_header(self, url):
        """The ``Cookie:`` value from ``-b``: a string (``a=b; c=d``) as given,
        or the rows of a Netscape file that apply to ``url`` (domain, path,
        Secure, expiry -- a jar with several hosts never leaks one host's
        cookies to another), ``#HttpOnly_`` rows included."""
        if not self.cookie:
            return None
        if os.path.exists(self.cookie):
            # curl's order: longest path, domain, name first; the newest (later in the file) first.
            jar = list(enumerate(self._jar()))
            jar.sort(key=lambda item: (-len(item[1].path or ''), -len(item[1].domain or ''), -len(item[1].name),
                                       -item[0]))
            pairs = ['%s=%s' % (c.name, c.value) for _, c in jar if cookie_applies(c, url)]
            return '; '.join(pairs) if pairs else None
        return self.cookie

    def save_cookies(self, url, header_items):
        """``-c``: the response's cookies in Netscape format -- the domain
        defaulting to the host of the URL the CALLER asked for, never a
        gateway's -- on top of what a ``-b <file>`` read; a cookie replaces one
        of the same domain, path and name, and one the server expires is
        dropped. The final response's headers only: urllib does not hand back
        the intermediate hops' cookies."""
        if not self.cookie_jar:
            return
        rows = {}
        if self.cookie and os.path.exists(self.cookie):
            for cookie in self._jar():
                rows[(cookie.domain, cookie.path, cookie.name)] = cookie
        values = [v for k, v in header_items if k.lower() == 'set-cookie']
        for cookie, gone in set_cookie_specs(values, urllib.parse.urlsplit(url).hostname or ''):
            key = (cookie.domain, cookie.path, cookie.name)
            if gone:
                rows.pop(key, None)
            else:
                rows[key] = cookie
        save_netscape(rows.values(), Path(self.cookie_jar))
