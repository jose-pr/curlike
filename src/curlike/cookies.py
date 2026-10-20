"""Cookie options: ``-b`` (a string, or a Netscape jar filtered to the URL)
and ``-c`` (the response's cookies written back as a jar) -- on
``syshttp.cookies``, the same reading, matching and writing syshttp's
client uses."""

import os
import shutil
import sys
import urllib.parse
from pathlib import Path
from typing import Optional

from syshttp.cookies import cookie_applies, load_netscape, save_netscape, set_cookie_specs

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
        """The -b file's cookies, its session cookies dropped under -j; a
        file that is not there holds none."""
        path = Path(self.cookie)
        if self.cookie == '-':
            import tempfile

            scratch = tempfile.mkdtemp(prefix='curlike-jar-')
            try:
                path = Path(scratch) / 'stdin'
                path.write_bytes(sys.stdin.buffer.read())
                return self._rows_of(path)
            finally:
                shutil.rmtree(scratch, ignore_errors=True)
        return self._rows_of(path)

    def _rows_of(self, path):
        try:
            return [c for c in load_netscape(path) if c.expires or not self.junk_session_cookies]
        except OSError:
            return []

    def cookie_from_jar(self):
        """Is ``-b`` a cookie FILE (the cookie engine: cookies chosen per
        URL), not a literal string? curl's rule: no ``=`` in it. ``-`` is
        stdin."""
        return self.cookie is not None and '=' not in self.cookie

    def cookie_engine(self):
        """Whether cookies are kept and chosen per URL: ``-b FILE`` or ``-c``
        turns the engine on, as in curl."""
        return bool(self.cookie_jar) or self.cookie_from_jar()

    def _rows(self):
        """The engine's cookies by ``(domain, path, name)``: the -b file's
        rows, then what responses set during this run."""
        rows = getattr(self, '_cookie_rows', None)
        if rows is None:
            rows = self._cookie_rows = {}
            if self.cookie_from_jar():
                for cookie in self._jar():
                    rows[(cookie.domain, cookie.path, cookie.name)] = cookie
        return rows

    def cookie_header(self, url, literal=True):
        """The ``Cookie:`` value for a request to ``url``: the ``-b`` string
        as given (``literal``), then the engine's cookies that apply (domain,
        path, Secure, expiry -- a jar with several hosts never leaks one
        host's cookies to another), in curl's order: longest path, domain,
        name first; the newest first."""
        pairs = [self.cookie] if self.cookie and not self.cookie_from_jar() and literal else []
        if self.cookie_engine():
            ranked = list(enumerate(self._rows().values()))
            ranked.sort(
                key=lambda item: (-len(item[1].path or ''), -len(item[1].domain or ''), -len(item[1].name), -item[0])
            )
            pairs += ['%s=%s' % (c.name, c.value) for _, c in ranked if cookie_applies(c, url)]
        return '; '.join(pairs) if pairs else None

    def learn_cookies(self, url, header_items):
        """The ``Set-Cookie`` headers of the response to ``url`` (as the
        caller named it), into the engine: a cookie replaces one of the same
        domain, path and name, and one the server expires is dropped."""
        if not self.cookie_engine():
            return
        rows = self._rows()
        values = [v for k, v in header_items if k.lower() == 'set-cookie']
        parts = urllib.parse.urlsplit(url)
        for cookie, gone in set_cookie_specs(values, parts.hostname or '', request_path=parts.path or '/'):
            key = (cookie.domain, cookie.path, cookie.name)
            if gone:
                rows.pop(key, None)
            else:
                rows[key] = cookie

    def save_cookie_jar(self):
        """``-c``: the engine's cookies in Netscape format."""
        if self.cookie_jar and self.cookie_jar != '-':
            try:
                save_netscape(self._rows().values(), Path(self.cookie_jar))
            except OSError:
                pass  # curl runs on when the jar cannot be written

    def write_cookie_jar_to_stdout(self):
        """``-c -``: the jar goes to stdout, after the body."""
        if self.cookie_jar == '-' and self.cookie_engine():
            import tempfile

            with tempfile.TemporaryDirectory() as scratch:
                path = Path(scratch) / 'jar'
                save_netscape(self._rows().values(), path)
                out = self.stdout()
                out.write(path.read_bytes())
                out.flush()
