"""Server authentication: ``-u``, credentials in the URL, ``.netrc``
(``-n`` / ``--netrc-file`` / ``--netrc-optional``), ``--digest`` and
``--oauth2-bearer``.

Precedence, recorded from curl 8.21: ``-u`` wins, then ``user:pw@`` in the
URL, then the netrc entry for the host (``default`` when none matches) --
with ``-n`` and ``--netrc-optional`` alike. ``-n`` without a netrc file is
exit 26; ``--netrc-file`` naming none is a usage error (exit 2). The netrc
is read by a small parser of our own: Python's ``netrc`` module refuses a
file with open permissions on POSIX, which curl does not."""

import base64
import os
import urllib.parse
from typing import Optional

from ._duho import Meta, Arg
from .args import Group
from .errors import EXIT_READ, EXIT_USAGE, EarlyExit, LocalError


def read_netrc(path):
    """``{machine: (login, password)}`` from a netrc file, ``default`` under
    the key ``None``; ``macdef`` bodies are skipped."""
    with open(path, encoding='utf-8', errors='replace') as handle:
        text = handle.read()
    entries, machine, fields = {}, False, {}
    lines = iter(text.splitlines())
    tokens = []
    for line in lines:
        words = line.split()
        if words[:1] == ['macdef']:
            for body in lines:  # a macro runs to the next blank line
                if not body.strip():
                    break
            continue
        tokens.extend(words)

    def close():
        if machine is not False:
            entries.setdefault(machine, (fields.get('login'), fields.get('password')))

    i = 0
    while i < len(tokens):
        word = tokens[i]
        if word == 'machine' and i + 1 < len(tokens):
            close()
            machine, fields = tokens[i + 1], {}
            i += 2
        elif word == 'default':
            close()
            machine, fields = None, {}
            i += 1
        elif word in ('login', 'password', 'account') and i + 1 < len(tokens):
            fields[word] = tokens[i + 1]
            i += 2
        else:
            i += 1
    close()
    return entries


def default_netrc():
    """``$HOME/.netrc`` -- ``_netrc`` too on Windows -- else the user
    profile's, as curl looks; ``None`` when there is none."""
    homes = [os.environ.get('HOME'), os.path.expanduser('~')]
    names = ['.netrc', '_netrc'] if os.name == 'nt' else ['.netrc']
    for home in homes:
        for name in names:
            if home and os.path.isfile(os.path.join(home, name)):
                return os.path.join(home, name)
    return None


def split_userinfo(url):
    """``(url without user:pw@, (user, password) or None)``."""
    parts = urllib.parse.urlsplit(url)
    if '@' not in parts.netloc:
        return url, None
    userinfo, _, hostport = parts.netloc.rpartition('@')
    user, _, password = userinfo.partition(':')
    stripped = urllib.parse.urlunsplit(parts._replace(netloc=hostport))
    return stripped, (urllib.parse.unquote(user), urllib.parse.unquote(password))


class AuthArgs(Group):
    """Who the request authenticates as."""

    #: Set by ``RequestArgs.target_url``: the ``user:pw@`` the URL carried.
    url_credentials = None
    _auth_host = None

    user: Arg[Optional[str], Meta(metavar='USER[:PASS]')] = None
    "Server user and password (Basic unless --digest)"
    ("-u", "--user")

    basic: bool = False
    "Use HTTP Basic for -u (the default; a no-op)"
    ("--basic",)

    digest: bool = False
    "Use HTTP Digest for -u / netrc / URL credentials"
    ("--digest",)

    anyauth: bool = False
    "Ask first, then answer the server's challenge with Digest or Basic"
    ("--anyauth",)

    oauth2_bearer: Arg[Optional[str], Meta(metavar='TOKEN')] = None
    "Send Authorization: Bearer TOKEN"
    ("--oauth2-bearer",)

    netrc: bool = False
    "Take credentials from ~/.netrc (_netrc on Windows) for the host"
    ("-n", "--netrc")

    netrc_file: Arg[Optional[str], Meta(metavar='FILE')] = None
    "Take credentials from this netrc file"
    ("--netrc-file",)

    netrc_optional: bool = False
    "Like -n, without failing when there is no netrc file"
    ("--netrc-optional",)

    def remember_auth_url(self, url):
        """Strip ``user:pw@`` from ``url`` (remembered as the URL's
        credentials) and note the host a netrc entry is chosen for."""
        url, creds = split_userinfo(url)
        self.url_credentials = creds
        self._auth_host = urllib.parse.urlsplit(url).hostname
        return url

    def _netrc_credentials(self):
        if self.netrc_file:
            if not os.path.isfile(self.netrc_file):
                raise EarlyExit(EXIT_USAGE, "The file '%s' provided to --netrc-file does not exist" % self.netrc_file)
            path = self.netrc_file
        elif self.netrc or self.netrc_optional:
            path = default_netrc()
            if path is None:
                if self.netrc:
                    raise LocalError(EXIT_READ, '.netrc error: no such file')
                return None
        else:
            return None
        entries = read_netrc(path)
        found = entries.get(self._auth_host) or entries.get(None)
        return found if found and found[0] is not None else None

    def credentials(self):
        """``(user, password)`` by curl's precedence, or ``None``."""
        if self.user:
            user, _, password = self.user.partition(':')
            return user, password
        if self.url_credentials:
            return self.url_credentials
        return self._netrc_credentials()

    def authorization(self):
        """The ``Authorization`` value to send up front: Bearer for
        ``--oauth2-bearer``, else Basic for the credentials (none with
        ``--digest``: its handler answers the server's challenge)."""
        if self.oauth2_bearer:
            return 'Bearer ' + self.oauth2_bearer
        creds = self.credentials()
        if creds is None or self.digest or self.anyauth:
            return None
        token = base64.b64encode(('%s:%s' % creds).encode('utf-8')).decode('ascii')
        return 'Basic ' + token
