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

_ESCAPES = {'n': '\n', 'r': '\r', 't': '\t'}


def _line_tokens(line):
    """The tokens of one netrc line: whitespace separates them, a token that
    starts with ``#`` ends the line, and a double-quoted one may hold spaces,
    a backslash taking the next character literally (``n``, ``r`` and ``t``
    become control characters)."""
    tokens, i = [], 0
    while i < len(line):
        if line[i].isspace():
            i += 1
        elif line[i] == '#':
            break
        elif line[i] == '"':
            word, i = [], i + 1
            while i < len(line) and line[i] != '"':
                if line[i] == '\\' and i + 1 < len(line):
                    i += 1
                    word.append(_ESCAPES.get(line[i], line[i]))
                else:
                    word.append(line[i])
                i += 1
            tokens.append(''.join(word))
            i += 1
        else:
            start = i
            while i < len(line) and not line[i].isspace():
                i += 1
            tokens.append(line[start:i])
    return tokens


def read_netrc(path):
    """``[(machine, login, password)]`` in file order from a netrc file:
    ``machine`` is lower case, ``None`` for ``default``; a login with no
    password has ``''``. ``macdef`` bodies are skipped."""
    with open(path, encoding='utf-8', errors='replace') as handle:
        lines = iter(handle.read().splitlines())
    tokens = []
    for line in lines:
        words = _line_tokens(line)
        if words[:1] == ['macdef']:
            for body in lines:  # a macro runs to the next blank line
                if not body.strip():
                    break
            continue
        tokens.extend(words)
    entries = []
    machine, fields, i = False, {}, 0

    def close():
        if machine is not False:
            entries.append((machine, fields.get('login'), fields.get('password', '')))

    while i < len(tokens):
        word = tokens[i]
        if word == 'machine' and i + 1 < len(tokens):
            close()
            machine, fields = tokens[i + 1].lower(), {}
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


def netrc_lookup(entries, host, user=None):
    """``(login, password)`` of the first entry, in file order, that names
    ``host`` (or is ``default``) and, when ``user`` is given, that login."""
    host = (host or '').lower()
    for machine, login, password in entries:
        if (machine is None or machine == host) and login is not None and (user is None or login == user):
            return login, password
    return None


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
    """``(url without user:pw@, (user, password) or None)``; the password is
    ``None`` when the URL gave a user only."""
    parts = urllib.parse.urlsplit(url)
    if '@' not in parts.netloc:
        return url, None
    userinfo, _, hostport = parts.netloc.rpartition('@')
    user, colon, password = userinfo.partition(':')
    stripped = urllib.parse.urlunsplit(parts._replace(netloc=hostport))
    return stripped, (urllib.parse.unquote(user), urllib.parse.unquote(password) if colon else None)


class AuthArgs(Group):
    """Who the request authenticates as."""

    #: Set by ``RequestArgs.target_url``: the ``user:pw@`` the URL carried.
    url_credentials = None
    _auth_host = None
    _asked = None  # the password typed for ``-u USER``

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

    def _netrc_credentials(self, user=None):
        """The netrc entry for the host (``user``'s, when one is named), or ``None``."""
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
        return netrc_lookup(read_netrc(path), self._auth_host, user)

    def _ask_password(self, user):
        """``-u USER`` with no password: curl asks for it, once, on the
        terminal (stdin when there is none); nothing to read is an empty one."""
        if self._asked is None:
            import getpass
            import warnings

            with warnings.catch_warnings():
                warnings.simplefilter('ignore', getpass.GetPassWarning)
                try:
                    self._asked = getpass.getpass("Enter host password for user '%s':" % user)
                except EOFError:
                    self._asked = ''
        return self._asked

    def credentials(self):
        """``(user, password)`` by curl's precedence, or ``None``."""
        if self.user:
            user, colon, password = self.user.partition(':')
            return user, password if colon else self._ask_password(user)
        if self.url_credentials:
            user, password = self.url_credentials
            if password is None:  # a user only: the netrc may know that login's password
                found = self._netrc_credentials(user)
                return user, found[1] if found else ''
            return user, password
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
