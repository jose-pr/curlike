"""The option groups' base, and the helpers several groups share.

Each group (``request``, ``body``, ``output``, ``writeout``, ``tls``,
``connection``, ``cookies``, ``unsupported``) is a duho ``Args`` mixin: it
declares its own fields -- a typed attribute, its help string, its flag tuple
-- and owns the behaviour those flags drive. ``options.CurlCmd`` inherits every
group, so one parse fills one object that has all of it.

Rules for a group: a field must not share a name with any method or class
attribute, a group reaches another group's options only through ``self``, and
``_check`` (optional) validates the group's own options after parsing.
"""

import sys
import urllib.parse

from ._duho import duho
from .errors import EXIT_READ, EXIT_USAGE, EarlyExit


class Group(duho.Args):
    """Base of every option group."""

    def check(self):
        """Every group's ``_check``, in MRO order -- the first-listed group,
        the unsupported flags, first, so that refusal comes before any
        conflict: an unsupported flag raises ``NotImplementedError``, a
        conflicting pair ``ValueError``."""
        for klass in type(self).__mro__:
            check = klass.__dict__.get('_check')
            if check is not None:
                check(self)

    def usage_error(self, message):
        """A usage error as curl prints it: the message and its help hint, exit 2."""
        raise EarlyExit(EXIT_USAGE, '%s\n%s' % (message, HELP_HINT))

    def read_data(self, path, option='-d'):
        """An ``@``-source's bytes for a data option; a missing file is curl's
        exit 26, before anything is sent."""
        try:
            return read_source(path)
        except OSError:
            raise read_failure(path, option)


#: The line curl ends a usage error with.
HELP_HINT = "curl: try 'curl --help' or 'curl --manual' for more information"


def wrapped(text):
    """``text`` as curl prints a message of its own: wrapped to the terminal's
    width, every line under ``curl: ``, the first line's prefix left to the
    caller (an :class:`EarlyExit` is printed after one)."""
    from .output import notice_lines

    return '\n'.join(notice_lines(text)).split(': ', 1)[1]


def read_failure(path, option):
    """curl's exit 26 for a file ``option`` was to read: the message, which
    names the option, and the help hint."""
    return EarlyExit(
        EXIT_READ,
        wrapped('Failed to open %s' % path)
        + "\ncurl: option %s: error encountered when reading a file\n%s" % (option, HELP_HINT),
    )


def missing_file(path, option):
    """curl's exit 2 for a file ``option`` names that is not there."""
    return EarlyExit(
        EXIT_USAGE,
        wrapped("The file '%s' provided to %s does not exist" % (path, option))
        + "\ncurl: option %s: is badly used here\n%s" % (option, HELP_HINT),
    )


def first_header(header_items, name):
    """The first value of header ``name`` (any case), or ``''``."""
    name = name.lower()
    return next((v for k, v in header_items if k.lower() == name), '')


def read_source(path):
    """A curl ``@``-source's bytes: ``-`` is stdin, anything else a file."""
    if path == '-':
        return sys.stdin.buffer.read()
    with open(path, 'rb') as handle:
        return handle.read()


def url_encoded(spec, reader, raw_plus=False):
    """curl's ``--data-urlencode`` / ``--url-query`` piece -- ``content``,
    ``=content``, ``name=content``, ``@file``, ``name@file`` (whichever of
    ``=`` / ``@`` comes first decides): the content percent-encoded, the name
    as given. ``raw_plus`` (``--url-query``): a leading ``+`` adds the rest as
    it stands. ``reader(path)`` returns a file's bytes."""
    if raw_plus and spec.startswith('+'):
        return spec[1:]
    cuts = [i for i in (spec.find('='), spec.find('@')) if i >= 0]
    if not cuts:
        return urllib.parse.quote_plus(spec, safe='')
    cut = min(cuts)
    name, rest = spec[:cut], spec[cut + 1 :]
    content = reader(rest) if spec[cut] == '@' else rest.encode('utf-8')
    encoded = urllib.parse.quote_plus(content, safe='')
    return '%s=%s' % (name, encoded) if name else encoded
