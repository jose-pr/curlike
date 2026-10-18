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
from .errors import EXIT_READ, EarlyExit


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
        """argparse's usage error (exit 2), from this command's parser."""
        duho.parser(type(self)).error(message)

    def read_data(self, path):
        """An ``@``-source's bytes for a data option; a missing file is curl's
        exit 26, before anything is sent."""
        try:
            return read_source(path)
        except OSError:
            raise EarlyExit(EXIT_READ, 'Failed to open %s' % path)


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
        return urllib.parse.quote(spec, safe='')
    cut = min(cuts)
    name, rest = spec[:cut], spec[cut + 1:]
    content = reader(rest) if spec[cut] == '@' else rest.encode('utf-8')
    encoded = urllib.parse.quote(content, safe='')
    return '%s=%s' % (name, encoded) if name else encoded
