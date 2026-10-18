"""duho for the CLI: the interpreter's own (a declared dependency), else the
paths named in ``<P>_PYLIB`` (``SYSHTTP_PYLIB`` by default) -- a directory or a
``.pyz`` a host tool runs from, imported by zipimport. The option classes live in real files, so duho's source-reading
field introspection works either way -- which is also why no class here
inherits a field from duho's own presets (their source is inside the zip)."""

import os
import sys

from syshttp.env import HTTPEnv

#: The setting, as ``<P>_PYLIB``.
PYLIB = 'PYLIB'


class DuhoMissing(ImportError):
    """No duho to build the CLI with."""


def _load():
    try:
        import duho

        return duho
    except ImportError:
        pass
    env = HTTPEnv()
    for entry in (env.get(PYLIB) or '').split(os.pathsep):
        if entry and entry not in sys.path:
            sys.path.append(entry)
    try:
        import duho

        return duho
    except ImportError:
        raise DuhoMissing(
            'the curl fallback needs duho: pip install duho, or name it in %s' % (env.name(PYLIB) or PYLIB)
        )


duho = _load()
Meta = duho.Meta
Arg = duho.Arg
