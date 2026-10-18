"""A curl-compatible command over the standard library -- the fallback
``curlike.shim`` runs when no real curl is on PATH.

Built on duho: the options are mixin groups, one module per group --
``request``, ``body``, ``output``, ``writeout``, ``tls``, ``connection``,
``cookies`` -- composed in ``options.CurlCmd``; ``transfer`` runs the request
(urllib, curl's output, one-line errors and exit codes, ``--retry``);
``routing`` is the proxy decision the real-curl passthrough shares;
``argv`` reads a command line the way curl does, without parsing it. Flags
curl has and this does not honour are declared in ``unsupported`` and refused
out loud (exit 2): it never silently does the wrong thing.

duho comes from the interpreter, else from ``<P>_PYLIB`` (see ``_duho``). This package's ``__init__`` imports neither,
so the stdlib-only modules (``routing``) load without it.
"""

import sys


def run_fallback(argv):
    """Parse ``argv`` and run it. A refusal propagates: ``NotImplementedError``
    (an unsupported flag), ``ValueError`` (a conflict, a bad proxy
    configuration), ``SystemExit`` (a usage error, ``--help``)."""
    from ._duho import duho
    from .argv import attach_values
    from .options import CurlCmd

    rc = duho.parse(CurlCmd, attach_values(argv))()
    return 0 if rc is None else rc


def main(argv=None):
    """The command: curl's exit code, a refusal as curl's one-line exit 2."""
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        from . import _duho  # noqa: F401  (no duho: one line, not a traceback)
    except ImportError as exc:
        print('curl: (2) %s' % exc, file=sys.stderr)
        return 2
    from .errors import EarlyExit

    try:
        return run_fallback(argv)
    except EarlyExit as exc:
        print('curl: %s' % exc, file=sys.stderr)
        return exc.code
    except (ValueError, NotImplementedError) as exc:
        print('curl: (2) %s' % exc, file=sys.stderr)
        return 2
    except SystemExit as exc:  # argparse: --help (0) or a usage error (2)
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 2)
