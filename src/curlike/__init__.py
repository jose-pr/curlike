"""A curl-compatible command over the standard library: ``pycurl``,
``python -m curlike`` and :func:`main`. It never runs the real curl; a
launcher that prefers the real one (the dotagents net overlay's ``curl``)
uses :func:`caller_steering`, :func:`requested_url`, :func:`find_real_curl`
and :func:`describe_curl` to decide.

Built on duho: the options are mixin groups, one module per group --
``request``, ``body``, ``output``, ``writeout``, ``tls``, ``connection``,
``cookies`` -- composed in ``options.CurlCmd``; ``transfer`` runs the request
(urllib, curl's output, one-line errors and exit codes, ``--retry``);
``routing`` is the proxy decision for a transfer;
``argv`` reads a command line the way curl does, without parsing it. Flags
curl has and this does not honour are declared in ``unsupported`` and refused
out loud (exit 2): it never silently does the wrong thing.

duho comes from the interpreter, else from ``<P>_PYLIB`` (see ``_duho``). This package's ``__init__`` imports neither,
so the stdlib-only modules (``routing``) load without it.
"""

import sys


def caller_steering(argv):
    """``(proxy, noproxy, proxy_user)`` as ``argv`` names them (``-x`` /
    ``--proxy`` / ``--proxy1.0`` / ``--preproxy`` / ``--socks*``, ``--noproxy``,
    ``-U`` / ``--proxy-user``), ``None`` each when absent: argv read the way
    curl reads it, option values never taken for options. A ``-K`` /
    ``--config`` file may name a proxy: without another, its name is
    ``proxy``. One ``--next`` group at a time."""
    from .argv import caller_steering as steering

    return steering(argv)


def requested_url(argv):
    """The URL ``argv`` asks for (``--url``, else the first positional), curl's
    default scheme applied, or ``None``; never an option's value. Needs duho."""
    from .argv import requested_url as requested

    return requested(argv)


def find_real_curl(skip=None):
    """The system curl on PATH, or ``None``. PATH is walked directory by
    directory, skipping the directory ``skip`` and any curl with a
    ``curl.py`` beside it (a launcher of curlike)."""
    from pathlib import Path

    from .realcurl import find_real_curl as find

    return find(skip=None if skip is None else Path(skip).resolve())


def describe_curl(path):
    """``(version, schannel)`` of the curl at ``path``: its version as a
    tuple of ints (``None`` when it does not answer ``-V``) and whether it is
    built on Windows' Schannel."""
    from .realcurl import describe

    return describe(path)


def _parse(duho, spec, argv):
    """``duho.parse`` with argparse's usage dump turned into curl's lines: a
    usage error is an ``EarlyExit`` (exit 2); ``--help`` is shown as it is."""
    import contextlib
    import io
    import re

    from .args import HELP_HINT
    from .errors import EXIT_USAGE, EarlyExit

    shown = io.StringIO()
    try:
        with contextlib.redirect_stderr(shown):
            return duho.parse(spec, argv)
    except SystemExit as exc:
        text = shown.getvalue()
        if exc.code in (0, None) or 'error:' not in text:
            sys.stderr.write(text)
            raise
        message = text.rsplit('error: ', 1)[1].strip()
        extra = re.match(r'unrecognized arguments: (.*)', message)
        required = re.match(r'argument (-[^/ ]+)(?:/\S+)?: expected one argument', message)
        if extra:
            words = extra.group(1).split()
            flags = [w for w in words if w.startswith('-')]
            if flags:
                message = 'option %s: is unknown' % flags[0]
            else:
                message = '(2) more than one URL (%s): the fallback makes one transfer' % ', '.join(words)
        elif required:
            message = 'option %s: requires parameter' % required.group(1)
        raise EarlyExit(EXIT_USAGE, '%s\n%s' % (message, HELP_HINT))


def run_fallback(argv, *, ssl_context=None, proxy_ssl_context=None):
    """Parse ``argv`` and run it. ``ssl_context`` / ``proxy_ssl_context`` --
    a caller's ``ssl.SSLContext`` for every https origin / an https://
    proxy, used as given in place of what ``-k``, ``--cacert``, ``--cert``,
    ``--ciphers``, ``--tlsv1.x`` (and their ``--proxy-*`` twins) would build;
    those flags beside it are a conflict. A refusal propagates:
    ``NotImplementedError`` (an unsupported flag), ``ValueError`` (a
    conflict, a bad proxy configuration), ``TypeError`` (a context that is
    not an ``ssl.SSLContext``), ``SystemExit`` (a usage error, ``--help``)."""
    from ._duho import duho
    from .argv import attach_values
    from .options import CurlCmd

    command = _parse(duho, CurlCmd, attach_values(argv))
    command.use_contexts(ssl_context, proxy_ssl_context)
    rc = command()
    return 0 if rc is None else rc


def main(argv=None, *, ssl_context=None, proxy_ssl_context=None):
    """The command: curl's exit code, a refusal as curl's one-line exit 2.
    ``ssl_context`` / ``proxy_ssl_context`` as in :func:`run_fallback`."""
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        from . import _duho  # noqa: F401  (no duho: one line, not a traceback)
    except ImportError as exc:
        print('curl: (2) %s' % exc, file=sys.stderr)
        return 2
    from .errors import EarlyExit

    try:
        return run_fallback(argv, ssl_context=ssl_context, proxy_ssl_context=proxy_ssl_context)
    except EarlyExit as exc:
        print('curl: %s' % exc, file=sys.stderr)
        return exc.code
    except (ValueError, NotImplementedError) as exc:
        print('curl: (2) %s' % exc, file=sys.stderr)
        return 2
    except SystemExit as exc:  # argparse: --help (0) or a usage error (2)
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 2)
