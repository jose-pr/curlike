"""A drop-in ``curl``: the ``pycurl`` command, ``python -m curlike``, or a
launcher of your own calling :func:`main`.

  1. **The real curl, when one is on PATH** (never this shim). Run with the
     caller's argv and its exit code returned -- with ONE addition: when
     syshttp's ``<P>_PROXY`` is set and the caller does not steer the proxy
     (``-x``/``--proxy*``/``--noproxy``/``-U``), ``--proxy`` and its
     credential are added, since real curl reads only the global proxy vars;
     and for a Schannel curl (Windows), ``--ssl-revoke-best-effort``
     (``<P>_CURL_SSL_REVOKE``).
     A leading ``-q`` stays first. ``<P>_CURL=0`` runs it exactly as typed.
  2. **Else the fallback** (:mod:`curlike`): the common curl surface over the
     standard library and duho. So is a request through a ``prefix``
     gateway, which curl cannot express.

A ``<P>_HOOKS_<KEY>_CURL`` wrapper runs in place of both for the URLs it
matches. ``<P>`` is syshttp's prefix (``SYSHTTP`` unless ``SYSHTTP_PREFIX``
says otherwise; see ``syshttp.env``). The real-curl path needs duho only when
the configured proxy or a URL hook is in play (to read argv the way curl does).
"""

import os
import subprocess
import sys
from pathlib import Path

from syshttp import hooks as net_hooks
from syshttp import proxy as agent_proxy
from syshttp.env import HTTPEnv

from curlike import main as fallback_main
from curlike import run_fallback  # noqa: F401  (re-exported for callers and tests)
from curlike.routing import configured_text, first_entry

#: Revocation checking for a real curl on Windows' Schannel, which (unlike
#: OpenSSL) checks it and fails a certificate whose revocation list is
#: missing or unreachable: ``best-effort`` (default) adds curl's
#: ``--ssl-revoke-best-effort``, ``false`` its ``--ssl-no-revoke``, ``true``
#: nothing (curl's own strict check).
REVOKE = 'CURL_SSL_REVOKE'
_REVOKE_VALUES = ('best-effort', 'true', 'false')
_REVOKE_FLAGS = ('--ssl-no-revoke', '--ssl-revoke-best-effort')

#: ``<P>_CURL=0`` / ``n`` / ``no`` / ``false`` / ``off``: run the real curl
#: exactly as typed -- no configured proxy, no hooks, no fallback. Anything
#: else (unset, ``1``, ``y``) is the shim.
SHIM = 'CURL'
_OFF = ('0', 'n', 'no', 'false', 'off')
#: The interpreter a ``.py`` hook wrapper runs under, as ``<P>_PYTHON``;
#: default this one.
PYTHON = 'PYTHON'

#: The names an executable of this shim goes by (a console script, a launcher).
_ENTRY_NAMES = ('curl', 'pycurl')


def _var(setting):
    return HTTPEnv().name(setting) or setting


def shim_enabled():
    return (HTTPEnv().get(SHIM) or '').lower() not in _OFF


def default_entry():
    """The executable this process was started as, when it is one of this
    shim's (``curl``, ``pycurl``, with any extension) -- else ``None``."""
    # os.path, not pathlib: on Python < 3.12 Path() picks its flavour from
    # os.name at call time, which a caller may have replaced.
    argv0 = sys.argv[0] if sys.argv else ''
    if not argv0:
        return None
    stem, suffix = os.path.splitext(os.path.basename(argv0))
    if stem.lower() not in _ENTRY_NAMES or suffix.lower() == '.py':
        return None
    return os.path.realpath(argv0) if os.path.isfile(argv0) else None


def caller_steering(argv):
    """``(proxy, noproxy, proxy_user)`` as the caller wrote them (see
    ``curlike.argv``)."""
    from curlike.argv import caller_steering as steering

    return steering(argv)


def requested_url(argv):
    """The URL the caller asked for, curl's default scheme applied, or ``None``."""
    from curlike.argv import requested_url as requested

    return requested(argv)


def find_real_curl(entry=None):
    """The system curl, or ``None`` -- never a copy of this shim. With the
    shim's own directory on PATH a bare ``which("curl")`` can find the shim
    itself, which would exec itself forever. PATH is walked directory by
    directory, skipping ``entry``'s directory, any hit that is not actually
    inside the directory searched (Windows ``which`` on Python < 3.12
    consults the cwd too) and any hit that has a ``curl.py`` beside it
    (another launcher of the shim)."""
    from curlike.compat import find_real_curl as find

    return find(skip=Path(entry).resolve().parent if entry else None)


def revoke_argv(curl_path, argv):
    """The revocation flag to add for ``curl_path`` (see :data:`REVOKE`):
    only for a Schannel curl (Windows), only when the caller chose none, and
    best-effort only where curl has it (7.70). An unknown value: ValueError."""
    raw = HTTPEnv().get(REVOKE)
    mode = (raw or 'best-effort').lower()
    if mode not in _REVOKE_VALUES:
        raise ValueError('%s=%s: expected one of %s' % (_var(REVOKE), raw, ', '.join(_REVOKE_VALUES)))
    if mode == 'true' or os.name != 'nt' or any(a in _REVOKE_FLAGS for a in argv):
        return []
    from curlike.compat import describe

    version, schannel = describe(curl_path)
    if not schannel:
        return []
    if mode == 'false':
        return ['--ssl-no-revoke']
    return ['--ssl-revoke-best-effort'] if version and version >= (7, 70, 0) else []


def _system_route(argv):
    """True when the system's proxy configuration is what would route this
    command: no proxy variable is set (curl reads the ``*_proxy`` ones
    itself, and ``<P>_PROXY`` is injected as configured)."""
    return not configured_text()


def agent_proxy_argv(argv):
    """Extra LEADING argv so real curl uses the proxy syshttp would, or ``[]``.

    Real curl reads only the global proxy vars (``http_proxy`` & co.), never
    ``<P>_PROXY`` and never the system's proxy configuration (WinHTTP,
    macOS, a desktop's, a PAC script), so a bare passthrough would send the
    traffic the wrong way. Injected when ``<P>_PROXY`` is set -- or, with no
    proxy variable at all, when the system's configuration names a proxy
    for the URL asked for (the first URL of the command) -- and the caller
    did not name a proxy (``-x``) or a bypass list (``--noproxy``); a
    caller's ``-U`` keeps the proxy but replaces the credential. A
    configured header value rides as ``--proxy-header`` (sent to the proxy
    only, the CONNECT included); URL userinfo as ``--proxy-user``.
    ``NO_PROXY`` needs nothing: curl honours it even with ``--proxy``. A
    prefix gateway is not expressible to curl -- see :func:`use_real_curl`."""
    configured = bool(HTTPEnv().get(agent_proxy.PROXY))
    if not configured and not _system_route(argv):
        return []
    proxy, noproxy, proxy_user = caller_steering(argv)
    if proxy or noproxy is not None:
        return []
    url = None if configured else requested_url(argv)
    if not configured and not url:
        return []
    if configured:
        entry = agent_proxy.configured_proxy()
    else:
        # The system's list: the first proxy that answers (exit 7 when none
        # does and it holds no DIRECT).
        entry = first_entry(agent_proxy.proxy_map(), url)
    if entry is None or entry.is_gateway:
        return []
    extra = ['--proxy', entry.url]
    if proxy_user:
        pass  # curl already has -U on its own argv
    elif entry.headers:
        for name, value in entry.headers.items():
            extra += ['--proxy-header', '%s: %s' % (name, value)]
    elif entry.username is not None:
        extra += ['--proxy-user', '%s:%s' % (entry.username, entry.password or '')]
    return extra


def use_real_curl(argv):
    """Real curl handles everything except a prefix gateway: it has no notion
    of ``<proxy><endpoint><url>``, and rewriting the URL argument by hand
    cannot cover multi-URL invocations, ``-L`` (curl would follow the
    gateway's Location straight to the origin, credential attached) or
    config files. So with the configured proxy in play and ``prefix``
    configured, the request is served by the fallback, which speaks the
    gateway per hop; flags the fallback lacks fail loud there, as the shim's
    contract says."""
    if not HTTPEnv().get(agent_proxy.PROXY):
        return True
    proxy, noproxy, _ = caller_steering(argv)
    if proxy or noproxy is not None:
        return True
    return agent_proxy.proxy_type()[0] != 'prefix'


def maybe_run_system_curl(argv, entry=None):
    """Run the real curl with the configured proxy applied; ``None`` when the
    fallback must serve the request (no real curl, or a prefix gateway).
    A malformed proxy configuration -- or no duho to read argv with --
    never blocks real curl: it runs with argv as typed, after one warning."""
    curl_path = find_real_curl(entry)
    if not curl_path:
        return None
    revoke = revoke_argv(curl_path, argv)  # a bad <P>_CURL_SSL_REVOKE: exit 2
    try:
        if not use_real_curl(argv):
            return None
        extra = agent_proxy_argv(argv)
    except agent_proxy.NoReachableProxyError as exc:
        # Nothing to hand real curl: no proxy the system names answers, and
        # its list holds no DIRECT. curl's own exit for an unreachable proxy.
        print('curl: (7) %s' % exc, file=sys.stderr)
        return 7
    except (ValueError, ImportError) as exc:
        print('curl: ignoring the configured proxy: %s' % exc, file=sys.stderr)
        extra = []
    # curl skips its config file only when -q / --disable is its FIRST
    # argument (any "-q..." cluster, e.g. -qs); anywhere else it is ignored,
    # so the injected proxy options go after it.
    lead = argv[:1] if argv and (argv[0].startswith('-q') or argv[0] == '--disable') else []
    result = subprocess.run([curl_path, *lead, *revoke, *extra, *argv[len(lead) :]])
    return result.returncode


def run_real_curl_as_typed(argv, entry=None):
    """``<P>_CURL=0``: the real curl with argv untouched, or exit 2 when
    there is none -- the caller asked for the real thing, a fallback would
    be a surprise."""
    curl_path = find_real_curl(entry)
    if not curl_path:
        print(
            'curl: (2) %s=%s asks for the real curl, which is not on PATH' % (_var(SHIM), HTTPEnv().get(SHIM)),
            file=sys.stderr,
        )
        return 2
    return subprocess.run([curl_path, *argv]).returncode


def maybe_run_hook(argv, entry=None):
    """``<P>_HOOKS_<KEY>`` + ``_CURL``: when the caller's URL matches, run the
    wrapper in this shim's place with argv appended and, in its environment,
    the ``<P>_HOOK_*`` variables of ``syshttp.hooks.wrapper_environment``
    (``<P>_HOOK_CURL`` is ``entry``: the executable to call curl back with).
    Returns the wrapper's exit code, or ``None`` when no hook applies."""
    if not net_hooks.hooks_from_env():
        return None  # no hook configured: argv need not be read
    url = requested_url(argv)
    if not url:
        return None
    hooks = net_hooks.matching(url, kind='curl')
    if not hooks:
        return None
    hook = hooks[0]
    command = net_hooks.curl_command(hook, python=HTTPEnv().get(PYTHON) or sys.executable)
    env = dict(os.environ)
    env.update(net_hooks.wrapper_environment(hook, url, entry or ''))
    return subprocess.run([*command, *argv], env=env).returncode


def main(argv=None, *, entry=None, ssl_context=None, proxy_ssl_context=None):
    """The shim: curl's exit code. ``entry`` -- the executable acting as this
    curl (a launcher's own path), skipped when looking for the real curl and
    handed to hook wrappers; default :func:`default_entry`.
    ``ssl_context`` / ``proxy_ssl_context`` -- a caller's TLS contexts
    (``curlike.run_fallback``). Neither the real curl nor a hook wrapper can
    be given one, so with a context the fallback serves the request."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if ssl_context is not None or proxy_ssl_context is not None:
        return fallback_main(argv, ssl_context=ssl_context, proxy_ssl_context=proxy_ssl_context)
    entry = entry if entry is not None else default_entry()
    if not shim_enabled():
        return run_real_curl_as_typed(argv, entry)
    try:
        hook_rc = maybe_run_hook(argv, entry)
        if hook_rc is not None:
            return hook_rc
        system_curl_rc = maybe_run_system_curl(argv, entry)
        if system_curl_rc is not None:
            return system_curl_rc
    except (ValueError, ImportError) as exc:
        # A configuration error (a bad <P>_PROXY / <P>_PROXY_TYPE that would
        # be used), or a URL hook with no duho to read argv with, is curl's
        # exit 2, one line on stderr -- not a traceback.
        print('curl: (2) %s' % exc, file=sys.stderr)
        return 2
    return fallback_main(argv)
