"""Which curl the fallback answers as, where curl versions disagree.

``<P>_CURL_COMPAT`` (``SYSHTTP_CURL_COMPAT`` by default; the prefix
is syshttp's, see ``syshttp.env``) names a curl version (``8.19``, ``8.19.0``) or ``auto``
(the default): the version of the real curl on PATH -- the shim serves a
prefix-gateway request from the fallback even when curl is installed -- else
:data:`NEWEST`. Read lazily: only a version-dependent answer asks for it.

The differences, measured against curl's own builds (8.17-8.22, Windows)
and static Linux builds (8.5-8.17; no 8.6 was measured):

- a proxy refusing the CONNECT: 56 before 8.20, 7 from 8.20 on;
- a response header over curl's limit: 27 ("Out of memory") before 8.6, 100
  from 8.6 on;
- ``%{scheme}`` upper case (``HTTP``) before 8.8; the ports with no
  connection 0 before 8.10 (-1 from 8.10 on);
- ``--proxy-pinnedpubkey`` ignored under ``--proxy-insecure`` before 8.10;
- a ``--netrc-file`` naming no file ignored before 8.12;
- a SOCKS proxy whose name does not resolve: 6 before 8.14, 5 from 8.14 on.

Distributions patch their curl: Ubuntu 24.04's 8.5 answers ``--proto =bogus``
as 8.7 does (a vanilla 8.5 drops the whole token). The fallback follows the
patched one, the 8.5 that ships there;
- a ``--cacert`` / ``--netrc-file`` naming no file: refused before anything
  else (exit 2) from 8.18 on; before, the CA file fails at the TLS handshake
  (77) and the netrc file when it is read (26);
- an unknown protocol name in ``--proto`` / ``--proto-redir``: a usage error
  (exit 2) from 8.18 on; before, the name is ignored (its ``=`` / ``-`` still
  applied);
- a ``-w`` variable newer than the version (``WRITE_OUT_SINCE``): a warning
  ("unknown --write-out variable") and nothing written;
- a name a ``socks5://`` / ``socks4://`` proxy needs resolved here and that
  does not resolve: 97 before 8.20 (worded "Could not resolve proxy: <the
  proxy>"), 6 from 8.20 on.

The wording of an output that cannot be written (exit 23 in every version)
was measured on Ubuntu 24.04's 8.5, on 8.18 (Linux) and on 8.21 (Windows, two
builds). The versions between are read from curl's source at its release
tags, not measured:

- a write the destination took only part of: "Failure writing output to
  destination", with ", passed N returned M" from 8.7 on; before 8.7 a header
  line that could not be written is "Failed writing header";
- an output file that cannot be opened: "client returned ERROR on write of N
  bytes" from 8.8 on; in 8.7 the message above with M as 4294967295, before
  that without numbers;
- ``-D -`` to a stdout that is gone: noticed at the first header line from 8.9
  on ("Failed writing headers to -"); before, only when the body is written;
- the tool's own messages, the ones with no exit code ("Failed writing body",
  "Failed to open <file>"): under ``-s`` they are printed with ``-S`` from
  8.17 on, and not at all before; wrapped to the terminal's width from 8.9
  on, to 79 columns before.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple

from syshttp.env import HTTPEnv

#: The setting, as ``<P>_CURL_COMPAT``.
COMPAT = 'CURL_COMPAT'


def var(env=None):
    """The variable naming the compatibility version, for messages and tests."""
    return (env or HTTPEnv()).name(COMPAT) or COMPAT


#: The newest curl measured: what the fallback answers as with no curl to ask.
NEWEST = (8, 22, 0)

_cached: Dict[str, Tuple[int, int, int]] = {}


def find_real_curl(skip=None):
    """The system curl, or ``None`` -- never a copy of the shim. PATH is
    walked directory by directory, skipping ``skip``, any hit that is not
    actually inside the directory searched (Windows ``which`` on Python <
    3.12 consults the cwd too) and any hit with a ``curl.py`` beside it (a
    copy of the shim: the overlay's ``bin/`` is on PATH in a session)."""
    for directory in os.environ.get('PATH', '').split(os.pathsep):
        if not directory:
            continue
        try:
            searched = Path(directory).resolve()
            if skip is not None and searched == skip:
                continue
            found = shutil.which('curl', path=directory)
            if not found:
                continue
            found_path = Path(found).resolve()
            if found_path.parent != searched or (found_path.parent / 'curl.py').is_file():
                continue
        except OSError:
            continue
        return found
    return None


def parse_version(text):
    """``(major, minor, patch)`` from ``8.19`` / ``8.19.0`` / ``curl 8.19.0
    (...)``, or ``None``."""
    m = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', text or '')
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


_described: Dict[str, Tuple[Optional[Tuple[int, int, int]], bool]] = {}


def describe(path):
    """``(version, schannel)`` of the curl at ``path`` (``curl -V``, once per
    process): its version or ``None``, and whether its TLS is Windows'
    Schannel -- which checks certificate revocation, unlike OpenSSL."""
    if path not in _described:
        try:
            out = getattr(
                subprocess.run([path, '-V'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL), 'stdout', b''
            )
        except (OSError, subprocess.SubprocessError):
            out = b''
        text = (out or b'').decode('ascii', 'replace')
        first = text.splitlines()[:1]
        version = parse_version(first[0]) if first and first[0].startswith('curl ') else None
        _described[path] = (version, 'schannel' in text.lower())
    return _described[path]


def installed_version():
    """The real curl's version (``curl -V``), or ``None`` without one."""
    path = find_real_curl()
    return describe(path)[0] if path else None


def version():
    """The curl version the fallback answers as. An unreadable
    ``<P>_CURL_COMPAT`` raises ``ValueError`` (the command's exit 2)."""
    raw = HTTPEnv().get(COMPAT) or ''
    if raw not in _cached:
        if raw.lower() in ('', 'auto'):
            _cached[raw] = installed_version() or NEWEST
        else:
            parsed = parse_version(raw) if re.match(r'^\d+\.\d+(\.\d+)?$', raw) else None
            if parsed is None:
                raise ValueError('%s=%s: expected a curl version (8.19, 8.19.0) or auto' % (var(), raw))
            _cached[raw] = parsed
    return _cached[raw]


def check():
    """Validate an explicit ``<P>_CURL_COMPAT`` before anything is sent (exit
    2); ``auto`` stays lazy, as it may run ``curl -V``."""
    if (HTTPEnv().get(COMPAT) or '').lower() not in ('', 'auto'):
        version()


def connect_refused_code():
    """curl's exit when the proxy answers the CONNECT with an error status."""
    return 7 if version() >= (8, 20, 0) else 56


def socks_unresolved(host, proxy_host):
    """``(exit code, message)`` for a target a SOCKS client could not resolve."""
    if version() >= (8, 20, 0):
        return 6, 'Could not resolve host: %s' % host
    return 97, 'Could not resolve proxy: %s' % proxy_host


#: The curl release that added a -w variable, where it is newer than 8.17.
WRITE_OUT_SINCE = {
    'size_delivered': (8, 20, 0),
    'time_posttransfer': (8, 10, 0),
    'proxy_used': (8, 7, 0),
    'num_retries': (8, 9, 0),
}


def knows_write_out(name):
    """Whether the curl answered as knows the -w variable ``name``."""
    since = WRITE_OUT_SINCE.get(name)
    return since is None or version() >= since


def no_port():
    """%{remote_port} / %{local_port} with no connection: -1 from curl 8.10, 0 before."""
    return -1 if version() >= (8, 10, 0) else 0


def upper_scheme():
    """Whether ``%{scheme}`` is written upper case (``HTTP``)."""
    return version() < (8, 8, 0)


def too_large():
    """``(exit code, message)`` for a response header over curl's limit."""
    if version() >= (8, 6, 0):
        return 100, 'A value or data field grew larger than allowed'
    return 27, 'Out of memory'


def pins_proxy_when_insecure():
    """Whether --proxy-pinnedpubkey holds under --proxy-insecure."""
    return version() >= (8, 10, 0)


def ignores_missing_netrc_file():
    """Whether a --netrc-file naming no file is silently ignored."""
    return version() < (8, 12, 0)


def socks_proxy_unresolved_code():
    """curl's exit when a SOCKS proxy's own name does not resolve."""
    return 5 if version() >= (8, 14, 0) else 6


def rejects_unknown_protocols():
    """Whether an unknown name in --proto / --proto-redir is exit 2 (else it
    is ignored)."""
    return version() >= (8, 18, 0)


def short_write(passed, returned, header=False):
    """curl's text for a write of ``passed`` bytes the destination took
    ``returned`` of; ``header`` when it was a header line."""
    if version() >= (8, 7, 0):
        return 'Failure writing output to destination, passed %d returned %d' % (passed, returned)
    return 'Failed writing header' if header else 'Failure writing output to destination'


def refused_write(passed, header=False):
    """curl's text for a write of ``passed`` bytes its own output callback
    refused: the output file could not be opened."""
    if version() >= (8, 8, 0):
        return 'client returned ERROR on write of %d bytes' % passed
    return short_write(passed, 0xFFFFFFFF, header)  # the callback's error value, printed as a count


def checks_header_dump():
    """Whether a ``-D`` stream that cannot be written fails the transfer at
    the header line (else it goes unnoticed until the body)."""
    return version() >= (8, 9, 0)


def shows_notices_when_silent():
    """Whether ``-S`` brings back, under ``-s``, the tool's own messages (the
    ones with no exit code)."""
    return version() >= (8, 17, 0)


def wraps_to_terminal():
    """Whether those messages wrap to the terminal's width (else to 79)."""
    return version() >= (8, 9, 0)


def checks_files_first():
    """Whether a ``--cacert`` / ``--netrc-file`` naming no file is refused
    before anything else (exit 2)."""
    return version() >= (8, 18, 0)
