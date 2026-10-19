"""The real curl on this machine: where it is and which build it is."""

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple


def find_real_curl(skip=None):
    """The system curl, or ``None`` -- never a launcher of curlike. PATH is
    walked directory by directory, skipping ``skip``, any hit that is not
    actually inside the directory searched (Windows ``which`` on Python <
    3.12 consults the cwd too) and any hit with a ``curl.py`` beside it (a
    launcher: the dotagents net overlay's ``bin/`` is on PATH in a session)."""
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
