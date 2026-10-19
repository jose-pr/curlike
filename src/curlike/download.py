"""Download options: what happens to a file on disk -- resume (``-C``), the
name from ``Content-Disposition`` (``-J``), the server's timestamp (``-R``),
conditional requests (``-z``, ``--etag-compare`` / ``--etag-save``), an
existing file (``--no-clobber``, ``--skip-existing``), a size cap
(``--max-filesize``) and cleanup (``--remove-on-error``).

Behaviour recorded from curl 8.21: a resume the server answers with 200
(ignoring the range) is exit 33 and leaves the file alone; 416 on a resume
means the file is complete, exit 0; a ``-z`` condition curl finds unmet from
``Last-Modified`` (or a 304) writes no file; an over-size download is exit
63 and writes nothing; ``-J`` strips directories from the name and will not
overwrite (exit 23).
"""

import email.utils
import os
import re
import sys
from datetime import datetime, timezone
from typing import Optional

from ._duho import Meta, Arg
from .args import Group, first_header
from .errors import EXIT_USAGE, EXIT_WRITE, EarlyExit, LocalError

EXIT_RANGE = 33
EXIT_FILESIZE = 63
#: ``--no-clobber`` tries ``name.1`` .. ``name.100``, as curl does.
NO_CLOBBER_TRIES = 100

_SIZE = re.compile(r'^\s*(\d+)\s*([kKmMgG]?)\s*$')
_DISPOSITION_NAME = re.compile(r'''filename\s*=\s*("([^"]*)"|[^;\s]+)''', re.IGNORECASE)


def parse_size(value):
    """curl's size argument: bytes, or a ``k`` / ``M`` / ``G`` suffix (1024s)."""
    match = _SIZE.match(value or '')
    if not match:
        raise ValueError('--max-filesize: not a size: %r' % value)
    return int(match.group(1)) * {'': 1, 'k': 1024, 'm': 1024**2, 'g': 1024**3}[match.group(2).lower()]


def parse_time(value):
    """A ``-z`` value as a unix time: an existing file's mtime, an HTTP date,
    an ISO 8601 date/time, or ``YYYYMMDD``; ``None`` when it is none of them
    (curl then warns and drops the condition)."""
    if os.path.exists(value):
        return os.path.getmtime(value)
    try:
        return email.utils.parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError, IndexError, OverflowError):
        pass
    for fmt in ('%Y%m%d', '%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def disposition_name(header_items):
    """The ``Content-Disposition`` filename with any directory part removed,
    or ``None``."""
    match = _DISPOSITION_NAME.search(first_header(header_items, 'content-disposition'))
    if not match:
        return None
    name = match.group(2) if match.group(2) is not None else match.group(1)
    name = re.split(r'[\\/]', name.strip())[-1]
    return name or None


class DownloadArgs(Group):
    """Resume, naming, timestamps, conditions and limits for the output file."""

    #: Set by ``prepare_download``: the resume offset, and whether the body
    #: is appended (a 206 to a resume).
    resume_from = None
    append_output = False
    _time_value = None
    opened = False  # the body's file was opened for writing by this run

    continue_at: Arg[Optional[str], Meta(metavar='OFFSET')] = None
    "Resume at OFFSET bytes, or - for the output file's size (Range: bytes=OFFSET-)"
    ("-C", "--continue-at")

    remote_header_name: bool = False
    "With -O, name the file from Content-Disposition (never overwriting)"
    ("-J", "--remote-header-name")

    remote_time: bool = False
    "Give the file the server's Last-Modified time"
    ("-R", "--remote-time")

    time_cond: Arg[Optional[str], Meta(metavar='TIME')] = None
    "Only if modified since TIME (a date or a file's mtime); -TIME: only if not"
    ("-z", "--time-cond")

    etag_save: Arg[Optional[str], Meta(metavar='FILE')] = None
    "Write the response's ETag to FILE"
    ("--etag-save",)

    etag_compare: Arg[Optional[str], Meta(metavar='FILE')] = None
    "Only if the ETag differs from the one in FILE (If-None-Match)"
    ("--etag-compare",)

    no_clobber: bool = False
    "Never overwrite the output file: write name.1, name.2, ... instead"
    ("--no-clobber",)

    skip_existing: bool = False
    "Do nothing when the output file already exists"
    ("--skip-existing",)

    remove_on_error: bool = False
    "Remove the output file when the transfer fails"
    ("--remove-on-error",)

    max_filesize: Arg[Optional[str], Meta(metavar='BYTES')] = None
    "Refuse a download larger than BYTES (k/M/G suffixes), exit 63"
    ("--max-filesize",)

    def _check(self):
        if self.continue_at is not None and self.remove_on_error:
            raise EarlyExit(
                EXIT_USAGE,
                '--continue-at is mutually exclusive with --remove-on-error\n'
                "curl: option -C: is badly used here\n"
                "curl: try 'curl --help' or 'curl --manual' for more information",
            )

    def size_limit(self):
        return parse_size(self.max_filesize) if self.max_filesize else None

    def prepare_download(self, headers):
        """Before the request: ``True`` when there is nothing to do
        (``--skip-existing`` and the file exists); otherwise the output
        name is settled (``--no-clobber``) and the conditional / range
        headers are added to ``headers``."""
        target = self.body_target
        if target and self.skip_existing and os.path.exists(target):
            if not self.silent:
                print('Note: skips transfer, "%s" exists locally' % target, file=sys.stderr)
            return True
        if target and self.no_clobber and os.path.exists(target):
            for n in range(1, NO_CLOBBER_TRIES + 1):
                candidate = '%s.%d' % (target, n)
                if not os.path.exists(candidate):
                    self.body_target = candidate
                    break
            else:
                raise LocalError(
                    EXIT_WRITE,
                    'Failure writing output to destination: %s and %s.1-%d exist' % (target, target, NO_CLOBBER_TRIES),
                )
        if self.continue_at is not None:
            if self.continue_at == '-':
                current = self.body_target
                self.resume_from = os.path.getsize(current) if current and os.path.exists(current) else 0
            else:
                self.resume_from = int(self.continue_at)
            if self.resume_from:
                headers['Range'] = 'bytes=%d-' % self.resume_from
        if self.time_cond:
            unmodified = self.time_cond.startswith('-')
            when = parse_time(self.time_cond[1:] if unmodified else self.time_cond)
            if when is None:
                if not self.silent:
                    print(
                        'Warning: Illegal date format for -z, --time-cond (and not a file name). '
                        'Disabling time condition.',
                        file=sys.stderr,
                    )
            else:
                self._time_value = (unmodified, when)
                name = 'If-Unmodified-Since' if unmodified else 'If-Modified-Since'
                headers[name] = email.utils.formatdate(when, usegmt=True)
        if self.etag_compare is not None:
            try:
                with open(self.etag_compare, encoding='utf-8') as handle:
                    etag = handle.readline().strip()
            except OSError:
                etag = ''
            headers['If-None-Match'] = etag or '""'
        return False

    def too_big(self, header_items, size=None):
        """Is the download over ``--max-filesize`` -- by its Content-Length
        before the body is read, or by ``size`` after?"""
        limit = self.size_limit()
        if limit is None:
            return False
        if size is not None:
            return size > limit
        length = first_header(header_items, 'content-length')
        return length.isdigit() and int(length) > limit

    def _continues_at(self, header_items):
        """Does the 206's ``Content-Range`` start at the resume offset?"""
        match = re.match(r'^\s*bytes\s+(\d+)-', first_header(header_items, 'content-range'), re.IGNORECASE)
        return bool(match) and int(match.group(1)) == self.resume_from

    def download_outcome(self, status, header_items):
        """After the response headers: ``'write'`` the body, ``'skip'`` it
        (a 304 or an unmet ``-z``, a 416 to a resume: nothing to do), or
        raise :class:`LocalError` (33: a resume the server ignored). Settles
        ``-J``'s name and the append mode."""
        if status == 304:
            return 'skip'
        if self.resume_from:
            if status == 416:
                return 'skip'
            if status == 200:
                raise LocalError(EXIT_RANGE, 'HTTP server does not seem to support byte ranges. Cannot resume.')
            if status == 206 and not self._continues_at(header_items):
                raise LocalError(EXIT_RANGE, 'HTTP server does not seem to support byte ranges. Cannot resume.')
            self.append_output = status == 206
        if self._time_value is not None and 200 <= status < 300:
            unmodified, when = self._time_value
            modified = first_header(header_items, 'last-modified')
            try:
                doc = email.utils.parsedate_to_datetime(modified).timestamp() if modified else None
            except (TypeError, ValueError, IndexError, OverflowError):
                doc = None
            if doc is not None and ((doc >= when) if unmodified else (doc <= when)):
                return 'skip'
        if self.remote_header_name and (self.remote_name or self.remote_name_all):
            name = disposition_name(header_items)
            if name:
                directory = os.path.dirname(self.body_target or '')
                target = os.path.join(directory, name) if directory else name
                if os.path.exists(target):
                    raise LocalError(
                        EXIT_WRITE, 'Failure writing output to destination: refusing to overwrite %s' % target
                    )
                self.body_target = target
        return 'write'

    def finish_download(self, header_items):
        """After the body is written: ``-R`` and ``--etag-save``."""
        if self.remote_time and self.body_target and os.path.exists(self.body_target):
            modified = first_header(header_items, 'last-modified')
            try:
                when = email.utils.parsedate_to_datetime(modified).timestamp() if modified else None
            except (TypeError, ValueError, IndexError, OverflowError):
                when = None
            if when is not None:
                os.utime(self.body_target, (when, when))
        if self.etag_save:
            etag = first_header(header_items, 'etag')
            with open(self.etag_save, 'w', encoding='utf-8', newline='\n') as handle:
                handle.write(etag + '\n' if etag else '')

    def cleanup_after(self, rc):
        """``--remove-on-error``: a failed transfer leaves no file it opened
        for writing, one it overwrote included."""
        if rc and self.remove_on_error and self.opened and self.body_target and os.path.exists(self.body_target):
            try:
                os.remove(self.body_target)
            except OSError:
                pass
