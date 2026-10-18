"""Output options: where the body and headers go, how loud the fallback is,
and what an HTTP error status does (``-f`` / ``--fail-with-body``)."""

import contextlib
import os
import sys
import urllib.parse
from typing import Optional

from ._duho import Meta, Arg
from .args import Group
from .errors import EXIT_WRITE, WRITE_ERROR_TEXT, LocalError, WriteFailure


def output_path(name):
    """The file to open for ``name``: ``/dev/null`` is the null device on
    every platform -- Windows has no such path (its name is ``NUL``), and
    ``-o /dev/null -w '%{http_code}'`` is the usual status probe."""
    return os.devnull if name == '/dev/null' else name


def discard_stdout():
    """Point stdout at the null device, once a write to it has failed (the
    reader of a pipe went away). Nothing more can be delivered there, and a
    later write, or the flush at interpreter exit, would fail again: a
    traceback and Python's exit 120 in place of curl's 23."""
    try:
        fd = sys.stdout.fileno()
    except (AttributeError, OSError, ValueError):  # not a real file: a captured stream
        fd = None
    if fd is not None:
        try:
            null = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(null, fd)
            finally:
                os.close(null)
            return
        except OSError:
            pass
    sys.stdout = open(os.devnull, 'w', encoding='utf-8')


#: The C library's buffer for a stdout that is not a terminal, and the most
#: curl hands its write callback at once. Together they decide which of
#: curl's messages a stdout that went away produces.
STDIO_BUFFER = 4096
WRITE_CHUNK = 16384


class Stdout(object):
    """stdout written the way the C library under curl writes it, so that a
    reader that went away is reported in curl's words.

    A write that fits the buffer is kept; it reaches the pipe, and can fail,
    only when a later write overflows the buffer or at the final flush. One
    that does not fit tops the buffer up and sends it, then sends its whole
    blocks directly. Which of the two a failure meets is the difference
    between ``passed N returned M`` and ``Failed writing body``."""

    def __init__(self):
        self.pending = b''
        self.gone = False

    def _send(self, data):
        if not self.gone:
            try:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            except OSError:
                self.gone = True
                discard_stdout()
        return not self.gone

    def write(self, data):
        """One write of curl's. Returns the bytes taken: ``len(data)`` when
        all were, fewer when the pipe refused what had to be sent."""
        held = len(self.pending)
        if (held + len(data) <= STDIO_BUFFER) if held else (len(data) < STDIO_BUFFER):
            self.pending += data
            return len(data)
        took = STDIO_BUFFER - held if held else 0
        block, rest = self.pending + data[:took], data[took:]
        self.pending = b''
        whole = len(rest) - len(rest) % STDIO_BUFFER
        if (block and not self._send(block)) or (whole and not self._send(rest[:whole])):
            return took
        self.pending = rest[whole:]
        return len(data)

    def flush(self):
        """Send what is held. False when it could not be."""
        pending, self.pending = self.pending, b''
        return not pending or self._send(pending)


def terminal_columns():
    """The width curl wraps its own messages to: ``$COLUMNS``, else the
    terminal's (read where curl reads it: stdin, stderr on Windows), else 79."""
    raw = os.environ.get('COLUMNS', '')
    if raw.isdigit() and 20 < int(raw) < 10000:
        return int(raw)
    try:
        columns = os.get_terminal_size(2 if os.name == 'nt' else 0).columns
    except (OSError, ValueError):
        columns = 0
    return columns if 0 < columns < 10000 else 79


def notice_lines(text, prefix='curl: '):
    """A message of the tool's own (one with no exit code) as curl prints
    it: wrapped to the terminal's width at a blank, or cut where there is
    none, every line under the prefix."""
    from . import compat

    width = max((terminal_columns() if compat.wraps_to_terminal() else 79) - len(prefix), 1)
    lines = []
    while len(text) > width:
        cut = width - 1
        while cut and text[cut] not in ' \t':
            cut -= 1
        if not cut:
            cut = width - 1
        lines.append(prefix + text[: cut + 1])
        text = text[cut + 1 :]
    lines.append(prefix + text)
    return lines


def header_lines(header_bytes):
    """The header block as curl writes it: a line at a time."""
    return header_bytes.splitlines(True)


def body_chunks(content):
    """The body as curl's write callback gets it."""
    return [content[i : i + WRITE_CHUNK] for i in range(0, len(content), WRITE_CHUNK)]


class OutputArgs(Group):
    """Body and header destinations, verbosity, and failure on HTTP errors."""

    #: The -o / -O file once resolved (``output_target``).
    body_target = None

    #: stdout once this run has written to it (``stdout``).
    _out = None

    output: Optional[str] = None
    "Write the body to this file (- for stdout)"
    ("-o", "--output")

    remote_name: bool = False
    "Write the body to a file named like the URL's last path segment"
    ("-O", "--remote-name")

    remote_name_all: bool = False
    "-O for every URL (there is one here)"
    ("--remote-name-all",)

    output_dir: Arg[Optional[str], Meta(metavar='DIR')] = None
    "Directory for -o / -O files"
    ("--output-dir",)

    create_dirs: bool = False
    "Create the output file's missing directories"
    ("--create-dirs",)

    dump_header: Arg[Optional[str], Meta(metavar='FILE')] = None
    "Write response headers to file (or - for stdout)"
    ("-D", "--dump-header")

    include: bool = False
    "Include response headers in output"
    ("-i", "--include", "--show-headers")

    head: bool = False
    "Fetch headers only"
    ("-I", "--head")

    silent: bool = False
    "Silent mode"
    ("-s", "--silent")

    show_error: bool = False
    "Show errors even when silent"
    ("-S", "--show-error")

    verbose: bool = False
    "Verbose mode"
    ("-v", "--verbose")

    fail: bool = False
    "Fail silently (exit 22, no body) on HTTP errors"
    ("-f", "--fail")

    fail_with_body: bool = False
    "Exit 22 on HTTP errors, still writing the body"
    ("--fail-with-body",)

    # No-ops: the fallback prints no progress meter and writes the body in one go.
    no_buffer: bool = False
    "Disable output buffering (a no-op)"
    ("-N", "--no-buffer")

    progress_bar: bool = False
    "Progress bar (a no-op: no progress is shown)"
    ("-#", "--progress-bar")

    no_progress_meter: bool = False
    "No progress meter (a no-op: none is shown)"
    ("--no-progress-meter",)

    styled_output: bool = False
    "Styled header output (a no-op: none is styled)"
    ("--styled-output",)

    stderr: Arg[Optional[str], Meta(metavar='FILE')] = None
    "Write what goes to stderr to FILE instead (- for stdout)"
    ("--stderr",)

    @contextlib.contextmanager
    def stderr_redirected(self):
        """``--stderr``: stderr goes to the file (or stdout) for the run."""
        if not self.stderr:
            yield
            return
        target = sys.stdout if self.stderr == '-' else open(self.stderr, 'w', encoding='utf-8')
        saved, sys.stderr = sys.stderr, target
        try:
            yield
        finally:
            sys.stderr = saved
            if target is not sys.stdout:
                target.close()

    def _check(self):
        if self.fail and self.fail_with_body:
            raise ValueError('You must select either --fail or --fail-with-body, not both.')

    def fails_on(self, status):
        """Does ``status`` end the transfer as curl's exit 22?"""
        return (self.fail or self.fail_with_body) and status >= 400

    def output_target(self, url):
        """Resolve and remember where the body goes (``body_target``): -o's
        file, or -O's (the URL's last path segment), under --output-dir;
        ``None`` for stdout (``-o -`` too). --create-dirs makes the missing
        directories. A URL with no file name for -O is curl's exit 23."""
        target = self.output
        if target is None and (self.remote_name or self.remote_name_all):
            target = urllib.parse.urlsplit(url).path.rsplit('/', 1)[-1]
            if not target:
                raise LocalError(EXIT_WRITE, 'Remote file name has no length')
        if target is None or target == '-':
            self.body_target = None
            return None
        if self.output_dir and target != '/dev/null' and not os.path.isabs(target):
            target = os.path.join(self.output_dir, target)
        if self.create_dirs and target != '/dev/null' and os.path.dirname(target):
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
            except OSError as exc:
                raise LocalError(EXIT_WRITE, 'Failed to create the directory for %s: %s' % (target, exc))
        self.body_target = target
        return target

    def should_print_error(self):
        return (not self.silent) or self.show_error

    def stdout(self):
        """This run's stdout (:class:`Stdout`): ``-D -`` and the body share it."""
        if self._out is None:
            self._out = Stdout()
        return self._out

    def write_header_dump(self, header_bytes):
        """``-D``: the response headers to a file, or to stdout a line at a
        time, each sent at once, as curl writes them. A failure is curl's
        :class:`WriteFailure`."""
        if not self.dump_header:
            return
        if self.dump_header == '-':
            from . import compat

            out = self.stdout()
            for line in header_lines(header_bytes):
                out.write(line)
                if not out.flush() and compat.checks_header_dump():
                    raise WriteFailure(compat.refused_write(len(line)), notice='Failed writing headers to -')
            return
        try:
            with open(output_path(self.dump_header), 'wb') as handle:
                handle.write(header_bytes)
        except OSError:
            raise WriteFailure(WRITE_ERROR_TEXT, notice='Failed to open %s' % self.dump_header)

    def emit_output(self, header_bytes, content):
        """The body, after the headers with -i / -I, to the -o file or to
        stdout. A failure is curl's :class:`WriteFailure`."""
        from . import compat

        headers = header_lines(header_bytes) if self.include or self.head else []
        writes = headers + body_chunks(content)
        if self.body_target:
            # 'ab': a 206 answering a resume (-C) continues the file.
            mode = 'ab' if getattr(self, 'append_output', False) else 'wb'
            try:
                with open(output_path(self.body_target), mode) as handle:
                    for data in writes:
                        handle.write(data)
            except OSError:
                if not writes:
                    # curl opens the file at its first write; with none, it
                    # only warns that the file could not be created.
                    raise WriteFailure(WRITE_ERROR_TEXT, coded=False)
                raise WriteFailure(compat.refused_write(len(writes[0]), header=bool(headers)))
            if not self.silent:
                print('Output written to %s' % self.body_target, file=sys.stderr)
            return
        out = self.stdout()
        for index, data in enumerate(writes):
            taken = out.write(data)
            if taken != len(data):
                raise WriteFailure(compat.short_write(len(data), taken, header=index < len(headers)))
        if not out.flush():
            raise WriteFailure(WRITE_ERROR_TEXT, notice='Failed writing body', coded=False)
