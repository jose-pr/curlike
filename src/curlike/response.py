"""The response head as curl reads it: http.client's own parser with curl's
limits (100 KB a header line, 300 KB and 5000 headers a response) and curl's
refusals (a Content-Length that is not one number, a NUL in a header), and
no process-wide setting changed to get them."""

import email.parser
import http.client

#: curl's limits: one header line, the whole block, and the number of headers.
MAX_HEADER_LINE = 100 * 1024
MAX_HEADER_BYTES = 300 * 1024
MAX_HEADERS = 5000


class ResponseRefused(http.client.HTTPException):
    """A response curl refuses: ``code`` is its exit code, ``text`` its message."""

    def __init__(self, code, text):
        http.client.HTTPException.__init__(self, text)
        self.code = code
        self.text = text


def content_length(values):
    """The one number a response's ``Content-Length`` values name (``2, 2`` is
    one), or ``None`` without any; anything else is :class:`ResponseRefused`
    (curl's 8)."""
    seen = set()
    for value in values:
        for part in value.split(','):
            part = part.strip()
            if not (part.isascii() and part.isdigit()):
                raise ResponseRefused(8, 'Invalid Content-Length: value')
            seen.add(int(part))
    if len(seen) > 1:
        raise ResponseRefused(8, 'Invalid Content-Length: value')
    return seen.pop() if seen else None


class LimitedResponse(http.client.HTTPResponse):
    """:class:`http.client.HTTPResponse` reading its head under curl's rules."""

    def _read_headers(self, consumed):
        lines = []
        while True:
            line = self.fp.readline(MAX_HEADER_LINE + 1)
            if len(line) > MAX_HEADER_LINE:
                raise http.client.LineTooLong('header line')
            consumed += len(line)
            if consumed > MAX_HEADER_BYTES:
                raise ResponseRefused(56, 'Too large response headers: %d > %d' % (consumed, MAX_HEADER_BYTES))
            if b'\0' in line:
                raise ResponseRefused(8, 'Nul byte in header')
            if line in (b'\r\n', b'\n', b''):
                return lines
            if len(lines) >= MAX_HEADERS:
                raise ResponseRefused(100, 'Too many response headers, %d is max' % MAX_HEADERS)
            lines.append(line)

    def begin(self):
        if self.headers is not None:
            return
        while True:
            version, status, reason = self._read_status()
            consumed = len(version) + len(str(status)) + len(reason) + 4  # the status line
            if status != http.client.CONTINUE:
                break
            self._read_headers(consumed)  # the 100 response's headers are skipped
        self.code = self.status = status
        self.reason = reason.strip()
        if version in ('HTTP/1.0', 'HTTP/0.9'):
            self.version = 10
        elif version.startswith('HTTP/1.'):
            self.version = 11
        else:
            raise http.client.UnknownProtocol(version)
        lines = self._read_headers(consumed)
        text = b''.join(lines).decode('iso-8859-1') + '\r\n'
        self.headers = self.msg = email.parser.Parser(_class=http.client.HTTPMessage).parsestr(text)
        encoding = self.headers.get('transfer-encoding')
        self.chunked = bool(encoding and encoding.lower() == 'chunked')
        self.chunk_left = None
        self.will_close = self._check_close()
        self.length = None
        if not self.chunked:
            self.length = content_length(self.headers.get_all('content-length') or [])
        if (
            status in (http.client.NO_CONTENT, http.client.NOT_MODIFIED)
            or 100 <= status < 200
            or self._method == 'HEAD'
        ):
            self.length = 0
        if not self.will_close and not self.chunked and self.length is None:
            self.will_close = True
