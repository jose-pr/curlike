"""A response body as it arrives: read in pieces (what came is kept when the
connection breaks) and, under ``--compressed``, decoded a piece at a time."""

import http.client
import urllib.error
import zlib

#: The most one write of curl's carries, and so the largest piece handed on.
PIECE = 16384


class TooSlow(Exception):
    """--speed-limit / --speed-time: the transfer stayed too slow."""


class EncodingError(Exception):
    """A ``Content-Encoding`` ``--compressed`` cannot undo: curl's 61."""


class _Layer(object):
    """One ``Content-Encoding`` undone: gzip (members may follow one another)
    or deflate (zlib-wrapped or raw)."""

    def __init__(self, name):
        if name not in ('gzip', 'x-gzip', 'deflate'):
            raise EncodingError('Unrecognized content encoding type')
        self.gzip = name != 'deflate'
        self.inflater = zlib.decompressobj(16 + zlib.MAX_WBITS) if self.gzip else None
        self.started = False

    def _deflate_start(self, data):
        # A zlib header: deflate method in the low nibble and a checksum
        # divisible by 31; anything else is a raw deflate stream.
        zlib_wrapped = len(data) >= 2 and data[0] & 0x0F == 8 and ((data[0] << 8) | data[1]) % 31 == 0
        self.inflater = zlib.decompressobj(zlib.MAX_WBITS if zlib_wrapped else -zlib.MAX_WBITS)

    def feed(self, data):
        if not data:
            return b''
        try:
            if self.inflater is None:
                self._deflate_start(data)
            self.started = True
            out = []
            while data:
                out.append(self.inflater.decompress(data))
                if not (self.gzip and self.inflater.eof and self.inflater.unused_data):
                    break
                data = self.inflater.unused_data  # the next gzip member
                self.inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
            return b''.join(out)
        except zlib.error as exc:
            raise EncodingError('Error while processing content unencoding: %s' % str(exc).rpartition(': ')[2])

    def finish(self):
        if self.started and not self.inflater.eof:
            raise EncodingError('Error while processing content unencoding: the data ends early')
        return b''


class Decoder(object):
    """The ``Content-Encoding`` layers of a response, undone in turn (the
    last applied first). An encoding it cannot undo raises
    :class:`EncodingError` when built, as curl fails with 61 at the headers."""

    def __init__(self, header_items):
        names = []
        for name, value in header_items:
            if name.lower() == 'content-encoding':
                names += [e.strip().lower() for e in value.split(',') if e.strip()]
        self.layers = [_Layer(name) for name in reversed(names) if name != 'identity']

    def feed(self, data):
        for layer in self.layers:
            data = layer.feed(data)
        return data

    def finish(self):
        """The data held back at the end of the body; a layer whose stream was
        cut short is :class:`EncodingError`."""
        out = b''
        for index, layer in enumerate(self.layers):
            tail = layer.finish()
            for later in self.layers[index + 1 :]:
                tail = later.feed(tail)
            out += tail
        return out


class BodyReader(object):
    """The body of ``response`` in pieces: iterate it, then ``cut`` is
    ``None`` or the exception that ended it early -- an ``IncompleteRead``
    for a body shorter than its Content-Length or a broken chunked encoding,
    else the socket's error or :class:`TooSlow`. ``pace`` is called with each
    piece's size; ``settle`` before each read."""

    def __init__(self, response, pace=None, ignore_length=False, settle=None):
        self.raw = response.fp if isinstance(response, urllib.error.HTTPError) else response
        self.pace = pace
        self.settle = settle
        self.cut = None
        if ignore_length and getattr(self.raw, 'length', None) is not None:
            self.raw.length = None  # --ignore-content-length: read until the server closes

    @property
    def chunked(self):
        return bool(getattr(self.raw, 'chunked', False))

    def __iter__(self):
        raw = self.raw
        if raw is None:
            return
        # read1: what has arrived, without waiting for a full buffer -- a plain
        # read() loses the bytes it buffered when the connection resets.
        read = getattr(raw, 'read1', raw.read)
        try:
            while True:
                if self.settle is not None:
                    self.settle()
                piece = read(PIECE)
                if not piece:
                    break
                yield piece
                if self.pace is not None:
                    self.pace(len(piece))
        except TooSlow as exc:
            self.cut = exc
            return
        except http.client.IncompleteRead as exc:
            self.cut = exc
            if exc.partial:
                yield exc.partial
            return
        except (OSError, http.client.HTTPException) as exc:
            self.cut = exc
            return
        missing = getattr(raw, 'length', None)
        if missing:
            # read(amt) returns b'' at EOF however much Content-Length promised.
            self.cut = http.client.IncompleteRead(b'', missing)
