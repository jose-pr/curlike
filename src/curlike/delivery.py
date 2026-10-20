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
        """``data`` undone, as a generator of pieces of at most ``PIECE``
        bytes: a layer never holds more output than one piece."""
        if not data:
            return
        try:
            if self.inflater is None:
                self._deflate_start(data)
            self.started = True
            while True:
                out = self.inflater.decompress(data, PIECE)
                if out:
                    yield out
                if self.inflater.eof:
                    data = self.inflater.unused_data  # past the stream: a gzip's next member
                    if not (self.gzip and data):
                        return
                    self.inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    continue
                data = self.inflater.unconsumed_tail
                # A full piece may leave output inside zlib with no input left.
                if not data and len(out) < PIECE:
                    return
        except zlib.error as exc:
            raise EncodingError('Error while processing content unencoding: %s' % str(exc).rpartition(': ')[2])

    def finish(self):
        if self.started and not self.inflater.eof:
            raise EncodingError('Error while processing content unencoding: the data ends early')


def _through(layer, pieces):
    for piece in pieces:
        yield from layer.feed(piece)


#: The most content encodings a response may name (curl's limit); more is exit 61.
MAX_ENCODINGS = 5


def encodings(header_items):
    """The ``Content-Encoding`` names of a response, lower-cased, in the order
    applied. More than ``MAX_ENCODINGS`` is :class:`EncodingError`."""
    names = []
    for name, value in header_items:
        if name.lower() == 'content-encoding':
            names += [e.strip().lower() for e in value.split(',') if e.strip()]
    if len(names) > MAX_ENCODINGS:
        raise EncodingError('Reject response exceeding limit of %d content encodings' % MAX_ENCODINGS)
    return names


class Decoder(object):
    """The ``Content-Encoding`` layers of a response, undone in turn (the
    last applied first). An encoding it cannot undo, or more than
    ``MAX_ENCODINGS`` of them, raises :class:`EncodingError` when built, as
    curl fails with 61 at the headers."""

    def __init__(self, header_items):
        self.layers = [_Layer(name) for name in reversed(encodings(header_items)) if name != 'identity']

    def feed(self, data):
        """``data`` decoded: a generator of pieces of at most ``PIECE``
        bytes. Each layer reads one piece of the one before only when asked
        for more, so a small body cannot expand in memory past a piece per
        layer."""
        pieces = iter((data,))
        for layer in self.layers:
            pieces = _through(layer, pieces)
        return pieces

    def finish(self):
        """At the end of the body: a layer whose stream was cut short is
        :class:`EncodingError`."""
        for layer in self.layers:
            layer.finish()


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
