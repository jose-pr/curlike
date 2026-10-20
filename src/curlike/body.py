"""Body options: ``-d`` and its variants, ``--json``, ``--data-urlencode``,
multipart ``-F`` / ``--form-string``, and ``-T`` uploads."""

import argparse
import binascii
import os
import re
import urllib.parse
from typing import List, Optional

from ._duho import Meta, Arg
from .args import Group, read_source, url_encoded
from .errors import EXIT_READ, LocalError

FORM_CONTENT_TYPE = 'application/x-www-form-urlencoded'
JSON_CONTENT_TYPE = 'application/json'

#: The ``;key=`` parameters that may trail a ``-F`` value.
_FORM_PARAM = re.compile(r';\s*(type|filename|headers|encoder)=', re.IGNORECASE)
#: curl's content types for an uploaded file, by extension; else octet-stream.
_FORM_TYPES = {
    '.gif': 'image/gif',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.txt': 'text/plain',
    '.htm': 'text/html',
    '.html': 'text/html',
    '.pdf': 'application/pdf',
    '.xml': 'application/xml',
}


class FileBody(object):
    """A regular file uploaded by ``-T``: read in pieces as it is sent (its
    size is the Content-Length), and again for a redirect that resends it."""

    PIECE = 65536

    def __init__(self, path, size):
        self.path = path
        self.size = size

    def __len__(self):
        return self.size

    def __iter__(self):
        with open(self.path, 'rb') as handle:
            while True:
                piece = handle.read(self.PIECE)
                if not piece:
                    return
                yield piece


#: The option name curl names when it cannot read a data file, by field.
_OPTIONS = {'data': '-d', 'data_binary': '--data-binary', 'data_urlencode': '--data-urlencode', 'json_data': '--json'}


class _InOrder(argparse.Action):
    """``append``, plus a ``(dest, value)`` record in the group's ordered
    list: curl joins the pieces in command-line order, across options."""

    group = 'body_parts'

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, (getattr(namespace, self.dest, None) or []) + [values])
        setattr(namespace, self.group, (getattr(namespace, self.group, None) or []) + [(self.dest, values)])


class _InFormOrder(_InOrder):
    group = 'form_parts'


def _form_quote(text):
    """A multipart name or filename as curl writes it: ``"``, CR and LF
    percent-encoded."""
    return text.replace('"', '%22').replace('\r', '%0D').replace('\n', '%0A')


def _split_form_value(value):
    """A ``-F`` value as ``(content, {'type': ..., 'filename': ...})``: after
    ``@`` / ``<`` a ``"..."`` (a backslash escapes ``"`` and itself) is a file
    name that may hold ``;``; the ``;type=`` / ``;filename=`` pieces follow,
    and a type keeps the ``;k=v`` pieces that are not keywords
    (``type=text/plain;charset=utf-8``)."""
    prefix = value[:1] if value[:1] in ('@', '<') else ''
    rest = value[len(prefix) :]
    if prefix and rest.startswith('"'):
        chars, i = [], 1
        while i < len(rest) and rest[i] != '"':
            if rest[i] == '\\' and rest[i + 1 : i + 2] in ('"', '\\'):
                i += 1
            chars.append(rest[i])
            i += 1
        content, tail = ''.join(chars), rest[i + 1 :]
    else:
        cut = _FORM_PARAM.search(rest)
        content, tail = (rest[: cut.start()], rest[cut.start() :]) if cut else (rest, '')
    params, last = {}, None
    for piece in tail.split(';')[1:]:
        key, sep, raw = piece.partition('=')
        key = key.strip().lower()
        if sep and key in ('type', 'filename', 'headers', 'encoder'):
            quoted = len(raw) > 1 and raw[0] == raw[-1] == '"'
            params[key] = raw[1:-1] if quoted else raw.strip()
            last = key
        elif last == 'type':
            params['type'] += ';' + piece.strip()  # a parameter of the type
        elif sep:
            params[key] = raw.strip()
    return prefix + content, params


def _form_file(path):
    """A ``-F`` part's file: curl reads it during the transfer, so a missing
    one is ``curl: (26)`` (``-w`` still written)."""
    try:
        return read_source(path)
    except OSError:
        raise LocalError(EXIT_READ, 'Failed to open/read local data from file/application')


class BodyArgs(Group):
    """What the request carries."""

    #: ``(option, value)`` in command-line order, filled by the actions.
    body_parts = None
    form_parts = None

    data: Arg[Optional[List[str]], Meta(action=_InOrder)] = None
    "HTTP POST data (repeatable, joined with &; @file, @- for stdin)"
    ("-d", "--data", "--data-ascii")

    data_raw: Arg[Optional[List[str]], Meta(action=_InOrder)] = None
    "HTTP POST data without @file expansion"
    ("--data-raw",)

    data_binary: Arg[Optional[List[str]], Meta(action=_InOrder)] = None
    "HTTP POST data as is (@file, @- for stdin)"
    ("--data-binary",)

    data_urlencode: Arg[Optional[List[str]], Meta(action=_InOrder, metavar='DATA')] = None
    "HTTP POST data, URL-encoded: content, =content, name=content, @file, name@file"
    ("--data-urlencode",)

    json_data: Arg[Optional[List[str]], Meta(action=_InOrder, metavar='DATA')] = None
    "JSON body (@file, @- for stdin; repeats concatenate); sends Content-Type and Accept: application/json"
    ("--json",)

    form: Arg[Optional[List[str]], Meta(action=_InFormOrder, metavar='NAME=CONTENT')] = None
    "multipart field: name=value, name=@file (upload), name=<file (its content); ;type= and ;filename= may follow"
    ("-F", "--form")

    form_string: Arg[Optional[List[str]], Meta(action=_InFormOrder, metavar='NAME=STRING')] = None
    "multipart field, the value taken literally"
    ("--form-string",)

    upload_file: Arg[Optional[str], Meta(metavar='FILE')] = None
    "PUT this file (- for stdin); a URL ending in / gets its name"
    ("-T", "--upload-file")

    def _check(self):
        if self.form_parts and self.body_parts:
            raise ValueError(
                'You can only select one HTTP request method! '
                'You asked for both POST (-d) and multipart formpost (-F).'
            )

    def body_headers(self):
        """The headers the body implies: ``--json``'s Content-Type and Accept."""
        if self.json_data:
            return {'Content-Type': JSON_CONTENT_TYPE, 'Accept': JSON_CONTENT_TYPE}
        return {}

    def build_body(self):
        """The ``-d`` family's body, or ``None``: every piece in command-line
        order, joined with ``&`` -- except consecutive ``--json`` pieces, which
        concatenate, as curl does. ``-d @file`` drops CR/LF; ``--data-raw``
        never reads a file."""
        pieces = []
        for dest, value in self.body_parts or []:
            option = _OPTIONS.get(dest, '-d')
            if dest == 'data_urlencode':
                part = url_encoded(value, lambda path: self.read_data(path, option)).encode('ascii')
            elif dest == 'data_raw' or not value.startswith('@'):
                part = value.encode('utf-8')
            else:
                part = self.read_data(value[1:], option)
                if dest == 'data':
                    part = part.replace(b'\r', b'').replace(b'\n', b'').replace(b'\0', b'')
            pieces.append((dest == 'json_data', part))
        if not pieces:
            return None
        body = pieces[0][1]
        for (was_json, _), (is_json, part) in zip(pieces, pieces[1:]):
            body += (b'' if is_json else b'&') + part
        return body

    def build_form(self):
        """``(body, content_type)`` for ``-F`` / ``--form-string``, or ``None``."""
        if not self.form_parts:
            return None
        boundary = ('-' * 24 + binascii.hexlify(os.urandom(8)).decode('ascii')).encode('ascii')
        out = []
        for dest, spec in self.form_parts:
            name, content, filename, ctype = self._form_field(spec, literal=dest == 'form_string')
            disposition = 'form-data; name="%s"' % _form_quote(name)
            if filename is not None:
                disposition += '; filename="%s"' % _form_quote(filename)
            head = 'Content-Disposition: %s\r\n' % disposition
            if ctype:
                head += 'Content-Type: %s\r\n' % ctype
            out.append(b'--' + boundary + b'\r\n' + head.encode('utf-8') + b'\r\n' + content + b'\r\n')
        out.append(b'--' + boundary + b'--\r\n')
        return b''.join(out), 'multipart/form-data; boundary=' + boundary.decode('ascii')

    def _form_field(self, spec, literal):
        """``(name, content, filename, content_type)`` of one ``-F`` value:
        ``@file`` uploads (filename and a type by extension), ``<file`` sends
        the file's content as the value; ``;type=`` / ``;filename=`` override."""
        name, sep, value = spec.partition('=')
        if not sep:
            self.usage_error('Illegally formatted input field: %s' % spec)
        if literal:
            return name, value.encode('utf-8'), None, None
        value, params = _split_form_value(value)
        unknown = sorted(set(params) - {'type', 'filename'})
        if unknown:
            raise NotImplementedError('Unsupported -F parameter: ;%s=' % unknown[0])
        if value.startswith('@'):
            path = value[1:]
            ctype = params.get('type') or _FORM_TYPES.get(os.path.splitext(path)[1].lower(), 'application/octet-stream')
            return name, _form_file(path), params.get('filename', os.path.basename(path)), ctype
        if value.startswith('<'):
            return name, _form_file(value[1:]), params.get('filename'), params.get('type')
        return name, value.encode('utf-8'), params.get('filename'), params.get('type')

    def build_upload(self, url):
        """``(url, content)`` for ``-T`` -- a URL with no file name (empty
        path, or ending in ``/``) gets the local file's -- or ``(url, None)``.
        ``-`` and ``.`` are stdin. An unreadable file is curl's exit 26."""
        source = self.upload_file
        if not source:
            return url, None
        stdin = source in ('-', '.')
        try:
            if not stdin and os.path.isfile(source):
                with open(source, 'rb'):  # readable, or curl's 26 now
                    pass
                size = os.path.getsize(source)
                content = FileBody(source, size) if size else b''
            else:
                content = read_source('-' if stdin else source)
        except OSError as exc:
            raise LocalError(EXIT_READ, 'Failed to open/read local data from file/application: %s' % exc)
        parts = urllib.parse.urlsplit(url)
        if not stdin and not parts.query and (not parts.path or parts.path.endswith('/')):
            path = (parts.path or '/') + urllib.parse.quote(os.path.basename(source))
            url = urllib.parse.urlunsplit(parts._replace(path=path))
        return url, content
