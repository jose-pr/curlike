"""``-w`` / ``--write-out``: curl's format language and the variables the
fallback can report, formatted as curl formats them (checked against curl
8.21). Written however the transfer ends -- ``000`` and the exit code after a
transport failure, the status after ``-f``'s 22."""

import json
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Optional

from ._duho import Meta, Arg
from .args import Group, first_header
from .errors import EXIT_READ, EarlyExit
from .request import CURL_VERSION
from .routing import caller_url

#: The ``--write-out`` variables the fallback reports, with curl's meaning and
#: format. Any other ``%{name}`` (``time_connect``, ``remote_ip``, ``json``...)
#: or an ``%output{file}`` is refused before the request, like an unsupported flag.
WRITE_OUT_VARIABLES = frozenset(
    [
        'content_type',
        'errormsg',
        'exitcode',
        'filename_effective',
        'header_json',
        'http_code',
        'http_version',
        'method',
        'num_headers',
        'num_redirects',
        'redirect_url',
        'response_code',
        'scheme',
        'size_download',
        'size_upload',
        'time_starttransfer',
        'time_total',
        'url',
        'url_effective',
        'urlnum',
        'time_namelookup',
        'time_connect',
        'time_appconnect',
        'time_pretransfer',
        'time_posttransfer',
        'time_redirect',
        'time_queue',
        'remote_ip',
        'remote_port',
        'local_ip',
        'local_port',
        'num_connects',
        'num_retries',
        'speed_download',
        'speed_upload',
        'size_header',
        'size_request',
        'size_delivered',
        'http_connect',
        'proxy_used',
        'referer',
        'conn_id',
        'xfer_id',
        'json',
    ]
    + [
        'url.%s' % part
        for part in ('scheme', 'user', 'password', 'options', 'host', 'port', 'path', 'query', 'fragment', 'zoneid')
    ]
    + [
        'urle.%s' % part
        for part in ('scheme', 'user', 'password', 'options', 'host', 'port', 'path', 'query', 'fragment', 'zoneid')
    ]
)
#: ``%{stdout}`` / ``%{stderr}`` switch the stream; after ``%{onerror}`` the
#: rest is written only when the transfer failed.
_CONTROL = ('stdout', 'stderr', 'onerror')
_ESCAPES = {'n': '\n', 'r': '\r', 't': '\t'}
#: http.client's response version -> curl's ``%{http_version}``.
_HTTP_VERSIONS = {10: '1', 11: '1.1'}


def parse_write_out(fmt):
    """``-w FORMAT`` as ``(kind, value)`` tokens -- ``text``, ``var``,
    ``header`` (``%header{name}``) and ``control`` -- read the way curl reads
    it: ``%%`` is ``%``; ``\\n``, ``\\r``, ``\\t`` are escapes; any other
    ``%x`` or ``\\x``, and an unclosed ``%{``, is written as it stands.
    ``@file`` / ``@-`` read the format from a file / stdin. A variable the
    fallback cannot report raises ``NotImplementedError``, before anything
    is sent."""
    if fmt.startswith('@'):
        source = fmt[1:]
        try:
            data = sys.stdin.buffer.read() if source == '-' else Path(source).read_bytes()
            fmt = data.decode('utf-8', 'surrogateescape')  # any byte comes out as it went in
        except OSError as exc:
            raise EarlyExit(EXIT_READ, 'Failed to open %s' % source)
    tokens, text, i = [], [], 0

    def take(kind, value):
        if text:
            tokens.append(('text', ''.join(text)))
            del text[:]
        tokens.append((kind, value))

    while i < len(fmt):
        char, nxt = fmt[i], fmt[i + 1 : i + 2]
        if char == '\\' and nxt:
            text.append(_ESCAPES.get(nxt, char + nxt))
            i += 2
        elif char != '%' or not nxt:
            text.append(char)
            i += 1
        elif nxt == '%':
            text.append('%')
            i += 2
        else:
            opener = next((o for o in ('{', 'header{', 'output{') if fmt.startswith(o, i + 1)), None)
            start = i + 1 + len(opener or '')
            end = fmt.find('}', start) if opener else -1
            if opener is None:
                text.append(char + nxt)  # not a variable: written as it stands
                i += 2
            elif end < 0:
                text.append(fmt[i:start])  # an unclosed %{ is written, the rest read on
                i = start
            else:
                name, i = fmt[start:end], end + 1
                if opener == 'header{':
                    take('header', name)
                elif opener == '{' and name in _CONTROL:
                    take('control', name)
                elif opener == '{' and name in WRITE_OUT_VARIABLES:
                    take('var', name)
                else:
                    raise NotImplementedError('Unsupported --write-out variable: %%%s%s}' % (opener, name))
    if text:
        tokens.append(('text', ''.join(text)))
    return tokens


def raw_header_text(text):
    """Header text http.client read as latin-1, as the text of its bytes read
    as UTF-8 (a byte that is not UTF-8 survives as a surrogate that writes
    back as itself)."""
    return text.encode('latin-1', 'replace').decode('utf-8', 'surrogateescape')


def _header_json(header_items):
    """curl's ``%{header_json}``: lower-cased names in first-seen order, each
    with all its values, one name per line."""
    grouped = {}
    for name, value in header_items:
        grouped.setdefault(name.lower(), []).append(value)
    return '{%s\n}' % ',\n'.join(
        '%s:%s' % (json.dumps(name, ensure_ascii=False), json.dumps(values, ensure_ascii=False, separators=(',', ':')))
        for name, values in grouped.items()
    )


def write_out_values(args, transfer, exitcode):
    """Every ``WRITE_OUT_VARIABLES`` value for a finished transfer, formatted
    as curl formats it: a 3-digit code (``000`` when nothing answered),
    6-decimal seconds, the LAST request's URL, method and body size."""
    total = time.monotonic() - transfer.started
    sent_url, method, upload = transfer.sent[-1] if transfer.sent else (transfer.target, transfer.method, 0)
    effective = caller_url(sent_url, transfer.plan)
    headers = [(raw_header_text(k), raw_header_text(v)) for k, v in transfer.header_items]
    location = first_header(headers, 'location')
    redirect = urllib.parse.urljoin(effective, location) if location and 300 <= transfer.status < 400 else ''
    # curl reports the whole elapsed time as start-transfer when nothing answered.
    first_byte = total if transfer.first_byte is None else transfer.first_byte - transfer.started

    def since(moment):
        return 0.0 if moment is None else max(moment - transfer.started, 0.0)

    redirects = max(len(transfer.sent) - 1, 0)
    remote = transfer.remote or ('', -1)  # no connection: -1
    local = transfer.local or ('', -1)
    typed = transfer.typed_url
    times = {
        'time_namelookup': since(transfer.t_namelookup),
        'time_connect': since(transfer.t_connect),
        'time_appconnect': since(transfer.t_appconnect),
        'time_pretransfer': since(transfer.t_pretransfer),
        'time_posttransfer': since(transfer.t_posttransfer),
        'time_redirect': since(transfer.final_start) if redirects and transfer.final_start else 0.0,
        'time_queue': 0.0,
    }
    numbers = {
        'remote_port': remote[1],
        'local_port': local[1],
        'num_connects': transfer.connects,
        'num_retries': transfer.retries,
        'speed_download': int(transfer.size_download / total) if total > 0 else 0,
        'speed_upload': int(upload / total) if total > 0 else 0,
        'size_header': transfer.size_header,
        'size_request': transfer.size_request,
        'size_delivered': transfer.size_delivered,
        'http_connect': transfer.connect_status,
        'proxy_used': int(transfer.plan is not None and not transfer.plan.bypasses(sent_url)),
        'conn_id': 0,
        'xfer_id': 0,
    }
    texts = {
        'remote_ip': remote[0],
        'local_ip': local[0],
        'referer': transfer.referer if transfer.referer is not None else args.referer_url(),
    }
    texts.update(_url_parts('url', typed))
    texts.update(_url_parts('urle', effective))
    values = {name: '%.6f' % value for name, value in times.items()}
    values.update({name: str(value) for name, value in numbers.items()})
    values['http_connect'] = '%03d' % transfer.connect_status  # a code, written as http_code is
    values.update({name: value or '' for name, value in texts.items()})
    values.update(
        {
            'content_type': first_header(headers, 'content-type'),
            'errormsg': transfer.errormsg,
            'exitcode': str(exitcode),
            'filename_effective': args.body_target or '',
            'header_json': _header_json(headers),
            'http_code': '%03d' % transfer.status,
            'http_version': _HTTP_VERSIONS.get(transfer.version, '1.1' if transfer.status else '0'),
            'method': method,
            'num_headers': str(len(headers)),
            'num_redirects': str(max(len(transfer.sent) - 1, 0)),
            'redirect_url': redirect,
            'response_code': '%03d' % transfer.status,
            'scheme': _scheme(effective),
            'size_download': str(transfer.size_download),
            'size_upload': str(upload),
            'time_starttransfer': '%.6f' % first_byte,
            'time_total': '%.6f' % total,
            'url': transfer.typed_url,
            'url_effective': effective,
            'urlnum': '0',
        }
    )
    values['json'] = _json(values, times, numbers, texts, transfer, exitcode)
    return values


#: %{json}'s keys whose curl value is a number, or null when empty.
_JSON_INTEGERS = (
    'exitcode',
    'http_code',
    'response_code',
    'num_headers',
    'num_redirects',
    'size_download',
    'size_upload',
    'urlnum',
)


def _scheme(url):
    """%{scheme}: lower case."""
    return url.split('://', 1)[0].lower() if '://' in url else ''


def _url_parts(prefix, url):
    """curl's ``url.*`` / ``urle.*`` parts of ``url`` (``None`` when absent)."""
    try:
        parts = urllib.parse.urlsplit(url or '')
        port = parts.port
    except ValueError:
        parts, port = urllib.parse.urlsplit(''), None
    values = {
        'scheme': parts.scheme or None,
        'user': parts.username,
        'password': parts.password,
        'options': None,
        'host': parts.hostname,
        'path': parts.path or None,
        'port': str(port or {'http': 80, 'https': 443}.get(parts.scheme)) if parts.scheme else None,
        'query': parts.query or None,
        'fragment': parts.fragment or None,
        'zoneid': None,
    }
    return {'%s.%s' % (prefix, key): value for key, value in values.items()}


def _json(values, times, numbers, texts, transfer, exitcode):
    """``%{json}``: every variable as curl writes it -- numbers as numbers,
    times as seconds, absent text as null."""
    out = {}
    for name in WRITE_OUT_VARIABLES - {'json', 'header_json'}:
        if name in times:
            out[name] = round(times[name], 6)
        elif name.startswith('time_'):
            out[name] = float(values[name])
        elif name in numbers:
            out[name] = numbers[name]
        elif name in _JSON_INTEGERS:
            out[name] = int(values[name])
        elif name in texts:
            out[name] = texts[name] if texts[name] not in ('', None) else None
        else:
            out[name] = values[name] if values[name] != '' else None
    out['http_code'] = out['response_code'] = transfer.status
    out['curl_version'] = 'libcurl/%d.%d.%d (curlike fallback)' % CURL_VERSION
    out.update(
        {
            'certs': '',
            'num_certs': 0,
            'ssl_verify_result': 0,
            'proxy_ssl_verify_result': 0,
            'tls_earlydata': 0,
            'ftp_entry_path': None,
        }
    )
    return json.dumps(out, sort_keys=True, separators=(',', ':'))


def _write_stream(name, text):
    """``text`` to stdout or stderr as UTF-8, after whatever is already buffered.
    A stream that cannot be written is skipped, as curl skips it: the exit
    code stays the transfer's."""
    stream = sys.stderr if name == 'stderr' else sys.stdout
    try:
        stream.flush()
        raw = getattr(stream, 'buffer', None)
        if raw is None:
            stream.write(text)
        else:
            raw.write(text.encode('utf-8', 'surrogateescape'))
            raw.flush()
    except OSError:
        if name != 'stderr':
            from .output import discard_stdout

            discard_stdout()


def emit_write_out(tokens, values, header_items, exitcode):
    """Write the parsed ``-w`` format: to stdout until ``%{stderr}`` switches
    it, and nothing after ``%{onerror}`` when the transfer succeeded."""
    stream = 'stdout'
    for kind, value in tokens:
        if kind == 'control':
            if value != 'onerror':
                stream = value
            elif exitcode == 0:
                return
            continue
        if kind == 'header':
            value = first_header([(raw_header_text(k), raw_header_text(v)) for k, v in header_items], value)
        elif kind == 'var':
            value = values[value]
        _write_stream(stream, value)


class WriteOutArgs(Group):
    """``-w``."""

    write_out: Arg[Optional[str], Meta(metavar='FORMAT')] = None
    "Write FORMAT after the transfer (@file / @- read it); see curlike.writeout.WRITE_OUT_VARIABLES"
    ("-w", "--write-out")

    def write_out_tokens(self):
        """The parsed format, or ``None`` without -w. Called before anything
        is sent, so an unsupported variable is refused first."""
        if not self.write_out:
            return None
        return parse_write_out(self.write_out)

    def report(self, tokens, transfer, exitcode):
        """Write the -w output for a finished transfer."""
        if tokens is not None:
            emit_write_out(tokens, write_out_values(self, transfer, exitcode), transfer.header_items, exitcode)
