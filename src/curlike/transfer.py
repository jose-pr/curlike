"""The pure-stdlib (urllib) fallback: assemble the request from the parsed
options, run it -- again, under ``--retry`` -- and answer as curl does:
the same output, the same one-line errors, the same exit codes."""

import gzip
import http.client
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from syshttp import proxy as agent_proxy
from syshttp.retry import retry_after

from . import compat
from .body import FORM_CONTENT_TYPE
from .download import EXIT_FILESIZE
from .connection import MAX_RETRY_SLEEP
from .errors import (
    EXIT_CONNECT,
    EXIT_EMPTY_REPLY,
    EXIT_HTTP,
    EXIT_PARTIAL,
    EXIT_PROTOCOL,
    EXIT_RECV,
    EXIT_REDIRECTS,
    EXIT_RESOLVE,
    EXIT_RESOLVE_PROXY,
    EXIT_SEND,
    EXIT_SSL,
    EXIT_SSL_CONNECT,
    EXIT_TIMEOUT,
    EXIT_WEIRD_REPLY,
    EXIT_WRITE,
    EXIT_BAD_ENCODING,
    EXIT_TOO_LARGE,
    LocalError,
    Retry,
    WriteFailure,
)
from .output import notice_lines
from .request import has_header
from .redirects import CurlRedirectHandler
from .connector import ConnectHTTPHandler, ConnectHTTPSHandler, ProxyAuth, Socks
from .routing import AgentProxyHandler, check_proxy_syntax
from .tls import UnusableContext

#: The shim's own version line (``-V``); real curl answers when it is present.
SHIM_VERSION = 'curl 0.0.0-curlike-shim (python %d.%d, urllib) -- curlike fallback' % sys.version_info[:2]

#: ``time.sleep`` between retries (a seam for tests).
sleep = time.sleep


class Transfer(object):
    """What one attempt did, recorded as it goes so ``-w`` can report it
    however the attempt ends."""

    def __init__(self, typed_url, target, method, plan):
        self.typed_url = typed_url or ''  # as the caller typed it: %{url}
        self.target = target  # the URL requested first
        self.method = method
        self.plan = plan
        self.started = time.monotonic()
        self.first_byte = None  # when the final response's headers arrived
        self.version = None  # http.client's: 10, 11
        self.status = 0
        self.header_items = []
        self.size_download = 0
        self.errormsg = ''
        self.sent = []  # (url, method, body size): every request, redirects included
        # -w's timings (time.monotonic(), None until reached) and addresses.
        self.t_namelookup = self.t_connect = self.t_appconnect = None
        self.t_pretransfer = self.t_posttransfer = None
        self.final_start = None  # when the last request (after any redirects) began
        self.remote = self.local = None  # (address, port) of the last connection
        self.connects = 0
        self.retries = 0
        self.size_request = 0
        self.size_header = 0
        self.size_delivered = 0
        self.connect_status = 0  # the last CONNECT reply's status

    def responded(self, response):
        self.first_byte = time.monotonic()
        self.version = getattr(response, 'version', None)


class RequestLog(urllib.request.BaseHandler):
    """Records every request the opener sends -- the first and each redirect
    hop -- into a :class:`Transfer`, before a prefix gateway rewrites it."""

    handler_order = 80  # before AgentProxyHandler (90)

    def __init__(self, transfer):
        self.transfer = transfer

    def _record(self, req):
        self.transfer.final_start = time.monotonic()
        data = req.data
        size = len(data) if isinstance(data, (bytes, bytearray)) else 0
        self.transfer.sent.append((req.full_url, req.get_method(), size))
        return req

    http_request = _record
    https_request = _record


class RequestTarget(urllib.request.BaseHandler):
    """--request-target: the first request's target as given (``*`` for
    OPTIONS), whatever the URL's path; a redirect's hop uses its own."""

    handler_order = 95  # after AgentProxyHandler (90), which may rewrite the selector

    def __init__(self, target):
        self.target = target
        self.used = False

    def _apply(self, req):
        if not self.used:
            self.used = True
            req.selector = self.target
        return req

    http_request = _apply
    https_request = _apply


class TooSlow(Exception):
    """--speed-limit / --speed-time: the transfer stayed too slow."""


class Pace(object):
    """One body's reading: sleeps to keep --limit-rate, raises
    :class:`TooSlow` when a --speed-time window ends under --speed-limit."""

    def __init__(self, rate=None, low_speed=None):
        self.rate = rate
        self.low_speed = low_speed
        self.start = self.window = time.monotonic()
        self.total = self.window_total = 0

    def __call__(self, count):
        self.total += count
        now = time.monotonic()
        if self.rate:
            ahead = self.total / self.rate - (now - self.start)
            if ahead > 0:
                sleep(ahead)
                now = time.monotonic()
        if self.low_speed:
            limit, seconds = self.low_speed
            if now - self.window >= seconds:
                if (self.total - self.window_total) / (now - self.window) < limit:
                    raise TooSlow(
                        'Operation too slow. Less than %d bytes/sec transferred the last %d seconds' % (limit, seconds)
                    )
                self.window, self.window_total = now, self.total


class PacedBody(object):
    """An upload under --limit-rate: the bytes in pieces, paced; iterable
    again for a redirect that resends it."""

    PIECE = 16384

    def __init__(self, data, rate):
        self.data = data
        self.rate = rate

    def __iter__(self):
        pace = Pace(self.rate)
        for offset in range(0, len(self.data), self.PIECE):
            piece = self.data[offset : offset + self.PIECE]
            yield piece
            pace(len(piece))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """When -L is absent, curl does not follow redirects; surface the 3xx as-is."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def format_response_headers(status, reason, header_items):
    status_line = ('HTTP/1.1 %s %s' % (status, reason or '')).rstrip()
    header_text = ''.join('%s: %s\r\n' % (k, v) for k, v in header_items)
    return ('%s\r\n%s\r\n' % (status_line, header_text)).encode('utf-8')


class EncodingError(Exception):
    """A ``Content-Encoding`` ``--compressed`` cannot undo: curl's 61."""


def decode_body(content, header_items):
    """``--compressed``: the body decoded per ``Content-Encoding`` (gzip,
    deflate -- zlib-wrapped or raw -- each layer in turn; ``identity`` is
    none). An encoding it does not know, or data that does not decode,
    raises :class:`EncodingError`, as curl fails with 61."""
    import zlib

    encodings = []
    for name, value in header_items:
        if name.lower() == 'content-encoding':
            encodings += [e.strip().lower() for e in value.split(',') if e.strip()]
    for encoding in reversed(encodings):  # the last applied is undone first
        try:
            if encoding in ('gzip', 'x-gzip'):
                content = gzip.decompress(content)
            elif encoding == 'deflate':
                try:
                    content = zlib.decompress(content)
                except zlib.error:
                    content = zlib.decompress(content, -zlib.MAX_WBITS)
            elif encoding != 'identity':
                raise EncodingError('Unrecognized content encoding type')
        except (OSError, EOFError, zlib.error) as exc:
            raise EncodingError('Error while processing content unencoding: %s' % exc)
    return content


#: curl's limits on a response's headers: one header's size (100 KB, beyond
#: which it fails with 100); http.client's own -- 100 headers, 64 KB a line --
#: are lifted to it for the transfer, since curl takes any number of headers.
MAX_HEADER_LINE = 100 * 1024
MAX_HEADERS = 1 << 20


def _header_defect(response):
    """curl's 8 for a header line with no colon: http.client takes it as the
    end of the headers (the rest becomes a defect) instead of refusing it."""
    import email.errors

    message = getattr(response, 'headers', None)
    return any(
        isinstance(d, email.errors.MissingHeaderBodySeparatorDefect) for d in getattr(message, 'defects', ()) or ()
    )


def build_opener(args, plan, context, transfer, removed):
    """The opener for one attempt. It always carries an EMPTY ProxyHandler:
    urllib's own would re-read the global vars (never <P>_PROXY), re-check
    NO_PROXY and, on Windows, the registry's bypass list -- and silently go
    direct where we decided to proxy. ``AgentProxyHandler`` applies the plan
    per hop instead."""
    args.connection.connect_replies = []
    args.connection.transfer = transfer
    handlers = args.connection_handlers(context) or [
        ConnectHTTPHandler(args.connection),
        ConnectHTTPSHandler(args.connection, context),
    ]
    handlers.append(urllib.request.ProxyHandler({}))
    if plan is not None:
        proxy_auth = _proxy_auth(args, plan, transfer.target)
        handlers.append(
            AgentProxyHandler(
                plan,
                tunnel_http=args.proxytunnel,
                headers=args.proxy_headers(),
                socks=args.socks,
                preproxy=args.socks_pre,
                proxy_tls=args.proxy_tls(),
                proxy_auth=proxy_auth,
            )
        )
        if proxy_auth is not None:
            # Plain proxying: urllib's handlers answer the 407, once.
            passwords = _ProxyPassword(proxy_auth.user, proxy_auth.password)
            handlers.append(_OnceProxyDigest(passwords))
            if proxy_auth.anyauth:
                handlers.append(_OnceProxyBasic(passwords))
    if args.request_target:
        handlers.append(RequestTarget(args.request_target))
    handlers.append(RequestLog(transfer))
    creds = args.credentials() if args.digest or args.anyauth else None
    if creds is not None:
        # --digest / --anyauth: urllib answers the server's challenge (Digest
        # before Basic); nothing is sent up front.
        passwords = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        passwords.add_password(None, transfer.target, creds[0], creds[1])
        handlers.append(urllib.request.HTTPDigestAuthHandler(passwords))
        if args.anyauth:
            handlers.append(urllib.request.HTTPBasicAuthHandler(passwords))
    if args.location:
        redirects = CurlRedirectHandler(args, plan)  # curl's rules for what each hop carries
        if args.max_redirs is not None and args.max_redirs >= 0:
            # urllib has two limits: distinct URLs (max_redirections) and
            # repeats of one URL (max_repeats, 4); curl's --max-redirs is both.
            redirects.max_redirections = args.max_redirs
            redirects.max_repeats = args.max_redirs
        handlers.append(redirects)
    else:
        handlers.append(NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    for name in removed:
        # urllib adds these itself; a `-H 'Name:'` removal must reach the wire.
        opener.addheaders = [(k, v) for k, v in opener.addheaders if k.lower() != name]
    return opener


def fail(args, transfer, code, message):
    """curl's one line, ``curl: (N) message`` (unless -s without -S); the
    message is ``%{errormsg}``. Returns ``code``."""
    transfer.errormsg = message
    if args.should_print_error():
        print('curl: (%d) %s' % (code, message), file=sys.stderr)
    return code


def _hop_url(transfer):
    """The URL of the request that failed: the last hop sent."""
    return transfer.sent[-1][0] if transfer.sent else transfer.target


def _via_proxy(transfer):
    """Whether the failed hop went to the proxy (or prefix gateway) rather
    than straight to the origin."""
    plan = transfer.plan
    return plan is not None and not plan.bypasses(_hop_url(transfer))


def _host_port(url):
    parts = urllib.parse.urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    return parts.hostname or '', port or (443 if parts.scheme == 'https' else 80)


def _elapsed_ms(transfer):
    return int((time.monotonic() - transfer.started) * 1000)


#: http.client's words for a CONNECT the proxy answered with a status.
_TUNNEL_FAILED = re.compile(r'Tunnel connection failed: (\d{3})')


def transport_error(args, reason, transfer, may_retry):
    """A failure before any response -- connecting, the proxy's CONNECT,
    the TLS handshake, sending: curl's exit code -- 5/6 could not resolve
    the proxy/host, 7 could not connect, 28 timed out, 35 a failed TLS
    handshake, 60 a certificate that does not verify, 56 a CONNECT the proxy
    refused (22 under -f) or dropped -- or :class:`Retry` when ``--retry``
    covers it."""
    text = str(reason)
    via_proxy = _via_proxy(transfer)
    tunnel = _TUNNEL_FAILED.search(text) if isinstance(reason, OSError) else None
    if isinstance(reason, socket.gaierror):
        if via_proxy:
            proxy_host = _host_port(transfer.plan.proxy)[0]
            code, message = EXIT_RESOLVE_PROXY, 'Could not resolve proxy: %s' % proxy_host
            if (
                transfer.plan.proxy.split('://', 1)[0].lower().startswith('socks')
                and compat.socks_proxy_unresolved_code() == EXIT_RESOLVE
            ):
                code, message = EXIT_RESOLVE, 'Could not resolve host: %s' % proxy_host  # before curl 8.14
        else:
            code, message = EXIT_RESOLVE, 'Could not resolve host: %s' % _host_port(_hop_url(transfer))[0]
    elif isinstance(reason, (socket.timeout, TimeoutError)) or 'timed out' in text:
        code, message = EXIT_TIMEOUT, 'Operation timed out after %d milliseconds with 0 bytes received' % (
            _elapsed_ms(transfer)
        )
    elif isinstance(reason, ssl.SSLError) and 'CERTIFICATE_REQUIRED' in str(reason).upper():
        # TLS 1.3 sends "certificate required" after the handshake, on the
        # first read: curl's receive error.
        code, message = EXIT_RECV, 'Recv failure: %s' % text
    elif isinstance(reason, ssl.SSLCertVerificationError):
        code, message = EXIT_SSL, 'SSL certificate problem: %s' % text
    elif isinstance(reason, ssl.SSLError):
        code, message = EXIT_SSL_CONNECT, 'SSL connect error: %s' % text
    elif tunnel:
        # The proxy answered the CONNECT with a status: 56 before curl 8.20,
        # 7 since (compat); under -f the status as an HTTP error, 22.
        status = int(tunnel.group(1))
        if args.fails_on(status):
            code, message = EXIT_HTTP, 'The requested URL returned error: %d' % status
        else:
            code, message = compat.connect_refused_code(), 'CONNECT tunnel failed, response %d' % status
    elif (
        via_proxy
        and isinstance(reason, (http.client.RemoteDisconnected, ConnectionResetError))
        and (urllib.parse.urlsplit(_hop_url(transfer)).scheme == 'https' or args.proxytunnel)
    ):
        code, message = EXIT_RECV, 'Proxy CONNECT aborted'
    elif isinstance(reason, (ConnectionRefusedError, socket.timeout)) or not isinstance(reason, ConnectionError):
        host, port = _host_port(transfer.plan.proxy if via_proxy else _hop_url(transfer))
        code, message = EXIT_CONNECT, 'Failed to connect to %s port %d after %d ms: %s' % (
            host,
            port,
            _elapsed_ms(transfer),
            'Could not connect to server' if isinstance(reason, ConnectionRefusedError) else text,
        )
    elif isinstance(reason, ConnectionResetError):
        code, message = EXIT_RECV, 'Recv failure: Connection reset by peer'
    else:
        code, message = EXIT_SEND, 'Send failure: %s' % text
    why = args.retry_reason_for_error(code, reason)
    if may_retry and why:
        raise Retry(why)
    return fail(args, transfer, code, message)


def reply_error(args, exc, transfer, may_retry):
    """A failure reading the response's status line and headers: 52 nothing
    came back, 1 not HTTP at all (curl's "HTTP/0.9") or an unusable status
    line, 8 an unreadable reply, 56 the connection broke, 28 timed out."""
    if isinstance(exc, http.client.RemoteDisconnected):
        code, message = EXIT_EMPTY_REPLY, 'Empty reply from server'
    elif isinstance(exc, http.client.LineTooLong) or str(exc).startswith('got more than'):
        code, message = compat.too_large()  # 100, or 27 before curl 8.6
    elif isinstance(exc, http.client.BadStatusLine):
        line = str(exc.args[0]) if exc.args else ''
        code = EXIT_PROTOCOL
        message = (
            'Unsupported HTTP/1 subversion in response'
            if line.startswith('HTTP/')
            else 'Received HTTP/0.9 when not allowed'
        )
    elif isinstance(exc, http.client.HTTPException):
        code, message = EXIT_WEIRD_REPLY, 'Weird server reply: %s' % exc
    elif isinstance(exc, (socket.timeout, TimeoutError)):
        return transport_error(args, exc, transfer, may_retry)
    elif isinstance(exc, ConnectionResetError):
        code, message = EXIT_RECV, 'Recv failure: Connection reset by peer'
    else:
        code, message = EXIT_RECV, 'Recv failure: %s' % exc
    why = args.retry_reason_for_error(code, exc)
    if may_retry and why:
        raise Retry(why)
    return fail(args, transfer, code, message)


def _bad_chunk(exc):
    """Whether an ``IncompleteRead`` from a chunked body is a malformed chunk
    size (curl's 56) rather than the connection closing early (18):
    http.client reports both from a ``ValueError`` parsing the size line, an
    empty line being the closed connection."""
    seen = exc
    while seen is not None:
        if isinstance(seen, ValueError):
            return not str(seen).endswith("b''")
        seen = seen.__cause__ or seen.__context__
    return False


def read_body(response, pace=None, ignore_length=False):
    """``(body, error)``: the body as far as it came, and the exception that
    cut it short -- an ``IncompleteRead`` for a body shorter than its
    Content-Length or a broken chunked encoding, else the socket's error --
    or ``None``. Read in pieces, so a reset keeps what arrived (curl writes
    it before failing)."""
    raw = response.fp if isinstance(response, urllib.error.HTTPError) else response
    if raw is None:
        return b'', None
    if ignore_length and getattr(raw, 'length', None) is not None:
        raw.length = None  # --ignore-content-length: read until the server closes
    parts = []
    # read1: what has arrived, without waiting for a full buffer -- a plain
    # read() loses the bytes it buffered when the connection resets.
    read = getattr(raw, 'read1', raw.read)
    try:
        while True:
            chunk = read(65536)
            if not chunk:
                break
            parts.append(chunk)
            if pace is not None:
                pace(len(chunk))
    except TooSlow as exc:
        return b''.join(parts), exc
    except http.client.IncompleteRead as exc:
        parts.append(exc.partial or b'')
        return b''.join(parts), exc
    except (OSError, http.client.HTTPException) as exc:
        return b''.join(parts), exc
    missing = getattr(raw, 'length', None)
    if missing:
        # read(amt) returns b'' at EOF however much Content-Length promised.
        return b''.join(parts), http.client.IncompleteRead(b'', missing)
    return b''.join(parts), None


def body_error(args, exc, transfer, chunked):
    """curl's exit for a body cut short: 18 a body shorter than promised,
    56 a malformed chunk or a broken connection, 28 timed out or too slow."""
    if isinstance(exc, TooSlow):
        return fail(args, transfer, EXIT_TIMEOUT, str(exc))
    low = args.low_speed()
    if low and isinstance(exc, (socket.timeout, TimeoutError)):
        return fail(
            args,
            transfer,
            EXIT_TIMEOUT,
            'Operation too slow. Less than %d bytes/sec transferred the last %d seconds' % low,
        )
    if isinstance(exc, http.client.IncompleteRead):
        if chunked and _bad_chunk(exc):
            return fail(args, transfer, EXIT_RECV, 'chunk hex-length char not a hex digit')
        if chunked:
            return fail(args, transfer, EXIT_PARTIAL, 'transfer closed with outstanding read data remaining')
        return fail(args, transfer, EXIT_PARTIAL, 'end of response with %d bytes missing' % (exc.expected or 0))
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return fail(
            args,
            transfer,
            EXIT_TIMEOUT,
            'Operation timed out after %d milliseconds with %d bytes received'
            % (_elapsed_ms(transfer), transfer.size_download),
        )
    if isinstance(exc, ConnectionResetError):
        return fail(args, transfer, EXIT_RECV, 'Recv failure: Connection reset by peer')
    return fail(args, transfer, EXIT_RECV, 'Recv failure: %s' % exc)


def exchange(args, opener, req, timeout, url, transfer, may_retry=False):
    """Send ``req``, write what curl writes and return curl's exit code;
    ``transfer`` records the outcome for ``-w``. Raises :class:`Retry`
    instead of answering when ``may_retry`` and the failure is transient.

    A failure is classed by where it happened, as curl's codes are: urllib
    wraps what goes wrong while connecting and sending in ``URLError``
    (:func:`transport_error`); the status line and headers raise bare
    (:func:`reply_error`); the body is read last (:func:`body_error`)."""
    transfer.started = time.monotonic()
    try:
        resp = opener.open(req, timeout=timeout)
        transfer.responded(resp)
        status = resp.getcode()
    except urllib.error.HTTPError as exc:
        # An HTTP status is a response, not a transport error: curl prints it
        # and exits 0 -- unless -f, which is exit 22.
        resp = exc
        transfer.responded(getattr(exc, 'fp', None))
        status = exc.code
        if args.location and 'infinite loop' in str(getattr(exc, 'reason', '') or ''):
            # urllib's redirect handler gave up (--max-redirs, or a loop):
            # curl's "(47) Maximum (N) redirects followed".
            transfer.status = status
            transfer.header_items = list(exc.headers.items()) if exc.headers else []
            if may_retry and args.retry_all_errors:
                raise Retry(' (retrying all errors)')
            limit = (
                args.max_redirs if args.max_redirs is not None else urllib.request.HTTPRedirectHandler.max_redirections
            )
            return fail(args, transfer, EXIT_REDIRECTS, 'Maximum (%d) redirects followed' % limit)
    except NotImplementedError:
        raise
    except LocalError as exc:
        # A TLS file the handshake needed and could not use (77 / 58).
        return fail(args, transfer, exc.code, str(exc))
    except urllib.error.URLError as exc:
        return transport_error(args, exc.reason, transfer, may_retry)
    except (OSError, http.client.HTTPException) as exc:
        return reply_error(args, exc, transfer, may_retry)
    reason = getattr(resp, 'reason', '') or ''
    header_items = list(resp.headers.items()) if resp.headers else []
    if _header_defect(resp):
        resp.close()
        return fail(args, transfer, EXIT_WEIRD_REPLY, 'Header without colon')
    transfer.status, transfer.header_items = status, header_items
    if not args.head and args.too_big(header_items):
        resp.close()
        return fail(args, transfer, EXIT_FILESIZE, 'Maximum file size exceeded')
    pace = Pace(args.rate(), args.low_speed()) if args.limit_rate or args.low_speed() else None
    content, cut = (b'', None) if args.head else read_body(resp, pace, args.ignore_content_length)
    transfer.size_download = len(content)  # as it came over the wire, before --compressed
    if cut is None and args.too_big(header_items, len(content)):
        return fail(args, transfer, EXIT_FILESIZE, 'Maximum file size exceeded')
    why = args.retry_reason_for_status(status)
    if may_retry and why:
        raise Retry(why, after=retry_after(header_items))

    if args.verbose and not args.silent:
        print('Response status: %s' % status, file=sys.stderr)
    args.save_cookies(url, header_items)
    if args.compressed and not args.head and cut is None:
        try:
            content = decode_body(content, header_items)
        except EncodingError as exc:
            return fail(args, transfer, EXIT_BAD_ENCODING, str(exc))
    header_bytes = format_response_headers(status, reason, header_items)
    transfer.size_header = len(header_bytes) + sum(len(r) for r in args.connection.connect_replies)
    if not args.suppress_connect_headers:
        # curl shows the proxy's CONNECT reply before the response's own headers.
        header_bytes = b''.join(args.connection.connect_replies) + header_bytes
    try:
        outcome = args.download_outcome(status, header_items)
    except LocalError as exc:
        return fail(args, transfer, exc.code, str(exc))
    try:
        args.write_header_dump(header_bytes)
        if outcome == 'skip':
            # A 304, an unmet -z, a finished resume: no body, no file.
            transfer.size_download = 0
            return 0
        if args.fails_on(status):
            # -f: no body; --fail-with-body: the body, then the same exit 22.
            if args.fail_with_body:
                args.emit_output(header_bytes, content)
            else:
                transfer.size_download = 0
            return fail(args, transfer, EXIT_HTTP, 'The requested URL returned error: %s' % status)
        args.emit_output(header_bytes, content)
        transfer.size_delivered = len(content)
        if cut is not None:
            # What arrived is written, as curl writes it, then the failure.
            raw = resp.fp if isinstance(resp, urllib.error.HTTPError) else resp
            return body_error(args, cut, transfer, getattr(raw, 'chunked', False))
        args.finish_download(header_items)
    except WriteFailure as exc:
        # -o / -D not writable, or stdout closed under us: curl's 23, in the
        # words curl has for where the write failed.
        transfer.errormsg = exc.message
        if exc.notice and (not args.silent or (args.show_error and compat.shows_notices_when_silent())):
            print('\n'.join(notice_lines(exc.notice)), file=sys.stderr)
        if exc.coded and args.should_print_error():
            print('curl: (%d) %s' % (EXIT_WRITE, exc.message), file=sys.stderr)
        return EXIT_WRITE
    except OSError as exc:
        # What follows the body (-R, --etag-save) could not be written.
        return fail(args, transfer, EXIT_WRITE, 'Failure writing output to destination: %s' % exc)
    return 0


class _ProxyPassword(urllib.request.HTTPPasswordMgr):
    """The proxy's credentials for any realm and URL: urllib's proxy Digest
    looks them up by the TARGET URL, which no proxy entry would match."""

    def __init__(self, user, password):
        urllib.request.HTTPPasswordMgr.__init__(self)
        self.credentials = (user, password)

    def find_user_password(self, realm, authuri):
        return self.credentials


class _OnceProxyDigest(urllib.request.ProxyDigestAuthHandler):
    """urllib's proxy Digest, answering a 407 once as curl does (urllib
    itself retries five times, then reports a 401 of its own)."""

    def http_error_407(self, req, fp, code, msg, headers):
        if req.has_header('Proxy-authorization'):
            return None
        return urllib.request.ProxyDigestAuthHandler.http_error_407(self, req, fp, code, msg, headers)


class _OnceProxyBasic(urllib.request.ProxyBasicAuthHandler):
    def http_error_407(self, req, fp, code, msg, headers):
        offered = headers.get_all('Proxy-Authenticate') or []
        if req.has_header('Proxy-authorization') or not any(c.strip().lower().startswith('basic') for c in offered):
            return None  # answered already, or Basic is not offered (urllib would raise)
        return urllib.request.ProxyBasicAuthHandler.http_error_407(self, req, fp, code, msg, headers)


def _proxy_auth(args, plan, url):
    """A :class:`ProxyAuth` for --proxy-digest / --proxy-anyauth with
    credentials (-U, else the proxy URL's -- the one chosen for ``url``), or
    ``None``."""
    if not (args.proxy_digest or args.proxy_anyauth) or plan is None or plan.endpoint is not None:
        return None
    if args.proxy_user:
        user, _, password = args.proxy_user.partition(':')
    else:
        found = agent_proxy.userinfo(args.effective_proxy() or agent_proxy.proxy_url(url=url))
        if not found:
            return None
        user, password = found
    return ProxyAuth(user, password, anyauth=args.proxy_anyauth)


def _socks_for(args, plan, proxy, url):
    """``(socks proxy, socks pre-proxy)`` for the transfer to ``url``: the
    plan's proxy when it is SOCKS (credentials from -U, else its URL's
    userinfo), and --preproxy in front of an HTTP proxy."""
    if plan is None:
        return None, None
    user = password = None
    if args.proxy_user:
        user, _, password = args.proxy_user.partition(':')
    raw = proxy or agent_proxy.proxy_url(url=url) or ''
    if Socks.is_socks(raw):
        return Socks(raw, user, password), None
    pre = Socks(args.preproxy) if args.preproxy else None
    if pre is not None and not Socks.is_socks(args.preproxy):
        raise NotImplementedError('--preproxy must be a SOCKS proxy (socks4://, socks4a://, socks5://, socks5h://)')
    return None, pre


def _count(number, one, many):
    return '%d %s' % (number, one if number == 1 else many)


def run(args):
    """One curl invocation from the parsed options (``options.CurlCmd``):
    urllib underneath, curl's output, errors and exit codes on top."""
    if args.show_version:
        print(SHIM_VERSION)
        return 0
    args.check()
    compat.check()  # an unreadable <P>_CURL_COMPAT: exit 2
    tokens = args.write_out_tokens()  # an unsupported -w variable fails before anything is sent
    args.check_files()  # --cacert / --netrc-file naming nothing: curl's 2, before anything else
    typed = args.url or args.url_positional
    body = args.build_body()

    transfer = Transfer(typed, typed or '', 'GET', None)
    try:
        url = args.target_url()  # curl's 1 / 3 for a URL it cannot use, -w still written
        transfer = Transfer(typed, url, 'GET', None)
        form = args.build_form()
        headers, removed = args.request_headers()  # may read a netrc: exit 26
        url, upload = args.build_upload(url)
        if args.get:
            url, body = args.query_url(url, body), None
        if form is not None:
            body, form_type = form
            if not has_header(headers, 'content-type'):
                headers['Content-Type'] = form_type
        elif body is not None and 'content-type' not in removed and not has_header(headers, 'content-type'):
            headers['Content-Type'] = FORM_CONTENT_TYPE
        data = upload if upload is not None else body
        method = args.request_method(data is not None, upload is not None)
        if method == 'HEAD':
            data = None
        cookie_header = args.cookie_header(url)
        if cookie_header and not has_header(headers, 'cookie'):
            headers['Cookie'] = cookie_header
        proxy = args.effective_proxy()
        if not proxy and args.preproxy and Socks.is_socks(args.preproxy):
            proxy = args.preproxy  # a pre-proxy with no proxy after it is the proxy
        check_proxy_syntax(proxy or agent_proxy.proxy_url(url=url))  # curl's 5
        # Decided for this URL (the system's answer may differ per URL); its
        # redirect hops keep the decision, as with curl's own --proxy.
        plan = agent_proxy.plan(proxy=proxy, noproxy=args.noproxy, proxy_user=args.proxy_user, url=url)
        args.socks, args.socks_pre = _socks_for(args, plan, proxy, url)
        transfer = Transfer(typed, url, method, plan)
        args.output_target(url)
        if args.prepare_download(headers):
            return 0  # --skip-existing: the file is there
        args.connection = args.connector()  # --interface / --local-port / --pinnedpubkey
        args.dns = args.dns_override()  # --dns-servers / --dns-*-addr / --dns-interface / --doh-url
        if args.limit_rate:
            limited = args.rate()
            if data is not None and limited:
                headers.setdefault('Content-Length', str(len(data)))
                data = PacedBody(data, limited)
        try:
            context = args.ssl_context()
        except LocalError as exc:
            # curl loads these files during the TLS handshake: an http://
            # transfer never notices, and an https one fails after connecting.
            context = UnusableContext(exc)
    except LocalError as exc:
        rc = fail(args, transfer, exc.code, str(exc))
        args.report(tokens, transfer, rc)
        return rc

    if args.verbose and not args.silent:
        print('Request: %s %s' % (method, url), file=sys.stderr)
        if data:
            print('Data:', data.decode('utf-8', errors='replace'), file=sys.stderr)
        print('Headers:', headers, file=sys.stderr)
        if plan is not None and not plan.bypasses(url):
            # The URL only, never the credential: this line ends up in logs.
            print(
                'Proxy%s: %s%s'
                % (
                    ' (prefix %s)' % plan.endpoint if plan.endpoint else '',
                    agent_proxy.redact(plan.proxy),
                    ' (with %s)' % plan.auth_header if plan.authorization else '',
                ),
                file=sys.stderr,
            )

    timeout = args.request_timeout()
    limits = http.client._MAXLINE, http.client._MAXHEADERS
    http.client._MAXLINE, http.client._MAXHEADERS = MAX_HEADER_LINE, MAX_HEADERS
    try:
        with args.resolution():
            rc, transfer = _attempts(args, typed, url, method, plan, context, removed, data, headers, timeout)
    finally:
        http.client._MAXLINE, http.client._MAXHEADERS = limits
    args.cleanup_after(rc)
    args.report(tokens, transfer, rc)
    return rc


def _attempts(args, typed, url, method, plan, context, removed, data, headers, timeout):
    """The transfer, again after each transient failure ``--retry`` covers:
    ``(exit code, the last attempt's Transfer)``."""
    retries = max(args.retry or 0, 0)
    first = time.monotonic()
    backoff = 1.0
    while True:
        in_time = not args.retry_max_time or time.monotonic() - first < args.retry_max_time
        transfer = Transfer(typed, url, method, plan)
        transfer.retries = max(args.retry or 0, 0) - retries
        opener = build_opener(args, plan, context, transfer, removed)
        req = urllib.request.Request(url, data=data, headers=dict(headers), method=method)
        try:
            rc = exchange(args, opener, req, timeout, url, transfer, may_retry=retries > 0 and in_time)
            break
        except Retry as retry:
            wait = args.retry_wait(backoff, retry.after)
            if args.retry_max_time:
                wait = max(0.0, min(wait, args.retry_max_time - (time.monotonic() - first)))
            if not args.silent:
                print(
                    'Warning: Problem %s. Will retry in %s. %s left.'
                    % (retry.what, _count(int(round(wait)), 'second', 'seconds'), _count(retries, 'retry', 'retries')),
                    file=sys.stderr,
                )
            sleep(wait)
            retries -= 1
            backoff = min(backoff * 2, MAX_RETRY_SLEEP)
    return rc, transfer
