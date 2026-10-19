"""The pure-stdlib (urllib) fallback: assemble the request from the parsed
options, run it -- again, under ``--retry`` -- and answer as curl does:
the same output, the same one-line errors, the same exit codes."""

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

from .body import FORM_CONTENT_TYPE
from .download import EXIT_FILESIZE
from .connection import MAX_RETRY_SLEEP
from .delivery import BodyReader, Decoder, EncodingError, TooSlow
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
from .response import ResponseRefused
from .redirects import REDIRECT_CODES, Follow, max_redirs, origin
from .challenge import ChallengeAuth, ChallengeHandler
from .connector import ConnectHTTPHandler, ConnectHTTPSHandler, Socks
from .routing import AgentProxyHandler, caller_url, check_proxy_syntax, configured_text, userinfo
from .routing import plan as proxy_plan
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
        self.hop_heads = []  # (CONNECT replies, response head) of each redirect hop before the last
        self.referer = None  # the last hop's Referer when ``-e URL;auto`` set it

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
        size = len(data) if data is not None else 0
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

    def __len__(self):
        return len(self.data)

    def _pieces(self):
        if isinstance(self.data, (bytes, bytearray)):
            for offset in range(0, len(self.data), self.PIECE):
                yield self.data[offset : offset + self.PIECE]
        else:
            for piece in self.data:
                for offset in range(0, len(piece), self.PIECE):
                    yield piece[offset : offset + self.PIECE]

    def __iter__(self):
        pace = Pace(self.rate)
        for piece in self._pieces():
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
    handlers = [ConnectHTTPHandler(args.connection), ConnectHTTPSHandler(args.connection, context)]
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
            handlers.append(ChallengeHandler(proxy_auth, proxy=True))  # plain proxying: a 407, answered once
    if args.request_target:
        handlers.append(RequestTarget(args.request_target))
    handlers.append(RequestLog(transfer))
    creds = args.credentials() if args.digest or args.anyauth else None
    if creds is not None:
        # --digest / --anyauth: the server's 401 is answered once; nothing is
        # sent up front. The credential goes only where -L would send it.
        handlers.append(
            ChallengeHandler(
                ChallengeAuth(creds[0], creds[1], anyauth=args.anyauth),
                allowed=lambda req: args.location_trusted or _first_origin(transfer),
            )
        )
    handlers.append(NoRedirect())  # a 3xx is a response; ``follow`` decides
    # Only what a transfer needs: urllib's default opener would also fetch
    # ftp:// and file:// URLs and answer data: URLs.
    opener = urllib.request.OpenerDirector()
    for default in (
        urllib.request.UnknownHandler,
        urllib.request.HTTPDefaultErrorHandler,
        urllib.request.HTTPErrorProcessor,
        urllib.request.HTTPHandler,
        urllib.request.HTTPSHandler,
    ):
        if not any(isinstance(handler, default) for handler in handlers):
            handlers.append(default())
    for handler in handlers:
        opener.add_handler(handler)
    for name in removed:
        # urllib adds these itself; a `-H 'Name:'` removal must reach the wire.
        opener.addheaders = [(k, v) for k, v in opener.addheaders if k.lower() != name]
    return opener


def say(args, transfer, code, message):
    """curl's one line, ``curl: (N) message`` (unless -s without -S); the
    message is ``%{errormsg}``. Every attempt of a retried transfer has its own."""
    transfer.errormsg = message
    if args.should_print_error():
        print('curl: (%d) %s' % (code, message), file=sys.stderr)


def fail(args, transfer, code, message):
    """:func:`say`, and ``code`` back."""
    say(args, transfer, code, message)
    return code


def _hop_url(transfer):
    """The URL of the request that failed: the last hop sent."""
    return transfer.sent[-1][0] if transfer.sent else transfer.target


def _via_proxy(transfer):
    """Whether the failed hop went to the proxy (or prefix gateway) rather
    than straight to the origin."""
    plan = transfer.plan
    return plan is not None and not plan.bypasses(_hop_url(transfer))


def _first_origin(transfer):
    """Whether the request being sent is to the first request's origin."""
    sent = transfer.sent[-1][0] if transfer.sent else transfer.target
    return origin(caller_url(sent, transfer.plan)) == origin(caller_url(transfer.target, transfer.plan))


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
        # The proxy answered the CONNECT with a status: exit 7; under -f the
        # status as an HTTP error, 22.
        status = int(tunnel.group(1))
        if args.fails_on(status):
            code, message = EXIT_HTTP, 'The requested URL returned error: %d' % status
        else:
            code, message = EXIT_CONNECT, 'CONNECT tunnel failed, response %d' % status
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
        say(args, transfer, code, message)
        raise Retry(why)
    return fail(args, transfer, code, message)


def reply_error(args, exc, transfer, may_retry):
    """A failure reading the response's status line and headers: 52 nothing
    came back, 1 not HTTP at all (curl's "HTTP/0.9") or an unusable status
    line, 8 an unreadable reply, 56 the connection broke, 28 timed out."""
    if isinstance(exc, ResponseRefused):
        code, message = exc.code, exc.text
    elif isinstance(exc, http.client.RemoteDisconnected):
        code, message = EXIT_EMPTY_REPLY, 'Empty reply from server'
    elif isinstance(exc, http.client.LineTooLong):
        code, message = 100, 'A value or data field grew larger than allowed'
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
        say(args, transfer, code, message)
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


def response_socket(response):
    """The socket a response is read from, or ``None``."""
    raw = response.fp if isinstance(response, urllib.error.HTTPError) else response
    return getattr(getattr(getattr(raw, 'fp', None), 'raw', None), '_sock', None)


def body_error(args, exc, transfer, chunked, may_retry=False):
    """curl's exit for a body cut short: 18 a body shorter than promised,
    56 a malformed chunk or a broken connection, 28 timed out or too slow;
    :class:`Retry` when ``--retry`` covers it."""
    code, message = body_failure(args, exc, transfer, chunked)
    why = args.retry_reason_for_error(code, exc)
    if may_retry and why:
        say(args, transfer, code, message)
        raise Retry(why)
    return fail(args, transfer, code, message)


def body_failure(args, exc, transfer, chunked):
    """``(exit code, message)`` for a body cut short by ``exc``."""
    if isinstance(exc, TooSlow):
        return EXIT_TIMEOUT, str(exc)
    low = args.low_speed()
    if low and isinstance(exc, (socket.timeout, TimeoutError)):
        return EXIT_TIMEOUT, 'Operation too slow. Less than %d bytes/sec transferred the last %d seconds' % low
    if isinstance(exc, http.client.IncompleteRead):
        if chunked and _bad_chunk(exc):
            return EXIT_RECV, 'chunk hex-length char not a hex digit'
        if chunked:
            return EXIT_PARTIAL, 'transfer closed with outstanding read data remaining'
        return EXIT_PARTIAL, 'end of response with %d bytes missing' % (exc.expected or 0)
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return EXIT_TIMEOUT, 'Operation timed out after %d milliseconds with %d bytes received' % (
            _elapsed_ms(transfer),
            transfer.size_download,
        )
    if isinstance(exc, ConnectionResetError):
        return EXIT_RECV, 'Recv failure: Connection reset by peer'
    return EXIT_RECV, 'Recv failure: %s' % exc


class TooManyRedirects(Exception):
    """``-L`` met a redirect past ``--max-redirs``; ``response`` is that 3xx."""

    def __init__(self, response, status):
        Exception.__init__(self, status)
        self.response = response
        self.status = status


def follow(args, opener, req, transfer):
    """``(response, status)`` of the last hop: ``req`` sent, and under ``-L``
    each redirect it meets sent in turn (curl's rules, :mod:`redirects`).
    The earlier hops' heads are kept on ``transfer`` for ``-D`` / ``-i``."""
    following = Follow(args, transfer.plan) if args.location or args.location_trusted else None
    limit = max_redirs(args)
    seen = 0
    consumed = 0
    while True:
        try:
            resp = opener.open(req, timeout=args.connect_limit())
            status = resp.getcode()
            transfer.responded(resp)
        except urllib.error.HTTPError as exc:
            # An HTTP status is a response, not a transport error: curl
            # prints it and exits 0 -- unless -f, which is exit 22.
            resp, status = exc, exc.code
            transfer.responded(getattr(exc, 'fp', None))
        previous = transfer.sent[-1][0] if transfer.sent else transfer.target
        args.learn_cookies(previous, list(resp.headers.items()) if resp.headers else [])
        location = resp.headers.get('Location') if resp.headers else None
        if following is None or status not in REDIRECT_CODES or not location:
            return resp, status
        if limit is not None and seen >= limit:
            raise TooManyRedirects(resp, status)
        replies = args.connection.connect_replies
        head = format_response_headers(status, getattr(resp, 'reason', ''), list(resp.headers.items()))
        transfer.hop_heads.append((b''.join(replies[consumed:]), head))
        consumed = len(replies)
        resp.close()
        req = following.next_request(req, previous, status, location)
        transfer.referer = following.referer
        seen += 1


def exchange(args, opener, req, url, transfer, may_retry=False):
    """Send ``req``, write what curl writes and return curl's exit code;
    ``transfer`` records the outcome for ``-w``. Raises :class:`Retry`
    instead of answering when ``may_retry`` and the failure is transient.

    A failure is classed by where it happened, as curl's codes are: urllib
    wraps what goes wrong while connecting and sending in ``URLError``
    (:func:`transport_error`); the status line and headers raise bare
    (:func:`reply_error`); the body is read last (:func:`body_error`)."""
    transfer.started = time.monotonic()
    try:
        resp, status = follow(args, opener, req, transfer)
    except TooManyRedirects as exc:
        # curl's "(47) Maximum (N) redirects followed"; the 3xx it stopped at
        # is the response -w reports.
        transfer.status = exc.status
        transfer.header_items = list(exc.response.headers.items()) if exc.response.headers else []
        exc.response.close()
        if may_retry and args.retry_all_errors:
            raise Retry('(retrying all errors)')
        return fail(args, transfer, EXIT_REDIRECTS, 'Maximum (%d) redirects followed' % max_redirs(args))
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
    why = args.retry_reason_for_status(status)
    if may_retry and why:
        after = retry_after(header_items)
        if args.retry_after_too_late(after):
            if not args.silent:
                print(
                    '\n'.join(
                        notice_lines(
                            'The Retry-After: time would make this command line exceed the maximum '
                            'allowed time for retries.',
                            prefix='Warning: ',
                        )
                    ),
                    file=sys.stderr,
                )
        else:
            resp.close()
            if args.fails_on(status):
                say(args, transfer, EXIT_HTTP, 'The requested URL returned error: %s' % status)
            raise Retry(why, after=after)

    if args.verbose and not args.silent:
        print('Response status: %s' % status, file=sys.stderr)
    args.save_cookie_jar()
    try:
        decoder = Decoder(header_items) if args.compressed and not args.head else None
    except EncodingError as exc:
        resp.close()
        return fail(args, transfer, EXIT_BAD_ENCODING, str(exc))
    header_bytes = format_response_headers(status, reason, header_items)
    transfer.size_header = len(header_bytes) + sum(len(r) for r in args.connection.connect_replies)
    # curl shows each hop's head, the proxy's CONNECT reply before its own.
    shown = [] if args.suppress_connect_headers else list(args.connection.connect_replies)
    earlier = b''
    for replies, head in transfer.hop_heads:
        earlier += (b'' if args.suppress_connect_headers else replies) + head
    taken = sum(len(replies) for replies, _ in transfer.hop_heads)
    header_bytes = earlier + b''.join(shown)[taken:] + header_bytes
    try:
        outcome = args.download_outcome(status, header_items)
    except LocalError as exc:
        resp.close()
        return fail(args, transfer, exc.code, str(exc))
    sink = None
    try:
        args.write_header_dump(header_bytes)
        if outcome == 'skip':
            # A 304, an unmet -z, a finished resume: no body, no file.
            return 0
        if args.fails_on(status) and not args.fail_with_body:
            return fail(args, transfer, EXIT_HTTP, 'The requested URL returned error: %s' % status)  # no body
        sink = args.body_sink(header_bytes)
        sink.start()
        return _deliver(args, resp, status, header_items, transfer, sink, decoder, may_retry)
    except EncodingError as exc:
        _flush(sink)
        return fail(args, transfer, EXIT_BAD_ENCODING, str(exc))
    except WriteFailure as exc:
        # -o / -D not writable, or stdout closed under us: curl's 23, in the
        # words curl has for where the write failed.
        transfer.errormsg = exc.message
        if exc.notice and (not args.silent or args.show_error):
            print('\n'.join(notice_lines(exc.notice)), file=sys.stderr)
        if exc.coded and args.should_print_error():
            print('curl: (%d) %s' % (EXIT_WRITE, exc.message), file=sys.stderr)
        return EXIT_WRITE
    except OSError as exc:
        # What follows the body (-R, --etag-save) could not be written.
        return fail(args, transfer, EXIT_WRITE, 'Failure writing output to destination: %s' % exc)
    finally:
        if sink is not None:
            sink.release()
        resp.close()


def _flush(sink):
    """What was delivered before a failure reaches its destination."""
    if sink is not None:
        try:
            sink.close()
        except WriteFailure:
            pass


def _deliver(args, resp, status, header_items, transfer, sink, decoder, may_retry):
    """The body from ``resp`` to ``sink``, a piece at a time: paced
    (--limit-rate, --speed-limit), capped (--max-filesize), decoded
    (--compressed). Returns curl's exit code."""
    pace = Pace(args.rate(), args.low_speed()) if args.limit_rate or args.low_speed() else None

    def settle():
        sock = response_socket(resp)
        if sock is not None:
            args.connection.settle(sock)

    reader = None
    too_big = False
    if not args.head:
        reader = BodyReader(resp, pace, args.ignore_content_length, settle)
        for piece in reader:
            transfer.size_download += len(piece)  # as it came over the wire, before --compressed
            if args.too_big(header_items, transfer.size_download):
                too_big = True
                break
            sink.body(decoder.feed(piece) if decoder else piece)
        if reader.cut is None and not too_big and decoder:
            sink.body(decoder.finish())
    sink.close()  # what was held back reaches its destination; a file opens even when empty
    transfer.size_delivered = sink.delivered
    if too_big:
        return fail(args, transfer, EXIT_FILESIZE, 'Maximum file size exceeded')
    if args.fails_on(status):  # --fail-with-body: the body, then the same exit 22
        return fail(args, transfer, EXIT_HTTP, 'The requested URL returned error: %s' % status)
    if reader is not None and reader.cut is not None:
        # What arrived is written, as curl writes it, then the failure.
        return body_error(args, reader.cut, transfer, reader.chunked, may_retry)
    args.finish_download(header_items)
    return 0


def _proxy_auth(args, plan, url):
    """A :class:`ChallengeAuth` for --proxy-digest / --proxy-anyauth with
    credentials (-U, else the proxy URL's -- the one chosen for ``url``), or
    ``None``."""
    if not (args.proxy_digest or args.proxy_anyauth) or plan is None or plan.endpoint is not None:
        return None
    if args.proxy_user:
        user, _, password = args.proxy_user.partition(':')
    else:
        found = userinfo(args.effective_proxy() or plan.uri)
        if not found:
            return None
        user, password = found
    return ChallengeAuth(user, password, anyauth=args.proxy_anyauth)


def _socks_for(args, plan, proxy, url):
    """``(socks proxy, socks pre-proxy)`` for the transfer to ``url``: the
    plan's proxy when it is SOCKS (credentials from -U, else its URL's
    userinfo), and --preproxy in front of an HTTP proxy."""
    if plan is None:
        return None, None
    user = password = None
    if args.proxy_user:
        user, _, password = args.proxy_user.partition(':')
    raw = proxy or plan.uri
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
        args.cookie_managed = not has_header(headers, 'cookie')  # else -H Cookie is the whole header
        cookie_header = args.cookie_header(url)
        if cookie_header and args.cookie_managed:
            headers['Cookie'] = cookie_header
        proxy = args.effective_proxy()
        if not proxy and args.preproxy and Socks.is_socks(args.preproxy):
            proxy = args.preproxy  # a pre-proxy with no proxy after it is the proxy
        check_proxy_syntax(proxy or configured_text())  # curl's 5
        # Decided for this URL (the system's answer may differ per URL); its
        # redirect hops keep the decision, as with curl's own --proxy.
        plan = proxy_plan(proxy=proxy, noproxy=args.noproxy, proxy_user=args.proxy_user, url=url)
        args.socks, args.socks_pre = _socks_for(args, plan, proxy, url)
        transfer = Transfer(typed, url, method, plan)
        args.output_target(url)
        if args.prepare_download(headers):
            return 0  # --skip-existing: the file is there
        args.connection = args.connector()  # --interface / --local-port / --pinnedpubkey
        if data is not None and not isinstance(data, (bytes, bytearray)):
            headers.setdefault('Content-Length', str(len(data)))  # a file sent as it is read
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
    except agent_proxy.NoReachableProxyError as exc:
        # curl's answer to a proxy it cannot connect to.
        rc = fail(args, transfer, EXIT_CONNECT, str(exc))
        args.report(tokens, transfer, rc)
        return rc

    if args.verbose and not args.silent:
        print('Request: %s %s' % (method, url), file=sys.stderr)
        if data and isinstance(data, (bytes, bytearray)):
            print('Data:', data.decode('utf-8', errors='replace'), file=sys.stderr)
        print('Headers:', headers, file=sys.stderr)
        if plan is not None and not plan.bypasses(url):
            # The URL only, never the credential: this line ends up in logs.
            print(
                'Proxy%s: %s%s'
                % (
                    ' (prefix %s)' % plan.endpoint if plan.endpoint else '',
                    plan.proxy,
                    ' (with %s)' % plan.auth_header if plan.authorization else '',
                ),
                file=sys.stderr,
            )

    rc, transfer = _attempts(args, typed, url, method, plan, context, removed, data, headers)
    args.cleanup_after(rc)
    args.report(tokens, transfer, rc)
    return rc


def _attempts(args, typed, url, method, plan, context, removed, data, headers):
    """The transfer, again after each transient failure ``--retry`` covers:
    ``(exit code, the last attempt's Transfer)``."""
    retries = max(args.retry or 0, 0)
    first = args.retry_started = time.monotonic()
    backoff = 1.0
    while True:
        in_time = not args.retry_max_time or time.monotonic() - first < args.retry_max_time
        transfer = Transfer(typed, url, method, plan)
        args.start_clock()
        transfer.retries = max(args.retry or 0, 0) - retries
        opener = build_opener(args, plan, context, transfer, removed)
        req = urllib.request.Request(url, data=data, headers=dict(headers), method=method)
        try:
            rc = exchange(args, opener, req, url, transfer, may_retry=retries > 0 and in_time)
            break
        except Retry as retry:
            wait = args.retry_wait(backoff, retry.after)
            if args.retry_max_time:
                wait = max(0.0, min(wait, args.retry_max_time - (time.monotonic() - first)))
            if not args.silent:
                print(
                    'Warning: Problem %s. Retrying in %s. %s left.'
                    % (retry.what, _count(int(round(wait)), 'second', 'seconds'), _count(retries, 'retry', 'retries')),
                    file=sys.stderr,
                )
            sleep(wait)
            retries -= 1
            backoff = min(backoff * 2, MAX_RETRY_SLEEP)
    return rc, transfer
