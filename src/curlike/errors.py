"""curl's exit codes, as far as the fallback can tell failures apart, and the
two exceptions a transfer raises on its way to one."""

EXIT_PROTOCOL = 1
EXIT_USAGE = 2
EXIT_URL = 3
EXIT_RESOLVE_PROXY = 5
EXIT_RESOLVE = 6
EXIT_CONNECT = 7
EXIT_WEIRD_REPLY = 8
EXIT_PARTIAL = 18
EXIT_HTTP = 22
EXIT_WRITE = 23
EXIT_READ = 26
EXIT_TIMEOUT = 28
EXIT_REDIRECTS = 47
EXIT_EMPTY_REPLY = 52
EXIT_SEND = 55
EXIT_RECV = 56
EXIT_BAD_ENCODING = 61
EXIT_TOO_LARGE = 100
EXIT_CLIENT_CERT = 58
EXIT_SSL_CONNECT = 35
EXIT_SSL = 60
EXIT_CACERT = 77
EXIT_CRL = 82


class LocalError(Exception):
    """A local file or name the transfer cannot use -- a CA bundle (77), a
    client certificate (58), an upload (26), an output (23). Reported like a
    transfer failure: one ``curl: (N)`` line, ``-w`` still written."""

    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code


#: libcurl's own text for exit 23, what ``%{errormsg}`` holds when the failure
#: was the tool's and no transfer message was set.
WRITE_ERROR_TEXT = 'Failed writing received data to disk/application'


class WriteFailure(Exception):
    """An output curl could not write: exit 23. ``message`` is ``%{errormsg}``
    and the text of the ``curl: (23)`` line, printed unless ``coded`` is
    false; ``notice`` is a line curl prints before it, with no code."""

    def __init__(self, message, notice=None, coded=True):
        Exception.__init__(self, message)
        self.message = message
        self.notice = notice
        self.coded = coded


class EarlyExit(Exception):
    """A failure curl reports before any transfer, as ``curl: message`` with
    no ``(N)`` -- a file named on the command line that is not there (2 for
    ``--cacert`` / ``--netrc-file``, 26 for a ``@file`` to read) -- and
    without ``-w`` output."""

    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code


class Retry(Exception):
    """A transient failure another ``--retry`` attempt may fix. ``what`` is
    curl's wording for the warning (``: timeout``, ``: HTTP error``, ...);
    ``after`` the server's ``Retry-After`` in seconds, or ``None``."""

    def __init__(self, what, after=None):
        Exception.__init__(self, what)
        self.what = what
        self.after = after
