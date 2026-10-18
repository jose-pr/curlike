"""``CurlCmd``: every option group composed into one duho command. Adding a
group is adding a base here; a flag lives in the group whose behaviour it
drives."""
from ._duho import duho
from .args import Group
from .auth import AuthArgs
from .body import BodyArgs
from .connection import ConnectionArgs
from .cookies import CookieArgs
from .download import DownloadArgs
from .output import OutputArgs
from .request import RequestArgs
from .tls import TLSArgs
from .unsupported import UnsupportedArgs
from .writeout import WriteOutArgs


class ShimArgs(Group):
    """The fallback's own ``-V`` (duho provides ``-h``)."""

    show_version: bool = False
    "Show the fallback's version"
    ("-V", "--version")


class CurlCmd(UnsupportedArgs, CookieArgs, ConnectionArgs, TLSArgs, WriteOutArgs, DownloadArgs, OutputArgs, BodyArgs,
              AuthArgs, RequestArgs, ShimArgs, duho.Cmd):
    """Pure Python curl-like tool: curlike's fallback for a missing curl.

    duho lists the fields from the last-listed group up, so the help reads
    request, body, output, ...; the refused flags (first-listed, hidden from
    the help) are also checked first. Flags curl has and this does not honour
    are refused, exit 2."""

    _parsername_ = "curl"

    def __call__(self):
        from .transfer import run

        with self.stderr_redirected():
            return run(self)


def build_parser():
    return duho.parser(CurlCmd)
