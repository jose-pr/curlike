"""Reading argv the way curl does: the table of options that take a value is
curl's, so an option's value is never taken for the URL or the proxy, and what
chooses the proxy is seen however it is written."""

import re
import subprocess
import sys

import pytest

import curlike as curl
from curlike import realcurl
from curlike.argv import VALUE_OPTIONS, attach_values

URL = "http://origin.example/x"

# `-A, --user-agent <name>` and `    --alt-svc <filename>` take one; `-a, --append` and `-:, --next` do not.
# Older layouts differ: 8.11 shows `--proxy [protocol://]host[:port]` without angle brackets, and 8.5 follows
# a name as wide as the column with one space, not several.
_WITH_ARGUMENT = re.compile(r"^ *(?:(-[^,\s]), )?(--[^\s<\[]+) [<\[]")
_WITHOUT_ARGUMENT = re.compile(r"^ *(?:(-[^,\s]), )?(--\S+)(?= |$)")
# Options an older `--help all` lists without the value they take, and the release that fixed the line.
LISTED_WITHOUT_VALUE = {"--haproxy-clientip": (8, 6, 0)}


def _help_all():
    path = realcurl.find_real_curl()
    if not path:
        pytest.skip("no real curl on PATH")
    out = subprocess.run([path, "--help", "all"], capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    with_argument, without, unread = set(), set(), []
    for line in out.stdout.decode("utf-8", "replace").splitlines():
        if not line.lstrip().startswith("-"):
            continue
        found = _WITH_ARGUMENT.match(line)
        names = with_argument
        if not found:
            found = _WITHOUT_ARGUMENT.match(line)
            names = without
        if found:
            names.update(name for name in found.groups() if name)
        else:
            unread.append(line)
    assert not unread and len(with_argument) > 100 and len(without) > 100, "`--help all` was not read: %r" % (
        unread[:3] or out.stdout[:300]
    )
    version = realcurl.describe(path)[0] or (0, 0, 0)
    for name, fixed in LISTED_WITHOUT_VALUE.items():
        if version < fixed and name in without:
            without.discard(name)
            with_argument.add(name)
    return with_argument, without


def test_the_table_holds_every_option_curl_takes_an_argument_for():
    with_argument, _without = _help_all()
    assert sorted(with_argument - VALUE_OPTIONS) == []


def test_the_table_holds_no_option_curl_takes_none_for():
    _with_argument, without = _help_all()
    assert sorted(without & VALUE_OPTIONS) == []


# Options that take a value in curl and that the command has no field for.
UNKNOWN_TO_THE_FALLBACK = [
    "--abstract-unix-socket",
    "--alt-svc",
    "--aws-sigv4",
    "--create-file-mode",
    "--curves",
    "--ech",
    "--ftp-port",
    "--haproxy-clientip",
    "--hostpubsha256",
    "--hsts",
    "--ip-tos",
    "--ipfs-gateway",
    "--keepalive-cnt",
    "--knownhosts",
    "--parallel-max-host",
    "--proxy1.0",
    "--rate",
    "--sigalgs",
    "--ssl-sessions",
    "--trace-config",
    "--upload-flags",
    "--vlan-priority",
    "-P",
]


@pytest.mark.parametrize("option", UNKNOWN_TO_THE_FALLBACK)
def test_the_value_of_any_curl_option_is_never_the_url(option):
    assert curl.requested_url([option, "value.txt", URL]) == URL
    assert curl.requested_url(["-s", option + "=value.txt", URL]) == URL
    assert curl.requested_url(["-s", option, "-", URL]) == URL, "a lone dash is a value too"


@pytest.mark.parametrize(
    "argv",
    [
        ["-qso", "FILE", URL],
        ["-qsoFILE", URL],
        ["-o", "FILE", URL],
        ["-so", "FILE", URL],
        ["--output", "FILE", URL],
        ["--output=FILE", URL],
        ["--expand-data", "{{x}}", URL],
        ["--expand-output", "FILE", URL],
        ["--no-keepalive", URL],
        ["--timeout", "5", URL],
        ["-H", "-x", "-o", "FILE", URL],
        ["-d", "--url", URL],
        ["--", URL],
        # a --next group is read on its own: the first URL of the group, whatever precedes it
        ["--next", "-o", "FILE", URL],
        ["-:", "-o", "FILE", URL],
        ["-s", "--next", "-sH", "X: y", URL],
        [URL, "--next", "-o", "FILE", "http://second.example/"],
    ],
)
def test_the_url_is_never_the_value_of_an_option(argv):
    assert curl.requested_url(argv) == URL


@pytest.mark.parametrize(
    "argv, proxy",
    [
        (["--proxy1.0", "h:1", URL], "h:1"),
        (["--preproxy", "socks5h://p:1", URL], "socks5h://p:1"),
        (["-K", "c.cfg", URL], "c.cfg"),
        (["--config", "c.cfg", URL], "c.cfg"),
        (["--config=c.cfg", URL], "c.cfg"),
        (["-sK", "c.cfg", URL], "c.cfg"),
        (["-sKc.cfg", URL], "c.cfg"),
        (["-qK", "c.cfg", URL], "c.cfg"),
        (["-K", "c.cfg", "-x", "h:1", URL], "h:1"),
        (["-x", "h:1", "-K", "c.cfg", URL], "h:1"),
        (["--proxy1.0", "h:1", "--preproxy", "socks5h://p:1", URL], "socks5h://p:1"),
        (["-x", "h:1", URL], "h:1"),
        (["-sx", "h:1", URL], "h:1"),
        (["--socks5-hostname", "p:1", URL], "p:1"),
    ],
)
def test_the_caller_steers_the_proxy(argv, proxy):
    assert curl.caller_steering(argv)[0] == proxy


@pytest.mark.parametrize(
    "argv",
    [
        [URL],
        ["-s", URL],
        ["-oK", URL],  # a file named K
        ["-soK", URL],
        ["-H", "--config", URL],  # option values that look like options
        ["-d", "-K", URL],
        ["-d", "--proxy1.0=h:1", URL],
        ["-H", "--preproxy", URL],
        ["-o", "-x", URL],
        ["--", "-K", URL],  # after `--` everything is a URL
        ["--expand-data", "--config", URL],
    ],
)
def test_nothing_steers_the_proxy(argv):
    assert curl.caller_steering(argv) == (None, None, None)


def test_expand_names_the_option_it_expands():
    assert curl.requested_url(["--expand-url", "{{u}}"]) == "http://{{u}}"
    assert curl.caller_steering(["--expand-proxy", "{{p}}", URL])[0] == "{{p}}"


def test_the_other_steering_values_are_read_with_the_proxy():
    argv = ["-sx", "h:1", "-U", "u:p", "--noproxy", "*", "--proxy1.0", "h2:2", URL]
    assert curl.caller_steering(argv) == ("h2:2", "*", "u:p")
    assert curl.caller_steering(["--proxy-user=u:p", "-Uv:q", "--noproxy=", URL]) == (None, "", "v:q")


def test_help_takes_no_argument_for_argparse():
    # curl's --help takes a category; argparse's does not, so a dashed word after it stays its own option.
    assert attach_values(["-h", "-x"]) == ["-h", "-x"]
    assert attach_values(["--help", "-x"]) == ["--help", "-x"]
    assert attach_values(["-sh", "-x"]) == ["-sh", "-x"]
    assert attach_values(["-z", "-DATE", URL]) == ["-z-DATE", URL]
    assert attach_values(["--timeout", "-1"]) == ["--timeout=-1"]


def test_steering_is_read_without_duho():
    code = (
        "import sys; sys.modules['duho'] = None; import curlike; "
        "print(curlike.caller_steering(['-sK', 'c.cfg', '--noproxy', '*', 'http://h/']))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
    assert out.stdout.decode().strip() == "('c.cfg', '*', None)", out.stderr.decode()[-500:]
