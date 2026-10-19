"""The netrc reader: curl's tokens (quotes, comments, macdef) and its choice
of entry (first match in file order, the login a URL names)."""

import pytest

from curlike.auth import netrc_lookup, read_netrc, split_userinfo


def _read(tmp_path, text):
    path = tmp_path / "netrc"
    path.write_text(text, encoding="utf-8")
    return read_netrc(str(path))


def test_quotes_comments_and_macros(tmp_path):
    entries = _read(
        tmp_path,
        '# whole line\nmachine Example.COM login u password "a \\"b\\" c" # trailing\n'
        "#machine hidden login x password y\nmacdef init\n machine evil login e password e\n\n"
        "machine other login o password pw#1\n",
    )
    assert entries == [("example.com", "u", 'a "b" c'), ("other", "o", "pw#1")]


def test_a_login_with_no_password_has_an_empty_one(tmp_path):
    assert _read(tmp_path, "machine h login only\n") == [("h", "only", "")]


def test_the_first_matching_entry_in_file_order_wins(tmp_path):
    entries = _read(
        tmp_path, "machine a login a1 password p1\ndefault login d password pd\nmachine b login b1 password p2\n"
    )
    assert netrc_lookup(entries, "A") == ("a1", "p1")
    assert netrc_lookup(entries, "b") == ("d", "pd"), "default comes first in the file"
    assert netrc_lookup(entries, "zzz") == ("d", "pd")


def test_a_named_login_picks_its_entry(tmp_path):
    entries = _read(tmp_path, "machine h login alice password a\nmachine h login bob password b\n")
    assert netrc_lookup(entries, "h", "bob") == ("bob", "b")
    assert netrc_lookup(entries, "h", "carol") is None


@pytest.mark.parametrize(
    "url,creds",
    [
        ("http://u:p@h/x", ("u", "p")),
        ("http://u@h/x", ("u", None)),
        ("http://u:@h/x", ("u", "")),
        ("http://h/x", None),
    ],
)
def test_a_url_user_without_a_colon_has_no_password(url, creds):
    assert split_userinfo(url)[1] == creds
