"""``curlike.realcurl``: finding the system curl and reading its version."""

import pytest

from curlike import realcurl


@pytest.mark.parametrize(
    "text,expected",
    [
        ("8.19", (8, 19, 0)),
        ("8.19.0", (8, 19, 0)),
        ("8.22.1", (8, 22, 1)),
        ("curl 8.21.0 (aarch64-w64-mingw32) libcurl/8.21.0", (8, 21, 0)),
        ("", None),
        ("x", None),
    ],
)
def test_versions_parse(text, expected):
    assert realcurl.parse_version(text) == expected


def test_a_launcher_is_never_the_real_curl(tmp_path, monkeypatch):
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    for name in ("curl", "curl.cmd", "curl.py"):
        (shim_dir / name).write_text("")
    monkeypatch.setenv("PATH", str(shim_dir))
    assert realcurl.find_real_curl() is None
