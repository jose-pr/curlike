"""HTTPLIB_CURL_COMPAT: the curl version the fallback answers as where versions
disagree (``curlike.compat``). The parity tests prove each answer against
real curl; these pin the setting itself."""
import pytest

from curlike import shim as curl
from curlike import compat


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setattr(compat, "_cached", {})
    monkeypatch.delenv(compat.var(), raising=False)


@pytest.mark.parametrize("text,expected", [
    ("8.19", (8, 19, 0)), ("8.19.0", (8, 19, 0)), ("8.22.1", (8, 22, 1)),
    ("curl 8.21.0 (aarch64-w64-mingw32) libcurl/8.21.0", (8, 21, 0)), ("", None), ("x", None),
])
def test_versions_parse(text, expected):
    assert compat.parse_version(text) == expected


@pytest.mark.parametrize("version,code,first", [
    ("8.17", 56, False), ("8.18", 56, True), ("8.19.9", 56, True), ("8.20", 7, True), ("8.22", 7, True),
])
def test_the_measured_boundaries(monkeypatch, version, code, first):
    monkeypatch.setenv(compat.var(), version)
    assert compat.connect_refused_code() == code
    assert compat.checks_files_first() is first
    assert compat.socks_unresolved("h.example", "proxy.example")[0] == (6 if code == 7 else 97)
    assert compat.rejects_unknown_protocols() is first


@pytest.mark.parametrize("version,large,pins,ignores_netrc,socks,port", [
    ("8.5", 27, False, True, 6, 0), ("8.7.1", 100, False, True, 6, 0), ("8.10", 100, True, True, 6, -1),
    ("8.12", 100, True, False, 6, -1), ("8.14", 100, True, False, 5, -1),
])
def test_the_older_boundaries(monkeypatch, version, large, pins, ignores_netrc, socks, port):
    monkeypatch.setenv(compat.var(), version)
    assert compat.too_large()[0] == large and compat.no_port() == port
    assert compat.upper_scheme() is (version in ("8.5", "8.7.1"))
    assert compat.pins_proxy_when_insecure() is pins and compat.ignores_missing_netrc_file() is ignores_netrc
    assert compat.socks_proxy_unresolved_code() == socks


def test_auto_is_the_installed_curl_else_the_newest(monkeypatch):
    monkeypatch.setattr(compat, "installed_version", lambda: (8, 18, 0))
    assert compat.version() == (8, 18, 0)
    monkeypatch.setattr(compat, "_cached", {})
    monkeypatch.setattr(compat, "installed_version", lambda: None)
    monkeypatch.setenv(compat.var(), "auto")
    assert compat.version() == compat.NEWEST


def test_an_unreadable_value_is_exit_2(monkeypatch, capsys):
    monkeypatch.setenv(compat.var(), "latest")
    monkeypatch.setattr(curl, "find_real_curl", lambda *a: None)
    rc = curl.main(["-sS", "-x", "http://127.0.0.1:1", "https://example.invalid/"])
    err = capsys.readouterr().err
    assert rc == 2 and "HTTPLIB_CURL_COMPAT=latest" in err, err


def test_the_shim_never_finds_itself(tmp_path, monkeypatch):
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    for name in ("curl", "curl.cmd", "curl.py"):
        (shim_dir / name).write_text("")
    monkeypatch.setenv("PATH", str(shim_dir))
    assert compat.find_real_curl() is None
