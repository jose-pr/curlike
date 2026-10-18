"""The shim's one trap: with its own executable's directory on PATH, "the
real curl" must never resolve to the shim itself."""

import os
import stat
import sys
from pathlib import Path

from curlike import shim as curl


def _executable(directory, stem):
    name = stem + (".exe" if os.name == "nt" else "")
    exe = directory / name
    exe.write_text("", encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return exe


def _path(monkeypatch, *dirs):
    monkeypatch.setenv("PATH", os.pathsep.join(str(d) for d in dirs))
    if os.name == "nt":
        monkeypatch.setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")


def test_real_curl_is_never_this_shim(tmp_path, monkeypatch):
    shim_dir, real_dir = tmp_path / "shim", tmp_path / "system"
    shim_dir.mkdir()
    real_dir.mkdir()
    entry = _executable(shim_dir, "curl")
    real = _executable(real_dir, "curl")
    # The shim's directory FIRST on PATH, as a drop-in curl is installed.
    _path(monkeypatch, shim_dir, real_dir)
    found = curl.find_real_curl(str(entry))
    assert found is not None and Path(found).resolve() == real.resolve()


def test_no_real_curl_means_fallback(tmp_path, monkeypatch):
    entry = _executable(tmp_path, "curl")
    _path(monkeypatch, tmp_path)
    assert curl.find_real_curl(str(entry)) is None


def test_fallback_runs_when_only_the_shim_is_on_path(tmp_path, monkeypatch, capsysbinary):
    """End to end: PATH holds nothing but the shim's own directory, so main()
    must take the stdlib path instead of re-executing itself."""
    entry = _executable(tmp_path, "curl")
    _path(monkeypatch, tmp_path)
    assert curl.main(["--help"], entry=str(entry)) == 0
    assert b"Pure Python curl-like tool" in capsysbinary.readouterr().out


def test_default_entry_is_a_shim_executable_only(tmp_path, monkeypatch):
    exe = _executable(tmp_path, "pycurl")
    monkeypatch.setattr(sys, "argv", [str(exe)])
    assert curl.default_entry() == str(exe.resolve())
    script = tmp_path / "curl.py"
    script.write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(script)])
    assert curl.default_entry() is None, "a .py is not an executable of the shim"
    monkeypatch.setattr(sys, "argv", [str(_executable(tmp_path, "pytest"))])
    assert curl.default_entry() is None
