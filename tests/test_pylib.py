"""CURLIKE_PYLIB: where the fallback finds duho when the interpreter has none.

The setting is a full variable name, read under each prefix of SYSHTTP_PREFIX
as syshttp's own are.
"""

import importlib.abc
import importlib.util
import os
import sys

import pytest

from curlike import _duho


class _NoInstalledDuho(importlib.abc.MetaPathFinder):
    """duho is not importable until the directory a test names is on sys.path,
    then it is the stand-in found there."""

    def __init__(self, library):
        self.library = str(library)

    def find_spec(self, name, path=None, target=None):
        if name != "duho":
            return None
        if self.library not in sys.path:
            raise ImportError("no duho")
        init = os.path.join(self.library, "duho", "__init__.py")
        return importlib.util.spec_from_file_location(name, init, submodule_search_locations=[os.path.dirname(init)])


@pytest.fixture()
def library(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    (lib / "duho").mkdir(parents=True)
    (lib / "duho" / "__init__.py").write_text("Meta = Arg = object\nSTAND_IN = True\n")
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "meta_path", [_NoInstalledDuho(lib)] + sys.meta_path)
    monkeypatch.delitem(sys.modules, "duho", raising=False)
    for name in ("CURLIKE_PYLIB", "SYSHTTP_PYLIB", "AGENTS_CURLIKE_PYLIB", "AGENTS_SYSHTTP_PYLIB"):
        monkeypatch.delenv(name, raising=False)
    return lib


def test_the_setting_names_where_duho_is_found(library, monkeypatch):
    monkeypatch.setenv("CURLIKE_PYLIB", str(library))
    assert _duho._load().STAND_IN is True


def test_a_prefix_moves_the_setting(library, monkeypatch):
    monkeypatch.setenv("SYSHTTP_PREFIX", "AGENTS_")
    monkeypatch.setenv("AGENTS_CURLIKE_PYLIB", str(library))
    assert _duho._load().STAND_IN is True


def test_a_prefix_list_falls_back_to_the_plain_name(library, monkeypatch):
    monkeypatch.setenv("SYSHTTP_PREFIX", "AGENTS_:")
    monkeypatch.setenv("CURLIKE_PYLIB", str(library))
    assert _duho._load().STAND_IN is True


@pytest.mark.parametrize("variable", ["SYSHTTP_PYLIB", "AGENTS_CURLIKE_PYLIB"])
def test_another_name_is_not_the_setting(variable, library, monkeypatch):
    monkeypatch.setenv(variable, str(library))
    with pytest.raises(_duho.DuhoMissing) as caught:
        _duho._load()
    assert "CURLIKE_PYLIB" in str(caught.value)


def test_the_message_names_the_variable_a_prefix_gives(library, monkeypatch):
    monkeypatch.setenv("SYSHTTP_PREFIX", "AGENTS_")
    with pytest.raises(_duho.DuhoMissing) as caught:
        _duho._load()
    assert str(caught.value).endswith("name it in AGENTS_CURLIKE_PYLIB")
