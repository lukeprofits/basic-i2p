"""
Tests for scripts/refresh_checksums.py — parsing and table rewriting only.

No network and no GPG: those paths are exercised for real when a maintainer
bumps the version. Here we check the SHA512SUMS parser and the in-place table
editor, which are the parts easy to get subtly wrong.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "refresh_checksums.py"

spec = importlib.util.spec_from_file_location("refresh_checksums", SCRIPT)
assert spec and spec.loader
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)


def _fake_sums(version: str) -> str:
    h = "a" * 128
    b = "b" * 128
    other = "c" * 128
    return (
        f"{h} *i2pd_{version}_win64_mingw.zip\n"
        f"{b} *i2pd_{version}_osx.tar.gz\n"
        f"{other} *i2pd_{version}-1_amd64.deb\n"   # ignored
    )


def test_parse_sums_extracts_supported():
    shas = refresh.parse_sums(_fake_sums("2.60.0"), "2.60.0")
    assert shas == {"win64": "a" * 128, "osx": "b" * 128}


def test_parse_sums_missing_archive_raises():
    incomplete = "a" * 128 + " *i2pd_2.60.0_win64_mingw.zip\n"
    with pytest.raises(SystemExit):
        refresh.parse_sums(incomplete, "2.60.0")


def test_update_table_replaces_existing(tmp_path):
    target = tmp_path / "i2pd_checksums.py"
    target.write_text(
        "CHECKSUMS: dict[str, dict[str, str]] = {\n"
        '    "2.60.0": {\n'
        '        "win64": "old",\n'
        '        "osx": "old",\n'
        "    },\n"
        "}\n"
    )
    refresh.update_table("2.60.0", {"win64": "a" * 128, "osx": "b" * 128}, path=target)
    text = target.read_text()
    assert "a" * 128 in text
    assert '"old"' not in text
    # Exactly one 2.60.0 block.
    assert text.count('"2.60.0":') == 1


def test_update_table_adds_new_version(tmp_path):
    target = tmp_path / "i2pd_checksums.py"
    target.write_text(
        "CHECKSUMS: dict[str, dict[str, str]] = {\n"
        '    "2.60.0": {\n'
        '        "win64": "x",\n'
        '        "osx": "y",\n'
        "    },\n"
        "}\n"
    )
    refresh.update_table("2.61.0", {"win64": "a" * 128, "osx": "b" * 128}, path=target)
    text = target.read_text()
    assert '"2.60.0":' in text
    assert '"2.61.0":' in text
