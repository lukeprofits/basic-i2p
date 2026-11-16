"""An i2pd too old for today's network is named as the likely reason it died."""

from __future__ import annotations

from pathlib import Path

import basic_i2p


def _router(tmp_path: Path, version: str) -> Path:
    fake = tmp_path / f"i2pd-{version}"
    fake.write_text(f"#!/bin/sh\necho 'i2pd version {version} (0.9.60)'\n")
    fake.chmod(0o755)
    return fake


def test_an_old_router_is_named_with_where_to_get_a_current_one(tmp_path: Path) -> None:
    hint = basic_i2p._old_router_hint(_router(tmp_path, "2.49.0"))
    assert "2.49.0" in hint
    assert "repo.i2pd.xyz" in hint
    assert "ppa:purplei2p/i2pd" in hint


def test_a_current_router_or_none_at_all_adds_nothing(tmp_path: Path) -> None:
    assert basic_i2p._old_router_hint(_router(tmp_path, "3.0.0")) == ""
    assert basic_i2p._old_router_hint(_router(tmp_path, "2.50.0")) == ""
    assert basic_i2p._old_router_hint(None) == ""
    assert basic_i2p._old_router_hint(tmp_path / "missing") == ""
    silent = tmp_path / "silent"
    silent.write_text("#!/bin/sh\necho nothing useful\n")
    silent.chmod(0o755)
    assert basic_i2p._old_router_hint(silent) == ""
