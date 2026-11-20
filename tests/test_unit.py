"""
Pure unit tests — no network, no i2pd process. Fast.

Covers everything testable without downloading the binary or bootstrapping:
platform detection, version gating, checksum lookup + mismatch, host
allowlist, safe archive extraction, and the SAM reply parser / helpers.
"""

from __future__ import annotations

import base64
import io
import os as _os
import socket as _socket
import sys as _sys
import tarfile
import zipfile
from unittest import mock

import pytest

import basic_i2p
from basic_i2p import (
    I2PBinaryNotFound,
    _archive_name,
    _archive_url,
    _check_redirect_origin,
    _expected_sha512,
    _extract_tar,
    _extract_zip,
    _platform_key,
    _safe_member_name,
    i2pd_checksums,
)

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "system,machine,expected",
    [
        ("Windows", "AMD64", "win64"),
        ("Windows", "x86_64", "win64"),
        ("Darwin", "x86_64", "osx"),
        ("Darwin", "arm64", "osx"),   # Rosetta 2
        ("Darwin", "aarch64", "osx"),
    ],
)
def test_platform_key_supported(system, machine, expected):
    with mock.patch("platform.system", return_value=system), \
         mock.patch("platform.machine", return_value=machine):
        assert _platform_key() == expected


@pytest.mark.parametrize(
    "system,machine",
    [
        ("Linux", "x86_64"),
        ("Linux", "aarch64"),
        ("FreeBSD", "amd64"),
    ],
)
def test_platform_key_uses_system_i2pd(system, machine):
    """Platforms without a static build raise a use-system-i2pd error."""
    with mock.patch("platform.system", return_value=system), \
         mock.patch("platform.machine", return_value=machine):
        with pytest.raises(I2PBinaryNotFound) as exc:
            _platform_key()
    assert "PATH" in str(exc.value)


def test_linux_error_names_apt():
    with mock.patch("platform.system", return_value="Linux"), \
         mock.patch("platform.machine", return_value="x86_64"):
        with pytest.raises(I2PBinaryNotFound) as exc:
            _platform_key()
    assert "apt install i2pd" in str(exc.value)


# ---------------------------------------------------------------------------
# Archive naming / URL
# ---------------------------------------------------------------------------


def test_archive_name_and_url():
    with mock.patch("basic_i2p._platform_key", return_value="win64"):
        assert _archive_name() == f"i2pd_{basic_i2p.I2PD_VERSION}_win64_mingw.zip"
        url = _archive_url()
    assert url.startswith("https://github.com/PurpleI2P/i2pd/releases/download/")
    assert url.endswith("_win64_mingw.zip")


def test_archive_url_rejects_bad_version(monkeypatch):
    monkeypatch.setattr(basic_i2p, "I2PD_VERSION", "2.60.0; rm -rf /")
    with mock.patch("basic_i2p._platform_key", return_value="osx"):
        with pytest.raises(I2PBinaryNotFound):
            _archive_url()


# ---------------------------------------------------------------------------
# Checksum table
# ---------------------------------------------------------------------------


def test_checksum_present_for_pinned_version():
    for plat in ("win64", "osx"):
        sha = i2pd_checksums.known_checksum(basic_i2p.I2PD_VERSION, plat)
        assert sha and len(sha) == 128


def test_checksum_unknown_returns_none():
    assert i2pd_checksums.known_checksum("0.0.0", "win64") is None
    assert i2pd_checksums.known_checksum(basic_i2p.I2PD_VERSION, "atari") is None


def test_expected_sha512_refuses_unknown_version(monkeypatch):
    monkeypatch.setattr(basic_i2p, "I2PD_VERSION", "0.0.0")
    with mock.patch("basic_i2p._platform_key", return_value="win64"):
        with pytest.raises(I2PBinaryNotFound) as exc:
            _expected_sha512()
    assert "refresh_checksums" in str(exc.value)


# ---------------------------------------------------------------------------
# Redirect / host allowlist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/PurpleI2P/i2pd/releases/download/2.60.0/x.zip",
        "https://objects.githubusercontent.com/foo",
        "https://release-assets.githubusercontent.com/foo",
    ],
)
def test_redirect_origin_allows_github(url):
    _check_redirect_origin(url)  # must not raise


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/x.zip",
        "http://github.com/x.zip",                 # non-HTTPS
        "https://github.com.evil.example/x.zip",   # suffix trick
    ],
)
def test_redirect_origin_rejects(url):
    with pytest.raises(I2PBinaryNotFound):
        _check_redirect_origin(url)


# ---------------------------------------------------------------------------
# Safe extraction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,ok",
    [
        ("i2pd.exe", True),
        ("contrib/certificates/reseed/x.crt", True),
        ("/etc/passwd", False),
        ("../../evil", False),
        ("a/../../../evil", False),
        ("C:\\evil", False),
        ("..\\windows\\system32", False),
    ],
)
def test_safe_member_name(name, ok):
    assert _safe_member_name(name) is ok


def test_extract_zip_rejects_traversal(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", b"nope")
    with pytest.raises(I2PBinaryNotFound):
        _extract_zip(archive, tmp_path / "out")


def test_extract_zip_rejects_traversal_dir_entry(tmp_path):
    # Directory entries (trailing "/") escape the tree just as surely as files.
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../outside/", b"")
    with pytest.raises(I2PBinaryNotFound):
        _extract_zip(archive, tmp_path / "out")
    assert not (tmp_path / "outside").exists()


def test_copy_capped_binds_on_actual_bytes():
    # Archive size metadata is attacker-writable; the cap must bind on bytes
    # actually produced by the decompressor, not on declared size.
    from basic_i2p import _copy_capped
    with pytest.raises(I2PBinaryNotFound):
        _copy_capped(io.BytesIO(b"x" * 64), io.BytesIO(), "member", cap=16)
    assert _copy_capped(io.BytesIO(b"x" * 8), io.BytesIO(), "member", cap=16) == 8


def test_extract_zip_rejects_too_many_members(tmp_path, monkeypatch):
    import basic_i2p as pkg
    monkeypatch.setattr(pkg, "_MAX_MEMBERS", 2)
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(3):
            zf.writestr(f"f{i}", b"x")
    with pytest.raises(I2PBinaryNotFound):
        _extract_zip(archive, tmp_path / "out")


def test_extract_tar_rejects_too_many_members(tmp_path, monkeypatch):
    import basic_i2p as pkg
    monkeypatch.setattr(pkg, "_MAX_MEMBERS", 2)
    archive = tmp_path / "many.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        for i in range(3):
            info = tarfile.TarInfo(f"f{i}")
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(I2PBinaryNotFound):
        _extract_tar(archive, tmp_path / "out")


def test_extract_zip_total_bytes_cap(tmp_path, monkeypatch):
    # Many members each under the per-member cap must still trip the
    # whole-archive budget.
    import basic_i2p as pkg
    monkeypatch.setattr(pkg, "_MAX_TOTAL_BYTES", 24)
    archive = tmp_path / "fat.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(3):
            zf.writestr(f"f{i}", b"x" * 10)
    with pytest.raises(I2PBinaryNotFound):
        _extract_zip(archive, tmp_path / "out")


def test_extract_tar_rejects_symlink(tmp_path):
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    with pytest.raises(I2PBinaryNotFound):
        _extract_tar(archive, tmp_path / "out")


def test_extract_zip_roundtrip(tmp_path):
    archive = tmp_path / "good.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("i2pd.exe", b"binary-bytes")
        zf.writestr("contrib/certificates/reseed/a.crt", b"cert")
    out = tmp_path / "out"
    _extract_zip(archive, out)
    assert (out / "i2pd.exe").read_bytes() == b"binary-bytes"
    assert (out / "contrib/certificates/reseed/a.crt").read_bytes() == b"cert"


def test_extract_tar_roundtrip(tmp_path):
    archive = tmp_path / "good.tar.gz"
    data = b"macho-binary"
    with tarfile.open(archive, "w:gz") as tf:
        info = tarfile.TarInfo("i2pd")
        info.size = len(data)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(data))
    out = tmp_path / "out"
    _extract_tar(archive, out)
    extracted = out / "i2pd"
    assert extracted.read_bytes() == data
    if _sys.platform != "win32":  # Windows has no exec bit to keep
        assert extracted.stat().st_mode & 0o100  # exec bit preserved


# ---------------------------------------------------------------------------
# Loopback port ownership (anti-impersonation check, Linux only)
# ---------------------------------------------------------------------------


linux_proc = pytest.mark.skipif(
    not _os.path.exists("/proc/net/tcp"), reason="needs Linux /proc"
)


@linux_proc
def test_verify_port_owner_true_for_own_listener():
    from basic_i2p import _verify_port_owner
    with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        assert _verify_port_owner(port, _os.getpid()) is True


@linux_proc
def test_verify_port_owner_false_for_foreign_listener():
    # Model the attack: the port's listener (here: us, playing the hostile
    # process) is NOT the child we launched. Checked against a real child
    # whose /proc/<pid>/fd we can read, this must be a definite False.
    import subprocess
    import sys

    from basic_i2p import _verify_port_owner
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]
            assert _verify_port_owner(port, child.pid) is False
    finally:
        child.kill()
        child.wait()


@linux_proc
def test_verify_port_owner_indeterminate_without_listener():
    from basic_i2p import _verify_port_owner
    with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    # Port now closed — no listener → indeterminate, never a hard failure.
    assert _verify_port_owner(port, _os.getpid()) is None


# ---------------------------------------------------------------------------
# Identity names + key storage
# ---------------------------------------------------------------------------


def test_identity_name_rejects_unsafe(tmp_path, monkeypatch):
    from basic_i2p import I2pdManager
    mgr = I2pdManager()
    for bad in ("a b", "x\nY", "", "a" * 65, 'q"q', "über"):
        with pytest.raises(ValueError):
            mgr._key_path(bad)
    assert mgr._key_path("my-app.v2").name == "my-app.v2.dat"


def test_save_keypair_mode_0600(tmp_path, monkeypatch):
    import os
    if os.name != "posix":
        pytest.skip("POSIX permissions only")
    import basic_i2p as pkg
    from basic_i2p import I2pdManager, _keys_dir
    monkeypatch.setattr(pkg, "DATA_DIR", tmp_path)
    _keys_dir().mkdir(parents=True)
    mgr = I2pdManager()
    mgr._save_keypair("default", "PUB", "PRIV")
    path = mgr._key_path("default")
    assert path.stat().st_mode & 0o777 == 0o600
    assert mgr._load_keypair("default") == ("PUB", "PRIV")
    assert not path.with_suffix(".dat.tmp").exists()


# ---------------------------------------------------------------------------
# Bundled certificates (needed for macOS reseed)
# ---------------------------------------------------------------------------


def test_certificates_bundled():
    certs = basic_i2p._certificates_dir()
    assert certs.is_dir()
    reseed = list((certs / "reseed").glob("*.crt"))
    assert len(reseed) >= 5


# ---------------------------------------------------------------------------
# SAM helpers (parser / dest recognition / b32)
# ---------------------------------------------------------------------------


def _fake_dest_b64(nbytes: int = 400) -> str:
    raw = bytes((i * 7) % 256 for i in range(nbytes))
    return base64.b64encode(raw, altchars=b"-~").decode()


def test_parse_reply_quoted_value():
    from basic_i2p._sam import parse_reply
    r = parse_reply('STREAM STATUS RESULT=I2P_ERROR MESSAGE="cannot reach peer"')
    assert r["_verb"] == "STREAM STATUS"
    assert r["RESULT"] == "I2P_ERROR"
    assert r["MESSAGE"] == "cannot reach peer"


def test_parse_reply_malformed():
    from basic_i2p._sam import SAMError, parse_reply
    with pytest.raises(SAMError):
        parse_reply("HELLO")


def test_looks_like_dest():
    from basic_i2p._sam import looks_like_dest
    assert looks_like_dest(_fake_dest_b64()) is True
    assert looks_like_dest("abcd.b32.i2p") is False
    assert looks_like_dest("notbob.i2p") is False
    assert looks_like_dest("short") is False


def test_b32_address_deterministic():
    from basic_i2p._sam import b32_address
    dest = _fake_dest_b64()
    a1 = b32_address(dest)
    a2 = b32_address(dest)
    assert a1 == a2
    assert a1.endswith(".b32.i2p")
    # 52 base32 chars for a 32-byte SHA-256, plus the suffix.
    assert len(a1) == len("q" * 52 + ".b32.i2p")


def test_b32_address_rejects_garbage():
    from basic_i2p._sam import SAMError, b32_address
    with pytest.raises(SAMError):
        b32_address("!!! not base64 !!!")
