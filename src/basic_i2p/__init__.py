"""
basic_i2p — stupid-simple, trustworthy I2P for Python.

Runs the *official* i2pd router (the C++ I2P implementation maintained by the
PurpleI2P project) under the hood. Auto-downloads and verifies it on first use
where an official static build exists (Windows, macOS), launches it with its
own data directory and loopback-only ports, and hands you:

  * an **I2P-only** HTTP proxy URL for fetching ``.i2p`` sites,
  * a way to **host** a local service under your own ``.b32.i2p`` address,
  * **peer-to-peer sockets** between I2P destinations (via the SAM bridge).

This package does **not** reimplement I2P. It manages the real thing — the
same i2pd binary the project ships — so you get the actual I2P network, not a
pure-Python approximation.

Unlike Tor, I2P is not an exit network: there is no clearnet browsing here.
The HTTP proxy is deliberately configured with **no outproxy**, so a request
to a clearnet host fails closed rather than leaking. Use basic-tor if you want
anonymous clearnet access.

Quick start::

    import basic_i2p
    import requests

    proxy = basic_i2p.ensure_running()        # "http://127.0.0.1:<port>"
    r = requests.get("http://notbob.i2p", proxies={"http": proxy, "https": proxy})
    print(r.text)

    addr = basic_i2p.host_service(8080)        # your local :8080 → "<b32>.i2p"
    basic_i2p.stop()                           # or just let atexit handle it

The router starts lazily on the first call and stops cleanly on process exit.
First run needs internet to fetch the binary (where auto-download applies) and
to reseed + build tunnels, which takes roughly 1-5 minutes; later runs reuse
the cached netdb and start faster.
"""

from __future__ import annotations

import atexit
import datetime
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, NoReturn
from urllib.parse import urljoin, urlparse

import requests
from platformdirs import user_data_dir

from . import i2pd_checksums
from ._sam import I2PSocket, SAMError, SamSession, b32_address

try:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("basic-i2p")
except PackageNotFoundError:
    __version__ = "0+unknown"

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — assign before the first API call to override
# ---------------------------------------------------------------------------

APP_NAME = "basic_i2p"

# Pinned i2pd release. To bump: change this, run scripts/refresh_checksums.py,
# commit. Read the *running* router's version at runtime via i2pd_version().
I2PD_VERSION = "2.60.0"

# Official i2pd distribution: signed release archives on GitHub. GitHub serves
# asset bytes off *.githubusercontent.com, so both are allowed as redirect
# targets — but nothing else is (see _check_redirect_origin).
_RELEASE_BASE = "https://github.com/PurpleI2P/i2pd/releases/download"
_ALLOWED_DOWNLOAD_HOSTS = ("github.com", "githubusercontent.com")

# Dedicated loopback ports. None → pick a free ephemeral port at launch (i2pd
# has no "auto" port token, so we probe one ourselves). proxy_url() always
# reflects the real port, so callers never hardcode it. Pin to a fixed int if
# you need a stable port across runs. Always bound to 127.0.0.1 only.
HTTP_PROXY_PORT: int | None = None
SAM_PORT: int | None = None

# Where i2pd keeps its data (netdb, router keys, our destination keys, log).
# None → platformdirs.user_data_dir(APP_NAME)/i2pd_data. Persistent by default
# so warm starts skip a full reseed.
DATA_DIR: Path | None = None

# Seconds to wait for i2pd to reseed and build client tunnels (readiness is
# probed over the SAM bridge). Cold first-run bootstrap can take 1-5 minutes,
# noticeably slower than Tor.
BOOTSTRAP_TIMEOUT = 300.0

# Seconds allowed for the one-time binary download.
_DOWNLOAD_TIMEOUT = 600

# Free-space buffer required before auto-download (archive + extracted tree +
# netdb headroom once reseeded).
_INSTALL_FREE_BYTES = 200 * 1024 * 1024

_I2PD_LOG_NAME = "i2pd.log"

# Default session id / key name for the process-wide identity.
_DEFAULT_NAME = "default"

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class I2PError(RuntimeError):
    """Base class for everything this package raises."""


class I2PBinaryNotFound(I2PError):
    """i2pd binary missing and auto-download failed (or platform unsupported)."""


class I2PBootstrapTimeout(I2PError):
    """i2pd did not reseed and build tunnels in time."""


class I2PDataDirLocked(I2PError):
    """The data directory is locked by another running i2pd process."""


# Re-export SAMError so callers can catch SAM failures without importing the
# private module. (It is defined in _sam to keep that module standalone.)
__all__ = [
    "ensure_running", "start", "is_running", "proxy_url", "stop", "i2pd_version",
    "my_destination", "host_service", "connect", "listen",
    "I2PSocket", "I2PListener", "b32_address",
    "I2PError", "I2PBinaryNotFound", "I2PBootstrapTimeout", "I2PDataDirLocked",
    "SAMError",
    "I2PD_VERSION", "HTTP_PROXY_PORT", "SAM_PORT", "DATA_DIR", "BOOTSTRAP_TIMEOUT",
]

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


def _base_dir() -> Path:
    """Package directory — respects PyInstaller one-file bundles."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


# Platform keys match the official archive naming: PurpleI2P publishes static
# builds only for Windows x86_64 and macOS x86_64 (the macOS build runs on
# Apple Silicon via Rosetta 2). Linux has no portable official build — every
# release .deb/.rpm dynamic-links distro-specific boost/openssl — so Linux
# uses a system i2pd instead (see _raise_use_system_i2pd).
_SUPPORTED_PLATFORMS = ("win64", "osx")


def _platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "windows":
        if machine in ("amd64", "x86_64"):
            return "win64"
        _raise_use_system_i2pd(system, machine, f"windows/{machine}")
    if system == "darwin":
        # The macOS build is x86_64 but runs on arm64 Macs via Rosetta 2.
        if machine in ("x86_64", "amd64", "arm64", "aarch64"):
            return "osx"
    if system == "linux":
        _raise_use_system_i2pd(system, machine, f"linux/{machine}")

    _raise_use_system_i2pd(system, machine, f"{system}/{machine}")


def _raise_use_system_i2pd(system: str, machine: str, label: str) -> NoReturn:
    """Raise a helpful error for a platform with no static i2pd build.

    We can still run if the user has a system i2pd on PATH — that path is tried
    before download in _find_or_install_i2pd — so point them at it rather than
    dead-ending. This is the normal path on Linux.
    """
    if system == "linux":
        hint = (
            "  Debian/Ubuntu:  sudo apt install i2pd\n"
            "  Fedora:         sudo dnf install i2pd\n"
            "  Arch:           sudo pacman -S i2pd\n"
            "  Official repo:  https://repo.i2pd.xyz\n"
        )
    else:
        hint = "  Install i2pd via your package manager.\n"
    manual = _manual_binary_path()
    raise I2PBinaryNotFound(
        f"No official static i2pd build for {label}.\n"
        f"  Auto-download is available for: {', '.join(_SUPPORTED_PLATFORMS)}.\n"
        f"  basic_i2p will use an `i2pd` binary already on your PATH if present:\n"
        f"{hint}"
        f"  …or place an i2pd binary manually at:\n"
        f"    {manual}"
    )


def _binary_name() -> str:
    return "i2pd.exe" if sys.platform == "win32" else "i2pd"


def _manual_binary_path() -> Path:
    """Drop-in location for platforms with no static build (keyed by raw
    system-machine, which _platform_key() rejects)."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    return Path(user_data_dir(APP_NAME)) / "bin" / f"{system}-{machine}" / _binary_name()


# ---------------------------------------------------------------------------
# Install paths
# ---------------------------------------------------------------------------


def _install_root() -> Path:
    """Where this version's extracted archive tree lives.

    Versioned so bumping I2PD_VERSION installs alongside the old tree. Written
    under user_data_dir, never into site-packages (a trust boundary owned by
    the package manager).
    """
    return Path(user_data_dir(APP_NAME)) / "i2pd" / I2PD_VERSION / _platform_key()


def _user_binary_path() -> Path:
    return _install_root() / _binary_name()


def _bundled_binary_path() -> Path:
    """Path inside the installed wheel — for pre-placed binaries
    (PyInstaller / Briefcase / air-gapped deploys)."""
    return _base_dir() / "bin" / _platform_key() / _binary_name()


def _certificates_dir() -> Path:
    """Reseed/family certificates shipped in the wheel.

    i2pd needs these to verify the signed reseed bundle when building netdb
    from scratch. The official Windows archive ships them; the macOS archive
    does not, so we bundle a copy (taken from a GPG-verified release) and
    always point i2pd at it with --certsdir, so reseed works on every platform.
    """
    return _base_dir() / "certificates"


def _get_data_dir() -> Path:
    if DATA_DIR is not None:
        return Path(DATA_DIR)
    return Path(user_data_dir(APP_NAME)) / "i2pd_data"


def _keys_dir() -> Path:
    return _get_data_dir() / "basic_i2p_keys"


# ---------------------------------------------------------------------------
# Download + verify + extract
# ---------------------------------------------------------------------------


# i2pd versions look like "2.60.0". We interpolate this into a URL, so anything
# outside this shape (traversal, query injection, whitespace) is rejected
# before it reaches the network.
_VERSION_RE = re.compile(r"^\d+\.\d+(\.\d+)?$")

# Hardening caps for extraction. Real archives are well under 20 MB extracted
# across a shallow tree of a few dozen files; anything materially larger,
# deeper, or more numerous is suspect. The SHA-512 gate runs before extraction,
# so these are defence-in-depth — they bound the damage if that gate is ever
# bypassed or misconfigured.
_MAX_MEMBER_BYTES = 128 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_MEMBERS = 4096
_MAX_PATH_DEPTH = 8
_MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024


def _archive_name() -> str:
    key = _platform_key()
    if key == "win64":
        return f"i2pd_{I2PD_VERSION}_win64_mingw.zip"
    return f"i2pd_{I2PD_VERSION}_osx.tar.gz"


def _archive_url() -> str:
    if not _VERSION_RE.match(I2PD_VERSION):
        raise I2PBinaryNotFound(
            f"Refusing to download with malformed I2PD_VERSION {I2PD_VERSION!r}. "
            f"Expected something like '2.60.0'."
        )
    return f"{_RELEASE_BASE}/{I2PD_VERSION}/{_archive_name()}"


def _check_redirect_origin(final_url: str) -> None:
    parsed = urlparse(final_url)
    # Scheme pin as well as host pin: a 30x downgrade to plain http on an
    # *allowed* host would otherwise hand the transfer to any on-path MitM.
    # The SHA-512 gate still rejects bad bytes, but there is no reason to ever
    # fetch over plaintext.
    if parsed.scheme != "https":
        raise I2PBinaryNotFound(f"Refusing non-HTTPS download URL {final_url!r}.")
    host = (parsed.hostname or "").lower()
    for allowed in _ALLOWED_DOWNLOAD_HOSTS:
        if host == allowed or host.endswith("." + allowed):
            return
    raise I2PBinaryNotFound(
        f"Refusing to follow redirect to unexpected host {host!r}. "
        f"Allowed: {', '.join(_ALLOWED_DOWNLOAD_HOSTS)}."
    )


class _PinnedRedirectAdapter(requests.adapters.HTTPAdapter):
    """HTTP adapter that re-checks the host pin at every redirect hop.

    Plain ``allow_redirects=True`` only lets us inspect the *final* URL — a 30x
    chain through attacker.example (with valid TLS) would still leak request
    headers before landing back on a trusted host. Walk the chain manually and
    enforce the origin pin on each hop.
    """

    def send(self, request, **kwargs):  # type: ignore[override]
        kwargs.pop("allow_redirects", None)
        resp = super().send(request, **kwargs)
        seen = 0
        while resp.is_redirect and seen < 30:
            seen += 1
            next_url = resp.headers.get("Location", "")
            if not next_url:
                break
            next_url = urljoin(resp.url, next_url)
            _check_redirect_origin(next_url)
            try:
                resp.close()
            except Exception:
                pass
            new_req = request.copy()
            new_req.url = next_url
            resp = super().send(new_req, **kwargs)
        if resp.is_redirect:
            raise I2PBinaryNotFound(
                f"Gave up after {seen} redirects downloading {request.url!r} "
                f"(last hop {resp.url!r})."
            )
        return resp


def _download_session() -> requests.Session:
    try:
        from urllib3.util.retry import Retry
    except ImportError:  # very old urllib3
        from requests.packages.urllib3.util.retry import Retry  # type: ignore

    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=(502, 503, 504, 520, 522, 524),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = _PinnedRedirectAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def _download(url: str, dest: Path, timeout: int = _DOWNLOAD_TIMEOUT) -> str:
    """Stream ``url`` into ``dest``, returning the SHA-512 hex digest.

    Aborts early if the byte count exceeds _MAX_DOWNLOAD_BYTES — the hash check
    is still the fail-closed gate, this just bounds the resource cost of a
    hostile or misconfigured origin.
    """
    logger.info("Downloading %s", url)
    hasher = hashlib.sha512()
    received = 0
    last_pct = -1
    dest.parent.mkdir(parents=True, exist_ok=True)
    with _download_session() as session, session.get(url, stream=True, timeout=timeout) as r:
        _check_redirect_origin(r.url)
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))
        with open(dest, "wb") as fh:
            for chunk in r.iter_content(chunk_size=1 << 16):
                if not chunk:
                    continue
                received += len(chunk)
                if received > _MAX_DOWNLOAD_BYTES:
                    raise I2PBinaryNotFound(
                        f"Refusing to download more than {_MAX_DOWNLOAD_BYTES} bytes "
                        f"from {url}. Origin misbehaving or version points at something "
                        f"unexpected."
                    )
                hasher.update(chunk)
                fh.write(chunk)
                if total:
                    pct = received * 100 // total
                    if pct >= last_pct + 10:
                        logger.info("  %3d%%  (%d / %d bytes)", pct, received, total)
                        last_pct = pct
    return hasher.hexdigest().lower()


def _expected_sha512() -> str:
    """The SHA-512 we require for this version+platform.

    Only the baked-in table is trusted. Fetching the companion SHA512SUMS from
    the same origin is refused: whoever controls the release controls both.
    New versions must have their hash committed to i2pd_checksums.py first.
    """
    baked = i2pd_checksums.known_checksum(I2PD_VERSION, _platform_key())
    if baked is not None:
        return baked.lower()
    raise I2PBinaryNotFound(
        f"No baked-in SHA-512 for i2pd {I2PD_VERSION}/{_platform_key()}. "
        f"Refusing to fetch a digest from the same origin as the archive — that "
        f"defeats verification. Run scripts/refresh_checksums.py {I2PD_VERSION} "
        f"and reinstall, or pin basic_i2p.I2PD_VERSION to a version already in "
        f"the table."
    )


def _safe_member_name(name: str) -> bool:
    if not name or name.startswith(("/", "\\")):
        return False
    # Validate under both path flavours regardless of host OS: a member named
    # "C:evil" or "..\\x" is not absolute and has no ".." part when parsed as
    # POSIX, but joining it under dest_root on Windows escapes the tree.
    for p in (PurePosixPath(name), PureWindowsPath(name)):
        if p.is_absolute() or p.drive:
            return False
        parts = [part for part in p.parts if part not in ("", ".")]
        if not 0 < len(parts) <= _MAX_PATH_DEPTH:
            return False
        if any(part == ".." for part in parts):
            return False
    return True


def _copy_capped(src: Any, out: Any, name: str, cap: int) -> int:
    """copyfileobj with a hard cap on bytes written; returns bytes written.

    Zip central-directory ``file_size`` is attacker-writable metadata; the only
    number that counts is how much actually inflates. ``cap`` is the smaller of
    the per-member cap and whatever remains of the whole-archive budget.
    """
    written = 0
    while True:
        chunk = src.read(1 << 16)
        if not chunk:
            return written
        written += len(chunk)
        if written > cap:
            raise I2PBinaryNotFound(
                f"Archive member {name!r} inflated past the "
                f"{cap}-byte cap — refusing to extract further."
            )
        out.write(chunk)


def _extract_zip(archive_path: Path, dest_root: Path) -> None:
    dest_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        if len(infos) > _MAX_MEMBERS:
            raise I2PBinaryNotFound(
                f"Archive has {len(infos)} members — exceeds the {_MAX_MEMBERS} cap."
            )
        for info in infos:
            # Directory entries carry a trailing "/"; validate the path either
            # way — a hostile dir entry like "../x/" escapes just as surely as
            # a file would.
            name = info.filename.rstrip("/\\") if info.is_dir() else info.filename
            if not _safe_member_name(name):
                raise I2PBinaryNotFound(f"Refusing archive member with unsafe path: {info.filename!r}")
            if not info.is_dir() and info.file_size > _MAX_MEMBER_BYTES:
                raise I2PBinaryNotFound(
                    f"Archive member {name!r} is {info.file_size} bytes — exceeds the "
                    f"{_MAX_MEMBER_BYTES}-byte cap."
                )
        total = 0
        for info in infos:
            name = info.filename
            if info.is_dir():
                (dest_root / name.rstrip("/\\")).mkdir(parents=True, exist_ok=True)
                continue
            target = dest_root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                total += _copy_capped(
                    src, out, name, min(_MAX_MEMBER_BYTES, _MAX_TOTAL_BYTES - total)
                )


def _extract_tar(archive_path: Path, dest_root: Path) -> None:
    dest_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(str(archive_path), mode="r:gz") as tf:
        members = tf.getmembers()
        if len(members) > _MAX_MEMBERS:
            raise I2PBinaryNotFound(
                f"Archive has {len(members)} members — exceeds the {_MAX_MEMBERS} cap."
            )
        for m in members:
            if not (m.isfile() or m.isdir()):
                raise I2PBinaryNotFound(
                    f"Refusing archive member of unexpected type "
                    f"({'symlink' if m.issym() or m.islnk() else 'special'}): {m.name!r}"
                )
            if not _safe_member_name(m.name):
                raise I2PBinaryNotFound(f"Refusing archive member with unsafe path: {m.name!r}")
            if m.isfile() and m.size > _MAX_MEMBER_BYTES:
                raise I2PBinaryNotFound(
                    f"Archive member {m.name!r} is {m.size} bytes — exceeds the "
                    f"{_MAX_MEMBER_BYTES}-byte cap."
                )
        total = 0
        for m in members:
            target = dest_root / m.name
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            # Cap on bytes actually produced, not the header's size field —
            # same rule as the zip path.
            with src, open(target, "wb") as out:
                total += _copy_capped(
                    src, out, m.name, min(_MAX_MEMBER_BYTES, _MAX_TOTAL_BYTES - total)
                )
            if m.mode & 0o111:
                target.chmod(target.stat().st_mode | stat.S_IXUSR)


def _extract_archive(archive_path: Path, dest_root: Path) -> None:
    if _platform_key() == "win64":
        _extract_zip(archive_path, dest_root)
    else:
        _extract_tar(archive_path, dest_root)


def _check_disk_space(target: Path) -> None:
    probe = target
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        free = shutil.disk_usage(probe).free
    except OSError:
        return  # best-effort
    if free < _INSTALL_FREE_BYTES:
        raise I2PBinaryNotFound(
            f"Not enough disk space to install i2pd: {free // (1024 * 1024)} MB free at "
            f"{probe}, need at least {_INSTALL_FREE_BYTES // (1024 * 1024)} MB."
        )


def _write_provenance(root: Path, url: str, sha512_hex: str) -> None:
    prov = root / ".provenance.json"
    data = {
        "i2pd_version": I2PD_VERSION,
        "url": url,
        "sha512": sha512_hex,
        "verification": "baked-in",
        "installed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": _platform_key(),
    }
    try:
        prov.write_text(json.dumps(data, indent=2))
    except OSError:
        pass


def _auto_download_i2pd(root: Path) -> None:
    url = _archive_url()
    expected = _expected_sha512()
    _check_disk_space(root.parent)

    root.mkdir(parents=True, exist_ok=True)
    archive_tmp = root / (_archive_name() + ".partial")
    archive_tmp.unlink(missing_ok=True)

    try:
        actual = _download(url, archive_tmp)
    except (requests.RequestException, OSError) as exc:
        archive_tmp.unlink(missing_ok=True)
        raise I2PBinaryNotFound(
            f"Failed to download i2pd {I2PD_VERSION} for {_platform_key()} from {url}: {exc}"
        ) from exc
    if not hmac.compare_digest(actual, expected):
        archive_tmp.unlink(missing_ok=True)
        raise I2PBinaryNotFound(
            f"SHA-512 mismatch for i2pd {I2PD_VERSION} ({_platform_key()}): "
            f"expected {expected}, got {actual}. Refusing to install an unverified binary."
        )

    # Extract into a sibling staging dir, then atomic-rename the tree into place
    # so an interrupted extract never leaves a half-populated install.
    staging = root.parent / (root.name + ".staging")
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    try:
        _extract_archive(archive_tmp, staging)
        binary = staging / _binary_name()
        if not binary.exists():
            raise I2PBinaryNotFound(
                f"i2pd binary not found inside archive for {_platform_key()} "
                f"(expected {_binary_name()} at the archive root)."
            )
        _ensure_exec(binary)
        if root.exists():
            shutil.rmtree(root, ignore_errors=True)
        os.replace(staging, root)
    finally:
        archive_tmp.unlink(missing_ok=True)
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)

    _write_provenance(root, url, expected)
    logger.info("i2pd %s installed at %s (verified via baked-in SHA-512)", I2PD_VERSION, root)


def _find_or_install_i2pd() -> Path:
    """user_data_dir install → bundled wheel → system PATH → auto-download.

    A pre-placed binary in user_data_dir wins so air-gapped/pre-vetted installs
    are honoured; a wheel-bundled binary wins next (PyInstaller/Briefcase); then
    a system ``i2pd`` on PATH (the only route on Linux); finally auto-download.
    """
    try:
        _platform_key()
    except I2PBinaryNotFound:
        # No static build for this platform (e.g. Linux), so the bundle-shaped
        # paths below can't exist. Honour the escape hatches the error message
        # advertises — a manually placed binary, then a system i2pd on PATH —
        # before giving up.
        manual = _manual_binary_path()
        if manual.exists():
            _ensure_exec(manual)
            return manual
        on_path = shutil.which("i2pd")
        if on_path:
            logger.info("Using system-installed i2pd at %s", on_path)
            return Path(on_path)
        raise

    user = _user_binary_path()
    if user.exists():
        _ensure_exec(user)
        return user

    bundled = _bundled_binary_path()
    if bundled.exists():
        _ensure_exec(bundled)
        return bundled

    on_path = shutil.which("i2pd")
    if on_path:
        logger.info("Using system-installed i2pd at %s", on_path)
        return Path(on_path)

    logger.info("i2pd binary not found locally — downloading %s…", I2PD_VERSION)
    _auto_download_i2pd(_install_root())
    return _user_binary_path()


#: Routers older than this are named as the likely cause when one aborts.
#: Observed: Ubuntu 24.04's packaged 2.49.0 aborts (SIGABRT) about 30
#: seconds after every start; 3.0.0 runs for days. 2.50.0 is the release
#: after the one seen to fail -- assumed good, not observed. Move it when a
#: version is seen either way.
_OLDEST_GOOD_I2PD = (2, 50, 0)


def _router_version(binary: Path | None) -> tuple[int, ...] | None:
    """`i2pd --version`, as numbers, or None if it cannot be had. Not asked
    on Windows, which always runs the pinned build and would flash a console
    window for it."""
    if binary is None or sys.platform == "win32":
        return None
    try:
        out = subprocess.run(
            [str(binary), "--version"], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"i2pd version (\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(g) for g in m.groups()) if m else None


def _old_router_text(version: tuple[int, ...] | None) -> str:
    """A sentence naming a router older than any seen to stay up, and where
    to get a current one; empty for any other."""
    if version is None or version >= _OLDEST_GOOD_I2PD:
        return ""
    found = ".".join(map(str, version))
    return (
        f" This i2pd is {found}, older than any seen to stay up on today's "
        "network (Ubuntu 24.04 ships 2.49.0, which aborts within a minute). "
        "Install a current one: https://repo.i2pd.xyz or, on Ubuntu, "
        "`sudo add-apt-repository ppa:purplei2p/i2pd && sudo apt update && "
        "sudo apt install i2pd`."
    )


def _old_router_hint(binary: Path | None) -> str:
    """:func:`_old_router_text` for the router at `binary`."""
    return _old_router_text(_router_version(binary))


def _ensure_exec(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    except OSError as exc:
        logger.warning("could not chmod %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _secure_mkdir(path: Path, mode: int = 0o700) -> None:
    """Create ``path`` (and parents) with restrictive ``mode`` on POSIX.

    The data dir holds our destination private keys, so 0700 keeps them from
    other users on a shared host.
    """
    path = Path(path)
    if path.exists():
        if os.name == "posix":
            try:
                os.chmod(path, mode)
            except OSError:
                pass
        return
    parent = path.parent
    if parent != path and not parent.exists():
        _secure_mkdir(parent, mode=mode)
    if os.name == "posix":
        try:
            os.mkdir(str(path), mode)
        except FileExistsError:
            return
        try:
            os.chmod(str(path), mode)
        except OSError:
            pass
    else:
        path.mkdir(parents=True, exist_ok=True)


def _free_tcp_port() -> int:
    """Grab a free loopback port. There is an unavoidable race between closing
    the probe socket and i2pd binding it, but on a single-user box it is
    effectively never lost, and a genuine clash surfaces as a startup error."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _listener_inodes(port: int) -> set[str] | None:
    """Socket inodes of LISTEN sockets on ``port``, from /proc/net/tcp{,6}.

    Returns None where /proc isn't available (non-Linux) — the caller treats
    that as indeterminate, never as failure.
    """
    inodes: set[str] = set()
    readable = False
    for name in ("tcp", "tcp6"):
        try:
            text = Path(f"/proc/net/{name}").read_text()
        except OSError:
            continue
        readable = True
        for line in text.splitlines()[1:]:
            parts = line.split()
            # local_address is "HEXADDR:HEXPORT"; st 0A is LISTEN; col 9 is inode.
            if len(parts) < 10 or parts[3] != "0A":
                continue
            _, _, port_hex = parts[1].partition(":")
            try:
                if int(port_hex, 16) == port:
                    inodes.add(parts[9])
            except ValueError:
                continue
    return inodes if readable else None


def _pid_owns_any_inode(pid: int, inodes: set[str]) -> bool | None:
    """Whether process ``pid`` holds any of the given socket inodes among its
    fds. None if /proc/<pid>/fd can't be read (gone, or no permission)."""
    fd_dir = Path(f"/proc/{pid}/fd")
    try:
        entries = list(fd_dir.iterdir())
    except OSError:
        return None
    held = set()
    for fd in entries:
        try:
            held.add(os.readlink(str(fd)))
        except OSError:
            continue
    return any(f"socket:[{inode}]" in held for inode in inodes)


def _verify_port_owner(port: int, pid: int) -> bool | None:
    """Best-effort check that the listener on loopback ``port`` is process
    ``pid``. True/False when determinable (Linux), None otherwise.

    Why: ports are probed as free before i2pd launches, so a hostile local
    process could win the bind race and impersonate the SAM bridge — and a
    SESSION CREATE against a fake bridge would hand it the destination
    private key. Positive mismatch must therefore fail closed.
    """
    inodes = _listener_inodes(port)
    if inodes is None or not inodes:
        return None  # non-Linux, or listener not visible yet — indeterminate
    return _pid_owns_any_inode(pid, inodes)


# ---------------------------------------------------------------------------
# I2pdManager — process-singleton router lifecycle + SAM sessions
# ---------------------------------------------------------------------------


class I2pdManager:
    """Manages the i2pd subprocess and SAM sessions for the process lifetime."""

    def __init__(self) -> None:
        self._binary: Path | None = None
        #: why a router this old may die, said when it does; empty if not old
        self._old_router = ""
        self._data_dir: Path | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._log_path: Path | None = None
        self._http_port: int | None = None
        self._sam_port: int | None = None
        self._sessions: dict[str, SamSession] = {}
        # name → persistent flag it was opened with; a later call asking for
        # the other kind must fail, not silently hand back the wrong identity.
        self._session_kinds: dict[str, bool] = {}
        self._initialised = False

    # ---------------- startup ----------------

    def start(self, timeout: float) -> None:
        # Guard on liveness, not just the flag: a crashed i2pd leaves
        # _initialised True but a dead process, so re-entry must relaunch.
        if self.is_running():
            return
        self._initialised = False

        # A relaunch (crash recovery, stop→start) gets fresh ports; any session
        # from the previous router is dead even though its local state still
        # says open. Drop them so callers get freshly created sessions.
        for session in self._sessions.values():
            session.close()
        self._sessions.clear()
        self._session_kinds.clear()

        self._binary = _find_or_install_i2pd()
        # Asked once, before launching: a router known to abort is said up
        # front, and named again if it does, after startup or during it.
        self._old_router = _old_router_text(_router_version(self._binary))
        if self._old_router:
            logger.warning("%s", self._old_router.strip())
        self._data_dir = _get_data_dir()
        _secure_mkdir(self._data_dir, mode=0o700)
        _secure_mkdir(_keys_dir(), mode=0o700)

        self._http_port = HTTP_PROXY_PORT if HTTP_PROXY_PORT is not None else _free_tcp_port()
        self._sam_port = SAM_PORT if SAM_PORT is not None else _free_tcp_port()

        self._launch()
        try:
            self._await_ready(timeout)
        except BaseException:
            self._kill_process()
            raise

        _ensure_atexit_registered()
        self._initialised = True
        logger.info("i2pd ready — HTTP proxy 127.0.0.1:%s, SAM 127.0.0.1:%s, data dir %s",
                    self._http_port, self._sam_port, self._data_dir)

    def _launch(self) -> None:
        assert self._binary is not None and self._data_dir is not None
        self._log_path = self._data_dir / _I2PD_LOG_NAME
        certs = _certificates_dir()

        cmd = [
            str(self._binary),
            "--datadir", str(self._data_dir),
            # No --daemon: i2pd runs in the foreground by default, which is what
            # we want (we manage it as a subprocess). --daemon is a bare switch,
            # not a boolean option, so passing it a value is a hard error.
            "--log=file", f"--logfile={self._log_path}", "--loglevel=warn",
            # I2P-only: we never configure an outproxy, so i2pd's HTTP proxy
            # returns an error for a clearnet host rather than leaking it to an
            # exit. No outproxy is i2pd's default and we run on a fresh data
            # dir with no i2pd.conf, so the default holds. (We can't pass
            # `--httpproxy.outproxy=` to force it — i2pd rejects an empty value
            # after the equals sign — but the default is exactly what we want.)
            "--httpproxy.enabled=true",
            "--httpproxy.address=127.0.0.1",
            f"--httpproxy.port={self._http_port}",
            # SAM drives hosting and P2P sockets; SOCKS is redundant, keep it off.
            "--socksproxy.enabled=false",
            "--sam.enabled=true",
            "--sam.address=127.0.0.1",
            f"--sam.port={self._sam_port}",
            # Trim the local attack surface: no web console, no UPnP port maps.
            "--http.enabled=false",
            "--upnp.enabled=false",
        ]
        # Point i2pd at the bundled reseed/family certs when we have them, so
        # a from-scratch reseed can verify the signed bundle on any platform.
        if certs.is_dir():
            cmd += ["--certsdir", str(certs)]

        popen_kwargs: dict[str, Any] = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        self._process = subprocess.Popen(cmd, **popen_kwargs)
        logger.info("i2pd started (pid %d)", self._process.pid)

    def _await_ready(self, timeout: float) -> None:
        """Wait until the SAM bridge answers and a probe session can be created.

        A successful SESSION CREATE means i2pd has reseeded and built client
        tunnels — the real readiness signal, more meaningful than a log scrape.
        """
        deadline = time.monotonic() + timeout
        assert self._sam_port is not None

        # 1) Wait for the SAM port to accept a HELLO.
        while time.monotonic() < deadline:
            self._check_alive()
            if self._sam_hello_ok():
                break
            time.sleep(0.5)
        else:
            raise I2PBootstrapTimeout(
                f"i2pd SAM bridge did not come up within {timeout:.0f}s. "
                f"See log: {self._log_path}"
            )

        # 2) Before anything sensitive crosses these ports, make sure they are
        # actually served by *our* i2pd. The free-port probe races the bind: a
        # hostile local process that wins it could impersonate the SAM bridge
        # (and receive destination private keys) or the HTTP proxy (and read
        # or spoof proxied traffic). Only determinable on Linux; a positive
        # mismatch is a hard stop.
        self._verify_ports_owned()

        # 3) Wait for a probe STREAM session (transient) to build tunnels.
        while time.monotonic() < deadline:
            self._check_alive()
            remaining = max(1.0, deadline - time.monotonic())
            probe = SamSession(
                "127.0.0.1", self._sam_port,
                session_id=f"basic-i2p-probe-{secrets.token_urlsafe(9)}",
                timeout=30.0, create_timeout=remaining,
            )
            try:
                probe.create()
                probe.close()
                return
            except OSError:
                # The router going away mid-probe surfaces as a refused or
                # reset connection: say that it died, and why, if it did.
                probe.close()
                self._check_alive()
                raise
            except SAMError as exc:
                probe.close()
                # DUPLICATED_ID shouldn't happen (unique id), but any transient
                # SAM error here just means "not ready yet" — retry until deadline.
                logger.debug("probe session not ready: %s", exc)
                time.sleep(2.0)
        raise I2PBootstrapTimeout(
            f"i2pd did not finish building tunnels within {timeout:.0f}s. "
            f"Network may be blocking I2P. See log: {self._log_path}"
        )

    def _verify_ports_owned(self) -> None:
        assert self._process is not None
        pid = self._process.pid
        for label, port in (("SAM bridge", self._sam_port),
                            ("HTTP proxy", self._http_port)):
            if port is None:
                continue
            if _verify_port_owner(port, pid) is False:
                raise I2PError(
                    f"The {label} port 127.0.0.1:{port} is served by a process "
                    f"other than the i2pd we launched (pid {pid}). Refusing to "
                    f"use it — a local process may be impersonating the router. "
                    f"Stop whatever holds that port, or pin a different port."
                )

    def _sam_hello_ok(self) -> bool:
        assert self._sam_port is not None
        try:
            with socket.create_connection(("127.0.0.1", self._sam_port), timeout=5) as s:
                s.sendall(b"HELLO VERSION MIN=3.1 MAX=3.1\n")
                data = s.recv(256)
            return b"RESULT=OK" in data
        except OSError:
            return False

    def _check_alive(self) -> None:
        if self._process and self._process.poll() is not None:
            tail = self._read_log_tail()
            lower = tail.lower()
            if "is already running" in lower or ("lock" in lower and "data" in lower):
                raise I2PDataDirLocked(
                    f"The i2pd data directory at {self._data_dir} is locked by another "
                    f"i2pd process. Only one i2pd can use a data dir at a time. Stop the "
                    f"other process or set basic_i2p.DATA_DIR to a different path.\n"
                    f"--- i2pd log tail ---\n{tail}"
                )
            code = self._process.returncode
            # Only an abort is blamed on the version: that is the failure
            # seen; any other exit has its own cause in the log below.
            hint = self._old_router if code == -signal.SIGABRT else ""
            raise I2PError(f"i2pd exited unexpectedly (code {code}).{hint}\n{tail}")

    def _read_log_tail(self, n_bytes: int = 4096) -> str:
        if not self._log_path or not self._log_path.exists():
            return "(no i2pd log yet)"
        try:
            with open(self._log_path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - n_bytes))
                return fh.read().decode(errors="replace")
        except OSError:
            return "(log unreadable)"

    # ---------------- identity / sessions ----------------

    @staticmethod
    def _check_name(name: str) -> str:
        """Identity names become SAM session ids and key filenames — restrict
        them up front so a bad one fails here with a clear message instead of
        deep in the SAM layer (or silently colliding key files after
        sanitisation)."""
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
            raise ValueError(
                f"invalid identity name {name!r}: use 1-64 characters from "
                f"letters, digits, '.', '_', '-'"
            )
        return name

    def _key_path(self, name: str) -> Path:
        return _keys_dir() / f"{self._check_name(name)}.dat"

    def _load_keypair(self, name: str) -> tuple[str, str] | None:
        path = self._key_path(name)
        try:
            data = json.loads(path.read_text())
            return data["pub"], data["priv"]
        except (OSError, ValueError, KeyError):
            return None

    def _save_keypair(self, name: str, pub: str, priv: str) -> None:
        path = self._key_path(name)
        # 0600 from the first byte (write_text-then-chmod leaves a
        # umask-readable window on the private key), and tmp+rename so a crash
        # mid-write can't leave a truncated key that silently rotates the
        # address next run. The 0700 keys dir is the outer wall; this is the
        # inner one.
        tmp = path.with_suffix(".dat.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(json.dumps({"pub": pub, "priv": priv}))
            os.replace(tmp, path)
        except OSError:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def _session(self, name: str, persistent: bool) -> SamSession:
        """Return the live STREAM session for ``name``, creating it once.

        Persistent sessions load/save their keypair so the ``.b32.i2p`` address
        is stable across runs; transient sessions get a fresh key each start.
        """
        assert self._sam_port is not None
        self._check_name(name)
        existing = self._sessions.get(name)
        if existing is not None and existing.is_open():
            if self._session_kinds.get(name) != persistent:
                have = "persistent" if self._session_kinds.get(name) else "transient"
                want = "persistent" if persistent else "transient"
                raise ValueError(
                    f"identity {name!r} is already open as a {have} session in "
                    f"this process; asking for a {want} one would silently hand "
                    f"back the wrong identity. Use a different name."
                )
            return existing

        pub = priv = None
        if persistent:
            loaded = self._load_keypair(name)
            if loaded is not None:
                pub, priv = loaded

        # The session id is a capability: SAM's STREAM CONNECT/ACCEPT/FORWARD
        # authenticate by id alone, and the bridge has no user auth. A
        # predictable id (name + pid) would let any local process attach
        # streams to this identity — so make it unguessable.
        session = SamSession(
            "127.0.0.1", self._sam_port,
            session_id=f"basic-i2p-{name}-{secrets.token_urlsafe(9)}",
            pub_b64=pub, priv_b64=priv,
        )
        session.create()
        if persistent:
            self._save_keypair(name, session.destination, session.private_key)
        self._sessions[name] = session
        self._session_kinds[name] = persistent
        return session

    def my_destination(self, name: str, persistent: bool) -> str:
        return self._session(name, persistent).b32

    def host_service(self, local_port: int, name: str, persistent: bool,
                     local_host: str) -> str:
        session = self._session(name, persistent)
        session.forward(local_port, host=local_host)
        return session.b32

    def open_session(self, name: str, persistent: bool) -> SamSession:
        return self._session(name, persistent)

    def sam_port(self) -> int:
        assert self._sam_port is not None
        return self._sam_port

    def http_port(self) -> int:
        assert self._http_port is not None
        return self._http_port

    def i2pd_version(self) -> str:
        """Best-effort router version, read from the log banner.

        SAM has no version-of-router query, so we scrape the startup line
        i2pd writes (``Daemon: i2pd vX.Y.Z starting``).
        """
        m = re.search(r"i2pd v(\d+\.\d+\.\d+)", self._read_log_tail(n_bytes=1 << 16))
        return m.group(1) if m else I2PD_VERSION

    def is_running(self) -> bool:
        return (
            self._initialised
            and self._process is not None
            and self._process.poll() is None
        )

    # ---------------- shutdown ----------------

    def stop(self) -> None:
        if not self._initialised and self._process is None:
            return
        logger.info("Shutting down i2pd…")
        for session in self._sessions.values():
            session.close()
        self._sessions.clear()
        self._session_kinds.clear()
        self._terminate_process()
        self._initialised = False

    def _terminate_process(self) -> None:
        proc = self._process
        if proc is None:
            return
        # SIGTERM triggers i2pd's immediate stop. (SIGINT would put it into a
        # 10-minute graceful shutdown — not what we want at exit.) Windows has
        # no SIGTERM; terminate() maps to TerminateProcess.
        if sys.platform == "win32":
            proc.terminate()
        else:
            proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self._process = None

    def _kill_process(self) -> None:
        """Hard stop used on a failed start — no graceful attempt."""
        for session in self._sessions.values():
            session.close()
        self._sessions.clear()
        self._session_kinds.clear()
        proc = self._process
        if proc is None:
            return
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass
        self._process = None
        self._initialised = False


# ---------------------------------------------------------------------------
# I2PListener — public wrapper around a SAM session's accept loop
# ---------------------------------------------------------------------------


class I2PListener:
    """A server endpoint that accepts inbound I2P streams.

    Returned by :func:`listen`. Each :meth:`accept` blocks until a peer dials
    this destination, then returns a connected :class:`I2PSocket`.

    ::

        listener = basic_i2p.listen()
        print("dial me:", listener.address)
        while True:
            conn = listener.accept()
            conn.sendall(b"hello")
            conn.close()
    """

    def __init__(self, session: SamSession, alive: Callable[[], bool] | None = None) -> None:
        self._session = session
        self._alive = alive
        self.address = session.b32

    def accept(self, timeout: float | None = None) -> I2PSocket:
        # Refuse to dial the SAM port once our router is gone: a dead router
        # frees the port, and accepting from whatever binds it next would let
        # a local process hand us spoofed "inbound" streams.
        if self._alive is not None and not self._alive():
            raise I2PError(
                "i2pd is no longer running — this listener is dead. "
                "Call basic_i2p.ensure_running() and listen() again."
            )
        return self._session.accept(timeout=timeout)

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> I2PListener:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Module-level singleton + public API
# ---------------------------------------------------------------------------

_manager: I2pdManager | None = None
_lock = threading.RLock()
_atexit_registered = False
_signals_installed = False
# Previous dispositions we displaced, so our handler can chain to them.
_prev_signal_handlers: dict[int, Any] = {}


def _ensure_atexit_registered() -> None:
    global _atexit_registered
    if not _atexit_registered:
        atexit.register(stop)
        _atexit_registered = True
    _install_signal_handlers()


# Signals whose default disposition terminates the process *without* running
# atexit — so without a handler here, `kill`, `docker stop`, and `systemctl
# stop` would all orphan i2pd. (SIGINT is absent on purpose: it raises
# KeyboardInterrupt, which unwinds through atexit already. SIGKILL is absent
# because it is uncatchable — see SECURITY.md.)
def _cleanup_signals() -> list[int]:
    names = ["SIGTERM", "SIGHUP"]
    out = []
    for name in names:
        sig = getattr(signal, name, None)
        if sig is not None:
            out.append(int(sig))
    return out


def _install_signal_handlers() -> None:
    """Stop i2pd on SIGTERM/SIGHUP, then chain to whatever was there before.

    signal.signal() only works on the main thread; if the first start happens
    on a worker thread we simply skip this (atexit still covers normal exit).
    We never clobber a handler silently — the previous disposition is saved and
    re-invoked, so a caller's own SIGTERM handling still runs.
    """
    global _signals_installed
    if _signals_installed:
        return
    if threading.current_thread() is not threading.main_thread():
        return
    for sig in _cleanup_signals():
        try:
            prev = signal.signal(sig, _handle_termination_signal)
        except (ValueError, OSError):
            continue  # not settable here (e.g. restricted environment)
        _prev_signal_handlers[sig] = prev
    _signals_installed = True


def _handle_termination_signal(signum: int, frame: Any) -> None:
    try:
        stop()
    finally:
        prev = _prev_signal_handlers.get(signum, signal.SIG_DFL)
        # Restore the prior disposition and let it take effect: chain to a
        # user callback if there was one, otherwise re-deliver so the default
        # action (terminate) still happens. SIG_IGN means "was ignored" — do
        # nothing and keep running, matching what the caller asked for.
        try:
            signal.signal(signum, prev if prev is not None else signal.SIG_DFL)
        except (ValueError, OSError):
            prev = signal.SIG_DFL
        if callable(prev):
            prev(signum, frame)
        elif prev != signal.SIG_IGN:
            os.kill(os.getpid(), signum)


def _get_manager() -> I2pdManager:
    global _manager
    if _manager is None:
        _manager = I2pdManager()
    return _manager


def _running_manager() -> I2pdManager:
    if _manager is None or not _manager.is_running():
        raise I2PError("i2pd is not running — call basic_i2p.ensure_running() first")
    return _manager


def ensure_running(timeout: float | None = None) -> str:
    """Start i2pd if it isn't already running; return the HTTP proxy URL.

    Idempotent: repeated calls return the same URL. On first call this may
    download and verify the i2pd binary (where a static build exists) and wait
    for the network to reseed and build tunnels (1-5 minutes). ``timeout``
    bounds that wait (default ``BOOTSTRAP_TIMEOUT``); the one-time download has
    its own longer timeout.

    The returned proxy is **I2P-only** — it has no outproxy, so requests to
    clearnet hosts fail closed instead of leaking.
    """
    if timeout is None:
        timeout = BOOTSTRAP_TIMEOUT
    with _lock:
        mgr = _get_manager()
        if not mgr.is_running():
            mgr.start(timeout)
        return proxy_url()


def start(timeout: float | None = None) -> str:
    """Alias for :func:`ensure_running` — symmetry with :func:`stop`."""
    return ensure_running(timeout)


def is_running() -> bool:
    """True if i2pd is running and ready in this process."""
    with _lock:
        return _manager is not None and _manager.is_running()


def proxy_url() -> str:
    """Return the I2P-only HTTP proxy URL. Raises if i2pd isn't running.

    Hand it to any HTTP client for fetching ``.i2p`` sites::

        proxy = basic_i2p.proxy_url()
        requests.get("http://notbob.i2p", proxies={"http": proxy, "https": proxy})
    """
    with _lock:
        return f"http://127.0.0.1:{_running_manager().http_port()}"


def i2pd_version() -> str:
    """Return the version of the running i2pd router (e.g. ``2.60.0``).

    Distinct from ``I2PD_VERSION`` (the pinned release basic_i2p downloads):
    this reflects whatever binary is actually running, including a system i2pd
    on Linux. Raises if i2pd isn't running.
    """
    with _lock:
        return _running_manager().i2pd_version()


def my_destination(name: str = _DEFAULT_NAME, persistent: bool = True) -> str:
    """Return this identity's ``.b32.i2p`` address, creating it if needed.

    With ``persistent=True`` (default) the destination key is saved in the data
    dir and reused, so the address is stable across runs. ``persistent=False``
    uses a fresh, unlinkable key each start. ``name`` selects among multiple
    identities. Raises if i2pd isn't running.
    """
    with _lock:
        return _running_manager().my_destination(name, persistent)


def host_service(local_port: int, name: str = _DEFAULT_NAME, persistent: bool = True,
                 local_host: str = "127.0.0.1") -> str:
    """Expose a local ``local_host:local_port`` server on I2P; return its ``.b32.i2p``.

    Inbound I2P streams to your destination are forwarded to the local port, so
    any TCP server (an HTTP app, an SSH daemon, …) gets an I2P address with no
    code changes and without exposing your IP. Persistent by default so the
    address stays the same across restarts. Raises if i2pd isn't running.
    """
    with _lock:
        return _running_manager().host_service(local_port, name, persistent, local_host)


def connect(dest: str, name: str = _DEFAULT_NAME, persistent: bool = True,
            timeout: float | None = None) -> I2PSocket:
    """Open a stream to another I2P destination; return a socket-like object.

    ``dest`` may be a ``.b32.i2p`` address, a full base64 destination, or a
    ``.i2p`` hostname (resolved via the router's address book). The returned
    :class:`I2PSocket` has ``sendall`` / ``send`` / ``recv`` / ``close`` and
    works as a context manager. ``name`` selects the local identity you dial
    *from*. Raises if i2pd isn't running or the peer can't be reached.
    """
    with _lock:
        session = _running_manager().open_session(name, persistent)
    # Dial outside the lock: a stream connect legitimately takes tunnel-build
    # time (up to minutes), and holding the module lock that long would block
    # every other API call. The dial uses its own SAM connection, so it needs
    # no shared state beyond the session id.
    return session.connect(dest, timeout=timeout)


def listen(name: str = _DEFAULT_NAME, persistent: bool = True) -> I2PListener:
    """Return an :class:`I2PListener` for accepting inbound streams.

    ``listener.address`` is your ``.b32.i2p`` destination to share with peers;
    ``listener.accept()`` blocks until one connects. Persistent by default so
    the address is stable across runs. Raises if i2pd isn't running.
    """
    with _lock:
        mgr = _running_manager()
        session = mgr.open_session(name, persistent)
        return I2PListener(session, alive=mgr.is_running)


def stop() -> None:
    """Stop the i2pd process if running. Safe to call repeatedly and at exit."""
    global _manager
    with _lock:
        if _manager is not None:
            _manager.stop()
