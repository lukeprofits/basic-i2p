#!/usr/bin/env python3
"""
Refresh src/basic_i2p/i2pd_checksums.py for an i2pd release version.

Fetches PurpleI2P's signed SHA512SUMS file for a GitHub release, GPG-verifies
it against the pinned i2pd release-signing key (R4SAS), extracts the hashes for
the archives basic_i2p auto-downloads, and rewrites the CHECKSUMS table.

GPG verification here is the trust gate; runtime verification in basic_i2p
stays checksum-only and needs no GPG.

Usage:
    python scripts/refresh_checksums.py 2.60.0

Requires `gpg` on PATH with the R4SAS key imported:
    curl -s https://repo.i2pd.xyz/r4sas.gpg | gpg --import
    # or:
    gpg --keyserver keys.openpgp.org --recv-keys \
        951928BB317024EFD053D73C66F6C87B98EBCFE2

Run this before bumping basic_i2p.I2PD_VERSION. Verify the diff, then commit.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import requests

RELEASE_BASE = "https://github.com/PurpleI2P/i2pd/releases/download"

# i2pd release-signing key: R4SAS (r4sas) <r4sas@i2pmail.org>. Matches the key
# PurpleI2P distributes at https://repo.i2pd.xyz/r4sas.gpg and the "Signed by
# r4sas" badge on every GitHub release.
I2PD_SIGNING_FPR = "951928BB317024EFD053D73C66F6C87B98EBCFE2"

# Platforms basic_i2p auto-downloads, mapped to the published archive name.
# Order preserved in the generated table. Linux has no portable official
# build, so it is deliberately absent (basic_i2p uses a system i2pd there).
ARCHIVES = {
    "win64": "i2pd_{version}_win64_mingw.zip",
    "osx": "i2pd_{version}_osx.tar.gz",
}

SUMS_NAME = "SHA512SUMS"


def _get(url: str) -> bytes:
    r = requests.get(url, timeout=60, allow_redirects=True)
    r.raise_for_status()
    return r.content


def _fetch(version: str, name: str) -> bytes:
    url = f"{RELEASE_BASE}/{version}/{name}"
    try:
        return _get(url)
    except requests.RequestException as exc:
        raise SystemExit(f"could not fetch {name} for {version} from {url}: {exc}") from exc


def gpg_verify(sums: bytes, sig: bytes) -> None:
    if not _have_gpg():
        raise SystemExit(
            "gpg not found on PATH. Install GnuPG and import the R4SAS key, "
            "or rerun with --no-gpg (NOT recommended)."
        )
    if not _key_present():
        raise SystemExit(
            f"i2pd release-signing key {I2PD_SIGNING_FPR} is not in your GPG keyring.\n"
            f"Import it, then retry:\n"
            f"  curl -s https://repo.i2pd.xyz/r4sas.gpg | gpg --import"
        )
    with tempfile.TemporaryDirectory() as td:
        sums_path = Path(td) / SUMS_NAME
        sig_path = Path(td) / (SUMS_NAME + ".asc")
        sums_path.write_bytes(sums)
        sig_path.write_bytes(sig)
        proc = subprocess.run(
            ["gpg", "--status-fd", "1", "--verify", str(sig_path), str(sums_path)],
            capture_output=True, text=True,
        )
    # Require exit 0 *and* a VALIDSIG status line naming the pinned key.
    # The return code alone is not enough — a valid signature from the *wrong*
    # key also exits 0 — and substring-matching the fingerprint anywhere in
    # the output would accept it out of an error message. Accept the pinned
    # fingerprint as either the signing-key fingerprint (field after VALIDSIG)
    # or the primary-key fingerprint (last field), in case a future release is
    # signed with a subkey.
    valid = False
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "[GNUPG:]" and parts[1] == "VALIDSIG":
            if I2PD_SIGNING_FPR in (parts[2], parts[-1]):
                valid = True
    if proc.returncode != 0 or not valid:
        raise SystemExit(
            f"GPG verification failed or wrong signer "
            f"(exit {proc.returncode}):\n{proc.stdout}{proc.stderr}"
        )
    print(f"GPG signature OK (signed by {I2PD_SIGNING_FPR}).")


def _have_gpg() -> bool:
    try:
        subprocess.run(["gpg", "--version"], capture_output=True, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def _key_present() -> bool:
    proc = subprocess.run(
        ["gpg", "--list-keys", I2PD_SIGNING_FPR], capture_output=True, text=True
    )
    return proc.returncode == 0


def parse_sums(sums_text: str, version: str) -> dict[str, str]:
    """Pull the sha512 for each archive basic_i2p auto-downloads."""
    wanted = {plat: tmpl.format(version=version) for plat, tmpl in ARCHIVES.items()}
    by_name = {}
    for line in sums_text.splitlines():
        parts = line.split()
        # SHA512SUMS uses "<hash> *<filename>" (binary-mode marker).
        if len(parts) == 2 and len(parts[0]) == 128:
            by_name[parts[1].lstrip("*")] = parts[0].lower()
    found: dict[str, str] = {}
    for plat, fname in wanted.items():
        sha = by_name.get(fname)
        if not sha or not re.fullmatch(r"[0-9a-f]{128}", sha):
            raise SystemExit(f"no valid sha512 for {fname} in {SUMS_NAME}")
        found[plat] = sha
    return found


def update_table(version: str, shas: dict[str, str], path: Path | None = None) -> None:
    if path is None:
        path = Path(__file__).resolve().parent.parent / "src" / "basic_i2p" / "i2pd_checksums.py"
    text = path.read_text()

    # Keep the trailing comma: dropping it breaks the dict when the replaced
    # entry is followed by another version. Use lambda replacements so hash
    # content is never interpreted as regex escapes.
    block = f'    "{version}": {{\n'
    for plat in ARCHIVES:
        block += f'        "{plat}": "{shas[plat]}",\n'
    block += "    },"

    pattern = re.compile(rf'    "{re.escape(version)}":\s*\{{[^}}]*\}},?', re.DOTALL)
    if pattern.search(text):
        text = pattern.sub(lambda _: block, text, count=1)
    else:
        text = re.sub(
            r"(CHECKSUMS:\s*dict\[str,\s*dict\[str,\s*str\]\]\s*=\s*\{)",
            lambda m: m.group(1) + "\n" + block,
            text,
            count=1,
        )
    path.write_text(text)
    print(f"Updated {path} with {version}:")
    for plat in ARCHIVES:
        print(f"  {plat:<6} {shas[plat][:16]}…")


def main() -> int:
    p = argparse.ArgumentParser(description="Refresh i2pd_checksums.py for an i2pd release")
    p.add_argument("version", help="i2pd release tag, e.g. 2.60.0")
    p.add_argument("--no-gpg", action="store_true",
                   help="skip GPG signature verification (NOT recommended)")
    args = p.parse_args()
    version = args.version.lstrip("v")

    print(f"Fetching {SUMS_NAME} for {version}…")
    sums = _fetch(version, SUMS_NAME)

    if args.no_gpg:
        print("WARNING: skipping GPG verification (--no-gpg). The recorded hashes "
              "are only as trustworthy as your TLS connection to GitHub.")
    else:
        sig = _fetch(version, SUMS_NAME + ".asc")
        gpg_verify(sums, sig)

    shas = parse_sums(sums.decode("utf-8", errors="replace"), version)
    update_table(version, shas)
    print("\nDone. Review the diff, then bump I2PD_VERSION in "
          "src/basic_i2p/__init__.py and commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
