"""
Built-in SHA-512 checksums for the official i2pd release archives.

Why baked in: if the GitHub release (or a mirror in between) is compromised, an
attacker could swap both the archive and its ``SHA512SUMS`` companion.
Verifying against a hash that shipped inside the wheel — installed via signed
PyPI metadata — closes that gap. Unknown versions are refused outright rather
than fetching a digest from the same origin as the archive; that would defeat
the verification.

The refresh script (``scripts/refresh_checksums.py``) GPG-verifies PurpleI2P's
signed ``SHA512SUMS`` file against the pinned release-signing key (R4SAS)
before writing any hash here, so a value in this table has already passed a
signature check at author time. Runtime stays checksum-table-only and
fail-closed — no GPG dependency for end users.

To populate a new version: ``python scripts/refresh_checksums.py <version>``
"""

# Keyed by i2pd release version (the GitHub release tag, e.g. "2.60.0").
# Platform keys name the archives PurpleI2P actually publishes:
#   win64 → i2pd_<version>_win64_mingw.zip   (static Windows x86_64 build)
#   osx   → i2pd_<version>_osx.tar.gz        (static macOS x86_64 build; runs
#                                              on Apple Silicon via Rosetta 2)
# There is no portable official Linux build — Linux uses a system i2pd.
#
# {version: {platform_key: sha512_hex}}
CHECKSUMS: dict[str, dict[str, str]] = {
    "2.60.0": {
        "win64": "4aab1eb7bbdf997c59e537fd4ccb0b4aab2024747e6dd037680f57772cf12cd56a411717e141ed4a41e69f368ba64a7e083ae26aa532cead5d83687f76583ef9",
        "osx": "2fb9600cbacc157cf7d73404a4be6c56e85b545cb26de51d04eae49fff19ae43a6451f8ecf6faaca23599db1167b550ea6a18b7cc63137ba90a1c6c3f61e8ea6",
    },
}


def known_checksum(version: str, platform_key: str) -> "str | None":
    """Return the baked-in SHA-512 hex, or None if not in the table."""
    return CHECKSUMS.get(version, {}).get(platform_key) or None
