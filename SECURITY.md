# Security model

basic_i2p runs the **official i2pd router**. It does not implement any part of
the I2P protocol itself. Your anonymity properties are exactly those of the
i2pd binary — the C++ router maintained by the PurpleI2P project — either
auto-downloaded from an official release (Windows/macOS) or installed from your
distribution (Linux).

## Supply-chain / binary trust

The threat we defend against: an attacker who can tamper with the binary you run.

1. **Pinned version.** `I2PD_VERSION` names an exact i2pd release. We never
   "latest".

2. **Origin allowlist.** Downloads are restricted to `github.com` and
   `githubusercontent.com` (where GitHub serves release-asset bytes) over TLS.
   A custom HTTP adapter re-checks the host on **every redirect hop**, so a 30x
   chain through a hostile host is refused before any request headers are sent
   — not just checked on the final URL.

3. **Baked-in SHA-512, fail-closed.** Every download is verified against a hash
   committed inside this package (and installed via signed PyPI metadata). We
   **never** fetch the checksum from the same origin as the archive — an
   attacker who controls the release controls both files, so that would be no
   check at all. An unknown version refuses to install rather than fetching a
   digest online.

4. **GPG-verified at author time.** `scripts/refresh_checksums.py` fetches the
   i2pd project's signed `SHA512SUMS` and **verifies its OpenPGP signature
   against the i2pd release-signing key** (R4SAS,
   `951928BB317024EFD053D73C66F6C87B98EBCFE2`) before recording any hash. So a
   value in `i2pd_checksums.py` has already passed a signature check. End users
   need no GPG — the fail-closed SHA-512 check inherits that trust.

5. **Hardened extraction.** The Windows archive is a tree (binary + certs +
   config samples); the macOS archive is a lone binary. Extraction validates
   every member of both `.zip` and `.tar.gz`: no absolute paths, no `..`
   traversal (checked under both POSIX and Windows path rules), regular
   files/directories only (symlinks/hardlinks/devices refused), per-member and
   total-size caps. Extraction stages to a sibling directory and atomically
   renames into place, so an interrupted install never leaves a half-populated
   tree.

6. **On Linux, your distro's binary.** There is no portable official i2pd
   build, so Linux uses the `i2pd` on your `PATH` — the signed, security-updated
   package from apt/dnf/pacman. We never download an unverifiable Linux binary.

7. **No pure-Python I2P.** We deliberately do not reimplement the router or use
   an unmaintained reimplementation. Those lag the real protocol's security
   fixes and are not audited to the standard the C++ i2pd is.

8. **Never writes to site-packages.** Any downloaded binary is cached under the
   per-user data dir, never inside the installed package (a trust boundary
   owned by your package manager).

## Reseed certificates

Building the netdb from scratch requires verifying a signed reseed bundle
against reseed-operator certificates. The Windows archive ships them; the macOS
archive does not. We therefore bundle a copy of the reseed/family certificates
**taken from a GPG-verified release** and point i2pd at them with `--certsdir`,
so reseed verification works identically on every platform. The certificates
are public and carry no secret material.

## Runtime isolation

- i2pd runs with its **own data directory** (created `0700`), separate from any
  system i2pd.
- The HTTP proxy and the SAM bridge bind to **`127.0.0.1` only**, on dedicated
  ports (default: free ports chosen at launch, never a fixed well-known port).
- The **web console** (`--http.enabled=false`) and **UPnP**
  (`--upnp.enabled=false`) are disabled, trimming the local and network attack
  surface.
- Destination private keys (the keys behind your `.i2p` addresses) are stored
  `0600` inside the `0700` data directory.

## Local attackers (shared hosts)

Loopback services are reachable by **every local user**, and i2pd offers no
authentication on its HTTP proxy or SAM bridge. What that means here, and what
we do about it:

- **Session hijack — mitigated.** SAM authenticates stream commands by session
  id alone. Ours are generated with `secrets` (unguessable), so another local
  process cannot attach `STREAM CONNECT`/`ACCEPT`/`FORWARD` to your identity by
  predicting the id.
- **Bridge impersonation via the port-bind race — verified on Linux.** Ports
  are probed as free before i2pd launches; a hostile local process could win
  that race and pose as the SAM bridge — and a `SESSION CREATE` against a fake
  bridge would hand it your destination private key. Before any session is
  created, we check via `/proc` that the listener on the SAM and proxy ports
  belongs to the i2pd process we launched, and **fail closed on a mismatch**.
  On Windows/macOS this check is not available; the race window there is the
  few hundred milliseconds between the port probe and i2pd's bind. If that
  residual window matters to you, pin `SAM_PORT`/`HTTP_PROXY_PORT` to ports you
  control by other means, or run inside an OS-level sandbox/container.
- **Dead-listener squatting — refused.** If the router dies, its ports are
  freed and could be re-bound by another local process. Listeners created by
  `listen()` check router liveness before each `accept()` and refuse to dial a
  port our router no longer owns; the module-level API re-checks liveness on
  every call.
- **Router use by other local users — not preventable.** Any local process can
  use the HTTP proxy to fetch `.i2p` sites through your router, or open its own
  SAM sessions (with their own keys) on it. i2pd has no auth knob for these;
  this affects any local i2pd, not just ours. It does not expose your keys or
  your sessions. On a multi-user host where this matters, isolate the process
  (container, dedicated user, network namespace).

## I2P-only — no clearnet exit

I2P is not an exit network, and basic_i2p does not turn it into one. The HTTP
proxy is launched with **no outproxy configured**, which is i2pd's default and
which we run on a fresh data dir to preserve. A request to a clearnet host is
answered by i2pd's own error page (HTTP 5xx) — the request never reaches the
clearnet host and cannot leak to a third-party exit. If you need anonymous
clearnet access, use a Tor-based tool such as basic-tor instead.

## Cleanup on exit, and the one case we can't handle

basic_i2p stops the router in every situation it can catch:

- **Normal exit, unhandled exception, or Ctrl-C** — an `atexit` handler runs
  `stop()`.
- **`SIGTERM` / `SIGHUP`** (`kill`, `docker stop`, `systemctl stop`) — a signal
  handler runs `stop()` and then chains to whatever disposition was in place
  before (a caller's own handler still runs; otherwise the default terminate
  proceeds). The handler is installed only when the first start happens on the
  main thread — the only place Python allows it — and it never silently
  replaces a handler you set.

The **one** case nothing can handle is `SIGKILL` of your process: it is
uncatchable by design, `atexit` never runs, and i2pd has no "exit if my parent
dies" mechanism (it exposes only `--pidfile`). If your process is `SIGKILL`ed,
the i2pd subprocess can be left running until you stop it or reboot. On a
shared or long-lived host, that is worth knowing.

## Reporting

Open an issue (or contact the maintainer privately for anything sensitive).
This wrapper's security depends on the i2pd router itself — I2P protocol issues
should go to the PurpleI2P project.
