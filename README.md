# basic-i2p

An intentionally tiny I2P library for Python. Zero setup, the real official i2pd router under the hood.

### Description

`basic-i2p` does exactly four things:

- Start [i2pd](https://i2pd.website/) and hand you an **I2P-only** HTTP proxy URL (`http://127.0.0.1:<port>`) for fetching `.i2p` sites
- Give any local service its own `.i2p` address (`host_service()`) so people reach it over I2P without ever seeing your IP
- Open peer-to-peer socket streams between I2P destinations (`connect()` / `listen()`)
- Stop cleanly

It does **not** reimplement I2P. It downloads, verifies, and runs the **official i2pd binary** — the C++ I2P router maintained by the [PurpleI2P](https://github.com/PurpleI2P/i2pd) project. Auto-downloaded on first use (where an official build exists), auto-shutdown on exit. No router to install, no config file to edit, no accounts.

I made `basic-i2p` because no other Python packages make it this simple. Everything else either assumes you already have an I2P router running and configured, or is an abandoned SAM binding with no router management at all.

**This is not for clearnet.** I2P is not an exit network, and browsing the clearnet over it is neither its purpose nor secure. The HTTP proxy is deliberately configured with **no outproxy**, so a request to a clearnet host fails closed instead of leaking. If you want anonymous clearnet access, use [basic-tor](https://github.com/lukeprofits/basic-tor) instead.

If it does exactly what you need → great, use it. If it doesn't → don't use it. Simple as that.

### Install

```
pip install basic-i2p
```

On **Windows** and **macOS**, the first call downloads the official i2pd binary (~4 MB, SHA-512 verified) into your per-user data directory and starts it as a background subprocess. It stops automatically when your program exits.

On **Linux** there is no portable official i2pd build (every release package dynamic-links distro-specific libraries), so `basic-i2p` uses a system i2pd — install it once:

```
sudo apt install i2pd      # Debian / Ubuntu (Ubuntu 24.04: use the PPA, below)
sudo dnf install i2pd      # Fedora
sudo pacman -S i2pd        # Arch
```

`basic-i2p` then finds `i2pd` on your `PATH` automatically. (See [Troubleshooting](#troubleshooting) for the official i2pd repo and manual-placement options.)

### Usage

```python
import basic_i2p
import requests

# Start i2pd (if not already running) and get the I2P-only proxy URL
proxy = basic_i2p.ensure_running()   # → "http://127.0.0.1:<port>"

# Fetch a .i2p site through it
r = requests.get("http://notbob.i2p", proxies={"http": proxy, "https": proxy})
print(r.text)

# Host your own service on I2P — any local TCP server gets a .i2p address
addr = basic_i2p.host_service(8080)  # forwards inbound I2P streams → 127.0.0.1:8080
print(addr)                          # → "<52 chars>.b32.i2p"  (share this)

# Peer-to-peer streams between destinations (no server, works behind NAT)
sock = basic_i2p.connect("otherpeer….b32.i2p")
sock.sendall(b"hello")
print(sock.recv(4096))
sock.close()

listener = basic_i2p.listen()        # your own destination
print("dial me at:", listener.address)
conn = listener.accept()             # blocks until a peer connects
conn.sendall(b"hi back")
conn.close()

# Housekeeping
basic_i2p.is_running()               # → True
basic_i2p.proxy_url()                # → the same proxy URL (raises if not running)
basic_i2p.my_destination()           # → your stable "<b32>.i2p" address
basic_i2p.i2pd_version()             # → "2.60.0" (the running router)
basic_i2p.stop()                     # or just let your program exit
```

That's the whole API. `start()` also exists as an alias for `ensure_running()` if you prefer the symmetry with `stop()`.

First bootstrap takes roughly **1–5 minutes** (reseeding, then building tunnels through the I2P network) — noticeably slower than Tor, so be patient on the first call. Later runs reuse the cached netdb and start faster. `ensure_running()` is idempotent — call it as often as you like.

**Identities are persistent by default.** Your `.i2p` address is derived from a keypair saved in the data directory, so a service you `host_service()` keeps the **same address across restarts**. Pass `persistent=False` to any of `host_service` / `connect` / `listen` / `my_destination` for a fresh, unlinkable identity each run. Use `name="…"` to keep multiple separate identities. A `name` keeps the kind it was first opened with — asking for the same name as persistent in one call and transient in another raises `ValueError` rather than silently reusing the wrong identity.

All failures raise `basic_i2p.I2PError`. Subclasses, all with actionable messages:

- `I2PBinaryNotFound` — no i2pd binary and auto-download failed or isn't available for this platform (e.g. Linux with no system i2pd installed). The message tells you exactly how to install it.
- `I2PBootstrapTimeout` — i2pd didn't reseed and build tunnels in time (default 300 s). Slow or blocked network.
- `I2PDataDirLocked` — another i2pd process owns the data directory. One process per data dir.
- `SAMError` — a SAM operation (hosting, connecting, name lookup) failed; the message carries the router's own reason (e.g. `CANT_REACH_PEER`).

### Config

Override module variables **before** the first call if you want non-defaults:

```python
import basic_i2p

basic_i2p.HTTP_PROXY_PORT = 4444           # default None = a free port is chosen
basic_i2p.SAM_PORT = 7656                   # default None = a free port is chosen
basic_i2p.DATA_DIR = "/mnt/data/i2pd"       # default: platformdirs user data dir
basic_i2p.BOOTSTRAP_TIMEOUT = 420.0         # seconds to wait for tunnels
basic_i2p.I2PD_VERSION = "2.60.0"           # must be in i2pd_checksums.py
```

By default both ports are `None`: `basic-i2p` binds a free loopback port and the returned URLs tell you which, so it can **never** clash with a system i2pd. Pin them only if you need stable ports across runs. Everything binds to `127.0.0.1` only.

### Two-peer example

Anything you `host_service()` on one machine can be reached from another that knows your `.i2p` address. Smallest possible demo:

```python
# Machine A — host a service
import basic_i2p, http.server, threading
basic_i2p.start()

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b"hello from A")

httpd = http.server.HTTPServer(("127.0.0.1", 8080), H)
threading.Thread(target=httpd.serve_forever, daemon=True).start()

print("share this address with B:", basic_i2p.host_service(8080))
input("press enter to stop…")
```

```python
# Machine B — fetch it over I2P
import basic_i2p, requests
proxy = basic_i2p.start()
print(requests.get("http://<address from A>",
                   proxies={"http": proxy, "https": proxy}).text)   # → "hello from A"
```

Or skip HTTP entirely and use raw sockets with `listen()` on A and `connect()` on B.

### Updating the pinned i2pd version

The version is pinned in `basic_i2p/__init__.py` (`I2PD_VERSION`).

```bash
python scripts/refresh_checksums.py 2.61.0   # fetches + GPG-verifies + records new hashes
# review the diff, bump I2PD_VERSION, commit
```

The script fetches PurpleI2P's signed `SHA512SUMS` and verifies its OpenPGP signature against the i2pd release-signing key (R4SAS, `951928BB317024EFD053D73C66F6C87B98EBCFE2`) before recording anything. Runtime verification stays checksum-only — users never need GPG.

### Troubleshooting

**Slow first run.** First bootstrap reseeds and builds tunnels through the live I2P network — 1–5 minutes is normal. Subsequent starts reuse the cached netdb. The router data lives in `platformdirs.user_data_dir("basic_i2p")` so it survives reinstalls. To wipe it, delete that directory.

**`I2PBinaryNotFound` on Linux.** Install a system i2pd (`sudo apt install i2pd`, or see the [official repo](https://repo.i2pd.xyz)). Alternatively, place an i2pd binary at the path printed in the error message and `basic-i2p` will use it.

**i2pd exits within a minute of starting.** An old router: Ubuntu 24.04's packaged i2pd is 2.49.0, which aborts about 30 seconds into every start on today's network. The error names the version when this is likely. Install a current one from the i2pd project's PPA:

```
sudo add-apt-repository ppa:purplei2p/i2pd
sudo apt update && sudo apt install i2pd
```

**`I2PDataDirLocked` on startup.** Another `basic-i2p`-using process (or a separately running i2pd) owns the data directory. Run one process per data dir — or set `basic_i2p.DATA_DIR` to a different path before starting.

**Auto-download fails (corporate proxy / firewall).** The downloader honors the standard environment variables:

```bash
HTTPS_PROXY=http://corp-proxy:3128 \
REQUESTS_CA_BUNDLE=/etc/ssl/corp-ca.pem \
python your_script.py
```

**Bootstrap never completes.** Your network may block I2P (some countries and corporate firewalls do). Check the log at `<data_dir>/i2pd.log`.

**Want to inspect the router log.** It's at `<data_dir>/i2pd.log` (default `~/.local/share/basic_i2p/i2pd_data/i2pd.log`).

### Security

- **Verified downloads, fail-closed.** Every download is checked against a SHA-512 baked into the wheel (`basic_i2p/i2pd_checksums.py`) using a constant-time compare. Unknown versions are refused — fetching a digest from the same origin as the archive adds no real protection. Downloads are pinned to `github.com` / `githubusercontent.com` at **every redirect hop** and require HTTPS on every hop.
- **Checksums are GPG-verified at authoring time** against the i2pd release-signing key (R4SAS, `951928BB317024EFD053D73C66F6C87B98EBCFE2`), so the baked-in table inherits the project's own signature.
- **I2P-only, no clearnet leak.** The HTTP proxy has no outproxy, so a clearnet request is refused by the router rather than forwarded. There is no exit path to leak through.
- **Loopback only.** The HTTP proxy and SAM bridge bind to `127.0.0.1`; the web console and UPnP are disabled. Your destination keys live in a `0700` data directory.
- **Hardened against local attackers.** SAM session ids are unguessable (no session hijack by other local processes), and on Linux the SAM/proxy ports are verified to belong to the i2pd we launched before any key material crosses them — a locally impersonated bridge fails closed. See [`SECURITY.md`](SECURITY.md) for the shared-host details.
- **Clean shutdown.** The router is stopped on normal exit, on an unhandled exception, and on `SIGTERM`/`SIGHUP` (`docker stop`, `systemctl stop`, `kill`) — the signal handler chains to any handler you set. The only thing that can orphan i2pd is a `SIGKILL` of your process, which nothing can catch.

See [`SECURITY.md`](SECURITY.md) for the full threat model, including the one honest caveat about orphaned processes on `SIGKILL`.

One thing worth knowing: `basic-i2p` gives you I2P's *transport* anonymity. Your application traffic (what you host, what you log in to, what your service reveals about itself) can still identify you — that part is on you.

### How it works

`basic-i2p` runs the official i2pd router as a subprocess and talks to it over I2P's [SAM v3](https://geti2p.net/en/docs/api/samv3) bridge (a tiny built-in client — no heavyweight dependencies). Bootstrap readiness is confirmed by building a probe tunnel over SAM rather than scraping logs; hosting is a SAM `STREAM FORWARD`; P2P sockets are SAM `STREAM CONNECT` / `STREAM ACCEPT`; shutdown is a clean `SIGTERM`.

- **Auto-download** (Windows/macOS): the binary fetches from the PurpleI2P GitHub release on first use, checksum-verified, and cached per-user. The Python wheel stays tiny because it ships no router binary.
- **System i2pd** (Linux): a `i2pd` on your `PATH` is used directly, so you get your distro's signed, security-updated build.
- **Reseed certificates** are bundled from a GPG-verified release and passed to i2pd with `--certsdir`, so a from-scratch reseed works even on the binary-only macOS build.
- **PyInstaller / Briefcase friendly:** respects `sys._MEIPASS`; a pre-placed binary in the user data dir skips the download entirely (air-gapped deploys).
- **Dependencies:** just `requests` and `platformdirs`.

### Contributing

If you want to add functionality, open a PR. I'll merge it if it keeps the library simple and matches the existing patterns.

### License

MIT for this library. See [LICENSE](LICENSE).

The i2pd binary is **not** part of this package — on Windows/macOS it is downloaded from the PurpleI2P project on first use, and on Linux it comes from your system package manager. i2pd is licensed under the [BSD 3-Clause license](https://github.com/PurpleI2P/i2pd/blob/openssl/LICENSE). The reseed certificates bundled for verification are likewise from the i2pd project and covered by its license.
