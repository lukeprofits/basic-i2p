"""
End-to-end lifecycle tests. Marked ``network``: deselect with ``-m "not network"``.

These start a real i2pd, reseed, and build tunnels — minutes on a cold run,
and they need i2pd available (auto-downloaded on Windows/macOS, or a system
i2pd on Linux). They are skipped automatically if no i2pd can be found.
"""

from __future__ import annotations

import http.server
import threading

import pytest
import requests

import basic_i2p

pytestmark = pytest.mark.network


def _i2pd_available() -> bool:
    try:
        basic_i2p._find_or_install_i2pd()
        return True
    except basic_i2p.I2PBinaryNotFound:
        return False


requires_i2pd = pytest.mark.skipif(
    not _i2pd_available(),
    reason="no i2pd binary available (install i2pd or run on a platform with a static build)",
)


@pytest.fixture(scope="module")
def running():
    basic_i2p.ensure_running()
    yield
    basic_i2p.stop()


@requires_i2pd
def test_start_and_proxy_url(running):
    assert basic_i2p.is_running()
    url = basic_i2p.proxy_url()
    assert url.startswith("http://127.0.0.1:")
    assert basic_i2p.i2pd_version()


@requires_i2pd
def test_persistent_destination_is_stable(running):
    a = basic_i2p.my_destination(name="stable-test")
    b = basic_i2p.my_destination(name="stable-test")
    assert a == b and a.endswith(".b32.i2p")


@requires_i2pd
def test_host_and_connect_loopback(running):
    """Host a tiny HTTP server on I2P and fetch it back through the proxy."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"hello from i2p")

        def log_message(self, *a):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        addr = basic_i2p.host_service(port, name="host-test")
        assert addr.endswith(".b32.i2p")
        proxy = basic_i2p.proxy_url()
        # Give inbound tunnels a moment; retry a few times. A Session context
        # manager closes pooled sockets deterministically (no ResourceWarning).
        last = None
        for _ in range(6):
            try:
                with requests.Session() as s:
                    r = s.get(f"http://{addr}/",
                              proxies={"http": proxy, "https": proxy}, timeout=60)
                if r.status_code == 200:
                    assert r.text == "hello from i2p"
                    return
            except requests.RequestException as exc:
                last = exc
        pytest.fail(f"could not fetch hosted service via I2P: {last}")
    finally:
        httpd.shutdown()
        httpd.server_close()   # close the listening socket (else ResourceWarning)


@requires_i2pd
def test_clearnet_fails_closed(running):
    """The proxy has no outproxy: a clearnet request must not reach the host.

    i2pd answers a clearnet request with its own error page (HTTP 5xx) rather
    than a connection error, so the check is that the *real* site's content
    never comes back — the request fails closed, it does not leak to an exit.
    """
    proxy = basic_i2p.proxy_url()
    try:
        with requests.Session() as s:
            r = s.get("http://example.com",
                      proxies={"http": proxy, "https": proxy}, timeout=30)
    except requests.RequestException:
        return  # also acceptable: refused outright
    assert r.status_code >= 400
    assert "example domain" not in r.text.lower()  # real example.com body never fetched
