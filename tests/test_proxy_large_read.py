"""
test_proxy_large_read.py — guards the xrootd_proxy large-read forwarding path.

Regression for the splice under-drain stall: a single large official-XrdCl read
(one big kXR_read) forwarded through xrootd_proxy used to take the zero-copy
splice() path, which on kernels whose socket-splice under-drains (e.g. WSL2)
crawled a 5 MiB read past the client's timeout — the real cause of flaky
test_conformance_topologies[proxy]/[mesh]. The proxy now falls back to the
buffered recv relay for the remainder when splice can't keep up.

Self-contained: provisions its own backend + proxy nginx (high ports) and drives
the freshly-built objs/nginx directly — no shared fleet. Uses the official XrdCl
worker (tests/_xrdcl_proxy) because the bug only manifests with XrdCl's single
large read (xrdcp chunks reads and never triggered splice).
"""

import hashlib
import os
import socket
import subprocess
import time

import pytest

NGINX_BIN = os.environ.get("LIFECYCLE_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

pytestmark = [
    pytest.mark.skipif(
        not os.path.isfile(NGINX_BIN),
        reason=f"nginx binary not built at {NGINX_BIN}",
    ),
    # serial: asserts large reads are "fast" — timing-sensitive under the pool.
    pytest.mark.serial,
]


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture
def proxy_stack(tmp_path):
    """A backend data server + a transparent proxy in front of it; yields (proxy_url, md5)."""
    root = tmp_path / "data"
    root.mkdir()
    blob = os.urandom(5 * 1024 * 1024)          # 5 MiB — large enough to splice
    (root / "big.bin").write_bytes(blob)
    md5 = hashlib.md5(blob).hexdigest()

    be_port, px_port = _free_port(), _free_port()
    confs = {
        "be": f"""\
worker_processes 1; daemon on; pid {tmp_path}/be.pid; error_log {tmp_path}/be.log info;
events {{ worker_connections 256; }}
stream {{ server {{ listen {be_port}; xrootd on; xrootd_storage_backend posix:{root}; xrootd_auth none; }} }}
""",
        "px": f"""\
worker_processes 1; daemon on; pid {tmp_path}/px.pid; error_log {tmp_path}/px.log info;
events {{ worker_connections 256; }}
stream {{ server {{ listen {px_port}; xrootd on; xrootd_auth none;
    xrootd_tap_proxy on; xrootd_tap_proxy_upstream 127.0.0.1:{be_port}; xrootd_tap_proxy_auth anonymous; }} }}
""",
    }
    paths = {}
    for name, text in confs.items():
        p = tmp_path / f"{name}.conf"
        p.write_text(text)
        paths[name] = str(p)
        subprocess.run([NGINX_BIN, "-c", str(p)], check=True)

    # wait for the proxy to accept
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", px_port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.02)

    yield f"root://127.0.0.1:{px_port}", md5

    for p in paths.values():
        subprocess.run([NGINX_BIN, "-c", p, "-s", "stop"], stderr=subprocess.DEVNULL)


def test_repeated_large_reads_through_proxy_are_fast_and_correct(proxy_stack):
    """20 single 5 MiB XrdCl reads through the proxy must each finish quickly + intact."""
    import _xrdcl_proxy as X

    url, md5 = proxy_stack
    slow = []
    for i in range(20):
        f = X.File()
        st, _ = f.open(url + "//big.bin", 1)   # OpenFlags.Read
        assert st.ok, f"open failed on iter {i}: {st.message}"
        info_st, info = f.stat()
        size = info.size if info_st.ok else 5 * 1024 * 1024
        t0 = time.time()
        rst, data = f.read(offset=0, size=size)
        dt = time.time() - t0
        f.close()
        assert rst.ok, f"read failed on iter {i}: {rst.message}"
        assert hashlib.md5(data).hexdigest() == md5, f"data corrupt on iter {i}"
        # The buffered fallback completes a 5 MiB loopback read in well under a
        # second; the pre-fix splice stall took ~60s. A 10s ceiling is a wide
        # margin that still catches any regression to the crawl/stall.
        if dt > 10:
            slow.append((i, dt))
    assert not slow, f"reads stalled (splice under-drain regression?): {slow}"
