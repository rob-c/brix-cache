"""
test_proxy_large_read.py — guards the brix_proxy large-read forwarding path.

Regression for the splice under-drain stall: a single large official-XrdCl read
(one big kXR_read) forwarded through brix_proxy used to take the zero-copy
splice() path, which on kernels whose socket-splice under-drains (e.g. WSL2)
crawled a 5 MiB read past the client's timeout — the real cause of flaky
test_conformance_topologies[proxy]/[mesh]. The proxy now falls back to the
buffered recv relay for the remainder when splice can't keep up
(src/net/proxy/events_splice.c, brix_proxy_splice_drain_to_buffered).

Throwaway backend + proxy nginx come from the registry lifecycle harness. Uses
the official XrdCl worker (tests/_xrdcl_proxy) because the bug only manifests
with XrdCl's single large read (xrdcp chunks reads and never triggered splice).
"""

import hashlib
import os
import time

import pytest

from settings import BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    # serial: asserts large reads are "fast" — timing-sensitive under the pool.
    pytest.mark.serial,
]


@pytest.fixture
def proxy_stack(lifecycle):
    """A backend data server + a transparent proxy in front of it; yields (proxy_url, md5)."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")

    backend = lifecycle.start(NginxInstanceSpec(
        name="lc-proxy-large-read-be",
        template="nginx_lc_proxy_large_read_backend.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST},
        reason="brix_proxy large-read backend origin"))

    blob = os.urandom(5 * 1024 * 1024)          # 5 MiB — large enough to splice
    with open(os.path.join(backend.data_root, "big.bin"), "wb") as fh:
        fh.write(blob)
    md5 = hashlib.md5(blob).hexdigest()

    proxy = lifecycle.start(NginxInstanceSpec(
        name="lc-proxy-large-read-px",
        template="nginx_lc_proxy_large_read_proxy.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "BACKEND_PORT": backend.port},
        reason="brix_proxy transparent front proxy"))

    return f"root://{proxy.host}:{proxy.port}", md5


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
