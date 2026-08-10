"""brix_cache_max_bytes — the pfc.diskusage files watermark (parity audit §4.7).

BriX's watermark reaper evicts on filesystem OCCUPANCY (statvfs). On a shared
filesystem that reflects everyone's data, so the FS watermark either never fires
(a huge mount) or thrashes (a noisy neighbour). `brix_cache_max_bytes <size>`
adds a second, independent arm: a cap on the cache's OWN total bytes. When the
sum of what this cache holds exceeds the cap, the reaper evicts oldest-first
until it is back within it — the same candidate set and evict primitive as the
FS arm, just a different target. Default 0 = off.

The behaviour is proven end-to-end: fill the cache past the cap, then watch the
reaper bring the cache's on-disk footprint back down to (roughly) the cap
without emptying it.

Directive-grammar accept/reject lives in tests/test_cache_directive_parse.py.

Run:
    PYTHONPATH=tests pytest tests/test_cache_max_bytes.py -v
"""

import os
import subprocess
import time

import pytest

from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")

_MAXBYTES = 262144          # 256 KiB cap
_FILE_SZ = 65536            # 64 KiB per object
_NFILES = 8                 # 512 KiB filled — twice the cap

pytestmark = [
    pytest.mark.timeout(180),
    pytest.mark.xdist_group("lc-cache-maxbytes"),
    pytest.mark.skipif(not os.path.exists(_XRDCP), reason="xrdcp not built"),
]


def _dir_bytes(root):
    """Total size of every regular file under `root` (data objects + their tiny
    sidecars); the sidecars are ~100 B each, negligible against 64 KiB objects."""
    total = 0
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
    return total


class TestMaxBytes:

    @pytest.fixture(scope="class")
    def instance(self, tmp_path_factory):
        base = tmp_path_factory.mktemp("maxbytes")
        data = base / "data"
        cache = base / "cache"
        export = base / "export"
        for p in (data, cache, export, export / "mb", cache / "mb"):
            p.mkdir(parents=True, exist_ok=True)

        harness = LifecycleHarness()
        spec = NginxInstanceSpec(
            name="lc-cache-maxbytes",
            template="nginx_lc_audit_maxbytes.conf",
            protocol="root",
            template_values={
                "BIND_HOST": BIND_HOST,
                "DATA_ROOT": str(data),
                "CACHE_ROOT": str(cache),
                "EXPORT_ROOT": str(export),
                "MAXBYTES": str(_MAXBYTES),
            },
            reason="audit §4.7 max_bytes (pfc.diskusage files)")
        try:
            endpoint = harness.start(spec)
        except Exception as exc:                                # noqa: BLE001
            harness.close()
            pytest.skip(f"max_bytes instance did not start: {exc}")
        try:
            yield endpoint, data, cache
        finally:
            harness.close()

    def test_owned_bytes_are_capped_by_the_reaper(self, instance):
        endpoint, data, cache = instance
        store = cache / "mb"

        # Fill the cache with 512 KiB across 8 distinct read-through objects.
        for i in range(_NFILES):
            (data / f"f{i}.bin").write_bytes(bytes((i * 7 + 3) % 251
                                                    for _ in range(_FILE_SZ)))
            out = data.parent / f"pull-{i}.bin"
            r = subprocess.run(
                [_XRDCP, "-f", "-s",
                 f"root://{HOST}:{endpoint.port}//f{i}.bin", str(out)],
                capture_output=True, text=True, timeout=60)
            assert r.returncode == 0, f"fill read {i} failed: {r.stderr}"

        # The cache now holds ~512 KiB, well over the 256 KiB cap.
        assert _dir_bytes(store) > _MAXBYTES, (
            "precondition: the cache should be over the cap right after filling")

        # The reaper's first tick is ~5 s out, then every 1 s. Poll until the
        # owned bytes fall to the cap (allowing one object of slack + sidecars).
        cap_with_slack = _MAXBYTES + _FILE_SZ
        deadline = time.time() + 40
        cached = _dir_bytes(store)
        while time.time() < deadline:
            cached = _dir_bytes(store)
            if cached <= cap_with_slack:
                break
            time.sleep(1)

        assert cached <= cap_with_slack, (
            f"reaper did not cap owned bytes: {cached} B still cached "
            f"(cap {_MAXBYTES} B)")
        # ...and it did not empty the cache — it reaps DOWN to the cap, not to 0.
        assert cached >= _FILE_SZ, (
            f"reaper over-evicted: only {cached} B left (expected ~{_MAXBYTES} B)")
