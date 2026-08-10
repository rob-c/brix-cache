"""brix_cache_uvkeep — the pfc.uvkeep analog (parity audit §4.3).

A cache entry whose contents were never verified against the origin digest
(F_VERIFIED clear — e.g. a TLS-trusted fill with no checksum to compare) used to
be trusted until its normal TTL. `brix_cache_uvkeep <time>` bounds that trust:
past the window (measured from the entry's fill time) the next open is a MISS, so
the cache revalidates the entry against the source. A verified entry, or one
still inside the window, is unaffected — the knob only ever ADDS revalidation.

Behaviour is proven end-to-end with a source-content swap the cache cannot see
on its own (freshness is checked at fill time, not on every read):

  * inside the window  — after the source changes, the cache still serves its own
                         cached copy (proving it does NOT auto-revalidate, which
                         is what isolates uvkeep as the cause of the refresh)
  * past the window    — the unverified aged entry is revalidated and the new
                         source bytes serve

Directive-grammar accept/reject lives in tests/test_cache_directive_parse.py.

Run:
    PYTHONPATH=tests pytest tests/test_cache_uvkeep.py -v
"""

import os
import subprocess
import time

import pytest

from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")

_UVKEEP = 4  # seconds — long enough that the fill + two reads land inside it

pytestmark = [
    pytest.mark.timeout(180),
    pytest.mark.xdist_group("lc-cache-uvkeep"),
    pytest.mark.skipif(not os.path.exists(_XRDCP), reason="xrdcp not built"),
]


class TestUvkeep:

    @pytest.fixture(scope="class")
    def instance(self, tmp_path_factory):
        base = tmp_path_factory.mktemp("uvkeep")
        data = base / "data"
        cache = base / "cache"
        export = base / "export"
        for p in (data, cache, export, export / "uv", cache / "uv"):
            p.mkdir(parents=True, exist_ok=True)

        harness = LifecycleHarness()
        spec = NginxInstanceSpec(
            name="lc-cache-uvkeep",
            template="nginx_lc_audit_uvkeep.conf",
            protocol="root",
            template_values={
                "BIND_HOST": BIND_HOST,
                "DATA_ROOT": str(data),
                "CACHE_ROOT": str(cache),
                "EXPORT_ROOT": str(export),
                "UVKEEP": str(_UVKEEP),
            },
            reason="audit §4.3 uvkeep")
        try:
            endpoint = harness.start(spec)
        except Exception as exc:                                # noqa: BLE001
            harness.close()
            pytest.skip(f"uvkeep instance did not start: {exc}")
        try:
            yield endpoint, data, base
        finally:
            harness.close()

    def _read(self, endpoint, base, name, tag):
        out = base / f"pull-{tag}.bin"
        r = subprocess.run(
            [_XRDCP, "-f", "-s",
             f"root://{HOST}:{endpoint.port}//{name}", str(out)],
            capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, f"xrdcp ({tag}) failed: {r.stderr}"
        return out.read_bytes()

    def test_unverified_entry_revalidates_after_uvkeep(self, instance):
        endpoint, data, base = instance
        src = data / "uv.bin"
        src.write_bytes(b"A" * 4096)

        # 1. First read fills the cache (verify off → the entry is UNVERIFIED)
        #    and serves the original bytes.
        assert self._read(endpoint, base, "uv.bin", "fill") == b"A" * 4096

        # 2. Change the source out from under the cache.
        src.write_bytes(b"B" * 4096)

        # 3. INSIDE the uvkeep window the cache serves its own copy — it does not
        #    revalidate on a source change by itself, which is exactly what makes
        #    the step-5 refresh attributable to uvkeep and nothing else.
        assert self._read(endpoint, base, "uv.bin", "window") == b"A" * 4096, (
            "the cache served revalidated bytes INSIDE the uvkeep window")

        # 4. Age the entry past uvkeep.
        time.sleep(_UVKEEP + 2)

        # 5. The unverified aged entry is now revalidated: the next open misses,
        #    refills from the source, and serves the new bytes.
        assert self._read(endpoint, base, "uv.bin", "aged") == b"B" * 4096, (
            "uvkeep did not revalidate the unverified aged entry")
