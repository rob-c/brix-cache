"""
test_audit15e_passthrough_crosses.py — cache passthrough co-resident with
the stage tier and with read_only (audit §B2.14,
testsuite-combinatorial-coverage-audit 2026-08-15:
`brix_cache_passthrough` was only ever paired with a lone cache tier;
never with a write-through stage tier in the same location, and never on a
read-only export — though passthrough is a pure read path and must compose
with both).

One instance (nginx_audit15e_pt.conf): a WebDAV posix origin and a front
with two locations — /ptstage/ (cache + passthrough + sync-flush stage:
the full hybrid) and /ptro/ (cache + passthrough with allow_write off).
Geometry as test_cache_passthrough_planes.py: cache_max_object 4096 /
passthrough_max 1 MiB, so small (1000 B) is admitted+cached, mid (50 KiB)
is passthrough-eligible, huge (2 MiB) is above both caps.

Cases:
  * success — on the hybrid location the read geometry survives the stage
    tier: small is served AND cached, mid is served WITHOUT a spool copy,
    huge is refused (502)
  * success — a PUT through the hybrid stages to the spool and sync-flushes
    to the origin; the object reads back through the same location
  * success + security-negative — on the read-only location the mid-size
    passthrough read is unimpaired, while PUT and DELETE both 403 and the
    origin object survives untouched
"""

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15e-pt")]

MAX_OBJECT = 4096
PT_MAX = 1024 * 1024
SMALL = b"s" * 1000
MID = b"m" * (50 * 1024)
HUGE = b"h" * (2 * 1024 * 1024)


@pytest.fixture()
def pt(lifecycle, tmp_path):
    origin = tmp_path / "origin"
    export = tmp_path / "export"
    cache = tmp_path / "cache"
    stage = tmp_path / "stage"
    # The wire path keeps the location prefix and the origin does not create
    # parent collections.
    for d in (origin / "ptstage", origin / "ptro",
              export / "ptstage", export / "ptro",
              cache / "ptstage", cache / "ptro", stage / "ptstage"):
        d.mkdir(parents=True)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15e-pt",
        template="nginx_audit15e_pt.conf",
        protocol="http",
        data_root=str(origin),
        template_values={"BIND_HOST": HOST,
                         "ORIGIN_ROOT": str(origin),
                         "EXPORT_ROOT": str(export),
                         "CACHE_ROOT": str(cache),
                         "STAGE_ROOT": str(stage),
                         "MAX_OBJECT": str(MAX_OBJECT),
                         "PT_MAX": str(PT_MAX)},
        reason="audit-15e passthrough x stage / x read_only crosses"))
    return ep.port, origin, cache, stage


def _url(port, path):
    return f"http://{HOST}:{port}{path}"


def _spool_files(root):
    return [p for p in root.rglob("*") if p.is_file()]


def test_hybrid_read_geometry_survives_the_stage_tier(pt):
    port, origin, cache, _ = pt
    (origin / "ptstage" / "small.bin").write_bytes(SMALL)
    (origin / "ptstage" / "mid.bin").write_bytes(MID)
    (origin / "ptstage" / "huge.bin").write_bytes(HUGE)

    g = requests.get(_url(port, "/ptstage/small.bin"), timeout=30)
    assert g.status_code == 200 and g.content == SMALL, g.status_code
    assert _spool_files(cache / "ptstage"), \
        "the small object was served but never cached"

    g = requests.get(_url(port, "/ptstage/mid.bin"), timeout=60)
    assert g.status_code == 200 and g.content == MID, (
        g.status_code, "mid-size passthrough read broke under the stage tier")
    assert not [p for p in _spool_files(cache / "ptstage")
                if p.stat().st_size >= len(MID)], \
        "the passthrough-served mid object left a spool copy behind"

    g = requests.get(_url(port, "/ptstage/huge.bin"), timeout=60)
    assert g.status_code == 502, (
        g.status_code, "an object above cache AND passthrough caps was served")


def test_hybrid_write_stages_through(pt):
    port, origin, _, stage = pt
    payload = b"audit15e-pt-stage-write " * 64
    r = requests.put(_url(port, "/ptstage/w.bin"), data=payload, timeout=30)
    assert r.status_code in (201, 204), (r.status_code, r.text)
    # sync flush: the origin copy exists and the spool is drained by the time
    # the PUT answers.
    assert (origin / "ptstage" / "w.bin").read_bytes() == payload
    assert not _spool_files(stage / "ptstage"), \
        "the sync-flush stage left its spool copy behind"
    g = requests.get(_url(port, "/ptstage/w.bin"), timeout=30)
    assert g.status_code == 200 and g.content == payload, g.status_code


def test_readonly_passthrough_serves_but_rejects_writes(pt):
    port, origin, _, _ = pt
    (origin / "ptro" / "mid.bin").write_bytes(MID)

    g = requests.get(_url(port, "/ptro/mid.bin"), timeout=60)
    assert g.status_code == 200 and g.content == MID, (
        g.status_code, "the passthrough read path broke under read_only")

    r = requests.put(_url(port, "/ptro/new.bin"), data=SMALL, timeout=30)
    assert r.status_code == 403, (r.status_code, r.text)
    assert not (origin / "ptro" / "new.bin").exists()

    d = requests.delete(_url(port, "/ptro/mid.bin"), timeout=30)
    assert d.status_code == 403, (d.status_code, d.text)
    assert (origin / "ptro" / "mid.bin").read_bytes() == MID, \
        "the read-only export's object was mutated"
