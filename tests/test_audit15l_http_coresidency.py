"""
test_audit15l_http_coresidency.py — §Method step 3 at block granularity, the
HTTP plane (docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md).

Tranche 11 re-ran the pairwise matrix per SERVER BLOCK instead of per file and
found 24 pairs the 08-15 pass scored as covered that no single block in the
tree runs; it closed the eight that make up the S3 security cluster.  Eight
more are one http-plane cluster — the ordinary WLCG storage element, where a
listener serves its data, reports on itself, and carries an admin face:

    proto:srr × store:posix · proto:srr × store:cache · proto:cvmfs × store:posix
    proto:cvmfs × proto:dashboard · proto:dashboard × store:cache
    proto:dashboard × store:httpbe · store:passthru × store:posix
    auth:authdb × store:httpbe

plus the two the block creates by existing at all — a file that mixes CVMFS
with SRR and with an authdb scores those pairs co-tested at FILE granularity,
so `proto:cvmfs × proto:srr` and `auth:authdb × proto:cvmfs` are carried in the
CVMFS block itself rather than left as fresh gaps.

`nginx_audit15l_httpcores.conf` is that deployment: SRR, a posix tier, a
read-through cache tier and a passthrough tier over a REMOTE origin, an XrdAcc
tier over that same origin, and the dashboard — one server block — plus the
CVMFS face on its own listener, because `brix_http_proto_exclusive_check()`
permits exactly one brix protocol per listen port.

WHAT THE BLOCK ESTABLISHES

- SRR reports on the tiers below it: each share's capacity is a live statvfs of
  the operator-configured path (`srr_share_usage()` → `brix_fs_usage_stat()`,
  builder.c:190), not a walk, and a stat failure is a WARN and zero bytes,
  never fatal.
- The two admission caps are one directive apart and behave differently:
  `brix_cache_max_object` declines a fill; `brix_cache_passthrough` serves the
  declined object anyway under its own spool cap and drops it when the last fd
  closes (`event=passthrough-evict`).
- Per-location `brix_export` really does separate two cache tiers in one server
  — the stores never hold each other's keys.
- XrdAcc runs BEFORE the backend fetch: a denied path that does not exist at
  the origin answers 403, not the origin's 404.
- The CVMFS grammar gate is a whitelist: only CVMFS traffic shapes reach the
  tier, everything else is `cvmfs-reject … cause="path is not a CVMFS traffic
  shape"`.

DEFECT CANDIDATE #39 (reporting, over-statement) — the SRR site capacity double
counts shares that share a filesystem.  `srr_share_usage()` statvfs's each
share path and `srr_emit_capacity()` sums the results (builder.c:350), with no
`st_dev` dedup, so the single-disk deployment this file runs — a posix export
and a cache store on one filesystem, the most common small-site shape — reports
`storagecapacity.online.totalsize` as exactly 2× the disk.  WLCG accounting
reads that number.  Every share is individually correct; the total is not.

DEFECT CANDIDATE #40 (availability) — on an HTTP backend a cache-admission
decline is fatal to the request.  `brix_http_fill_resolve_waiter()` maps
NGX_DECLINED to `NGX_HTTP_BAD_GATEWAY` (http_cache_fill_worker.c:104), so an
object that exists at the origin, is readable, and is merely larger than
`brix_cache_max_object` is 502 — unreachable through this server.  The same
policy word on a `root://` backend does the opposite: `sd_cache_open_common()`
falls through to the source and serves the bytes (pinned by
test_audit15f_cache_admission_and_staging.py, "a decline is not a failure").
`brix_cache_passthrough` recovers the object, but only up to its own cap, and
it is off by default: a cap intended to bound the STORE silently bounds the
EXPORT.

DEFECT CANDIDATE #41 (security, detection without enforcement) — a CVMFS CAS
object whose content does not hash to its name is served to the client with
200 while the fill path quarantines it.  `brix_cache_verify_cvmfs_cas()`
(verify.c:264) logs `cvmfs-cas verify FAILED … object was quarantined, client
will retry` and raises `signal=cvmfs_tamper`, but verification is a FILL-time
filter, not a serve-time gate: on a posix-backed repo the read is answered from
the source, so the client already has the bytes the verifier just rejected, and
the diagnostic's "client will retry" is false.

DEFECT CANDIDATE #42 (observability, blind panel) — the dashboard's cache panel
is root-protocol-only.  `srv->cache_enabled` is assigned in exactly one place
in the tree, `protocols/root/connection/handler.c:333`; no HTTP-plane unit ever
sets it, and both `dashboard_fill_cache()` and the Prometheus cache families
(`stream_cache.c:83/118/152/195`) gate on it.  A server whose WebDAV cache
tiers are filling, evicting and being read reports `cache.enabled=false` with
an empty `listeners` array — no occupancy, no eviction counters — while the
storage census two keys away lists those very tiers.

DEFECT CANDIDATE #43 (security, directive that does nothing) — `brix_dashboard_
anonymous on` is a no-op unless a password or users file is also configured.
`ngx_http_brix_dashboard_check_auth()` returns NGX_OK for EVERY request when no
credential is configured (auth.c:232, "No password configured — dashboard
accessible without auth"), so `redact` stays 0 and the unauthenticated caller
receives the full admin payload — export roots, listen ports, origin host and
port — with the payload's own `anonymous` flag reading false.  The operator who
writes the directive to DOWNGRADE anonymous viewers to the redacted tier gets
the opposite of what they asked for, and nothing at parse time says so.

DEFECT CANDIDATE #44 (security, silent no-op) — `brix_authdb` on a CVMFS export
is parsed and never consulted.  `src/protocols/cvmfs/` contains no reference to
the acc tier at all: the authz gate is called by the root plane
(`open_request_resolve.c`, `mv.c`, `locate.c`, …), by gridftp
(`ftp_ev_path.c:115`), by WebDAV (`module_acc_directives.c`) and by S3 (its own
`s3_acc_check`) — and by nothing under `protocols/cvmfs/`.  The same authdb
file that denies `/acl/priv` two listeners away denies nothing here: every path
in the repo is uncovered by any rule, which is XrdAcc for "deny", and every one
of them is served 200 with no audit line.  Unlike #36 this is not fail-closed
behind another gate — CVMFS is anonymous by default, so an operator who
restricts a repo with path rules gets no restriction whatsoever, and `nginx -t`
says nothing.

NOT DEFECTS, PINNED AS FACTS.  `proto:cvmfs × proto:webdav` is not a coverage
gap but a design rule — the guard-negative below shows `nginx -t` refusing that
pair on one port.  And the dashboard's storage census is process-wide (it reads
the VFS backend registry, not the server block), so the CVMFS listener's admin
face lists the WebDAV block's exports; that is the census's documented scope,
recorded here because a reader of one listener's dashboard should know it.
"""

import json
import os
import subprocess
import time
from pathlib import Path

import pytest
import requests

from cmdscripts.live_common import inject_nginx_load_modules
from server_registry import NginxInstanceSpec
from settings import HOST, NGINX_BIN, BIND_HOST

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15l-httpcores")]

REPO = Path(__file__).resolve().parents[1]

MAX_OBJECT = "64k"
PT_MAX = "1m"
REPO_NAME = "atlas.example.org"

SMALL = b"audit15l small object\n"
MID = b"M" * 200_000          # over brix_cache_max_object, under the spool cap
HUGE = b"H" * 3_000_000       # over both

AUTHDB = "u * /acl/pub rl\n"

DEFECT39 = (
    "DEFECT CANDIDATE #39 has been FIXED: the SRR site capacity no longer sums "
    "two shares that live on one filesystem. Flip this expectation — the total "
    "should now be the disk, once.")
DEFECT40 = (
    "DEFECT CANDIDATE #40 has been FIXED: an object the cache declines to "
    "admit is no longer 502 on an HTTP backend. Flip this expectation to the "
    "root:// behaviour — serve the source bytes, store nothing.")
DEFECT41 = (
    "DEFECT CANDIDATE #41 has been FIXED: a CAS object that fails verification "
    "is no longer served. Flip this expectation — the client should get an "
    "error, not the bytes the verifier rejected.")
DEFECT42 = (
    "DEFECT CANDIDATE #42 has been FIXED: the dashboard cache panel now sees "
    "HTTP-plane cache tiers. Flip this expectation and assert the occupancy "
    "and eviction numbers, not their absence.")
DEFECT44 = (
    "DEFECT CANDIDATE #44 has been FIXED: brix_authdb now reaches the CVMFS "
    "plane (or is refused there). Flip this expectation — an uncovered path "
    "should be denied, and the denial should be audited.")
DEFECT43 = (
    "DEFECT CANDIDATE #43 has been FIXED: brix_dashboard_anonymous now "
    "redacts (or is refused) without a password. Flip this expectation to the "
    "redacted tier — anonymous=true and no export roots.")


# --------------------------------------------------------------------------- #
# The block.                                                                   #
# --------------------------------------------------------------------------- #

def _sha1(blob):
    import hashlib
    return hashlib.sha1(blob).hexdigest()


# A CAS object is content-addressed: the 40-hex name IS sha1(served bytes), so
# the verified arm names itself and the tampered arm cannot be mistaken for a
# transport error.
CAS_GOOD = b"audit15l verified cas payload\n"
CAS_GOOD_HEX = _sha1(CAS_GOOD)
CAS_BAD_HEX = _sha1(b"a different object entirely\n")
CAS_BAD = b"audit15l TAMPERED cas payload\n"


def _cas_uri(hexname):
    return f"/cvmfs/{REPO_NAME}/data/{hexname[:2]}/{hexname[2:]}"


@pytest.fixture()
def httpcores(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    # WebDAV maps export root + the WHOLE request URI, so the tree on disk
    # mirrors the URI space rather than stripping the location prefix.
    for uri_dir in ("local/posix/pub", "origin/cache/pub", "origin/pt/pub",
                    "origin/acl/pub", "origin/acl/priv"):
        (data / uri_dir).mkdir(parents=True)
        for name, blob in (("seed.txt", SMALL), ("mid.bin", MID),
                           ("huge.bin", HUGE)):
            (data / uri_dir / name).write_bytes(blob)

    repo = data / "repo" / "cvmfs" / REPO_NAME
    (repo / "data" / CAS_GOOD_HEX[:2]).mkdir(parents=True)
    (repo / "data" / CAS_BAD_HEX[:2]).mkdir(parents=True, exist_ok=True)
    (repo / ".cvmfspublished").write_bytes(b"Caudit15l\n")
    (repo / "data" / CAS_GOOD_HEX[:2] / CAS_GOOD_HEX[2:]).write_bytes(CAS_GOOD)
    (repo / "data" / CAS_BAD_HEX[:2] / CAS_BAD_HEX[2:]).write_bytes(CAS_BAD)
    (repo / "seed.txt").write_bytes(SMALL)      # a real file, not a CVMFS shape

    cache_root = tmp_path / "stores"
    export_root = tmp_path / "exports"
    for tier in ("cache", "pt", "cvmfs"):
        (cache_root / tier).mkdir(parents=True)
        (export_root / tier).mkdir(parents=True)
    tmp = tmp_path / "ngxtmp"
    tmp.mkdir()
    authdb = tmp_path / "authdb"
    authdb.write_text(AUTHDB, encoding="utf-8")

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15l-httpcores",
        template="nginx_audit15l_httpcores.conf",
        protocol="http",
        data_root=str(data),
        template_values={"CACHE_ROOT": str(cache_root),
                         "EXPORT_ROOT": str(export_root),
                         "MAX_OBJECT": MAX_OBJECT,
                         "PT_MAX": PT_MAX,
                         "AUTHDB": str(authdb),
                         "SRR_HOST": HOST,
                         "TMP_DIR": str(tmp)},
        reason="audit-15l: the HTTP plane's tiers and faces in one block"))
    return endpoint, cache_root, data


# --------------------------------------------------------------------------- #
# Helpers.                                                                     #
# --------------------------------------------------------------------------- #

def _url(endpoint, path, port=None):
    return f"http://{HOST}:{port or endpoint.port}{path}"


def _get(endpoint, path, **kwargs):
    kwargs.setdefault("timeout", 60)
    return requests.get(_url(endpoint, path, kwargs.pop("port", None)), **kwargs)


def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        return (Path(endpoint.prefix) / "logs" / "error.log").read_text(
            errors="replace")
    except FileNotFoundError:
        return ""


def _store_keys(cache_root, tier):
    root = cache_root / tier
    return sorted(str(p)[len(str(root)):] for p in root.rglob("*") if p.is_file())


def _wait_until(pred, timeout=10.0):
    """The fill and the evict both finish off the request; poll, do not guess."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = pred()
        if value:
            return value
        time.sleep(0.1)
    return pred()


def _srr(endpoint):
    resp = _get(endpoint, "/.well-known/wlcg-storage-resource-reporting")
    assert resp.status_code == 200, (
        f"the SRR document is not served beside its own tiers: "
        f"{resp.status_code}\n{_errlog(endpoint)}")
    return resp.json()["storageservice"]


def _shares(endpoint):
    return {s["name"]: s for s in _srr(endpoint)["storageshares"]}


def _statvfs_total(path):
    st = os.statvfs(path)
    return st.f_blocks * st.f_frsize


# --------------------------------------------------------------------------- #
# proto:srr × store:posix, proto:srr × store:cache.                            #
# --------------------------------------------------------------------------- #

def test_srr_reports_the_two_tiers_configured_below_it(httpcores):
    endpoint, cache_root, data = httpcores

    shares = _shares(endpoint)

    assert set(shares) == {"localdata", "cachedata"}, (
        f"the SRR document does not describe this server's own tiers: {shares}")
    assert shares["localdata"]["path"] == [str(data / "local")]
    assert shares["cachedata"]["path"] == [str(cache_root / "cache")]


def test_each_share_reports_a_live_statvfs_of_its_configured_path(httpcores):
    endpoint, cache_root, _ = httpcores

    shares = _shares(endpoint)

    expected = _statvfs_total(cache_root)
    for name, share in shares.items():
        assert share["totalsize"] == expected, (
            f"share {name} reports {share['totalsize']} where statvfs of its "
            f"path reports {expected} — the number is not a live filesystem "
            f"reading")
        assert 0 < share["usedsize"] <= share["totalsize"], (
            f"share {name} reports a nonsensical usedsize: {share}")


def test_site_capacity_double_counts_two_shares_on_one_filesystem(httpcores):
    """DEFECT CANDIDATE #39.  srr_emit_capacity() sums the shares with no
    st_dev dedup, so the single-disk site — one export, one cache store, one
    disk — advertises twice the storage it has."""
    endpoint, cache_root, data = httpcores

    service = _srr(endpoint)
    online = service["storagecapacity"]["online"]
    shares = service["storageshares"]

    assert os.stat(data / "local").st_dev == os.stat(cache_root / "cache").st_dev, (
        "this assertion only means anything while both tiers are on one "
        "filesystem; the fixture put them under one tmp_path and they are not")
    assert online["totalsize"] == sum(s["totalsize"] for s in shares), (
        "the site total is no longer the plain sum of the shares — re-derive "
        "this pin from srr_emit_capacity()")
    assert online["totalsize"] == 2 * _statvfs_total(cache_root), DEFECT39


def test_srr_endpoint_names_the_posix_tier_of_this_same_block(httpcores):
    endpoint, _, _ = httpcores

    service = _srr(endpoint)

    urls = [e.get("endpointurl", "") for e in service["storageendpoints"]]
    assert any(u.endswith("/posix/") for u in urls), (
        f"the advertised endpoint is not the tier this block serves: {urls}")


def test_share_usage_is_a_statvfs_and_a_stat_failure_is_never_fatal():
    """The behavioural assertions above cannot distinguish "statvfs" from "a
    walk that happens to agree"; the source can."""
    src = (REPO / "src" / "protocols" / "srr" / "builder.c").read_text()

    body = src.split("srr_share_usage(")[1].split("\n}")[0]
    assert "brix_fs_usage_stat" in body, (
        "srr_share_usage no longer measures shares with brix_fs_usage_stat")
    assert "NGX_LOG_WARN" in body or "WARN" in body, (
        "a share whose path cannot be stat'd must WARN, not fail the document")


# --------------------------------------------------------------------------- #
# The four tiers on one listener.                                              #
# --------------------------------------------------------------------------- #

def test_the_posix_tier_serves_its_own_bytes(httpcores):
    endpoint, _, _ = httpcores

    resp = _get(endpoint, "/posix/pub/seed.txt")

    assert resp.status_code == 200, f"{resp.status_code}\n{_errlog(endpoint)}"
    assert resp.content == SMALL


def test_the_cache_tier_serves_the_remote_origin_and_stores_the_object(httpcores):
    endpoint, cache_root, _ = httpcores

    resp = _get(endpoint, "/cache/pub/seed.txt")

    assert resp.status_code == 200, f"{resp.status_code}\n{_errlog(endpoint)}"
    assert resp.content == SMALL, "the cache tier did not serve the origin bytes"
    assert _wait_until(lambda: "/cache/pub/seed.txt" in _store_keys(
        cache_root, "cache")), (
        f"an admissible object never landed in brix_cache_store:\n"
        f"{_store_keys(cache_root, 'cache')}\n{_errlog(endpoint)}")


def test_the_passthrough_tier_serves_the_same_remote_origin(httpcores):
    endpoint, _, _ = httpcores

    resp = _get(endpoint, "/pt/pub/seed.txt")

    assert resp.status_code == 200, f"{resp.status_code}\n{_errlog(endpoint)}"
    assert resp.content == SMALL


def test_the_authdb_tier_grants_the_prefix_its_rule_names(httpcores):
    endpoint, _, _ = httpcores

    resp = _get(endpoint, "/acl/pub/seed.txt")

    assert resp.status_code == 200, f"{resp.status_code}\n{_errlog(endpoint)}"
    assert resp.content == SMALL
    assert 'grant read "/acl/pub/seed.txt"' in _errlog(endpoint), (
        "brix_authdb_audit all did not record the grant")


def test_a_path_no_rule_covers_is_denied_on_the_authdb_tier(httpcores):
    endpoint, _, _ = httpcores

    resp = _get(endpoint, "/acl/priv/seed.txt")

    assert resp.status_code == 403, (
        f"an uncovered path was not denied: {resp.status_code}\n"
        f"{_errlog(endpoint)}")
    assert 'deny read "/acl/priv/seed.txt"' in _errlog(endpoint), (
        "the denial was not attributed in the audit trail")


# --------------------------------------------------------------------------- #
# store:passthru × store:posix — the two caps, one directive apart.            #
# --------------------------------------------------------------------------- #

def test_an_object_over_the_cache_cap_is_502_on_an_http_backend(httpcores):
    """DEFECT CANDIDATE #40.  The object exists at the origin and the posix
    tier one location away serves objects this size all day; the cache tier
    turns "too big to store" into "cannot be read"."""
    endpoint, cache_root, _ = httpcores

    resp = _get(endpoint, "/cache/pub/mid.bin")

    assert resp.status_code == 502, DEFECT40
    assert "cache fill declined" in _errlog(endpoint), (
        "the 502 did not come from the admission decline — re-derive this pin")
    assert "/cache/pub/mid.bin" not in _store_keys(cache_root, "cache"), (
        "a declined object was stored anyway")


def test_the_same_object_is_served_by_the_passthrough_tier(httpcores):
    endpoint, cache_root, _ = httpcores

    resp = _get(endpoint, "/pt/pub/mid.bin")

    assert resp.status_code == 200, (
        f"brix_cache_passthrough did not recover the declined object: "
        f"{resp.status_code}\n{_errlog(endpoint)}")
    assert resp.content == MID, "the passthrough bytes are not the origin's"


def test_the_passthrough_object_is_dropped_once_the_last_fd_closes(httpcores):
    endpoint, cache_root, _ = httpcores

    assert _get(endpoint, "/pt/pub/mid.bin").status_code == 200

    assert _wait_until(lambda: "event=passthrough-evict" in _errlog(endpoint)), (
        f"the transient object was never evicted:\n{_errlog(endpoint)}")
    assert _wait_until(
        lambda: "/pt/pub/mid.bin" not in _store_keys(cache_root, "pt")), (
        f"the evicted object is still in the store: "
        f"{_store_keys(cache_root, 'pt')}")


def test_an_object_over_the_spool_cap_is_declined_by_passthrough_too(httpcores):
    endpoint, _, _ = httpcores

    resp = _get(endpoint, "/pt/pub/huge.bin")

    assert resp.status_code == 502, (
        f"brix_cache_passthrough_max is not a cap: {resp.status_code}\n"
        f"{_errlog(endpoint)}")


def test_two_cache_tiers_in_one_server_never_hold_each_others_keys(httpcores):
    """Per-location brix_export is what separates them: the VFS backend
    registry is keyed by the canonical export root, so a shared root would
    make /cache/ inherit /pt/'s passthrough policy."""
    endpoint, cache_root, _ = httpcores

    assert _get(endpoint, "/cache/pub/seed.txt").status_code == 200
    assert _get(endpoint, "/pt/pub/seed.txt").status_code == 200
    _wait_until(lambda: _store_keys(cache_root, "cache")
                and _store_keys(cache_root, "pt"))

    cache_keys = _store_keys(cache_root, "cache")
    pt_keys = _store_keys(cache_root, "pt")
    assert cache_keys and all(k.startswith("/cache/") for k in cache_keys), (
        f"the cache tier's store holds foreign keys: {cache_keys}")
    assert pt_keys and all(k.startswith("/pt/") for k in pt_keys), (
        f"the passthrough tier's store holds foreign keys: {pt_keys}")


# --------------------------------------------------------------------------- #
# auth:authdb × store:httpbe.                                                  #
# --------------------------------------------------------------------------- #

def test_authorization_runs_before_the_backend_fetch(httpcores):
    """A path that is BOTH denied and absent at the origin answers with the
    denial: if the fetch ran first the origin's 404 would win."""
    endpoint, _, _ = httpcores

    resp = _get(endpoint, "/acl/priv/does-not-exist-at-the-origin.txt")

    assert resp.status_code == 403, (
        f"the origin was consulted before the authdb: {resp.status_code}\n"
        f"{_errlog(endpoint)}")


def test_a_write_is_denied_by_the_rule_that_grants_reads(httpcores):
    """`u * /acl/pub rl` is read+lookup; create is a separate letter."""
    endpoint, _, _ = httpcores

    resp = requests.put(_url(endpoint, "/acl/pub/new.txt"), data=b"x",
                        timeout=60)

    assert resp.status_code == 403, (
        f"a create was allowed by a read rule: {resp.status_code}\n"
        f"{_errlog(endpoint)}")
    assert 'deny create "/acl/pub/new.txt"' in _errlog(endpoint), (
        "the refused write was not attributed as a create")


def test_the_denied_read_never_reaches_the_origin_tier(httpcores):
    """Security-negative: the denial must not be a 403 rendered AFTER the
    bytes were fetched — the origin file exists, so a leak would be visible."""
    endpoint, _, _ = httpcores

    resp = _get(endpoint, "/acl/priv/seed.txt")

    assert resp.status_code == 403
    assert SMALL not in resp.content, (
        "the denied response carried the object's bytes")


# --------------------------------------------------------------------------- #
# proto:dashboard × store:cache, × store:httpbe.                               #
# --------------------------------------------------------------------------- #

def test_the_dashboard_answers_beside_the_tiers(httpcores):
    endpoint, _, _ = httpcores

    resp = _get(endpoint, "/brix/api/v1/snapshot")

    assert resp.status_code == 200, f"{resp.status_code}\n{_errlog(endpoint)}"
    doc = resp.json()
    assert doc["schema"] == "xrootd-dashboard.v1"
    assert {"cache", "storage", "protocols", "cvmfs"} <= set(doc), (
        f"the snapshot lost a panel: {sorted(doc)}")


def test_the_storage_census_carries_the_remote_backend_of_this_block(httpcores):
    endpoint, _, _ = httpcores

    doc = _get(endpoint, "/brix/api/v1/snapshot").json()

    exports = doc["storage"]["exports"]
    remote = [e for e in exports if e.get("remote")]
    assert remote, f"the http-backed tiers are missing from the census: {exports}"
    origin_port = endpoint.extra_ports["ORIGIN_PORT"]
    assert any(e.get("origin_port") == origin_port for e in remote), (
        f"no census entry names the origin this block fetches from "
        f"({origin_port}): {remote}")


def test_the_storage_census_carries_the_local_tiers_too(httpcores):
    endpoint, _, data = httpcores

    doc = _get(endpoint, "/brix/api/v1/snapshot").json()

    roots = {e.get("root") for e in doc["storage"]["exports"]}
    assert str(data / "local") in roots, (
        f"the posix tier is missing from the census: {sorted(roots)}")
    for entry in doc["storage"]["exports"]:
        if entry.get("root") == str(data / "local"):
            assert entry["bytes_total"] == _statvfs_total(data), (
                "the census capacity is not a live statvfs of the export")


def test_the_cache_panel_is_blind_to_http_plane_cache_tiers(httpcores):
    """DEFECT CANDIDATE #42.  Two tiers in this block just filled, served and
    evicted; the panel that exists to report caches says there are none."""
    endpoint, cache_root, _ = httpcores

    assert _get(endpoint, "/cache/pub/seed.txt").status_code == 200
    _wait_until(lambda: _store_keys(cache_root, "cache"))
    doc = _get(endpoint, "/brix/api/v1/snapshot").json()

    assert _store_keys(cache_root, "cache"), (
        "the store is empty, so this test is not measuring what it claims")
    assert doc["cache"]["enabled"] is False, DEFECT42
    assert doc["cache"]["listeners"] == [], DEFECT42


def test_only_the_root_protocol_populates_the_cache_metrics_slot():
    """The structural half of #42: one assignment, in one protocol."""
    hits = subprocess.run(
        ["grep", "-rln", "srv->cache_enabled =", "src"],
        cwd=str(REPO), capture_output=True, text=True, timeout=60).stdout.split()

    assert hits == ["src/protocols/root/connection/handler.c"], (
        f"srv->cache_enabled is now written from {hits} — if an HTTP-plane "
        f"unit joined that list, DEFECT CANDIDATE #42 is fixed and this "
        f"expectation should flip")


def test_anonymous_without_a_password_serves_the_unredacted_admin_view(httpcores):
    """DEFECT CANDIDATE #43.  No cookie, no credential of any kind — and the
    payload arrives with redact=0: export roots, listen ports and the origin
    host are all present, and the flag the page's banner reads says the viewer
    is NOT anonymous."""
    endpoint, _, data = httpcores

    doc = _get(endpoint, "/brix/api/v1/snapshot",
               headers={"Cookie": ""}).json()

    assert doc["anonymous"] is False, DEFECT43
    roots = {e.get("root") for e in doc["storage"]["exports"]}
    assert str(data / "local") in roots, DEFECT43
    assert any(e.get("origin_host") for e in doc["storage"]["exports"]), DEFECT43


# --------------------------------------------------------------------------- #
# proto:cvmfs × store:posix, proto:cvmfs × proto:dashboard.                    #
# --------------------------------------------------------------------------- #

def _cvmfs(endpoint, path):
    return _get(endpoint, path, port=endpoint.extra_ports["CVMFS_PORT"])


def test_the_cvmfs_face_serves_a_manifest_from_a_posix_repo(httpcores):
    endpoint, _, _ = httpcores

    resp = _cvmfs(endpoint, f"/cvmfs/{REPO_NAME}/.cvmfspublished")

    assert resp.status_code == 200, f"{resp.status_code}\n{_errlog(endpoint)}"
    assert resp.content == b"Caudit15l\n"


def test_a_cas_object_whose_name_is_its_digest_is_served_and_cached(httpcores):
    endpoint, cache_root, _ = httpcores

    resp = _cvmfs(endpoint, _cas_uri(CAS_GOOD_HEX))

    assert resp.status_code == 200, f"{resp.status_code}\n{_errlog(endpoint)}"
    assert resp.content == CAS_GOOD
    assert _wait_until(lambda: _store_keys(cache_root, "cvmfs")), (
        f"a verified CAS object never reached the cvmfs store:\n"
        f"{_errlog(endpoint)}")


def test_a_path_that_is_not_a_cvmfs_shape_is_refused(httpcores):
    """Security-negative: the grammar is a whitelist, so a real file in the
    repo that is not CVMFS traffic must not be reachable through this face."""
    endpoint, _, data = httpcores

    resp = _cvmfs(endpoint, f"/cvmfs/{REPO_NAME}/seed.txt")

    assert resp.status_code == 403, (
        f"a non-CVMFS path was served by the CVMFS face: {resp.status_code}")
    assert SMALL not in resp.content
    assert 'cause="path is not a CVMFS traffic shape"' in _errlog(endpoint), (
        "the refusal did not come from the grammar gate")


def test_a_tampered_cas_object_is_detected_and_served_anyway(httpcores):
    """DEFECT CANDIDATE #41.  The verifier catches it, the sesslog raises
    cvmfs_tamper, the copy is quarantined — and the client gets the bytes."""
    endpoint, cache_root, _ = httpcores

    resp = _cvmfs(endpoint, _cas_uri(CAS_BAD_HEX))

    log = _wait_until(
        lambda: "cvmfs-cas verify FAILED" in _errlog(endpoint) and _errlog(endpoint))
    assert log, "the CAS verifier did not run on this object at all"
    assert "signal=cvmfs_tamper" in log, (
        "verification failed without raising the tamper signal")
    assert resp.status_code == 200, DEFECT41
    assert resp.content == CAS_BAD, DEFECT41
    assert _cas_uri(CAS_BAD_HEX) not in _store_keys(cache_root, "cvmfs"), (
        "the object that failed verification was kept in the store")


def test_the_cvmfs_listener_carries_its_own_dashboard(httpcores):
    """The CVMFS panel's `enabled` is inferred from work done, not from the
    config (api_cvmfs.c:163) — an idle face reads false and the first request
    flips it.  That inference is what the cache panel is missing (#42): here
    the counters ARE the source of truth, there a never-set flag is."""
    endpoint, _, _ = httpcores

    idle = _cvmfs(endpoint, "/brix/api/v1/snapshot")
    assert idle.status_code == 200, f"{idle.status_code}\n{_errlog(endpoint)}"
    assert idle.json()["cvmfs"]["enabled"] is False, (
        "the panel now reports the configured face rather than its traffic — "
        "re-derive this pin from dashboard_fill_cvmfs()")

    assert _cvmfs(endpoint, f"/cvmfs/{REPO_NAME}/.cvmfspublished").status_code == 200
    doc = _cvmfs(endpoint, "/brix/api/v1/snapshot").json()

    assert doc["cvmfs"]["enabled"] is True, (
        f"the CVMFS panel did not see its own listener's traffic: {doc['cvmfs']}")


def test_the_cvmfs_panel_counts_the_shapes_this_face_answered(httpcores):
    endpoint, _, _ = httpcores

    assert _cvmfs(endpoint, f"/cvmfs/{REPO_NAME}/.cvmfspublished").status_code == 200
    assert _cvmfs(endpoint, f"/cvmfs/{REPO_NAME}/seed.txt").status_code == 403
    doc = _cvmfs(endpoint, "/brix/api/v1/snapshot").json()

    requests_panel = doc["cvmfs"]["requests"]
    assert requests_panel["manifest"] >= 1, requests_panel
    assert requests_panel["reject"] >= 1, (
        f"the refused shape was not counted as a reject: {requests_panel}")


def test_an_authdb_on_a_cvmfs_export_enforces_nothing(httpcores):
    """DEFECT CANDIDATE #44.  The authdb below is the file that denies
    /acl/priv on the WebDAV listener; no rule in it covers /cvmfs/, which is
    XrdAcc for "deny".  The CVMFS face serves the repo anyway and writes no
    audit line, because nothing under src/protocols/cvmfs/ ever asks."""
    endpoint, _, _ = httpcores

    manifest = _cvmfs(endpoint, f"/cvmfs/{REPO_NAME}/.cvmfspublished")
    cas = _cvmfs(endpoint, _cas_uri(CAS_GOOD_HEX))

    assert manifest.status_code == 200, DEFECT44
    assert cas.content == CAS_GOOD, DEFECT44
    log = _errlog(endpoint)
    assert "/cvmfs/" not in log.split("xrootd authz:")[-1] or \
        "xrootd authz:" not in log, (
        "the CVMFS face now consults the acc tier — DEFECT CANDIDATE #44 is "
        "fixed and these expectations should become a denial")


def test_no_translation_unit_under_cvmfs_calls_the_authz_gate():
    """The structural half of #44: the gate has call sites in root, gridftp,
    webdav and s3 — and none in the CVMFS plane."""
    hits = subprocess.run(
        ["grep", "-rl", "brix_auth_gate", "src/protocols"],
        cwd=str(REPO), capture_output=True, text=True, timeout=60).stdout.split()

    assert hits, "brix_auth_gate has no call sites at all; re-derive this pin"
    assert not [h for h in hits if "/cvmfs/" in h], (
        f"the CVMFS plane now gates on the authz tier ({hits}) — DEFECT "
        f"CANDIDATE #44 is fixed")


def test_the_cvmfs_listener_reports_its_own_cache_through_srr(httpcores):
    endpoint, cache_root, _ = httpcores

    resp = _get(endpoint, "/.well-known/wlcg-storage-resource-reporting",
                port=endpoint.extra_ports["CVMFS_PORT"])

    assert resp.status_code == 200, f"{resp.status_code}\n{_errlog(endpoint)}"
    service = resp.json()["storageservice"]
    shares = {s["name"]: s for s in service["storageshares"]}
    assert set(shares) == {"cvmfsdata"}, (
        f"the CVMFS site's SRR is not describing its own store: {shares}")
    assert shares["cvmfsdata"]["path"] == [str(cache_root / "cvmfs")]
    assert shares["cvmfsdata"]["totalsize"] == _statvfs_total(cache_root)


def test_the_two_srr_documents_describe_their_own_listeners(httpcores):
    """SRR is location state, not process state: two faces in one nginx
    publish two different documents."""
    endpoint, _, _ = httpcores

    webdav = _srr(endpoint)
    cvmfs = _get(endpoint, "/.well-known/wlcg-storage-resource-reporting",
                 port=endpoint.extra_ports["CVMFS_PORT"]).json()["storageservice"]

    assert webdav["name"] != cvmfs["name"], (
        f"both listeners published one identity: {webdav['name']}")
    assert {s["name"] for s in webdav["storageshares"]} == {"localdata",
                                                            "cachedata"}
    assert {s["name"] for s in cvmfs["storageshares"]} == {"cvmfsdata"}


def test_the_storage_census_is_process_wide_not_per_listener(httpcores):
    """Not a defect — the census reads the VFS backend registry — but a reader
    of the CVMFS listener's admin face is seeing the WebDAV block's exports."""
    endpoint, _, data = httpcores

    doc = _cvmfs(endpoint, "/brix/api/v1/snapshot").json()

    roots = {e.get("root") for e in doc["storage"]["exports"]}
    assert str(data / "local") in roots, (
        f"the census is now per-listener; re-derive this pin: {sorted(roots)}")


# --------------------------------------------------------------------------- #
# The rule that keeps proto:cvmfs × proto:webdav off one port.                 #
# --------------------------------------------------------------------------- #

def _nginx_t(root, body):
    """Render `body` as an http server and return (rc, diagnostics).  The
    damage is done to a tmp_path config; no tracked file is ever touched."""
    (root / "logs").mkdir(exist_ok=True)
    conf = root / "exclusive.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ access_log off;
  server {{ listen {BIND_HOST}:13297;
{body}
  }}
}}
""")
    inject_nginx_load_modules(conf)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=60)
    return p.returncode, p.stderr + p.stdout


@pytest.mark.skipif(not os.access(NGINX_BIN, os.X_OK),
                    reason=f"nginx not executable: {NGINX_BIN}")
def test_two_brix_protocols_on_one_listen_port_are_refused(tmp_path):
    (tmp_path / "repo").mkdir()
    rc, diag = _nginx_t(tmp_path, f"""
    location /dav/ {{ brix_webdav on;
        brix_storage_backend posix:{tmp_path}; brix_webdav_auth none; }}
    location /cvmfs/ {{ brix_cvmfs on;
        brix_storage_backend posix:{tmp_path / "repo"}; }}
""")

    assert rc != 0, f"webdav and cvmfs shared a port without complaint:\n{diag}"
    assert "one brix protocol per port" in diag, (
        f"the refusal is no longer the exclusivity check:\n{diag}")


@pytest.mark.skipif(not os.access(NGINX_BIN, os.X_OK),
                    reason=f"nginx not executable: {NGINX_BIN}")
def test_the_dashboard_is_not_a_protocol_and_may_join_any_of_them(tmp_path):
    """The control for the test above: the same file, minus the second
    protocol, parses — so the refusal is about the protocol pair and not about
    two locations on one listener."""
    rc, diag = _nginx_t(tmp_path, f"""
    location /dav/ {{ brix_webdav on;
        brix_storage_backend posix:{tmp_path}; brix_webdav_auth none; }}
    location /brix {{ brix_dashboard on; brix_dashboard_anonymous on; }}
""")

    assert rc == 0, f"the dashboard was treated as a competing protocol:\n{diag}"


def test_the_exclusivity_check_aggregates_every_server_on_the_port():
    """Structural: the check is per PORT, not per server block — two server
    blocks that each carry one protocol still collide if they share a listen."""
    src = (REPO / "src" / "protocols" / "shared" / "proto_exclusive.c").read_text()

    assert "one brix protocol per port" in src, (
        "the exclusivity diagnostic moved; re-derive the guard-negative above")
    body = src.split("brix_http_proto_exclusive_check(")[-1]
    assert "port" in body.split("\n}")[0], (
        "the check no longer keys on the listen port")
