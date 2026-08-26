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

