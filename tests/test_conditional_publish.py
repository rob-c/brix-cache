"""test_conditional_publish.py — phase-107 C1: the conditional publish matrix.

W7 moved the PUT/COPY precondition decision from the edge (a stat before the
body arrived) to the COMMIT (the storage decides at publish time):
`brix_http_write_precond` lifts `If-None-Match: *` / single-tag `If-Match`
into a typed brix_sd_precond_t that rides to brix_vfs_writer_commit_pre /
brix_vfs_copy, where an ABSENT failure is EEXIST and a MATCH_* failure is
ECANCELED — both answered 412, decided under the same atomic rename that
publishes the bytes (no TOCTOU between check and commit).

Live rows (the doc's §C6 matrix) against the pre-started nginx_shared fleet:
plain-HTTP WebDAV PUT/COPY and S3 PUT.  The S3 `If-None-Match: *` ABSENT rows
(including the N-writers-one-winner race) predate W7 and stay in
test_s3_create_exclusive.py; the root-protocol open-time ItExists row stays in
test_file_api.py (test_create_existing_file_new_flag_fails).  What W7 adds on
the root plane — the kXR_new intent RIDING TO THE COMMIT, and §5.5's refusal
to invent MATCH_* preconditions the wire cannot carry — is pinned at source
level below.

The security row is existence-probe prevention: on a read-only endpoint a
conditional PUT answers 403 whether or not the target exists — never 412,
which would leak existence through the refusal code (the policy gate runs
before any precondition evaluation).

ETags here are constructed from the shared data root's stat, because both
WebDAV and S3 emit brix_http_etag_str's grammar: "%lx-%llx" (hex mtime, hex
size, quoted) — the same grammar brix_sd_precond_eval_stat answers at commit.

Run:
  PYTHONPATH=tests pytest tests/test_conditional_publish.py -v
"""

import os
import pathlib
import re
import socket
import uuid

import pytest
import requests

from metrics_helpers import fetch, value
from settings import (
    READONLY_HTTP_DATA_ROOT,
    READONLY_HTTP_DAV_PORT,
    S3_BUCKET,
    SERVER_HOST,
)

REPO = pathlib.Path(__file__).resolve().parents[1]


def _src(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def _etag_of(disk_path):
    st = os.stat(disk_path)
    return '"{:x}-{:x}"'.format(int(st.st_mtime), st.st_size)


@pytest.fixture(scope="module")
def dav(test_env):
    return test_env["http_webdav_url"]


@pytest.fixture(scope="module")
def data_dir(test_env):
    return test_env["data_dir"]


@pytest.fixture(scope="module")
def s3(test_env):
    return test_env["s3_url"]


def _fresh(prefix):
    return f"/condpub_{prefix}_{uuid.uuid4().hex}"


# --------------------------------------------------------------------------
# WebDAV PUT
# --------------------------------------------------------------------------

def test_put_if_none_match_star_creates_then_412(dav, data_dir):
    """ABSENT row: the exclusive create wins once; the second identical PUT is
    412 and the winner's bytes survive — decided at the publish rename, not by
    a pre-body stat."""
    path = _fresh("inm")
    r = requests.put(f"{dav}{path}", data=b"first-writer",
                     headers={"If-None-Match": "*"}, timeout=10)
    assert r.status_code in (200, 201, 204), r.status_code
    r = requests.put(f"{dav}{path}", data=b"second-writer",
                     headers={"If-None-Match": "*"}, timeout=10)
    assert r.status_code == 412, r.status_code
    assert requests.get(f"{dav}{path}", timeout=10).content == b"first-writer"


def test_put_if_match_correct_etag_replaces(dav, data_dir):
    path = _fresh("im_ok")
    assert requests.put(f"{dav}{path}", data=b"version-one",
                        timeout=10).status_code in (200, 201, 204)
    etag = _etag_of(os.path.join(data_dir, path.lstrip("/")))
    r = requests.put(f"{dav}{path}", data=b"version-two",
                     headers={"If-Match": etag}, timeout=10)
    assert r.status_code in (200, 201, 204), r.status_code
    assert requests.get(f"{dav}{path}", timeout=10).content == b"version-two"


def test_put_if_match_mismatch_412_content_survives(dav):
    path = _fresh("im_bad")
    assert requests.put(f"{dav}{path}", data=b"protected",
                        timeout=10).status_code in (200, 201, 204)
    r = requests.put(f"{dav}{path}", data=b"clobber",
                     headers={"If-Match": '"deadbeef-1"'}, timeout=10)
    assert r.status_code == 412, r.status_code
    assert requests.get(f"{dav}{path}", timeout=10).content == b"protected"


# --------------------------------------------------------------------------
# WebDAV COPY (the precondition rides brix_vfs_copy to the destination commit)
# --------------------------------------------------------------------------

def test_copy_if_none_match_star_dest(dav):
    src, dst = _fresh("cp_src"), _fresh("cp_dst")
    assert requests.put(f"{dav}{src}", data=b"copy-me",
                        timeout=10).status_code in (200, 201, 204)
    r = requests.request("COPY", f"{dav}{src}",
                         headers={"Destination": f"{dav}{dst}",
                                  "If-None-Match": "*"}, timeout=10)
    assert r.status_code in (200, 201, 204), r.status_code
    assert requests.get(f"{dav}{dst}", timeout=10).content == b"copy-me"
    # destination now exists — the same conditional COPY refuses 412
    r = requests.request("COPY", f"{dav}{src}",
                         headers={"Destination": f"{dav}{dst}",
                                  "If-None-Match": "*"}, timeout=10)
    assert r.status_code == 412, r.status_code


def test_copy_if_match_mismatch_412_dest_survives(dav):
    src, dst = _fresh("cpm_src"), _fresh("cpm_dst")
    assert requests.put(f"{dav}{src}", data=b"new-bytes",
                        timeout=10).status_code in (200, 201, 204)
    assert requests.put(f"{dav}{dst}", data=b"old-bytes",
                        timeout=10).status_code in (200, 201, 204)
    r = requests.request("COPY", f"{dav}{src}",
                         headers={"Destination": f"{dav}{dst}",
                                  "If-Match": '"deadbeef-2"'}, timeout=10)
    assert r.status_code == 412, r.status_code
    assert requests.get(f"{dav}{dst}", timeout=10).content == b"old-bytes"


# --------------------------------------------------------------------------
# S3 PUT (If-None-Match:* ABSENT rows live in test_s3_create_exclusive.py)
# --------------------------------------------------------------------------

def test_s3_put_if_match_mismatch_412(s3):
    url = f"{s3}/{S3_BUCKET}/condpub_{uuid.uuid4().hex}"
    try:
        assert requests.put(url, data=b"orig", timeout=10).status_code == 200
        r = requests.put(url, data=b"clobber",
                         headers={"If-Match": '"deadbeef-3"'}, timeout=10)
        assert r.status_code == 412, r.status_code
        assert requests.get(url, timeout=10).content == b"orig"
    finally:
        requests.delete(url, timeout=10)


def test_s3_put_if_match_correct_etag_replaces(s3, data_dir):
    key = f"condpub_{uuid.uuid4().hex}"
    url = f"{s3}/{S3_BUCKET}/{key}"
    try:
        assert requests.put(url, data=b"orig", timeout=10).status_code == 200
        # the bucket is routing, not namespace: keys land at the export root
        etag = _etag_of(os.path.join(data_dir, key))
        r = requests.put(url, data=b"replaced",
                         headers={"If-Match": etag}, timeout=10)
        assert r.status_code == 200, r.status_code
        assert requests.get(url, timeout=10).content == b"replaced"
    finally:
        requests.delete(url, timeout=10)


# --------------------------------------------------------------------------
# SECURITY: existence-probe prevention on a read-only endpoint
# --------------------------------------------------------------------------

@pytest.mark.registry_server("readonly-http")
def test_readonly_conditional_put_is_403_never_412():
    """Write-disabled beats precondition: the refusal is 403 for an existing
    AND an absent target — a 412 on the existing one would let a read-only
    client enumerate the namespace through conditional PUTs."""
    try:
        socket.create_connection(
            (SERVER_HOST, READONLY_HTTP_DAV_PORT), timeout=3).close()
    except OSError:
        pytest.skip("read-only HTTP nginx not running (manage_test_servers)")

    os.makedirs(READONLY_HTTP_DATA_ROOT, exist_ok=True)
    existing = f"condpub_probe_{uuid.uuid4().hex}"
    with open(os.path.join(READONLY_HTTP_DATA_ROOT, existing), "wb") as fh:
        fh.write(b"must-survive")
    base = f"http://{SERVER_HOST}:{READONLY_HTTP_DAV_PORT}"

    for target in (existing, f"condpub_absent_{uuid.uuid4().hex}"):
        for hdr in ({"If-None-Match": "*"}, {"If-Match": '"deadbeef-4"'}):
            r = requests.put(f"{base}/{target}", data=b"x", headers=hdr,
                             timeout=10)
            assert r.status_code == 403, (
                f"{hdr} on {'existing' if target == existing else 'absent'} "
                f"target: got {r.status_code}, want 403 — a non-403 forks the "
                f"refusal by existence")
    with open(os.path.join(READONLY_HTTP_DATA_ROOT, existing), "rb") as fh:
        assert fh.read() == b"must-survive"


# --------------------------------------------------------------------------
# C6 metrics: the refusal counters and the honesty ratio
# --------------------------------------------------------------------------

FAILED = "brix_vfs_precond_failed_total"
ADVISORY = "brix_vfs_precond_advisory_total"


def _advisory_sum(text):
    """Sum of the advisory counter across every driver row."""
    return sum(
        int(m.group(1))
        for m in re.finditer(
            r"^" + re.escape(ADVISORY) + r"\{[^}]*\}\s+([0-9]+)",
            text, re.M))


def test_precond_metric_rows_present():
    """Both C6 families export their full label vocabulary from boot — every
    kind row and a posix driver row — so a dashboard sees zeros, never a
    missing series it cannot alert on."""
    text = fetch()
    for kind in ("absent", "etag", "meta"):
        assert value(text, FAILED, {"kind": kind}) >= 0, f"kind={kind} row absent"
    assert value(text, ADVISORY, {"driver": "posix"}) >= 0, "posix row absent"


def test_if_match_mismatch_books_failed_etag_and_advisory(dav):
    """An If-Match refusal is a stat-then-compare — the edge fast path answers
    it before the body uploads — so failed{kind="etag"} bumps AND the advisory
    counter bumps with it (an edge refusal is non-atomic by construction).
    Lower-bound deltas — the shared fleet may book unrelated refusals."""
    path = _fresh("m_etag")
    assert requests.put(f"{dav}{path}", data=b"held",
                        timeout=10).status_code in (200, 201, 204)
    before = fetch()
    r = requests.put(f"{dav}{path}", data=b"x",
                     headers={"If-Match": '"deadbeef-5"'}, timeout=10)
    assert r.status_code == 412, r.status_code
    after = fetch()
    assert (value(after, FAILED, {"kind": "etag"})
            - value(before, FAILED, {"kind": "etag"})) >= 1, (
        "the 412 did not book failed{kind=etag}")
    assert (value(after, ADVISORY, {"driver": "posix"})
            - value(before, ADVISORY, {"driver": "posix"})) >= 1, (
        "a check-then-act refusal did not book the advisory counter")


def test_absent_refusal_books_the_absent_kind(dav):
    """The kind axis distinguishes: an If-None-Match:* refusal books
    failed{kind="absent"} — never the etag row — and, being edge-answered
    (the fast path spares the doomed body upload), books advisory too."""
    path = _fresh("m_inm")
    assert requests.put(f"{dav}{path}", data=b"holder",
                        headers={"If-None-Match": "*"}, timeout=10
                        ).status_code in (200, 201, 204)
    before = fetch()
    r = requests.put(f"{dav}{path}", data=b"x",
                     headers={"If-None-Match": "*"}, timeout=10)
    assert r.status_code == 412, r.status_code
    after = fetch()
    assert (value(after, FAILED, {"kind": "absent"})
            - value(before, FAILED, {"kind": "absent"})) >= 1, (
        "the 412 did not book failed{kind=absent}")
    assert (value(after, ADVISORY, {"driver": "posix"})
            - value(before, ADVISORY, {"driver": "posix"})) >= 1, (
        "an edge-answered refusal did not book the advisory counter")


def test_atomic_refusals_set_the_out_bit_at_source():
    """The honesty contract behind the advisory metric cannot be driven over
    the wire deterministically — a COMMIT-path refusal needs a writer racing
    into the edge-check-to-rename window — so the atomic-on-refusal settings
    are pinned at source: the compat/posix EEXIST branch reports
    RENAME_NOREPLACE's verdict, the remote origin's ECANCELED and http's 412
    are storage-decided (atomic = 1), and a refusal that leaves the bit 0
    books advisory in brix_vfs_precond_refused_observe."""
    staged = _src("src/fs/vfs/vfs_staged.c")
    assert staged.count("pre->atomic = !brix_renameat_noreplace_degraded()") >= 1, (
        "the compat EEXIST refusal no longer reports RENAME_NOREPLACE's verdict")
    assert re.search(r"if\s*\(!pre->atomic\)\s*\{\s*\n?\s*"
                     r"brix_metric_vfs_precond_advisory", staged), (
        "the advisory booking no longer keys on pre->atomic")
    assert "pre->atomic = !brix_renameat_noreplace_degraded()" in _src(
        "src/fs/backend/posix/sd_posix_staged.c"), (
        "the posix driver's EEXIST refusal no longer reports the rename verdict")
    for rel in ("src/fs/backend/remote/sd_remote_write.c",
                "src/fs/backend/http/sd_http_write.c"):
        assert re.search(r"pre->atomic\s*=\s*1", _src(rel)), (
            f"{rel}: the origin-decided refusal no longer sets pre->atomic")


# --------------------------------------------------------------------------
# Source pins: the root plane and the remote origin
# --------------------------------------------------------------------------

def test_root_kxr_new_intent_rides_to_the_commit():
    """The open-time existence check is only a fast path; the guarantee is the
    commit's RENAME_NOREPLACE.  kXR_new (without kXR_delete) must set
    staged_excl at dispatch and commit through commit_ex."""
    dispatch = _src("src/protocols/root/read/open_resolved_file_dispatch.c")
    assert re.search(
        r"staged_excl\s*=\s*\n?\s*\(\(a->options & kXR_new\) "
        r"&& !\(a->options & kXR_delete\)\)", dispatch), (
        "the kXR_new -> staged_excl carry left the staged dispatch")
    commit = _src("src/protocols/root/write/write_staged.c")
    assert "brix_vfs_writer_commit_ex(file->writer, file->staged_excl)" in commit, (
        "the staged close no longer forwards the exclusive-create intent")


def test_root_plane_never_constructs_match_preconditions():
    """§5.5: kXR_open has no header that can carry an etag, so the root plane
    must not INVENT MATCH_* preconditions — ABSENT (kXR_new) is the only kind
    it may express.  A MATCH kind appearing here means someone bolted a
    validator onto a plane that cannot transport one."""
    root = pathlib.Path(REPO, "src/protocols/root")
    offenders = [
        str(p.relative_to(REPO))
        for p in root.rglob("*.c")
        if re.search(r"BRIX_SD_PRECOND_MATCH_(ETAG|META)",
                     p.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"MATCH_* precondition on the root plane: {offenders}"


def test_remote_publish_is_one_conditional_request():
    """Over sd_remote the precondition is armed as RFC 7232 headers ON THE
    PUBLISH REQUEST itself — one round trip, decided at the origin.  A HEAD
    pre-flight here would reopen the TOCTOU the typed precondition closed."""
    text = _src("src/fs/backend/remote/sd_remote_write.c")
    m = re.search(r"^sd_remote_staged_commit\(.*?^\}", text, re.S | re.M)
    assert m, "sd_remote_staged_commit moved — re-anchor"
    body = m.group(0)
    assert "if-none-match" in body and "if-match" in body
    code = re.sub(r"/\*.*?\*/", "", body, flags=re.S)   # comments may DISCUSS
    assert '"HEAD"' not in code and "sd_s3_stat" not in code, (  # the old probe
        "a pre-flight probe appeared in the conditional publish path")


def test_one_lift_serves_all_three_protocol_commit_sites():
    """WebDAV PUT, WebDAV COPY and S3 PUT must all parse the conditional
    headers through the ONE shared lift, so the lifted grammar (single-tag
    If-Match, If-None-Match:*) can never fork between planes."""
    for rel in ("src/protocols/webdav/put.c",
                "src/protocols/webdav/copy.c",
                "src/protocols/s3/put_finalize.c"):
        assert "brix_http_write_precond(" in _src(rel), (
            f"{rel}: no longer parses via the shared precondition lift")
