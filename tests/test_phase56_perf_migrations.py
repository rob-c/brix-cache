"""
test_phase56_perf_migrations.py — phase-56 VFS/storage-driver perf-audit
migrations B-2 / B-5 / C-1 / C-4 / C-5 (+ C-2 source contracts; C-2's live
behaviour is tests/test_neg_stat_cache.py).

Each item is asserted as a SOURCE CONTRACT (the shape that made the audit
finding go away must stay in the tree) plus a live sanity leg on the shared
fleet.  Per the 3-tests rule each item carries success + error + security
negative coverage:

  B-2  read-ahead hints ride the Storage Driver seam — optional
       ``read_advise`` vtable slot; the POSIX driver maps it onto
       posix_fadvise(2) (which RETURNS the error, doesn't set errno); the
       stream/webdav WILLNEED funnels dispatch through the seam (no bare
       posix_fadvise left in protocol code); S3 GetObject files a whole-object
       SEQUENTIAL hint.  Advisory-only: never a confinement/auth surface.
  B-5  staged-commit byte accounting comes from an fstat of OUR still-open
       staged fd (or the driver total) — never a path re-stat of final_path
       after the rename (impersonation IPC per upload + overwrite race).
  C-1  readdir d_type rides brix_sd_dirent_t through the SD seam; the kind
       mapper trusts it only when != DT_UNKNOWN (stat fallback otherwise) and
       both sd-plane call sites zero the dirent first.
  C-4  a failed per-entry dirlist stat is only SILENT for the benign unlink
       race (ENOENT); anything else logs "entry omitted from the listing".
       The entry is skipped either way — never fabricated.
  C-5  off impersonation the per-entry stat is a dirfd-relative fstatat
       (O(1), no join/re-walk); under impersonation the broker-routed
       brix_lstat_confined_canon join stays mandatory (mapped-user DAC).
  C-2  contracts only here: env knob is exactly "1"; lookup/insert are
       impersonation- and nofollow-gated; insert only on genuine ENOENT; all
       four mutator forget hooks present; forget NOT impersonation-gated.

Run: PYTHONPATH=tests pytest tests/test_phase56_perf_migrations.py -v
"""

import os
import re
import subprocess

import pytest

from settings import DATA_ROOT, HOST, NGINX_ANON_PORT
from metrics_helpers import xrdcp, xrdfs

pytestmark = pytest.mark.timeout(120)

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(_REPO, rel), encoding="utf-8") as fh:
        return fh.read()


def _fn_body(text, name):
    """Body of a K&R/nginx-style function: name at column 0 to closing brace."""
    m = re.search(rf"^{name}\(.*?^\}}", text, re.S | re.M)
    assert m, f"function {name} not found"
    return m.group(0)


def _grep_c_sources(needle, root="src", word=False):
    """Repo-relative .c/.h files under `root` whose text contains `needle`
    (word=True matches on identifier boundaries, so e.g. a search for d_type
    does not hit field_type)."""
    pat = re.compile(rf"\b{re.escape(needle)}\b") if word else None
    hits = []
    for dirpath, _dirs, files in os.walk(os.path.join(_REPO, root)):
        for f in files:
            if not f.endswith((".c", ".h")):
                continue
            rel = os.path.relpath(os.path.join(dirpath, f), _REPO)
            text = _read(rel)
            if pat.search(text) if pat else needle in text:
                hits.append(rel)
    return sorted(hits)


# ---------------------------------------------------------------------------
# B-2 — read_advise SD slot + fadvise pushdown
# ---------------------------------------------------------------------------

def test_b2_sd_slot_and_posix_driver_wiring():
    """Success contract: the vtable slot exists, the POSIX driver wires it, and
    the driver impl compensates for posix_fadvise RETURNING the error number
    (it does not set errno — the audit's silent-failure trap)."""
    sd_h = _read("src/fs/backend/sd.h")
    assert "(*read_advise)" in sd_h
    for name, val in (("BRIX_SD_ADV_SEQUENTIAL", 0),
                      ("BRIX_SD_ADV_WILLNEED", 1),
                      ("BRIX_SD_ADV_RANDOM", 2)):
        assert re.search(rf"#define\s+{name}\s+{val}\b", sd_h), name
    assert ".read_advise = sd_posix_read_advise" in \
        _read("src/fs/backend/posix/sd_posix.c")
    body = _fn_body(_read("src/fs/backend/posix/sd_posix_io.c"),
                    "sd_posix_read_advise")
    assert "posix_fadvise(" in body
    assert "errno = rc" in body, \
        "posix_fadvise returns the error number; the driver must store it"


def test_b2_protocol_funnels_ride_the_seam():
    """Success contract: both WILLNEED funnels dispatch through the driver slot
    and no protocol code calls posix_fadvise directly any more."""
    pf = _fn_body(_read("src/protocols/root/read/prefetch.c"),
                  "brix_prefetch_fd_range")
    assert "read_advise" in pf and "posix_fadvise" not in pf
    wd = _fn_body(_read("src/protocols/webdav/io.c"),
                  "webdav_fadvise_willneed")
    assert "read_advise" in wd and "posix_fadvise" not in wd
    # S3 GetObject: whole-object sequential streaming hint via the VFS wrapper.
    assert "brix_vfs_file_read_advise(fh, 0, 0, BRIX_SD_ADV_SEQUENTIAL)" in \
        _read("src/protocols/s3/object.c")
    # The syscall itself lives in exactly one place: the POSIX driver.
    assert _grep_c_sources("posix_fadvise(") == \
        ["src/fs/backend/posix/sd_posix_io.c"]


def test_b2_wrapper_error_and_noop_semantics():
    """Error contract: the VFS wrapper rejects a bad handle/offset with EINVAL
    and treats a driver without the slot as a SILENT no-op success (advice must
    never fail an op)."""
    body = _fn_body(_read("src/fs/vfs/vfs_sync.c"), "brix_vfs_file_read_advise")
    assert "EINVAL" in body
    assert re.search(r"read_advise == NULL.*?return NGX_OK", body, re.S)


def test_b2_advice_is_not_an_auth_surface():
    """Security-negative: read_advise is advisory I/O plumbing only — it must
    never appear in auth or path-confinement code."""
    assert not _grep_c_sources("read_advise", root="src/auth")
    assert not _grep_c_sources("read_advise", root="src/fs/path")


# ---------------------------------------------------------------------------
# B-5 — staged-commit bytes from the staged fd, not a final_path re-stat
# ---------------------------------------------------------------------------

def test_b5_commit_bytes_from_staged_fd():
    """Success contract: the committed size is an fstat of OUR still-open
    staged fd taken BEFORE the rename; the driver-staged arm reuses the
    driver's own running total."""
    staged = _read("src/fs/vfs/vfs_staged.c")
    assert "fstat(st->staged.fd, &sb)" in staged
    assert "bytes = (size_t) sb.st_size" in staged
    assert "bytes = (size_t) st->driver_total" in staged
    # The rationale must survive as a comment: a path re-stat of final_path is
    # an impersonation broker round-trip AND a concurrent-overwrite race.
    assert "never a path re-stat" in staged


def test_b5_no_post_commit_restat_helper_left():
    """Error/security contract: the old post-commit re-stat helper is GONE
    repo-wide, and the ns copy plane reports exactly the bytes it moved
    (ssb->st_size fed to brix_copy_range), not a fresh destination stat."""
    assert not _grep_c_sources("brix_vfs_copy_ns_bytes")
    copy_src = _read("src/core/compat/namespace_ops_copy.c")
    assert "res->bytes   = ssb->st_size" in copy_src


# ---------------------------------------------------------------------------
# C-1 — d_type through the brix_sd_dirent_t seam
# ---------------------------------------------------------------------------

def test_c1_dtype_rides_the_sd_seam():
    """Success contract: the POSIX driver copies readdir's d_type into the SD
    dirent, and the VFS kind mapper trusts it only when != DT_UNKNOWN (stat
    verb decides otherwise)."""
    assert "out->d_type = de->d_type" in \
        _read("src/fs/backend/posix/sd_posix_ns.c")
    vfs_dir = _read("src/fs/vfs/vfs_dir.c")
    body = _fn_body(vfs_dir, "vfs_sd_entry_kind")
    assert "de->d_type != DT_UNKNOWN" in body


def test_c1_sd_dirents_are_zeroed_before_fill():
    """Error contract: both sd-plane call sites zero the dirent before the
    driver fills it, so a name-only driver yields d_type == DT_UNKNOWN (= 0),
    never stack garbage promoted to a fake kind."""
    vfs_dir = _read("src/fs/vfs/vfs_dir.c")
    assert vfs_dir.count("ngx_memzero(&de_sd, sizeof(de_sd))") >= 2


def test_c1_dtype_never_reaches_auth_or_confinement():
    """Security-negative: d_type is a listing-kind optimisation only; access
    and confinement decisions must never key off it."""
    assert not _grep_c_sources("d_type", root="src/auth", word=True)
    assert not _grep_c_sources("d_type", root="src/fs/path", word=True)


# ---------------------------------------------------------------------------
# C-4 — non-ENOENT per-entry stat failures are surfaced, entry still skipped
# ---------------------------------------------------------------------------

def test_c4_omitted_entries_are_logged_except_unlink_race():
    """Success+error contract: both dirlist planes log 'entry omitted from the
    listing' on a per-entry stat failure, gated on errno != ENOENT (the benign
    unlink race stays silent)."""
    for rel in ("src/fs/vfs/vfs_dir.c", "src/fs/vfs/vfs_io_core_dirlist.c"):
        text = _read(rel)
        assert "entry omitted from the" in text, rel
        assert "errno != ENOENT" in text, rel


# ---------------------------------------------------------------------------
# C-5 — dirfd-relative fstatat off impersonation; broker join kept under it
# ---------------------------------------------------------------------------

def test_c5_fstatat_fast_path_gated_on_impersonation():
    """Success contract: the O(1) fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)
    fast path runs only when no client is being impersonated."""
    body = _fn_body(_read("src/fs/vfs/vfs_dir.c"), "vfs_readdir_stat_child")
    assert "!brix_imp_client_active()" in body
    assert "int dfd = dirfd(dh->dir)" in body
    assert re.search(r"fstatat\(dfd, name, &st,\s*AT_SYMLINK_NOFOLLOW\)", body)


def test_c5_impersonation_keeps_broker_confined_stat():
    """Security-negative: under impersonation the join + broker-routed
    brix_lstat_confined_canon stays mandatory — mapped-user DAC must keep
    applying to every listed entry."""
    body = _fn_body(_read("src/fs/vfs/vfs_dir.c"), "vfs_readdir_stat_child")
    imp_branch = body.split("!brix_imp_client_active()")[1]
    assert "brix_lstat_confined_canon" in imp_branch


# ---------------------------------------------------------------------------
# C-2 — negative-stat cache source contracts (live suite: test_neg_stat_cache)
# ---------------------------------------------------------------------------

def test_c2_gates_and_insert_conditions():
    """Contract bundle for the cache core: the env knob is EXACTLY "1"; lookup
    and insert are both impersonation-gated; the follow and nofollow stat arms
    are keyed separately (a follow-stat ENOENT can be a dangling symlink whose
    lstat succeeds, so they must never alias); inserts happen only on genuine
    ENOENT."""
    stat_c = _read("src/fs/vfs/vfs_stat.c")
    env_on = _fn_body(stat_c, "brix_neg_stat_env_on")
    assert 'getenv("BRIX_NEG_STAT_CACHE")' in env_on
    assert "env[0] == '1' && env[1] == '\\0'" in env_on
    for fn in ("brix_neg_stat_lookup", "brix_neg_stat_insert"):
        assert "brix_imp_enabled()" in _fn_body(stat_c, fn), fn
    # Per-arm keying: the key derivation salts the follow arm.
    key_fn = _fn_body(stat_c, "brix_neg_stat_key")
    assert "BRIX_NEG_STAT_FOLLOW_SALT" in key_fn
    assert "brix_neg_stat_lookup(ctx->root_canon, path, nofollow)" in stat_c
    assert re.search(r"saved_errno == ENOENT.*?"
                     r"brix_neg_stat_insert\(ctx->root_canon, path, nofollow\)",
                     stat_c, re.S)


def test_c2_forget_hooks_cover_every_mutator():
    """Contract: every same-worker namespace mutator clears its slot, and the
    forget itself is NOT impersonation-gated (an impersonated create must clear
    entries inserted off-impersonation)."""
    # VFS-level mutators, plus the protocol publish points that materialise a
    # path OUTSIDE the VFS mutators: the root:// in-place create-open and POSC
    # commit rename, and the WebDAV chunked-PUT commit rename (all three were
    # live-verified gaps — a raw kXR_statNoFollow probe saw the stale ENOENT).
    for rel in ("src/fs/vfs/vfs_open.c", "src/fs/vfs/vfs_mkdir.c",
                "src/fs/vfs/vfs_rename.c", "src/fs/vfs/vfs_staged.c",
                "src/protocols/root/read/open_resolved_file_open.c",
                "src/protocols/root/read/close.c",
                "src/protocols/webdav/put_setup.c"):
        assert "brix_vfs_neg_stat_forget(" in _read(rel), rel
    forget = _fn_body(_read("src/fs/vfs/vfs_stat.c"),
                      "brix_vfs_neg_stat_forget")
    assert "brix_imp_enabled" not in forget
    # A create clears the negatives of BOTH stat arms, not just one.
    assert "for (arm = 0; arm <= 1; arm++)" in forget


# ---------------------------------------------------------------------------
# Live sanity on the shared fleet — the migrated planes still serve correctly
# ---------------------------------------------------------------------------

def _url(name):
    return f"root://{HOST}:{NGINX_ANON_PORT}//{name}"


@pytest.mark.registry_server("main")
def test_live_upload_roundtrip_and_stat_size(tmp_path):
    """B-5 live: an uploaded file reads back byte-exact and an immediate stat
    reports the true size (the commit-time fd-fstat accounting plane)."""
    payload = os.urandom(65536)
    src = tmp_path / "p56_up.bin"
    src.write_bytes(payload)
    name = f"p56_roundtrip_{os.getpid()}.bin"
    try:
        r = xrdcp("-f", str(src), _url(name))
        assert r.returncode == 0, r.stderr
        out = tmp_path / "p56_down.bin"
        r = xrdcp("-f", _url(name), str(out))
        assert r.returncode == 0, r.stderr
        assert out.read_bytes() == payload
        r = xrdfs(f"root://{HOST}:{NGINX_ANON_PORT}", "stat", "/" + name)
        assert r.returncode == 0, r.stderr
        m = re.search(r"Size:\s*(\d+)", r.stdout)
        assert m and int(m.group(1)) == len(payload), r.stdout
    finally:
        target = os.path.join(DATA_ROOT, name)
        if os.path.exists(target):
            os.unlink(target)


@pytest.mark.registry_server("main")
def test_live_dirlist_distinguishes_dir_from_file():
    """C-1/C-5 live: a long listing classifies a directory and a regular file
    correctly (the d_type/fstatat kind plane)."""
    tag = f"p56_kind_{os.getpid()}"
    d = os.path.join(DATA_ROOT, tag + "_dir")
    f = os.path.join(DATA_ROOT, tag + ".dat")
    os.mkdir(d)
    try:
        with open(f, "wb") as fh:
            fh.write(b"k" * 16)
        r = xrdfs(f"root://{HOST}:{NGINX_ANON_PORT}", "ls", "-l", "/")
        assert r.returncode == 0, r.stderr
        dir_line = [l for l in r.stdout.splitlines()
                    if l.rstrip().endswith("/" + tag + "_dir")]
        file_line = [l for l in r.stdout.splitlines()
                     if l.rstrip().endswith("/" + tag + ".dat")]
        assert dir_line and file_line, r.stdout
        assert dir_line[0].lstrip().startswith("d"), dir_line[0]
        assert not file_line[0].lstrip().startswith("d"), file_line[0]
    finally:
        if os.path.exists(f):
            os.unlink(f)
        os.rmdir(d)
