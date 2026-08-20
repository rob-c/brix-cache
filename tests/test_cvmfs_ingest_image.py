# tests/test_cvmfs_ingest_image.py — `brixcvmfs ingest image` against the mock
# OCI registry (phase-104 D8.4): pull → flatten → Stratum-0 publish, driven
# through the real client binary and verified by reading the published
# catalogs/CAS directly in Python. Success lanes (flat layout, whiteouts,
# platform select, symlink-only retag, memo no-op, dry-run), error lanes
# (registry fault mid-fetch, publish crash hook), security negatives (corrupt
# layer, foreign-path collision vs --force-overlap) and the prune plane.
# Ports: srv_ingest block (canonical 13640; session-tiled), mock at base+0.
#
# The registry fixture is module-scoped and its tag table is MUTABLE
# (/ctl/retag): tests that permanently move a shared tag run LAST in this
# file — pytest executes in definition order.
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
import time
import zlib
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from cmdscripts.cvmfs_publish_txn import (
    FLAG_DIR, FLAG_FILE, FLAG_LINK,
    cas_path, lookup, open_catalog, parse_manifest,
)
from conformance_common import PortBlock
from settings import HOST

REPO_ROOT = Path(__file__).resolve().parent.parent
BRIX = REPO_ROOT / "client" / "bin" / "brixcvmfs"
MOCK = Path(__file__).resolve().parent / "oci" / "mock_registry.py"

PORT = PortBlock("srv_ingest").mock()
FQRN = "img.brix.io"
PREFIX = "/images"
REFHOST = f"{HOST}:{PORT}"          # ref form: host:port picks the transport
HOSTDIR = HOST                      # published dir: ref.host only, no port

pytestmark = [
    pytest.mark.skipif(not BRIX.exists(),
                       reason="client/bin/brixcvmfs not built (make -C client)"),
    # mkfs mints an RSA key pair per test and the module shares one registry:
    # the 30 s default cannot absorb a loaded host.
    pytest.mark.timeout(120),
]


@pytest.fixture(scope="module")
def registry():
    proc = subprocess.Popen([sys.executable, str(MOCK), "--port", str(PORT)])
    base = f"http://{HOST}:{PORT}"
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/ctl/log", timeout=0.2)
            break
        except Exception:
            time.sleep(0.1)
    else:
        proc.terminate()
        raise RuntimeError("mock registry never came up")
    yield base
    proc.terminate()
    proc.wait()


def _ctl_post(base, path, obj=None):
    data = json.dumps(obj).encode() if obj is not None else b""
    urllib.request.urlopen(urllib.request.Request(
        base + path, method="POST", data=data))


def _blob_hits(base):
    log = json.load(urllib.request.urlopen(base + "/ctl/log"))
    return [e for e in log if "/blobs/" in e["path"]]


def brix(*args, home, env=None, timeout=90):
    # HOME always points at a scratch dir so a developer's real registry
    # credentials can never leak into a lane.
    full = dict(__import__("os").environ, HOME=str(home))
    if env:
        full.update(env)
    return subprocess.run([str(BRIX), *map(str, args)], capture_output=True,
                          text=True, timeout=timeout, env=full)


def mkrepo(tmp_path):
    repo = tmp_path / "repo"
    r = brix("repo", "mkfs", FQRN, repo, home=tmp_path)
    assert r.returncode == 0, r.stderr
    return repo


def ingest(repo, ref, *extra, home, env=None):
    return brix("ingest", "image", ref, "--repo", repo, "--insecure",
                *extra, home=home, env=env)


def rev(repo):
    return int(parse_manifest(repo)["S"])


def root_cat(repo, base):
    return open_catalog(repo, parse_manifest(repo)["C"], base)


def memo_digest(repo, name_tag):
    # memo file <repo>/.brix-ingest/memo<flat-path>, line "<flat> <digest> ..."
    memo = repo / ".brix-ingest" / f"memo{PREFIX}" / HOSTDIR / name_tag
    return memo.read_text().split()[1]


def image_root(repo, name_tag):
    return f"{PREFIX}/.images/sha256/{memo_digest(repo, name_tag)[7:]}"


def cat_bytes(repo, cat, path):
    row = lookup(cat, path)
    assert row is not None and row[0] & FLAG_FILE, path
    return zlib.decompress(cas_path(repo, row[3].hex()).read_bytes())


def layer_digests(repo, cat, root):
    # the manifest sidecar is published verbatim, so the lane reads the layer
    # list out of the tree rather than re-deriving it from the mock
    man = json.loads(cat_bytes(repo, cat, f"{root}/.manifest.json"))
    return [lyr["digest"] for lyr in man["layers"]]


# ---- success ------------------------------------------------------------

def test_ingest_publishes_flat_layout(registry, tmp_path):
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/app:v1", home=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "ingested" in r.stdout and "2 layers" in r.stdout
    assert rev(repo) == 2

    root = image_root(repo, "lab/app:v1")
    hexd = root.rsplit("/", 1)[1]
    cat = root_cat(repo, tmp_path)
    for d in (PREFIX, f"{PREFIX}/.images", f"{PREFIX}/.images/sha256",
              root, f"{root}/bin"):
        row = lookup(cat, d)
        assert row is not None and row[0] & FLAG_DIR, d
    for p, size in ((f"{root}/bin/tool", 3000), (f"{root}/etc/conf", 200),
                    (f"{root}/share/data", 8000)):
        row = lookup(cat, p)
        assert row is not None and row[0] & FLAG_FILE and row[1] == size, p
    # the manifest sidecar's bytes hash back to the digest-root dirname
    row = lookup(cat, f"{root}/.manifest.json")
    assert row is not None and row[0] & FLAG_FILE
    body = zlib.decompress(cas_path(repo, row[3].hex()).read_bytes())
    assert hashlib.sha256(body).hexdigest() == hexd
    assert lookup(cat, f"{root}/.config.json") is not None
    # tag symlink is RELATIVE into the flat namespace
    row = lookup(cat, f"{PREFIX}/{HOSTDIR}/lab/app:v1")
    assert row is not None and row[0] & FLAG_LINK
    assert row[2] == f"../../.images/sha256/{hexd}"
    cat.close()


def test_ingest_v2_applies_whiteouts(registry, tmp_path):
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/app:v2", home=tmp_path)
    assert r.returncode == 0, r.stderr
    root = image_root(repo, "lab/app:v2")
    cat = root_cat(repo, tmp_path)
    # layer 3 whiteouts share/data and adds share/extra
    assert lookup(cat, f"{root}/share/data") is None
    row = lookup(cat, f"{root}/share/extra")
    assert row is not None and row[0] & FLAG_FILE and row[1] == 500
    assert lookup(cat, f"{root}/bin/tool") is not None
    cat.close()


def test_platform_selects_from_index(registry, tmp_path):
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/multi:latest",
               "--platform", "linux/arm64", home=tmp_path)
    assert r.returncode == 0, r.stderr
    root = image_root(repo, "lab/multi:latest")
    cat = root_cat(repo, tmp_path)
    row = lookup(cat, f"{root}/bin/arm64")
    assert row is not None and row[0] & FLAG_FILE and row[1] == 2000
    cat.close()

    r = ingest(repo, f"{REFHOST}/lab/multi:latest",
               "--platform", "linux/s390x", home=tmp_path)
    assert r.returncode == 4


def test_retag_is_symlink_only(registry, tmp_path):
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/app:v1", home=tmp_path)
    assert r.returncode == 0, r.stderr
    d1 = memo_digest(repo, "lab/app:v1")

    _ctl_post(registry, "/ctl/retag",
              {"name": "lab/app", "tag": "v9", "digest": d1})
    _ctl_post(registry, "/ctl/reset")
    r = ingest(repo, f"{REFHOST}/lab/app:v9", home=tmp_path)
    assert r.returncode == 0, r.stderr
    # no layer bytes moved, and the publish is structurally tiny
    assert "0 layers" in r.stdout
    assert int(re.search(r"(\d+) changes", r.stdout).group(1)) <= 8
    assert _blob_hits(registry) == []
    assert rev(repo) == 3

    cat = root_cat(repo, tmp_path)
    row = lookup(cat, f"{PREFIX}/{HOSTDIR}/lab/app:v9")
    assert row is not None and row[0] & FLAG_LINK
    assert row[2].endswith(d1[7:])
    cat.close()


def test_memo_noop_zero_data_plane(registry, tmp_path):
    repo = mkrepo(tmp_path)
    assert ingest(repo, f"{REFHOST}/lab/app:v1", home=tmp_path).returncode == 0
    _ctl_post(registry, "/ctl/reset")
    r = ingest(repo, f"{REFHOST}/lab/app:v1", home=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "up to date" in r.stdout
    assert rev(repo) == 2                 # nothing republished
    assert _blob_hits(registry) == []


def test_dry_run_touches_nothing(registry, tmp_path):
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/app:v1", "--dry-run", home=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "dry-run:" in r.stdout and "2 layers" in r.stdout
    assert rev(repo) == 1
    assert not (repo / ".brix-ingest").exists()


def test_verify_diffids_accepts_an_honest_config(registry, tmp_path):
    # the config's rootfs.diff_ids are sha256 over the UNCOMPRESSED layers,
    # which the flattener decompresses anyway — so the check is a hash pass,
    # not a second fetch: the blob ledger is the same as an unverified run.
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/app:v1", "--verify-diffids",
               home=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "verified 2 diff_ids against the image config" in r.stdout
    assert rev(repo) == 2
    assert lookup(root_cat(repo, tmp_path),
                  image_root(repo, "lab/app:v1") + "/bin/tool") is not None


# ---- error --------------------------------------------------------------

def test_registry_fault_midfetch_exit6_rerun_heals(registry, tmp_path):
    repo = mkrepo(tmp_path)
    # manifest resolve succeeds, every blob GET dies mid-transfer
    _ctl_post(registry, "/ctl/fault",
              {"kind": "reset", "path_re": "/blobs/", "persist": True})
    r = ingest(repo, f"{REFHOST}/lab/app:v1", home=tmp_path)
    assert r.returncode == 6, (r.returncode, r.stderr)
    assert rev(repo) == 1
    assert (repo / ".brix-ingest" / "scratch").exists()  # forensics kept

    _ctl_post(registry, "/ctl/reset")
    r = ingest(repo, f"{REFHOST}/lab/app:v1", home=tmp_path)
    assert r.returncode == 0, r.stderr
    assert rev(repo) == 2
    assert not (repo / ".brix-ingest" / "scratch").exists()


def test_publish_crash_rerun_completes(registry, tmp_path):
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/app:v1", home=tmp_path,
               env={"BRIXCVMFS_PUBLISH_CRASH": "1"})
    assert r.returncode == 66
    assert rev(repo) == 1                 # manifest swap never happened

    r = ingest(repo, f"{REFHOST}/lab/app:v1", home=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "breaking stale lock" in r.stderr
    assert rev(repo) == 2
    cat = root_cat(repo, tmp_path)
    assert lookup(cat, f"{image_root(repo, 'lab/app:v1')}/bin/tool") is not None
    cat.close()


# ---- security-negative --------------------------------------------------

def test_corrupt_layer_exit5_nothing_published(registry, tmp_path):
    repo = mkrepo(tmp_path)
    _ctl_post(registry, "/ctl/fault",
              {"kind": "corrupt", "path_re": "/blobs/", "persist": True})
    r = ingest(repo, f"{REFHOST}/lab/app:v1", home=tmp_path)
    _ctl_post(registry, "/ctl/reset")
    assert r.returncode == 5, (r.returncode, r.stderr)
    assert rev(repo) == 1


def test_diffid_mismatch_refuses_and_publishes_nothing(registry, tmp_path):
    # lab/liar's config pairs the two diff_ids the wrong way round. Every
    # compressed blob digest still verifies, so without the flag the image
    # publishes — the point of the flag is that this is the only place the
    # config's claim about the bytes is ever checked.
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/liar:v1", "--verify-diffids",
               home=tmp_path)
    assert r.returncode == 5, (r.returncode, r.stderr)
    assert "diff_id mismatch" in r.stderr and "layer 0" in r.stderr
    assert rev(repo) == 1

    assert ingest(repo, f"{REFHOST}/lab/liar:v1",
                  home=tmp_path).returncode == 0
    assert rev(repo) == 2


def test_diffid_count_disagreement_refused(registry, tmp_path):
    # a config that names fewer diff_ids than the manifest has layers: the
    # arithmetic never gets a chance to be wrong, so the count is its own
    # refusal rather than a silent short compare.
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/shortcfg:v1", "--verify-diffids",
               home=tmp_path)
    assert r.returncode == 5, (r.returncode, r.stderr)
    assert "fewer diff_ids than the manifest has layers" in r.stderr
    assert rev(repo) == 1


def test_foreign_collision_refused_then_forced(registry, tmp_path):
    repo = mkrepo(tmp_path)
    # squat a published FILE exactly where the image's <host> dir must go
    src = tmp_path / "src"
    src.mkdir()
    (src / HOSTDIR).write_bytes(b"squat\n")
    r = brix("ingest", "dir", src, "--repo", repo, "--prefix", PREFIX,
             home=tmp_path)
    assert r.returncode == 0, r.stderr

    r = ingest(repo, f"{REFHOST}/lab/app:v1", home=tmp_path)
    assert r.returncode == 5, (r.returncode, r.stderr)
    assert "not a directory" in r.stderr
    assert rev(repo) == 2                 # the refusal published nothing

    r = ingest(repo, f"{REFHOST}/lab/app:v1", "--force-overlap", home=tmp_path)
    assert r.returncode == 0, r.stderr
    cat = root_cat(repo, tmp_path)
    row = lookup(cat, f"{PREFIX}/{HOSTDIR}")
    assert row is not None and row[0] & FLAG_DIR   # file retyped, opted-in
    assert lookup(cat, f"{PREFIX}/{HOSTDIR}/lab/app:v1") is not None
    cat.close()


# ---- --require-digest (D15.12) ------------------------------------------

# App. L's registry-MITM row: the digest chain proves the published tree
# matches the manifest we resolved, never that the manifest is the one the
# operator meant — a tag can be repointed between two runs by anyone who can
# write to the registry. --require-digest is how a pinned deployment says so.

def _log_len(base):
    return len(json.load(urllib.request.urlopen(base + "/ctl/log")))


def test_require_digest_accepts_a_pinned_ref(registry, tmp_path):
    seed = mkrepo(tmp_path)
    assert ingest(seed, f"{REFHOST}/lab/app:v1", home=tmp_path).returncode == 0
    digest = memo_digest(seed, "lab/app:v1")

    (tmp_path / "second").mkdir()
    repo = mkrepo(tmp_path / "second")
    r = ingest(repo, f"{REFHOST}/lab/app@{digest}", "--require-digest",
               home=tmp_path)
    assert r.returncode == 0, r.stderr
    assert rev(repo) == 2


def test_require_digest_refuses_a_tag_ref(registry, tmp_path):
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/app:v1", "--require-digest",
               home=tmp_path)
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert "--require-digest" in r.stderr
    assert rev(repo) == 1                    # mkfs revision, nothing published
    assert not (repo / ".brix-ingest" / f"memo{PREFIX}").exists()


def test_require_digest_refuses_before_the_first_request(registry, tmp_path):
    """Security-negative: a refusal that still talks to the registry has
    already given an attacker the tag lookup, the credentials on that leg and
    a place to answer from. The check is argv-only, so it fires with the
    socket unopened."""
    repo = mkrepo(tmp_path)
    before = _log_len(registry)

    r = ingest(repo, f"{REFHOST}/lab/app:latest", "--require-digest",
               "--token-file", "/nonexistent", home=tmp_path)

    assert r.returncode == 2, (r.returncode, r.stderr)
    assert "--require-digest" in r.stderr
    assert _log_len(registry) == before


# ---- --layout layered (D15.6) -------------------------------------------

def test_layered_publishes_one_root_per_layer(registry, tmp_path):
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/stack:base", "--layout", "layered",
               home=tmp_path)
    assert r.returncode == 0, r.stderr
    root = image_root(repo, "lab/stack:base")
    cat = root_cat(repo, tmp_path)
    digs = layer_digests(repo, cat, root)
    assert len(digs) == 1
    lroot = f"{PREFIX}/.layers/sha256/{digs[0][7:]}"
    row = lookup(cat, f"{lroot}/bin/base")
    assert row is not None and row[1] == 4000
    # the image root carries the COMPOSITION, not a merged rootfs
    assert lookup(cat, f"{root}/bin/base") is None
    desc = cat_bytes(repo, cat, f"{root}/.layers").decode().split()
    assert desc == [f"../../../.layers/sha256/{digs[0][7:]}"]
    # and the descriptor's relative path really resolves to the layer root
    assert os.path.normpath(os.path.join(root, desc[0])) == lroot
    cat.close()


def test_layered_reuses_a_published_base_layer(registry, tmp_path):
    repo = mkrepo(tmp_path)
    assert ingest(repo, f"{REFHOST}/lab/stack:base", "--layout", "layered",
                  home=tmp_path).returncode == 0
    cat = root_cat(repo, tmp_path)
    basedig = layer_digests(repo, cat, image_root(repo, "lab/stack:base"))[0]
    cat.close()

    _ctl_post(registry, "/ctl/reset")
    r = ingest(repo, f"{REFHOST}/lab/stack:childa", "--layout", "layered",
               home=tmp_path)
    assert r.returncode == 0, r.stderr
    # the whole point: the shared base is never pulled a second time
    fetched = [e["path"] for e in _blob_hits(registry)]
    assert fetched and not any(basedig[7:] in p for p in fetched), fetched

    cat = root_cat(repo, tmp_path)
    root = image_root(repo, "lab/stack:childa")
    digs = layer_digests(repo, cat, root)
    assert len(digs) == 2 and digs[0] == basedig
    desc = cat_bytes(repo, cat, f"{root}/.layers").decode().split()
    assert len(desc) == 2 and desc[0].endswith(basedig[7:])
    assert lookup(cat, f"{PREFIX}/.layers/sha256/{basedig[7:]}/bin/base")
    assert lookup(cat, f"{PREFIX}/.layers/sha256/{digs[1][7:]}/opt/a")
    cat.close()


def test_layered_verify_diffids_still_covers_a_reused_layer(registry,
                                                            tmp_path):
    # a reused layer is not decompressed again, so the only diff_id available
    # for it is the one the ledger recorded when it WAS materialized. The
    # flag has to keep meaning what it says across that boundary.
    repo = mkrepo(tmp_path)
    assert ingest(repo, f"{REFHOST}/lab/stack:base", "--layout", "layered",
                  "--verify-diffids", home=tmp_path).returncode == 0
    r = ingest(repo, f"{REFHOST}/lab/stack:childb", "--layout", "layered",
               "--verify-diffids", home=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "verified 2 diff_ids against the image config" in r.stdout


def test_layered_prune_retires_only_the_unshared_layer(registry, tmp_path):
    repo = mkrepo(tmp_path)
    for tag in ("base", "childa"):
        assert ingest(repo, f"{REFHOST}/lab/stack:{tag}", "--layout",
                      "layered", home=tmp_path).returncode == 0
    cat = root_cat(repo, tmp_path)
    child = image_root(repo, "lab/stack:childa")
    digs = layer_digests(repo, cat, child)
    cat.close()

    # untag childa: its image root AND its own top layer become unreachable,
    # the base layer does not — another image still composes it
    (repo / ".brix-ingest" / f"memo{PREFIX}" / HOSTDIR / "lab"
     / "stack:childa").unlink()
    r = brix("ingest", "prune", "--repo", repo, "--prefix", PREFIX,
             home=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "pruned 1 root(s)" in r.stdout, r.stdout
    assert "pruned 1 layer root(s)" in r.stdout, r.stdout
    cat = root_cat(repo, tmp_path)
    assert lookup(cat, child) is None
    assert lookup(cat, f"{PREFIX}/.layers/sha256/{digs[1][7:]}") is None
    assert lookup(cat, f"{PREFIX}/.layers/sha256/{digs[0][7:]}/bin/base")
    cat.close()


def test_layered_refused_layer_leaves_no_reusable_ledger(registry, tmp_path):
    # security-negative: the ledger is what a LATER run trusts instead of
    # re-fetching. A layer that never verified must therefore leave no entry
    # behind, or a corrupt blob would be laundered into every future image.
    repo = mkrepo(tmp_path)
    _ctl_post(registry, "/ctl/fault",
              {"kind": "corrupt", "path_re": "/blobs/", "persist": True})
    r = ingest(repo, f"{REFHOST}/lab/stack:childb", "--layout", "layered",
               home=tmp_path)
    _ctl_post(registry, "/ctl/reset")
    assert r.returncode == 5, (r.returncode, r.stderr)
    assert rev(repo) == 1
    ledger = repo / ".brix-ingest" / f"layers{PREFIX}"
    assert not ledger.exists() or list(ledger.iterdir()) == []

    r = ingest(repo, f"{REFHOST}/lab/stack:childb", "--layout", "layered",
               home=tmp_path)
    assert r.returncode == 0, r.stderr
    cat = root_cat(repo, tmp_path)
    digs = layer_digests(repo, cat, image_root(repo, "lab/stack:childb"))
    assert lookup(cat, f"{PREFIX}/.layers/sha256/{digs[1][7:]}/opt/b")
    cat.close()


def test_layout_value_is_validated(registry, tmp_path):
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/stack:base", "--layout", "hybrid",
               home=tmp_path)
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert "usage:" in r.stderr and "--layout flat|layered" in r.stderr
    assert rev(repo) == 1
    assert not (repo / ".brix-ingest").exists()


# ---- lazy-pull layer encodings (D15.7) ----------------------------------
# eStargz is a chain of gzip MEMBERS; zstd:chunked a chain of zstd FRAMES with
# its TOC in a trailing skippable frame. Both must publish the rootfs their
# plain-gzip original would — and --verify-diffids is the proof, since a
# reader that stopped at the first member/frame would hash a prefix.

_STARGZ_META = ("stargz.index.json", ".prefetch.landmark",
                ".no.prefetch.landmark")


def _chunked_rootfs(repo, tmp_path, tag):
    root = image_root(repo, f"lab/chunked:{tag}")
    cat = root_cat(repo, tmp_path)
    try:
        for p, size in ((f"{root}/bin/app", 3000),
                        (f"{root}/etc/app.conf", 120)):
            row = lookup(cat, p)
            assert row is not None and row[0] & FLAG_FILE and row[1] == size, p
        for meta in _STARGZ_META:
            assert lookup(cat, f"{root}/{meta}") is None, meta
    finally:
        cat.close()


def test_estargz_layer_publishes_the_original_rootfs(registry, tmp_path):
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/chunked:estargz", "--verify-diffids",
               home=tmp_path)
    assert r.returncode == 0, r.stderr
    _chunked_rootfs(repo, tmp_path, "estargz")


def test_zstd_chunked_layer_publishes_the_original_rootfs(registry, tmp_path):
    pytest.importorskip("zstandard",
                        reason="no zstd compressor to build the layer with")
    repo = mkrepo(tmp_path)
    r = ingest(repo, f"{REFHOST}/lab/chunked:zstd", "--verify-diffids",
               home=tmp_path)
    if r.returncode != 0 and "without zstd support" in r.stderr:
        pytest.skip("client built without libzstd")
    assert r.returncode == 0, r.stderr
    _chunked_rootfs(repo, tmp_path, "zstd")


# ---- prune plane (moves the shared v1 tag — keep this test LAST) ---------

def test_prune_old_then_prune_verb(registry, tmp_path):
    repo = mkrepo(tmp_path)
    assert ingest(repo, f"{REFHOST}/lab/app:v1", home=tmp_path).returncode == 0
    assert ingest(repo, f"{REFHOST}/lab/app:v2", home=tmp_path).returncode == 0
    d1 = memo_digest(repo, "lab/app:v1")
    d2 = memo_digest(repo, "lab/app:v2")
    assert d1 != d2

    # the shared v1 tag now points at v2's manifest (permanent for the module)
    _ctl_post(registry, "/ctl/retag",
              {"name": "lab/app", "tag": "v1", "digest": d2})
    r = ingest(repo, f"{REFHOST}/lab/app:v1", "--prune-old", home=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "pruned old root" in r.stdout and "0 layers" in r.stdout
    cat = root_cat(repo, tmp_path)
    assert lookup(cat, f"{PREFIX}/.images/sha256/{d1[7:]}") is None
    row = lookup(cat, f"{PREFIX}/{HOSTDIR}/lab/app:v1")
    assert row is not None and row[2].endswith(d2[7:])
    cat.close()

    # untag everything (what `brixoci rm` does upstream) → the root is
    # unreferenced; --keep spares it, plain prune reaps it
    for tag in ("app:v1", "app:v2"):
        (repo / ".brix-ingest" / f"memo{PREFIX}" / HOSTDIR / "lab" / tag).unlink()
    r = brix("ingest", "prune", "--repo", repo, "--prefix", PREFIX,
             "--keep", "1", home=tmp_path)
    assert r.returncode == 0 and "nothing to prune" in r.stdout, r.stdout
    r = brix("ingest", "prune", "--repo", repo, "--prefix", PREFIX,
             "--dry-run", home=tmp_path)
    assert r.returncode == 0 and "would prune" in r.stdout, r.stdout
    r = brix("ingest", "prune", "--repo", repo, "--prefix", PREFIX,
             home=tmp_path)
    assert r.returncode == 0 and "pruned 1 root(s)" in r.stdout, r.stdout
    cat = root_cat(repo, tmp_path)
    assert lookup(cat, f"{PREFIX}/.images/sha256/{d2[7:]}") is None
    cat.close()
