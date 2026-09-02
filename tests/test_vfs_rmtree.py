"""Phase-107 C4 — the windowed rmtree walk, live over both dispatch arms.

A recursive collection DELETE may only batch WITHIN one directory level: a
prefix cannot be removed before its children, and every registered driver but
`mirage` advertises CAP_DIRS, so the per-level rule IS the rule (the trap in
docs/refactor/phase-107-vfs-mutation-surface-completion.md §4/C4).
brix_vfs_rmtree_dispatch gates on the LEAF: with CAP_BULK_DELETE + a real
unlink_many (sd_remote) files leave in windowed ?delete batches flushed at
each directory's boundary BEFORE the directory's own removal; without the bit
(sd_http — RFC 4918 has no batch DELETE) the classic per-key walk runs
unchanged.

The matrix (nginx_p107_rmtree.conf, two WebDAV fronts + two logged origins):

  success   a 3-level recursive DELETE over sd_http removes every child
            before its parent (DAV-origin access-log order);
  success   the same tree over sd_remote leaves in ?delete batches — no
            per-file upstream DELETE — every batch flushed before its
            directory's removal, and the metric pair books the file count in
            the VALUE;
  error     rmtree of an absent collection is 404 and books no batch;
  sec-neg   a read-only... (the EROFS arm lives with the S3 batch endpoint in
            test_s3_delete_objects_batch.py; here the walk itself) — a DELETE
            of the export ROOT is refused and removes nothing.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_vfs_rmtree.py -v
"""
import os
import pathlib
import re

import pytest
import requests

from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p107-rmtree")]

SPEC = "lc-p107-rmtree"
BUCKET = "testbucket"
S3_AK = "AKIDP107RMTREETST12"
S3_SK = "cDEwNy1ybXRyZWUtd2luZG93ZWQtd2Fsay1zZWNyZXQ"


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    base = tmp_path_factory.mktemp("p107-rmtree")
    dirs = {name: base / name for name in (
        "origin_data", "http_export", "s3store", "remote_export")}
    for d in dirs.values():
        d.mkdir()
    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name=SPEC,
            template="nginx_p107_rmtree.conf",
            protocol="http",
            data_root=str(dirs["origin_data"]),
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_DATA": str(dirs["origin_data"]),
                "HTTP_EXPORT": str(dirs["http_export"]),
                "S3_DIR": str(dirs["s3store"]),
                "REMOTE_EXPORT": str(dirs["remote_export"]),
                "S3_ACCESS_KEY": S3_AK,
                "S3_SECRET_KEY": S3_SK,
            },
            reason="phase-107 C4 windowed rmtree walk, both dispatch arms"))
        logdir = pathlib.Path(ep.prefix) / "logs"
        yield {
            "http_port": ep.port,
            "remote_port": ep.extra_ports["REMOTE_PORT"],
            "metrics": f"http://{HOST}:{ep.extra_ports['METRICS_PORT']}/metrics",
            "dirs": dirs,
            "dav_log": logdir / "dav_origin_access.log",
            "s3_log": logdir / "s3_origin_access.log",
        }
    finally:
        harness.close()


def _uri(ln):
    """Field 1 of a p107rm log line as a clean URI: nginx renders an EMPTY
    $args as a literal '-', so an argless line carries a trailing dash glued
    to the path ("DELETE /a/b- 204") while a query-carrying line does not."""
    tok = ln.split()[1]
    if "?" not in tok and tok.endswith("-"):
        tok = tok[:-1]
    return tok.rstrip("/") or "/"


def _lines(path):
    return path.read_text().splitlines() if path.exists() else []


def _metric(srv, name, driver):
    text = requests.get(srv["metrics"], timeout=15).text
    m = re.search(rf'^{name}{{driver="{driver}"}} (\d+)$', text, re.MULTILINE)
    assert m, f"{name}{{driver={driver!r}}} missing from /metrics"
    return int(m.group(1))


def _seed_tree(root, prefix):
    """3 levels: prefix/{f0, d1/{f1a, f1b, d2/{f2}}} — 4 files, 3 dirs."""
    (root / prefix / "d1" / "d2").mkdir(parents=True)
    files = [f"{prefix}/f0.bin", f"{prefix}/d1/f1a.bin",
             f"{prefix}/d1/f1b.bin", f"{prefix}/d1/d2/f2.bin"]
    for f in files:
        (root / f).write_bytes(b"leaf")
    return files


def _assert_tree_gone(root, prefix, files):
    survivors = [f for f in files if (root / f).exists()]
    assert survivors == [], f"files survived the walk: {survivors}"
    assert not (root / prefix).exists(), "the tree root survived"


def _origin_deletes(lines):
    """The DELETE-line URIs, in origin-log order."""
    return [_uri(ln) for ln in lines if ln.startswith("DELETE ")]


def _assert_children_before_parents(deletes, prefix):
    """Every child's origin DELETE strictly precedes its parent's, at every
    level of the _seed_tree shape."""
    def last(path):
        hits = [i for i, uri in enumerate(deletes) if uri.endswith(path)]
        assert hits, f"no origin DELETE for {path!r} in: {deletes}"
        return hits[-1]

    assert last(f"/{prefix}/d1/d2/f2.bin") < last(f"/{prefix}/d1/d2")
    assert last(f"/{prefix}/d1/f1a.bin") < last(f"/{prefix}/d1")
    assert last(f"/{prefix}/d1/f1b.bin") < last(f"/{prefix}/d1")
    assert last(f"/{prefix}/d1/d2") < last(f"/{prefix}/d1")
    assert last(f"/{prefix}/f0.bin") < last(f"/{prefix}")
    assert last(f"/{prefix}/d1") < last(f"/{prefix}")


def _is_batch_post(ln):
    return ln.startswith("POST") and "delete" in ln


def _is_per_file_delete(ln):
    return ln.startswith("DELETE ") and _uri(ln).endswith(".bin")


def _batch_shape(new_lines):
    """(?delete POSTs, per-file DELETEs) among the new store-log lines."""
    batch = [ln for ln in new_lines if _is_batch_post(ln)]
    per_file = [ln for ln in new_lines if _is_per_file_delete(ln)]
    return batch, per_file


# --------------------------------------------------------------------------- #
# success                                                                      #
# --------------------------------------------------------------------------- #

def test_http_rmtree_children_before_parents(srv):
    """(success) over sd_http (no batch verb) the classic walk survives the
    W5 dispatch rewire byte-for-byte: every child's origin DELETE precedes its
    parent's, three levels deep."""
    origin = srv["dirs"]["origin_data"]
    files = _seed_tree(origin, "rmt-http")
    before = len(_lines(srv["dav_log"]))

    # without the opt-in header the pinned require-empty policy answers 409
    r = requests.delete(f"http://{HOST}:{srv['http_port']}/rmt-http",
                        timeout=60)
    assert r.status_code == 409, f"no-header DELETE should 409, got {r.status_code}"

    r = requests.delete(f"http://{HOST}:{srv['http_port']}/rmt-http",
                        headers={"Depth": "infinity"}, timeout=60)
    assert r.status_code in (200, 204), f"{r.status_code} {r.text[:300]}"
    _assert_tree_gone(origin, "rmt-http", files)

    deletes = _origin_deletes(_lines(srv["dav_log"])[before:])
    _assert_children_before_parents(deletes, "rmt-http")


def test_remote_rmtree_batches_within_levels(srv):
    """(success) over sd_remote (CAP_BULK_DELETE) the files leave in ?delete
    batches — never one upstream DELETE per file — and the batch metric books
    the 4 files in its VALUE across 1..3 flushes (one per non-empty directory
    boundary, readdir order deciding how early siblings ride along)."""
    store = srv["dirs"]["s3store"]
    files = _seed_tree(store, "rmt-remote")
    before = len(_lines(srv["s3_log"]))
    batches0 = _metric(srv, "brix_vfs_bulk_delete_batches_total", "remote")
    keys0 = _metric(srv, "brix_vfs_bulk_delete_keys_total", "remote")

    r = requests.delete(f"http://{HOST}:{srv['remote_port']}/rmt-remote",
                        headers={"Depth": "infinity"}, timeout=60)
    assert r.status_code in (200, 204), f"{r.status_code} {r.text[:300]}"
    _assert_tree_gone(store, "rmt-remote", files)

    batch_posts, per_file = _batch_shape(_lines(srv["s3_log"])[before:])
    assert batch_posts, "no upstream ?delete batch was issued"
    assert per_file == [], (
        "files left via per-key upstream DELETEs instead of the batch:\n"
        + "\n".join(per_file[:5]))

    db = _metric(srv, "brix_vfs_bulk_delete_batches_total", "remote") - batches0
    dk = _metric(srv, "brix_vfs_bulk_delete_keys_total", "remote") - keys0
    assert dk == 4, f"keys metric booked {dk}, expected the 4 files"
    assert 1 <= db <= 3, f"{db} flushes for a 3-directory tree"
    assert db == len(batch_posts), (
        "metric batches and upstream ?delete POSTs disagree")


# --------------------------------------------------------------------------- #
# error                                                                        #
# --------------------------------------------------------------------------- #

def test_rmtree_of_absent_collection_is_404(srv):
    """(error) deleting a collection that does not exist is a clean 404 on
    both arms and books no batch."""
    batches0 = _metric(srv, "brix_vfs_bulk_delete_batches_total", "remote")
    for port in (srv["http_port"], srv["remote_port"]):
        r = requests.delete(f"http://{HOST}:{port}/never-was-here",
                            headers={"Depth": "infinity"}, timeout=30)
        assert r.status_code == 404, f"port {port}: {r.status_code}"
    assert _metric(srv, "brix_vfs_bulk_delete_batches_total", "remote") \
        == batches0


# --------------------------------------------------------------------------- #
# security-negative                                                            #
# --------------------------------------------------------------------------- #

def test_delete_of_export_root_refused(srv):
    """(sec-neg) DELETE of the export root itself is refused on both arms and
    the trees beneath survive — the walk must never be reachable above the
    confinement anchor."""
    origin = srv["dirs"]["origin_data"]
    store = srv["dirs"]["s3store"]
    keep_http = _seed_tree(origin, "rmt-keep-http")
    keep_remote = _seed_tree(store, "rmt-keep-remote")

    for port in (srv["http_port"], srv["remote_port"]):
        r = requests.delete(f"http://{HOST}:{port}/",
                            headers={"Depth": "infinity"}, timeout=30)
        assert r.status_code in (400, 403, 405), (
            f"port {port}: DELETE / answered {r.status_code}")

    for f in keep_http:
        assert (origin / f).exists(), f"{f} was removed by a refused DELETE /"
    for f in keep_remote:
        assert (store / f).exists(), f"{f} was removed by a refused DELETE /"
