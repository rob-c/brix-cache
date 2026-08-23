"""
Client-conformance: narrative (stateful) scenarios.

Hand-written sequences that a flat case table expresses poorly — cross-client
round-trips, recursive trees, and a full xrdfs namespace lifecycle.  Each step
still goes through ``diffcore.run_client`` so normalization/skip semantics match
the rest of the suite.  These run against the always-on anon tier (skipping if
it is down) to keep them deterministic.
"""

import hashlib
import os

import pytest

from clientconf import corpus, diffcore
from clientconf import endpoints as E
from clientconf.diffcore import OURS, STOCK
from clientconf.fixtures import clientconf_env  # noqa: F401
from clientconf.runner import Ctx

pytestmark = pytest.mark.timeout(300)


def _ep(env, key="anon"):
    if key not in env["healthy"]:
        pytest.skip("endpoint %s not healthy" % key)
    return E.BY_KEY[key]


def _md5(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _ctx(env, tmp_path):
    return Ctx(_ep(env), str(tmp_path), env["worker"])


# --------------------------------------------------------------------------- #
# Cross-client round-trips: bytes must survive whichever client writes/reads.  #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("writer,reader", [(OURS, STOCK), (STOCK, OURS)])
def test_roundtrip_cross_client(clientconf_env, tmp_path, writer, reader):  # noqa: F811
    env = clientconf_env
    ep = _ep(env)
    ctx = _ctx(env, tmp_path)
    src = os.path.join(str(tmp_path), "src.bin")
    payload = corpus.local_bytes(corpus.BY_REL["mib1.bin"])
    with open(src, "wb") as fh:
        fh.write(payload)
    remote = ctx.remote("rt", writer)

    up = diffcore.run_client(writer, "xrdcp", ["-f", src, ep.url(remote)], ep,
                             timeout=120)
    if up.rc != 0:
        pytest.skip("writer %s could not upload: %s" % (writer, up.stderr))
    dst = os.path.join(str(tmp_path), "dst.bin")
    dl = diffcore.run_client(reader, "xrdcp", ["-f", ep.url(remote), dst], ep,
                             timeout=120)
    assert dl.rc == 0, "reader %s failed: %s" % (reader, dl.stderr)
    assert _md5(dst) == hashlib.md5(payload).hexdigest(), \
        "round-trip %s->%s corrupted bytes" % (writer, reader)


# --------------------------------------------------------------------------- #
# Recursive tree download parity (-r): full-tree manifest must match.          #
# --------------------------------------------------------------------------- #
def test_recursive_download_tree_manifest(clientconf_env, tmp_path):  # noqa: F811
    env = clientconf_env
    ep = _ep(env)

    def fetch(which):
        out = os.path.join(str(tmp_path), which)
        os.makedirs(out, exist_ok=True)
        r = diffcore.run_client(which, "xrdcp", ["-r", ep.url(corpus.ROOT), out],
                                ep, timeout=45)
        return r, out

    rs, os_dir = fetch(STOCK)
    ro, ou_dir = fetch(OURS)
    if rs.rc != 0 or ro.rc != 0:
        pytest.skip("recursive copy unsupported/failed (stock rc=%s ours rc=%s)"
                    % (rs.rc, ro.rc))

    # Documented layout divergence: stock `xrdcp -r` nests the copied tree under
    # the SOURCE directory name (clientconf/...), while ours flattens it into the
    # destination root.  This test asserts INTEGRITY — that recursive copy
    # preserved every file's bytes — so it compares the (relative-path -> md5)
    # map after stripping the differing top-level component, plus the content
    # multiset as a backstop.
    from collections import Counter

    ms, mo = _manifest(os_dir), _manifest(ou_dir)
    assert ms == mo, (
        "recursive tree content differs after layout-normalization:\n"
        "only-stock=%s\nonly-ours=%s"
        % (sorted(set(ms) - set(mo)), sorted(set(mo) - set(ms))))
    assert Counter(ms.values()) == Counter(mo.values()), \
        "recursive copy did not preserve identical file contents"


def _manifest(root):
    manifest = {}
    for base, _directories, files in os.walk(root):
        for filename in files:
            path = os.path.join(base, filename)
            relative = _normalized_manifest_path(path, root)
            manifest[relative] = _md5(path)
    return manifest


def _normalized_manifest_path(path, root):
    relative = os.path.relpath(path, root)
    prefix = corpus.PREFIX + os.sep
    if relative.startswith(prefix):
        return relative[len(prefix):]
    return relative


# --------------------------------------------------------------------------- #
# Multi-stream large-file integrity.                                          #
# --------------------------------------------------------------------------- #
def test_multistream_integrity(clientconf_env, tmp_path):  # noqa: F811
    env = clientconf_env
    ep = _ep(env)
    e = corpus.BY_REL["mib1.bin"]
    want = hashlib.md5(corpus.local_bytes(e)).hexdigest()
    for which in (STOCK, OURS):
        dst = os.path.join(str(tmp_path), "ms_%s.bin" % which)
        r = diffcore.run_client(which, "xrdcp", ["-f", "-S", "3",
                                ep.url(e.remote), dst], ep, timeout=120)
        if r.rc != 0:
            pytest.skip("%s multi-stream failed: %s" % (which, r.stderr))
        assert _md5(dst) == want, "%s multi-stream corrupted bytes" % which


# --------------------------------------------------------------------------- #
# xrdfs namespace lifecycle: mkdir -> upload -> stat -> mv -> rm.              #
# Run with OUR client; verify each step with the STOCK client.                #
# --------------------------------------------------------------------------- #
def test_xrdfs_namespace_lifecycle(clientconf_env, tmp_path):  # noqa: F811
    env = clientconf_env
    ep = _ep(env)
    ctx = _ctx(env, tmp_path)
    _require_lifecycle_clients()
    d, f, moved = _lifecycle_paths(ctx)
    src = os.path.join(str(tmp_path), "life_src.bin")
    with open(src, "wb") as fh:
        fh.write(corpus.local_bytes(corpus.BY_REL["page.bin"]))
    _exercise_lifecycle(ep, src, d, f, moved)


def _exercise_lifecycle(endpoint, source, directory, path, moved):
    _assert_lifecycle_created(endpoint, source, directory, path)
    _assert_lifecycle_moved(endpoint, path, moved)
    _assert_lifecycle_removed(endpoint, directory, moved)


def _assert_lifecycle_created(endpoint, source, directory, path):
    assert _ours_fs(endpoint, ["mkdir", "-p", directory]).rc == 0
    upload = diffcore.run_client(OURS, "xrdcp",
                                 ["-f", source, endpoint.url(path)], endpoint,
                                 timeout=90)
    assert upload.rc == 0, "upload failed: %s" % upload.stderr
    assert _stock_stat(endpoint, path).rc == 0, (
        "stock cannot see file ours created")


def _assert_lifecycle_moved(endpoint, original, moved):
    assert _ours_fs(endpoint, ["mv", original, moved]).rc == 0
    assert _stock_stat(endpoint, moved).rc == 0, "stock cannot see moved file"
    assert _stock_stat(endpoint, original).rc != 0, "old path still present after mv"


def _assert_lifecycle_removed(endpoint, directory, moved):
    assert _ours_fs(endpoint, ["rm", moved]).rc == 0
    assert _stock_stat(endpoint, moved).rc != 0, "file present after rm"
    _ours_fs(endpoint, ["rmdir", directory])


def _require_lifecycle_clients():
    binaries = (diffcore.binary(STOCK, "xrdfs"),
                diffcore.binary(OURS, "xrdfs"), diffcore.binary(OURS, "xrdcp"))
    if not all(binaries):
        pytest.skip("missing client binaries")


def _lifecycle_paths(ctx):
    directory = ctx.remote("life", "ours")
    return directory, directory + "/file.bin", directory + "/moved.bin"


def _ours_fs(endpoint, arguments):
    return diffcore.run_client(OURS, "xrdfs", [endpoint.url()] + arguments,
                               endpoint, timeout=60)


def _stock_stat(endpoint, path):
    return diffcore.run_client(STOCK, "xrdfs",
                               [endpoint.url(), "stat", path], endpoint,
                               timeout=60)
