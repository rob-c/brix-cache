# tests/test_oci_flatten.py — the D7 layer flattener (phase-104 D7.4):
# OCI layers (built here with Python's tarfile) applied into an overlay
# upper tree via the `flatten_unittest apply` driver.
#   * success: a 3-layer image — adds, overwrite, `.wh.` delete, opaque
#     dir, symlink, hardlink group, pax user.* xattrs — lands as the exact
#     expected tree in the `.brix.*` overlay grammar;
#   * error: --strict device refusal, byte budget, entry budget;
#   * security-negative: `..` members, absolute paths confined, marker
#     smuggling, the two-layer symlink-escape, whiteout of `..`;
#   * oracle: the same layers wrapped in a hand-written OCI layout, unpacked
#     by podman, and diffed against ours (D10.3) — skipped without podman.
# Needs only a C compiler + sqlite3/crypto/z devel libs; no server.
import errno
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import zlib

import pytest

from cmdscripts.container_runtime import container_runtime

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARED = os.path.join(REPO, "shared")
SRC = [os.path.join(SHARED, "oci", f)
       for f in ("flatten_unittest.c", "flatten.c", "tar.c", "tar_pax.c",
                 "tar_digest.c", "digest.c", "stargz.c", "stargz_toc.c")] + \
      [os.path.join(SHARED, "cvmfs", "catalog", "catalog_write.c"),
       os.path.join(SHARED, "cvmfs", "catalog", "catalog.c"),
       os.path.join(SHARED, "cvmfs", "grammar", "hash.c")]


def _compiler():
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not all(os.path.exists(s) for s in SRC):
        pytest.skip("flattener sources missing")
    return cc


@pytest.fixture(scope="module")
def flatten_ut(tmp_path_factory):
    cc = _compiler()
    out = str(tmp_path_factory.mktemp("bin") / "flatten_ut")
    comp = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror", "-I", SHARED, "-o", out,
         *SRC, "-lsqlite3", "-lcrypto", "-lz"],
        capture_output=True, text=True)
    assert comp.returncode == 0, \
        "flatten driver failed to COMPILE:\n%s" % comp.stderr
    return out


def _add(tf, name, data=None, typ=tarfile.REGTYPE, mode=0o644, link="",
         uid=0, gid=0, pax=None, devmajor=0, devminor=0):
    ti = tarfile.TarInfo(name)
    ti.type, ti.mode, ti.uid, ti.gid = typ, mode, uid, gid
    ti.mtime = 1700000000
    ti.linkname = link
    ti.devmajor, ti.devminor = devmajor, devminor
    if pax:
        ti.pax_headers = pax
    if data is not None:
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    else:
        tf.addfile(ti)


def _layer(path, build):
    with tarfile.open(str(path), "w", format=tarfile.PAX_FORMAT) as tf:
        build(tf)
    return path


def _apply(flatten_ut, upper, *layers, flags=()):
    upper.mkdir(exist_ok=True)
    return subprocess.run(
        [flatten_ut, "apply", *flags, str(upper), *[str(l) for l in layers]],
        capture_output=True, text=True, timeout=60)


def _stats(r):
    assert r.returncode == 0, r.stdout + r.stderr
    line = r.stdout.strip().splitlines()[-1]
    assert line.startswith("stats "), r.stdout
    return {k: int(v) for k, v in
            (kv.split("=") for kv in line.split()[1:])}


def _refused(r, needle):
    assert r.returncode == 1, r.stdout + r.stderr
    assert r.stdout.startswith("ERROR:"), r.stdout
    assert needle in r.stdout, r.stdout


def _assert_three_layer_tree(upper):
    assert (upper / "etc/conf").read_bytes() == b"v2\n"
    assert not (upper / "etc/oldfile").exists()
    assert (upper / "etc/.brix.wh.oldfile").exists()
    assert not (upper / "var/cache/old1").exists()
    assert (upper / "var/cache/.brix.opq").exists()
    assert (upper / "var/cache/newfile").read_bytes() == b"fresh"


def _assert_three_layer_links(upper):
    hello = upper / "usr/bin/hello"
    assert hello.read_bytes().startswith(b"#!/bin/sh")
    assert (hello.stat().st_mode & 0o7777) == 0o755
    assert os.readlink(upper / "usr/bin/h") == "hello"
    assert (upper / "usr/bin/hello2").stat().st_ino == hello.stat().st_ino
    assert (upper / "srv/data.bin").stat().st_size == 1000
    return hello


def _assert_three_layer_stats(stats):
    assert (stats["files"], stats["dirs"], stats["links"]) == (7, 5, 2)
    assert (stats["wh"], stats["opq"], stats["skip"]) == (1, 1, 0)
    assert stats["bytes"] == 3 + 3 + 18 + 5 + 3 + 5 + 1000


def _assert_xattr(hello):
    try:
        assert os.getxattr(hello, "user.color") == b"red"
    except OSError as error:
        if error.errno != errno.ENOTSUP:
            raise


# ---- success: a 3-layer image lands as the expected tree ------------------

def test_three_layer_image(flatten_ut, tmp_path):
    def base(tf):
        _add(tf, "etc", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "etc/conf", b"v1\n")
        _add(tf, "etc/oldfile", b"old")
        _add(tf, "usr", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "usr/bin", typ=tarfile.DIRTYPE, mode=0o755)
        # xattr goes on a file no later layer replaces — an overwrite is a
        # whole-file swap, so only the winning member's xattrs survive
        _add(tf, "usr/bin/hello", b"#!/bin/sh\necho hi\n", mode=0o755,
             pax={"SCHILY.xattr.user.color": "red"})
        _add(tf, "usr/bin/h", typ=tarfile.SYMTYPE, link="hello")
        # link members carry the target's mode (writers stat the target);
        # its metadata is applied through the shared inode
        _add(tf, "usr/bin/hello2", typ=tarfile.LNKTYPE, link="usr/bin/hello",
             mode=0o755)
        _add(tf, "var", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "var/cache", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "var/cache/old1", b"stale")

    def update(tf):
        _add(tf, "etc/conf", b"v2\n")                  # overwrite wins
        _add(tf, "etc/.wh.oldfile", b"")               # OCI whiteout
        _add(tf, "var/cache/.wh..wh..opq", b"")        # opaque dir
        _add(tf, "var/cache/newfile", b"fresh")

    def top(tf):
        _add(tf, "srv/data.bin", b"z" * 1000)          # implicit parents

    upper = tmp_path / "upper"
    r = _apply(flatten_ut, upper,
               _layer(tmp_path / "l1.tar", base),
               _layer(tmp_path / "l2.tar", update),
               _layer(tmp_path / "l3.tar", top))
    st = _stats(r)

    _assert_three_layer_tree(upper)
    hello = _assert_three_layer_links(upper)
    _assert_three_layer_stats(st)
    _assert_xattr(hello)


def test_hardlink_across_layers_shares_the_inode(flatten_ut, tmp_path):
    """A link member names a path in the FLATTENED tree, not in its own layer.

    Image builders emit one member with the bytes and hardlinks for every
    other name that shares the inode — and the bytes routinely live in a layer
    laid down long before the link. Resolving the target against the layer
    being read would leave the second name empty; resolving it against the
    accumulated upper tree is what makes a multi-layer image with a busybox
    farm of links come out the size it went in.
    """
    def base(tf):
        _add(tf, "bin", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "bin/busybox", b"#!/bin/sh\nexit 0\n", mode=0o755)

    def links(tf):
        _add(tf, "bin/sh", typ=tarfile.LNKTYPE, link="bin/busybox", mode=0o755)
        _add(tf, "bin/ls", typ=tarfile.LNKTYPE, link="bin/busybox", mode=0o755)

    upper = tmp_path / "upper"
    st = _stats(_apply(flatten_ut, upper,
                       _layer(tmp_path / "l1.tar", base),
                       _layer(tmp_path / "l2.tar", links)))

    target = upper / "bin" / "busybox"
    assert (upper / "bin" / "sh").stat().st_ino == target.stat().st_ino
    assert (upper / "bin" / "ls").stat().st_ino == target.stat().st_ino
    assert st["links"] == 2
    # The bytes were counted once, when they arrived: a link is a name, and
    # charging the budget per name is how a link farm looks like a bomb.
    assert st["bytes"] == 17


def test_hardlink_to_a_whiteouted_target_is_refused(flatten_ut, tmp_path):
    """A link with nothing to point at is a broken image, not an empty file.

    Materialising it as a zero-length regular file would publish a tree in
    which `sh` exists and does nothing — the failure surfaces at run time, on
    a node, as an exec that silently does nothing. Refusing at ingest keeps it
    where a human is looking.
    """
    def base(tf):
        _add(tf, "bin", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "bin/busybox", b"#!/bin/sh\nexit 0\n", mode=0o755)

    def gone(tf):
        _add(tf, "bin/.wh.busybox", b"")
        _add(tf, "bin/sh", typ=tarfile.LNKTYPE, link="bin/busybox", mode=0o755)

    upper = tmp_path / "upper"
    _refused(_apply(flatten_ut, upper,
                    _layer(tmp_path / "l1.tar", base),
                    _layer(tmp_path / "l2.tar", gone)), "hardlink")
    assert not (upper / "bin" / "sh").exists()


# ---- oracle: the same image, flattened by podman (phase-104 D10.3) --------

def _oci_layout(root, layer_tars):
    """Write a minimal OCI image layout around already-built layer tars.

    Hand-rolled rather than produced by a builder: the point of the oracle is
    that podman and the flattener are fed the *same bytes*, and the only way
    to be sure of that is to wrap the very tars the flattener was given.
    """
    blobs = root / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    def put(payload):
        digest = hashlib.sha256(payload).hexdigest()
        (blobs / digest).write_bytes(payload)
        return "sha256:" + digest, len(payload)

    diff_ids, descriptors = [], []
    for tar in layer_tars:
        raw = tar.read_bytes()
        diff_ids.append("sha256:" + hashlib.sha256(raw).hexdigest())
        digest, size = put(gzip.compress(raw))
        descriptors.append({
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": digest, "size": size})

    cfg, cfg_size = put(json.dumps({
        "architecture": "amd64", "os": "linux",
        "config": {"Cmd": ["/bin/hello"]},
        "rootfs": {"type": "layers", "diff_ids": diff_ids}}).encode())
    man, man_size = put(json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": cfg, "size": cfg_size},
        "layers": descriptors}).encode())

    (root / "index.json").write_text(json.dumps({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": man, "size": man_size,
            "annotations": {"org.opencontainers.image.ref.name": "oracle"}}]}))
    (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    return root


def _rt(*argv, rt, timeout=300):
    r = subprocess.run([rt, *argv], capture_output=True, text=True,
                       timeout=timeout)
    assert r.returncode == 0, " ".join(argv) + "\n" + r.stdout + r.stderr
    return r.stdout.strip()


def _podman_rootfs(rt, layout, tar_out):
    """Pull the layout, export the container's rootfs, leave nothing behind."""
    image = _rt("pull", "oci:%s:oracle" % layout, rt=rt).splitlines()[-1]
    container = None
    try:
        container = _rt("create", image, rt=rt).splitlines()[-1]
        with open(str(tar_out), "wb") as fh:
            r = subprocess.run([rt, "export", container], stdout=fh,
                               stderr=subprocess.PIPE, text=True, timeout=300)
        assert r.returncode == 0, r.stderr
    finally:
        if container:
            subprocess.run([rt, "rm", "-f", container], capture_output=True,
                           timeout=120)
        subprocess.run([rt, "rmi", "-f", image], capture_output=True,
                       timeout=120)
    return tar_out


def _shape_from_tar(path):
    """path -> (kind, mode, payload) for one exported rootfs, plus link groups.

    Only what a flattener decides is compared: kind, permission bits, file
    bytes, symlink target, and which names share an inode. Ownership, mtimes
    and device numbers are the unpacker's business, not the grammar's.
    """
    shape, groups = {}, {}
    with tarfile.open(str(path)) as tf:
        for m in tf.getmembers():
            name = m.name.lstrip("./").rstrip("/")
            if not name:
                continue
            if m.isdir():
                shape[name] = ("dir", m.mode, None)
            elif m.issym():
                shape[name] = ("sym", None, m.linkname)
            elif m.islnk():
                target = m.linkname.lstrip("./")
                shape[name] = shape.get(target, ("reg", m.mode, None))
                groups.setdefault(target, {target}).add(name)
            elif m.isfile():
                shape[name] = ("reg", m.mode, tf.extractfile(m).read())
            else:
                shape[name] = ("other", m.mode, None)
    return shape, {frozenset(v) for v in groups.values()}


def _record_tree_entry(shape, inodes, rel, full, stat_result):
    mode = stat_result.st_mode & 0o7777
    if stat.S_ISDIR(stat_result.st_mode):
        shape[rel] = ("dir", mode, None)
        return
    if stat.S_ISLNK(stat_result.st_mode):
        shape[rel] = ("sym", None, os.readlink(full))
        return
    if stat.S_ISREG(stat_result.st_mode):
        shape[rel] = ("reg", mode, open(full, "rb").read())
        if stat_result.st_nlink > 1:
            inodes.setdefault(stat_result.st_ino, set()).add(rel)
        return
    shape[rel] = ("other", mode, None)


def _shape_from_tree(root):
    """The same shape, read off the flattened upper tree.

    `.brix.*` names are the overlay grammar's own bookkeeping — a deletion or
    an opaque marker is precisely a name that must NOT be in the oracle — so
    they are collected separately rather than compared.
    """
    shape, inodes, markers = {}, {}, set()
    for dirpath, dirnames, filenames in os.walk(str(root)):
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, str(root))
            if name.startswith(".brix."):
                markers.add(rel)
                continue
            _record_tree_entry(shape, inodes, rel, full, os.lstat(full))
    return shape, {frozenset(v) for v in inodes.values()}, markers


def _assert_same_shape(ours, theirs):
    assert sorted(ours) == sorted(theirs), (
        "only ours: %s\nonly theirs: %s"
        % (sorted(set(ours) - set(theirs)), sorted(set(theirs) - set(ours))))
    for path in sorted(ours):
        assert ours[path] == theirs[path], "%s: %r != %r" % (
            path, ours[path], theirs[path])


def _assert_oracle_bookkeeping(markers, theirs, our_groups, their_groups):
    expected = {os.path.join("etc", ".brix.wh.gone"),
                os.path.join("var", "cache", ".brix.opq")}
    assert markers == expected
    assert "etc/gone" not in theirs and "var/cache/stale" not in theirs
    expected_links = {frozenset({"bin/busybox", "bin/sh"})}
    assert our_groups == their_groups == expected_links


@pytest.mark.timeout(300)          # a cold container store pulls and unpacks
def test_podman_export_diff_clean(flatten_ut, tmp_path):
    """The flattener and podman must disagree about nothing that is visible.

    Every property this lane asserts on its own — whiteouts delete, opaque
    dirs truncate, a later layer wins, links stay links — is our reading of
    the spec. This test replaces the reading with a second implementation:
    the same layer tars go into a hand-written OCI layout, podman unpacks
    them with its own storage driver, and `podman export` hands back the
    rootfs it believes in. A difference is a bug in one of us, and either way
    it is worth knowing before an image is published into /cvmfs.

    podman only, and offline by construction: the layout is built from the
    test's own layers, so nothing is pulled from a network and no base image
    is needed. Rootless docker would need daemon-level configuration a test
    may not perform.

    The hardlink here is deliberately *within* one layer. containers/storage
    unpacks each layer into an empty directory before it is stacked, so a link
    whose target arrived in an earlier layer fails the pull outright with
    ENOENT — the cross-layer case this lane covers separately (and that a
    running overlay mount resolves fine) is simply outside what this oracle
    can be asked. See the phase doc's DRIFT table.
    """
    rt = container_runtime(candidates=("podman",))
    if rt is None:
        pytest.skip("no usable podman for the flattener oracle")

    def base(tf):
        _add(tf, "etc", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "etc/conf", b"v1\n")
        _add(tf, "etc/gone", b"bye")
        _add(tf, "bin", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "bin/busybox", b"#!/bin/sh\nexit 0\n", mode=0o755)
        _add(tf, "bin/h", typ=tarfile.SYMTYPE, link="busybox")
        _add(tf, "bin/sh", typ=tarfile.LNKTYPE, link="bin/busybox",
             mode=0o755)                                # hardlink, same layer
        _add(tf, "var", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "var/cache", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "var/cache/stale", b"old")

    def update(tf):
        _add(tf, "etc/conf", b"v2\n")                   # later layer wins
        _add(tf, "etc/.wh.gone", b"")                   # whiteout
        _add(tf, "var/cache/.wh..wh..opq", b"")         # opaque directory
        _add(tf, "var/cache/fresh", b"new")
        _add(tf, "srv/data", b"z" * 100)                # implicit parent

    layers = [_layer(tmp_path / "l1.tar", base),
              _layer(tmp_path / "l2.tar", update)]

    upper = tmp_path / "upper"
    _stats(_apply(flatten_ut, upper, *layers))
    ours, our_groups, markers = _shape_from_tree(upper)

    layout = _oci_layout(tmp_path / "layout", layers)
    theirs, their_groups = _shape_from_tar(
        _podman_rootfs(rt, layout, tmp_path / "rootfs.tar"))

    _assert_same_shape(ours, theirs)
    _assert_oracle_bookkeeping(markers, theirs, our_groups, their_groups)



from split_continuation import load as _load_continuation
_load_continuation(globals(), __file__, "_oci_flatten_part2.py")
