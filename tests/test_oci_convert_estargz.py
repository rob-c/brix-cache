# tests/test_oci_convert_estargz.py — `brixoci convert --estargz` (phase-104
# D15.8): a hand-built OCI image layout converted layer-by-layer into
# eStargz, with the config's rootfs.diff_ids and the manifest descriptors
# rewritten around the new blobs.
#   * success: every layer blob is a valid eStargz (51-byte footer, TOC as
#     the last entry), each layer descriptor carries the toc.digest
#     annotation the snapshotter reads, and the rewritten config's diff_ids
#     are the digests of the new decompressed layers — not the old ones;
#   * success: the rest of the config (architecture, os, Cmd, history) is
#     copied through byte-identical — only rootfs is rebuilt;
#   * oracle: podman pulls the converted layout and exports the same rootfs
#     the original produces (skipped without a container runtime);
#   * error: an image index is refused, a foreign layer is refused, and
#     `convert` without --estargz is a usage error;
#   * security-negative: nothing in the destination is bound under a digest
#     it does not hash to, and the source's diff_ids never survive into the
#     converted config (an eStargz layer wearing its original's diff_id is
#     a lie a runtime would catch at unpack time).
# Needs client/bin/brixoci; the podman leg is optional.
import gzip
import hashlib
import io
import json
import os
import subprocess
import tarfile

import pytest

from cmdscripts.container_runtime import container_runtime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRIXOCI = os.path.join(REPO_ROOT, "client", "bin", "brixoci")

MT_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MT_INDEX = "application/vnd.oci.image.index.v1+json"
MT_CONFIG = "application/vnd.oci.image.config.v1+json"
MT_LAYER_GZ = "application/vnd.oci.image.layer.v1.tar+gzip"
MT_LAYER_FOREIGN = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
TOC_ANNOTATION = "containerd.io/snapshot/stargz/toc.digest"
FOOTER_LEN = 51

pytestmark = pytest.mark.skipif(
    not os.path.exists(BRIXOCI),
    reason="client/bin/brixoci not built (make -C client brixoci)")


# ---- a layout built by hand, so the fixture owns every byte ---------------

class Layout:
    def __init__(self, root):
        self.root = root
        (root / "blobs" / "sha256").mkdir(parents=True, exist_ok=True)
        (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')

    def put(self, data):
        dig = hashlib.sha256(data).hexdigest()
        (self.root / "blobs" / "sha256" / dig).write_bytes(data)
        return "sha256:" + dig, len(data)

    def blob(self, digest):
        return (self.root / "blobs" / "sha256"
                / digest.split(":", 1)[1]).read_bytes()

    def bind(self, digest, size, mt=MT_MANIFEST, tag="v1"):
        (self.root / "index.json").write_text(json.dumps({
            "schemaVersion": 2,
            "manifests": [{"mediaType": mt, "digest": digest, "size": size,
                           "annotations": {
                               "org.opencontainers.image.ref.name": tag}}]}))

    def manifest(self):
        idx = json.loads((self.root / "index.json").read_text())
        m = idx["manifests"][0]
        return json.loads(self.blob(m["digest"]))


def _tar_gz(entries):
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, body, mode in entries:
            ti = tarfile.TarInfo(name)
            ti.mtime = 1700000000
            ti.mode = mode
            if body is None:
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            else:
                ti.size = len(body)
                tf.addfile(ti, io.BytesIO(body))
    return gzip.compress(plain.getvalue()), plain.getvalue()


LAYER_A = [("bin", None, 0o755),
           ("bin/hello", b"#!/bin/sh\necho hello\n", 0o755),
           ("etc", None, 0o755),
           ("etc/conf", b"key = one\n", 0o644)]
LAYER_B = [("etc/conf", b"key = two\n", 0o644),
           ("usr", None, 0o755),
           ("usr/data", bytes(range(256)) * 32, 0o644)]

CONFIG_EXTRAS = {
    "architecture": "amd64",
    "os": "linux",
    "config": {"Cmd": ["/bin/hello"], "Env": ["PATH=/bin"]},
    "history": [{"created_by": "layer a"}, {"created_by": "layer b"}],
}


def _image(root, layers=(LAYER_A, LAYER_B), layer_mt=MT_LAYER_GZ):
    lay = Layout(root)
    descs, diff_ids = [], []
    for entries in layers:
        blob, plain = _tar_gz(entries)
        dig, size = lay.put(blob)
        descs.append({"mediaType": layer_mt, "digest": dig, "size": size})
        diff_ids.append("sha256:" + hashlib.sha256(plain).hexdigest())
    cfg = dict(CONFIG_EXTRAS)
    cfg["rootfs"] = {"type": "layers", "diff_ids": diff_ids}
    cdig, csize = lay.put(json.dumps(cfg).encode())
    mdig, msize = lay.put(json.dumps({
        "schemaVersion": 2, "mediaType": MT_MANIFEST,
        "config": {"mediaType": MT_CONFIG, "digest": cdig, "size": csize},
        "layers": descs}).encode())
    lay.bind(mdig, msize)
    return lay


def _convert(src, dst, *extra):
    return subprocess.run(
        [BRIXOCI, "convert", "--estargz", "oci:%s" % src, "oci:%s" % dst,
         *extra], capture_output=True, text=True, timeout=300)


def _ok(r):
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout.strip().splitlines()[-1]


# ---- eStargz readers (zlib only — no library speaks this for us) ----------

def _toc(blob):
    foot = blob[-FOOTER_LEN:]
    assert foot[12:14] == b"SG" and foot[32:38] == b"STARGZ", foot.hex()
    off = int(foot[16:32].decode("ascii"), 16)
    import zlib
    member = zlib.decompressobj(31).decompress(blob[off:])
    tf = tarfile.open(fileobj=io.BytesIO(member))
    m = tf.next()
    assert m.name == "stargz.index.json", m.name
    return tf.extractfile(m).read()


# ---- success --------------------------------------------------------------

def test_converted_image_is_estargz_end_to_end(tmp_path):
    src = _image(tmp_path / "src")
    dst_root = tmp_path / "dst"
    dst_root.mkdir()
    _ok(_convert(tmp_path / "src", dst_root))
    dst = Layout(dst_root)

    man = dst.manifest()
    smn = src.manifest()
    assert len(man["layers"]) == len(smn["layers"]) == 2

    diff_ids = []
    for desc in man["layers"]:
        blob = dst.blob(desc["digest"])
        assert desc["size"] == len(blob)
        assert desc["mediaType"] == MT_LAYER_GZ
        # the blob is really named by its own bytes
        assert desc["digest"] == \
            "sha256:" + hashlib.sha256(blob).hexdigest()
        # ... and really is eStargz, with the annotation a snapshotter
        # verifies the TOC against
        raw = _toc(blob)
        assert desc["annotations"][TOC_ANNOTATION] == \
            "sha256:" + hashlib.sha256(raw).hexdigest()
        assert json.loads(raw)["version"] == 1
        diff_ids.append(
            "sha256:" + hashlib.sha256(gzip.decompress(blob)).hexdigest())

    cfg = json.loads(dst.blob(man["config"]["digest"]))
    assert cfg["rootfs"]["diff_ids"] == diff_ids
    assert man["config"]["size"] == len(dst.blob(man["config"]["digest"]))


def test_only_rootfs_is_rewritten_in_the_config(tmp_path):
    src = _image(tmp_path / "src")
    dst_root = tmp_path / "dst"
    dst_root.mkdir()
    _ok(_convert(tmp_path / "src", dst_root))
    dst = Layout(dst_root)

    old = json.loads(src.blob(src.manifest()["config"]["digest"]))
    new = json.loads(dst.blob(dst.manifest()["config"]["digest"]))
    for key, val in CONFIG_EXTRAS.items():
        assert new[key] == val == old[key]
    assert new["rootfs"]["type"] == "layers"


def test_the_original_diffids_do_not_survive(tmp_path):
    """Security-negative: an eStargz layer that keeps its original's
    diff_id claims an unpack result it cannot produce. Every diff_id in the
    converted config must be new, and must describe the new blob."""
    src = _image(tmp_path / "src")
    dst_root = tmp_path / "dst"
    dst_root.mkdir()
    _ok(_convert(tmp_path / "src", dst_root))
    dst = Layout(dst_root)

    old = set(json.loads(
        src.blob(src.manifest()["config"]["digest"]))["rootfs"]["diff_ids"])
    new = json.loads(
        dst.blob(dst.manifest()["config"]["digest"]))["rootfs"]["diff_ids"]
    assert old.isdisjoint(new)
    # and no source blob was rebound under a new name either
    for desc in dst.manifest()["layers"]:
        assert desc["digest"] not in \
            {d["digest"] for d in src.manifest()["layers"]}


def test_every_destination_blob_hashes_to_its_own_name(tmp_path):
    """Security-negative: the layout's contract is that the path claims the
    content. A converter that stages bytes under a digest computed from
    something else would poison every reader that trusts the path."""
    _image(tmp_path / "src")
    dst_root = tmp_path / "dst"
    dst_root.mkdir()
    _ok(_convert(tmp_path / "src", dst_root))

    blobs = (dst_root / "blobs" / "sha256")
    names = sorted(os.listdir(str(blobs)))
    assert len(names) == 4                       # 2 layers + config + manifest
    for name in names:
        data = (blobs / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == name


# ---- oracle ---------------------------------------------------------------

@pytest.mark.timeout(300)
def test_podman_unpacks_the_converted_image_to_the_same_rootfs(tmp_path):
    # the `oci:` transport is podman's (and skopeo's); docker's CLI cannot
    # pull an image layout off disk at all
    rt = container_runtime(candidates=("podman",))
    if rt is None:
        pytest.skip("no usable podman for the convert oracle")
    _image(tmp_path / "src")
    dst_root = tmp_path / "dst"
    dst_root.mkdir()
    # a layout carries no reference of its own, so the converted image is
    # named at the destination — podman can only pull what it can name
    _ok(_convert(tmp_path / "src", dst_root, "--tag", "v1"))

    want = _export_rootfs(rt, tmp_path / "src", tmp_path / "want.tar")
    got = _export_rootfs(rt, dst_root, tmp_path / "got.tar")
    # A runtime with no stargz snapshotter unpacks the layer as the ordinary
    # gzip tar it also is — so the format's own entries land in the rootfs as
    # files. That is the format's documented legacy behaviour, and the reason
    # they carry reserved names: everything ELSE must be byte-identical.
    fmt = {"stargz.index.json", ".no.prefetch.landmark"}
    assert fmt <= set(got), sorted(got)
    assert got[".no.prefetch.landmark"][2] == hashlib.sha256(b"\x0f").hexdigest()
    assert {k: v for k, v in got.items() if k not in fmt} == want


def _export_rootfs(runtime, layout, output):
    image = _pull_layout(runtime, layout)
    container = None
    try:
        container = _create_container(runtime, image)
        _export_container(runtime, container, output)
    finally:
        _remove_runtime_objects(runtime, container, image)
    return _rootfs_shape(output)


def _pull_layout(runtime, layout):
    result = subprocess.run([runtime, "pull", "oci:%s:v1" % layout],
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip().splitlines()[-1]


def _create_container(runtime, image):
    result = subprocess.run([runtime, "create", image], capture_output=True,
                            text=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip().splitlines()[-1]


def _export_container(runtime, container, output):
    with open(str(output), "wb") as stream:
        result = subprocess.run([runtime, "export", container], stdout=stream,
                                stderr=subprocess.PIPE, text=True, timeout=300)
    assert result.returncode == 0, result.stderr


def _remove_runtime_objects(runtime, container, image):
    if container:
        subprocess.run([runtime, "rm", "-f", container], capture_output=True,
                       timeout=120)
    subprocess.run([runtime, "rmi", "-f", image], capture_output=True,
                   timeout=120)


def _rootfs_shape(archive):
    shape = {}
    with tarfile.open(str(archive)) as stream:
        for member in stream.getmembers():
            item = _rootfs_item(stream, member)
            if item is not None:
                name, value = item
                shape[name] = value
    return shape


def _rootfs_item(stream, member):
    name = _archive_name(member.name)
    if not name or name.startswith(("dev/", "proc/", "sys/")):
        return None
    body = stream.extractfile(member).read() if member.isfile() else b""
    value = (member.type, member.mode & 0o777, hashlib.sha256(body).hexdigest())
    return name, value


def _archive_name(name):
    # lstrip("./") would corrupt a leading dot in .no.prefetch.landmark.
    if name.startswith("./"):
        name = name[2:]
    return name.rstrip("/")


def test_the_destination_entry_is_named_by_tag(tmp_path):
    """--tag is the destination layout's ref name; without it the converted
    manifest is bound the way `copy` binds a layout→layout result: present,
    addressable by digest, but unnamed."""
    _image(tmp_path / "src")
    for name, extra in (("named", ("--tag", "edge")), ("bare", ())):
        dst = tmp_path / name
        dst.mkdir()
        digest = _ok(_convert(tmp_path / "src", dst, *extra))
        entry = json.loads((dst / "index.json").read_text())["manifests"][0]
        assert entry["digest"] == digest
        got = entry.get("annotations", {}).get(
            "org.opencontainers.image.ref.name")
        assert got == ("edge" if extra else None), got


# ---- error ---------------------------------------------------------------

def test_a_registry_destination_names_itself(tmp_path):
    """--tag names an entry in a layout. Accepting it for a registry
    destination would silently ignore either it or the reference's own tag —
    two names for one push, one of them a lie."""
    _image(tmp_path / "src")
    r = subprocess.run(
        [BRIXOCI, "convert", "--estargz", "oci:%s" % (tmp_path / "src"),
         "localhost:1/repo:v2",  # net-literal-allow: flag conflict is refused before anything dials (port 1)
         "--tag", "v1"],
        capture_output=True, text=True, timeout=60)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "--tag" in r.stdout + r.stderr


def test_an_image_index_is_refused(tmp_path):
    lay = _image(tmp_path / "src")
    man = lay.manifest()
    mdig, msize = lay.put(json.dumps(man).encode())
    idig, isize = lay.put(json.dumps({
        "schemaVersion": 2, "mediaType": MT_INDEX,
        "manifests": [{"mediaType": MT_MANIFEST, "digest": mdig,
                       "size": msize,
                       "platform": {"os": "linux", "architecture": "amd64"}}]
    }).encode())
    lay.bind(idig, isize, mt=MT_INDEX)

    dst_root = tmp_path / "dst"
    dst_root.mkdir()
    r = _convert(tmp_path / "src", dst_root)
    assert r.returncode == 6, r.stdout + r.stderr
    assert "image index" in r.stderr, r.stderr


def test_a_foreign_layer_is_refused(tmp_path):
    _image(tmp_path / "src", layer_mt=MT_LAYER_FOREIGN)
    dst_root = tmp_path / "dst"
    dst_root.mkdir()
    r = _convert(tmp_path / "src", dst_root)
    assert r.returncode == 6, r.stdout + r.stderr
    assert "foreign layer" in r.stderr, r.stderr


def test_the_target_encoding_must_be_named(tmp_path):
    _image(tmp_path / "src")
    dst_root = tmp_path / "dst"
    dst_root.mkdir()
    r = subprocess.run([BRIXOCI, "convert", "oci:%s" % (tmp_path / "src"),
                        "oci:%s" % dst_root],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "--estargz" in r.stderr, r.stderr


def test_a_config_that_miscounts_its_layers_is_refused(tmp_path):
    """A config whose diff_ids do not line up with the manifest's layers is
    already broken; rewriting it would launder that into a plausible-looking
    image."""
    lay = _image(tmp_path / "src")
    man = lay.manifest()
    cfg = json.loads(lay.blob(man["config"]["digest"]))
    cfg["rootfs"]["diff_ids"] = cfg["rootfs"]["diff_ids"][:1]
    cdig, csize = lay.put(json.dumps(cfg).encode())
    man["config"] = {"mediaType": MT_CONFIG, "digest": cdig, "size": csize}
    mdig, msize = lay.put(json.dumps(man).encode())
    lay.bind(mdig, msize)

    dst_root = tmp_path / "dst"
    dst_root.mkdir()
    r = _convert(tmp_path / "src", dst_root)
    assert r.returncode == 6, r.stdout + r.stderr
    assert "diff_ids" in r.stderr, r.stderr
