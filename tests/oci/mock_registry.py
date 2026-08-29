#!/usr/bin/env python3
# tests/oci/mock_registry.py — synthetic OCI distribution registry with fault
# injection (phase-104 §0.8.1, control plane per Appendix G.1).
#
# Serves the /v2/ matrix (API check, manifests with Docker-Content-Digest,
# blobs, paginated tags/list) over a deterministic in-memory image set built
# at start: a 2-layer and a 3-layer image plus one multi-arch index. Layer
# bodies are real gzipped tars so the ingest lanes can reuse the same mock.
# Modes: --auth (Bearer token dance against its own /token), --push (upload
# state machine), --blob-redirect URL (302 the blob plane to a CDN twin),
# --cdn (be that twin: serve blobs, count Authorization headers). Faults via
# /ctl/fault, mock_stratum1 vocabulary + wrong_digest_header/retag/
# toomanyrequests; they apply to the TOKEN plane as well as the data plane, so
# a lane that means only one of the two passes path_re.
import argparse, base64, gzip, hashlib, io, json, random, re, socket, zlib
import tarfile, threading, time, uuid
from urllib.parse import unquote
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MT_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MT_INDEX = "application/vnd.oci.image.index.v1+json"
MT_CONFIG = "application/vnd.oci.image.config.v1+json"
MT_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
# The Docker twins of the same four types. A mirror that returns an OCI
# content-type for a Docker manifest sends the client down the wrong unpack
# path, so both dialects have to exist upstream for the round-trip to mean
# anything (§0.7.3).
MT_D_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
MT_D_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
MT_D_CONFIG = "application/vnd.docker.container.image.v1+json"
MT_D_LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip"
MT_LAYER_ZSTD = "application/vnd.oci.image.layer.v1.tar+zstd"

STATE = {"log": [], "fault": {"kind": "none", "count": 0, "path_re": None},
         "blobs": {}, "manifests": {}, "repos": {}, "uploads": {},
         "transcript": [], "token_count": 0, "tokens": {},
         "saw_authorization": 0, "auth": False, "push": False,
         "realm": None, "basic": None, "token_ttl": 300, "token_key": "token",
         "blob_redirect": None, "blob_redirect_sign": False,
         "require_signature": False, "token_len": 0, "cdn": False,
         "token_redirect_loop": False,
         "page_tags": 0,
         "users": {}, "private": {},
         "shared": {},
         "lock": threading.Lock()}


def sha(body, alg="sha256"):
    # The registry grammar registers two algorithms; a mirror that only ever
    # sees sha256 upstream can never prove it handles the other one.
    h = hashlib.sha512(body) if alg == "sha512" else hashlib.sha256(body)
    return "%s:%s" % (alg, h.hexdigest())


# The three entries eStargz adds to a layer it converts. An ingest that
# publishes a whole rootfs has to drop them again (phase-104 D15.7).
STARGZ_META = ("stargz.index.json", ".prefetch.landmark",
               ".no.prefetch.landmark")


def _blocks(raw, parts):
    """Split at 512-byte tar-block boundaries, as a per-file chunker does."""
    step = ((len(raw) // parts) // 512) * 512 or 512
    return [raw[i:i + step] for i in range(0, len(raw), step)]


def _gz_chain(raw):
    """A CHAIN of gzip members, one per chunk — the eStargz shape. Plain
    `gzip -d` and any correct reader see one continuous tar."""
    out = b""
    for chunk in _blocks(raw, 3):
        g = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        out += g.compress(chunk) + g.flush()
    return out


def _zstd_chain(raw):
    """A chain of zstd frames plus a trailing skippable frame where a
    zstd:chunked producer parks its TOC. None when the module is absent."""
    try:
        import zstandard
    except ImportError:
        return None
    cc = zstandard.ZstdCompressor(level=3)
    toc = b'{"version":1,"entries":[]}'
    return b"".join(cc.compress(c) for c in _blocks(raw, 3)) \
        + b"\x50\x2a\x4d\x18" + len(toc).to_bytes(4, "little") + toc


def _layer_names(entries, codec):
    names = list(entries)
    if codec == "estargz":
        names.extend((name, 16) for name in STARGZ_META)
    return names


def _tar_layer(rng, entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as t:
        for name, size in entries:
            body = bytes(rng.getrandbits(8) for _ in range(size))
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(body), 0, 0o644
            t.addfile(ti, io.BytesIO(body))
    return raw.getvalue()


def _gzip_layer(raw):
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as stream:
        stream.write(raw)
    return output.getvalue(), sha(raw), MT_LAYER


def _encode_layer(raw, codec):
    if codec == "estargz":
        return _gz_chain(raw), sha(raw), MT_LAYER
    if codec == "zstd":
        body = _zstd_chain(raw)
        return (body, sha(raw), MT_LAYER_ZSTD) if body is not None else None
    return _gzip_layer(raw)


def build_layer(rng, entries, codec="gzip"):
    """Build a deterministic gzip, eStargz, or zstd OCI layer."""
    raw = _tar_layer(rng, _layer_names(entries, codec))
    return _encode_layer(raw, codec)


def shared_layer(rng, key, entries):
    """A layer built ONCE and reused by every image that names it. Without a
    genuinely shared blob no lane can tell `--layout layered` skipping work it
    already did from it simply doing the work twice quickly."""
    if key not in STATE["shared"]:
        STATE["shared"][key] = build_layer(rng, entries)
    return STATE["shared"][key]


def put_blob(body, alg="sha256"):
    d = sha(body, alg)
    STATE["blobs"][d] = body
    return d


def put_manifest(name, tag, body, mt, alg="sha256"):
    d = sha(body, alg)
    STATE["manifests"][d] = (body, mt)
    repo = STATE["repos"].setdefault(name, {"tags": {}})
    if tag is not None:
        repo["tags"][tag] = d
    return d


def _dialect_media_types(dialect):
    if dialect == "oci":
        return MT_MANIFEST, MT_CONFIG, MT_LAYER
    return MT_D_MANIFEST, MT_D_CONFIG, MT_D_LAYER


def _build_layer_spec(rng, spec):
    if isinstance(spec, tuple) and len(spec) == 3:
        return build_layer(rng, spec[1], codec=spec[0])
    if isinstance(spec, tuple):
        return shared_layer(rng, spec[0], spec[1])
    return build_layer(rng, spec)


def _layer_descriptor(body, media_type, default_media_type, alg):
    selected_type = default_media_type if media_type == MT_LAYER else media_type
    return {"mediaType": selected_type, "digest": put_blob(body, alg),
            "size": len(body)}


def _image_config(arch, diff_ids):
    doc = {"architecture": arch, "os": "linux",
           "config": {"Env": ["PATH=/usr/bin:/bin"]},
           "rootfs": {"type": "layers", "diff_ids": diff_ids}}
    return json.dumps(doc, separators=(",", ":")).encode()


def _image_manifest(media_types, config_digest, config_size, layers):
    manifest_type, config_type, _layer_type = media_types
    doc = {"schemaVersion": 2, "mediaType": manifest_type,
           "config": {"mediaType": config_type, "digest": config_digest,
                      "size": config_size},
           "layers": layers}
    return json.dumps(doc, separators=(",", ":")).encode()


def _rewrite_diff_ids(diff_ids, rewrite):
    if rewrite is None:
        return diff_ids
    return rewrite(diff_ids)


def make_image(rng, name, tag, layer_specs, arch, dialect="oci", diffids=None,
               alg="sha256"):
    """diffids: optional rewrite of the config's rootfs.diff_ids (D8.e lanes
    need a config that lies about the uncompressed layer bytes while every
    compressed blob digest still checks out)."""
    media_types = _dialect_media_types(dialect)
    manifest_type, _config_type, layer_type = media_types
    layers, diff_ids = [], []
    for spec in layer_specs:
        gzbody, diff, media_type = _build_layer_spec(rng, spec)
        layers.append(_layer_descriptor(gzbody, media_type, layer_type, alg))
        diff_ids.append(diff)
    config = _image_config(arch, _rewrite_diff_ids(diff_ids, diffids))
    manifest = _image_manifest(media_types, put_blob(config, alg), len(config), layers)
    return put_manifest(name, tag, manifest, manifest_type, alg), len(manifest)


def make_index(rng, name, tag, dialect="oci"):
    """A two-arch index/list whose children are of the matching dialect."""
    mt_idx, mt_child = ((MT_INDEX, MT_MANIFEST) if dialect == "oci"
                        else (MT_D_LIST, MT_D_MANIFEST))
    entries = []
    for arch in ("amd64", "arm64"):
        d, n = make_image(rng, name, None, [[(f"bin/{arch}", 2000)]], arch,
                          dialect=dialect)
        entries.append({"mediaType": mt_child, "digest": d, "size": n,
                        "platform": {"os": "linux", "architecture": arch}})
    idx = json.dumps({"schemaVersion": 2, "mediaType": mt_idx,
                      "manifests": entries}, separators=(",", ":")).encode()
    return put_manifest(name, tag, idx, mt_idx)


def build_images(seed):
    rng = random.Random(seed)
    make_image(rng, "lab/app", "v1",
               [[("bin/tool", 3000), ("etc/conf", 200)],
                [("share/data", 8000)]], "amd64")
    make_image(rng, "lab/app", "v2",
               [[("bin/tool", 3000), ("etc/conf", 200)],
                [("share/data", 8000)],
                [("share/extra", 500), ("share/.wh.data", 0)]], "amd64")
    make_index(rng, "lab/multi", "latest")
    # Every digest in this one — manifest, config and layers — is sha512, so
    # a leg that pulls it exercises the whole algorithm-keyed path rather
    # than just the grammar's willingness to parse the name.
    make_image(rng, "lab/sha512app", "v1",
               [[("bin/tool", 2500), ("etc/conf", 300)]], "amd64",
               alg="sha512")
    # The Docker dialect of both shapes, for the media-type round trip.
    make_image(rng, "lab/dockerapp", "v1",
               [[("bin/tool", 1500)]], "amd64", dialect="docker")
    make_index(rng, "lab/dockermulti", "latest", dialect="docker")
    # D8.e: configs that disagree with their own layers — one pairs the
    # diff_ids the wrong way round, one declares too few. Both pull and
    # publish cleanly without --verify-diffids: the blob digests are honest.
    two = [[("bin/tool", 3000)], [("share/data", 8000)]]
    make_image(rng, "lab/liar", "v1", two, "amd64",
               diffids=lambda ids: list(reversed(ids)))
    make_image(rng, "lab/shortcfg", "v1", two, "amd64",
               diffids=lambda ids: ids[:1])
    # D15.6: three images over ONE base layer. `--layout layered` must fetch
    # that base for the first of them and for none of the others.
    base = ("stack-base", [("bin/base", 4000), ("etc/base.conf", 100)])
    make_image(rng, "lab/stack", "base", [base], "amd64")
    make_image(rng, "lab/stack", "childa", [base, [("opt/a", 700)]], "amd64")
    make_image(rng, "lab/stack", "childb", [base, [("opt/b", 900)]], "amd64")
    # D15.7: the same content in the two lazy-pull layer encodings. The
    # zstd:chunked one exists only where the compressor does; a lane that
    # needs it importorskips the same module.
    chunk = [("bin/app", 3000), ("etc/app.conf", 120)]
    make_image(rng, "lab/chunked", "estargz",
               [("estargz", chunk, None)], "amd64")
    if _zstd_chain(b"") is not None:
        make_image(rng, "lab/chunked", "zstd", [("zstd", chunk, None)],
                   "amd64")

# Standalone-spawned server: only tests/oci/ is on sys.path, but the shard
# loader lives one level up in tests/ — put it on the path before importing.
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from split_continuation import load as _load_shard_mock_registry_part3
_load_shard_mock_registry_part3(globals(), __file__, "mock_registry_part3.py")


from split_continuation import load as _load_shard_mock_registry_part2
_load_shard_mock_registry_part2(globals(), __file__, "mock_registry_part2.py")
