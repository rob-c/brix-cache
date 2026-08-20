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
         "transcript": [], "token_count": 0, "tokens": set(),
         "saw_authorization": 0, "auth": False, "push": False,
         "realm": None, "basic": None, "token_ttl": 300, "token_key": "token",
         "blob_redirect": None, "blob_redirect_sign": False,
         "require_signature": False, "token_len": 0, "cdn": False,
         "page_tags": 0,
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


def build_layer(rng, entries, codec="gzip"):
    # entries: [(name, size)]; a ".wh."-prefixed name exercises the D7
    # whiteout translation later. Deterministic bytes + zeroed timestamps.
    # codec: "gzip" one member (the ordinary case), "estargz" a member chain
    # carrying the format's own entries, "zstd" a frame chain with a TOC.
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as t:
        names = [(n, s) for n, s in entries]
        if codec == "estargz":
            names += [(n, 16) for n in STARGZ_META]
        for name, size in names:
            body = bytes(rng.getrandbits(8) for _ in range(size))
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(body), 0, 0o644
            t.addfile(ti, io.BytesIO(body))
    raw = raw.getvalue()
    if codec == "estargz":
        return _gz_chain(raw), sha(raw), MT_LAYER
    if codec == "zstd":
        body = _zstd_chain(raw)
        return (body, sha(raw), MT_LAYER_ZSTD) if body is not None else None
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0) as g:
        g.write(raw)
    return gz.getvalue(), sha(raw), MT_LAYER


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


def make_image(rng, name, tag, layer_specs, arch, dialect="oci", diffids=None,
               alg="sha256"):
    """diffids: optional rewrite of the config's rootfs.diff_ids (D8.e lanes
    need a config that lies about the uncompressed layer bytes while every
    compressed blob digest still checks out)."""
    mt_man, mt_cfg, mt_layer = ((MT_MANIFEST, MT_CONFIG, MT_LAYER)
                                if dialect == "oci"
                                else (MT_D_MANIFEST, MT_D_CONFIG, MT_D_LAYER))
    layers, diff_ids = [], []
    for spec in layer_specs:
        # a tuple spec is ("<shared key>", entries): the same bytes for every
        # image that names it; a bare list is unique to this image.
        # a 3-tuple spec is ("codec", entries, None): the same content in a
        # non-plain layer encoding, which carries its own media type.
        if isinstance(spec, tuple) and len(spec) == 3:
            gzbody, diff, mt = build_layer(rng, spec[1], codec=spec[0])
        elif isinstance(spec, tuple):
            gzbody, diff, mt = shared_layer(rng, spec[0], spec[1])
        else:
            gzbody, diff, mt = build_layer(rng, spec)
        layers.append({"mediaType": mt if mt != MT_LAYER else mt_layer,
                       "digest": put_blob(gzbody, alg),
                       "size": len(gzbody)})
        diff_ids.append(diff)
    if diffids is not None:
        diff_ids = diffids(diff_ids)
    cfg = json.dumps({"architecture": arch, "os": "linux",
                      "config": {"Env": ["PATH=/usr/bin:/bin"]},
                      "rootfs": {"type": "layers", "diff_ids": diff_ids}},
                     separators=(",", ":")).encode()
    man = json.dumps({"schemaVersion": 2, "mediaType": mt_man,
                      "config": {"mediaType": mt_cfg,
                                 "digest": put_blob(cfg, alg),
                                 "size": len(cfg)},
                      "layers": layers}, separators=(",", ":")).encode()
    return put_manifest(name, tag, man, mt_man, alg), len(man)


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


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/octet-stream", extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self):
        # podman/skopeo PATCH layer chunks with Transfer-Encoding: chunked;
        # BaseHTTPRequestHandler leaves the decoding to us.
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            out = bytearray()
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass                    # skip trailers to the blank line
                    return bytes(out)
                out += self.rfile.read(size)
                self.rfile.readline()           # the chunk's trailing CRLF
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def _log(self):
        keep = {k: self.headers[k] for k in ("Accept", "Range")
                if self.headers.get(k)}
        auth = self.headers.get("Authorization")
        keep["has_authorization"] = auth is not None
        # The SCHEME, never the credential: a lane has to be able to prove that
        # Basic reached the token endpoint and nothing else, and logging the
        # secret itself would put it in every failure dump.
        keep["auth_scheme"] = auth.split(" ", 1)[0] if auth else None
        with STATE["lock"]:
            STATE["log"].append({"method": self.command, "path": self.path,
                                 "headers": keep, "ts": time.time()})
            if self.headers.get("Authorization"):
                STATE["saw_authorization"] += 1

    def _take_fault(self):
        with STATE["lock"]:
            f = STATE["fault"]
            if f["count"] != 0:
                pr = f.get("path_re")
                if pr is None or re.search(pr, self.path):
                    if f["count"] > 0:          # -1 = persist
                        f["count"] -= 1
                    return f["kind"]
        return "none"

    # ---- token plane -----------------------------------------------------
    def _token(self):
        # Logged like any other request: "which credential reached WHICH plane"
        # is the whole subject of the auth-dance negatives, and a realm the
        # mirror was supposed to refuse can only be proven untouched if its
        # listener records what it did (not) receive.
        self._log()
        if STATE["basic"] is not None:
            want = "Basic " + base64.b64encode(
                STATE["basic"].encode()).decode()
            if self.headers.get("Authorization") != want:
                return self._send(401, b'{"error":"bad credentials"}',
                                  "application/json")
        fault = self._take_fault()
        if fault == "corrupt":
            # A 200 the JSON parser cannot use — the failure mode a registry
            # behind a captive portal or a broken CDN actually presents.
            return self._send(200, b'{"tok', "application/json")
        if self._fault_body(fault, b""):
            return
        with STATE["lock"]:
            STATE["token_count"] += 1
            tok = "tok-%d" % STATE["token_count"]
            # A real registry bearer is a JWT: DockerHub's is ~2.7 KB, and a
            # client that carries a short one but clips a long one looks
            # perfectly healthy against a mock. --token-len is how a lane makes
            # the credential the size it is in production.
            if STATE["token_len"] > len(tok):
                tok += "." + "T" * (STATE["token_len"] - len(tok) - 1)
            STATE["tokens"].add(tok)
        # Quay spells the field `access_token`, DockerHub `token`, and a
        # registry may omit `expires_in` entirely (the spec's default is 60 s).
        # All three shapes are one flag away so the client can be held to them.
        doc = {STATE["token_key"]: tok}
        if STATE["token_ttl"] > 0:
            doc["expires_in"] = STATE["token_ttl"]
        self._send(200, json.dumps(doc).encode(), "application/json")

    def _authorized(self, name, actions):
        if not STATE["auth"]:
            return True
        ah = self.headers.get("Authorization", "")
        if ah.startswith("Bearer ") and ah[7:] in STATE["tokens"]:
            return True
        realm = STATE["realm"] or "http://%s:%d/token" % (
            self.server.server_address[0], self.server.server_address[1])
        scope = 'service="mock-registry",scope="repository:%s:%s"' % (
            name, actions)
        # "-" is the challenge RFC 7235 forbids: no realm at all. A client that
        # guesses one is a client that can be aimed at any host.
        ch = ("Bearer " + scope if realm == "-"
              else 'Bearer realm="%s",%s' % (realm, scope))
        self._send(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}',
                   "application/json", [("WWW-Authenticate", ch)])
        return False

    # ---- data plane ------------------------------------------------------
    def _serve_manifest(self, name, ref):
        repo = STATE["repos"].get(name, {"tags": {}})
        # A tag cannot contain ':' (OCI tag grammar), so the colon is the
        # whole test for "this is a digest" — and it stays true for every
        # registered algorithm rather than just the one we happened to seed.
        d = ref if ":" in ref else repo["tags"].get(ref)
        if d is None or d not in STATE["manifests"]:
            return self._send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN",'
                              b'"message":"manifest unknown"}]}',
                              "application/json")
        fault = self._take_fault()
        if fault == "retag":
            others = [x for x in repo["tags"].values() if x != d]
            d = others[0] if others else d
        body, mt = STATE["manifests"][d]
        hdr_digest = d
        if fault == "wrong_digest_header":
            hdr_digest = "sha256:" + "0" * 64
        if self._fault_body(fault, body):
            return
        if fault == "corrupt":
            mid = len(body) // 2
            body = body[:mid] + bytes([body[mid] ^ 0xFF]) + body[mid + 1:]
        self._send(200, body, mt, [("Docker-Content-Digest", hdr_digest)])

    def _serve_blob(self, digest, query=""):
        if STATE["blob_redirect"] is not None and self.command == "GET":
            loc = STATE["blob_redirect"] + self.path
            if STATE["blob_redirect_sign"]:
                # The CloudFront shape DockerHub actually emits: the blob URL
                # carries its own authorization in the query, so a client that
                # follows the redirect but drops the query arrives unsigned.
                loc += "?Expires=%d&Signature=%s&Key-Pair-Id=BRIXTEST" % (
                    int(time.time()) + 300, digest[7:39])
            return self._send(302, b"", extra=[("Location", loc)])
        if STATE["require_signature"] and "Signature=" not in query:
            return self._send(403, b'{"errors":[{"code":"DENIED",'
                              b'"message":"unsigned request"}]}',
                              "application/json")
        body = STATE["blobs"].get(digest)
        if body is None:
            return self._send(404, b'{"errors":[{"code":"BLOB_UNKNOWN"}]}',
                              "application/json")
        fault = self._take_fault()
        if self._fault_body(fault, body):
            return
        if fault == "corrupt":
            mid = len(body) // 2
            body = body[:mid] + bytes([body[mid] ^ 0xFF]) + body[mid + 1:]
        self._send(200, body, extra=[("Docker-Content-Digest", digest)])

    def _fault_body(self, fault, body):
        # Transport-shaped faults that replace the normal send. True = done.
        if fault == "http500":
            self._send(500, b"origin error")
            return True
        if fault == "toomanyrequests":
            self._send(429, b'{"errors":[{"code":"TOOMANYREQUESTS",'
                       b'"message":"pull rate limit exceeded"}]}',
                       "application/json", [("Retry-After", "7")])
            return True
        if fault == "reset":
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                       b"\x01\x00\x00\x00\x00\x00\x00\x00")
            self.connection.close()
            return True
        if fault in ("stall", "truncate", "wrong_length", "slowdrip"):
            n = len(body) + 7 if fault == "wrong_length" else len(body)
            self.send_response(200)
            self.send_header("Content-Length", str(n))
            self.end_headers()
            if fault == "stall":
                self.wfile.write(body[:64]); self.wfile.flush()
                time.sleep(30)
            elif fault == "truncate" or fault == "wrong_length":
                self.wfile.write(body[:len(body) // 2 if fault == "truncate"
                                      else len(body)])
                self.wfile.flush()
                self.connection.close()
            else:
                for i in range(0, len(body), 64):
                    self.wfile.write(body[i:i + 64]); self.wfile.flush()
                    time.sleep(0.2)
            return True
        return False

    def _serve_tags(self, name, query):
        repo = STATE["repos"].get(name)
        if repo is None:
            return self._send(404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}',
                              "application/json")
        tags = sorted(repo["tags"])
        q = {k: unquote(v) for k, v in
             (p.split("=", 1) for p in query.split("&") if "=" in p)}
        # --page-tags forces paging even for clients that never send ?n=
        n = int(q.get("n", 0)) or STATE["page_tags"]
        last = q.get("last", "")
        if last:
            tags = [t for t in tags if t > last]
        extra = []
        if n and len(tags) > n:
            tags = tags[:n]
            extra = [("Link", '</v2/%s/tags/list?n=%d&last=%s>; rel="next"'
                      % (name, n, tags[-1]))]
        body = json.dumps({"name": name, "tags": tags}).encode()
        self._send(200, body, "application/json", extra)

    def _serve_referrers(self, name, subject, query):
        """A deterministic referrers index for `subject` (D15.1).

        The mirror must forward this route verbatim and cache nothing, so the
        answer carries the QUERY back in an annotation: a lane can then prove
        the filter reached the upstream rather than being answered locally.
        """
        if STATE["repos"].get(name) is None:
            return self._send(404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}',
                              "application/json")
        q = {k: unquote(v) for k, v in
             (p.split("=", 1) for p in query.split("&") if "=" in p)}
        descs = [{"mediaType": MT_MANIFEST, "digest": subject, "size": 7,
                  "artifactType": t,
                  "annotations": {"mock.query": query}}
                 for t in ("application/vnd.example.sbom",
                           "application/vnd.example.signature")]
        extra = []
        if "artifactType" in q:
            descs = [d for d in descs if d["artifactType"] == q["artifactType"]]
            extra = [("OCI-Filters-Applied", "artifactType")]
        body = json.dumps({"schemaVersion": 2, "mediaType": MT_INDEX,
                           "manifests": descs}).encode()
        self._send(200, body, MT_INDEX, extra)

    # ---- push plane ------------------------------------------------------
    def _upload_start(self, name, query):
        q = {k: unquote(v) for k, v in
             (p.split("=", 1) for p in query.split("&") if "=" in p)}
        with STATE["lock"]:
            STATE["transcript"].append({"op": "start", "name": name,
                                        "query": query})
        if "mount" in q and q["mount"] in STATE["blobs"]:
            return self._send(201, b"", extra=[
                ("Location", "/v2/%s/blobs/%s" % (name, q["mount"]))])
        body = self._read_body()
        if "digest" in q:                       # monolithic shortcut
            return self._upload_seal(name, q["digest"], body)
        sid = uuid.uuid4().hex
        with STATE["lock"]:
            STATE["uploads"][sid] = {"name": name, "data": bytearray(body)}
        self._send(202, b"", extra=[
            ("Location", "/v2/%s/blobs/uploads/%s" % (name, sid))])

    def _upload_seal(self, name, digest, body):
        if sha(body) != digest:
            return self._send(400, b'{"errors":[{"code":"DIGEST_INVALID"}]}',
                              "application/json")
        put_blob(bytes(body))
        with STATE["lock"]:
            STATE["transcript"].append({"op": "seal", "name": name,
                                        "digest": digest, "size": len(body)})
        self._send(201, b"", extra=[
            ("Location", "/v2/%s/blobs/%s" % (name, digest)),
            ("Docker-Content-Digest", digest)])

    def _upload_put(self, name, sid, query):
        q = {k: unquote(v) for k, v in
             (p.split("=", 1) for p in query.split("&") if "=" in p)}
        body = self._read_body()
        with STATE["lock"]:
            up = STATE["uploads"].pop(sid, None)
        if up is None or "digest" not in q:
            return self._send(404, b'{"errors":[{"code":"BLOB_UPLOAD_'
                              b'UNKNOWN"}]}', "application/json")
        up["data"].extend(body)
        self._upload_seal(name, q["digest"], up["data"])

    def _manifest_put(self, name, ref):
        body = self._read_body()
        mt = self.headers.get("Content-Type", MT_MANIFEST)
        d = put_manifest(name, None if ref.startswith("sha256:") else ref,
                         body, mt)
        with STATE["lock"]:
            STATE["transcript"].append({"op": "manifest", "name": name,
                                        "ref": ref, "digest": d})
        self._send(201, b"", extra=[("Docker-Content-Digest", d)])

    # ---- routing ---------------------------------------------------------
    def _ctl(self):
        with STATE["lock"]:
            if self.path == "/ctl/log":
                return self._send(200, json.dumps(STATE["log"]).encode(),
                                  "application/json")
            if self.path == "/ctl/token_count":
                body = json.dumps({"count": STATE["token_count"]})
                return self._send(200, body.encode(), "application/json")
            if self.path == "/ctl/saw_authorization":
                body = json.dumps({"count": STATE["saw_authorization"]})
                return self._send(200, body.encode(), "application/json")
            if self.path == "/ctl/uploads":
                return self._send(200,
                                  json.dumps(STATE["transcript"]).encode(),
                                  "application/json")
        self._send(404, b"")

    def do_GET(self):
        if self.path.startswith("/ctl/"):
            return self._ctl()
        if self.path.split("?")[0] == "/token":
            return self._token()
        self._log()
        path, _, query = self.path.partition("?")
        m = re.fullmatch(r"/v2/(.+)/manifests/([^/]+)", path)
        if m:
            if self._authorized(m.group(1), "pull"):
                self._serve_manifest(m.group(1), m.group(2))
            return
        m = re.fullmatch(
            r"/v2/(.+)/blobs/(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})",
            path)
        if m:
            if self._authorized(m.group(1), "pull"):
                self._serve_blob(m.group(2), query)
            return
        m = re.fullmatch(r"/v2/(.+)/tags/list", path)
        if m:
            if self._authorized(m.group(1), "pull"):
                self._serve_tags(m.group(1), query)
            return
        m = re.fullmatch(r"/v2/(.+)/referrers/(sha256:[0-9a-f]{64})", path)
        if m:
            if self._authorized(m.group(1), "pull"):
                self._serve_referrers(m.group(1), m.group(2), query)
            return
        if path == "/v2/" or path == "/v2":
            if self._authorized("", "pull"):
                self._send(200, b"{}", "application/json")
            return
        self._send(404, b"not found")

    do_HEAD = do_GET

    def do_POST(self):
        if self.path == "/ctl/fault":
            req = json.loads(self.rfile.read(
                int(self.headers.get("Content-Length", 0))))
            with STATE["lock"]:
                STATE["fault"] = {
                    "kind": req["kind"],
                    "count": -1 if req.get("persist") else 1,
                    "path_re": req.get("path_re")}
            return self._send(200, b"ok")
        if self.path == "/ctl/reset":
            with STATE["lock"]:
                STATE["log"].clear()
                STATE["transcript"].clear()
                STATE["uploads"].clear()
                STATE["saw_authorization"] = 0
                STATE["fault"] = {"kind": "none", "count": 0,
                                  "path_re": None}
            return self._send(200, b"ok")
        if self.path == "/ctl/retag":
            req = json.loads(self.rfile.read(
                int(self.headers.get("Content-Length", 0))))
            with STATE["lock"]:
                STATE["repos"][req["name"]]["tags"][req["tag"]] = \
                    req["digest"]
            return self._send(200, b"ok")
        self._log()
        path, _, query = self.path.partition("?")
        m = re.fullmatch(r"/v2/(.+)/blobs/uploads/", path)
        if m and STATE["push"]:
            if self._authorized(m.group(1), "push,pull"):
                self._upload_start(m.group(1), query)
            return
        self._send(404, b"not found")

    def do_PUT(self):
        self._log()
        path, _, query = self.path.partition("?")
        m = re.fullmatch(r"/v2/(.+)/blobs/uploads/([0-9a-f]{32})", path)
        if m and STATE["push"]:
            if self._authorized(m.group(1), "push,pull"):
                self._upload_put(m.group(1), m.group(2), query)
            return
        m = re.fullmatch(r"/v2/(.+)/manifests/([^/]+)", path)
        if m and STATE["push"]:
            if self._authorized(m.group(1), "push,pull"):
                self._manifest_put(m.group(1), m.group(2))
            return
        self._send(404, b"not found")

    def do_PATCH(self):
        # chunked upload leg (podman/skopeo push): append to the open session,
        # ack with Location + Range; the closing PUT?digest= seals as usual.
        self._log()
        path, _, _query = self.path.partition("?")
        m = re.fullmatch(r"/v2/(.+)/blobs/uploads/([0-9a-f]{32})", path)
        if not (m and STATE["push"]):
            return self._send(404, b"not found")
        if not self._authorized(m.group(1), "push,pull"):
            return
        body = self._read_body()
        with STATE["lock"]:
            up = STATE["uploads"].get(m.group(2))
            if up is not None:
                up["data"].extend(body)
                size = len(up["data"])
        if up is None:
            return self._send(404, b'{"errors":[{"code":"BLOB_UPLOAD_'
                              b'UNKNOWN"}]}', "application/json")
        self._send(202, b"", extra=[
            ("Location", "/v2/%s/blobs/uploads/%s" % (m.group(1), m.group(2))),
            ("Range", "0-%d" % (size - 1))])

    def do_DELETE(self):
        self._log()
        m = re.fullmatch(
            r"/v2/(.+)/manifests/"
            r"(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})", self.path)
        if m and STATE["push"]:
            if not self._authorized(m.group(1), "push,pull"):
                return
            with STATE["lock"]:
                gone = STATE["manifests"].pop(m.group(2), None)
                repo = STATE["repos"].get(m.group(1), {"tags": {}})
                for t in [t for t, d in repo["tags"].items()
                          if d == m.group(2)]:
                    del repo["tags"][t]
            code = 202 if gone else 404
            return self._send(code, b"")
        self._send(404, b"not found")


class V6Server(ThreadingHTTPServer):
    """The same server on AF_INET6, for the IPv6-literal reference lane.

    A bare `--bind ::1` would otherwise be handed to socket.bind() on an
    AF_INET socket and fail; the family is a property of the address, so it is
    decided here rather than by a flag the caller could get wrong.
    """
    address_family = socket.AF_INET6


def server_for(bind, port):
    cls = V6Server if ":" in bind else ThreadingHTTPServer
    return cls((bind, port), Handler)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--bind", default="127.0.0.1")  # net-literal-allow: standalone-spawned helper server (no tests/ on sys.path); loopback bind
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--auth", action="store_true",
                    help="401 + Bearer challenge on the data plane")
    ap.add_argument("--token-port", type=int, default=None,
                    help="serve /token on a second listener too")
    ap.add_argument("--token-bind", default=None,
                    help="address for the --token-port listener (default: "
                         "--bind); a token service on an address of its own "
                         "is what an off-domain realm looks like")
    ap.add_argument("--realm", default=None,
                    help="advertise this realm URL instead of self (the "
                         "third-party-realm negative); \"-\" omits the realm "
                         "parameter entirely")
    ap.add_argument("--basic", default=None, metavar="USER:PASS",
                    help="/token requires exactly these Basic creds")
    ap.add_argument("--token-ttl", type=int, default=300,
                    help="expires_in on issued tokens; 0 omits the field")
    ap.add_argument("--token-key", default="token",
                    choices=("token", "access_token"),
                    help="which JSON field carries the token (Quay spells it "
                         "access_token)")
    ap.add_argument("--push", action="store_true",
                    help="accept the upload state machine + manifest PUT")
    ap.add_argument("--blob-redirect", default=None, metavar="URL",
                    help="302 every blob GET to URL + path (CDN twin)")
    ap.add_argument("--blob-redirect-sign", action="store_true",
                    help="sign that redirect in the query, CloudFront-style")
    ap.add_argument("--require-signature", action="store_true",
                    help="CDN twin: 403 a blob request with no Signature=")
    ap.add_argument("--token-len", type=int, default=0, metavar="N",
                    help="pad issued bearers to N chars (JWT-sized tokens)")
    ap.add_argument("--cdn", action="store_true",
                    help="CDN twin: serve blobs only, count Authorization "
                         "headers (/ctl/saw_authorization)")
    ap.add_argument("--page-tags", type=int, default=0, metavar="N",
                    help="page tags/list N at a time even without ?n=")
    args = ap.parse_args()
    STATE.update(auth=args.auth and not args.cdn, push=args.push,
                 realm=args.realm, basic=args.basic,
                 token_ttl=args.token_ttl, token_key=args.token_key,
                 blob_redirect=args.blob_redirect,
                 blob_redirect_sign=args.blob_redirect_sign,
                 require_signature=args.require_signature,
                 token_len=args.token_len, page_tags=args.page_tags)
    build_images(args.seed)
    if args.token_port is not None:
        threading.Thread(target=server_for(args.token_bind or args.bind,
                                           args.token_port).serve_forever,
                         daemon=True).start()
    server_for(args.bind, args.port).serve_forever()


if __name__ == "__main__":
    main()
