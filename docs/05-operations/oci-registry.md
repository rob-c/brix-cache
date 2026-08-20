# Running your own OCI registry

**Status: source-verified 2026-08-18.** The executable forms of this page are
`tests/test_oci_registry_push.py` (block 14150), `tests/test_oci_brixoci_copy.py`
(block 14140) and the registry half of
`deploy/oci-mirror/full-stack.conf.example`.

Companion pages: [oci.md](../04-protocols/oci.md) — the wire contract ·
[oci-mirror.md](oci-mirror.md) — caching somebody else's registry ·
[container-ingest.md](container-ingest.md) — serving the same images as a
filesystem.

---

## 1. What it is

`brix_oci_registry on` turns a location into a full OCI Distribution
endpoint backed by **local storage**: pushes land here and stay here. It is
the source of truth, not a cache — a miss is a `404`, never a fill. The
mirror and the registry share a URL grammar and an error envelope and
nothing else, deliberately: a registry that could fill a miss from an
upstream would launder unpushed content into a repository people trust.

```nginx
location /v2/ {
    brix_oci_registry      on;
    brix_oci_registry_root /srv/brix/registry;
    brix_allow_write       on;
    brix_oci_token_issuers /etc/brix/scitokens.cfg;

    brix_oci_max_blob_size 8192m;   # nginx sizes take k/m — not g
    brix_oci_upload_grace  1h;

    brix_oci_gc_interval   6h;      # unset = off; see §5 before enabling
    brix_oci_gc_grace      1h;
}

client_max_body_size 16m;           # manifests; layers arrive in chunks
```

### Directives

| Directive | Context | Notes |
|---|---|---|
| `brix_oci_registry on` | location | the surface, and the handler install |
| `brix_oci_registry_root <dir>` | location | store root; canonicalised, must resolve inside the export |
| `brix_allow_write on` | location | **the** write gate — see §3 |
| `brix_oci_token_issuers <file>` | http/server/location | SciTokens/WLCG issuer table |
| `brix_oci_registry_allow_anonymous on` | location | the typed decision to run an open registry |
| `brix_oci_max_blob_size <size>` | http/server/location | per-blob cap; `0` = unlimited |
| `brix_oci_upload_grace <time>` | http/server/location | how long an idle upload session survives |
| `brix_oci_gc_interval <time>` | http/server/location | run the reclamation pass on a timer; unset = off, minimum `1s` |
| `brix_oci_gc_grace <time>` | http/server/location | how old an unreferenced blob must be before that pass may take it (default `1h`) |

`client_max_body_size` bounds a *single request body*, so it bounds manifest
PUTs and each PATCH chunk — not the layer, which arrives across many. The
layer cap is `brix_oci_max_blob_size`, and it is parsed by nginx's size
parser: `8192m`, not `8g`.

---

## 2. On-disk layout

```
<root>/blobs/sha256/ab/<hex>              global CAS — one copy per digest
<root>/repos/<name>/manifests/sha256/<hex>       the manifest bytes
<root>/repos/<name>/manifests/sha256/<hex>.meta  its media type
<root>/repos/<name>/tags/<tag>            one line: sha256:<hex>
<root>/repos/<name>/layers/<hex>          this repo's claim on a CAS blob
<root>/repos/<name>/referrers/sha256/<subject>/<referrer>
                                          the referrer's descriptor JSON
<root>/repos/<name>/manifests/sha256/<hex>.subject
                                          the back-pointer a DELETE follows
<root>/_uploads/<session>/                staged, in-flight pushes
```

Two things follow from this shape, both of them security properties:

- **The CAS is global; the reference marks are not.** A blob is stored once
  no matter how many repositories reference it, but a repository only serves
  a digest it has a `layers/<hex>` mark for. Without that, one tenant could
  read another's private layer by guessing nothing more than its digest —
  which a leaked manifest hands over for free.
- **Tags are a one-line indirection.** That is the entire reason tags are
  mutable and digests are not; retagging rewrites one small file and moves
  no bytes.

Directories are `0700` and files `0600`. Objects are staged and renamed into
place, so a reader following the same tree never observes a partial object.

---

## 3. Authorization

The order is INVARIANT #3 and has no exceptions:

1. **`brix_allow_write`** is consulted first, before any token is parsed. A
   location that has not been told to accept writes answers `403` +
   `DENIED` — *"this registry location is read-only"* — and no credential of
   any strength promotes it. This is what makes a read-only mirror of your
   own registry a one-word change rather than a policy review.
2. **Bearer**, validated against every enabled issuer in
   `brix_oci_token_issuers`. A valid token still needs a write scope
   covering `/v2/<name>`; a valid token *without* one gets **403**, not 401,
   because re-authenticating would hand back the same token and the client
   would loop.
3. **TLS client certificate**, if the location validated one and no
   `Authorization` header was sent. The handshake did the proving; the
   subject DN becomes the principal.
4. **`brix_oci_registry_allow_anonymous on`**, if set — recorded as the
   principal `anonymous` so the access log distinguishes "nobody
   authenticated" from "somebody did, and it was anonymous".

Otherwise: **401** with

```
WWW-Authenticate: Bearer realm="https://<host>/v2/token",service="<host>"
```

The challenge shape is part of the contract, not decoration: `podman login`
only works against a registry that answers an unauthenticated request with a
challenge it can follow. The realm names *this* location's token endpoint —
the registry surface never delegates its authentication to a mirror's
upstream.

A minting endpoint is not shipped: issue tokens with your site's existing
SciTokens/WLCG issuer, the same one the other protocols in this tree already
trust. `utils/make_token.py` mints one for a lab.

---

## 4. The push data plane

`podman push` is four exchanges, and the contract that matters is
**resumability**:

| Step | Request | Answer |
|---|---|---|
| open | `POST /v2/<name>/blobs/uploads/` | `202` + `Location` + `Range` |
| append | `PATCH <location>` (chunked, usually with no `Content-Range`) | `202` + updated `Range` |
| seal | `PUT <location>?digest=sha256:…` | `201` + `Location` + `Docker-Content-Digest` |
| manifest | `PUT /v2/<name>/manifests/<ref>` | `201` + `Docker-Content-Digest` |

The session's state **is the staged file itself** — `OPEN` is a zero-length
part file, `ACTIVE` is a non-empty one, and sealed/aborted/reaped are all
"the directory is gone", which is why each answers `404` and none needs a
flag. A crashed worker leaves a session exactly as resumable as it was a
moment earlier; `GET <location>` reports how much arrived.

The seal is the only place bytes become an object: the staged file is
hashed and compared against the digest the client claimed. A mismatch is
`BLOB_UPLOAD_INVALID`, and nothing is published. A registry that stored what
it was *told* it received would be a corruption pump — every later pull
would hand a client bytes that hash to something else, and the client would
be the one that looked broken.

A manifest PUT walks its own descriptors (`config`, `layers`, and a nested
`manifests` array for an index) and refuses with `MANIFEST_BLOB_UNKNOWN` if
any referenced blob has not been pushed. That is what makes "the push
succeeded" mean the image is actually pullable.

Idle sessions older than `brix_oci_upload_grace` are reaped.

---

## 5. Deleting things, and reclaiming the space

`DELETE` on a manifest removes the manifest, its `.meta` and the referrer
edges it owns; `DELETE` on a blob removes this repository's claim on it. The
client-side verb is:

```console
$ brixoci rm registry.example.org/lab/app:v1
```

**No request handler ever deletes a blob.** It cannot: it sees one
repository, and the CAS is global — the layer this delete orphans may be the
layer three other repositories are serving. Answering that question means
reading the whole store, so it is a separate pass:

```console
$ brixoci gc /var/lib/brix/registry --dry-run     # rehearse
$ brixoci gc /var/lib/brix/registry               # reclaim
```

The pass marks every digest that every manifest in every repository names,
then sweeps what nothing named: unreferenced CAS blobs, `layers/<hex>` marks
a manifest delete orphaned, and referrer descriptors whose referrer manifest
is gone. `--json` prints the same counters for a cron wrapper to log.

Where there is nobody to run a cron job — an appliance, a container image
with one config file and no shell — the proxy runs the same pass itself:

```nginx
brix_oci_gc_interval 6h;    # off unless you say this
brix_oci_gc_grace    1h;    # the same window --grace names
```

It is the same code, deliberately: a tool and a server that disagreed about
what garbage is would be a disagreement neither side could see. Worker 0
alone runs it, at most one store at a time, never while a previous pass is
still walking, and on the `default` thread pool if one is configured (declare
`thread_pool default threads=…;` — without it the walk runs inline on that
worker, which on a large store is a stall that shows up as latency). A pass
that reclaimed nothing logs nothing; a pass that reclaimed something logs one
`NOTICE` with the counters. Setting it on a `brix_oci_mirror` location is
refused at parse time: a mirror's objects are cache entries and the cache
tier owns their eviction.

Three properties are worth knowing before you schedule it — by cron or by
directive, they apply equally:

- **It removes no manifest and no tag, ever.** Untagged is not garbage here
  — every signature and SBOM is an untagged manifest, so sweeping by
  reachability-from-tags would delete exactly the evidence a verifier came
  for. Manifests go when you delete them.
- **`--grace` (default 3600s) is what keeps a concurrent push safe.** Between
  a blob sealing and the manifest that names it arriving, that blob is
  indistinguishable from garbage; the window is the difference between a
  cron entry and a sabotaged push. A blob older than the window whose
  manifest is still in flight is the one case the window cannot cover — for
  a store under continuous push, run the pass with `brix_allow_write off` on
  the location and reload, which turns the race into a short read-only
  interval.
- **It only unlinks names it re-parsed as a digest** under the registered
  grammar (`sha256` and `sha512`; the width says which), and it stats with
  `lstat`, so a symlink planted in the store cannot walk it out of the
  root. A directory that does not hold both `blobs/` and `repos/` is
  refused outright — `brixoci gc /` is a plausible typo, not a plausible
  instruction.

---

## 6. The CLI

`brixoci` is a clean-room client for this surface and any other conformant
registry:

```console
$ brixoci pull  <ref> [--to DIR] [--platform os/arch]
$ brixoci push  <ref> [--from DIR]
$ brixoci copy  <src-ref|oci:DIR> <dst-ref|oci:DIR>
$ brixoci ls    [oci:DIR]
$ brixoci tags  <host/name>
$ brixoci rm    <ref>
$ brixoci inspect <ref> [--raw]
$ brixoci gc    <store-dir> [--grace SECS] [--dry-run] [--json]
$ brixoci convert --estargz <src-ref|oci:DIR> <dst-ref|oci:DIR> [--tag NAME]
```

`convert` re-encodes every layer of one image into **eStargz**, the lazy-pull
format a containerd stargz snapshotter fetches file-by-file over `Range`
requests. The result is a *new* image: reframing a layer changes its
compressed digest and its diff_id, so the config's `rootfs.diff_ids` and the
manifest's layer descriptors are rewritten (each gaining
`containerd.io/snapshot/stargz/toc.digest`), and everything else in the
config — labels, env, history — is preserved byte-for-byte. Convert one
image at a time: an index is refused, so select the platform upstream.
`--tag NAME` names the entry in a **destination layout**, which is the one
thing a layout has no reference of its own to supply; a registry destination
is named by its own reference and rejects `--tag`. A runtime with no
snapshotter still runs a converted image — it unpacks the layer as the
ordinary gzip tar it also is, and finds the format's two reserved entries
(`stargz.index.json`, `.no.prefetch.landmark`) in the rootfs.

`oci:DIR` is an OCI image-layout directory, so `copy` moves images between
registries, or between a registry and a directory, without a container
engine anywhere. Credentials come from `--token-file`, `--cert`/`--key`, or
a netrc-style `~/.config/brix/oci-auth` that **must** be mode `0600`.
`--insecure` allows cleartext HTTP and disables TLS verification — lab
fixtures only.

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `[emerg] "brix_oci_max_blob_size" directive invalid value` | a `g` suffix | nginx sizes take `k`/`m`: write `8192m` |
| push gets `403 DENIED` immediately, no challenge | `brix_allow_write` is off | that is the gate working; turn it on deliberately |
| push gets `403` *after* logging in | the token is valid but carries no write scope for `/v2/<name>` | fix the scope, not the login |
| `podman login` reports "not a v2 registry" | the location prefix is not reaching the handler | check that the `/v2/` segment is inside the location prefix |
| `MANIFEST_BLOB_UNKNOWN` on the last step | a layer was never sealed | re-push; the failed seal is the real error |
| a repo serves `404` for a blob that is in `blobs/` | no `layers/<hex>` mark for this repository | expected — the CAS is global, the claims are not |
| `convert` exits 2, "source manifest is an image index" | the source ref resolves to a multi-arch index | pull the one platform first (`--platform os/arch`), then convert the image |
| a converted image runs but shows `stargz.index.json` in `/` | no stargz snapshotter on that node | expected: the layer is a valid gzip tar too, and that is the format's legacy behaviour |
| `brixoci gc` reclaims nothing after a delete | the blobs are younger than `--grace` | check `blobs_within_grace` in `--json`; lower the window only when no push is in flight |
| `brixoci gc` exits 2, "not an OCI registry store" | the path is not `brix_oci_registry_root` (one level up, or the export root) | pass the directory that holds `blobs/` and `repos/` |
| `brixoci gc` exits 6, "Permission denied" | a repository directory it cannot read | fix the mode and rerun — the pass fails closed rather than sweeping against a live set it could not finish building |
| `[emerg] brix_oci_gc_interval: … busy loop over the store` | an interval under `1s` | a pass costs a full walk; give it minutes or hours, not milliseconds |
| `[emerg] brix_oci_gc_interval: nothing for a registry sweep to collect on a pull-through mirror` | the directive is on a `brix_oci_mirror` location | move it to the registry location; a mirror's objects are the cache tier's to evict |
| `brix_oci_gc_interval` is set and the error log never mentions gc | either nothing was reclaimable, or the timer never armed | silence on a clean store is by design; if you expect reclamation, confirm the location really has `brix_oci_registry on` (the directive inherits, and an outer block's copy is inert) |
