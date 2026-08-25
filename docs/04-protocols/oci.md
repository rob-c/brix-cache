# The OCI Distribution surface (`/v2/`)

**Status: source-verified 2026-08-18** against `src/protocols/oci/` and
`shared/oci/`. This page is the *wire* contract — what the two `/v2/`
surfaces answer and why. The operator pages are
[oci-mirror.md](../05-operations/oci-mirror.md) (cache somebody else's
registry), [oci-registry.md](../05-operations/oci-registry.md) (be your own),
and [container-ingest.md](../05-operations/container-ingest.md) (turn an
image into a filesystem).

Normative sources: OCI Distribution Specification v1.1 and the Docker
Registry HTTP API V2. Clean-room throughout: nothing here links against
docker, containerd, skopeo or any registry implementation — the grammars,
the error envelope and the token dance are implemented from the
specification text.

---

## 1. Two surfaces, one grammar

| | `brix_oci_mirror <base-url>` | `brix_oci_registry on` |
|---|---|---|
| Role | pull-through cache of an upstream registry | the site's own registry — the source of truth |
| Miss | fills from upstream, verifies, caches | **404** — a registry never invents content |
| Writes | refused (405 + a guard line) | full push API behind `brix_allow_write` |
| Storage | `brix_cache_store` | `brix_oci_registry_root` |

They share `shared/oci/{name,digest}.c` and the classifier
(`src/protocols/oci/oci_classify.c`), and nothing else. The split is
deliberate and structural: a registry that could "fill" a miss from an
upstream would launder unpushed content into a repository people trust, and
one `if` is all that would take if the two routers were one router.

Both are **off by default**. A location becomes an OCI endpoint only by
carrying one of the two directives, which is also what installs the content
handler — the same shape as `brix_cvmfs`.

---

## 2. Endpoint × method matrix

Routes are relative to the location prefix, so a mount at `/local/v2/`
behaves exactly like one at `/v2/` (`oci_api_prefix_end()` matches the
`/v2/` segment wherever it sits).

| Route | Mirror | Registry |
|---|---|---|
| `/v2/` | GET, HEAD → **local** `200 {}` | GET, HEAD → `200 {}` authenticated, else `401` + challenge |
| `/v2/<name>/manifests/<ref>` | GET, HEAD | GET, HEAD, PUT, DELETE |
| `/v2/<name>/blobs/<digest>` | GET, HEAD | GET, HEAD, DELETE |
| `/v2/<name>/blobs/uploads/` | 405 | POST |
| `/v2/<name>/blobs/uploads/<session>` | 405 | GET, PATCH, PUT, DELETE |
| `/v2/<name>/tags/list` | forwarded, uncached | GET |
| `/v2/<name>/referrers/<digest>` | forwarded, uncached | GET, HEAD |

Anything else under the prefix is a classifier reject (§4). Any method not
in the row is **405** with `Allow:` and the `UNSUPPORTED` envelope.

`GET /v2/` is answered by the mirror **locally, with zero upstream
traffic** (`oci_gate.c:oci_answer_api_root`). Clients issue it as a
liveness probe before their first pull; forwarding it would double every
pull's round-trips and — worse — make the mirror's availability a function
of DockerHub's weather.

---

## 3. Response headers

| Header | Where | Meaning |
|---|---|---|
| `Docker-Distribution-API-Version: registry/2.0` | every response, both surfaces (`oci_errors.c`) | what makes a client believe this host speaks v2 |
| `Docker-Content-Digest` | manifest and blob responses, upload seals | the digest of the bytes in *this* response |
| `Content-Type` | manifests | round-tripped byte-exact from the upstream/push |
| `Allow` | every 405 | the methods the route does define |
| `WWW-Authenticate` | registry 401 | `Bearer realm="<scheme>://<host>/v2/token",service="<host>"` |
| `OCI-Subject` | registry manifest `201` | the subject digest a pushed referrer named — its presence is how a signing client learns this registry indexes referrers |
| `OCI-Filters-Applied: artifactType` | registry referrers `200` | this answer was filtered; without it a client cannot tell an empty selection from an ignored filter |

The mirror **never branches on media types**. It stores and echoes
`Content-Type` verbatim; a new manifest type invented next year passes
through a mirror that has never heard of it. Only the tools
(`brixoci`, `brixcvmfs ingest`) interpret them, through the constants in
`shared/oci/mediatypes.h`.

`Docker-Content-Digest` on a cached response is the **strong digest of the
bytes served** — for a digest-addressed object that is the request's own
digest, re-derived rather than echoed from the upstream's word for it.

---

## 4. Grammars — enforced once, at the edge

`shared/oci/name.c` and `shared/oci/digest.c`:

```
name      ::= component ("/" component)*          ; <= 255 bytes total
component ::= [a-z0-9]+ ( ( "." | "_" | "__" | "-"+ ) [a-z0-9]+ )*
tag       ::= [a-zA-Z0-9_] [a-zA-Z0-9._-]{0,127}
digest    ::= algorithm ":" hex
algorithm ::= [a-z0-9]+ ( [+._-] [a-z0-9]+ )*     ; registered: sha256, sha512
hex       ::= [a-f0-9]{64} | [a-f0-9]{128}        ; the width names the algorithm
reference ::= tag | digest
```

The classifier is a **pure kernel** — no nginx types, no allocation, spans
into the caller's buffer — which is what lets the protocol-fuzz lane link it
standalone beside the other parser kernels. It runs on the **decoded** URI
and refuses any decoded `/` that changes the component count, so
encoded-slash smuggling cannot reach a path builder.

The property that matters downstream: **a name or digest that classifies
cannot traverse.** Every later stage (cache key, store path, upstream URL)
concatenates rather than parses, because validation happened exactly once
and cannot be skipped by reaching a stage another way.

Both algorithms the distribution spec registers are accepted, and the
algorithm is read out of the digest at every stage rather than assumed: the
cache key, the store path, the verify-at-edge hash and the upload seal all
take it from the request. Every *other* algorithm — including real ones the
spec does not register, such as sha384 — is `DIGEST_INVALID`. No two
registered algorithms share a hex width, so a bare hex is unambiguous, which
is why the flat parts of the store — upload marks, ingest image roots, and
the per-layer roots `brixcvmfs ingest image --layout layered` publishes —
stay flat.

### 4.1 The realm grammar is the security-critical one

`shared/oci/url.c` parses one more thing, and it is the only grammar here
whose input is chosen by the *upstream*: the `realm=` of a `WWW-Authenticate`
challenge. A realm is an instruction to hand a credential to a named host, so
the parser refuses a userinfo authority, a path-shaped host and any scheme but
http(s), and the verdict is then checked against the upstream it claims to
speak for — the same host, its registrable parent, or a sibling under that
parent. The parent must itself be multi-label, so a single-label upstream can
never widen the trust to a whole TLD. A refusal is
`signal=oci_realm_refused`, and it applies to every hop of the token leg's
redirect chain, not only the first.

`brix_oci_upstream_auth_realm <host>` widens that boundary by one exact host,
for registries that delegate to an unrelated identity domain. It has no
pattern form and refuses a port, a scheme, a wildcard or a duplicate at
`nginx -t`; a dance that only completes because of it logs one INFO line
naming the host. The same allowlist governs redirect hops, so it cannot be
used to get past the first check and then wander.

---

## 5. The cache key is the route

`oci_key.c` builds one string that is simultaneously the cache key, the
export-relative store path, and the upstream URL suffix:

```
/v2/ [<upstream-namespace> /] <name> / (manifests|blobs) / <reference>
```

Two consumers **re-classify** it: `brix_cache_verify_oci_digest()` reads the
reference back off the key to learn which digest a fill must hash to, and
`sd_cache_is_manifest_key()` reads it to decide whether the object is a
mutable tag manifest (TTL) or immutable content (cache forever). A key in
any other shape — a hash, a flattened name, an `Accept`-qualified variant —
silently turns the verify into a no-op *and* makes tag manifests permanent.
Hence: the key is the route, and the single normalisation
(`brix_oci_upstream_namespace`, applied only to single-component DockerHub
shorthand names) happens here, before any consumer reads it.

---

## 6. Error envelope

Every non-2xx from either surface carries the spec body
(`oci_errors.c` is the only emitter):

```json
{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown",
            "detail":{"name":"library/foo","ref":"1.2"}}]}
```

| Code | HTTP | Raised by |
|---|---|---|
| `NAME_INVALID` | 400 | grammar reject |
| `NAME_UNKNOWN` | 404 | legal name, nothing routed |
| `MANIFEST_UNKNOWN` | 404 | both surfaces |
| `MANIFEST_INVALID` | 400 | registry: manifest JSON or its descriptors |
| `MANIFEST_BLOB_UNKNOWN` | 400 | registry: manifest references an unpushed blob |
| `BLOB_UNKNOWN` | 404 | both |
| `BLOB_UPLOAD_UNKNOWN` | 404 | registry: no such session |
| `BLOB_UPLOAD_INVALID` | 400 | registry: bad range/offset/digest on seal |
| `DIGEST_INVALID` | 400 | both |
| `SIZE_INVALID` | 413 | registry: over `brix_oci_max_blob_size` |
| `UNAUTHORIZED` | 401 | registry gate |
| `DENIED` | 403 | registry gate |
| `UNSUPPORTED` | 405 / 400 | method gate |
| `TOOMANYREQUESTS` | 429 | mirror: upstream throttled us (with **our** `Retry-After`, not the upstream's) |
| `UNAVAILABLE` | the upstream's own status, or 502 when the tier reports none | mirror: upstream could not answer |

Two mirror-specific remappings are worth knowing: an upstream **401 that
survived the token dance becomes a 403** (relaying it would tell the client
*our* mirror wants credentials it cannot mint), and an upstream 404 becomes
`MANIFEST_UNKNOWN` or `BLOB_UNKNOWN` by route — the difference between
`podman pull` reporting a missing tag and reporting a corrupt image.

---

## 7. Metrics

`src/observability/metrics/oci.c`. Image names, tags and digests are
unbounded wire data and appear in **no** label (INVARIANT #8):

| Family | Labels | Reads |
|---|---|---|
| `brix_oci_requests_total` | `surface` × `class` × `outcome` | 2 × 7 × 5 fixed-enum series, emitted even at zero |
| `brix_oci_fill_bytes_total` | `surface` | bytes that crossed the WAN |
| `brix_oci_token_fetch_total` | `outcome` = cached\|fetched\|failed | is the upstream token dance working |
| `brix_oci_verify_fail_total` | — | fills whose bytes did not hash to their digest |
| `brix_oci_upstream_errors_total` | `status` = 401\|403\|404\|429\|5xx\|other | upstream weather |
| `brix_oci_delegate_total` | `outcome` = cached\|granted\|denied\|error | delegated-pull (D16) authorization proofs |

`class` = api\|manifest\|blob\|upload\|tags\|referrers\|bad;
`outcome` = hit\|fill\|local\|refused\|error. Cache hit ratio is
`hit / (hit + fill)` per class — blobs and manifests have genuinely
different ratios and averaging them hides the interesting one.

---

## 8. Guard signals

Two `signal=` tokens, both with shipped fail2ban assets under
`deploy/fail2ban/`:

- **`ocipush`** — a write-class method aimed at a *mirror*. The surface is
  read-only by construction and no client pushes to a mirror by accident, so
  the jail ships `enabled = true` with `maxretry = 1`.
- **`oci_tamper`** — a fill whose bytes did not hash to the digest the
  request named. The banned host is the **upstream**, never a client, so a
  ban here takes the mirror offline for everyone; the jail ships
  `enabled = false` on purpose. Nothing bad was cached either way — the
  client got a 502 and the line is the alert.

Delegate-mode denials (§D16) emit the tree-wide **`authfail`** signal — one
line per uniform 401, same shape every other authenticated surface uses, so
an existing `authfail` jail covers credential probing against the mirror
with no new filter.

---

## 9. What this surface does not do

Containerd stargz snapshotter compatibility — the *plugin*, which is Go
inside containerd's process · image *building* and vulnerability scanning.
Each is a recorded decision in
`docs/refactor/phase-104-oci-rpm-distribution.md` §D15, with the trigger that
would reopen it.

Two things that were on that list no longer are. Non-flat per-layer publish
ships as `brixcvmfs ingest image --layout layered` (§D15.6). The lazy-pull
layer encodings are handled on both sides: eStargz and `zstd:chunked` layers
are read wherever a layer is read (§D15.7), and `brixoci convert --estargz`
writes eStargz images a snapshotter can pull lazily off either surface
(§D15.8) — this surface serves them as ordinary blobs, which is all a
snapshotter's ranged fetches need.

Reclamation is **not** on that list: a registry store is swept by the
operator-run `brixoci gc` pass, or by `brix_oci_gc_interval` on a registry
location, which runs the same kernel on a worker-0 maintenance timer off the
thread pool (§D15.3, §D15.5). Both honour a `grace` window — the state every
push passes through, where a blob is sealed and its manifest has not landed
yet — and neither ever sweeps a manifest or a tag.
