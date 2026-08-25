# oci — the OCI Distribution plane: pull-through mirror + local registry

## Overview

Two surfaces over one `/v2/` grammar, each behind its own directive and each
default-off.

**`brix_oci_mirror`** is a pull-through mirror of an upstream registry
(DockerHub, Quay, GitLab). A podman/docker client is pointed at the location;
requests are classified, keyed, and filled through the ordinary read-through
cache tier, so a cold blob is fetched once no matter how many nodes ask at
once. Blobs are digest-addressed, which makes them immutable and
self-verifying — the key names the expected sha256, and
`src/fs/cache/verify.c` (`BRIX_CACHE_VERIFY_OCI_DIGEST`) hashes the staged
part against it before publishing, so a CDN that serves the wrong bytes gets
quarantined rather than cached. Tag manifests are mutable and live on a short
TTL. The one thing upstreams demand that a plain proxy cannot give them is the
Bearer token dance (`oci_upstream_auth.c`): a `WWW-Authenticate` challenge is
answered once per (realm, scope) and the token is cached in SHM, because one
extra round-trip per blob is unacceptable on a cold pull.

**`brix_oci_registry`** is a registry of our own over the local VFS store: the
resumable blob upload state machine, manifest PUT with every referenced blob
proven present, tag listing, DELETE, the referrers graph, and a maintenance-timer
GC. Writes pass `brix_allow_write` **before** any token scope is consulted
(INVARIANT #3), and every published object lands by atomic rename over a staged
part file — the bytes on disk are the only answer that survives a crash.

Both surfaces share the grammar (`oci_classify.c`), the cache key
(`oci_key.c`), the error envelope (`oci_errors.c`) and the `.ocimeta` sidecar
that remembers the media type and digest a cached manifest must be presented
with (`oci_meta.c`, `oci_present.c`).

## Files

### The shared grammar

| File | Responsibility |
|---|---|
| `oci_classify.c` / `oci_classify.h` | one validating parse of a decoded URI into a typed route; pure C over `shared/oci/{name,digest}.h`, no nginx types |
| `oci_key.c` | the canonical cache key — simultaneously the store path, the fill target and the digest a self-verifying route is checked against |
| `oci_errors.c` | every way this plane says "no": one JSON error envelope, one errno→code map, one guard line |
| `oci_meta.c` | the `.ocimeta` sidecar riding beside each cached manifest |
| `oci_present.c` | the two headers a registry client actually reads: `Content-Type` and `Docker-Content-Digest` |
| `oci.h` | loc-conf, request ctx, and the seams the translation units share |
| `oci_module.c` / `oci_module_internal.h` | nginx wiring: config lifecycle, directive table, handler install |
| `oci_merge.c` | the location merge — refusals first (unsupported storage grammar is an EMERG at config load), then the export build |
| `directives_mirror.h` / `directives_registry.h` | the two directive families, `#include`d into the commands array |

### The mirror surface (`brix_oci_mirror`)

| File | Responsibility |
|---|---|
| `oci_gate.c` | method policing, classification, and the routes answered locally |
| `oci_mirror.c` | the content handler: coalesced fills, ranged serving, digest verify at the edge |
| `oci_upstream_auth.c` | the Bearer token dance HTTP legs; the realm allowlist (`brix_oci_upstream_auth_realm`) applies to every redirect hop |
| `oci_token_cache.c` | the SHM (upstream, scope[, credential]) → bearer cache and its key discipline; `pull_scope`; the proof-to-fill token share |
| `oci_delegate.c` | delegated pull (D16): downstream Basic identity, the per-credential authorize-on-hit proof gate, and the uniform 401 |
| `oci_tags.c` | uncached passthrough of the two listing routes — a cached page would pair a fresh cursor with a stale body |

### The registry surface (`brix_oci_registry`)

| File | Responsibility |
|---|---|
| `oci_registry.c` / `oci_registry.h` | the router: gate → route → handler, plus the store-layout seams |
| `oci_authz.c` | the authorization gate, decided once per request and fail-closed |
| `oci_store.c` | the on-disk store: every path the push surface writes, and the five primitives over them (exists, verify, publish-atomically, …) |
| `oci_upload.c` / `oci_upload_internal.h` | the blob upload-session state machine (POST/PATCH/PUT/GET/DELETE) |
| `oci_upload_seal.c` | the body half: append to the staged part, then hash and compare before the seal |
| `oci_manifest_put.c` | manifest PUT (every referenced blob proven present first) and DELETE |
| `oci_referrers.c` / `oci_referrers.h` | the referrers graph: index a pushed manifest under the subject it declares |
| `oci_gc.c` | config-time registry of store roots + one worker-0 maintenance timer |

## Gating and invariants

- **Default off, twice.** Neither surface exists until its directive appears
  in a location; the phase-84/96 corpora are byte-unchanged with the gates off.
- **INVARIANT #3.** `brix_allow_write` is consulted before token scope on
  every mutating route.
- **INVARIANT #8.** `brix_oci_*` metrics label by route kind, disposition and
  code class — **never** by repository or tag name.
- **INVARIANT #12.** Storage goes through the VFS seam; no positional-byte
  syscalls live here.

## See also

- `docs/04-protocols/oci.md` — the `/v2/` surface and its directives
- `docs/05-operations/oci-mirror.md`, `docs/05-operations/oci-registry.md`
- `shared/oci/` — the name/digest/tar/stargz grammars shared with the client
- `client/apps/oci/` — the `brixoci` CLI personality
- `docs/refactor/phase-104-oci-rpm-distribution.md` — §D0–D5, §D15
