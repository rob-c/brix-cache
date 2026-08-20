# Phase-104 — OCI & RPM distribution: registry mirror, local repos, container → Stratum-0 ingest

**Goal:** grow a general **software-distribution plane** on top of the stacks
phases 84–96 built. Three capabilities, one phase:

1. **In-line registry mirror** — the proxy becomes a pull-through cache for
   DockerHub / Quay / GitLab container registries (OCI Distribution Spec pull
   surface) and for RPM/dnf repositories, so a site's pulls are served locally
   after first fetch.
2. **Local repository management** — a gated push surface plus a `brixoci`
   client tool: sites can host, copy, list and retire their own images and
   RPM repos on this server.
3. **Container / folder → Tier-0 CVMFS ingest** — the headline: a container
   image (or any plain folder of software) becomes a published, mountable
   Stratum-0 CVMFS subtree in seconds — `brixcvmfs ingest image
   registry.example/foo:1.2` or `brixcvmfs ingest dir ./build --prefix
   /sw/foo/1.2` — deployable via the cvmfs protocol (FUSE-mounted, scvmfs-
   gated where private) and re-exportable over the other protocol planes.

Terminology: WLCG says *Tier-0*; CVMFS says **Stratum-0** — same thing here
(phase-96 convention). "OCI image" covers both Docker (schema-2) and OCI
media-type families; the wire surface is the **OCI Distribution Spec** (the
`/v2/` API), which DockerHub, Quay and GitLab all speak.

**Document version:** v8 (2026-08-17) — the v2 implementation-grain body
(file inventory with APIs, directive grammar, wire primers, state machines,
layouts, error mappings, rosters, port claims, per-test enumeration), closed
by the **Appendices**: normative wire transcripts and JSON bodies (A) ·
byte-exact on-disk formats (B) · parser-kernel pseudocode (C) · a
*generated-and-verified* tar byte walk (D) · the RPM byte walk (E) ·
per-lane named test rosters (F) · harness/mock/template specs (G) · sub-task
work breakdown with review gates (H) · sizing and budget arithmetic (I) ·
**the v4 tier**: the nginx server-integration blueprint grounded in the
tree's actual handler/fill composition (J) · proposed public headers
verbatim in house style (K) · the consolidated threat model (L) · the
invariant-compliance matrix (M) · the CI-guard integration map (N) · an
operator walkthrough (O) · the risk register (P) · **the v5 tier**: a
generated-and-verified RPM byte walk with the system `rpm` as its oracle
(Q) · a live wire capture against the real Docker Hub, token dance
included (R) · function-level substrate contracts read off the tree's
headers (S) · the ingest driver call-flow in real API names (T) · **the
v6 tier — executed labs**: a real whiteout layer built with podman,
walked byte-by-byte, hand-flattened per the D7 rules and *run* with
`podman run --rootfs` (U) · the publish plane benchmarked with the
tree's own `brixcvmfs` binary — the §I budgets are now measured, two of
them corrected (V) · **the v7 tier — the client-oracle labs**: a real
`podman pull` executed against a brix-shaped static `/v2/` tree, cold and
warm, with the raw request bytes captured (W) · a stock EL9 `dnf`
depsolving and installing from repodata emitted by this phase's own
clean-room generator (X) · **the v8 tier — the composition labs**: a
real `podman push` received, traced, and byte-verified by a capturing
registry — the token dance, chunked uploads, and the percent-encoded
seal digest all observed (Y) · the headline image → publish → serve →
mount → `podman run` chain executed end-to-end with zero new C, its GET
ledger and rootless traps measured (Z). Proposed C signatures
remain **design sketches** — final names follow the coding-standard review,
but the shapes (what is passed, what is returned, what is ngx-free) are
normative for the waves, and the appendix formats are normative for the
bytes.

**Provenance:** anchors below read from the tree at working state on
**2026-08-17** (post-phase-96…103, several waves uncommitted). Every
`file:line` anchor in this document was verified against that tree on that
date. Re-verify anchors at the start of each wave and mark drift `DRIFT:`
inline (phase-80 convention). Cross-references use S-numbers from
`docs/refactor/phase-96-cvmfs-stratum0-publishing.md`, G-numbers from
`docs/refactor/phase-87-cvmfs-next-gen-storage-and-distribution.md` and
F-numbers from `docs/refactor/phase-85-cvmfs-swiss-army-features.md`.
External normative references (clean-room inputs, specs only — never other
implementations' source): OCI Distribution Spec v1.1, OCI Image Format Spec
v1.1, Docker Registry HTTP API V2 + image manifest schema 2, POSIX.1-2017
`pax` Interchange Format, GNU tar extensions, the RPM package format
(rpm.org file-format documentation), and the `createrepo_c` repodata XML
shapes as emitted (observed output, not source).

---

## 0.0 What this phase is NOT — scope fences up front

- **The cvmfs cache/serve plane does not change.** Phase-84's contracts stand
  byte-for-byte: cvmfs locations stay GET/HEAD-only (405 otherwise), write
  directives on them stay config-load EMERGs. Container ingest happens on the
  **tool surface** against a Stratum-0 repo dir, exactly like every phase-96
  publish; the proxy only ever *serves* the result.
- **The OCI surfaces are new, separate locations** (`src/protocols/oci/`),
  each behind its own directive, default **off**. With every phase-104 gate
  off, the phase-84 and phase-96 corpora — and every other protocol's conf
  matrix — must be byte-for-byte unchanged.
- **No image building, no vulnerability scanning, no `docker save` archive
  formats.** We move and publish images; we do not create or judge them.
- **Flat ingest by default** (the DUCC "flattened rootfs" variant); per-layer
  subtree sharing in the published namespace arrived later as `--layout
  layered` (§D15.6), eStargz/`zstd:chunked` layers are *read* correctly
  (§D15.7) and eStargz layers are *written* by `brixoci convert` (§D15.8).
  Being a containerd **snapshotter** — the Go plugin, not the formats —
  remains D15, deferred.
- **Both registered digest algorithms.** `sha256` and `sha512` are the two
  the OCI grammar registers, and both are carried end to end — classify,
  verify-at-edge, store layout, upload seal, CLI transport, image layout, GC
  and ingest (§D15.4). Every other algorithm is answered with the spec's
  `DIGEST_INVALID`. This came off the deferred list; DRIFT 30 and 31 record
  what the deferral had priced wrong.

## 0.1 Why this is cheaper than it looks — the machinery already in-tree

Phase-96 delivered the entire *producing* half of CVMFS (S0–S14): repo
lifecycle, signed publish transactions, catalog writers, GC, tags, Stratum-0
serving with scvmfs authn. **Container→CVMFS ingest is a front-end to that
plane**, not a new plane:

- `cvmfs_changeset_scan()` (`shared/cvmfs/publish/changeset.h`) already turns
  an overlay upper tree — real entries = adds, `.brix.wh.<name>` = whiteouts,
  `.brix.opq` = opaque dirs — into an ordered changeset, with O_NOFOLLOW
  per-component descent so a hostile tree cannot walk the scan out of the
  upper dir. **OCI layer whiteouts (`.wh.<name>`, `.wh..wh..opq`) are the
  same grammar with a different spelling.** The flattener (D7) is a
  transliteration, not an invention. The marker vocabulary is already
  centralized as `BRIX_OV_WH_PREFIX` / `BRIX_OV_OPQ_NAME`
  (`client/lib/fs/overlay.h:35-36`) — the flattener includes that header and
  never spells the strings itself.
- `cvmfs_publish_run()` (`shared/cvmfs/publish/publish.h`) applies a
  changeset bottom-up with chunking, dirtab nesting, reflog append, re-sign
  and atomic manifest swap — crash-safe, idempotent CAS puts, cost scales
  with the touched subtree. Ingest calls it as-is. Its test hook
  (`$BRIXCVMFS_PUBLISH_CRASH` → `_exit(66)` before the manifest swap) is the
  ready-made kill-injection point for ingest crash lanes too.
- `brixcvmfs` already exists as an argv[0] personality of brixMount
  (`client/apps/fs/brixmount.c:149` `brixcvmfs_personality()`, symlink minted
  by `client/Makefile:202` `OPT_LINKS += $(BINDIR)/brixcvmfs`) with a
  `repo mkfs|info|resign|transaction|abort|publish|fsck|gc|tag` subcommand
  family — `ingest` is one more branch of an existing dispatcher, and
  `brixoci`/`brixrpm` are two more `OPT_LINKS` lines plus two more
  personality functions in the same TU.

On the mirror side, the read-through cache is likewise already generic:

- One fill path stages bytes from the export's registered storage backend;
  HTTP(S) origins are the `src/fs/backend/http/sd_http*.c` driver (static
  bearer header emission at `sd_http.c:178`, per-user credential forwarding
  throughout `sd_http_mutate.c` / `sd_http_write.c` / `sd_http_dir.c:341`),
  pumped by blocking libcurl in an nginx thread-pool worker
  (`src/fs/cache/origin/README.md` — never on the event loop), with digest
  verification once at the edge (`src/fs/cache/verify.h`:
  `brix_cache_verify off|best-effort|require` + the phase-68 `cvmfs-cas`
  self-verifying mode; kernel = `brix_checksum_hex_name_fd`,
  `src/core/compat/checksum.h:163`, whose algorithm roster already includes
  `BRIX_CHECKSUM_SHA256`). **What's missing for OCI is only the `/v2/` URL
  surface and the `WWW-Authenticate: Bearer` token dance** — the
  byte-moving, caching, eviction, metrics and guard planes all exist.
- An RPM/dnf repo is *plain HTTP with a metadata-freshness rule* — the mirror
  work there is TTL policy, a config recipe, and an oracle lane, not new C.
- The client tool surface has its own hardened HTTP/1.1(+TLS) stack —
  `brix_http_req()` / `brix_http_header()` / `brix_http_download()`
  (`client/lib/brix_net.h:321`), already injected into the shared S3 driver
  as a `brix_s3_transport_t` (`client/lib/fs/backend/s3/vfs_s3_transport.c`)
  — so `brixoci` needs **zero new socket code**: registry pull/push is
  request-building over an existing transport, exactly the sd_s3 pattern.

## 0.2 Reusable substrate (verified anchors, 2026-08-17)

| Need | Already in tree |
|---|---|
| Read-through cache fill from an HTTP(S) origin | `src/fs/cache/open_or_fill.c` → `src/fs/backend/http/sd_http*.c`; thread-pool curl transport `src/fs/cache/origin/` (`s3_transport.c` = server-side `brix_s3_transport_t` impl) |
| Static bearer + per-user credential forwarding to origins | `sd_http.c:178` (`Authorization: Bearer %s` from `cfg->bearer_token`), `sd_http_mutate.c`, `sd_http_dir.c:341` |
| Digest verification at the fill edge | `src/fs/cache/verify.h` — verify against origin-advertised digest before the part-file rename; policy `brix_cache_verify off|best-effort|require|cvmfs-cas`; records `BRIX_CINFO_F_VERIFIED` provenance |
| Checksum kernel with sha256 | `src/core/compat/checksum.h` — `brix_checksum_alg_t` incl. `BRIX_CHECKSUM_SHA256`; `brix_checksum_hex_name_fd()` (name-string → hex) |
| Cross-worker SHM KV with TTL (token cache substrate) | `src/core/shm/kv.h` — `brix_kv_t` zones: `brix_kv_configure/get/set/delete/stats`, FNV-1a + linear probing, lazy expiry, load ≤ 0.5, per-zone spinlock; INVARIANT #10's creation path |
| HTTP-plane protocol module template (commands[] from directive headers, gate/classify → handler, per-repo authz, virtual union) | `src/protocols/cvmfs/{module,gate,handler,virtual}.c`; directive-header pattern `directives_core.h` ("#included into … commands[]; not a standalone TU") |
| scvmfs-style authn preamble (TLS / bearer / x509-DN / VOMS, policy glue only) | `src/protocols/cvmfs/secure.c`, `secure_x509.c` (S14 proved it pure config on new trees) |
| Publish engine: changeset → signed revision, chunking, dirtab, reflog, GC, tags, fsck | `shared/cvmfs/publish/{changeset,publish,admin,fsck}` — `cvmfs_changeset_scan()`, `cvmfs_publish_run()` (+ `$BRIXCVMFS_PUBLISH_CRASH` hook), `cvmfs_gc_run()`, `cvmfs_fsck_run(check_data)` |
| Overlay whiteout grammar + upper-tree ops | `client/lib/fs/overlay.h` — `BRIX_OV_WH_PREFIX ".brix.wh."`, `BRIX_OV_OPQ_NAME ".brix.opq"`, `BRIX_OV_TMP_PREFIX`, `brix_overlay_whiteout_set/clear()`, reserved-name classifier |
| CLI personality dispatch + usage/man pattern | `client/apps/fs/brixmount.c` — `brix_prog_base(argv[0])` compare in `main()`, `brixcvmfs_personality()` at :149, `BRIX_USAGE_FOOTER`; `client/Makefile:202` `OPT_LINKS` |
| Client HTTP/1.1(+TLS) stack | `client/lib/brix_net.h:321` `brix_http_req()` (extra_headers block, verify + ca_dir + client_cert), `brix_http_header()`, `brix_http_resp_free()`, streaming `brix_http_download`/upload via `brix_http_body_src_fn` |
| Transport-injection precedent (protocol logic in src/, transport per consumer) | `src/fs/backend/s3/sd_s3_transport.h` (`brix_s3_transport_t`: one synchronous request op + accessors); client impl `vfs_s3_transport.c`, server impl `src/fs/cache/origin/s3_transport.c` |
| Minimal libc-only JSON extraction (client/shared side) | `src/core/compat/json_min.h` — `brix_json_get_str()` (string-aware, escape-decoding, depth-1 member extract; arrays/objects deliberately not copied → D5 adds the span/iterator API) |
| Security-critical JSON (server side) | jansson layer `src/auth/token/json.c` (JWKS/JWT paths) |
| Atomic staged writes (upload sessions, metadata swaps) | `src/core/compat/staged_file.h` — `brix_staged_open/_resume`, `brix_commit_staged`, pending-mark + reaper (`brix_stage_reap_dir/all`); VFS flavor `src/fs/vfs/vfs_staged.c` |
| CAS store discipline (temp+rename, dirfd, quota, reap) | `shared/cache/cas_store.h` — `brix_cas_init[_at]/_put/_open/_has/_del/_reap/_enforce_quota` |
| zlib (unconditional) / zstd (gated) | `./config:253` `BRIX_HAVE_ZSTD` via pkg-config; shared-core dep set is libc + OpenSSL/zlib/zstd + sqlite3 |
| Unified guard line + fail2ban co-landing | `src/net/guard/guard.h` (`guard_reason_t`; precedent `GUARD_R_TAMPER` → `signal=cvmfs_tamper`), `guard_audit.c:112` line format `"<ts> ip=<ip> proto=<proto> signal=<s> op=<op> path=\"…\" status=<d>"`; filters/jails in `deploy/fail2ban/{filter.d,jail.d}` |
| Rootless-container test seam | `tests/cmdscripts/container_runtime.py` (phase-92) |
| Mock-origin server pattern (request log + `/ctl/` fault plane) | `tests/cvmfs/mock_stratum1.py` — one-shot faults stall/reset/corrupt/truncate/wrong_length/http500/slowdrip; the shape `tests/oci/mock_registry.py` mirrors (§0.8.1) |
| Fleet registration | `tests/server_registry.py` `NginxInstanceSpec` (name/template/port/protocol/extra_ports/env/template_values/readiness/requires/tags), specs catalogued in `tests/fleet_specs.py` via `RegistryLauncher` |
| Official-cvmfs-client oracle lane pattern | phase-96 S9; `tests/test_cvmfs_stratum0_quickstart.py` shape (personality → publish → mount → tamper legs) |
| Port-block bookkeeping | `docs/10-reference/test-fleet-ports.md` — cvmfs tiling 13100–13619, next free base 13620; the 14000–14999 range is **entirely unclaimed** today (verified: zero `14xxx` occurrences) |

**Genuinely absent (the actual work):** OCI `/v2/` URL classifier + method
gate · upstream Bearer token dance + SHM token cache · manifest/blob cache
policy (immutable-by-digest vs tag revalidation, media-type round-trip) ·
push API (upload sessions) · `brixoci` tool + local image store · **any tar
reader** · OCI→overlay whiteout flattener · ingest subcommands · **any RPM
header parser** · repomd/primary/filelists XML emission · oracle lanes
(podman pull, podman push, podman run --rootfs, dnf install).

## 0.3 Prime directives

1. **Tool-heavy, proxy-light.** Ingest, flattening, RPM metadata generation
   live on the client/tool surface (the G14 ruling, applied by phase-96):
   nginx workers never walk catalogs, never untar layers, never parse RPM
   headers. The proxy's new code is URL surface + auth dance + cache policy.
2. **Ride the fill path; do not fork it.** The mirror is the existing
   read-through cache with an OCI-shaped key/policy layer. No second HTTP
   client, no per-scheme transport revival (phase-64 §14 stays retired).
3. **Content addressing is the security model.** Every blob and manifest
   fetched by digest is verified against that digest at the fill edge before
   a client sees a byte (mirror) or a manifest is signed (ingest). A
   digest-mismatch is a hard fail plus a guard line, never a serve.
4. **Fail-closed gating.** All server-side behavior sits behind new
   directives, default off (`brix_oci_mirror`, `brix_oci_registry`); tool
   subcommands are inert unless invoked. Gates off ⇒ phase-84/96 corpora and
   every existing conf matrix byte-identical.
5. **Existing authn planes only.** The push surface authorizes via the
   token/x509/VOMS machinery that already gates WebDAV writes
   (`allow_write` before token scope — INVARIANT #3); private-image serving
   via the scvmfs preamble (S14). No new credential formats.
6. **Standard discipline:** ngx-free shared core; no `goto`; every new `.c`
   in repo-root `./config` **and** `CMakeLists.txt`/`cmake/` **and**
   `client/Makefile` where client-linked (guards `check_config_coverage.py` /
   `check_client_build_coverage.py`); 3 tests per feature (success + error +
   security-negative); VFS seam (INVARIANT #12) for anything under `src/`;
   clean-room — **no linkage of docker/containerd/skopeo/librpm/libarchive**;
   formats from the published specs (§Provenance list) and our own pinned
   parsers.
7. **External oracles from day one.** rootless **podman** (pull through the
   mirror, push to the registry, `run --rootfs` off the cvmfs mount), the
   **official cvmfs client** (mount ingested images), and **dnf** (install
   from mirrored and generated repos). A surface only our own client accepts
   is a bug the corpus can't see.

---

## 0.4 Scope and the feature roster

**In scope — 16 features in 5 waves.** Surface = Proxy (nginx) / Tool
(`brixoci`·`brixcvmfs`·`brixrpm`) / Shared (`shared/oci/`, `shared/rpm/`).

| # | Feature | Surface | Wave | Gate |
|---|---|---|---|---|
| D0 | OCI `/v2/` classifier + method gate + location plumbing | Proxy | A | `brix_oci_mirror` |
| D1 | Upstream registry auth: Bearer token dance + SHM token cache | Proxy | A | (inside D0) |
| D2 | Cache policy: immutable-by-digest, tag revalidation, media-type fidelity | Proxy | A | (inside D0) |
| D3 | Mirror observability + podman-pull oracle lane | Proxy/Test | A | live-lab marker |
| D4 | Local registry push API (upload sessions, manifest PUT, tags, DELETE) | Proxy | B | `brix_oci_registry` |
| D5 | `brixoci` CLI: pull / push / ls / tags / rm / copy + local image store | Tool | B* | `brixoci …` |
| D6 | Streaming tar reader (ustar/pax/GNU-long; gzip/zstd member and frame chains, zstd gated) | Shared | C | n/a (library) |
| D7 | Layer flattener: OCI whiteouts → overlay grammar, containment | Shared | C | n/a (library) |
| D8 | `brixcvmfs ingest image <ref>` — image → published Stratum-0 subtree | Tool | C | `brixcvmfs ingest image` |
| D9 | `brixcvmfs ingest dir <folder> --prefix P` — folder → Tier-0 in seconds | Tool | C | `brixcvmfs ingest dir` |
| D10 | Container-runtime + official-client oracle (`podman run --rootfs /cvmfs/…`) | Test | C | live-lab marker |
| D11 | RPM/dnf pull-through mirror recipe + repodata TTL policy | Proxy-config | D | config + docs |
| D12 | `brixrpm createrepo` — clean-room RPM header parser + repomd emission | Tool/Shared | D | `brixrpm …` |
| D13 | RPM repo → CVMFS runbook (`ingest dir` + `file:///cvmfs` baseurl) | Tool/docs | D | (uses D9) |
| D14 | Deployment composition: scvmfs-gated private images, virtual union, re-export | Proxy/docs | E | existing directives |
| D15.1 | OCI referrers API (`/v2/<n>/referrers/<digest>`) + `OCI-Subject` | Proxy | E′ | existing directives |
| D15.2 | IPv6-literal registry hosts in refs, over the shared authority grammar | Tool/Shared | E′ | — |
| D15.3 | Registry GC — the operator-run `brixoci gc` mark-and-sweep | Tool | E′ | — |
| D15.4 | sha512 digests end to end — the grammar's second registered algorithm | Proxy/Shared/Tool | E′ | — |
| D15.5 | Background in-proxy registry GC — the same kernel on a maintenance timer | Proxy/Shared | E′ | §D15.3 |
| D15.6 | Non-flat (layered) publish — one content-addressed root per layer, shared across images | Tool | E′ | §D8 |
| D15.7 | Lazy-pull layer encodings — eStargz gzip-member chains and `zstd:chunked` frame chains read whole | Shared | E′ | §D6/§D7 |
| D15.8 | eStargz layer **building** — `brixoci convert --estargz`, the writer half of the lazy-pull encodings | Shared/Tool | E′ | §D15.7 |
| D15 | containerd snapshotter plugin (the runtime, not the layer formats — which are now both read and written) | — | E′ | **DEFERRED** |

\* D5's **pull-transport slice** (§D5.1: ref parse, token dance, manifest
resolve, blob fetch) is carved out and landed **inside Wave C** as
`client/lib/oci/` — Wave C depends on pulling, not on pushing.

**Non-goals (phase-104):** image building & Dockerfile anything ·
vulnerability scanning / signing-policy engines (cosign verification is a
D15 candidate) · `docker save`/`load` tarball archives ·
federation/notification webhooks · multi-arch
*fan-out* publishing (ingest selects one platform; the index is preserved by
the mirror verbatim). IPv6-literal registry hosts, sha512 digests,
background registry-side GC and non-flat per-layer publish were all on this
list and came off it — delivered in §D15.2, §D15.4, §D15.5, §D15.6, §D15.7
and §D15.8; the lazy-pull encodings are now both read and written, and only
the snapshotter *runtime* stays out. The
GC row was on it **twice**,
which is worth recording: a non-goal restated is not a stronger non-goal,
and both spellings of it fell to the same observation, that the objection
was to a whole-store walk on the event loop and never to a schedule.

---

## 0.5 Deliverable inventory — every new file, its owner surface, its size budget

The guard fleet's caps (CCN ≤ 15, ≤ 600 lines/file) are design inputs, not
after-the-fact fixes: the split below is the *planned* file set. Estimated
LOC are budgets — crossing a budget forces a split review, not a waiver.

### New server code (`src/protocols/oci/` — nginx-linked, wired in `./config` + `CMakeLists.txt`)

| File | Wave | ~LOC | Responsibility |
|---|---|---|---|
| `oci.h` | A | 150 | Public types: request classification struct, conf structs, enums shared across the bucket |
| `oci_module.c` | A | 300 | `ngx_http_brix_oci_module`, commands[] concatenated from `directives_mirror.h` + `directives_registry.h` (cvmfs pattern), conf create/merge, EMERG cross-checks (§0.6.3) |
| `directives_mirror.h` | A | 120 | Mirror directive table fragment (not a TU) |
| `directives_registry.h` | B | 140 | Registry directive table fragment (not a TU) |
| `oci_classify.c` | A | 350 | Pure-C `/v2/` URL classifier (§D0.2) — no nginx types in the kernel, mirrors `src/net/guard/` embeddability so the fuzz lane links it standalone |
| `oci_gate.c` | A | 250 | Location entry: method gate, classify call, per-class routing, guard adapter |
| `oci_mirror.c` | A | 400 | Pull-surface handler: cache-key derivation, fill-or-serve orchestration, header echo (§D2.4) |
| `oci_upstream_auth.c` | A | 400 | Token dance: challenge parse, token fetch, `brix_kv_t` cache (§D1) |
| `oci_errors.c` | A | 150 | Spec error-body emitter (`{"errors":[{code,message,detail}]}`, §0.7.4) — single source of truth for every error the surface returns |
| `oci_registry.c` | B | 450 | Push-surface handler: routing for uploads/manifest/tag/delete (§D4) |
| `oci_upload.c` | B | 450 | Upload-session state machine over `staged_file` (§D4.2) |
| `oci_manifest_put.c` | B | 300 | Manifest validation (jansson), referential blob check, tag swap (§D4.3) |
| `oci_store.c` | B | 350 | Registry store layout over VFS seam (§D4.1): blob/manifest/tag path mapping, link/refcount helpers |

### New shared core (`shared/oci/`, `shared/rpm/` — ngx-free: libc + zlib [+zstd] + OpenSSL only; wired in `./config` + `client/Makefile` + `CMakeLists.txt`)

| File | Wave | ~LOC | Responsibility |
|---|---|---|---|
| `shared/oci/digest.{c,h}` | A | 120 | Digest grammar parse/format (§0.7.2), hex validation, constant-time compare helper |
| `shared/oci/name.{c,h}` | A | 120 | Repository-name + tag grammar (§0.7.2) — one implementation used by proxy classifier AND client tools |
| `shared/oci/tar.{c,h}` | C | 550 | Streaming tar pull-parser (§D6) |
| `shared/oci/tar_pax.c` | C | 250 | pax record parsing (split from tar.c by design) |
| `shared/oci/flatten.{c,h}` | C | 450 | Layer application into an overlay upper tree (§D7) |
| `shared/oci/stargz.{c,h}` | E′ | 500 | eStargz writer: gzip re-framing over verbatim tar bytes, landmark + footer (§D15.8) |
| `shared/oci/stargz_toc.c` | E′ | 220 | The `stargz.index.json` TOC document (split from stargz.c by design) |
| `shared/oci/mediatypes.h` | A | 80 | The media-type string table (§0.7.3) — the only place the strings appear |
| `shared/rpm/rpmhdr.{c,h}` | D | 500 | RPM lead/signature/header reader + tag accessors (§D12.2) |
| `shared/rpm/repomd_write.c` | D | 450 | primary/filelists/other/repomd XML emission (§D12.3) |

### New client code (`client/lib/oci/`, `client/apps/` — wired in `client/Makefile`)

| File | Wave | ~LOC | Responsibility |
|---|---|---|---|
| `client/lib/oci/ref.{c,h}` | C | 200 | Image reference parse (`[host[:port]/]name[:tag][@digest]`, §D5.1) |
| `client/lib/oci/reg_client.{c,h}` | C | 500 | Registry client over `brix_http_req`: token dance, manifest resolve (index → platform), blob fetch/upload, redirect policy (§D5.1) |
| `client/lib/oci/layout.{c,h}` | B | 300 | OCI image-layout local store read/write (§D5.3) |
| `src/core/compat/json_iter.{c,h}` | C | 250 | `json_min` extension: raw-span getter + array/object element iterator (§D5.2) — lives beside `json_min` itself, which is what §D15.5 needed when the server-side GC mark phase came to walk manifests too |
| `client/apps/oci/brixoci.c` | B | 400 | `brixoci` subcommand dispatch + usage/man (personality registered in `brixmount.c`, `OPT_LINKS` line) |
| `client/apps/oci/brixoci_copy.c` | B | 300 | `copy` verb (registry↔layout↔registry pump) |
| `client/apps/oci/brixoci_convert.c` | E′ | 540 | `convert --estargz` verb: per-layer re-encode plus the config/manifest rewrite the new diff_ids force (§D15.8), over the copy pump's endpoint seams |
| `client/apps/fs/brixcvmfs_ingest.c` | C | 450 | `ingest image|dir` verbs: pipeline conductor (§D8/§D9) — shipped as five TUs under the size cap, one of them `brixcvmfs_ingest_layout.c` for the published namespace (§D15.6) |
| `client/apps/rpm/brixrpm.c` | D | 300 | `brixrpm createrepo|inspect` dispatch |

### New test assets

| Path | Wave | Responsibility |
|---|---|---|
| `tests/oci/mock_registry.py` | A | Mock upstream registry + token server (§0.8.1) |
| `tests/oci/fixtures/` | C | Checked-in tar corpus (GNU/bsdtar/podman-writer archives, §D6 tests), a 3-layer fixture image, malformed-header corpus |
| `tests/rpm/fixtures/` | D | Small real RPMs (noarch, tiny) + truncated/fuzzed headers |
| `tests/test_oci_mirror_classify.py` · `_authdance.py` · `_cachepolicy.py` · `_podman_pull.py` | A | Wave-A lanes |
| `tests/test_oci_registry_push.py` · `_brixoci_copy.py` | B | Wave-B lanes |
| `tests/test_oci_tar_corpus.py` · `test_oci_flatten.py` · `test_cvmfs_ingest_image.py` · `test_cvmfs_ingest_dir.py` · `test_cvmfs_ingest_oracle.py` | C | Wave-C lanes |
| `tests/test_rpm_mirror_dnf.py` · `test_rpm_createrepo.py` · `test_rpm_cvmfs_compose.py` | D | Wave-D lanes |
| `tests/test_oci_compose_secure.py` | E | Wave-E lane |

Docs deliverables are enumerated in §Cross-cutting.

---

## 0.6 New configuration surface — complete directive grammar

All directives live in `src/protocols/oci/directives_*.h` fragments
following the cvmfs pattern (`directives_core.h` header comment: "#included
into … commands[]; the compiler concatenates; not a standalone TU").

### 0.6.1 Mirror directives (Wave A)

| Directive | Context | Args | Default | Meaning |
|---|---|---|---|---|
| `brix_oci_mirror <base-url>;` | loc | 1 | unset (surface off) | Marks the location as an OCI pull-through mirror of `<base-url>` (e.g. `https://registry-1.docker.io`). Exactly one upstream per location. Scheme must be `https` unless `brix_oci_mirror_insecure on` (test-only). |
| `brix_oci_mirror_auth <user> <password-file>;` | loc | 2 | none (anonymous) | Basic credentials presented to the **token endpoint** (never to the registry data plane) — lifts DockerHub anonymous pull limits. Password read from file at config load (never inline in conf), file must be mode ≤ 0600 (EMERG otherwise — same stance as key material elsewhere). |
| `brix_oci_manifest_ttl <time>;` | http/srv/loc | 1 | `60s` | Freshness window for **tag**-addressed manifests (§D2.2). Digest-addressed objects ignore it (immutable). |
| `brix_oci_token_zone <name> <size>;` | http | 2 | `oci_tokens 1m` | The `brix_kv_t` zone for cached upstream bearer tokens (§D1.3). One zone serves all mirror locations. |
| `brix_oci_upstream_namespace <prefix>;` | loc | 1 | none | Optional name prefix prepended before forwarding (e.g. GitLab's group/project nesting under one mirror path). Applied after grammar validation, before cache-key derivation. |
| `brix_oci_mirror_insecure on\|off;` | loc | 1 | off | Allow `http://` upstream + disable TLS verify on the fill. **Test fixture only**; the directive description says so and the ops doc never shows it. |

`brix_oci_token_zone` is sugar over the generic KV plane: it performs the
same `brix_kv_configure()` call as the existing declaration grammar
`brix_kv_zone <name> <size> key=<bytes> val=<bytes>;`
(`src/core/shm/kv.h:105`) with `key=32 val=4096` pinned (§D1.3), plus the
mirror binding. Sizing arithmetic: Appendix I.1.

**DockerHub `library/` normalization** is behavior, not a directive: when the
upstream base host is `registry-1.docker.io` and the requested `<name>` has
no `/`, the classifier canonicalizes `alpine` → `library/alpine` *before*
cache-key derivation, so both spellings share one cache entry.

### 0.6.2 Registry directives (Wave B)

| Directive | Context | Args | Default | Meaning |
|---|---|---|---|---|
| `brix_oci_registry on\|off;` | loc | 1 | off | Enables the full Distribution API (pull + push) against local VFS storage rooted at the export. |
| `brix_oci_registry_root <path>;` | loc | 1 | export root | Store root override (layout §D4.1). Must resolve inside the export (`resolve_path()` — INVARIANT #4). |
| `brix_oci_max_blob_size <size>;` | http/srv/loc | 1 | `0` (unlimited) | Hard cap on a single blob; `PATCH`/`PUT` beyond it → 413 + `SIZE_INVALID`. |
| `brix_oci_upload_grace <time>;` | http/srv/loc | 1 | `24h` | Idle upload sessions older than this are reaped (rides `brix_stage_reap_dir` — §D4.2 step R). |

### 0.6.3 Config-load EMERG matrix (pinned by `srv_config`-style negative tests)

| Combination | Result |
|---|---|
| `brix_oci_mirror` + `brix_oci_registry` in one location | EMERG — "mirror and registry are different locations" |
| `brix_oci_mirror` + `brix_allow_write`/`brix_stage` | EMERG — mirror is read-only by construction |
| `brix_oci_registry on` without an authenticated context (no token issuer, no x509/VOMS, no explicit `brix_oci_registry_allow_anonymous on` escape hatch) | EMERG — an open push registry must be a typed decision |
| `brix_oci_mirror` with a non-`https` base and `brix_oci_mirror_insecure` unset | EMERG |
| `brix_oci_mirror_auth` password file world/group-readable | EMERG |
| any `brix_oci_*` directive on a cvmfs location | EMERG — surfaces never stack |

### 0.6.4 Reference config shapes (land in `deploy/oci-mirror/nginx.conf.example`)

```nginx
# Pull-through mirror of DockerHub (+ optional auth for rate limits)
location /v2/ {
    brix_oci_mirror       https://registry-1.docker.io;
    brix_oci_mirror_auth  mirroruser /etc/brix/dockerhub.pass;
    brix_oci_manifest_ttl 60s;
    brix_cache_store      /srv/oci-cache;          # existing cache grammar
    brix_cache_verify     require;                  # digest objects MUST verify
}
# Site-local registry (push), token-gated
location /local/v2/ {
    brix_oci_registry     on;
    brix_oci_registry_root /srv/oci-registry;
    brix_allow_write      on;                       # INVARIANT #3 ordering
    # existing token/x509 directives gate identity exactly as on dav writes
}
```

Client side: `podman` consumes the mirror via
`/etc/containers/registries.conf` `[[registry]] location="docker.io"` +
`[[registry.mirror]] location="mirror.site:8443"` — the ops doc shows the
full stanza; nothing image-side changes.

---

## 0.7 Wire primer — the OCI Distribution surface we implement

Normative source: OCI Distribution Spec v1.1 + Docker Registry HTTP API V2.
This section is the contract the classifier, handlers, tools and mock all
implement; conformance tests cite section numbers from here.

### 0.7.1 Endpoint × method matrix

| Route (under the location prefix) | GET | HEAD | POST | PATCH | PUT | DELETE | Mirror (D0) | Registry (D4) |
|---|---|---|---|---|---|---|---|---|
| `/v2/` | ✓ | ✓ | — | — | — | — | ✓ (local 200) | ✓ |
| `/v2/<name>/manifests/<ref>` | ✓ | ✓ | — | — | ✓ | ✓ | GET/HEAD only | all |
| `/v2/<name>/blobs/<digest>` | ✓ | ✓ | — | — | — | ✓ | GET/HEAD only | GET/HEAD/DELETE |
| `/v2/<name>/blobs/uploads/` | — | — | ✓ | — | — | — | 405 | ✓ |
| `/v2/<name>/blobs/uploads/<session>` | ✓ | — | — | ✓ | ✓ | ✓ | 405 | ✓ |
| `/v2/<name>/tags/list` | ✓ | — | — | — | — | — | forward, uncached | ✓ |
| `/v2/<name>/referrers/<digest>` | ✓ | ✓ | — | — | — | — | forward, uncached | ✓ |

Anything else under the prefix → 404 with `NAME_INVALID`/`NAME_UNKNOWN`
bodies as appropriate; any method not in the row → **405** with an `Allow:`
header naming the row's methods. Both surfaces always answer with
`Docker-Distribution-API-Version: registry/2.0`.

`GET /v2/` on the mirror answers **locally** — `200`, body `{}`, no upstream
round-trip (decision pinned here, was v1 open question #1): clients use it
as a liveness ping, and coupling our liveness to the upstream's would make
`podman login`-style probes flap with DockerHub weather. The registry
surface answers `200 {}` when the request is authenticated and `401` +
challenge otherwise (spec behavior clients key their auth flow off).

### 0.7.2 Grammars (implemented once, in `shared/oci/{name,digest}.c`)

```
name      ::= component ("/" component)*          ; ≤ 255 bytes total
component ::= [a-z0-9]+ ( ( "." | "_" | "__" | "-"+ ) [a-z0-9]+ )*
tag       ::= [a-zA-Z0-9_] [a-zA-Z0-9._-]{0,127}
digest    ::= algorithm ":" hex
algorithm ::= [a-z0-9]+ ( [+._-] [a-z0-9]+ )*     ; registered: sha256, sha512
hex       ::= [a-f0-9]{64} | [a-f0-9]{128}        ; the WIDTH names the algorithm
reference ::= tag | digest                        ; manifests/<ref>
```

Enforced properties (each is a classifier unit test): no empty components,
no leading/trailing separator runs, no `..` anywhere, no `%`-escapes
surviving into the grammar (the classifier operates on the *decoded* URI and
refuses any decoded `/` that changes component count — encoded-slash
smuggling), byte-length caps before any allocation, and the digest hex is
validated before it is ever used as a path component (it becomes one in the
cache key and the store layout — a digest that passes grammar **cannot**
traverse, by construction).

### 0.7.3 Media types (`shared/oci/mediatypes.h` — the only place the strings live)

| Constant | Value |
|---|---|
| `OCI_MT_MANIFEST` | `application/vnd.oci.image.manifest.v1+json` |
| `OCI_MT_INDEX` | `application/vnd.oci.image.index.v1+json` |
| `OCI_MT_CONFIG` | `application/vnd.oci.image.config.v1+json` |
| `OCI_MT_LAYER_TAR` | `application/vnd.oci.image.layer.v1.tar` |
| `OCI_MT_LAYER_GZ` | `application/vnd.oci.image.layer.v1.tar+gzip` |
| `OCI_MT_LAYER_ZSTD` | `application/vnd.oci.image.layer.v1.tar+zstd` |
| `D2_MT_MANIFEST` | `application/vnd.docker.distribution.manifest.v2+json` |
| `D2_MT_LIST` | `application/vnd.docker.distribution.manifest.list.v2+json` |
| `D2_MT_CONFIG` | `application/vnd.docker.container.image.v1+json` |
| `D2_MT_LAYER_GZ` | `application/vnd.docker.image.rootfs.diff.tar.gzip` |
| `D2_MT_LAYER_FOREIGN` | `application/vnd.docker.image.rootfs.foreign.diff.tar.gzip` |

Mirror rule: media types are **opaque round-tripped strings** — the mirror
never branches on them (it stores and echoes Content-Type byte-exact,
§D2.4). Tools (D5/D8) branch on them via these constants only. Foreign
layers (Windows base images) are refused by ingest with a clear message and
passed through untouched by the mirror.

### 0.7.4 Error bodies (`oci_errors.c` — single emitter)

Every non-2xx from either surface carries the spec envelope:

```json
{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown","detail":{"name":"library/foo","ref":"1.2"}}]}
```

| Code | Used by | HTTP |
|---|---|---|
| `NAME_INVALID` / `NAME_UNKNOWN` | both | 400 / 404 |
| `MANIFEST_UNKNOWN` / `MANIFEST_INVALID` / `MANIFEST_BLOB_UNKNOWN` | both / D4 / D4 | 404 / 400 / 400 |
| `BLOB_UNKNOWN` | both | 404 |
| `BLOB_UPLOAD_UNKNOWN` / `BLOB_UPLOAD_INVALID` | D4 | 404 / 400 |
| `DIGEST_INVALID` | both | 400 |
| `SIZE_INVALID` | D4 | 413 |
| `UNAUTHORIZED` / `DENIED` | both | 401 / 403 |
| `UNSUPPORTED` | both | 405/400 |
| `TOOMANYREQUESTS` | mirror (upstream echo) | 429 |

Upstream-failure mapping on the mirror (fill path): upstream 401/403 after a
completed token dance → 502 (OUR auth to upstream failed — never leak the
upstream challenge to the client); upstream 404 → 404 `MANIFEST_UNKNOWN`/
`BLOB_UNKNOWN`; upstream 429 → 429 echoed with `Retry-After` if present;
upstream 5xx / transport error / digest-verify fail → 502; token-endpoint
failure → 502. Every 5xx-class mapping increments a metric (§D3.1) and the
verify failure additionally emits the guard line (§D3.2).

### 0.7.5 The token dance (registry auth protocol), end to end

```
1→ GET /v2/library/alpine/manifests/latest        (no auth)
1← 401  WWW-Authenticate: Bearer realm="https://auth.docker.io/token",
        service="registry.docker.io",scope="repository:library/alpine:pull"
2→ GET https://auth.docker.io/token?service=registry.docker.io
        &scope=repository:library/alpine:pull
        [Authorization: Basic <user:pass>]         (only if brix_oci_mirror_auth)
2← 200  {"token":"eyJ…","expires_in":300,"issued_at":"…"}
3→ GET /v2/library/alpine/manifests/latest
        Authorization: Bearer eyJ…
3← 200  Content-Type: application/vnd.oci.image.index.v1+json
        Docker-Content-Digest: sha256:…
```

Parse rules (D1): the challenge is RFC 7235 auth-param grammar — split on
commas outside quotes, unquote values, require `realm`; `service`/`scope`
optional (echo the server's `scope` verbatim — never synthesize one when the
challenge supplies it; synthesize `repository:<name>:pull` only when absent).
The token is `token` or `access_token` (Quay uses the latter) —
`brix_json_get_str()`-class extraction server-side is **not** used here:
this is a security-relevant parse, so the jansson layer
(`src/auth/token/json.c` patterns) does it. `expires_in` absent → assume
60 s (spec default). GitLab's realm is `https://gitlab.com/jwt/auth`,
service `container_registry`; Quay's realm `https://quay.io/v2/auth` —
no per-vendor code paths: the challenge tells us everything.

---

## 0.8 Test infrastructure additions

### 0.8.1 `tests/oci/mock_registry.py` — the Wave-A deliverable everything leans on

Mirrors `tests/cvmfs/mock_stratum1.py`'s shape exactly (ThreadingHTTPServer,
locked STATE, request log, `/ctl/` control plane, one-shot faults):

- Serves the §0.7.1 matrix over a small in-memory image set built at start
  (a 2-layer and a 3-layer image, one multi-arch index, deterministic seed);
  bodies are real tars built by the fixture generator so ingest lanes can
  reuse the same mock.
- **Token mode** (`--auth`): data-plane requests without a bearer → 401 +
  challenge pointing at its own `/token` endpoint; `/token` validates
  optional Basic creds, returns `{"token": …, "expires_in": N}` with
  configurable N; `/ctl/token_count` exposes how many tokens were minted
  (the D1 "one dance per scope" assertions read this).
- **Redirect mode** (`--blob-redirect http://host:port`): blob GETs answer
  302 to a second instance posing as the CDN, which **asserts** no
  `Authorization` header arrived (the D1 security-negative).
- Faults via `/ctl/fault` (one-shot, mock_stratum1 vocabulary): `stall`,
  `reset`, `corrupt` (flip a body byte — the D2 verify lanes), `truncate`,
  `http500`, `slow drip`, plus OCI-specific `wrong_digest_header` (lie in
  `Docker-Content-Digest`) and `retag` (move a tag to another digest — the
  D2 TTL lanes).
- Push mode (`--push`) for D4/D5 client tests: accepts the upload state
  machine, `/ctl/` exposes received session transcript.

### 0.8.2 Port claims (write into `docs/10-reference/test-fleet-ports.md` in the same change as the first lane)

The 14000–14999 range is unclaimed (verified 2026-08-17 — zero occurrences
in the map). Claim a new **`oci` neighborhood at 14100**, 20-port blocks,
same tiling discipline as the cvmfs table (base+0..9 mocks, base+10..19
nginx):

| Block | Base | Lanes |
|---|---|---|
| `oci_mirror` | 14100 | classify/authdance/cachepolicy |
| `oci_mirror_live` | 14120 | podman-pull live lab |
| `oci_registry` | 14140 | push API + brixoci |
| `rpm_mirror` | 14160 | dnf mirror lanes |
| `rpm_repo` | 14180 | createrepo + compose |
| `oci_compose` | 14200 | Wave-E secure/compose lane |

CVMFS-adjacent ingest lanes continue the existing conformance tiling:
`srv_ingest` **13620**, `srv_ingest_oracle` **13640** (next free after
`srv_s0_quickstart` 13600–13619; re-verify at wave start, `DRIFT:` if taken).
`DRIFT (2026-08-17):` `srv_smoke` had taken 13620 by wave-C start — the two
blocks landed one slot later: `srv_ingest` **13640**, `srv_ingest_oracle`
**13660** (appended to `_CANONICAL_ORDER`; lanes draw via `PortBlock`, never
raw numbers, so only the canonical map moved).

### 0.8.3 Fleet registration

Mirror/registry nginx instances register in `tests/fleet_specs.py` as
`NginxInstanceSpec` entries (verbatim proposed entries: Appendix G.3).
Conf templates are **not** a separate format: they are plain nginx confs
carrying `{PLACEHOLDER}` tokens, living in `tests/configs/`, rendered by
`render_config()` (`tests/config_templates.py`; `strict=True` makes an
unresolved placeholder fatal) — `oci_mirror.conf` / `oci_registry.conf`
land beside the existing ones (template text: Appendix G.2). Ingest lanes follow whichever pattern the
cvmfs suite they sit beside already uses (standing caveat: cvmfs conformance
files spawn their own `LiveRun` instances — do not mix patterns within a
file). Container lanes (`podman`/`dnf`) ride
`tests/cmdscripts/container_runtime.py` and are live-lab marked,
fast-tier-skipped, SKIP-not-FAIL without a runtime.

---

# Wave A — OCI pull-through mirror (the in-line DockerHub/Quay/GitLab cache)

**Exit criterion:** a stock rootless `podman pull` of a multi-arch public
image through the mirror succeeds cold and warm; the second pull's data plane
is served entirely from cache (mock request log proves zero upstream blob
hits); a corrupted upstream blob is refused with a guard line, never served.

## D0 — `/v2/` classifier + method gate + location plumbing

### D0.1 Request flow (one request, end to end)

```
client GET /v2/library/alpine/blobs/sha256:abc…
  → oci_gate.c    : location handler; surface on? method in matrix? (405+Allow if not)
  → oci_classify.c: pure-C parse → brix_oci_req_t {class, name, ref, digest}
                    grammar violation → 400 NAME_INVALID / DIGEST_INVALID (oci_errors.c)
  → oci_mirror.c  : derive cache key (§D2.3); cache hit? serve (existing plane)
                    miss → fill via sd_http upstream with token (D1) → verify (D2) → serve
```

The serve/fill step is not new machinery: it is the same shared
offload → coalesced-fill → `brix_vfs_open` → ranged-serve composition the
cvmfs and WebDAV GET handlers already drive — the full wiring blueprint,
grounded in the tree's actual helpers, is Appendix J.

### D0.2 The classifier kernel (`oci_classify.c`) — pure C, fuzz-linked

Modeled on `src/net/guard/`'s embeddability: no nginx types, no allocation
(caller provides the struct; name/ref are pointers+lengths into the input
URI), so the protocol-fuzz lane links it standalone alongside the existing
parser kernels.

```c
typedef enum {
    BRIX_OCI_REQ_API_ROOT,        /* /v2/                          */
    BRIX_OCI_REQ_MANIFEST,        /* /v2/<name>/manifests/<ref>    */
    BRIX_OCI_REQ_BLOB,            /* /v2/<name>/blobs/<digest>     */
    BRIX_OCI_REQ_UPLOAD_START,    /* /v2/<name>/blobs/uploads/     */
    BRIX_OCI_REQ_UPLOAD_SESSION,  /* /v2/<name>/blobs/uploads/<id> */
    BRIX_OCI_REQ_TAGS_LIST,       /* /v2/<name>/tags/list          */
    BRIX_OCI_REQ_REFERRERS,       /* /v2/<name>/referrers/<digest> */
    BRIX_OCI_REQ_BAD              /* + err code for the error body */
} brix_oci_class_t;

typedef struct {
    brix_oci_class_t  cls;
    const char       *name;  size_t name_len;   /* validated repo name   */
    const char       *ref;   size_t ref_len;    /* tag or digest string  */
    int               ref_is_digest;            /* manifests/<ref> only  */
    char              digest_hex[65];           /* blobs/uploads: parsed */
    const char       *session; size_t session_len;
} brix_oci_req_t;

int brix_oci_classify(const char *uri, size_t len,   /* DECODED uri     */
                      brix_oci_req_t *out);          /* 0 ok, -1 = BAD  */
```

Rules beyond §0.7.2: the literal `/v2/` prefix is found *after* the location
prefix strip (so `/local/v2/…` registries work); `<name>` greedily matches
components until one of the four reserved terminals (`manifests`, `blobs`,
`tags`, `blobs/uploads` — matched right-to-left so a repo actually named
`blobs` still works when followed by its own terminal); session IDs are
`[A-Za-z0-9_-]{1,128}` (ours are staged-file basenames; upstream ones are
opaque — the mirror never sees them since it 405s uploads).

### D0.3 Gate behavior (`oci_gate.c`)

- Surface selection: `brix_oci_mirror` set → mirror mode (GET/HEAD rows
  only); `brix_oci_registry on` → full matrix. Both set is EMERG'd at load.
- Mirror mode: POST/PATCH/PUT/DELETE anywhere → 405 + `Allow: GET, HEAD` +
  `UNSUPPORTED` body, **and** a `GUARD_R_OCIPUSH` audit line (§D3.2) — a
  write aimed at a mirror is the same signal class as a write aimed at a
  cvmfs location (phase-84's 405 discipline).
- `TAGS_LIST` on the mirror: forwarded with the D1 token, **never cached**
  (tag lists are unboundedly mutable), response streamed through; `?n=&last=`
  pagination params forwarded verbatim.
- All handling happens after the existing access/authz phases — an scvmfs- or
  token-gated mirror location composes for free (Wave E uses this).

### D0.4 Tests (`tests/test_oci_mirror_classify.py`, block 14100)

1. *success* — matrix sweep: every §0.7.1 mirror row × (valid name shapes:
   1-component, 3-component, DockerHub-normalized bare name) classifies and
   routes; `/v2/` answers 200 `{}` locally with zero mock hits.
2. *error* — 405s carry correct `Allow:` + `UNSUPPORTED` envelope; unknown
   routes 404; over-long name (256 B) and 129-B tag → 400 `NAME_INVALID`.
3. *security-negative* — traversal corpus (`%2e%2e`, encoded-slash smuggling
   `%2f` changing component count, digest with non-hex, `.wh.`-spelled repo
   names — legal per grammar, must classify not sanitize), each → 400/404
   and **zero** upstream requests in the mock log; plus the classifier fuzz
   corpus seed set checked into `tests/oci/fixtures/classify/`.

**Effort:** M. Classifier + gate + module scaffolding + errors ≈ 1.2 kLOC
across 6 files; the fill-path wiring itself is configuration of the existing
plane.

## D1 — Upstream Bearer token dance + SHM token cache

### D1.1 Placement

The dance runs **inside the fill path** (thread-pool context, where blocking
curl already lives — `src/fs/cache/origin/`), not in the event loop: a fill
that gets 401 performs challenge-parse → token-fetch → retry-with-bearer
within the same blocking fill operation. `oci_upstream_auth.c` provides:

```c
/* Returns a bearer for (upstream, scope) — from the SHM cache when fresh,
 * else by performing the §0.7.5 dance against `challenge`. Thread-pool
 * context only. 0 ok (token in buf), -1 dance failed (fill → 502). */
int brix_oci_token_get(brix_oci_upstream_t *up,
                       const char *scope,            /* "repository:N:pull" */
                       const char *challenge,        /* WWW-Authenticate or NULL */
                       char *token, size_t toklen);
```

### D1.2 Challenge parsing

RFC 7235 auth-param list, quoted-string aware, `realm` required; implemented
beside the handler (it is small) with the parse-table unit-tested through
the C-unit lane. The realm URL is refetched **through the same curl
transport with TLS verify on** — the realm is attacker-influenced input
(it arrives in a response header), so it is constrained: scheme must be
https (unless `brix_oci_mirror_insecure`), and the host must be either the
upstream host itself or match a small allowlist derived from the configured
base (DockerHub's `auth.docker.io`, GitLab's `/jwt/auth` on the same host,
Quay's same-host `/v2/auth` all pass; an arbitrary third-party realm does
not — that would let a compromised upstream aim our Basic credentials
anywhere). Token JSON is parsed with the jansson layer; `token` then
`access_token`; `expires_in` default 60.

### D1.3 SHM token cache

A dedicated `brix_kv_t` zone (`brix_oci_token_zone`, default `oci_tokens
1m`): key = `sha256(upstream_base ‖ 0x00 ‖ scope)` (fixed 32-byte key —
`brix_kv` keys are fixed-max at configure; hashing sidesteps long scopes);
value = token bytes (val_max 4 KiB — DockerHub JWTs are ~1.5 KiB) with TTL
`(expires_in − 30 s slack)` clamped to ≥ 5 s, set via the existing
`brix_kv_set(..., ttl_ms)`. Expiry is the zone's lazy-expiry; no sweeper
needed. **No single-flight in v1:** two workers racing the dance costs one
duplicate token fetch (idempotent, cheap) — noted as accepted, revisit only
if `token_fetch_total` says otherwise.

### D1.4 Redirect policy (the CDN hop)

Registry blob GETs commonly 302 to a CDN (DockerHub → Cloudflare). Policy,
matching what container clients do: follow ≤ 3 redirects **within the
fill**, and **strip `Authorization` on any cross-host hop** (the classic
token-leak bug class — pinned by the D1 security-negative below). The curl
handle in the fill path sets this explicitly rather than trusting defaults.

### D1.5 Tests (`tests/test_oci_mirror_authdance.py`, block 14100; mock in `--auth` mode)

1. *success* — cold pull does exactly one dance (`/ctl/token_count == 1`);
   N follow-up requests within TTL reuse the cached token (count still 1);
   after mock-configured `expires_in` elapses, count becomes 2. Both `token`
   and `access_token` response spellings pass.
2. *error* — token endpoint 500/timeout/garbage-JSON → client sees 502 with
   our envelope (never the upstream challenge); malformed challenge (no
   realm) → 502; `TOOMANYREQUESTS` from data plane → 429 echoed.
3. *security-negative* — (a) blob 302 to second mock host: asserts
   `Authorization` absent on the CDN leg; (b) challenge with third-party
   realm → refused, no request leaves for it, no Basic creds sent anywhere;
   (c) with `brix_oci_mirror_auth` set, assert Basic goes **only** to the
   allow-listed realm, never the data plane.

**Effort:** M. ~400 LOC + kv zone plumbing; the risky part is redirect/realm
policy, which is why both are pinned by name in the negatives.

## D2 — Cache policy: immutable-by-digest, tag revalidation, media-type fidelity

### D2.1 Object classes

| Class | Key addressed by | Mutability | Policy |
|---|---|---|---|
| Blob (`blobs/sha256:X`) | digest | immutable | cache forever; verify at fill; never revalidate |
| Manifest by digest (`manifests/sha256:X`) | digest | immutable | same as blob |
| Manifest by tag (`manifests/latest`) | name+tag | mutable | serve-while-fresh ≤ `brix_oci_manifest_ttl`; stale → conditional refetch |
| Tags list | name | mutable | never cached (D0.3) |

### D2.2 Tag revalidation flow

Fresh (age ≤ TTL) → serve from cache, zero upstream. Stale → HEAD upstream
`manifests/<tag>` with the D1 token; compare `Docker-Content-Digest` against
the cached entry's recorded digest: equal → touch freshness, serve cached
(no body transfer); different → full GET, verify body against the *response*
`Docker-Content-Digest`, store under the tag key **and** under the digest
key (one fetch warms both), serve. Upstream unreachable while stale →
serve-stale + `X-Brix-Oci-Stale: 1` + `oci_stale_serves_total` increment
(a mirror's job is availability; the TTL bounds staleness under normal
operation — decision pinned here, was v1 open question about offline mode).

### D2.3 Cache-key derivation & storage

Keys are the *canonical decoded route* under the location:
`<name>/manifests/sha256:<hex>` · `<name>/manifests/<tag>` ·
`<name>/blobs/sha256:<hex>` — after DockerHub `library/` normalization, so
key space is injective with upstream identity. Storage rides the existing
cache plane unchanged (the key is what the fill path already namespaces
per-location); no new eviction machinery — blobs age out under the
existing cache quota/reaper exactly like any cached object.

### D2.4 Metadata sidecar (media-type fidelity)

The spec requires echoing the manifest's original `Content-Type` (clients
select schema parsing off it — a mirror that rewrites it breaks pulls).
Alongside each cached manifest the fill writes a small sidecar
(staged+rename, same discipline as cache-info files):
`content_type=<verbatim>\n digest=sha256:<hex>\n fetched_at=<unix>\n
etag=<verbatim-or-empty>\n` — flat `key=value` lines, parsed with the
existing config-line helpers, **not** JSON (nothing here needs it);
byte-exact grammar and a worked example in Appendix B.1. Serves
echo: `Content-Type` (sidecar), `Docker-Content-Digest` (sidecar digest),
`Docker-Distribution-API-Version`, `Content-Length`; conditional client
requests (`If-None-Match` on the digest-as-etag) answer 304 locally.

### D2.5 Verify integration

Fill-side, both surfaces: digest-addressed objects hash-on-stream
(`BRIX_CHECKSUM_SHA256` via the `verify.h` seam — the transport advertises
the URL digest as the expected checksum) and **mismatch = discard part-file
+ 502 + guard line**, regardless of the location's `brix_cache_verify`
setting — for OCI the digest is the object's identity, not an optional
integrity nicety; policy `require` semantics are forced for this class.
Tag-manifest fetches verify against the response `Docker-Content-Digest`
when present (best-effort semantics: absent header → store unverified,
flag in sidecar).

### D2.6 Range and HEAD

HEAD on cached objects answers from sidecar/stat without upstream. Range
requests on **cached** blobs are served by the existing byte-range plane;
Range on a cache **miss** triggers a full-object fill first (fills are
whole-object — digest verification demands the whole stream), then the
range is served from cache. This matches how the cvmfs plane handles
ranged CAS reads and is called out in the ops doc (first ranged pull of a
10 GiB layer pays a full fill).

### D2.7 Tests (`tests/test_oci_mirror_cachepolicy.py`, block 14100)

1. *success* — cold pull → warm pull byte-identical, mock log shows zero
   second-pull data-plane hits; media-type round-trip pinned for all four
   §0.7.3 manifest types (Docker v2, OCI manifest, both index flavors);
   304 on If-None-Match; retag visible after TTL (mock `retag` fault →
   fresh-window serve returns old digest, post-TTL HEAD-revalidate returns
   new); digest-equal revalidation transfers no body.
2. *error* — upstream down + fresh cache → serves; upstream down + stale
   tag → serve-stale header set; upstream down + cold → 502 envelope.
3. *security-negative* — mock `corrupt` fault (body byte-flip): fill
   refused, nothing cached, 502 + `signal=oci_tamper` in guard log, retry
   after fault clears succeeds; mock `wrong_digest_header` on tag manifest:
   sidecar marks unverified, digest-addressed re-request of same bytes
   refused.

**Effort:** M. Policy/sidecar ≈ 400 LOC (`oci_mirror.c`); verify plumbing
is seam configuration.

## D3 — Mirror observability + podman oracle

### D3.1 Metrics (families follow the §8 low-cardinality invariant; all counters)

| Family | Labels | Incremented |
|---|---|---|
| `brix_oci_requests_total` | `surface`(mirror\|registry), `class`(manifest\|blob\|tags\|api\|upload), `outcome`(hit\|fill\|revalidate\|stale\|error) | every classified request |
| `brix_oci_fill_bytes_total` | `surface` | bytes landed by fills |
| `brix_oci_token_fetch_total` | `outcome`(ok\|fail) | each dance leg 2 |
| `brix_oci_verify_fail_total` | — | each digest mismatch |
| `brix_oci_upstream_errors_total` | `code`(4xx\|5xx\|timeout\|tls) | fill-path upstream failures |

No `name`, no `tag`, no digest labels — unbounded cardinality (INVARIANT
#8); per-image visibility is the access log's job. Families register through
the existing metrics plane and appear in the conformance sweep that guards
label sets (`tests/_cachemx*` conventions). Two measured caveats (App. W):
every plaintext client contact is preceded by one TLS-ClientHello garbage
request (W-2) — it must not count toward `outcome=error` or any guard
signal; and warm clients skip already-held blobs entirely (W-4), so
hit-rate reads only make sense per-blob, never per-image.

### D3.2 Guard + fail2ban

Two new `guard_reason_t` members (enum tail — `guard.h`), audit strings via
the `guard_audit.c:112` line format:

| Reason | `signal=` | Fires on |
|---|---|---|
| `GUARD_R_OCITAMPER` | `oci_tamper` | digest verify failure at fill (upstream or CDN gave us wrong bytes) |
| `GUARD_R_OCIPUSH` | `ocipush` | write-class method on a mirror location |

Co-land `deploy/fail2ban/filter.d/brix-oci.conf` + jail (phase-94's rule:
a guard signal without a shipped filter is half a feature). `oci_tamper`
default: log-only (the offender is the upstream/CDN, banning the *client*
IP would be wrong) — the filter ships commented-out with that explanation;
`ocipush` bans like `notroot_wire`.

### D3.3 Podman oracle lane (`tests/test_oci_mirror_podman_pull.py`, block 14120, live-lab)

Rootless podman via `container_runtime.py`: configure a containers-registries
mirror stanza at the fleet instance → `podman pull` a fixture image (mock
upstream, so no internet in the lane) → run `podman image inspect` and
assert digest equality with the fixture's — then repeat the pull with the
mock's kill switch thrown (`/ctl/fault http500` persistent) proving the warm
path never touches upstream. A weekly-tier variant pulls `docker.io/library/
alpine:latest` through a live-lab instance against real DockerHub (internet
+ live-lab markers, SKIP-not-FAIL).

Tests: (1) success = the two-pull flow above; (2) error = mirror down →
podman falls back per its own semantics (lane asserts our 502 envelope is
what podman saw, not a hang); (3) security-negative = `podman push` at the
mirror → denied, `signal=ocipush` present.

**Effort:** S–M. Metrics/guard ≈ 150 LOC; the lane is fleet+runtime glue.

---

# Wave B — local registry management

**Exit criterion:** `podman push` + `podman pull` round-trip against the
`brix_oci_registry` surface as an authenticated user; anonymous push denied
with spec envelope; `brixoci copy` moves an image mirror→local-registry
offline.

## D4 — Push API (upload sessions, manifest PUT, tags, DELETE)

### D4.1 Store layout (under `brix_oci_registry_root`, all I/O via VFS seam)

```
<root>/blobs/sha256/<hex[0:2]>/<hex>              # blob bodies (CAS discipline)
<root>/repos/<name>/manifests/sha256/<hex>        # manifest bodies
<root>/repos/<name>/manifests/sha256/<hex>.meta   # §D2.4-format sidecar
<root>/repos/<name>/tags/<tag>                    # one line: sha256:<hex>\n
<root>/repos/<name>/layers/<hex>                  # blob-reference marks (empty files)
<root>/_uploads/<session>/                        # staged sessions (§D4.2)
```

Blobs are stored once, globally (content addressing makes per-repo copies
pointless); `layers/<hex>` marks record which repos reference a blob so a
future GC has honest refcounts and cross-repo mount is a mark + 201. Tag
swap = staged write + `brix_commit_staged` rename (atomic retag). Name
components map to directories only *after* grammar validation (§0.7.2 —
validated names cannot traverse) and under `resolve_path()` (INVARIANT #4).

### D4.2 Upload-session state machine (`oci_upload.c` over `staged_file`)

```
POST /v2/<n>/blobs/uploads/           → 202, Location: …/uploads/<id>, Range: 0-0
   [monolithic shortcut: POST?digest=D with body → seal directly → 201]
   [cross-repo:          POST?mount=D&from=R → blob exists? mark+201 : plain 202]
PATCH …/uploads/<id>  (body chunk)    → 202, Range: 0-<end>   (repeatable)
PUT   …/uploads/<id>?digest=D [+tail] → seal: hash streamed so far+tail,
                                        compare D → match: rename into CAS, 201
                                        mismatch: destroy session, 400 DIGEST_INVALID
DELETE …/uploads/<id>                 → abort, 204
GET    …/uploads/<id>                 → 204 + Range (resume probe)
R: reaper — sessions idle > brix_oci_upload_grace reaped via brix_stage_reap_dir
```

Sessions are `brix_staged_open`-backed part-files; `<id>` = staged basename;
resume rides `brix_staged_resume`; a sha256 running context is checkpointed
beside the part-file every PATCH (small state file) so seal never re-reads
multi-GiB uploads — checkpoint bytes and the resume-truncation rule in
Appendix B.2. Out-of-order/overlapping PATCH (offset ≠ current end) →
416 + current `Range` (spec resume semantics); podman/skopeo retry from
there. Concurrent PATCH to one session: the part-file's pending-mark is the
mutex — second writer gets 409 `BLOB_UPLOAD_INVALID`.

### D4.3 Manifest PUT (`oci_manifest_put.c`)

Parse with jansson (server-side security-relevant JSON — never `json_min`):
enforce schema shape by declared media type (config+layers for manifests,
manifests[] for indexes), **verify every referenced digest exists in the
blob store** (else 400 `MANIFEST_BLOB_UNKNOWN` naming the missing digest in
`detail`), verify body digest = `<ref>` when pushed by digest, then store
body → CAS path, write sidecar (Content-Type fidelity, same §D2.4 format),
atomically swap the tag file. An index may reference manifests (not blobs) —
both existence namespaces are checked. Size cap: manifests > 4 MiB → 413
(spec guidance; real manifests are KBs).

### D4.4 DELETE semantics (v1: honest and minimal)

`DELETE manifests/sha256:X` → remove manifest + any tags pointing at it
(scan `tags/`, few entries) → 202. `DELETE manifests/<tag>` → 400 per spec
(delete by digest only). `DELETE blobs/sha256:X` → remove the repo's
`layers/` mark; the global blob is removed only when no marks remain
(refcount walk) — otherwise 202 with the blob retained. No *background* GC:
reclaiming what a delete orphans across repositories is the offline
`brixoci gc` pass (§D15.3). `brixoci rm` (D5) drives this API.

### D4.5 Authorization

Sits behind the existing write gates exactly as a dav write: location must
carry `brix_allow_write on` (INVARIANT #3 order) and identity comes from the
already-configured token/x509/VOMS plane; push additionally requires the
authenticated principal (the same principal the dav plane would log). Reads
on the registry surface are gated by whatever authn the location config
composes (public-read + authed-push is one location with method-conditional
enforcement — same pattern the dav surface already supports). 401 responses
carry a `WWW-Authenticate` challenge naming the site's own token realm when
the token plane is configured (that is what makes `podman login` work
against us). Measured client behavior at this seam (App. Y.1): the token
GET is **anonymous** unless the user ran `podman login` (no Authorization
header — the realm must tolerate anonymous requests to issue pull-scope
tokens for public content, or 401 them cleanly for private), the scope
grammar observed is `repository:<name>:pull,push`, and refresh requests
carry **repeated `scope` parameters** in one URL (Y-4) — parse all of
them, not the first.

### D4.6 Tests (`tests/test_oci_registry_push.py`, block 14140)

1. *success* — full chunked-upload push (PATCH×3 + PUT) then pull-back
   byte-identical; monolithic POST?digest shortcut; cross-repo mount answers
   201 without re-upload; resumable: kill connection mid-PATCH, GET-probe
   Range, resume, seal ok; retag is atomic under a concurrent-GET hammer
   (no reader ever sees a missing/partial tag file).
2. *error* — seal with wrong digest → 400 + session gone; PATCH to unknown
   session → 404 `BLOB_UPLOAD_UNKNOWN`; manifest referencing absent blob →
   400 naming it; over-`brix_oci_max_blob_size` PATCH → 413; out-of-order
   PATCH → 416 + honest Range; reaper kills idle session (clock injection),
   later PUT → 404.
3. *security-negative* — anonymous push with anonymous-allow unset → 401 +
   challenge, nothing staged on disk; authenticated-but-unauthorized (token
   scope lacks write) → 403 `DENIED`; traversal attempts in name/session →
   400, store tree untouched (before/after tree hash); manifest with 100 MiB
   body → 413 before jansson ever parses it.

**Effort:** L. The session machine + manifest validation + store ≈ 1.5 kLOC;
podman/skopeo as clients are unforgiving spec oracles (that is the point).

## D5 — `brixoci` CLI + local image store

### D5.1 The pull-transport slice (`client/lib/oci/` — built in Wave C, D5 finishes the rest)

`ref.c`: `[host[:port]/]name[:tag][@digest]` — host recognized by containing
`.`/`:`/`localhost` (the podman rule); neither tag nor digest → `latest`;
both → digest wins, tag advisory. IPv6-literal hosts refused in v1 with a
clear message (grammar collision with the port colon; revisit on demand).
`reg_client.c` (over `brix_http_req` / `brix_http_download` — **zero new
socket code**, the `vfs_s3_transport.c` precedent):

```c
int brix_oci_reg_manifest(brix_oci_reg_t *r, const brix_oci_ref_t *ref,
                          const char *accept,        /* §0.7.3 joined */
                          brix_oci_desc_t *out,      /* mt, digest, body */
                          char *err, size_t errlen);
int brix_oci_reg_blob_fetch(brix_oci_reg_t *r, const char *name,
                            const char *digest, int out_fd,  /* hash-on-stream,
                              digest mismatch = unlink + fail */
                            char *err, size_t errlen);
int brix_oci_reg_blob_push (brix_oci_reg_t *r, const char *name,
                            const char *digest, int in_fd, size_t len,
                            char *err, size_t errlen);   /* D4 session client */
int brix_oci_reg_manifest_put(brix_oci_reg_t *r, const brix_oci_ref_t *ref,
                            const char *mt, const void *body, size_t len,
                            char *err, size_t errlen);
```

Token dance client-side reuses the same challenge grammar (shared parse in
`shared/oci/`), token cached in-process per (host, scope). Index → platform
selection: default `linux/$(uname -m normalized: x86_64→amd64,
aarch64→arm64)`, override `--platform os/arch[/variant]`; no match →
error listing available platforms.

### D5.2 `json_min` extension (`src/core/compat/json_iter.c`)

`brix_json_get_str` deliberately refuses object/array values. Manifest
walking needs spans + iteration, added beside it (json_min itself frozen):

```c
int brix_json_get_raw(const char *json, size_t len, const char *key,
                      const char **out, size_t *outlen);  /* any value type:
                        raw span incl. delimiters; nesting-aware skip */
int brix_json_arr_next(const char *arr, size_t arrlen, size_t *cursor,
                       const char **elem, size_t *elemlen); /* 1 elem, 0 end,
                        -1 malformed; cursor=0 starts */
```

Same discipline as json_min: no allocation, byte-bounded, depth-capped
(nesting > 32 → malformed), tested against the malformed-JSON corpus.
Manifest fields needed: `schemaVersion`, `mediaType`, `config.digest`,
`layers[].{digest,mediaType,size}`, `manifests[].{digest,platform.{os,
architecture,variant}}` — all reachable with get_raw + arr_next + get_str
composition.

### D5.3 Local store: OCI image layout (the interchange format on disk)

`oci-layout` (`{"imageLayoutVersion":"1.0.0"}`) + `index.json` +
`blobs/sha256/<hex>` — the spec's directory layout, readable/writable by
skopeo and podman (`oci:` transport), which makes our store itself
oracle-testable. `layout.c` verifies every blob it reads against its path
digest (the layout's contract) and writes via temp+rename.

### D5.4 Subcommands (personality dispatch in `brixmount.c`, usage panel per `BRIX_USAGE_FOOTER` convention)

```
brixoci pull  <ref> [--to DIR] [--platform P]     # registry → layout
brixoci push  <ref> [--from DIR]                  # layout  → registry
brixoci copy  <src-ref|oci:DIR> <dst-ref|oci:DIR> # any → any, one pump
brixoci ls    [oci:DIR]                           # layout contents
brixoci tags  <host/name>                         # remote tags/list (paged)
brixoci rm    <ref>                               # remote delete via D4.4
brixoci inspect <ref> [--raw]                     # resolved manifest JSON
```

Auth: `--token-file` / `--cert`+`--key` / netrc-style `~/.config/brix/
oci-auth` (0600-enforced, same stance as `brix_oci_mirror_auth`); TLS
verify on by default, `--insecure` for lab fixtures. Exit codes follow the
brixcvmfs table (0 ok · 2 usage · 3 auth · 4 not-found · 5 verify ·
6 transport).

### D5.5 Tests (`tests/test_oci_brixoci_copy.py`, block 14140)

1. *success* — `pull` from mock → layout validates under `skopeo inspect
   oci:` (oracle, live-lab-marked leg); `copy` mock→local-registry(D4)
   offline; `push` round-trips; multi-arch `pull --platform` picks
   correctly; `tags` paginates (mock serves `n=2` pages).
2. *error* — unknown ref → exit 4 with the registry's envelope message;
   wrong platform → exit 4 listing platforms; layout with corrupt blob →
   exit 5 naming the digest.
3. *security-negative* — blob served with wrong bytes → hash-on-stream
   refuses, partial unlinked, exit 5; token endpoint at third-party realm →
   refused (same allowlist rule as D1); world-readable auth file → refused
   at startup.

**Effort:** M–L. reg_client + layout + CLI ≈ 1.6 kLOC client-side; the
D4-dependent verbs (`push`/`rm`) land with Wave B, the pull slice ships in
Wave C first.

---

# Wave C — container / folder → Stratum-0 (the headline)

**Exit criterion:** `brixcvmfs ingest image <ref>` publishes a public image
as a mountable Stratum-0 subtree; the **official cvmfs client** mounts it;
`podman run --rootfs /cvmfs/<repo>/<path> <cmd>` executes; `brixcvmfs ingest
dir ./build --prefix /sw/foo/1.2` completes in seconds on a 10k-file tree;
re-ingesting an unchanged image is a fast no-op.

## D6 — Streaming tar reader (`shared/oci/tar.{c,h}` + `tar_pax.c`)

### D6.1 API — pull-parser, fixed memory, fd-in

```c
typedef struct {
    char        path[4096];     /* pax/GNU-long resolved, NUL-terminated */
    char        linkname[4096];
    brix_tar_type_t type;       /* REG DIR SYMLINK HARDLINK CHR BLK FIFO */
    int64_t     size;  mode_t mode;  int64_t mtime;
    uid_t uid;  gid_t gid;  dev_t rdev;
    const char *xattr;  size_t xattr_len;   /* packed name\0value pairs,
                                               changeset.h wire format */
} brix_tar_entry_t;

brix_tar_t *brix_tar_open_fd(int fd, char *err, size_t errlen);
    /* sniffs magic: 1f 8b → zlib inflate; 28 b5 2f fd → zstd
       (BRIX_HAVE_ZSTD; else clean "zstd layer, rebuild with zstd" error);
       else raw tar */
int  brix_tar_next(brix_tar_t *t, brix_tar_entry_t *e); /* 1 entry, 0 EOF,
                                                           -1 malformed */
int  brix_tar_read(brix_tar_t *t, void *buf, size_t n); /* current body */
int  brix_tar_skip(brix_tar_t *t);                       /* rest of body */
void brix_tar_close(brix_tar_t *t);
```

One 512-byte header buffer + one 64 KiB body buffer + the decompressor
state; memory is flat regardless of archive size. `brix_tar_next` enforces
body-fully-consumed-or-skipped before advancing (misuse is a caller bug →
-1, not silent desync).

### D6.2 Header parsing (the §Provenance pax/GNU specs, pinned here)

ustar 512-byte block, fields at fixed offsets: `name[100]@0 · mode[8]@100 ·
uid[8]@108 · gid[8]@116 · size[12]@124 · mtime[12]@136 · chksum[8]@148 ·
typeflag@156 · linkname[100]@157 · magic[6]@257 ("ustar\0", accept old-GNU
"ustar ") · uname[32]@265 · gname[32]@297 · devmajor[8]@329 ·
devminor[8]@337 · prefix[155]@345`. Numbers: NUL/space-terminated octal
ASCII; **base-256** (first byte high-bit set) accepted for size/uid/gid/
mtime (GNU large-file convention). Checksum verified (unsigned sum, chksum
field as 8 spaces; tolerate the historical signed-sum variant). Typeflags:
`0`/NUL regular · `1` hardlink · `2` symlink · `3` char · `4` block · `5`
dir · `6` fifo · `7` treated as regular · `x` pax-next · `g` pax-global ·
`L` GNU longname · `K` GNU longlink; unknown typeflag → skip body, emit
nothing, count it (podman's writers emit nothing exotic, but truncating a
stream over an unknown flag would be wrong). End = two zero blocks (accept
single-zero-block+EOF, seen from sloppy writers). name/prefix join with
`/` when prefix non-empty.

### D6.3 pax records (`tar_pax.c`)

Body of `x`/`g` entries: repeated `"<len> <key>=<value>\n"` where len is the
decimal byte length **of the whole record including itself** — parsed
byte-exactly, malformed length → -1. Keys honored: `path`, `linkpath`,
`size`, `mtime` (fractional part truncated), `uid`, `gid`,
`SCHILY.xattr.<name>` (packed into `e->xattr` in the changeset wire format —
this is how layer xattrs reach the publish plane); others skipped. pax
overrides ustar fields for the *next* entry; globals apply to all subsequent
(kept in a single overlay struct, per-file wins). GNU `L`/`K` bodies
likewise override name/linkname for the next entry. Bounds: resolved path >
4095 B → -1 (PATH_MAX discipline, not truncation); xattr accumulation capped
at 64 KiB per entry (matches changeset.c's cap).

### D6.4 Tests (`tests/test_oci_tar_corpus.py` — pure C-unit + pytest driver, no fleet)

1. *success* — corpus round-trip: archives written by GNU tar, bsdtar and a
   podman-built layer (checked into `tests/oci/fixtures/tar/`), each with
   long names (>100), long links, pax xattrs, base-256 sizes, hardlink
   groups, all typeflags; gzip and (gated) zstd compression; parsed entry
   stream compared field-by-field against a JSON manifest of expected
   entries generated at fixture-build time.
2. *error* — truncated header, truncated body, bad checksum, malformed pax
   length, size overflow (`> INT64_MAX` base-256), zstd layer without
   BRIX_HAVE_ZSTD → each a clean -1 with a message, never a crash (ASan
   lane) or an infinite loop (alarm-guarded).
3. *security-negative* — the malformed corpus fuzz-seeded: negative sizes,
   header claiming 8 EiB, pax `size` contradicting header, 10⁶ zero-length
   pax records (CPU bomb → bounded by record-count cap 64k/entry),
   decompression bomb (1 GiB of zeros gzipped to 1 MiB → reader is
   streaming, flat memory; the *flattener* enforces total-bytes budget,
   §D7.4).

**Effort:** M. ~800 LOC of very careful code; the corpus is half the work
and most of the value.

## D7 — Layer flattener (`shared/oci/flatten.{c,h}`): OCI whiteouts → overlay grammar

### D7.1 Translation table (OCI image-spec layer semantics → our upper tree)

| Tar entry in layer N | Action in upper tree |
|---|---|
| regular file `a/b` | write `upper/a/b` (temp+rename), mode/mtime applied |
| dir `a/` | mkdir -p, apply mode; **merge** with existing (later layers win metadata) |
| symlink / hardlink | recreate (hardlinks resolved *within the layer* via target path recorded in-tree; cross-layer hardlink → copy, counted + warned) |
| `a/.wh.foo` | remove `upper/a/foo` (recursive if dir) **and** drop `BRIX_OV_WH_PREFIX`-spelled marker `upper/a/.brix.wh.foo` — visible to `cvmfs_changeset_scan` as a DELETE against the published base on re-ingest |
| `a/.wh..wh..opq` | clear `upper/a/` contents, drop `BRIX_OV_OPQ_NAME` marker (opaque: earlier-layer contents dead) |
| device / fifo | **skipped + counted** (CVMFS namespace serves files/dirs/links; a rootfs's `/dev` nodes are runtime-provided anyway); count reported, `--strict` makes it fatal |
| entry whose *own name* starts `.brix.` | **refused** — a layer must not smuggle our marker grammar (`brix_ov_name_reserved()`, overlay.h:60, is the oracle) |
| setuid/setgid bits | preserved in mode (publish carries mode; mount-side policy decides honor) |

Layers apply in manifest order (base first); within a layer, entries in
archive order (the spec's contract). uid/gid recorded as-is into the
changeset (publish stores them; FUSE presents per its config) — ingest does
not chown-normalize in v1 (`--squash-owner uid:gid` is the escape hatch,
applied at flatten time).

### D7.2 API

```c
typedef struct {
    const char *upper_dir;          /* exists, empty or being accumulated */
    int64_t     max_total_bytes;    /* 0 = unlimited; bomb budget */
    int64_t     max_entries;        /* default 1M */
    int         strict;             /* devices/fifos fatal instead of counted */
    uid_t squash_uid; gid_t squash_gid; int squash;   /* --squash-owner */
} brix_flatten_opts_t;

typedef struct { int64_t files, dirs, links, whiteouts, opaques,
                 skipped_special, bytes; } brix_flatten_stats_t;

int brix_flatten_layer(const brix_flatten_opts_t *o, int layer_fd,
                       brix_flatten_stats_t *st, char *err, size_t errlen);
```

### D7.3 Containment (the security core)

Same discipline as `changeset.c`'s scan, in reverse direction: every write
descends from an `open(upper_dir, O_DIRECTORY)` dirfd with **per-component
`openat(…, O_NOFOLLOW)`** — never a joined-string path — so a layer that
plants `a → /etc` as a symlink in layer 1 and ships `a/passwd` in layer 2
hits ELOOP at the component, not `/etc/passwd`. Path components `.`/`..`
refused at parse (before any syscall). Hardlink targets resolved through
the same descent. This is the portable equivalent of `RESOLVE_BENEATH`
(the phase-8 openat2 confinement precedent) chosen because it matches
changeset.c's mechanism exactly and works on every kernel the tools target.

### D7.4 Tests (`tests/test_oci_flatten.py`)

1. *success* — 3-layer fixture (adds, file overwrite, `.wh.` delete, opaque
   dir, symlinks, hardlink group, pax xattrs): flattened tree
   compared entry-for-entry (type, mode, content hash, xattrs) against the
   fixture's expected-tree JSON; podman-exported rootfs of the same image
   diffs clean (oracle leg, live-lab).
2. *error* — layer with cross-layer hardlink → copies + warns (count in
   stats); device node under `--strict` → fatal naming the entry; budget
   exceeded (`max_total_bytes`) → clean abort, partial upper removed.
3. *security-negative* — the escape corpus: symlink-then-descend (above),
   `..` in name and in pax `path` override, absolute pax `path`, whiteout
   naming `../sibling`, layer entry named `.brix.wh.x` (grammar smuggling),
   1M-entry bomb → each refused/bounded, upper tree provably confined
   (before/after find-walk fingerprint outside `upper/` unchanged).

**Effort:** M. ~500 LOC; the negatives corpus is the deliverable.

## D8 — `brixcvmfs ingest image <ref>` (pull → flatten → publish, incrementally)

### D8.1 CLI

```
brixcvmfs ingest image <ref> --repo <repo_dir> [--prefix /images]
        [--platform os/arch] [--tag-path <name:tag-dir>] [--squash-owner U:G]
        [--strict] [--keys-dir D] [--chunk-size N] [--verify-diffids]
        [--dry-run]
```

### D8.2 Published namespace (the DUCC-compatible flat layout)

```
<prefix>/.images/sha256/<manifest-hex>/          # content root: the rootfs
<prefix>/.images/sha256/<manifest-hex>/.config.json   # image config, verbatim
<prefix>/.images/sha256/<manifest-hex>/.manifest.json # manifest, verbatim
<prefix>/<host>/<name>:<tag>  →  relative symlink → ../.images/sha256/<hex>
```

Digest-addressed roots are immutable; the human path is one symlink — so a
**retag is a one-symlink publish** (milliseconds), and two tags of one
image share one tree. `podman run --rootfs /cvmfs/<repo><prefix>/<host>/
<name>:<tag> …` is the deployment story; the config/manifest sidecars let
tooling recover entrypoint/env without a registry round-trip.

### D8.3 Pipeline (numbered; each step's failure mode → exit code)

```
1 resolve   ref → manifest (reg_client, D5.1); index → --platform select   [4/6]
2 memo      manifest digest == <repo>/.brix-ingest/memo/<flat-path>?       → no-op, exit 0
3 fetch     layers → CAS-side scratch, hash-on-stream (digest = identity)  [5]
4 flatten   layers in order into a scratch upper tree (D7)                 [5/2]
5 graft     upper moved under scratch/<prefix>/.images/sha256/<hex>/ +
            sidecars + tag symlink staged                                  [—]
5b verify   --verify-diffids: the diff_ids captured in step 4 (the reader
            hashes what it decompresses) vs the config's rootfs.diff_ids  [5]
6 scan      cvmfs_changeset_scan(scratch_upper) → changeset                [5]
7 publish   cvmfs_publish_run() — chunking, dirtab, reflog, sign, swap     [5]
8 memo-write staged+rename of the memo line: "<flat-path> <manifest-digest>
            <revision> <utc>"                                              [—]
```

Steps 1–5 never touch the repo; a crash pre-publish leaves scratch only
(reaped on next run). Step 7 inherits publish's own crash-safety
(`$BRIXCVMFS_PUBLISH_CRASH` exercises ingest's re-runnability for free).
Cost model, corrected by measurement (Z-2): the memo (step 2) is what
skips steps 3–6, but step 7 is *already* cheap for near-identical
content — CAS idempotent puts made republishing an alpine-±2-files
rootfs 0.75 s against 2.04 s cold (App. Z.1) with no memo involved. The
memo's value is skipping fetch+flatten+scan, not the store.
Re-ingest of a moved tag (same name, new digest): new content root +
symlink swap + **whiteout-driven removal is unnecessary** — old root stays
until `ingest prune` (below) or repo GC policy removes unreferenced
`.images/` roots; `--prune-old` does it in the same transaction (emits
`.brix.wh.` markers for the orphaned root so the changeset carries the
DELETEs). Concurrency: publish's existing transaction lock serializes
concurrent ingests (second waits or `--no-wait` → exit 7).

`brixcvmfs ingest prune --repo D [--keep N]` — companion verb listing/
removing `.images/` roots no tag symlink references (memo-file driven,
publish-transactional).

### D8.4 Tests (`tests/test_cvmfs_ingest_image.py`, srv 13620)

1. *success* — mock-registry fixture image → ingest → in-tree client FUSE
   mount: tree matches fixture expectation; retag ingest publishes 1-symlink
   revision (revision delta's changeset length pinned); unchanged re-ingest
   = memo no-op (zero registry data-plane hits beyond the manifest HEAD);
   `--dry-run` prints the plan, repo untouched.
2. *error* — registry down mid-layer-fetch → exit 6, repo revision
   unchanged, scratch reaped on rerun; `BRIXCVMFS_PUBLISH_CRASH` during
   step 7 → repo intact at old revision, rerun completes (the phase-96
   crash-lane pattern verbatim).
3. *security-negative* — layer corrupted between manifest and fetch (mock
   `corrupt`) → exit 5, nothing published; hostile layer from the D7 escape
   corpus → refused, scratch confined; image whose flattened tree collides
   with an existing *foreign* path under `--prefix` (not its own `.images/`
   root) → refused without `--force-overlap`; and, for D8.e, a mock image
   whose config pairs its two `diff_ids` the wrong way round — every
   compressed blob digest still verifies, so `--verify-diffids` is the only
   thing that sees it (`test_diffid_mismatch_refuses_and_publishes_nothing`,
   with `test_diffid_count_disagreement_refused` for a config that names
   fewer diff_ids than the manifest has layers, and
   `test_verify_diffids_accepts_an_honest_config` for the success leg).

**Effort:** M — the conductor is glue over D5.1+D6+D7+phase-96 (~450 LOC);
the value concentration of the whole phase.

## D9 — `brixcvmfs ingest dir <folder> --prefix P` (folder → Tier-0 in seconds)

### D9.1 Semantics

```
brixcvmfs ingest dir <src_dir> --repo <repo_dir> --prefix /sw/foo/1.2
        [--delete] [--follow-symlinks=no] [--dry-run]
```

The trivial-by-design path: treat `<src_dir>` as if it were the upper tree
for subtree `<prefix>` and publish it. Implementation: scan `<src_dir>`
with `cvmfs_changeset_scan()` (unchanged — it already handles the grammar,
containment, hardlink groups, xattrs), then **prefix-remap** every
changeset path (`p → <prefix>/p`), prepending ADD_DIR entries for absent
prefix ancestors. `--delete` makes the subtree mirror-exact: pre-pass
drops a `BRIX_OV_OPQ_NAME` marker at the prefix root in a scratch overlay
so published content absent from `<src_dir>` is removed (without it,
ingest is add/overwrite-only — the safe default). Publish cost = touched
subtree only (phase-96 S5/S6 scaling), which is what makes "seconds" true
for a 10k-file tree on a warm repo.

The prefix-remap is one new small helper on the changeset
(`cvmfs_changeset_reprefix(cs, prefix, err, errlen)` in `changeset.c`'s
TU — path rewrite + ancestor synthesis, ~80 LOC) rather than scan-time
plumbing; `ingest image` step 6 uses the same helper (its scratch tree is
rooted at `/`).

### D9.2 Tests (`tests/test_cvmfs_ingest_dir.py`, srv 13620)

1. *success* — 10k-file generated tree ingested; FUSE mount matches;
   second ingest after touching 3 files publishes a 3-file changeset
   (length pinned); wall-clock budget assertion: warm re-ingest of the 3-file
   delta < 5 s on the CI floor (generous; locally it is sub-second —
   the "seconds" claim, made falsifiable); `--delete` removes a file
   dropped from src; `--dry-run` prints and does nothing.
2. *error* — src dir vanishes mid-scan → clean error, repo untouched;
   `--prefix` colliding with an existing file (not dir) → refused naming it.
3. *security-negative* — src tree containing `.brix.wh.` spelled names →
   refused (reserved grammar, overlay.h classifier); symlink in src
   pointing outside → stored as symlink verbatim (never followed —
   `--follow-symlinks=no` default pinned); `--prefix ../escape` → refused
   at parse.

**Effort:** **S** — the reprefix helper + CLI branch + lanes. The biggest
demo-value-per-line item in the phase.

## D10 — Runtime + official-client oracle (`tests/test_cvmfs_ingest_oracle.py`, srv 13640, live-lab)

Compose: mock registry → `ingest image` → nginx Stratum-0 instance →
**official cvmfs client** mounts (phase-96 S9 harness pattern) → assertions:
(1) *success* — mounted tree diff-walks clean against podman's own export
of the same image (type/mode/content-hash/symlink-target per entry; mtime
excluded, uid/gid compared only under `--squash-owner`), then
`podman run --rootfs <mountpoint> /bin/echo ok` exits 0; (2) *error* —
Stratum-0 instance down → mount fails per client semantics, no wedge
(the orphaned-FUSE-mount trap from the fleet gotcha list is the thing this
leg guards); (3) *security-negative* — tamper a CAS object under the
served repo (the S9 tamper-leg pattern) → client refuses the object,
`signal=cvmfs_tamper` on the serve side.

The whole composition has already run once by hand (App. Z) — this lane
automates that recipe. Two rootless pre-flights it must pin, both
learned the hard way there (Z-4, both symptoms a misleading `ENOENT`):
the mount needs `-o allow_other` (+ `user_allow_other` in
`/etc/fuse.conf`) or podman's userns cannot enter it, and a mount
created after any podman activity is invisible to the pause process's
mount namespace until `podman system migrate`.

**Effort:** S–M — harness glue; every C line it exercises landed in D6–D9.

---

# Wave D — the RPM plane

**Exit criterion:** a containerized dnf installs (a) through the mirror from
a fixture repo and (b) from a `brixrpm createrepo`-generated repo served
off CVMFS.

## D11 — RPM/dnf pull-through mirror (config + policy; superseded by §D15.9)

> **Read §D15.9 first.** The recipe below shipped and still works — it is what
> a site puts in front of *stock* nginx — but the default answer for this
> server is now the `brix_rpm_mirror` module, which verifies the digest a
> repodata filename carries, refuses writes at the gate and names the route it
> took. The estimate in this section's title is DRIFT 37.


An RPM repo is static HTTP: `repodata/repomd.xml` (mutable, the freshness
root) → digest-named `repodata/<sha256>-primary.xml.gz` etc. (immutable —
the filename carries its checksum) → `Packages/*.rpm` (immutable in
practice; verified by dnf against repomd's chain + GPG client-side).
Mirror = the existing HTTP fill path + one policy: **short TTL on
`repomd.xml`** (and `repomd.xml.asc`/`.key`), cache-forever on everything
else. This split is client-mandated, not invented here: dnf sends
`Cache-Control: no-cache` on its `repomd.xml` fetch (measured, X.3 —
finding X-2), and it is the same mutable-name/immutable-digest rule as
OCI tags vs blobs (D2), so one cache-policy kernel serves both planes.
Delivered as a documented recipe (existing cache directives; a
location-scoped TTL on the repomd names): the fallback
`brix_cache_default_ttl <time> <pattern>` mini-directive was **not**
needed and was not built — two `location ~` blocks with `proxy_cache_valid`
express the split exactly (rpm-mirror.md §"Cache policy"), so the plane
adds no directive to the conf grammar at all. Recipe lands in
`deploy/rpm-mirror/nginx.conf.example` + `docs/05-operations/rpm-mirror.md`
(incl. client `.repo` stanza with `baseurl=` pointing at the mirror).

Tests (`tests/test_rpm_mirror_dnf.py`, block 14160; dnf container via
`container_runtime.py`, live-lab): (1) install through mirror from a
fixture repo (mock upstream), second install with upstream killed succeeds
from cache; (2) upstream down + expired repomd → dnf sees the error, not a
hang; stale-metadata window behaves per TTL (update repo upstream, mirror
serves old list until TTL, then new); (3) fixture repo re-signed with a
wrong GPG key → **dnf** refuses (proving the mirror preserved bytes
end-to-end enough for client-side verification to work — the mirror never
weakens the trust chain).

**Effort:** S. Config, docs, three lanes.

## D12 — `brixrpm createrepo` (clean-room header parser + repodata emission)

### D12.1 CLI

```
brixrpm createrepo <dir> [--update] [--baseurl-relative] [--compress gz]
brixrpm inspect <pkg.rpm> [--json]      # debug/verify aid, prints NEVRA+deps
```

### D12.2 RPM reader (`shared/rpm/rpmhdr.{c,h}` — rpm.org file format, read-only, no payload decode)

File = **lead** (96 B: magic `ed ab ee db`, versions, type, name[66],
signature_type must be 5) → **signature header** (skipped: parsed only for
its length; padded to 8) → **main header** → payload (never read; the
package sha256 `pkgid` hashes the *whole file*, streamed). Header section:
magic `8e ad e8` + version 01 + reserved(4) + `il`(4 BE) + `dl`(4 BE), then
`il` × 16-byte index entries `{tag(4) type(4) offset(4) count(4)}` +
`dl` bytes of data. Types: 0 NULL · 2 INT8 · 3 INT16 · 4 INT32 · 5 INT64 ·
6 STRING · 7 BIN · 8 STRING_ARRAY · 9 I18NSTRING. Bounds: every
offset/count validated against `dl` before dereference; `il ≤ 4096`,
`dl ≤ 64 MiB` caps; STRING reads NUL-bounded within the region.

Tags consumed (the primary.xml working set):

| Tag | # | Tag | # |
|---|---|---|---|
| NAME | 1000 | PROVIDENAME | 1047 |
| VERSION | 1001 | PROVIDEFLAGS | 1112 |
| RELEASE | 1002 | PROVIDEVERSION | 1113 |
| EPOCH | 1003 | REQUIRENAME | 1049 |
| SUMMARY | 1004 | REQUIREFLAGS | 1048 |
| DESCRIPTION | 1005 | REQUIREVERSION | 1050 |
| BUILDTIME | 1006 | CONFLICTS n/f/v | 1054/1053/1055 |
| SIZE | 1009 | OBSOLETES n/f/v | 1090/1114/1115 |
| LICENSE | 1014 | DIRINDEXES | 1116 |
| GROUP | 1016 | BASENAMES | 1117 |
| URL | 1020 | DIRNAMES | 1118 |
| ARCH | 1022 | FILEMODES | 1030 |
| SOURCERPM | 1044 | PAYLOADFORMAT/COMPRESSOR | 1124/1125 |

Dependency sense flags (REQUIREFLAGS bits): `LESS 0x02 · GREATER 0x04 ·
EQUAL 0x08`; rpmlib() internal deps (flag `0x1000000`) filtered from
primary.xml (createrepo_c behavior). File list = DIRNAMES[DIRINDEXES[i]] +
BASENAMES[i]; primary.xml carries only the dnf-relevant subset (paths under
`/etc`, `bin/`, and dirs), filelists.xml carries all — matching observed
createrepo_c output so dnf's two-stage resolution behaves identically.

### D12.3 repodata emission (`shared/rpm/repomd_write.c`)

Emits `primary.xml.gz`, `filelists.xml.gz`, `other.xml.gz` (changelogs:
emitted empty-per-package in v1 — dnf tolerates; flag `--changelogs` reads
tags 1080/81/82 if wanted), then `repomd.xml`: per-data `type=`,
`<checksum type="sha256">` (compressed) + `<open-checksum>` (uncompressed),
`<location href="repodata/<sha256>-primary.xml.gz"/>` (checksum-named files,
createrepo_c convention → immutable-by-name, which is exactly what makes
D11's TTL split correct), `<timestamp>`, `<size>/<open-size>`, `<revision>`.
Namespaces: `http://linux.duke.edu/metadata/{repo,common,rpm,filelists,
other}`. XML writing is a ~80-line escaper+printf helper (attr/text
escaping of `&<>"'`), not a library. All files staged+renamed;
`repomd.xml` renamed **last** (readers follow the same swap discipline as
`.cvmfspublished`). `--update` keeps entries whose `(size, mtime, sha256)`
match the previous run's record (a `.brixrpm-cache` line file beside
repodata) so re-runs scan only changed packages. The whole emission
contract is **proven consumable**: Appendix X's clean-room Python
generator implements exactly this spec and a stock EL9 dnf depsolved and
installed from its output first try (X-1) — the C port's oracle is
byte-parity with that generator plus the X.2 install.

### D12.4 Tests (`tests/test_rpm_createrepo.py`, block 14180)

1. *success* — fixture dir of small real RPMs (noarch + arch, epoch and
   epoch-less, ≥1 with rich file list) → createrepo → **dnf in container
   installs from it over plain nginx serving** (the oracle); `inspect
   --json` NEVRA/provides/requires matches `rpm -qp` output for the corpus
   (oracle leg, live-lab); `--update` rescans only the touched package
   (probe: mtime-bump one, assert one parse via stats line).
2. *error* — truncated header, `il/dl` bounds violations, non-RPM file in
   dir → skipped-with-warning vs fatal per `--strict`; empty dir → valid
   empty repo (dnf sees "no packages", not an error).
3. *security-negative* — fuzzed header corpus (offsets past `dl`, type
   confusion INT32-tag-as-STRING, count overflow `count*size` wrap,
   `il=0xffffffff`) → clean refusal, ASan-silent; a package whose
   BASENAMES/DIRINDEXES imply `../` paths → path entries sanitized out of
   the XML + warning (metadata may not traverse either).

**Effort:** M–L. The parser is fiddly-but-finite (~500 LOC + 450 XML);
dnf-as-oracle keeps us honest byte-for-byte.

## D13 — RPM repo → CVMFS (runbook, no new code)

`brixrpm createrepo /srv/repo` → `brixcvmfs ingest dir /srv/repo --prefix
/rpm/<name>` → clients: `baseurl=file:///cvmfs/<repo>/rpm/<name>` (or the
Stratum-0's HTTP URL directly). Runbook in
`docs/05-operations/rpm-on-cvmfs.md`: ordering (createrepo before ingest so
repomd lands atomically *within* the publish), update cadence, GC
interaction, GPG signing note (site signs `repomd.xml` with its own key —
detached `.asc` is just a file, ingest carries it).
Test (`tests/test_rpm_cvmfs_compose.py`, srv 13620 + block 14180):
(1) end-to-end dnf install from the FUSE-mounted repo; (2) republish with
one package added → dnf sees it post-remount, old snapshot revision still
consistent (tag pinning — the CVMFS time-machine as repo snapshotting,
called out in the runbook as the actual killer feature); (3) tampered
`.rpm` inside the published tree → dnf's GPG/checksum chain refuses.

**Effort:** S — docs + one composed lane.

---

# Wave E — deployment composition + deferred tail

## D14 — Composition recipes (config + docs + one lane; ~zero new C)

The pieces compose because everything landed on existing planes; D14 makes
the compositions *pinned* instead of theoretical:

- **Private images:** scvmfs preamble (S14 directives) on the Stratum-0
  location → token/x509-gated image trees; `.images/` roots for private
  refs live under a distinct prefix so authorization maps to path prefix
  (the grammar the scvmfs plane already enforces).
- **Union serving:** `brix_cvmfs_virtual_repo` (G16, `virtual.c` — 404
  advances members, 401/403/5xx terminal) unions a site's ingested-images
  repo behind its main software repo under one client-visible name; the
  honest limit (member[0]'s namespace on FUSE) restated for images.
- **Re-export:** ingested trees are ordinary published content — the same
  export serves over WebDAV/xroot/S3 read planes where configured; recipe
  shows a read-only WebDAV view of `/sw` for non-CVMFS consumers.
- **Mirror + registry on one host:** `/v2/` mirror location + `/local/v2/`
  registry location + Stratum-0 location in one server block — the
  full-stack single-box story (`deploy/oci-mirror/full-stack.conf.example`).

Lane `tests/test_oci_compose_secure.py` (block 14200): (1) authorized pull
of a private ingested image over scvmfs succeeds; (2) same path anonymous →
401/403 (the S14 matrix applied to an image tree); (3) virtual union serves
image repo behind main repo; wrong-token 403 remains terminal (no
fall-through leak — the G16 security property re-pinned on this
composition).

**Effort:** S.

## D15.1 — Referrers API (delivered; was the first D15 row)

**Goal.** A client holding an image digest can ask what anybody said *about*
that image — a signature, an SBOM, a provenance attestation — without
enumerating the repository.

**Design.** A referrer is an ordinary manifest carrying a `subject`
descriptor; the registry's whole contribution is to make the reverse
direction answerable. The edge is recorded by the **push that creates it**,
because that is the only moment the registry sees referrer and subject
together:

- `src/protocols/oci/oci_referrers.c` (+ `.h`, jansson-including, the
  per-feature internal-header precedent of `oci_upload_internal.h`).
- **Store** (App. B.3): `repos/<name>/referrers/sha256/<subject>/<referrer>`
  holds the *descriptor* JSON — `mediaType`, `digest`, `size`,
  `artifactType`, bounded `annotations` — and
  `repos/<name>/manifests/sha256/<referrer>.subject` holds the subject hex.
  Both names are 64-hex by the §0.7.2 grammar, so neither can spell a path
  component of its own; the traversal defense is the classifier's, once.
- **Commit order** (`oci_manifest_put.c`): blob-existence walk → CAS write →
  `.meta` sidecar → **referrers index** → tag swap. Once a name resolves to
  the manifest, everything the spec says about it is already true.
  `subject` is deliberately *exempt* from the existence walk — a signature
  may legitimately describe an image this registry never held — but it is
  shape-checked: a subject we cannot read is a 400, because storing it would
  publish an artifact whose edge nothing can follow, and to the pusher that
  is indistinguishable from a signature that was recorded.
- **`OCI-Subject`** on the PUT response is how a signing tool learns the API
  is live here; its absence sends cosign down the tag-schema fallback, so the
  header is part of the handshake, not decoration.
- **Read** (`GET|HEAD /v2/<name>/referrers/<digest>`): an image index
  assembled from the subject directory, bounded at 512 entries / 256 KiB.
  An unknown subject is **200 with an empty `manifests`** — never 404, which
  would be the different claim that the route or repository is unknown, and
  would make a verifier retry rather than conclude.
- **`?artifactType=`** filters, and a filtered answer sets
  `OCI-Filters-Applied: artifactType`. Without that header a client cannot
  tell "no signatures of this type" from "this registry ignored your filter"
  — and reads the second as the first, which is a verification silently
  skipped. `artifactType` falls back to `config.mediaType` per the image
  spec, which is what makes a cosign signature filterable at all.
- **Mirror side** (D0): the route joins `tags/list` on the uncached
  passthrough (`brix_oci_listing_passthrough`, née `..._tags_passthrough`).
  A cached referrers answer would hide the signature the client came to
  verify.
- **Metrics**: its own fixed `class="referrers"` enum value (INVARIANT #8),
  taking the family to 2 × 7 × 5 = 70 series.
- **Deletion**: a manifest DELETE cuts its own edge via the back-pointer.
  Deleting the *subject* leaves its referrers standing — a signature over an
  image this registry no longer holds is still a valid signature, and
  dropping it would destroy evidence the pusher owns.
- **Per-repository by construction.** Cross-repository visibility would let
  anyone who can push to a scratch repository fabricate the appearance of a
  signature over somebody else's image, since a subject is a bare digest
  with no owner attached.

**Tests:** `tests/test_oci_registry_referrers.py` (front at 14154) —
success, the fallback, the filter and its header, the empty graph, both
deletion directions, tenant isolation, the read-only refusal, the digest
grammar and the traversal spellings — plus two mirror-side rows in
`tests/test_oci_mirror_classify.py` over a new mock referrers route.

**Effort:** S (delivered).

## D15.2 — IPv6-literal registry hosts in refs (delivered)

**Goal.** `brixoci pull [::1]:5000/lab/app:v1` works, and means the host the
brackets say it means.

**Design.** The deferral had called this a "grammar collision", and the
collision is real: a reference is `[host[:port]/]name[:tag][@digest]`, so the
colons of an IPv6 literal sit in the same span as the port separator and the
tag separator. What made it cheap is that the collision was already solved
once — `shared/oci/url.c` parses exactly this authority for
`brix_oci_mirror <base-url>` and for the security-critical `realm=` of a
WWW-Authenticate challenge. The work was to *share* that grammar, not to
write a second one:

- `brix_oci_url_authority()` (public in `shared/oci/url.h`) parses a bare
  `host[:port]` or `[v6-literal][:port]` span in its entirety — refusing a
  userinfo, a byte no host may carry, a port outside 1..65535, or anything
  trailing the port. `client/lib/oci/ref.c` calls it instead of hand-rolling
  the split, so a host this CLI will dial is exactly a host the proxy would
  have accepted in a base URL.
- It lives in its own TU, `shared/oci/authority.c`, for a build reason worth
  recording: `ar` keys archive members by **basename**, and
  `client/lib/net/url.c` already owns `url.o` inside `libbrix.a` — adding
  `shared/oci/url.c` to `LIB_SRCS` would have silently replaced one with the
  other. The one byte-copy the two halves share sits in a header-local
  `static inline` (`shared/oci/url_internal.h`).
- **One canonical spelling.** The literal is written bracketed on the wire
  and stored UNBRACKETED in `brix_oci_ref_t.host`, which is the form
  `brix_oci_url_t` already carries — so the two are comparable without a
  normalising step, and the transport re-brackets on emit
  (`brix_format_host_port`).

**Tests:** `tests/test_oci_brixoci_copy.py` (25 tests; the D15.2 front is a
sixth mock at 14145, bound on `::1`, so a pull exercises a real AF_INET6
dial and a bracketed `Host:` header rather than only the parser) — the pull
and tags success legs, a six-case malformed-literal refusal
(`[::1zz]`, unterminated, empty brackets, port 0, port 70000, host with no
repository), and a four-case authority-confusion negative (`user@[::1]:5000`,
`[::1]evil.example:5000`, `[::1]:5000@evil.example`, `[::1/lab]:5000`).

**Effort:** S (delivered).

## D15.3 — Registry-side GC (delivered as `brixoci gc`)

**Goal.** Reclaim what a `DELETE` deliberately leaves behind, without ever
being the thing that loses an image.

**Design.** The deferral said "explicit `rm`/`prune` + refcount marks are
enough at site scale", and the second half of that turned out to be the
mistake: the marks are per-repository bookkeeping written at **upload seal**,
so they cannot answer the only question that matters — is any *other*
repository still holding this blob? A request handler cannot answer it
either; it sees one repository. So the pass is a tool, exactly as upstream
distribution's `registry garbage-collect` is a command and not a timer:

```console
$ brixoci gc <store-dir> [--grace SECS] [--dry-run] [--json]
```

- **Mark from manifest bodies, never from the marks.** `shared/oci/
  gc_mark.c` walks `repos/**` (a repository name carries `/`, so the
  walk recurses and a directory may be a repository *and* the parent of
  others), reads every `manifests/<alg>/<hex>` body under every registered
  algorithm, and marks its
  `config`, `layers[]`, `manifests[]` and `subject` digests. The whole walk
  completes before any sweep runs: a blob judged against a half-built live
  set is a blob deleted because the pass had not yet reached the repository
  that names it.
- **Three sweeps**: unreferenced CAS blobs; `layers/<hex>` marks no manifest
  in that repository justifies any more (what a manifest DELETE leaves); and
  referrer descriptors whose referrer manifest is gone — which closes the
  hole §D15.1 names explicitly, where a descriptor is written but its
  `.subject` back-pointer is not.
- **No manifest and no tag is ever swept.** Untagged is not garbage here:
  every signature and SBOM is an untagged manifest, so a
  reachability-from-tags sweep would delete exactly the evidence a verifier
  came for. `--delete-untagged` is not offered.
- **`--grace` (default 3600 s)** covers the window between a blob sealing
  and the manifest that names it arriving — the state every push passes
  through. The runbook's answer for a store under continuous push is
  `brix_allow_write off` + reload, which turns the race into a short
  read-only interval rather than a probability.
- **Containment.** Nothing is unlinked whose name has not re-parsed as a
  digest under the shared grammar, every stat is an `lstat` (a symlinked
  fan-out or repository cannot walk the pass out of the store),
  and a root that does not hold both `blobs/` and `repos/` is refused
  — `brixoci gc /` is a plausible typo, not a plausible instruction. A
  repository directory that cannot be *read* is fatal, not skipped: a sweep
  against a live set that could not be finished is the one failure mode that
  destroys data.

**Tests:** `tests/test_oci_registry_gc.py` (14 tests, front at 14155) —
every case pushes through the real registry, so the store swept is one the
registry built: the shared-layer case a handler cannot decide, the surviving
image still servable afterwards, stale marks, untagged manifests surviving,
the dangling descriptor, both grace directions, `--dry-run` agreeing with
the real pass, the two refusals, and the two symlink negatives.

**Effort:** S (delivered).

## D15.4 — sha512 digests, end to end (DELIVERED)

`sha256` and `sha512` are the two algorithms the OCI distribution grammar
registers, and a mirror that only ever meets one of them cannot say which of
its many "sha256" spellings were *decisions* and which were assumptions. They
were assumptions almost everywhere: the parser §0.0 called algorithm-agnostic
handed back an algorithm nobody downstream read.

**The store needed no migration.** Its layout already carried the algorithm —
`blobs/<alg>/<xx>/<hex>`, `repos/<n>/manifests/<alg>/<hex>`,
`repos/<n>/referrers/<alg>/<subject>/<referrer>` — because it was written
that way in §D4.3 and then only ever filled with the literal `sha256`. The
change is that the directory component is now `brix_oci_alg_name(d->alg)`,
which is the same string for every store that exists today.

**The width names the algorithm.** No two registered algorithms share a hex
width (64 vs 128), so anything holding a *bare* hex — the `layers/<hex>`
upload marks, the GC live set, the ingest roots ledger — stays flat and
recovers the algorithm by re-parsing. That rule is `brix_oci_digest_parse_hex()`
in `shared/oci/digest.c`, written once rather than open-coded in the two
tools that need it, and `BRIX_OCI_ALG_COUNT` is pinned to the algorithm table
by a `_Static_assert` so a third algorithm cannot be added to one and not the
other.

**Where it landed:**

- **Kernel** — `BRIX_CHECKSUM_SHA512` / `BRIX_CK_SHA512` **appended** to the
  two enumerations (never inserted: `brix_checksum_digest_fd` passes the
  ordinal straight through, so the two must stay index-identical) + the
  `EVP_sha512()` hookup and the `"sha512"` name/lookup rows.
- **Mirror** — `src/fs/cache/verify.c` hashes under the algorithm the *key*
  names. Verifying a sha512 body with sha256 is not a near-miss; it compares
  two different functions' output and rejects an honest object.
- **Registry** — a push **by digest** is sealed and filed under the algorithm
  the client named. A push **by tag** has nothing to be checked against, so
  it is filed under the algorithm we produce, and a tag therefore always
  resolves to a sha256-addressed manifest.
- **CLI** — `client/lib/oci/`: the ref parser re-emits through the formatter
  (the algorithm a ref pinned is part of its identity), `reg_verbs.c` hashes
  a fetched manifest under the algorithm the ref asked for, `reg_blob.c`
  verifies with a running context opened on the descriptor's algorithm, and
  every URL builder takes the algorithm rather than spelling it.
- **Image layout** — `blobs/<alg>/<hex>` per the image-layout spec, with the
  algorithm directory materialized **on demand**: an empty `blobs/sha512` in
  every layout is a lie another runtime has to read past. Staging moved up to
  `blobs/.stage.XXXXXX`, since the fd is opened before the digest is known
  and `blobs/` is the nearest shared ancestor a rename can stay atomic within.
- **GC** — marks under **every** algorithm before judging anything (a
  manifest the pass never opened is a manifest whose blobs look unreferenced)
  and sweeps every `blobs/<alg>` (tolerating the absent one).
- **Ingest** — `.images/<alg>/<hex>`, and the `digest + 7` prefix-skip that
  assumed `"sha256:"` is now a real parse.

**Tests:** the sha512 legs live in the lanes that already own each surface
rather than in a lane of their own — a sha512 image seeded in the mock
registry (`lab/sha512app`, every digest sha512), a cold/warm mirror pull whose
by-digest manifest leg proves `verified=1` was earned, a corrupt-sha512 fill
refused (written so that *both* opposite bugs fail it — hashing with the
wrong function fails it exactly as not hashing at all does), a push +
resolve by sha512 digest, a sha512 seal that must be **verified** and not
waved through as an unknown algorithm, and a GC pass over a repository
holding nothing but sha512 objects, where a mark walk that skipped
`manifests/sha512` and a sweep that skipped `blobs/sha512` fail on opposite
sides of the same report. The classify lane's bad-digest corpus gained the
cross-product rows: sha256's width under sha512's name, sha512's width under
sha256's name, and `sha384` — a real algorithm the grammar does not register.

**Effort:** M (delivered). See DRIFT 30 and 31.

## D15.5 — Background (in-proxy) registry GC (DELIVERED)

**Goal.** Give the deployment that cannot run a cron job the same
reclamation the operator pass performs, without giving the event loop a
whole-store walk and without letting two callers disagree about what garbage
is.

**Design.** The deferral was right about the *shape* of the work and wrong
about who can ask for it. Reclamation does want a whole-store read and a
grace window — but that is an argument about where the walk runs, not about
whether a schedule may start one. A container image with one config file and
no shell, a read-only host, an appliance: all of them accept `DELETE`s and
none of them can be told "remember to run `brixoci gc`". So the pass stays
exactly what §D15.3 built and gains a second caller.

- **One kernel, promoted.** The mark-and-sweep moved out of the tool into
  `shared/oci/gc.{c,h}` + `gc_mark.c` + `gc_sweep.c`, behind a context
  struct (`brix_oci_gc_t`: root, grace, dry-run in; stats and an error
  string out) that names no CLI option type. `brixoci gc` is now 94 lines of
  options → context → report, and the server calls the same
  `brix_oci_gc_run()`. A divergence between what the tool sweeps and what
  the server sweeps would be a divergence nobody could see from either side.
- **`brix_oci_gc_interval` (off by default) + `brix_oci_gc_grace`
  (3600 s).** Registered at config time by canonical store root — every
  location that inherits the directives names the same store, so the
  registry dedups and the first registration wins.
- **Worker 0 only, one pass at a time, off the event loop.** The
  `cancelable` maintenance timer (`src/protocols/oci/oci_gc.c`, the
  `process_timers.c` idiom) picks at most one due store per tick and hands
  the walk to the `default` thread pool via `brix_task_bind`; with no pool
  configured it runs inline, which is the tree's standing fallback. `N`
  workers must not sweep one store `N` times, and a second pass must not
  start while the first is still walking.
- **Silence is the normal report.** A pass that reclaimed nothing logs
  nothing: a maintenance timer that logs every time it runs teaches
  operators to filter it out, and then it cannot tell them anything. A pass
  that reclaimed something logs one `NOTICE` with the counts; a failed pass
  logs `ERR`.
- **Two refusals at parse time.** `brix_oci_gc_interval` on a
  `brix_oci_mirror` location is refused — a mirror's objects are cache
  entries and the cache tier owns their eviction, so unlinking them behind
  its back would leave it indexing files that are gone. An interval below
  1 s is refused as a busy walk of the disk rather than maintenance. The
  refusal is keyed on the *mirror*, not on "not a registry": the directives
  inherit, so an operator who sets the cadence once at server level and
  enables the registry in one location underneath has written a correct
  config and the outer block's copy is simply inert.
- **The grace window is what makes it safe unattended.** Between a client's
  last blob `PUT` and its manifest `PUT` the blob genuinely is
  unreferenced — that state is on the path of every push — so a sweeper that
  took it literally would corrupt concurrent pushes. Unattended running is
  precisely the case that meets the race, which is why the window is a
  parameter of the kernel and not of the tool.

**Tests:** `tests/test_oci_registry_gc_background.py` (6 tests, fronts at
14156–14157) — the timer reclaims a deleted manifest's exclusive config blob
while a second repository's hold on the shared layer keeps that one (the
question no request handler can answer, now asked by a background thread),
the surviving image is still servable afterwards, manifests are still never
swept, and the grace leg pins the safety claim without a timing race: two
unreferenced blobs whose only difference is age, one backdated past the
default window and one just written, and the young one is checked only after
the old one has demonstrably gone. The two refusals are `nginx -t` rows.

**Effort:** S (delivered). See DRIFT 32 and 33.

## D15.6 — Non-flat (layered) publish (DELIVERED)

**Goal.** Stop paying for a base layer once per image that stands on it, and
do it without making the flat layout worse for the people running images out
of it.

**Design.** The deferral priced the feature against *storage* and won that
argument: the CAS already dedups identical files, so two images off one base
cost the store almost nothing extra. What it never priced is the **work** —
the base is fetched, decompressed, flattened and scanned again for every
image, because the flat layout has no name for "this layer, on its own". The
layered layout gives it one.

- **`--layout flat|layered`, flat by default.** The flag exists rather than a
  migration because the two layouts are for different consumers: a flat image
  root is a runnable rootfs (`podman run --rootfs`), and a layered one is not
  — composing the layer roots (overlayfs `lowerdir=`, lowest last) is the
  consumer's job. That is a real limitation and it is why this is not the
  default; it is also the whole reason the layout can be shared.
- **`<prefix>/.layers/<alg>/<layer-hex>/`** is one layer, published verbatim
  through the same D7 flattener that builds a flat rootfs — the whiteout
  grammar, containment and squash options are unchanged, only the upper
  directory differs. The image root keeps `.config.json`, `.manifest.json`
  and gains **`.layers`**: one relative path per line, lowest first, so the
  composition reads the same from a Stratum-0 tree and a client mount.
- **The ledgers are the reuse.** `<repo>/.brix-ingest/layers<pfx>/<hex>`
  records a published layer (`<prefix> <digest> <diff_id|-> <rev> <utc>`) and
  `imglayers<pfx>/<image-hex>` records which layers an image is composed of.
  Both are flat because a bare hex's **width** already names its algorithm
  (§D15.4) — the same property that keeps the upload marks and the GC live
  set flat. Both are advisory, exactly like the memo: losing one costs a
  re-publish of content that was already there, never correctness.
- **A refused layer records nothing.** The ledger is what a *later* run
  trusts instead of re-fetching, so an entry written before the layer
  verified would launder a corrupt blob into every future image. Ledger
  writes happen after the publish, and reused layers are skipped by the
  writer because their entry is the reason they were reused.
- **`--verify-diffids` composes rather than conflicts.** Layered mode always
  captures the diff_id when it materializes a layer — the flattener
  decompresses anyway — and records it, so a *reused* layer is still verified
  against the value the ledger holds. A published layer whose entry predates
  the flag has no recorded diff_id, and is materialized again rather than
  skipped: a flag that silently verified nothing would be worse than the
  fetch it saved.
- **Prune gained a second pass.** `ingest prune` retires image roots first,
  drops their `imglayers` records, and only then asks which layer roots no
  surviving record names — a layer is provably orphaned only after the images
  that composed it have actually left the tree. The two passes are two
  publishes, never merged. The pass runs even when the first found nothing,
  so a root removed some other way still frees its layers.
- **The structural guard learned the layer namespace.** Two images off one
  base both `ADD` the same layer root; `no_clobber` there would turn a
  correct second publish into a refusal, so `<prefix>/.layers` is this tool's
  own namespace exactly as its digest root is.

`brixcvmfs_ingest_layout.c` is the new TU — the tag symlink every layout ends
with, plus the layer roots and ledgers — and `--prune-old`'s "delete the root
the tag moved off" moved into `brixcvmfs_ingest_prune.c`, where deleting a
digest root already lived.

**Tests:** six rows in `tests/test_cvmfs_ingest_image.py` over three mock
images sharing one genuinely identical base blob (`lab/stack:{base,childa,
childb}`) — the layer roots and the `.layers` descriptor (whose relative path
is resolved by the test, not assumed), the base layer never being fetched a
second time, `--verify-diffids` still reporting two verified diff_ids when
one of the two layers was reused, prune retiring the unshared layer while the
shared one survives, the security-negative that a corrupt layer leaves no
reusable ledger entry, and `--layout hybrid` refused at parse time.

**Effort:** S (delivered). See DRIFT 34.

## D15.7 — Lazy-pull layer encodings: eStargz and `zstd:chunked` (DELIVERED)

**Goal.** Ingest the layers the lazy-pull ecosystem actually publishes. The
*snapshotter* stays out of scope for the reasons §D15 gives, but "we do not
implement their runtime" was never a licence to mis-read their blobs — and
that is exactly what the reader was doing.

**What was wrong.** Both formats are ordinary tars in a **chain** of
compressed units: eStargz converts a layer into one gzip **member** per file
(plus a TOC member and a footer), and `zstd:chunked` into one zstd **frame**
per file, with the TOC parked in trailing *skippable* frames. The D6 reader
stopped at the end of the first member — `Z_STREAM_END` set `z_done` and the
source was declared spent — and on the zstd side treated any frame that ended
without producing output as end-of-stream. Neither reported an error. A
seven-entry eStargz layer dumped **two** entries and exited 0; a
`zstd:chunked` layer whose TOC frame leads the stream dumped **none** and
exited 0. Silently publishing a truncated rootfs is the worst failure shape a
publisher has, and no lane could see it because every test archive was a
single member.

- **A member boundary is not the end of the source.** At `Z_STREAM_END` the
  reader peeks the next two bytes: a gzip magic means `inflateReset` and
  another member, anything else (trailing NUL padding, which real producers
  do emit) ends the stream. The peek needs the two bytes to be in the window
  together, so the input refill became `src_topup(t, want)` — it compacts
  first, and a boundary falling between the magic's two bytes no longer
  decides the shape of the layer.
- **A frame boundary is not the end either.** The zstd path simply continues
  into whatever follows and ends only at EOF with an empty window; skippable
  frames are consumed by `ZSTD_decompressStream` itself. The early return it
  replaced is now a no-progress guard, so a decoder that consumed nothing and
  produced nothing is a refusal rather than a spin.
- **The sniff accepts a skippable frame as a stream header.** All sixteen
  magics (`0x184D2A50..5F`), because a TOC frame may lead the stream — and a
  zstd layer mistaken for an uncompressed tar is not refused, it is garbage.
- **eStargz's own entries are dropped at the archive root.** `stargz.index.json`
  and the two prefetch landmarks are the format's bookkeeping; a snapshotter
  consumes and hides them, and a publisher that materializes the whole rootfs
  must drop them or the published tree differs from the original image's.
  They are matched at the **root only** and skipped before any syscall, so
  the name can neither plant a symlink nor make real content vanish from a
  subdirectory. `skipped_toc` counts them. Dropping them cannot change a diff
  _id: that is hashed over the decompressed stream before any entry is
  interpreted, which is what makes `--verify-diffids` the proof that the whole
  chain was read.

**Tests:** five rows in `tests/test_oci_tar_corpus.py` (a multi-member gzip
corpus matched against `tarfile` as the oracle, trailing padding that is not a
member, a multi-frame zstd corpus, leading/interleaved/trailing skippable TOC
frames, and the error row where a **middle** member is cut — the last member
carries only end-of-archive padding the reader legitimately never reaches);
two in `tests/test_oci_flatten.py` (an eStargz-shaped layer flattening to
exactly what its plain original does, and the security-negative where the
reserved names arrive as symlinks out of the tree); and two end-to-end in
`tests/test_cvmfs_ingest_image.py` over `lab/chunked:{estargz,zstd}`, both
with `--verify-diffids`. The mock registry grew the two encodings as layer
codecs; the zstd image exists only where a zstd compressor does, and the lane
`importorskip`s the same module.

**Effort:** S (delivered). See DRIFT 35.

## D15.8 — eStargz layer *building* (`brixoci convert --estargz`) (DELIVERED)

**Goal.** Produce the layers §D15.7 taught the tree to read. A registry that
wants an off-the-shelf containerd stargz snapshotter to pull from it lazily
has to **serve** eStargz blobs, and until now nothing in the tree could make
one: `convert` re-encodes every layer of an image and binds the rewritten
manifest at the destination. What stays deferred after this is the
snapshotter itself — a Go plugin that lives in containerd's process, not
ours (§D15).

**The format, as the writer has to emit it** (verified against upstream, not
inferred): the blob is a chain of gzip **members** whose concatenation is an
ordinary tar; a member boundary sits at the top of every non-empty file
payload, at the top of the TOC entry, and at the footer. The footer is
exactly **51 bytes** — a 4-byte-XLEN gzip header carrying the 22-byte
`%016xSTARGZ` subfield, a stored empty deflate block, and eight zero bytes —
so a snapshotter finds the TOC with one ranged read of the blob's tail. The
TOC is the archive's last entry, `stargz.index.json`, holding
`{"version":1,"entries":[…]}`; each regular file's entry carries the member
offset its payload begins at and the digest of its content. The landmark
(`.no.prefetch.landmark` when nothing is prioritized, content one `0x0f`
byte) leads the archive. The layer descriptor gains
`containerd.io/snapshot/stargz/toc.digest`, the sha256 of the **TOC JSON
bytes alone**.

- **No tar encoder was written, and that is the design.** The source is
  drained through the D6 reader's gunzip half (`brix_tar_drain`) into an
  unlinked scratch file, walked once for entry boundaries
  (`brix_tar_stream_offset`, which is exact because the reader never reads
  ahead into a decompressed window), and then `pread` through **verbatim**.
  Pax records, GNU-long names and SCHILY xattrs survive byte-for-byte
  because nothing re-encodes them; the only headers this TU synthesizes are
  the landmark's and the TOC's. Reframing, not rewriting, is what makes
  "extracts to exactly the tree the original did" a property rather than a
  hope.
- **The 512-byte padding after a body rides in the body's own member.** This
  is what a tar writer that flushes per entry does, and it is the reason the
  *next* entry's header still lands on a member boundary. It is outside the
  content digest — that covers the file's bytes, not its framing. Getting
  this wrong produces a blob that is valid gzip and invalid tar, which is
  precisely the failure a lane that only decompresses will not see (the
  §D15.8 lane parses the whole stream with `tarfile` for exactly this
  reason).
- **Conversion is not identity-preserving, so the image around it is
  rebuilt.** New framing means a new compressed digest *and* a new diff_id;
  an eStargz layer wearing its original's diff_id is a lie the runtime
  catches at unpack. `brixoci_convert.c` therefore rewrites the config's
  `rootfs.diff_ids` from what the writer reports — splicing a rebuilt
  `rootfs` over the raw span `json_iter` hands back, so every other byte of
  the config (labels, history, env) is preserved — and emits fresh layer
  descriptors with the TOC annotation. A config whose `diff_ids` count does
  not match the manifest's layer count is refused rather than patched.
- **It reuses the copy pump's endpoints, it does not fork them.** Five seams
  came out of `brixoci_copy.c` (`src_manifest`, `is_index`, `xfer_tags`,
  `fd_pump`, `put_manifest`), so `convert` resolves, refuses and binds
  exactly the way `copy` does — an image index is refused with the same
  message, a foreign layer is refused, and a registry destination is named
  by its own reference. `--tag` names the entry in a **destination layout**,
  which is the one thing a layout cannot carry itself; giving it to a
  registry destination is a usage error rather than a silently ignored
  second name for one push.
- **A legacy runtime still runs the result, with two extra files.** With no
  snapshotter present, podman unpacks the layer as the ordinary gzip tar it
  also is, so `stargz.index.json` and the landmark materialize in the
  rootfs. That is the format's documented legacy behaviour and the reason
  those names are reserved — and it is asserted, not hand-waved: the oracle
  requires everything *else* to be byte-identical to the original image's
  export.

**Tests:** `tests/test_oci_stargz.py` (13, over a `stargz_unittest convert`
driver): the footer points at the TOC; the reframed stream is the same tar
plus the format's own entries; every TOC offset decompresses **its one
member** to that file's bytes (which is exactly what a snapshotter's ranged
fetch does, and so is the check that the payload really starts at a
boundary); metadata and landmark shape; pax extras survive; a plain
uncompressed tar converts too; a converted layer flattens to the tree the
original flattens to; security-negative rows for a source that already
carries bookkeeping entries (dropped, not duplicated), for a reserved name
deeper in the tree (ordinary content), and for a tampered blob failing its
own TOC digests; error rows for a non-archive, a truncated gzip layer and a
missing source. `tests/test_oci_convert_estargz.py` (11, over a hand-built
image layout): end-to-end conversion; only `rootfs` is rewritten in the
config; the original diff_ids do not survive; every destination blob hashes
to its own name; the destination entry is named by `--tag`; the podman
oracle above; and refusals for an image index, a foreign layer, a registry
destination given `--tag`, a missing `--estargz`, and a config that
miscounts its layers.

**Effort:** M (delivered) — `shared/oci/stargz.c` + `stargz_toc.c` (the
writer), `client/apps/oci/brixoci_convert.c` (the image rewrite), the
`convert` verb and five seams exported from the copy pump. See DRIFT 36.

## D15.9 — The RPM mirror as a C surface (`brix_rpm_mirror`) (DELIVERED)

**Goal.** Give the RPM plane the same shape the OCI plane has had since §D0: a
protocol module that classifies the request, decides the cache policy from the
route it classified, fills through the shared never-drop plane and verifies at
the edge — instead of §D11's `proxy_cache` recipe, which expressed the same
policy in two `location ~` blocks and could express nothing else.

**Why the recipe was not the end of it.** D11 is correct and stays shipped (a
site that wants a mirror in front of stock nginx still gets one), but a config
recipe can only match a *pattern*. It cannot verify a digest-named file against
the digest in its own name, it cannot tell an operator which route a request
took, and — the part that decided this — it cannot refuse. `proxy_cache` in
front of an upstream that has been compromised caches whatever it is handed;
the name `<checksum>-primary.xml.gz` is a *proof* that the recipe has no way to
check. Every other pull-through plane in this tree checks it (`cvmfs-cas`,
`oci-digest`), and the reason RPM did not was that nobody had written down that
createrepo's filenames are the third instance of one grammar.

- **One classifier, read once, at the edge.** `rpm_classify.c` turns a decoded
  URI into one of four routes — `repomd` (the mutable freshness root),
  `metadata` (`<hex>-<name>`, self-addressing), `package` (`.rpm`/`.drpm`,
  immutable in practice, verified client-side by dnf) and `aux` — or refuses
  it. The traversal defense rides along rather than being a second pass: a path
  that classifies cannot escape the store, because the grammar rejects every
  component that could. It is pure C over the caller's buffer with no nginx
  types, which is what lets the fill-side verify and the cache TTL policy
  re-read a key with the SAME grammar the gate used.
- **`brix_cache_verify rpm-repodata` is the third self-addressing mode, not a
  fourth mechanism.** `brix_cache_verify_is_selfaddr()` now answers for
  `cvmfs-cas`, `oci-digest` and `rpm-repodata` alike, and the three share one
  dispatcher, one fail-closed policy and one local-posix-store requirement. The
  RPM half is `brix_cache_verify_rpm_repodata()`: the hex LENGTH names the
  algorithm (40/64/96/128 → sha1/sha256/sha384/sha512), which is what stops a
  file that merely *begins* with hex digits being verified under the wrong
  function. Everything else — repomd, packages, aux — returns UNVERIFIED by
  design: repomd is mutable by definition, and a package carries its proof
  inside the RPM header, where dnf checks it.
- **The mutable half expires on `brix_rpm_metadata_ttl`, and only it.** The
  merge stamps the directive's window as the plane's manifest TTL, so
  `repomd.xml` (and its `.asc`/`.key`) revalidate while every digest-named file
  beside it is immutable and ignores it. That is the split D11 measured from
  dnf's own request trace (Appendix X, finding X-2) — now a property of the
  code rather than of two regexes an operator has to copy correctly.
- **Writes are refused at the gate, and the refusal is evidence.** dnf never
  writes; a `PUT` into a repository path is a scanner looking for somewhere to
  plant one. `brix_rpm_gate()` answers `405` with `Allow: GET, HEAD` before
  anything touches the store, and emits `signal=rpmwrite` on the guard-audit
  line — a jail that bans on the first occurrence, because there is no honest
  client that produces it. A verify mismatch emits `signal=rpm_tamper`, whose
  jail ships **disabled**: the host on that line is the upstream mirror, not a
  client, and banning it is a decision an operator makes deliberately.
- **The mirror is a pure cache node and shares the plumbing that makes it one.**
  The export root anchors at `/`, the cache key IS the request URI, and the
  fill goes through the shared T20 never-drop plane — which is why a transient
  upstream failure answers a keep-alive `504` + `Retry-After` rather than a
  `502` (DRIFT 37). Two helpers came out of writing this rather than a third
  copy of each: `brix_http_merge_export_anchor()` (the anchor→rootfd→backend
  order that CVMFS, OCI and RPM all depend on being in that order) and
  `brix_http_mirror_key_path()` / `brix_http_mirror_postconf()` (the key→path
  composition and the HTTP-only node's zones, dashboard and fill-pool
  resolution).
- **Observability names the route, because the route is the policy.**
  `brix_rpm_requests_total{class,outcome}` and `brix_rpm_verify_fail_total`,
  plus `$rpm_class` / `$rpm_cache` for the access log — four class values and a
  fixed outcome set, so the label space is bounded by the grammar (INVARIANT
  8).

**Tests:** `tests/test_rpm_mirror_native.py` (20, block 14170–14175, over
`tests/rpm/mock_repo.py` — a repository origin with a `/ctl/fault` plane that
can tamper, 404, 503 or hang a chosen path). Success: cold fill then warm hit
costs exactly one upstream GET; a package serves ranged and conditional (200 +
ETag → 206 `Content-Range` → 304); `repomd.xml` is refetched after its TTL
while the digest-named file beside it is fetched exactly once, ever; and a real
`dnf install` through the mirror (`slow`, the D11 oracle re-pointed at the C
surface). Error: a broken origin fails promptly and caches nothing
(parametrized over 503→504 and 404→404), and cached objects survive the origin
going away while an object never pulled answers 504 with `Retry-After`.
Security: tampered metadata is refused (502), absent from the store, and
audited with `signal=rpm_tamper`; every write method is refused 405 with
`Allow: GET, HEAD`, never reaches the origin, and is audited with
`signal=rpmwrite`; traversal never reaches the origin; and the plane refuses to
**start** under the wrong verify mode or with a cleartext upstream and no
`brix_rpm_mirror_insecure`. And the shipped recipe is the one under test:
`deploy/rpm-mirror/brix.conf.example` is rendered and parsed by the binary it
is written for, because a recipe an operator pastes that does not parse has
never been run by anyone.

**Effort:** M (delivered) — `src/protocols/rpm/` (classifier, gate, merge,
mirror, module), the `rpm-repodata` verify half in `src/fs/cache/verify.c`, the
metrics family in `src/observability/metrics/rpm.c`, two fail2ban filters, and
the two shared helpers above. See DRIFT 37.

## D15.10 — Warm repodata prefetch (`brix_rpm_prefetch`) (DELIVERED)

**Goal.** Turn the one prediction an RPM mirror can make without guessing into
cached bytes: when a new `repomd.xml` comes through, fetch the two files the
client is about to ask for — `primary` and `filelists` — before it asks.

**Why this is not speculation in the usual sense.** Appendix X, finding X-3,
measured a stock EL9 dnf against a real repository: after `repomd.xml` it
fetches primary AND filelists, unconditionally, every time its metadata window
has expired, before it can answer any question at all. The finding was written
down as "the D11 warm-prefetch set is {repomd, primary, filelists}" and then
never became code, because the recipe D11 shipped had nowhere to put it — an
nginx `proxy_cache` block can cache what was asked for and cannot fetch what
was not. The C plane (§D15.9) can, and the objects are not a guess: they are
named, by name and by checksum, in the index the mirror is holding at that
moment. On a cold mirror those two fills are the client's entire wait.

- **The trigger is narrow, and that is the whole safety argument.** A REPOMD
  request that resolved as a **FILL** — this worker just pulled a *new* index
  — and nothing else. A hit means everything the index names was already
  considered; a request that never reached the origin has no new warm set. So
  the upstream cost is bounded by the mutable half's own TTL
  (`brix_rpm_metadata_ttl`), not by client traffic: N clients per window still
  produce one warm pass, because only the first of them is a fill.
- **The index is read from the handle the response is about to use.** No
  second open, no store walk: one positional `pread` of at most 256 KiB from
  the file the serve is already holding, on the same event-loop pass that is
  about to send it. A repomd bigger than that cap is not speculated on.
- **Every href is re-checked by the request grammar.** `repomd.xml` is the
  one route in this plane that is NOT self-verifying — it is mutable by
  definition, so a compromised origin can write any `<location href>` it
  likes. The reader therefore drops anything absolute, `..`-bearing,
  scheme-bearing or entity-bearing before it is a path at all, and then the
  composed key must pass `brix_rpm_classify()` as a **metadata**-class object
  — the same grammar a client request passes — before it can become a fetch.
  A legal-but-not-digest-named location (`repodata/filelists.xml.gz`, an
  unhashed repository) is refused and *says so* in the log. What survives is
  digest-named, so the fill verifies it against the checksum in its own name
  exactly as it would a client's fetch: the prefetch cannot admit an object
  the request path would have quarantined.
- **The fill is the ordinary fill, on the ordinary pool.** One detached
  thread-pool job per index, carrying at most two composed keys, running
  `brix_sd_cache_fill_key()` — the same whole-file fill the miss path runs —
  and only for a key `brix_sd_cache_fill_needs_offload()` says is both absent
  and worth a round trip. Nothing runs an origin fetch on the event loop,
  nothing parks the client's request on the speculation, and a failure is
  invisible to the client by construction: a warm fill that does not happen is
  the cache miss the client would have had anyway.
- **Off by default.** It spends upstream bandwidth on an index nobody may
  follow up on, which is a trade only the operator of the repository's clients
  can make — and it is exactly the trade a site mirror wants, so the shipped
  recipe turns it on. Two counters say whether it was worth it:
  `brix_rpm_prefetch_total` (round trips a client did not wait for) and
  `brix_rpm_prefetch_fail_total` (round trips nobody wanted).

**Tests:** four rows in `tests/test_rpm_mirror_native.py` (block 14170–14176;
the warm front binds 14176). Success: with the directive on, one client GET of
`repomd.xml` warms both files into the store and the client's own subsequent
GETs cost **zero** further upstream requests. Default: with the directive
absent, the mirror fetches exactly what was asked of it and nothing else.
Error: a 404 on the warm object leaves the client's index served, the store
without a half-object, and the file fetchable normally the moment a client
actually wants it. Security: a hand-written poisoned `repomd.xml` whose four
`<location href>`s are a traversal, a scheme, an absolute path and a
legal-but-unhashed name produces **no** upstream request and no store entry
for any of them, and the last one is logged for what it is.

**Effort:** S (delivered) — `src/protocols/rpm/rpm_repomd.c` (the reader and
the key composition, pure C), `rpm_prefetch.c` (the trigger, the re-check and
the job), one flag directive and two counters. See DRIFT 38.

## D15.11 — The explicit realm allowlist (`brix_oci_upstream_auth_realm`) (DELIVERED)

**Goal.** Make the one mitigation the threat model already promised actually
exist: an operator-named host a `WWW-Authenticate` realm may live on, for
upstreams whose token service is not on the registry's own domain.

**Why this was a gap and not a feature request.** Appendix L's row for
"malicious challenge steers the token dance to an attacker realm" names the
mitigation as "the realm host must match the configured upstream host **or its
explicit `brix_oci_upstream_auth_realm` allowlist entry**". Only the first
half was built. The derived rule in `shared/oci/url.c` — same host, its
registrable parent, or a sibling under that parent — is a good rule and covers
every registry that runs its own token service (`registry-1.docker.io` →
`auth.docker.io`, `quay.io` → itself, GitLab's `registry.<group>` →
`<group>`). What it cannot express is a registry that delegates to an
unrelated identity host, which is an ordinary self-hosted shape: distribution's
`auth.token.realm` is an arbitrary URL, and sites point it at the SSO they
already run. For those upstreams the mirror did not merely refuse the
challenge, it could not be configured to work **at all** — and a security
check with no configured path through it is a check that gets deleted, not
one that gets obeyed.

- **Shape.** `brix_oci_upstream_auth_realm <host>`, repeatable, valid in
  http/server/location so a fleet can set it once. Each entry is one exact
  host. There is deliberately **no pattern form**: `*.example` is how a single
  line re-admits every host under a domain the operator does not run, which is
  the failure this directive exists to avoid, not to enable.
- **The derived rule still runs first.** `brix_oci_url_realm_allowed_ex()`
  tries the same-domain rule and only then walks the list, so an empty
  allowlist cannot change any verdict that exists today, and the common case
  never touches it.
- **Entries are validated by the parser a realm goes through.** An entry is
  passed to `brix_oci_url_authority()`: an entry can therefore only ever name
  something a realm could also spell. A scheme, a userinfo, a port, a wildcard
  or a duplicate is an `nginx -t` failure with a message that says which of
  those it was. The port refusal is the subtle one and is the reason the
  validator is not just "is this a hostname": accepting `auth.example:8443`
  would read as pinning a port, while the trust rule compares hosts only — an
  operator would believe they had narrowed the boundary while having widened
  it by the whole host.
- **It governs redirect hops too.** The token leg follows redirects, and each
  hop is re-checked; the allowlist is passed to that check as well, so it
  cannot be used to clear the first gate and then wander.
- **A widened boundary is audited.** A dance honoured only because of an entry
  logs one INFO line naming the host. The dance is cached per scope, so this
  is rare rather than noisy, and "which realm did we actually trust" becomes a
  log question rather than a config-reading exercise.
- **Storage.** `brix_oci_realm_list_t` — eight fixed 256-byte slots — lives in
  `shared/oci/url.h` beside the rule it feeds, is copied by value into the
  upstream descriptor at merge, and is therefore read by the fill thread from
  storage that cannot move. Eight, because an allowlist that needs a dozen
  entries has stopped being one.

**Tests** (`tests/test_oci_mirror_authdance.py`, four rows). Success: an
upstream serving `/token` on a second listener at a *different* address, with
its realm pointing there, pulls successfully once the host is named — and the
INFO line is present while `signal=oci_realm_refused` is absent. The mock
serves both listeners from one process on purpose: two processes would fail
the test for the wrong reason (a bearer the data plane never minted) rather
than on the realm boundary, which is why the harness grew `--token-bind`.
Error: naming `127.0.0.4` while the realm is on `127.0.0.3` still refuses —
the compare is equality, not neighbourhood. Security: `*.docker.io` and
`127.0.0.3:14102` are both refused at `nginx -t`.

**Effort:** S (delivered) — one shared type and two functions in
`shared/oci/url.{c,h}`, one setter, one merge copy, two call sites. See
DRIFT 39.

## D15.12 — The two flags the risk tables named (`--require-digest`, `--paranoid`) (DELIVERED)

**Provenance.** The same audit that produced §D15.11, run over the tooling
surface instead of the directive surface: every `--flag` this document spells
in backticks, diffed against the flags the client binaries actually parse.
Three came back. Two were mitigations promised in the risk tables and never
built — App. L's registry-MITM row offered `--require-digest`, App. B.7's memo
paragraph offered `--paranoid`. The third, App. E's P6 row, named `--skip-bad`
for behaviour the tool already has under the opposite spelling (`--strict`
makes a bad package fatal; skip-and-count is the default), which is a
documentation defect and is corrected in place rather than aliased.

The failure mode is the one §D15.11 described: a risk table that names a
control the operator cannot type reads as a mitigation and is worth less than
an empty cell, because it stops anyone looking for the real one.

### D15.12.1 `brixcvmfs ingest image --require-digest`

**What it refuses.** A reference without `@sha256:<hex>`. Exit 2 (usage),
emitted from `img_resolve()` immediately after `brix_oci_ref_parse()` and
before `brix_oci_reg_from_ref()` — no socket, no credential on any leg, no
tag lookup handed to whoever is answering.

**Why a flag and not a default.** The digest chain already in place (manifest
digest pins config + layer digests, each verified on receipt, `--verify-diffids`
extending through the uncompressed layers) proves the published tree matches
the manifest that was *resolved*. It cannot prove the manifest is the one the
operator meant, because a tag is a mutable name: a re-push, or a registry
compromise, changes what `app:v1` resolves to and every verification still
passes. Only the operator knows whether a given ingest is a pinned deployment
or a deliberate follow-the-tag mirror — both are legitimate, so this is
intent, and intent is a flag. Defaulting it on would break the mirror case;
leaving it absent left the pinned case with nothing to say.

**Cost.** `ref.has_digest` already existed (`client/lib/oci/ref.h`, D5.1), so
the whole feature is one condition, one option bit and one usage line.

### D15.12.2 `brixrpm createrepo --paranoid`

**What it changes.** The `--update` memo hit test. The default asks
`(size, mtime)`; `--paranoid` asks for the file's sha256 and compares it to
the `pkgid` the memo recorded.

**The gap that buys.** A package **rewritten in place at the same length with
its timestamp preserved** — a rebuild copied with `cp -p`, an `rsync` without
`--checksum`, a mirror leg someone else runs — is invisible to `(size, mtime)`
and gets republished under its *old* checksum. The repository then advertises
metadata naming bytes the file no longer holds, and the first client to
download that package fails verification against metadata this site signed.
The failure surfaces one download later, on a package that looks fine on disk,
which is why §7 of the operations doc now carries it as its own row.

**What it costs.** One read pass per memo hit. An unchanged package still
skips the header walk and the three XML renders — the flag is a verification,
not a rebuild. It also makes the mtime-only case *free*: same bytes, new
timestamp is a hit under `--paranoid` where the default re-parses.

**What it reports.** Drift is warned by package name and counted as
`changed-in-place` in the summary line, appended only when non-zero (a run
that never re-hashed has nothing to say, and a zero is the normal case). That
counter is the product: a non-zero there means something rewrote a package
behind the operator's back.

**Interaction.** Without `--update` there is no memo to consult, so
`--paranoid` changes nothing — a full run parses every package anyway, which
is strictly stronger. Accepted as a no-op rather than a usage error for that
reason, and the usage text says so.

**Substrate.** `brix_rpm_file_sha256()` (`shared/rpm/rpmhdr.{c,h}`) — the
whole-file digest `brix_rpm_pkgid()` reports, computed without parsing a byte
of the headers. It lives beside the pkgid definition on purpose: the two must
never be able to disagree about what "the package's checksum" means.

**Tests** (six rows). `tests/test_cvmfs_ingest_image.py`: a pinned ref
completes the ingest; a tag ref exits 2, publishes nothing and leaves no memo;
and the refusal happens with the mock registry's request log unmoved —
asserted by length, because a refusal that still talks to the registry has
already leaked the thing it was refusing to risk.
`tests/test_rpm_createrepo.py`: `--paranoid` on an untouched repo is
`(0 parsed, 3 cached)` and stays a hit when only the mtime moves; a package
rewritten in place under an identical `(size, mtime)` is caught, warned,
counted and re-parsed, and primary.xml's checksum set moves by exactly one;
and the same rewrite **without** the flag is silently cached with the stale
checksum still published. That last row asserts the wrong answer deliberately
— it is the reason the flag exists, and it must not change without a decision.

**Effort:** S (delivered). See DRIFT 40.

## D15.13 — The flag audit becomes a guard (`check_client_flags_doc.py`) (DELIVERED)

**Provenance.** §D15.12's own residual said it: the sweep that found
`--require-digest`, `--paranoid` and `--skip-bad` is one command, and the
operations guides make promises too. Running it once per wave is a habit;
running it in CI is a property. This is the §D15.11/§D15.12 technique — read
the document's claims, diff them against what the tree defines — turned into
`tools/ci/check_client_flags_doc.py`, the flag twin of commit 38714b18's
`check_metric_names.py`.

**Ground truth.** Every long option the client tree can actually match, in the
three argv dialects that coexist under `client/`: exact `"--…"` literals (the
hand-written ladders, and `add_argument("--…")` in the Python-implemented
tools, which spell it identically), the *name* column of a `getopt_long`
`struct option` table (`{"listen", required_argument, …}` — a literal with no
dashes in it at all, which is how `brix-fault-proxy`'s entire surface hides
from a naive scan), and the strncmp prefix forms with their trailing `=`
trimmed. 245 flags. One union rather than a set per tool, because
`brixcvmfs`/`brixoci`/`brixrpm` are argv[0] personalities of one binary and a
per-tool split would be a fiction the link map does not support.

**Claims.** A `--flag` counts only when it sits in a command segment whose
leading word is a shipped tool — the tool names read from `client/Makefile`, so
a new binary is covered the day it is added. Two scoping rules do the work of
keeping the guard quiet enough to survive: a line is cut down to its
inline-code spans when it has any (a page that marks its commands as code is
telling us where they end, which is what stops the prose sentence "xrdcp fails,
then fsck `--repair` converges" from reading as one command line), and each
segment is split on `| && || ;` so `brixcvmfs … | grep --color` does not
attribute grep's flag to us. Everything else — `podman pull
--tls-verify=false`, `dnf --installroot`, `./configure --add-module`,
`pytest --collect-only` — is somebody else's grammar and is never looked at.

**Escape hatch, and no backlog.** `client-flags-allow: <reason>` on the line.
A plan proposing a flag it has not built is legitimate; it just has to say so,
which is the sentence that was missing from the two risk tables. There is
deliberately **no backlog file**: the tree was brought to zero before the guard
landed, so a finding is new drift and the marker is the only way past it.

**What the first full-tree run found.** Sixteen references to `xrdcp
--allow-http` (README twice, and seven operator-facing pages) plus one
`xrdcp --allow-tls`, and fourteen plan/audit lines naming flags nothing builds.  <!-- client-flags-allow: the typo this section corrects, quoted -->
The resolution split three ways, and the split is the interesting part:

- `-A` / `--allow-http` is a **real stock-xrdcp flag** — the gate on the
  XrdClHttp plugin, without which stock refuses an `http://`/`davs://` URL.
  This client has no plugin layer and no such gate, so the permission it asks
  for is already granted unconditionally. Deleting the flag from fifteen
  recipes would have broken them against the stock binary they were written
  for; so `xrdcp` now **accepts it and does nothing with it**
  (`xrdcp_parse_compat_option()`), which is not a fudge but the exact
  translation of what it asks. It grants a capability; it does not relax one,
  and the security-negative row pins that: the run with the flag must be
  byte-identical to the run without it, with no `notlsok`/`cleartext`/
  `verifyhost` posture change smuggled in behind a compatibility spelling.
- `--allow-tls` exists in neither client. It was a typo for `--tls`, and the
  one page carrying it now says `--tls`.
- The fourteen plan lines are honest proposals (`brixMount cvmfs --kernel`,  <!-- client-flags-allow: quoting the proposals the markers below now carry -->
  `brixcvmfs export --format=oci-tar`, `brix-fault-proxy --cleanup`), stock  <!-- client-flags-allow: quoting the proposals the markers below now carry -->
  spellings quoted for comparison (`xrdcp --delegate`, `--xrate`, and the  <!-- client-flags-allow: quoting stock xrdcp spellings BriX does not implement -->
  parity-audit row that *is* the list of flags BriX does not implement), one
  phase-96 design sketch whose shipped grammar took its arguments positionally
  — and one genuine name collision: `xrd --ca-file` in the GSI matrix is  <!-- client-flags-allow: `xrd` here is XrdRust, the third-party client this row is about -->
  XrdRust, a third-party client that happens to share a name with ours. Each
  now carries a marker naming which of those it is.

**Tests.** `tests/test_ci_guards_b.py`: the extractor reads all three argv
dialects off a synthetic client tree (the `getopt_long` row is the one that
bites); an invented flag in a mitigation table is caught with its line number;
foreign grammar and the post-pipe segment stay silent; and the allow marker is
line-scoped — it cannot launder the flag written under it, because a
file-scoped opt-out is how a guard stops guarding. `tests/test_xrdcp_transport_opts.py`:
`-A`/`--allow-http` accepted (reaching connect proves the valueless flag did
not swallow the source positional), four look-alikes rejected as unknown
options, and the inertness proof above. The guard joins the blocking
`guards.yml` set and `_FAST` in `tests/test_ci_guards.py`.

**A second guard was already red.** Running the blocking set over the tree
while wiring this one in surfaced `check_readme_coverage.py` failing on
`src/protocols/oci/` (27 C sources) and `src/protocols/rpm/` (10) — this
phase's own two directories had shipped without the orientation layer every
other substantial `src/` directory carries, and had been red since §D0.
Both now have one, written against the file headers rather than the plan:
the surfaces and what is gated, a per-file responsibility table split
mirror/registry for OCI, and the invariants each plane is holding (#3 write
gate before token scope, #8 closed label vocabularies, #12 the VFS seam).
DRIFT 42.

**Effort:** S (delivered). See DRIFT 41.

## D15 — Deferred (recorded so the cut is a decision, not an accident)

| Item | Why deferred | Revisit trigger |
|---|---|---|
| containerd stargz **snapshotter** plugin | what is left is out-of-repo by construction: a Go plugin loaded into containerd's own process. Both halves this tree owns are delivered — reading those layers (§D15.7), writing them (§D15.8), and the `Range` blob surface both `/v2/` surfaces already serve. Nothing in C remains to write for it | k8s node-side demand |

---

# Cross-cutting

**Build wiring.** `src/protocols/oci/*.c` → new `ngx_module_srcs` block in
repo-root `./config` (beside the cvmfs block at `./config:1779`) + mirrored
in `CMakeLists.txt`/`cmake/`; `shared/{oci,rpm}/*.c` split by who
parses them (DRIFT 29): the five grammar TUs a worker really does evaluate —
`name`, `digest`, `challenge`, `url`, `authority` — go in **both** `./config`
and `client/Makefile`; the heavy tool TUs (`tar`, `tar_pax`, `tar_digest`,
`flatten`, `stargz`, `stargz_toc`, and all of `shared/rpm/`) go in
`client/Makefile` **only**; `client/lib/oci/`,
`client/apps/{oci,rpm}/` → `client/Makefile`, personalities registered in
`brixmount.c` `main()`, `OPT_LINKS += $(BINDIR)/brixoci` /
`$(BINDIR)/brixrpm` beside `:202`. zstd usage in `tar.c` guarded by
`BRIX_HAVE_ZSTD` (`./config:253` sets it; the no-zstd build must compile
and give the D6 clean error). Coverage guards (`check_config_coverage.py`,
`check_client_build_coverage.py`) make omissions CI-fatal; re-`./configure`
required once per wave that adds sources (build-governance rule).

**Docs.** `docs/04-protocols/oci.md` (the §0.7 material, maintained) ·
`docs/05-operations/oci-mirror.md`, `oci-registry.md`, `container-ingest.md`,
`rpm-mirror.md`, `rpm-on-cvmfs.md` · `docs/10-reference/test-fleet-ports.md`
port claims (§0.8.2) · client man/usage panels ride the existing generator ·
this file's §Status updated per wave (phase-96 discipline: delivery notes +
traps inline).

**Metrics/guard conformance.** New families (§D3.1) enter the
label-cardinality sweep; new guard reasons enter the audit-line format
tests; fail2ban filters ship in the same change as their signal (the
phase-94 rule, applied twice here).

**The three-test rule** is enumerated per feature above — 16 features ×
(success + error + security-negative) with the negatives *named at plan
time*, because for two of these surfaces (tar, RPM header) the negative
corpus **is** the feature.

**Fixtures are built, not downloaded.** `tests/oci/fixtures/` and
`tests/rpm/fixtures/` are generated by checked-in scripts (podman/gtar/
rpmbuild where available, pre-built binaries committed for the tiny
canonical set) — lanes never fetch from the internet except explicitly
live-lab-marked legs.

# Sequencing and the minimal high-value cut

**Recommended order: A → C → D → B → E.** A first (the mirror is
self-contained and immediately useful; its mock + fixtures feed everything);
C next (the headline — needs only D5.1's pull slice, not the push
machinery); D next (RPM mirror is nearly free after A, createrepo is
independent); B last (nothing else depends on push; podman-push oracle
needs the most auth plumbing); E is composition varnish.

**Minimal high-value cut = A + C + D9**: an in-line DockerHub mirror plus
`ingest image` plus folder→Tier-0 — the three things the phase was asked
for — deliverable without D4/D5-push/D12 at roughly half the total effort.

| # | Effort | Impact | Notes |
|---|---|---|---|
| D0 | M | H | unlocks everything mirror-side |
| D1 | M | H | the actual "talks to DockerHub" step |
| D2 | M | H | correctness of the mirror story |
| D3 | S–M | M | proof + ops |
| D4 | L | M | biggest single feature; deliberately late |
| D5 | M–L | M–H | pull slice early (C), rest with B |
| D6 | M | H | prerequisite of the headline |
| D7 | M | H | the security-critical translation |
| D8 | M | **H+** | the headline feature |
| D9 | **S** | **H+** | best effort/impact ratio in the phase |
| D10 | S–M | H | external proof of the headline |
| D11 | S | M–H | cheapest complete deliverable |
| D12 | M–L | M | clean-room parser; dnf oracle |
| D13 | S | M | composition payoff |
| D14 | S | M | pins the promises |

# Open decisions — closed by what the code does

Decided when this edition was written: `/v2/` ping answers locally
(§0.7.1) · offline/serve-stale semantics (§D2.2) · no single-flight on the
token dance (§D1.3). The remaining three were left for the implementation
to settle ("implementation decides, doc records"); it has, so here is the
record:

1. **D11 TTL mechanism** → **existing conf grammar**. Two location blocks
   (`repodata/repomd.xml*` at 60 s, everything else at 720 h) express the
   split-TTL rule with no new directive, so `brix_cache_default_ttl` was
   never built. The RPM plane's whole proxy side was configuration
   (`deploy/rpm-mirror/nginx.conf.example`); its C was `brixrpm` only.
   **Superseded by §D15.9** — the split is now the classifier's verdict
   rather than two `location` regexes, and `brix_rpm_metadata_ttl` is the
   directive the first half of this decision said would not be needed. The
   decision was not wrong: the recipe still ships and is still supported.
   What changed is that a route the server can *name* also lets it verify,
   refuse and count, which a `proxy_cache` recipe cannot (§D15.9.1).
2. **`ingest image --tag-path` naming** → **`<host>/<name>:<tag>`**, the
   colon form, with `--tag-path` as the escape hatch for sites that dislike
   it. The lane writes the assertion the decision was waiting on
   (`test_cvmfs_ingest_image.py` looks up `…/lab/app:v1`), and D14 proved
   the WebDAV worry unfounded — a colon is an ordinary path byte, percent-
   encoded by clients that care, and keeping the tag in the same component
   makes `ls` of the tree read like `podman images`.
3. **Registry anonymous-read default** → **authed-everything**.
   `registry_anon` merges to 0, and `brix_oci_registry on` without an
   authenticated context — no token issuer, no `ssl_verify_client`, no
   `brix_oci_registry_allow_anonymous on` — is an EMERG at `nginx -t`
   (`oci_merge.c`) rather than a registry that starts open. The example
   config therefore cannot *silently* be the permissive one, which was the
   point of forcing the decision to be explicit.

---

# Appendices

A wire transcripts & JSON bodies · B on-disk byte formats · C parser-kernel
pseudocode · D verified tar bytes · E RPM byte walk · F test rosters ·
G harness specs · H work breakdown · I sizing & budgets · J server
integration blueprint · K proposed headers · L threat model · M invariant
matrix · N CI-guard map · O operator walkthrough · P risk register ·
Q verified RPM bytes · R live wire capture · S substrate contracts ·
T ingest call-flow · U whiteout lab (executed) · V measured publish
baseline · W mirror pull lab (executed) · X dnf lane lab (executed) ·
Y push lab (executed) · Z headline chain (executed).
Appendix formats are **normative**: an implementation that disagrees with a
byte here either fixes itself or fixes the appendix in the same change.

## Appendix A — wire transcripts and JSON bodies

All digests below are synthetic patterned hex (`a1`×32 etc.), full-length so
field widths are honest: index `sha256:a1a1…`, amd64 manifest `sha256:b2b2…`,
arm64 manifest `sha256:c3c3…`, config `sha256:d4d4…`, layers `sha256:e5e5…`
/ `sha256:f6f6…`. A **live capture** of this flow against the real Docker
Hub — actual challenge, actual token, actual index with real digests — is
Appendix R; where R disagrees with a synthetic shape here, R wins.

### A.1 Cold multi-arch pull through the mirror (the whole Wave-A story in one flow)

```
# leg 0 — liveness (podman's first contact)
> GET /v2/ HTTP/1.1
> Host: mirror.site:8443
< HTTP/1.1 200 OK
< Docker-Distribution-API-Version: registry/2.0
< Content-Type: application/json
< {}
        (answered locally, §0.7.1 — zero upstream traffic)

# leg 1 — tag manifest, cold → fill with token dance (D1), verify, sidecar
> GET /v2/library/alpine/manifests/latest
> Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.
>         distribution.manifest.list.v2+json, application/vnd.oci.image.
>         manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json
    [fill] > GET registry-1.docker.io /v2/library/alpine/manifests/latest
    [fill] < 401  WWW-Authenticate: Bearer realm="https://auth.docker.io/token",
                  service="registry.docker.io",scope="repository:library/alpine:pull"
    [fill] > GET auth.docker.io /token?service=registry.docker.io
                  &scope=repository:library/alpine:pull        (+Basic iff D1 auth)
    [fill] < 200  {"token":"eyJhbG…","expires_in":300}
    [fill] > GET …/manifests/latest   Authorization: Bearer eyJhbG…
    [fill] < 200  Content-Type: application/vnd.oci.image.index.v1+json
                  Docker-Content-Digest: sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1
                  <index body — A.2>
    [verify body sha256 == a1a1…; store under tag key AND digest key; sidecar B.1]
< HTTP/1.1 200 OK
< Content-Type: application/vnd.oci.image.index.v1+json
< Docker-Content-Digest: sha256:a1a1…a1
< Content-Length: 764

# leg 2 — platform manifest by digest (immutable class: cached forever)
> GET /v2/library/alpine/manifests/sha256:b2b2…b2
> Accept: application/vnd.oci.image.manifest.v1+json, …
    [fill: cached token reused (token_count still 1) → 200 → verify == b2b2… → store]
< 200  Content-Type: application/vnd.oci.image.manifest.v1+json
< Docker-Content-Digest: sha256:b2b2…b2

# leg 3 — config blob;  leg 4/5 — layer blobs, with the CDN hop
> GET /v2/library/alpine/blobs/sha256:e5e5…e5
    [fill] > GET registry-1.docker.io /v2/library/alpine/blobs/sha256:e5e5…e5
                  Authorization: Bearer eyJhbG…
    [fill] < 302  Location: https://cdn.example.net/…?sig=…
    [fill] > GET cdn.example.net /…?sig=…          ← NO Authorization (D1.4)
    [fill] < 200  <layer bytes>
    [verify streamed sha256 == e5e5… BEFORE part-file rename — mismatch: discard,
     502, signal=oci_tamper]
< 200  Docker-Content-Digest: sha256:e5e5…e5

# warm pull, same day: legs 1–5 all cache hits; upstream traffic = zero.
# warm pull after brix_oci_manifest_ttl: leg 1 becomes
    [fill] > HEAD …/manifests/latest  → Docker-Content-Digest unchanged
    → touch freshness, serve cached body (no body transferred, D2.2).
```

**Accept-set decision (pinned here):** fills always present the full modern
Accept set above, and the client's own `Accept` never enters the cache key —
one cached object per tag, whatever the client. Schema1-era content
negotiation is out of scope (upstream registries have dropped schema1); a
client that cannot parse a manifest list is pre-2017 and unsupported.
Inbound caveat (measured, W.3): real clients send the set as **six
repeated `Accept:` header lines**, not one comma list — any server-side
inspection of the client's preferences walks the full `r->headers_in`
list (finding W-1); with the no-key rule above, the mirror mostly never
needs to, which is itself part of why the rule is pinned.

### A.2 Image index (multi-arch manifest list)

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    { "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:b2b2…b2", "size": 1152,
      "platform": { "os": "linux", "architecture": "amd64" } },
    { "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:c3c3…c3", "size": 1152,
      "platform": { "os": "linux", "architecture": "arm64", "variant": "v8" } }
  ]
}
```

### A.3 Image manifest (what D8 walks)

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": { "mediaType": "application/vnd.oci.image.config.v1+json",
              "digest": "sha256:d4d4…d4", "size": 1469 },
  "layers": [
    { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:e5e5…e5", "size": 3370706 },
    { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:f6f6…f6", "size": 421002 }
  ]
}
```

Fields the D5.2 iterator must reach: `schemaVersion`, `mediaType`,
`config.digest`, `layers[].{digest,mediaType,size}`,
`manifests[].{digest,platform.{os,architecture,variant}}` — nothing else is
load-bearing; unknown members are skipped by construction (get_raw walks by
key, never by position).

### A.4 Image config (trimmed to the fields ingest cares about)

```json
{
  "architecture": "amd64", "os": "linux",
  "config": { "Env": ["PATH=/usr/local/sbin:…"], "Entrypoint": ["/bin/sh"],
              "Cmd": [], "WorkingDir": "/" },
  "rootfs": { "type": "layers",
              "diff_ids": [ "sha256:9d9d…9d", "sha256:8c8c…8c" ] },
  "history": [ "…" ]
}
```

`diff_ids` are digests of the **uncompressed** layer tars (≠ the manifest's
compressed-blob digests). v1 ingest verifies the compressed digests (that is
the transport identity); since D6 streams the decompressed bytes anyway, a
`diff_id` cross-check is a near-free `--verify-diffids` flag — **delivered**
(D8.e): `shared/oci/tar_digest.c` hangs a streaming sha256 on the reader's
byte source, so the hash rides the decompression the flattener is doing
anyway, and `client/apps/fs/brixcvmfs_ingest_diffid.c` compares the captured
hashes against `rootfs.diff_ids` once the config sidecar is in hand. Off by
default: it makes the config a trusted document, which is the operator's
call, not ours.

### A.5 Token responses — both field spellings pass D1

```json
{"token": "eyJhbG…", "expires_in": 300, "issued_at": "2026-08-17T12:00:00Z"}
{"access_token": "eyJhbG…", "expires_in": 3600}     ← Quay spelling
{"token": "eyJhbG…"}                                 ← no expiry → assume 60 s
```

### A.6 Push session transcript (D4, our registry as server)

```
> POST /local/v2/site/tools/blobs/uploads/ HTTP/1.1
> Authorization: Bearer <site-issued token>
> Content-Length: 0
< 202 Accepted
< Location: /local/v2/site/tools/blobs/uploads/stg_7f3a9c41
< Docker-Upload-UUID: stg_7f3a9c41
< Range: 0-0

> PATCH …/uploads/stg_7f3a9c41        Content-Range: 0-5242879
< 202 Accepted                        Range: 0-5242879

> PATCH …/uploads/stg_7f3a9c41        Content-Range: 5242880-8388607
< 202 Accepted                        Range: 0-8388607

# out-of-order retry (offset ≠ current end) — spec resume semantics:
> PATCH …/uploads/stg_7f3a9c41        Content-Range: 5242880-8388607
< 416 Range Not Satisfiable           Range: 0-8388607   {"errors":[{"code":"BLOB_UPLOAD_INVALID",…}]}

> PUT …/uploads/stg_7f3a9c41?digest=sha256:e5e5…e5      Content-Length: 0
< 201 Created
< Location: /local/v2/site/tools/blobs/sha256:e5e5…e5
< Docker-Content-Digest: sha256:e5e5…e5

> PUT /local/v2/site/tools/manifests/1.0
> Content-Type: application/vnd.oci.image.manifest.v1+json
> <A.3-shaped body>
< 201 Created
< Docker-Content-Digest: sha256:b2b2…b2
```

### A.7 Error envelopes (three canonical examples)

```json
404 {"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown",
     "detail":{"name":"library/nosuch","ref":"latest"}}]}
400 {"errors":[{"code":"DIGEST_INVALID","message":"provided digest did not
     match uploaded content","detail":{"expected":"sha256:e5e5…e5"}}]}
401 WWW-Authenticate: Bearer realm="https://site.example/token",
     service="site-registry",scope="repository:site/tools:pull,push"
    {"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}
```

## Appendix B — on-disk byte formats

### B.1 Mirror manifest sidecar (`<cache-entry>.ocimeta`)

Grammar: `key=value LF` lines, fixed emission order, unknown keys ignored on
read (forward compatibility), values must be LF/CR-free (refused at write —
they are header tokens by construction). Written staged+rename beside the
cached body.

```
content_type=application/vnd.oci.image.index.v1+json
digest=sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1
fetched_at=1755432000
etag="sha256:a1a1…a1"
verified=1
```

`verified=0` marks the D2.5 best-effort case (tag manifest fetched without a
`Docker-Content-Digest` to check against); digest-addressed entries are
always `verified=1` or absent from cache.

### B.2 Upload session directory (D4.2)

```
<root>/_uploads/stg_7f3a9c41/
    part          # brix_staged part-file — the received bytes
    sha256.ckpt   # binary, 92 bytes, little-endian:
                  #   magic  "BXSC"          4
                  #   version u32 = 1        4
                  #   total_bytes u64        8      bytes hashed so far
                  #   h[8]   u32×8          32      SHA-256 chaining state
                  #   tail_len u32           4      0..63
                  #   tail   bytes          64      unhashed partial block
    meta          # B.1-style lines: name=site/tools  started_at=…  last_patch_at=…
```

Checkpoint written staged+rename after every PATCH. **Resume-truncation
rule:** on `brix_staged_resume`, if `part` is longer than
`ckpt.total_bytes`, the part-file is truncated down to it — the checkpoint
is authoritative, bytes beyond it were never checkpointed — and the `Range`
answer reflects the truncated length. Seal = feed `tail`, finish, compare.

### B.3 Registry store — worked example after the A.6 push

```
/srv/oci-registry/
├── blobs/sha256/e5/e5e5…e5                 # layer (stored once, globally)
├── blobs/sha256/f6/f6f6…f6
├── blobs/sha256/d4/d4d4…d4                 # config blob
├── repos/site/tools/
│   ├── manifests/sha256/b2b2…b2            # manifest body
│   ├── manifests/sha256/b2b2…b2.meta       # B.1-format sidecar
│   ├── tags/1.0                            # one line: "sha256:b2b2…b2\n"
│   └── layers/e5e5…e5  ·  f6f6…f6  ·  d4d4…d4   # empty ref-marks
└── _uploads/                               # empty after seal
```

After an SBOM is pushed at that image (D15.1), the same repository also
holds the referrers graph — one directory per **subject**, one small
descriptor per **referrer**, plus the back-pointer a DELETE reads:

```
└── repos/site/tools/
    ├── manifests/sha256/a7a7…a7            # the SBOM manifest itself
    ├── manifests/sha256/a7a7…a7.subject    # "b2b2…b2" — the edge, reversed
    └── referrers/sha256/b2b2…b2/a7a7…a7    # {"mediaType":…,"digest":"sha256:a7a7…a7",
                                            #  "size":412,"artifactType":…,"annotations":{…}}
```

Storing the *descriptor* rather than a bare digest is what keeps the read
path from re-opening and re-parsing every referring manifest to rebuild
fields the push already knew. The back-pointer is what keeps a DELETE from
scanning every subject in the repository to find the one edge it must cut.

### B.4 Ingest memo + scratch (D8)

```
<repo_dir>/.brix-ingest/
├── memo/registry.example/site/tools:1.0    # B.1-style lines:
│       manifest=sha256:b2b2…b2
│       revision=42
│       at=2026-08-17T14:03:11Z
│       platform=linux/amd64
└── scratch/<pid>.<rand>/                   # steps 3–5 workspace; reaped on entry
    ├── layers/e5e5…e5.tar.gz               # fetched blobs (hash-verified)
    └── upper/…                             # the flattened tree pre-graft
```

Memo path = the flat human path (grammar-validated, so it cannot traverse);
step 2's no-op test is `manifest==` string equality on that file.

### B.5 `brixoci` local store = the OCI image layout (interchange, oracle-readable)

```
./mylayout/
├── oci-layout        # {"imageLayoutVersion":"1.0.0"}
├── index.json        # A.2-shaped, org.opencontainers.image.ref.name annotations
└── blobs/sha256/<hex>   # manifests, configs, layers — all flat by digest
```

`layout.c` re-hashes every blob it reads against its path name (the
layout's own contract) and writes temp+rename; `skopeo inspect
oci:mylayout` is the conformance oracle (F, live-lab leg).

### B.6 repodata skeletons (D12.3 — byte shapes dnf actually reads)

`repomd.xml` (complete):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo"
        xmlns:rpm="http://linux.duke.edu/metadata/rpm">
  <revision>1755432000</revision>
  <data type="primary">
    <checksum type="sha256">…of the .gz…</checksum>
    <open-checksum type="sha256">…of the XML…</open-checksum>
    <location href="repodata/<sha256-of-gz>-primary.xml.gz"/>
    <timestamp>1755432000</timestamp>
    <size>2412</size><open-size>10233</open-size>
  </data>
  <data type="filelists"> …same five children… </data>
  <data type="other">     …same five children… </data>
</repomd>
```

`primary.xml` per-package element (complete working set):

```xml
<package type="rpm">
  <name>brix-demo</name><arch>x86_64</arch>
  <version epoch="0" ver="1.4.0" rel="1.el9"/>
  <checksum type="sha256" pkgid="YES">…sha256 of the whole .rpm file…</checksum>
  <summary>…</summary><description>…</description><packager/>
  <url>https://example.org</url>
  <time file="1755432000" build="1755431000"/>
  <size package="123456" installed="345678" archive="345900"/>
  <location href="Packages/brix-demo-1.4.0-1.el9.x86_64.rpm"/>
  <format>
    <rpm:license>MIT</rpm:license><rpm:vendor/>
    <rpm:group>Unspecified</rpm:group><rpm:buildhost>ci</rpm:buildhost>
    <rpm:sourcerpm>brix-demo-1.4.0-1.el9.src.rpm</rpm:sourcerpm>
    <rpm:header-range start="4504" end="8280"/>
    <rpm:provides>
      <rpm:entry name="brix-demo" flags="EQ" epoch="0" ver="1.4.0" rel="1.el9"/>
    </rpm:provides>
    <rpm:requires><rpm:entry name="libc.so.6()(64bit)"/></rpm:requires>
    <file>/usr/bin/brix-demo</file>
  </format>
</package>
```

`rpm:header-range` = the main header's byte span in the file — we know it
exactly from the D12.2 parse (start = 96 + 16 + sig_il·16 + align8(sig_dl);
end = start + 16 + il·16 + dl), so it is emitted, enabling dnf's
header-only fetches. `filelists.xml`/`other.xml`: same `<package
pkgid="…sha256…" name arch>` framing with `<version/>` + `<file>`/
`<changelog>` children. `pkgid` everywhere = the whole-file sha256, the
same value as primary's `<checksum>`.

### B.7 `.brixrpm-cache` (the `--update` memo beside repodata/)

One line per package, B.1 discipline (space-safe because href is
URL-escaped): `href=<location> size=<st_size> mtime=<st_mtime>
sha256=<hex>` — a package whose `(size,mtime)` both match is trusted
without re-hash; `--paranoid` (§D15.12.2) compares the recorded sha256
instead, so a package rewritten in place under an unchanged `(size,mtime)`
is caught, counted and re-parsed rather than republished stale.

### B.8 Master caps table (every limit in the phase, one place)

| Cap | Value | Where enforced |
|---|---|---|
| repo name | ≤ 255 B | name.c (§0.7.2) |
| tag | ≤ 128 B | name.c |
| digest hex | = 64 (sha256) | digest.c |
| upload session id | ≤ 128 B, `[A-Za-z0-9_-]` | classifier |
| manifest body | ≤ 4 MiB | D4.3 / mirror fill |
| blob | `brix_oci_max_blob_size` (0=∞) | D4.2 |
| token value | ≤ 4 KiB | kv zone val_max |
| kv token key | = 32 B (sha256 of upstream‖scope) | D1.3 |
| redirects per fill | ≤ 3 | D1.4 |
| `expires_in` default / slack / floor | 60 s / −30 s / ≥ 5 s | D1.3 |
| `brix_oci_manifest_ttl` default | 60 s | §0.6.1 |
| `brix_oci_upload_grace` default | 24 h | §0.6.2 |
| tar path / linkname | ≤ 4095 B | tar.c |
| pax records per entry | ≤ 65536 | tar_pax.c |
| xattr per entry | ≤ 64 KiB | tar_pax.c (changeset cap) |
| flatten entries | default 1 M (`max_entries`) | flatten.c |
| flatten bytes | `max_total_bytes` (0=∞) | flatten.c |
| JSON nesting (manifest iter) | ≤ 32 | json_iter.c |
| RPM index entries `il` | ≤ 4096 | rpmhdr.c |
| RPM data region `dl` | ≤ 64 MiB | rpmhdr.c |
| kv zone size / zones | ≥ 64 KiB · ≤ 16 | kv.h (existing) |

## Appendix C — parser-kernel pseudocode (normative control flow)

### C.1 `/v2/` classifier (oci_classify.c)

```
classify(uri, len, out):
    p = after location-prefix strip;  require literal "v2/"          else BAD
    if p at end: return API_ROOT
    decode already done by caller; any residual '%' → BAD(NAME_INVALID)
    # find the reserved terminal, scanning right-to-left:
    #   …/tags/list$            → TAGS_LIST,   name = head
    #   …/referrers/<digest>$   → REFERRERS,   subject = digest_hex
    #   …/manifests/<ref>$      → MANIFEST,    ref  = tail component
    #   …/blobs/uploads/$       → UPLOAD_START
    #   …/blobs/uploads/<id>$   → UPLOAD_SESSION (id charset check)
    #   …/blobs/<digest>$       → BLOB (digest.c parse → digest_hex)
    validate name via name.c grammar (length, components)            else BAD
    MANIFEST: ref_is_digest = digest.c parse succeeds; else tag grammar
    return class
```

Right-to-left terminal matching is what lets a repo legally named `blobs`
or `manifests` work (`/v2/blobs/manifests/latest` → name="blobs",
terminal="manifests").

### C.2 Bearer challenge parser (D1.2)

```
parse_challenge(hdr):
    require prefix "Bearer" + space                     else fail
    split on ',' at depth 0 (inside "" doesn't split)
    for each `k=v`: unquote v ('\' escapes inside quotes), trim OWS
    require realm; keep service, scope; ignore unknown keys
    realm policy: https scheme (unless insecure), host ∈ allowlist(upstream)
build_token_url = realm ? service=… [&scope=… (server's, verbatim)]
                            [&scope=repository:<name>:pull  iff absent]
```

### C.3 tar next-entry loop (D6)

```
next(t, e):
    if body_remaining: return -1 (caller bug: unconsumed body)
    loop:
        blk = read512();  all-zero → expect second zero block or EOF → 0
        verify chksum (unsigned sum, field-as-spaces; retry signed)   else -1
        switch typeflag:
          'x': parse pax records into per-file overlay (C.3a); continue
          'g': parse into global overlay; continue
          'L': body → longname override; continue
          'K': body → longlink override; continue
          default: break
    fill e from ustar fields (octal or base-256 numerics)
    apply global overlay, then per-file overlay (path,linkpath,size,
        mtime,uid,gid,SCHILY.xattr.* → e->xattr pack); clear per-file
    join prefix[345]/name when prefix non-empty and no override took path
    bound path/linkname ≤ 4095                                        else -1
    body_remaining = e->size (data blocks rounded to 512)
    return 1
C.3a pax record:  "<len> <key>=<value>\n", len = decimal byte count of the
    WHOLE record including the digits and the \n; len mismatch → -1;
    record count > 65536 → -1.
```

### C.4 flatten apply loop (D7 — containment inline)

```
apply_layer(layer_fd, upper_dirfd, o, st):
    t = brix_tar_open_fd(layer_fd)
    while next(t, e) == 1:
        parts = split(e.path);  reject "", ".", ".."
        if any brix_ov_name_reserved(part): fail "marker smuggling"
        dfd = descend(upper_dirfd, parts[:-1])
              # per-component openat(O_NOFOLLOW|O_DIRECTORY),
              # mkdirat on ENOENT; ELOOP/ENOTDIR → fail (symlink escape)
        base = parts[-1]
        base == ".wh..wh..opq"  → clear_children(dfd); drop .brix.opq; continue
        base startswith ".wh."  → victim = base[4:]
                                  remove_recursive_at(dfd, victim)
                                  drop ".brix.wh."+victim marker; continue
        switch e.type:
          REG:  tmp = openat(dfd, BRIX_OV_TMP_PREFIX+n, O_CREAT|O_EXCL|O_WRONLY)
                pump body (st.bytes += n; budget check) → fchmod, futimens
                → renameat(dfd, tmp, dfd, base)
          DIR:  mkdirat-or-merge; fchmodat
          SYM:  symlinkat(e.linkname, dfd, base)      # never resolved
          HARD: linkat via descent to recorded target; cross-layer → copy, st.count
          CHR/BLK/FIFO: st.skipped_special++; fatal iff o->strict
        apply e.xattr (fsetxattr on tmp before rename / lsetxattr for links)
        st.entries++;  > o->max_entries → fail
```

### C.5 RPM header walk (D12.2)

```
read_rpm(fd):
    lead = read(96); magic ed ab ee db; sigtype(=5) @78            else fail
    sig  = read_header_section()          # skipped, but bounds-parsed
    seek align8(after sig)
    hdr  = read_header_section():
        preamble: 8e ad e8 01 + reserved4; il(4BE) ≤ 4096; dl(4BE) ≤ 64 MiB
        entries  = il × {tag,type,offset,count} (16 B each)
        data     = read(dl)
        per entry: offset+extent(type,count) ≤ dl                   else fail
                   numeric types: offset alignment (INT16 2, INT32 4,
                   INT64 8)                                         else fail
                   STRING*: each string NUL-bounded inside data     else fail
    accessors: tag→(type,ptr,count) map; pkgid = sha256(whole file, streamed)
    header_range = (96+16+sig_il*16+align8(sig_dl),  … + 16+il*16+dl)
```

### C.6 changeset reprefix (D9)

```
cvmfs_changeset_reprefix(cs, prefix):
    validate prefix: absolute, no "..", components pass name rules
    for missing ancestors of prefix (repo-relative): prepend ADD_DIR entries
        (mode 0755, uid/gid 0, mtime=now) in parent-before-child order
    for each change: path = prefix + "/" + path   (bounds-checked)
    ordering invariant preserved: DELETEs stay first, ADDs stay
        parent-before-child (prefix ADD_DIRs sort before all)
```

## Appendix D — verified tar bytes

Generated with a pax-format writer and hex-dumped on 2026-08-17; the D6
corpus fixture generator reproduces exactly this. Entry:
`usr/bin/demo`, 11 bytes, mode 0755, mtime 1755388800.

```
off   bytes                                            field
0000  75 73 72 2f 62 69 6e 2f 64 65 6d 6f 00 …         name[100]  "usr/bin/demo"
0064  30 30 30 30 37 35 35 00                          mode[8]    "0000755\0"
006c  30 30 30 30 30 30 30 00                          uid[8]     "0000000\0"
0074  30 30 30 30 30 30 30 00                          gid[8]
007c  30 30 30 30 30 30 30 30 30 31 33 00              size[12]   octal 13 = 11
0088  31 35 30 35 30 32 31 35 36 30 30 00              mtime[12]  octal 15050215600
                                                                  = 1755388800 ✓
0094  30 31 32 30 33 33 00 20                          chksum[8]  "012033\0 "
009c  30                                               typeflag   '0' regular
0101  75 73 74 61 72 00 30 30                          magic+ver  "ustar\0" "00"
0109  72 6f 6f 74 00 …                                 uname[32]  "root"
0129  72 6f 6f 74 00 …                                 gname[32]  "root"
```

Verified pax extended-header example (same generator; long path + xattr —
the header block carrying it has typeflag `x` and its own name field holds
the writer convention `././@PaxHeader`, which readers ignore):

```
34 SCHILY.xattr.user.brix.demo=42
119 path=opt/really/quite/deeply/nested/path/that/overflows/the/one/hundred/byte/ustar/name/field/for/sure/demo-binary
```

Record-length check the C.3a rule performs: `"34 " (3) +
"SCHILY.xattr.user.brix.demo" (27) + "=" (1) + "42" (2) + "\n" (1) = 34` ✓.

Numeric encodings: plain fields are NUL/space-terminated octal ASCII;
**base-256** (first byte `0x80`-flagged, remainder big-endian binary) is
accepted for size/uid/gid/mtime — e.g. a 9 GiB size arrives as
`80 00 00 00 00 02 40 00 00 00 00 00` in the 12-byte field. Checksum =
unsigned byte sum of the 512-byte header with the chksum field replaced by
eight spaces (tolerate the historic signed variant). Compression magics
sniffed by `brix_tar_open_fd`: gzip `1f 8b`, zstd `28 b5 2f fd`.

## Appendix E — RPM byte walk

Lead (96 bytes, fixed):

| off | len | field |
|---|---|---|
| 0 | 4 | magic `ed ab ee db` |
| 4 | 1+1 | version major(3) / minor(0) |
| 6 | 2 | type (0 binary, 1 source) |
| 8 | 2 | archnum |
| 10 | 66 | name "n-v-r", NUL-padded |
| 76 | 2 | osnum |
| 78 | 2 | signature_type — **must be 5** (header-style) |
| 80 | 16 | reserved |

Header section preamble: `8e ad e8` + version `01` + 4 reserved bytes +
`il` (u32 BE, index-entry count) + `dl` (u32 BE, data-region bytes). Then
`il` × 16-byte entries `{tag u32, type u32, offset u32, count u32}` (all
BE), then `dl` data bytes. The signature header is padded to the next
8-byte boundary before the main header starts.

Worked index-entry decode (the C.5 accessor path):

```
00 00 03 e8  00 00 00 06  00 00 00 00  00 00 00 01
tag=1000     type=6       offset=0     count=1
= RPMTAG_NAME, STRING, data[0..] = "brix-demo\0"
```

Type extents for the bounds check: NULL 0 · INT8 1×n · INT16 2×n (align 2)
· INT32 4×n (align 4) · INT64 8×n (align 8) · STRING/I18NSTRING/
STRING_ARRAY = NUL-scan ×count within `dl` · BIN 1×n. Dependency sense
bits (REQUIREFLAGS/PROVIDEFLAGS): `LESS 0x02 · GREATER 0x04 · EQUAL 0x08`
(`flags="EQ"/"LE"/"GE"` in primary.xml); entries with the rpmlib bit
`0x1000000` are internal and filtered from emission (§D12.2). Payload
format/compressor (tags 1124/1125) are read for `brixrpm inspect` display
only — the payload is never decoded (pkgid hashes the whole file as an
opaque stream).

This appendix is the format reference; the **generated-and-verified
instance** — a real RPM built, walked byte-by-byte and cross-checked
against the system `rpm` — is Appendix Q, and its findings ledger amends
the D12 walker rules.

## Appendix F — per-lane test rosters (named functions, one-line intents)

Style follows `tests/test_cvmfs_stratum0_quickstart.py`: plain module-level
`def test_…` functions over a session fixture, `pytest.mark.parametrize`
for corpora, live-lab legs marked. Names below are the plan of record —
a lane that lands with different coverage updates this roster in the same
change.

**Delivered names differ from planned names, on purpose.** The roster was
written before the code; writing the tests found better names for most of
them (`test_strict_fails_on_devices` → `test_strict_refuses_device`,
`test_cross_repo_mount_201_without_reupload` →
`test_cross_repo_mount_publishes_without_moving_bytes`,
`test_official_client_mount_diffs_clean_vs_podman_export` →
`test_mounted_tree_diffwalks_clean_against_podman`, and so on), and several
planned parametrized corpora landed as named individual tests instead. The
2026-08-18 audit walked this roster property by property against the
delivered functions: every property is pinned somewhere, the nine that were
not are listed in the Status section, and `grep '^def test_' tests/test_oci_*.py
tests/test_rpm_*.py tests/test_cvmfs_ingest_*.py` is the authoritative index.
Two planned names have no counterpart by decision rather than by rename:
`test_pull_to_layout_validates_under_skopeo` (skopeo is not installable on
the target hosts — the layout is validated by our own reader in
`test_pull_creates_verified_layout`) and
`test_resume_after_cut_connection_via_range_probe` (the resume contract is
pinned by `test_patch_at_the_wrong_offset_reports_where_to_resume`, which
does not need a severed connection to assert it).

**`test_oci_mirror_classify.py`** (D0)
- `test_api_root_answers_locally` — 200 `{}`, zero mock hits
- `test_matrix_get_head_every_class_routes` — parametrized §0.7.1 sweep
- `test_shorthand_name_expands_to_one_namespaced_cache_key` — a single-component name fills once under the operator's namespace
- `test_tags_list_forwards_uncached_with_pagination` — `?n=&last=` verbatim, two GETs = two mock hits
- `test_write_methods_405_allow_header_and_ocipush_guard` — POST/PUT/PATCH/DELETE sweep
- `test_bad_name_shapes_400_name_invalid` — parametrized: 256 B, empty component, uppercase, `__`-abuse
- `test_bad_digest_400_digest_invalid` — non-hex, 63/65 chars, `sha512:` in v1
- `test_traversal_corpus_never_reaches_upstream` — the §D0.4 negative corpus, mock log length pinned at 0
- `test_classifier_fuzz_seed_corpus_survives` — delivered as a kernel in the
  protocol-fuzz lane rather than a lane of its own: `tests/fuzz/fuzz_oci_classify.c`
  + `corpus_oci_classify/` + a `BUILD_ARGS` row in `cmdscripts/fuzz_all.py`,
  run by `test_cmd_fuzz_all.py` under `-fsanitize=fuzzer,address,undefined`.
  The harness asserts what the callers rely on, not merely "did not crash":
  every reported span lies inside the URI, a name that classified re-validates
  and re-counts its components, a digest that classified is 64 lowercase hex,
  and a refusal always carries an error code to emit.

**`test_oci_mirror_authdance.py`** (D1)
- `test_cold_pull_one_dance_warm_reuse` — `/ctl/token_count` 1 → 1 → 2 after expiry
- `test_access_token_spelling_and_missing_expiry` — Quay spelling; absent `expires_in` → 60 s behavior
- `test_token_endpoint_failures_map_to_502` — 500 / timeout / garbage JSON
- `test_malformed_challenge_502_no_leak` — client never sees upstream challenge
- `test_toomanyrequests_echoed_with_retry_after`
- `test_cdn_redirect_strips_authorization` — second mock asserts header absent
- `test_third_party_realm_refused_no_egress` — no request leaves for it
- `test_basic_creds_only_to_allowlisted_realm` — with `brix_oci_mirror_auth`

**`test_oci_mirror_cachepolicy.py`** (D2)
- `test_cold_then_warm_pull_zero_upstream_data_hits`
- `test_media_type_roundtrip_all_four_manifest_kinds` — parametrized §0.7.3
- `test_if_none_match_304_local`
- `test_tag_fresh_serves_old_after_retag_until_ttl`
- `test_stale_revalidate_digest_equal_transfers_no_body`
- `test_upstream_down_fresh_serves__stale_marks__cold_502` — three legs
- `test_corrupt_fill_refused_guarded_then_recovers` — `signal=oci_tamper` pinned
- `test_wrong_digest_header_marks_unverified_sidecar`

**`test_oci_mirror_podman_pull.py`** (D3, live-lab, block 14120)
- `test_podman_pull_cold_and_warm_through_mirror`
- `test_warm_pull_survives_upstream_kill_switch`
- `test_podman_push_at_mirror_denied_and_guarded`
- `test_live_dockerhub_alpine_pull` — weekly tier, internet-marked

**`test_oci_registry_push.py`** (D4)
- `test_chunked_push_then_pullback_byte_identical`
- `test_monolithic_post_digest_shortcut`
- `test_cross_repo_mount_201_without_reupload`
- `test_resume_after_cut_connection_via_range_probe`
- `test_retag_between_two_manifests_is_never_seen_half_done` — 200 reads across a swap hammer, each body hashing to its own digest header
- `test_seal_wrong_digest_400_session_destroyed`
- `test_unknown_session_404__out_of_order_416__oversize_413` — three legs
- `test_manifest_missing_blob_400_names_digest`
- `test_an_idle_session_is_reaped_and_its_bytes_go_with_it` — the part-file's mtime backdated, the sweep run by the next session-creating request
- `test_anonymous_push_401_nothing_staged` — disk tree hash before/after
- `test_scoped_token_without_write_403_denied`
- `test_traversal_names_400_store_untouched`
- `test_manifest_over_the_document_cap_is_refused_before_it_is_parsed` — 4 MiB, refused on the declared length

**`test_oci_brixoci_copy.py`** (D5)
- `test_pull_to_layout_validates_under_skopeo` — oracle leg, live-lab
- `test_copy_mock_to_local_registry_offline`
- `test_push_roundtrip_and_tags_pagination`
- `test_platform_selection_and_no_match_lists_available`
- `test_corrupt_layout_blob_exit5_names_digest`
- `test_wrong_bytes_hash_refused_partial_unlinked`
- `test_world_readable_auth_file_refused`

**`test_oci_tar_corpus.py`** (D6) — `test_corpus_roundtrip[writer]`
(gnu/bsdtar/podman ×gzip/zstd/raw) · `test_long_names_links_pax_xattrs_base256`
· `test_hardlink_groups_and_all_typeflags` ·
`test_malformed[case]` (truncated header/body, bad checksum, bad pax len,
size overflow, zstd-without-zstd) ·
`test_oversized_pax_header_refused_before_it_is_parsed` and
`test_xattr_flood_on_one_entry_refused` (the two metadata bombs; the 160 KiB
pax byte cap is the bound that fires, `TAR_PAX_REC_MAX` the belt behind it) ·
the decompression-byte budget belongs to the flattener and is asserted
there.

**`test_oci_flatten.py`** (D7) — `test_three_layer_fixture_matches_expected_tree`
· `test_podman_export_diff_clean` (oracle: the same layer tars wrapped in a
hand-written OCI layout, `podman pull oci:` → `podman export`, diffed on
kind/mode/bytes/symlink target/inode groups — offline, skipped without podman) ·
`test_hardlink_across_layers_shares_the_inode` ·
`test_hardlink_to_a_whiteouted_target_is_refused` · `test_strict_fails_on_devices`
· `test_budget_abort_cleans_partial_upper` ·
`test_escape_corpus_confined[case]` (symlink-descend, dotdot in name and
pax path, absolute pax path, whiteout `../`, `.brix.`-smuggling, 1 M-entry).

**`test_cvmfs_ingest_image.py`** (D8, srv 13620) —
`test_ingest_mounts_and_matches_fixture` · `test_retag_is_one_symlink_publish`
(changeset length pinned) · `test_memo_noop_zero_data_plane_hits` ·
`test_dry_run_touches_nothing` · `test_registry_down_midfetch_repo_unchanged`
· `test_publish_crash_rerun_completes` (`$BRIXCVMFS_PUBLISH_CRASH`) ·
`test_corrupt_layer_nothing_published` · `test_foreign_path_collision_refused`.

**`test_cvmfs_ingest_dir.py`** (D9) — five tests over one module-scoped run
of `cmdscripts/cvmfs_ingest_dir.py` (two tool builds and a 10k-file publish
are not worth repeating per assertion), one per check group, covering:
`test_the_tools_build_standalone` ·
`test_a_folder_publishes_with_its_shape_intact` (I1: files, nested and empty
dirs, symlinks stored verbatim, dry-run) ·
`test_reingest_updates_in_place_and_delete_mirrors` (I2) ·
`test_every_refusal_leaves_the_old_revision_standing` (I3: reserved `.brix.*`
grammar, bad prefixes, `no_clobber` collision, busy lock exit 7, crash-resume,
empty prune ledger) · `test_ten_thousand_files_publish_inside_the_budget` (I4,
the wall-clock claim made falsifiable). A group that produced no results fails
as "never ran", so a build that did not compile cannot report green.

**`test_cvmfs_ingest_oracle.py`** (D10, srv 13640, live-lab) —
`test_official_client_mount_diffs_clean_vs_podman_export` ·
`test_podman_run_rootfs_executes` · `test_stratum0_down_mount_fails_no_wedge`
· `test_tampered_cas_object_refused_and_guarded`.

**`test_rpm_mirror_dnf.py`** (D11, block 14160, live-lab) —
`test_dnf_install_through_mirror_cold_then_upstream_dead` ·
`test_repomd_ttl_staleness_window` · `test_expired_metadata_upstream_down_errors_not_hangs`
· `test_wrong_gpg_key_dnf_refuses_end_to_end`.

**`test_rpm_createrepo.py`** (D12, block 14180) —
`test_dnf_installs_from_generated_repo` ·
`test_inspect_matches_rpm_qp[pkg]` (oracle, live-lab) ·
`test_update_rescans_only_touched` · `test_nonrpm_and_truncated_skip_vs_strict`
· `test_empty_dir_valid_empty_repo` · `test_fuzzed_header_corpus_clean_refusal`
· `test_traversal_basenames_sanitized_from_xml`.

**`test_rpm_cvmfs_compose.py`** (D13) — three tests over one module-scoped
run of `cmdscripts/rpm_cvmfs_compose.py`:
`test_dnf_installs_from_the_published_repo` (C1) ·
`test_republish_adds_a_package_and_the_old_snapshot_still_installs` (C2) ·
`test_a_tampered_rpm_in_the_tree_is_refused` (C3).

**`test_oci_compose_secure.py`** (D14, block 14200) —
`test_scvmfs_gated_private_image_authorized_pull` ·
`test_anonymous_denied_401_403_matrix` ·
`test_virtual_union_serves_image_repo_behind_main` ·
`test_wrong_token_403_terminal_no_fallthrough`.

## Appendix G — harness specs

### G.1 `tests/oci/mock_registry.py` control plane

CLI: `python3 -m tests.oci.mock_registry --port N [--auth [--token-port N]]
[--blob-redirect URL] [--push] [--seed N] [--webroot DIR]`.

| Endpoint | Method | Behavior |
|---|---|---|
| `/ctl/log` | GET | JSON request log: `[{method, path, headers-subset, ts}]` |
| `/ctl/reset` | POST | clear log, faults, upload transcripts (not the image set) |
| `/ctl/fault` | POST | `{"kind": K, "persist": bool}` — one-shot unless persist. K ∈ stall · reset · corrupt · truncate · wrong_length · http500 · slowdrip · **wrong_digest_header** · **retag** |
| `/ctl/token_count` | GET | `{"count": N}` tokens minted (D1 assertions) |
| `/ctl/retag` | POST | `{"name","tag","digest"}` — move a tag (D2 TTL lanes) |
| `/ctl/uploads` | GET | push-mode session transcripts (D4/D5 client tests) |

The redirect instance (`--blob-redirect` target) exposes
`/ctl/saw_authorization` → `{"count": N}` — the D1 security-negative reads
it and asserts 0.

### G.2 `tests/configs/oci_mirror.conf` (template text; placeholders per `render_config`)

```nginx
worker_processes 1;
daemon off;
error_log {ERROR_LOG} info;
pid {PID_FILE};
events { worker_connections 128; }
http {
    access_log {ACCESS_LOG};
    brix_kv_zone oci_tokens 1m key=32 val=4096;
    server {
        listen {BIND_HOST}:{PORT};
        location /v2/ {
            brix_oci_mirror          http://{BIND_HOST}:{MOCK_PORT};
            brix_oci_mirror_insecure on;            # mock speaks plain http
            brix_oci_manifest_ttl    {MANIFEST_TTL};
            brix_cache_store         {CACHE_ROOT};
            brix_cache_verify        require;
        }
    }
}
```

(Exact log/tempdir boilerplate follows whatever the neighbouring configs in
`tests/configs/` carry — copy a sibling, don't invent; `strict=True`
rendering catches a placeholder the lane forgot to supply.)
`oci_registry.conf` adds the `/local/v2/` location with `brix_oci_registry
on`, `brix_allow_write on` and the token-plane directives the dav-write
configs already use.

### G.3 Fleet entries (`tests/fleet_specs.py`, proposed verbatim)

```python
NginxInstanceSpec(
    name="oci_mirror",
    template="oci_mirror.conf",
    port=14110,
    protocol="http",
    extra_ports={"mock": 14100, "token": 14101, "redirect": 14102},
    readiness="tcp",
    tags=("oci",),
    reason="OCI pull-through mirror against the mock registry (Wave A).",
),
NginxInstanceSpec(
    name="oci_registry",
    template="oci_registry.conf",
    port=14150,
    protocol="http",
    extra_ports={"mock": 14140},
    readiness="tcp",
    tags=("oci",),
    reason="Local OCI push registry (Wave B lanes; podman/skopeo oracles).",
),
```

Ingest lanes (13620/13640) spawn their own instances via the cvmfs
conformance `LiveRun` pattern instead — the standing don't-mix-patterns
caveat (§0.8.3).

### G.4 Fixture generator (`tests/oci/fixtures/build_fixtures.py`)

Emits, deterministically from `--seed`: the tar corpus (GNU tar, bsdtar and
podman-writer variants × raw/gzip/zstd, incl. the Appendix-D entries), the
2-layer and 3-layer fixture images + one multi-arch index as OCI layout
dirs (consumed by mock_registry and the D7/D8 lanes), per-fixture
expected-tree JSON (entry → type/mode/content-sha256/xattrs), and the
malformed/bomb corpora. The tiny canonical set is committed; the generator
re-creates the rest at session start where the writer tools exist
(SKIP-not-FAIL legs otherwise). RPM fixtures: `tests/rpm/fixtures/` — two
committed micro-RPMs (noarch + x86_64, built once with rpmbuild, checked
in) plus generator-fuzzed header mutants.

## Appendix H — work breakdown (ordered sub-tasks, review gates)

Gates: **[std]** = coding-standards read + OP→FILE table check before the
first edit in an area · **[cfg]** = build-wiring (config/CMake/Makefile +
coverage guards) lands with the first `.c` · **[neg]** = the feature's
security-negative lane green before the success lane is trusted · **[doc]**
= ops/protocol doc stub in the same wave.

- **D0** — a. `shared/oci/{name,digest,mediatypes}` + unit lane [std][cfg] ·
  b. classifier kernel + fuzz seeds [neg] · c. module scaffold, directive
  fragments, EMERG matrix (`srv_config`-style negatives) · d. gate + mirror
  handler against mock (no auth yet) · e. lanes + port-map claim +
  `docs/04-protocols/oci.md` stub [doc].
- **D1** — a. challenge parser + realm allowlist, table-driven unit tests ·
  b. kv zone plumbing (`brix_oci_token_zone`) · c. dance in the fill thread,
  jansson token parse · d. redirect policy on the fill handle [neg first —
  the CDN-leak test exists before the code that could leak].
- **D2** — a. sidecar write/read (B.1) · b. class policy + tag revalidation ·
  c. forced-`require` verify wiring for digest objects [neg: corrupt-fill] ·
  d. serve-stale + headers echo + 304.
- **D3** — a. metric families + conformance-sweep registration · b. guard
  reasons + audit strings + fail2ban filters (same change) · c. podman lane
  [doc: oci-mirror.md complete, not stub].
- **D4** — a. store layout + link marks over VFS seam [std] · b. session
  machine over staged_file + B.2 checkpoint · c. manifest PUT validation ·
  d. DELETE + refcounts · e. auth wiring (INVARIANT #3 review) [neg] ·
  f. podman/skopeo push oracles.
- **D5** — a. *(Wave C)* ref parse + reg_client pull side + json_iter [cfg]
  · b. layout store · c. pull/copy/ls/tags verbs · d. *(Wave B)* push/rm
  verbs · e. auth-file handling [neg] · f. man/usage panels.
- **D6** — a. fixture generator + committed corpus **first** · b. header
  walk + numerics · c. pax/GNU overlays · d. decompressor sniff (zstd
  gated) · e. malformed/bomb corpus green under ASan [neg].
- **D7** — a. escape-corpus lanes written **before** the apply loop [neg
  first, by design] · b. descend/containment helpers · c. translation
  table + stats · d. podman-export diff oracle.
- **D8** — a. conductor pipeline (steps 1–5, dry-run) · b. graft + reprefix
  + publish + memo · c. crash/rerun lanes (`$BRIXCVMFS_PUBLISH_CRASH`) ·
  d. prune verb · e. `--verify-diffids` (A.4) — landed, over the reader's
  own decompression rather than a second inflate.
- **D9** — a. `cvmfs_changeset_reprefix` + unit lane · b. CLI verb +
  `--delete` opaque pre-pass · c. lanes incl. the wall-clock pin [doc:
  container-ingest.md covers both verbs].
- **D10** — a. compose harness (mock → ingest → serve → official mount) ·
  b. podman `--rootfs` leg · c. tamper leg.
- **D11** — a. TTL mechanism decision (open decision 1) + recipe conf ·
  b. dnf container lanes · c. rpm-mirror.md [doc].
- **D12** — a. header reader + bounds fuzz corpus [neg first] · b. tag
  accessors + NEVRA/deps extraction, `rpm -qp` differential · c. XML
  emission + repomd swap discipline · d. `--update` memo · e. dnf oracle.
- **D13** — a. runbook · b. composed lane.
- **D14** — a. example configs · b. secure/union lane · c. full-stack doc.

## Appendix I — sizing and budgets

### I.1 Token zone

Per-entry stride ≈ `key_max(32) + val_max(4096)` + entry header (tens of
bytes; exact arithmetic is kv.c's `table_bytes` = header +
capacity·stride). Default `oci_tokens 1m` ⇒ ≈ 250 slots ⇒ ≈ 125 live
tokens at the ≤ 0.5 load ceiling. One token per (upstream, scope) ≈ one per
actively-pulled repo per TTL window — 125 concurrent hot repos per default
zone; a busier site raises the directive. Zone exhaustion degrades to
re-dancing (correctness unaffected), visible as `token_fetch_total` slope.

### I.2 Fill-path memory & concurrency

Per in-flight fill: one curl handle + 64 KiB stream buffer + one SHA-256
ctx + < 8 KiB sidecar/headers assembly — no whole-object buffering
anywhere (bodies stream to part-files). Concurrency is bounded by the
existing thread-pool geometry; phase-104 adds no pool and no per-request
event-loop state beyond the classify struct (stack) and conf pointers.

### I.3 The "seconds" claim, decomposed (budget targets, not benchmarks)

```
ingest image (cold)  = resolve (1 RTT + dance) + fetch (Σbytes / link-bw)
                     + flatten (entries × ~20 µs + bytes / disk-bw)
                     + scan (entries × ~1 stat) + publish (touched-subtree
                       catalogs + compress+hash of new bytes) + 1 rename
  alpine-class (8 MB, ~520 entries — the real count, App. U): fetch ≈ 0.1 s ·
  flatten ≈ 0.2 s · scan ≈ 0.05 s · publish 2.0 s MEASURED  →  **< 3 s cold ✓**
ingest image (warm)  = 1 manifest HEAD + memo compare        → **< 0.3 s**
ingest dir (10 k files, 3 changed) = 0.34 s MEASURED         → **≪ 5 s ✓**
ingest dir (10 k files, ALL new)   = 10 s MEASURED on WSL2   → I/O-bound
                                     bulk import, after the V-3 lever
                                     (95 s with per-object fsync)
```

Appendix V holds the measurement transcript: the two ✓ rows are the
phase's headline claims and both survived contact with the real publish
binary; the bulk-import row replaced an earlier 2.9 s guess that did not.

The D9 lane pins only the generous CI floor (< 5 s for the 3-file delta);
the table above is the engineering budget that makes the phase's opening
sentence ("in seconds") falsifiable locally. Retag = 1-symlink changeset →
publish cost ≈ one catalog rewrite ≈ tens of ms + fsync.

### I.4 Mirror disk & eviction

Cache footprint ≈ Σ unique compressed layers pulled (indexes/manifests are
KBs; layers dominate). No new eviction machinery: the existing cache
quota/reaper applies per location — size the store for the site's working
set of images and let LRU do its job; `brix_oci_fill_bytes_total` vs quota
is the capacity-planning signal. Registry (D4) storage is *not* a cache —
it is primary data under the site's own retention (prune/rm), excluded
from any reaper by construction (different root).

## Appendix J — nginx server-integration blueprint (grounded in the tree)

Everything in this appendix was read off the working tree on 2026-08-17,
not off nginx folklore. It answers the one question the body's Wave A left
at arm's length: **exactly which existing seams does `src/protocols/oci/`
plug into, function by function?**

### J.0 The reading list (what was verified, where)

| File read | What it establishes for phase-104 |
|---|---|
| `src/protocols/cvmfs/handler.c` | The mirror handler's template end-to-end: gate → classify → serve, where serve is the shared **offload → coalesced-fill → `brix_vfs_open` → ranged-serve** composition; the `cvmfs_errno_status()` errno→HTTP convention; the `cvmfs_fill_fail` fill-failure interceptor precedent (G16) |
| `src/protocols/shared/http_cache_fill.h` | The shared fill entry: `brix_http_cache_fill_if_needed(r, …, on_fail)` (:70) with `brix_http_cache_reenter_pt` (:43) re-entry trampoline and `brix_http_fill_fail_pt` (:54) failure hook — **dogpile protection (coalesced fills) comes free** |
| `src/protocols/shared/http_serve_offload.h`, `file_serve.h` | Thread-pool offload + ranged file serving; honors INVARIANT #2 (TLS `b->memory=1` vs cleartext sendfile) so the OCI handler never touches a send path |
| `src/fs/cache/cache_http.h` | `brix_cache_file_ready(path)` → 1 serve / 0 miss / −1 stat error — the **HTTP-plane** hit check, deliberately free of stream types |
| `src/fs/cache/open_or_fill.c` | `brix_cache_open_or_fill(brix_ctx_t *, ngx_connection_t *, ngx_stream_brix_srv_conf_t *, …)` — the **kXR/STREAM plane**. Listed here as the anti-pattern: it takes stream conf + thread-task types the HTTP plane must not touch (§J.8) |
| `src/protocols/cvmfs/module.c` | Handler installation pattern: the enabling directive's parse callback sets `clcf->handler` (:310); module ctx (:285); `create_loc_conf`/`merge_loc_conf` registration (:292–293) |
| `src/protocols/cvmfs/cvmfs_module_internal.h` | The module-split seam: `module.c` stays a thin registration TU, heavyweight merge/build logic lives in sibling TUs (`cvmfs_merge_cache` = the enabled-branch export/backend/cache build) |
| `src/core/shm/kv.h` | `brix_kv_zone <name> <size> key=<n> val=<n>;` (:105) — the token cache is configuration sugar, not a new SHM mechanism |

### J.1 The serve/fill composition — reuse, verbatim

The cvmfs handler's GET path *is* the OCI mirror's GET path with a
different classifier and a different fill URL. The composition:

```
ngx_http_brix_oci_handler(r)
  ├─ gate: method GET|HEAD else 405 (mirror surface; registry adds the rest)
  ├─ oci_classify(decoded URI) → {kind, name, ref/digest}   (D0, App. C.1)
  ├─ oci_gate: auth per location (existing token/x509 machinery, INVARIANT #3)
  ├─ key = canonical cache key (§D2.3) → cache path under the tier
  ├─ brix_cache_file_ready(path)                      [cache_http.h]
  │     1 → serve            0 → fill            −1 → errno→HTTP (§J.5)
  ├─ fill: brix_http_cache_fill_if_needed(r, …, oci_reenter, oci_fill_fail)
  │     [http_cache_fill.h:70 — coalesced: N concurrent pulls of one blob
  │      produce ONE upstream fetch; the rest park on the fill and re-enter
  │      via the trampoline, exactly as cvmfs catalogs do today]
  │     the fill transport is the sd_http upstream with the D1 Bearer token
  │     injected; digest verify-at-edge (D2) runs in the fill, so a corrupt
  │     object never becomes cache-visible
  └─ serve: offload decision [brix_sd_cache_fill_needs_offload] →
            brix_vfs_open → ranged serve [file_serve.h]
            (Range/If-None-Match/HEAD semantics inherited, zero new code)
```

Two consequences worth stating because they delete design work the body
had provisionally budgeted:

1. **No dogpile design needed.** "Registry mirror gets hammered by a
   500-node farm pulling the same image" is the coalesced-fill case the
   shared helper already exists for. D3's stampede test becomes a
   *verification* of inherited behavior, not a test of new code.
2. **No send-path code at all.** Ranged blob serving, HEAD, sendfile vs
   TLS-memory buffers — all inside `file_serve.h`/offload helpers. The OCI
   module's original C is: classifier, gate, key derivation, token dance,
   digest verify, error mapping. That is the whole Wave-A surface.

### J.2 Module skeleton and handler installation

`src/protocols/oci/oci_module.c` copies the cvmfs registration shape
(module.c:285–310):

- `ngx_http_module_t` ctx with `create_loc_conf` / `merge_loc_conf` only —
  no postconfiguration handler-injection; **the enabling directive installs
  the handler** in its parse callback (`clcf->handler =
  ngx_http_brix_oci_handler`), the tree's pattern for opt-in content
  handlers. A location without `brix_oci_mirror`/`brix_oci_registry` is
  byte-for-byte untouched nginx — the fail-closed gate is structural, not
  a runtime flag test.
- `module.c` stays thin (registration, directive table, trivial setters);
  the enabled-branch merge work — resolving the token zone, building the
  upstream, validating the EMERG matrix (§0.6.2) — lives in
  `oci_merge.c` behind `oci_module_internal.h`, mirroring the
  `cvmfs_merge_cache` split so `check_file_size`/`check_complexity`
  budgets hold from day one.

### J.3 The loc_conf and its merge rules

```c
typedef struct {
    /* mirror surface (D0–D2) */
    ngx_flag_t            mirror;          /* brix_oci_mirror on|off */
    ngx_str_t             upstream_url;    /* brix_oci_upstream */
    ngx_str_t             upstream_ns;     /* brix_oci_upstream_namespace */
    ngx_str_t             auth_file;       /* brix_oci_upstream_auth (basic) */
    ngx_msec_t            manifest_ttl;    /* brix_oci_manifest_ttl */
    ngx_str_t             token_zone_name; /* brix_oci_token_zone */
    brix_kv_t            *token_zone;      /* resolved in merge (enabled branch) */
    brix_oci_upstream_t  *up;              /* built in merge (enabled branch) */
    /* registry surface (D4) */
    ngx_flag_t            registry;        /* brix_oci_registry on|off */
    ngx_str_t             store_root;      /* brix_oci_store_root */
    size_t                max_blob;        /* brix_oci_max_blob_size */
    ngx_msec_t            upload_grace;    /* brix_oci_upload_grace */
} ngx_http_brix_oci_loc_conf_t;
```

| Field | create default | merge rule | EMERG when |
|---|---|---|---|
| `mirror`, `registry` | `NGX_CONF_UNSET` | `ngx_conf_merge_value(…, 0)` | both on in one location |
| `upstream_url` | null str | `ngx_conf_merge_str_value(…, "")` | `mirror on` and empty (§0.6.2 row 1) |
| `manifest_ttl` | `NGX_CONF_UNSET_MSEC` | merge, default 60 000 ms | — |
| `token_zone_name` | null str | merge, default `""` (= anonymous-only upstream OK, no token caching for authed) | named zone not declared by `brix_kv_zone` |
| `auth_file` | null str | merge; file read **at parse time** (secrets never re-read per request), perms `!= 0600` → EMERG | unreadable |
| `store_root` | null str | merge | `registry on` and empty, or path fails `resolve_path()` probe |
| `max_blob` | `NGX_CONF_UNSET_SIZE` | merge, default 0 = tier quota governs | — |
| `upload_grace` | `NGX_CONF_UNSET_MSEC` | merge, default 3 600 000 ms | — |

Merge-time building (`oci_merge.c`, enabled branch only): parse
`upstream_url` into the `brix_oci_upstream_t` (host, port, TLS, base
path), resolve `token_zone` against the declared kv zones, and run the
full §0.6.2 EMERG matrix. Disabled branch does nothing — config-parse cost
for non-OCI deployments is one flag merge.

### J.4 Fill failure → OCI error bodies (the `on_fail` hook)

`brix_http_fill_fail_pt` (http_cache_fill.h:54) is invoked when the fill
cannot produce a servable object; the cvmfs handler's `cvmfs_fill_fail`
maps catalog-fetch failures today. The OCI mirror's `oci_fill_fail`
translates fill outcome → the §0.7.6 error-code JSON the docker/podman
clients actually parse:

| Fill outcome | Client sees | Body `code` |
|---|---|---|
| upstream 401/403 after a completed token dance | 403 | `DENIED` |
| upstream 404 | 404 | `MANIFEST_UNKNOWN` / `BLOB_UNKNOWN` by kind |
| upstream 429 | 429 + relayed `Retry-After` | `TOOMANYREQUESTS` |
| upstream 5xx / transport error (connect, TLS, timeout) | 502 | `UNAVAILABLE` — and if a **stale** cached manifest exists inside the serve-stale window (§D2.2), serve it instead with `Warning: 110` |
| digest mismatch at verify-at-edge | 502 (never cached, `oci_tamper_total`++) | `UNAVAILABLE` |
| token endpoint unreachable/malformed | 502 | `UNAVAILABLE` |

The serve-stale check lives *in the interceptor*, not in the hot path:
hits never pay for it, and the offline-registry semantics pinned in §D2.2
fall out of one branch here.

### J.5 errno → HTTP (convention #3, `cvmfs_errno_status` flavor)

Local filesystem errors (cache tier, registry store) map per the tree's
convention — origin trouble is a *gateway* error, local misconfiguration
is not:

| errno | Mirror (read) | Registry (write) | Note |
|---|---|---|---|
| `ENOENT` `ENOTDIR` `ENAMETOOLONG` | 404 | 404 (`BLOB_UNKNOWN`) | |
| `EACCES` `EPERM` `ELOOP` `EXDEV` | 403 | 403 (`DENIED`) | `ELOOP`/`EXDEV` = containment tripwire, also logged at WARN with `signal=oci_path_escape` |
| `EIO` | 502 | 500 | convention #3: read-side EIO = backing trouble |
| `ENOSPC` `EDQUOT` | 502 | **507** | 507 Insufficient Storage — already in the tree's WebDAV vocabulary; honest to pushing clients |
| `EEXIST` (store put collision) | — | treated as success | CAS immutable-put idempotency, same ruling as publish |
| anything else | 500 | 500 | + ALERT log, `oci_internal_errors_total`++ |

### J.6 The `$oci_cache` disposition variable

Modeled on `$cvmfs_cache` (handler.c records the fill disposition for the
access log). Values: `hit` · `fill` (this request fetched) · `wait` (parked
on a coalesced fill) · `reval` (tag manifest revalidated upstream) ·
`stale` (served past TTL under J.4's offline branch) · `error`. Registered
in `oci_module.c` preaccess-free (pure log-time variable). The D3 metrics
and this variable must agree by construction — both read the same
disposition enum off the request ctx, so the Grafana panel and the access
log can never tell different stories.

### J.7 D4 upload-session state × event matrix (normative)

States live in the session sidecar (App. B.3); transitions are the whole
push protocol. `—` = 400 `UNSUPPORTED`; rows are current state.

| State \ Event | `PATCH` (offset = size) | `PATCH` (offset ≠ size) | `GET` session | `PUT ?digest=` (match) | `PUT` (mismatch) | `DELETE` | grace expiry |
|---|---|---|---|---|---|---|---|
| **OPEN** (created, 0 bytes) | → ACTIVE, 202 | 416 + `Range: 0-0` | 204 `Range: 0-0` | → SEALED (empty blob legal) | 400 `DIGEST_INVALID` | → ABORTED, 204 | → REAPED |
| **ACTIVE** (n bytes staged) | append, 202 | 416 + `Range: 0-<n-1>` (client resumes) | 204 `Range: 0-<n-1>` | hash staged file server-side; match → rename into store, SEALED, 201 | 400 `DIGEST_INVALID`, stays ACTIVE (client may re-PUT) | → ABORTED, 204 | → REAPED |
| **SEALED** | 404 (session gone) | 404 | 404 | 404 | 404 | 404 | n/a (sidecar removed at seal) |
| **ABORTED / REAPED** | 404 | 404 | 404 | 404 | 404 | 404 | sidecar+staging unlinked |

Concurrency rule: one writer per session (session id is
single-client-issued; a concurrent `PATCH` on the same id hits the
staged-file `O_EXCL` advisory lock → 409). Reaper = the `upload_grace`
sweep, walking the staging dir mtimes — no timers per session, no SHM.

Two measured amendments (App. Y): real layer `PATCH`es arrive
`Transfer-Encoding: chunked` with **no Content-Range and no
Content-Length** (Y-2) — the append path streams on a running byte
counter, and `max_blob` is enforced against that counter, never a
header; and the `PUT ?digest=` value arrives **percent-encoded**
(`sha256%3A…`, Y-1) — decode before comparing, or every real push
fails the seal.

### J.8 Anti-patterns — wiring the blueprint forbids

- **Never call `brix_cache_open_or_fill`** (open_or_fill.c) from the OCI
  module: it is the kXR/stream plane (`brix_ctx_t`,
  `ngx_stream_brix_srv_conf_t`, stream thread-task). The HTTP-plane pair
  is `brix_cache_file_ready` + `brix_http_cache_fill_if_needed`, full stop.
- **Never install the handler from postconfiguration** — that would make
  every location pay an OCI flag test; the directive-installs-handler
  pattern keeps disabled deployments structurally untouched.
- **Never open/read/sendfile directly** in `oci_mirror.c`/`oci_registry.c`:
  serving is `file_serve.h`'s job (INVARIANT #2), storage I/O is
  `brix_vfs_*` (INVARIANT #12) — raw syscalls in `src/protocols/oci/`
  will (correctly) fail `check_vfs_seam.py`.
- **Never put the Accept header into the cache key** (pinned in App. A.2)
  — the media type is stored in the sidecar and echoed; keying on Accept
  would shard the blob cache per client generation.

## Appendix K — proposed public headers, verbatim (house style)

Drafted in the WHAT/WHY/HOW comment style of `shared/cvmfs/publish/publish.h`
so Wave-C review starts from a real header, not a sketch. Signatures match
the body (§D6.1, §D7.2); names remain subject to coding-standard review.

### K.1 `shared/oci/tar.h`

```c
/* tar.h — streaming pull-parser for OCI layer archives (phase-104 D6).
 *
 * WHAT: iterate a (possibly gzip/zstd-compressed) ustar/pax/GNU tar stream
 *       from an fd, one entry at a time, with pax and GNU-long overrides
 *       resolved before the entry is handed to the caller.
 * WHY:  tool-surface only — links into brixcvmfs/brixoci, never nginx
 *       workers (same G14 ruling as the publish engine). The flattener
 *       (flatten.h) and the ingest personality are the only callers.
 * HOW:  one 512-byte header buffer + one 64 KiB body window + decompressor
 *       state; memory is flat in archive size. brix_tar_next() refuses to
 *       advance until the current body is fully read or skipped — desync
 *       is an API-misuse error (-1), never a silent re-frame.
 */
#ifndef BRIX_OCI_TAR_H
#define BRIX_OCI_TAR_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    BRIX_TAR_REG, BRIX_TAR_DIR, BRIX_TAR_SYMLINK, BRIX_TAR_HARDLINK,
    BRIX_TAR_CHR, BRIX_TAR_BLK, BRIX_TAR_FIFO
} brix_tar_type_t;

typedef struct {
    char            path[4096];      /* pax/GNU-long resolved, NUL-terminated */
    char            linkname[4096];
    brix_tar_type_t type;
    int64_t         size;
    mode_t          mode;
    int64_t         mtime;
    uid_t           uid;
    gid_t           gid;
    dev_t           rdev;
    const char     *xattr;           /* packed name\0value pairs — the
                                        changeset.h wire format, so layer
                                        xattrs flow to publish unchanged */
    size_t          xattr_len;
} brix_tar_entry_t;

typedef struct brix_tar_s brix_tar_t;

/* Sniffs the leading magic: 1f 8b → gzip, 28 b5 2f fd → zstd (refused with
 * a clear message unless built with BRIX_HAVE_ZSTD), else raw tar. Takes
 * ownership of nothing; fd stays the caller's. NULL + err on failure. */
brix_tar_t *brix_tar_open_fd(int fd, char *err, size_t errlen);

/* 1 = entry produced, 0 = clean EOF (two zero blocks, or one + EOF),
 * -1 = malformed archive or body-not-consumed misuse (err says which). */
int  brix_tar_next(brix_tar_t *t, brix_tar_entry_t *e);

/* Read up to n bytes of the current entry body; 0 at body end, -1 error. */
int  brix_tar_read(brix_tar_t *t, void *buf, size_t n);

/* Discard the rest of the current body (decompressing as needed). */
int  brix_tar_skip(brix_tar_t *t);

void brix_tar_close(brix_tar_t *t);

#endif /* BRIX_OCI_TAR_H */
```

### K.2 `shared/oci/flatten.h`

```c
/* flatten.h — apply one OCI layer to an overlay upper tree (phase-104 D7).
 *
 * WHAT: stream a layer archive through tar.h and materialize it into an
 *       upper directory in the repository overlay grammar: OCI ".wh."
 *       whiteouts become BRIX_OV_WH_PREFIX markers, ".wh..wh..opq"
 *       becomes the opaque marker, so cvmfs_changeset_scan() sees an
 *       ingested image exactly as it sees a hand-edited upper tree.
 * WHY:  the bridge that makes `brixcvmfs ingest image` a *front-end* to
 *       the phase-96 publish plane instead of a second publisher.
 * HOW:  every write descends from an O_DIRECTORY dirfd on upper_dir with
 *       per-component O_NOFOLLOW openat — never a joined string path — so
 *       a layer that plants a symlink in layer N and writes through it in
 *       layer N+1 hits the containment wall (EXDEV-class refusal), the
 *       changeset.c discipline in reverse. Entries whose own name trips
 *       brix_ov_name_reserved() are refused: layers do not get to spell
 *       our marker grammar.
 */
#ifndef BRIX_OCI_FLATTEN_H
#define BRIX_OCI_FLATTEN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    const char *upper_dir;        /* exists; empty or mid-accumulation */
    int64_t     max_total_bytes;  /* 0 = unlimited; decompression-bomb budget */
    int64_t     max_entries;      /* 0 → default 1M */
    int         strict;           /* devices/fifos fatal instead of counted */
    uid_t       squash_uid;       /* --squash-owner … */
    gid_t       squash_gid;
    int         squash;
} brix_flatten_opts_t;

typedef struct {
    int64_t files, dirs, links, whiteouts, opaques, skipped_special, bytes;
} brix_flatten_stats_t;

/* Apply one layer (manifest order; base first). 0 ok with st populated,
 * -1 with err on refusal (containment trip, marker smuggling, budget
 * exhaustion, malformed archive). The upper tree is left as-is on failure:
 * callers treat the whole ingest scratch dir as disposable (D8 reaps it). */
int brix_flatten_layer(const brix_flatten_opts_t *o, int layer_fd,
                       brix_flatten_stats_t *st, char *err, size_t errlen);

#endif /* BRIX_OCI_FLATTEN_H */
```

## Appendix L — consolidated threat model

One table per attack surface. *Residual* = what the design consciously
does **not** defend and where that is written down.

### L.1 Mirror surface (D0–D3)

| Adversary / vector | Control | Residual |
|---|---|---|
| Client smuggles path tricks through `/v2/` (`..`, `%2f`, doubled slashes, digest-shaped garbage) | Classifier parses the **decoded** URI against the closed §0.7.2 grammar; anything unparseable → 404 before any upstream or filesystem contact (D0 security-negatives) | — |
| Compromised upstream/CDN serves wrong bytes for a digest | Verify-at-edge in the fill: sha256 mismatch → never cache-visible, 502, `oci_tamper_total`++ (J.4) | **Tag** manifests have no client-supplied digest; first fetch is trust-on-first-fetch, sidecar records what was seen — documented in §D2.2 |
| Malicious `WWW-Authenticate` challenge steers the token dance to an attacker realm | The realm host must satisfy the derived rule (the upstream host, its registrable parent, or a sibling under that parent) or be named verbatim by `brix_oci_upstream_auth_realm` — **delivered in both halves as of §D15.11**; every redirect hop of the token leg is re-checked, and a refusal is `signal=oci_realm_refused` | — |
| Token/credential leakage on redirect | `Authorization` stripped on any cross-host redirect in the fill transport (existing sd_http discipline, re-asserted in D1 tests) | — |
| Cache poisoning via key collision | Canonical key is injective (§D2.3: kind/name/ref components length-prefixed); digest path components validated hex before touching the tier | — |
| DoS: gigantic blob fills | Whole-object fills bounded by the cache tier's existing quota/eviction; per-fill no new budget in v1 | A single blob larger than the tier is a config-sizing problem, WARN-logged — §I.3 sizing table is the operator guidance |
| DoS: fill stampede | Coalesced fills (J.1) — one upstream fetch per object regardless of client count | — |
| Upstream rate-limit exhaustion (429) | Relayed verbatim with `Retry-After` + `oci_upstream_429_total` for alerting; configured mirror credentials raise the ceiling | The mirror does not queue/retry on the client's behalf (deliberate: §0.3 prime directive "the mirror lies about nothing") |

### L.2 Registry surface (D4–D5)

| Adversary / vector | Control | Residual |
|---|---|---|
| Unauthenticated push | `brix_oci_registry on` without an auth directive in scope = EMERG at parse (§0.6.2); write ops additionally require `brix_allow_write` **before** token scope (INVARIANT #3 ordering) | — |
| Path traversal via repository name / session id | Name grammar is the classifier's (closed set); session ids are server-minted UUIDs, never client-echoed paths; store paths pass `resolve_path()` (INVARIANT #4) | — |
| Digest spoof at seal | `PUT ?digest=` triggers a full server-side hash of the staged file; mismatch → 400, blob never enters the store (J.7) | — |
| Manifest referencing blobs the pusher never uploaded | Manifest PUT verifies every referenced digest exists in this repo's store (or is cross-mounted with proven read access on the source repo) | Referrers/artifact graphs are out of scope v1 (§Non-goals) |
| Storage exhaustion via abandoned uploads | `upload_grace` reaper unlinks stale sessions (J.7); `max_blob` caps a single upload; tier quota is the backstop | Unreferenced sealed blobs are reclaimed by the `brixoci gc` pass (§D15.3), whose `--grace` window is what keeps it from racing an in-flight push — run by an operator, or by `brix_oci_gc_interval` on the same kernel (§D15.5) where there is nobody to run it |
| Tag race (two pushers retagging) | Tag write is staged-file + atomic rename; last writer wins, both writes are durable and logged | No CAS-compare-and-swap tag API in v1 (spec has none either) |

### L.3 Ingest surface (D6–D10)

| Adversary / vector | Control | Residual |
|---|---|---|
| Hostile layer escapes the upper tree (symlink swap, `..`, absolute paths) | dirfd + per-component `O_NOFOLLOW` containment (K.2/§D7.3), same wall as changeset.c | — |
| Layer smuggles `.brix.*` marker names to forge whiteouts | `brix_ov_name_reserved()` refusal (overlay.h:60) — fatal, not skipped | — |
| Decompression bomb / entry-count bomb / pax-record CPU bomb | `max_total_bytes`, `max_entries`, per-entry pax record cap (§D6.3/§D6.4-3) | — |
| Registry MITM during pull-for-ingest | TLS verify on by default **plus** the digest chain: manifest digest pins config and layer digests, each verified on receipt — a tampered byte anywhere breaks the chain. `--require-digest` (§D15.12.1) refuses a reference that is not `@sha256:`-pinned, before the first request | Pull **by tag** pins nothing above the manifest: the chain proves the tree matches the manifest we *resolved*, not that it is the one the operator meant. Without the flag, a repointed tag is legitimate-looking drift the memo records but nothing refuses |
| Crash mid-publish corrupts the repo | Inherited: `cvmfs_publish_run` swaps `.cvmfspublished` last, CAS puts idempotent (publish.h) — ingest adds only disposable scratch | — |

### L.4 RPM surface (D11–D13)

| Adversary / vector | Control | Residual |
|---|---|---|
| Fuzzed/hostile RPM headers | Bounds-checked walk (App. C.5/E): il/dl caps, offset-in-range, alignment honored, string-region NUL-scan — ASan lane + `corpus_rpm_header` fuzzing | — |
| Metadata path traversal via crafted filename tags | DIRNAMES/BASENAMES joined then rejected on `..`/absolute before entering primary.xml | — |
| Package trust | **Unchanged model:** the mirror/createrepo plane never signs and never strips signatures — dnf's GPG check against the distro key is end-to-end through us | We do not sign repomd.xml in v1 (`repo_gpgcheck=0` documented in the D13 runbook) |

## Appendix M — INVARIANTS compliance matrix

Phase-wide answer for each of the 12 (CLAUDE.md keywords, full text in the
extended guide). *Ruling* is what the implementer must uphold; guards
column names the CI that will catch a violation.

| # | Invariant (keyword) | Phase-104 ruling | Caught by |
|---|---|---|---|
| 1 | pgread/pgwrite CRC32c framing | **N/A** — no root-protocol changes anywhere in D0–D15 | — |
| 2 | TLS `b->memory=1` vs cleartext sendfile | Inherited whole: OCI serves only through `file_serve.h`/offload helpers (J.1); no new send path exists to get wrong | `check_http_helper_reimpl` |
| 3 | `allow_write` before token scope | Registry mutations (D4) gate on `brix_allow_write` first, token scope second — enforced in `oci_gate.c`, tested in every D4 security-negative | review + F-lane tests |
| 4 | `resolve_path()` before every `open()` | Registry store + ingest scratch resolve; mirror cache paths are tier-derived from validated keys (the tier plane already resolves) | `check_vfs_seam` (path helpers ride the seam) |
| 5 | Collection DEL/MOVE/COPY recursive child locks | **N/A** — `/v2/` has no WebDAV collection semantics; registry DELETE touches single manifest/tag objects | — |
| 6 | S3 SigV4 ≠ WLCG token auth | Untouched; the new upstream Bearer dance is outbound-only and never enters either inbound auth path | — |
| 7 | stat via handle metadata | Inherited via shared serve helpers | — |
| 8 | Low-cardinality metric labels | §D3.1 label sets are closed enums (kind, disposition, code-class); **repository name is never a label** | `check_metric_cardinality`, `check_metric_names` |
| 9 | `crc64` ≠ `crc64nvme`, encode at edge | N/A to OCI (sha256-only, §0.0); no checksum-name surface added | — |
| 10 | SHM mutex spin+yield, create via `brix_shm_table_*` | Token cache is a `brix_kv_zone` (kv.h:105) — the compliant machinery, no bare `ngx_shmtx_create` anywhere in the phase | `check_shm_mutex` |
| 11 | Native TPC SHM registry vs WebDAV TPC curl | Untouched | — |
| 12 | VFS sole storage truth | `src/protocols/oci/*` and `oci_store.c` use `brix_vfs_*` exclusively; `shared/oci/` + `client/` tar/flatten code is **tool-surface** (raw syscalls legal there, the `shared/cvmfs/publish/` precedent — the seam guard's scope is `src/`) | `check_vfs_seam` |

## Appendix N — CI-guard integration map

What each existing guard (tools/ci/) demands of phase-104 code, plus the
new corpora the phase contributes. `guard_set.py` is the single source of
truth for which guards run in CI (`.github/workflows/guards.yml`) vs
pre-push — **new guards and corpora must be registered there**, not just
dropped in the directory.

| Guard | Phase-104 obligation |
|---|---|
| `check_config_coverage.py` | Every new `src/protocols/oci/*.c` and `shared/rpm/*.c` server-linked TU listed in repo-root `./config` — the build wiring row of every H-task's `[cfg]` gate |
| `check_client_build_coverage.py` | Every new `client/**/*.c` **and `shared/oci/*.c`, `shared/rpm/*.c`** tool-linked TU listed in `client/Makefile` (shared/{cvmfs,cache} precedent extends to shared/oci) |
| `check_vfs_seam.py` | Raw data syscalls in `src/protocols/oci/` are violations; `brix_vfs_*` or a justified same-line `/* vfs-seam-allow: … */`. Tool-surface `shared/oci/` is outside its scope (M#12) |
| `check_metric_cardinality.py` / `check_metric_names.py` | The §D3.1 families: closed label sets, `brix_oci_*`/`brix_rpm_*` naming, docs⇄C agreement (the commit-38714b18 regime: docs cannot invent a family) |
| `check_ports_doc.py` | The §0.8 port claims (14100–14200 OCI neighborhood, 13620/13640 ingest) land in `docs/10-reference/test-fleet-ports.md` in the same change that claims them in `fleet_specs` |
| `check_template_refs.py` | New `tests/configs/oci_*.conf` templates: every `{PLACEHOLDER}` consumed, every template referenced by a spec |
| `check_file_size.py` (<600) / `check_complexity.py` | The §0.5 per-file LOC budgets were drawn under these caps; the J.2 module split exists so they hold |
| `check_duplication.py` | Classifier/gate must not clone cvmfs classify/gate code — shared shapes get promoted to `protocols/shared/`, not copied |
| `check_http_helper_reimpl.py` | No hand-rolled serving/range/ETag code in oci handlers (J.8) |
| `check_shm_mutex.py` | Token zone via kv only (M#10) |
| `check_brix_namespace.py` | All new externs `brix_`/`ngx_http_brix_` prefixed (§0.5 names already comply) |
| `asan.py` lanes | D6/D7/D12 parser kernels are the archetypal ASan customers: the malformed corpora of §D6.4/§E run under ASan in the slow tier |
| `fuzz_corpus_writeback.py` | New corpora follow the `tests/fuzz/corpus_*` convention: **`corpus_oci_classify`** (D0 URI grammar) · **`corpus_oci_challenge`** (D1 WWW-Authenticate parser) · **`corpus_tar_header`** (D6 ustar/pax) · **`corpus_rpm_header`** (D12 header walk). Seeds = the App. D/E byte walks + §D6.4-3 malformed set |
| `codechecker` ratchet | New TUs enter at zero-finding baseline; the ratchet only tightens |

Registration checklist (one H-task, Wave A): corpora seeded → fuzz
targets added beside the existing harnesses → `guard_set.py` entries →
`guards.yml` lane mapping → one green full-guard run recorded in §Status.

**Delivered 2026-08-18.** All four kernels exist and run:
`fuzz_oci_classify` (D0 route grammar, links `oci_classify.c` +
`shared/oci/{name,digest}.c`), `fuzz_oci_challenge` (D1),
`fuzz_tar_header` (D6 — the reader hands layer xattrs on in the changeset
wire format, so `shared/cvmfs/catalog/` links with it), and
`fuzz_rpm_header` (D12.2, seeded from the three built fixtures plus the
twelve `tests/rpm/rpm_corrupt.py` mutants — offset past `dl`, `count`
wrap, type confusion, absurd `il`/`dl`, three truncations, bad magic,
traversal `DIRNAMES`, dangling `DIRINDEXES`). Each harness asserts the
contract its callers rely on, not merely the absence of a crash: spans
inside the input, fields NUL-terminated, `nfiles()` walkable to its end.
Registered in `cmdscripts/fuzz_all.BUILD_ARGS`, documented in
`tests/fuzz/README.md`, and therefore carried by the existing
`.github/workflows/fuzz.yml` lane (blocking on PR, nightly at 600 s, with
the corpus-writeback job minimizing the new corpora like the others) —
no `guard_set.py` or `guards.yml` change was needed, since that lane
already runs the whole `BUILD_ARGS` roster. Fourteen targets green at
`FUZZ_TIME=5`; the four new ones were additionally run 180 s each with no
finding.

## Appendix O — operator day-in-the-life (end-to-end walkthrough)

The whole phase in one sitting, as the site operator will actually drive
it. Commands and outputs are the acceptance shape for the D3/D10/D13
oracle lanes; expected timings come from the §I budgets.

### O.1 Bring up the mirror (Wave A)

```
# /etc/brix/nginx.conf — the §0.6.4 mirror block, verbatim
$ objs/nginx -t && systemctl reload brix-nginx

# point podman at it (per-host drop-in, no daemon config)
$ cat /etc/containers/registries.conf.d/brix-mirror.conf
[[registry]]
location = "docker.io"
[[registry.mirror]]
location = "mirror.example.org:8443"

$ podman pull docker.io/library/alpine:3.20
Trying to pull docker.io/library/alpine:3.20...
Getting image source signatures
Copying blob sha256:b2b2… done
...

# second pull anywhere on the farm: all hits
$ grep oci_cache /var/log/brix/access.log | tail -2
… GET /v2/library/alpine/manifests/3.20 200 oci_cache=reval
… GET /v2/library/alpine/blobs/sha256:b2b2… 200 oci_cache=hit
```

### O.2 Container → CVMFS (Wave C, the headline)

```
$ brixcvmfs ingest image docker.io/library/alpine:3.20 \
      --repo /srv/cvmfs/sw.example.org --prefix /images/alpine/3.20
resolved   docker.io/library/alpine:3.20 → sha256:c64c687c… (linux/amd64,
           index sha256:d9e853e8… — the real digests, captured in App. R)
fetched    1 layer, 3.5 MiB (via mirror.example.org — cache hit)
flattened  517 entries (the counted alpine:3.20 layer — App. U; earlier
           drafts guessed 3 481, off by 7×)
published  revision 42 in 2.1 s      (measured for this tree class — App. V)

# unchanged re-ingest is a memo no-op
$ brixcvmfs ingest image docker.io/library/alpine:3.20 --repo … --prefix …
unchanged  layer set matches memo (sha256:c64c687c…) — nothing to publish

# run straight off the mounted repo, no image store on the node at all
# (this command was executed for real against a hand-flattened alpine — App. U.3)
$ podman run --rootfs /cvmfs/sw.example.org/images/alpine/3.20 \
      /bin/cat /etc/alpine-release
3.20.10
```

### O.3 Folder → Tier-0 in seconds (D9, the quick path)

```
$ ls ./mytool-build/    # ordinary directory, 10k files
bin/ lib/ share/
$ brixcvmfs ingest dir ./mytool-build \
      --repo /srv/cvmfs/sw.example.org --prefix /sw/mytool/1.2 --delete
scanned    10 212 entries · changeset: 10 212 adds
published  revision 43 in 10 s       (cold bulk import, I/O-bound — App. V,
                                      with the fsync-batching lever V-3)

# day-2 — edit three files and republish: THIS is the quick path
$ vi src/… && make && brixcvmfs ingest dir ./mytool-build \
      --repo /srv/cvmfs/sw.example.org --prefix /sw/mytool/1.2 --delete
published  revision 44 in 0.4 s      (3-file delta — measured, App. V)
# clients see /cvmfs/sw.example.org/sw/mytool/1.2/bin/... on next TTL roll
```

### O.4 RPM plane (Wave D)

```
# mirror recipe (D11) is nginx config only — then, local repo publishing:
$ brixrpm createrepo /srv/repo
read       214 packages (fastest: 12 ms/pkg header walk)
wrote      repodata/{primary,filelists,other}.xml.gz + repomd.xml

$ brixcvmfs ingest dir /srv/repo --repo /srv/cvmfs/sw.example.org \
      --prefix /rpm/tools --delete
published  revision 44 in 0.8 s

# any client, zero infrastructure beyond the cvmfs mount:
$ dnf --repofrompath=tools,file:///cvmfs/sw.example.org/rpm/tools \
      --setopt=tools.gpgcheck=1 install mytool
```

### O.5 Local registry (Wave B)

```
$ brixoci copy docker://docker.io/library/alpine:3.20 \
        docker://registry.example.org:8443/site/alpine:3.20
$ brixoci tags registry.example.org:8443/site/alpine
3.20
$ podman pull registry.example.org:8443/site/alpine:3.20   # served locally
```

What the walkthrough demonstrates end-to-end: one nginx is the farm's
image mirror, its private registry, and its RPM channel; CVMFS is the
deployment fabric; and the distance from "container on DockerHub" or
"folder on disk" to "mounted on every worker node" is one command.

## Appendix P — risk register

| # | Risk | L | Blast | Mitigation | Detector |
|---|---|---|---|---|---|
| P1 | OCI auth dance edge cases (quirky `WWW-Authenticate` from GitLab/Quay/Harbor variants) burn Wave-A schedule | M | A slips | Pin the three §0.7.5 transcript shapes as the supported set; anything else → clean 502 + logged challenge for later corpus growth | `corpus_oci_challenge` failures; `oci_token_fail_total` |
| P2 | Tag-manifest TTL semantics surprise operators (stale tag served in the offline window) | M | Confusion, not corruption | `Warning: 110` header + `oci_cache=stale` in logs; §D2.2 doc box; digest pulls never stale | Log/metric audit in D3 lane |
| P3 | Tar corpus misses a writer quirk (some builder emits a shape D6 refuses) | M | Ingest fails for that image | Refusals are loud and name the offset; corpus grows by incident (the phase-84 conformance-corpus playbook) | `brix_tar_next` error strings in ingest output |
| P4 | Hardlink/xattr fidelity gaps vs `podman run --rootfs` expectations | M | D10 oracle red | D10 runs early in Wave C (not last); fidelity gaps become D7 table rows while the wave is open | D10 lane |
| P5 | Whole-object blob fills of multi-GiB layers pressure the cache tier | M | Eviction churn | §I.3 sizing guidance; per-location tier as already supported; D15 records chunked-fill as the follow-up | Tier eviction metrics |
| P6 | RPM header walk meets a hostile/ancient package in the wild | L | createrepo aborts | Bounds-first walk (App. E), ASan+fuzz lanes, and skip-and-count as the DEFAULT — a package that will not parse is a warning and a `skipped` tally; `--strict` is the opt-in that makes it fatal (for cron paths that must not publish a partial repo) | `brixrpm` exit report |
| P7 | Upload-session staging fills the disk (abandoned pushes) | L | Registry 507s | Grace reaper (J.7) + `max_blob` + tier quota | `oci_upload_reaped_total` |
| P8 | Port-block collision as the fleet grows past the 14xxx claims | L | Test flakes | Claims land in `test-fleet-ports.md` in the same change (`check_ports_doc`) | Guard |
| P9 | Scope creep toward referrers/artifacts/GC mid-phase | M | Waves B/E balloon | §Non-goals + D15 parking list are normative; new asks get a D15 row, not code. Referrers later came OFF that list deliberately, as §D15.1 + DRIFT 26 — a parked row promoted on evidence, which is the mechanism working, not scope creep | Review |
| P10 | The two-plane confusion (someone wires the stream-plane `open_or_fill` into the HTTP handler) | L | Subtle breakage | J.8 anti-pattern list; the type system mostly forbids it (`ngx_stream_*` conf in an http TU won't link cleanly) | Review + build |



## Appendix Q — verified RPM bytes (generated 2026-08-17, system `rpm` as oracle)

Appendix D's discipline applied to Appendix E: a real package was built and
walked byte-by-byte, with the workstation's `rpm` as the independent
oracle. Fixture: `brixdemo-1.2-3.noarch.rpm` (6587 bytes) from a minimal
spec — one payload file `/usr/share/brixdemo/hello.txt` (20 bytes), one
versioned dependency `Requires: filesystem >= 3.0` — built with the host
`rpmbuild`, walked with a from-scratch parser implementing exactly the
Appendix C.5 accessor rules.

### Q.1 The verified region map

| region | offset | size | decoded |
|---|---|---|---|
| lead | 0 | 96 | magic `ed ab ee db`, v3.0, type=0 (binary), arch=1, name=`"brixdemo-1.2-3"`, os=1, **sigtype=5** ✓ |
| signature header | 96 | 4404 | magic `8e ad e8 01`, il=7, dl=4276 → store@224, end@4500 |
| alignment pad | 4500 | 4 | to the 8-byte boundary ✓ (the E rule, observed) |
| main header | 4504 | 1965 | il=51, dl=1133 → store@5336, end@6469 |
| payload | 6469 | 118 | first bytes `28 b5 2f fd` — **zstd** |

### Q.2 The signature header, all seven entries

```
[0] tag=62    HEADERSIGNATURES  BIN     cnt=16    (region trailer)
[1] tag=269   SHA1              STRING  260b9d2d…  (of the main header)
[2] tag=273   SHA256            STRING  43694b91…  (of the main header)
[3] tag=1000  SIZE              INT32   [2083]
[4] tag=1004  MD5               BIN     697032e8…  (16 bytes)
[5] tag=1007  PAYLOADSIZE       INT32   [288]      (uncompressed cpio bytes)
[6] tag=1008  RESERVEDSPACE     BIN     cnt=4128   (zeros — signing headroom)
```

### Q.3 Arithmetic ledger (every number cross-checks)

- `96 + 16 + 7×16 = 224` = store offset ✓ · `224 + 4276 = 4500` = sig end ✓
- sig tag 1000 `SIZE = 2083` **= 6587 − 4504** — signature-covered size is
  main header + payload, verified by subtraction
- `4504 + 16 + 51×16 = 5336` = main store ✓ · `5336 + 1133 = 6469` = payload ✓
- `<rpm:header-range start="4504" end="6469"/>` — the exact numbers the
  D12 `primary.xml` emitter computes, now pinned to a worked instance
- `PAYLOADSIZE 288` = one 20-byte file + cpio framing; on-disk payload 118
  bytes of zstd

Oracle agreement: `rpm -qp --nodigest --nosignature` reports
`name=brixdemo evr=1.2-3 size=20 payload=cpio/zstd digestalgo=8` and the
five-entry requires list — field-for-field what the walk decoded (main
header: NAME=`brixdemo`@off 2, VERSION=`1.2`@11, RELEASE=`3`@15,
SIZE=[20], DIRINDEXES=[0], BASENAMES=[`hello.txt`],
PAYLOADCOMPRESSOR=`zstd`, FILEDIGESTALGO=[8]).

### Q.4 Findings ledger — normative deltas for the D12 walker

| # | Observed | D12 rule amended |
|---|---|---|
| Q-1 | Index entry [0] of **both** headers is a region trailer (tag 62 sig / 63 main, BIN, cnt=16) | Walker treats region tags as ordinary entries — never special-cased, never an error |
| Q-2 | Sig tag 1008 `RESERVEDSPACE`: 4128 bytes of zeros (97% of dl) | Unknown sig tags are skipped silently; a mostly-padding signature header is normal, not suspicious |
| Q-3 | Modern rpmbuild default: `PAYLOADCOMPRESSOR=zstd` (magic verified at offset 6469) and `FILEDIGESTALGO=8` (SHA-256) | E's "payload never decoded" ruling unchanged and now clearly right — assuming gzip would already be wrong on this workstation; file digests in `primary.xml` are emitted with the *tag-declared* algorithm, not hardcoded |
| Q-4 | Sense flags in the wild: `12` = `0x0C` = GREATER\|EQUAL for `>= 3.0`; `16777226` = `0x0100000A` = rpmlib-bit\|LESS\|EQUAL on all four `rpmlib(…)` rows | The E flag table and the §D12.2 rpmlib filter confirmed against live values — the filter drops exactly 4 of 5 requires here |
| Q-5 | SUMMARY is I18NSTRING with `HEADERI18NTABLE` (tag 100) = `["C"]` | I18NSTRING reads entry 0 of the locale table — one string, not a scan |
| Q-6 | Lead name is the **truncated NEVR** `"brixdemo-1.2-3"` (66-byte field) | Lead name is display-only; N-V-R truth is tags 1000/1001/1002, never parsed from the lead |

Fixture + walker live in the phase's test corpus as
`tests/rpm/fixtures/brixdemo-1.2-3.noarch.rpm` seed material
(regenerated by `tests/rpm/fixtures/build.sh` so the corpus never depends
on a checked-in binary).

## Appendix R — live wire capture (Docker Hub, 2026-08-17)

The Appendix A transcripts, run for real: anonymous pulls of
`library/alpine:3.20` against `registry-1.docker.io` from this
workstation. Everything below is captured, not composed. Where a synthetic
A shape disagrees, **this appendix wins**.

### R.1 The 401 challenge (leg 0)

```
HTTP/2 401
content-type: application/json
content-length: 87
docker-distribution-api-version: registry/2.0
www-authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
```

Captured details the synthetic transcript missed: over HTTP/2 the header
name arrives **lowercase** (`www-authenticate`) — the D1 challenge parser
is case-insensitive on the header name and the `Bearer` scheme token; and
the first-contact challenge carries **no `error=` parameter** —
`error="insufficient_scope"` appears only on scope-upgrade retries. Both
are now seeds in `corpus_oci_challenge`.

### R.2 The token response (leg 0b)

```
{ "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1…",   ← 2658 bytes
  "access_token": "…(identical)…",
  "expires_in": 300,
  "issued_at": "2026-08-17T15:12:32.605031277Z" }
```

Normative consequences for D1:

- Both `token` and `access_token` are present and identical at Hub; the
  parser prefers `token`, falls back to `access_token` (some registries
  send only one).
- **Observed token size: 2658 bytes** — the §0.6 `val=4096` kv sizing is
  validated by reality, with headroom logged: a `brix_kv_set` refusal
  (oversized value) increments `oci_token_cache_overflow_total` rather
  than failing the fill (the dance just runs uncached).
- Cache TTL = `expires_in − 30 s` skew (here: 270 s), never a config
  constant; absent `expires_in` → 60 s default (the spec's stated
  assumption).

### R.3 The tag manifest is an OCI index now (leg 1)

```
HTTP/2 200
content-type: application/vnd.oci.image.index.v1+json
content-length: 9226
docker-content-digest: sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
```

Docker Hub answers official-image tag requests with an **OCI image
index**, not the legacy docker manifest-list the older literature
implies — the §0.7 pinned Accept set (which lists both) is validated, and
any implementation that special-cased the docker list type first would
exercise its OCI path on day one. The `docker-content-digest` header is
recorded in the D2 sidecar verbatim: it is what a later `HEAD` of the tag
must echo, and what the client's own digest computation is cross-checked
against.

### R.4 Attestation entries — a real index is half decoys

The captured index holds **16 manifests: 8 runnable platforms and 8
attestation manifests**, the latter with platform `unknown/unknown` and
annotation `vnd.docker.reference.type: attestation-manifest`:

```
amd64/linux            arm64/linux            386/linux    ppc64le/linux
arm/linux (v6)         arm/linux (v7)         riscv64/linux  s390x/linux
+ 8 × unknown/unknown  ATTESTATION (one per platform, digest-paired)
```

**New normative rule for D8 platform resolution** (absent from the v1–v4
design, surfaced only by the live capture): candidate filtering skips any
index entry whose `platform` is `unknown/unknown` **or** whose annotations
contain `vnd.docker.reference.type` — *before* platform matching. An index
whose filtered set is empty fails with `no runnable platform in index
(N attestation/unknown entries skipped)`. Without this rule, a naive
"first entry matching nothing = fallback" implementation can select an
attestation blob and try to flatten a provenance JSON as a rootfs.

### R.5 The full verified chain (real digests)

```
tag 3.20 ──► index    sha256:d9e853e8…  (9226 B, OCI index)
              └─amd64 ► manifest sha256:c64c687c…  (1023 B)
                         ├─ config sha256:bf8527eb…  (612 B)
                         └─ layer  sha256:25f1d6b1…  (3 630 321 B, tar+gzip)
```

One layer — `alpine:3.20` is a single-layer image (the O.2 walkthrough
was corrected against this capture). These are the digests the D3 oracle
lane will see on its first live run; the mock registry's alpine fixture
reuses them so mock and live lanes agree on the arithmetic.

### R.6 Consequences ledger

| # | Capture fact | Where it lands |
|---|---|---|
| R-1 | lowercase `www-authenticate`, no `error=` on first contact | D1 parser rules + `corpus_oci_challenge` seeds |
| R-2 | token 2658 B, `expires_in: 300`, dual token fields | kv `val=4096` validated · TTL derivation rule · parser fallback order |
| R-3 | Hub serves OCI index for official images | §0.7 media-type table annotated; D0 tests exercise OCI-index first, docker-list second |
| R-4 | 8 of 16 index entries are attestations | **New D8 filter rule (R.4)** + a named test `test_ingest_skips_attestation_manifests` added to the F roster |
| R-5 | `docker-content-digest` present on tag GET | D2 sidecar records + re-serves it |

## Appendix S — substrate contracts, function-level (read off the tree)

The body says "reuse the fill path / the kv zone / the publish plane".
This appendix pins those claims to the actual exported functions, read
from the headers on 2026-08-17, and states per seam what **exists** and
what the phase **adds** — the checkable boundary of every "no new
machinery here" assertion.

### S.1 The fill transport: `src/fs/backend/http/sd_http.h`

Exists (cited from the header):

- `brix_sd_http_cfg_t` — endpoint set (`extra`/`n_extra`, cap
  `SD_HTTP_EP_MAX 8` ranked failover), injected transport vtable
  (`brix_s3_transport_t` — the server libcurl singleton), `bearer_token`
  (**static per-instance** credential), `ca_path`, `timeout_ms` (default
  `BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS` 60 000), and injected accounting hooks
  `failover_note` / `health_note` (the driver stays ngx-free; owners
  inject metrics).
- Per-open credentials: the header's AUTH note — `open_cred` presents the
  *requesting user's* WLCG bearer per request (phase-2 T7) when the
  transport implements `request_cred`.
- `sd_http_penalize_last_origin()` — demote the endpoint whose bytes
  failed **integrity verification** (not transport failure): decaying
  fail-score bump so the EBADMSG retry rotates to a clean origin.

Rulings this forces on D1 (each deletes provisional design work):

1. **The registry token is per-request state, so it rides the `open_cred`
   leg — not `bearer_token`.** `bearer_token` is fixed at instance build;
   OCI tokens rotate every ~300 s (R.2). The mirror resolves the token
   (kv hit or dance) and hands it down the existing per-open credential
   plumbing. **Expected sd_http source diff: zero lines.**
2. The token dance itself runs on the fill thread through the same
   injected transport singleton — no second libcurl surface appears in
   the tree.
3. Verify-at-edge digest mismatch calls `sd_http_penalize_last_origin()`
   — the exact mechanism built for cvmfs CAS verification failures; the
   mirror's retry-rotation behavior is inherited, not designed.

### S.2 The token cache: `src/core/shm/kv.h`

Exists — the complete call set the phase uses:

```c
brix_kv_configure(cf, kv, name, size, key_max, val_max, module);  /* :68 */
brix_kv_find(&name);          /* :99  merge-time resolve by zone name   */
brix_kv_get(kv, k, klen, out, &outlen);   /* :76  1 hit / 0 miss        */
brix_kv_set(kv, k, klen, v, vlen, ttl_ms);/* :85  NGX_ERROR = full/oversized */
brix_kv_stats(kv, &st);       /* :92  Prometheus export                 */
```

Semantics from the header that shape D1, none of which need new code:

- **Lazy expiry** (get() evicts what it finds expired; "no background
  sweeper") — precisely right for short-lived tokens; no reaper to write.
- **Load factor capped at 0.5** — live-entry capacity is `capacity/2`;
  the §I zone arithmetic gains this factor (a "125-token" zone needs
  capacity 256).
- One spinlock per zone, O(1) probe, "no I/O or allocation inside the
  critical section" — safe to call from fill threads by construction.
- The Prometheus exporter **iterates all zones**
  (`brix_kv_zone_count`/`brix_kv_zone_get`) — the token cache's
  hit/miss/eviction rows appear in `/metrics` with **zero exporter
  changes**, labeled by zone name (kv.h:42).
- `brix_kv_set` refuses oversized values with `NGX_ERROR` — the R.2
  overflow-metric rule keys off exactly this return.

What the phase adds: one struct field (`brix_kv_t *token_zone`), one
`brix_kv_find` call in `oci_merge.c`, and the key convention
`"<upstream-host>\0<scope>"` — nothing else.

### S.3 The publish plane: `shared/cvmfs/publish/{changeset.h,publish.h}`

Exists — the **two-call** publish path D8/D9 drive:

```c
cvmfs_changeset_scan(upper_dir, &cs, err, errlen);      /* changeset.h:55 */
cvmfs_publish_run(&opts, &cs, &new_rev, err, errlen);   /* publish.h:45   */
```

Contract details that shape Wave C:

- **Ordering is scan's problem, not the flattener's** (changeset.h:48):
  the result arrives "DELETEs first, then ADDs sorted by path (parents
  strictly before children)". D7 writes the upper tree in tar order and
  never sorts.
- **Hardlinks**: scan assigns `hardlink_group`/`linkcount` from shared
  inodes *within the upper tree* (changeset.h:35–36, :50) — so D7's
  within-layer hardlink recreation via `link()` is automatically
  published as a hardlink group; the cross-layer copy caveat (D7.1) is a
  flattener limitation, not a publish one.
- **xattrs**: scan captures `user.*` xattrs as packed BLOBs — this is
  *why* K.1 specifies `e->xattr` in the changeset wire format: the
  flattener applies layer xattrs to the upper files with `setxattr`, and
  scan re-harvests them. No parallel xattr channel exists or is added.
- `cvmfs_publish_opts_t.chunk_size` floor/ceil
  (`CVMFS_PUBLISH_CHUNK_FLOOR` 4096, ceil = `CVMFS_OBJECT_MAX_BYTES`,
  publish.h:26–32) — ingest exposes `--chunk-size` by pass-through,
  bounds enforced where they already are.
- **Crash-safety is testable for free**: publish.h:43 documents the
  `$BRIXCVMFS_PUBLISH_CRASH` kill-injection hook (`_exit(66)` before the
  manifest swap). The D8 crash test *is* the existing hook: kill an
  ingest mid-publish, re-run, assert revision monotonicity — no new
  injection point required.

### S.4 The CLI personality seam: `client/apps/fs/brixmount.c`

Exists: argv[0] dispatch at :197 —
`strcmp(brix_prog_base(argv[0]), "brixcvmfs") == 0 →
brixcvmfs_personality(argc, argv)` (:149), which shows the house
conventions the new surfaces copy: `--version` prints
`brix_client_version()`, usage text ends with
`BRIX_USAGE_FOOTER("<name>")`, and sub-drivers are `*_main(argc, argv)`
entry points (`brixcvmfs_main`, `brixcvmfs_rw_main` — :135–136).

What the phase adds, mechanically:

- D8/D9: two rows in `brixcvmfs_personality`'s dispatch (`ingest image` ·
  `ingest dir`) + two usage lines — the umbrella already owns the `repo …`
  release-manager surface, so `ingest` lands beside it.
- D5: one new `strcmp` branch for `"brixoci"` → `brixoci_personality`,
  one symlink in the install rule, the `client/Makefile` source rows —
  the xrdcksum/xrddiag pattern, third verse.

## Appendix T — the ingest driver, in real API names

The D8 main loop written against the verified contracts of K, S.1–S.4 and
R.4 — pseudo-C, but every function that exists today is cited, so the
glue-to-invention ratio is visible line by line. (New code: the registry
client and the memo. Everything below the `fetch` block exists.)

```c
/* brixcvmfs ingest image <ref> — client/apps/fs/brixcvmfs_ingest.c (D8) */
static int ingest_image(const ingest_opts_t *o)
{
    /* 1 · resolve: ref parse (D5 lib), token dance (R.1–R.2), index GET */
    oci_ref_parse(o->ref, &ref);                       /* new: lib/oci/ref.c */
    reg_open(&s, &ref, o->auth);                       /* new: reg_client.c  */
    reg_fetch_index(&s, &idx);                         /* Accept set: A.2    */

    /* 2 · platform: filter attestations FIRST (R.4), then match */
    pick = oci_index_pick(&idx, o->platform);          /* skips unknown/unknown
                                                          + vnd.docker.reference.type */
    reg_fetch_manifest(&s, pick.digest, &mf);          /* verified: sha256 chain */

    /* 3 · memo: layer-set unchanged → no-op exit (D8.3, App. B.4) */
    if (ingest_memo_match(o->repo, o->prefix, &mf))
        return ingest_report_unchanged(&mf);

    /* 4 · flatten: manifest order, containment per K.2 */
    for (i = 0; i < mf.n_layers; i++) {
        fd = reg_fetch_blob_spooled(&s, mf.layers[i].digest);  /* digest
                                        verified as it streams — a bad byte
                                        never reaches the flattener */
        rc = brix_flatten_layer(&fopts, fd, &st, err, sizeof err);  /* K.2:
                                        internally brix_tar_open_fd/_next
                                        (K.1) against the dirfd wall */
        if (rc != 0) return ingest_fail_cleanup(scratch, err);
    }

    /* 5 · publish: the two-call path, verbatim phase-96 machinery */
    cvmfs_changeset_scan(upper, &cs, err, sizeof err);     /* changeset.h:55 */
    cvmfs_publish_run(&popts, &cs, &rev, err, sizeof err); /* publish.h:45 —
                                        atomic .cvmfspublished swap; crash
                                        test rides $BRIXCVMFS_PUBLISH_CRASH */

    /* 6 · memo + report */
    ingest_memo_write(o->repo, o->prefix, &mf, rev);       /* App. B.4 */
    return ingest_report(&mf, &cs, rev);
}
```

`ingest dir` (D9) is steps 5–6 with `upper` = the staged folder (plus the
`--delete` diff pass that synthesizes whiteouts against the published
tree) — the tail is shared code, which is why D9 is the smallest feature
in the phase and ships first in Wave C.

## Appendix U — the whiteout lab (executed 2026-08-17)

Appendix D verified the tar *format*; this lab verified the OCI *layer
semantics* — by building a real whiteout layer with rootless podman on
this workstation, walking its bytes, then hand-executing the D7
translation and **running the result**.

### U.1 Fixture

```dockerfile
FROM docker.io/library/alpine:3.20
RUN rm /etc/motd && rm -rf /media && mkdir /media && echo marker > /media/keep
```

`podman build` → image `0684ec56…`; `podman save --format oci-archive`
→ two layers: the alpine base (re-gzipped by podman to `sha256:c265cb3f…`,
3 741 667 B) and the whiteout layer (`sha256:fd2303e1…`, **212 B gzipped /
4096 B raw / 8 tar blocks**).

**Finding U-1 (identity):** podman's re-export changed the base layer's
compressed digest (`c265cb3f…` ≠ the registry's `25f1d6b1…` from R.5) —
compressed layer digests are *transport artifacts*; the uncompressed
DiffID is the stable identity. The mirror caches by requested digest and
the ingest memo records the manifest's layer digests, so both are
internally consistent — but no component may ever equate compressed
digests across sources. Corollary verified the same minute: `podman pull`
prints image ID `bf8527eb…` — exactly the **config blob** digest captured
in R.5 (image ID ≡ config digest).

### U.2 The whiteout layer, walked

```
typeflag='5' mode=0755 size=0  name='etc/'
typeflag='0' mode=0000 size=0  name='etc/.wh.motd'          ← whiteout
typeflag='5' mode=0755 size=0  name='media/'
typeflag='0' mode=0755 size=0  name='media/.wh..wh..opq'    ← opaque
typeflag='0' mode=0644 size=7  name='media/keep'
```

Findings, each now a D7 rule or test:

| # | Observed | D7 consequence |
|---|---|---|
| U-2 | A whiteout is a **zero-byte regular file with mode 0000000** | The flattener treats whiteout entries as pure grammar — never applies their mode/owner to anything (`test_flatten_whiteout_mode_zero`) |
| U-3 | Entry order within the layer: parent dir → its whiteouts/opaque → its surviving content (`media/` → `.wh..wh..opq` → `keep`) | Sequential single-pass apply is correct as designed: opaque clears *accumulated* content, later entries in the same layer land after (`test_flatten_opaque_then_content_same_layer`) |
| U-4 | Whiteout entries are typeflag `'0'`, uid/gid 0/0, `ustar\0` `00` magic — ordinary POSIX entries | No writer-specific special-casing needed; the D6 reader hands them through untouched |

### U.3 The pipeline, executed by hand

The base layer was untarred, the whiteout layer applied manually per the
D7 table (delete `etc/motd`; clear and repopulate `media/`), and the
result run — rootless, no image store involved:

```
$ podman run --rm --rootfs $PWD/rootfs /bin/sh -c \
    'echo "release=$(cat /etc/alpine-release)"; ls /media; test ! -e /etc/motd && echo MOTD-GONE'
release=3.20.10
keep
MOTD-GONE
```

Every load-bearing claim of Wave C just ran on this machine: the D7
translation produces a tree podman executes (`--rootfs`, rootless,
overlay driver), whiteout semantics are observable from inside the
container, and the D10 oracle command needs no privileges the test fleet
lacks. The fixture layer (212 B) is checked into the corpus as the
canonical whiteout seed (`tests/oci/fixtures/tar/whiteout-layer.tar.gz`,
regenerated by the U.1 Containerfile).

## Appendix V — measured publish baseline (this workstation, 2026-08-17)

The §I.3 budgets, run against the tree's own binary
(`client/bin/brixMount` via its `brixcvmfs` personality — the *actual*
plane D8/D9 will drive). Repo created with `repo mkfs`, populated via
`repo transaction` upper trees, published with `repo publish`, verified
with `repo fsck --data` (clean). WSL2 filesystem — treat the absolute
numbers as a conservative floor; re-baseline on EL9 metal at Wave C start.

### V.1 The numbers

| Workload | Wall | Notes |
|---|---|---|
| alpine rootfs (521 entries, 8.1 MiB) — the D8 image case | **2.04 s** | peak RSS 18.3 MiB — §I.3 "< 3 s cold" ✓ |
| 10 000 new files (~24 MiB) — cold bulk dir import, one fsync per CAS put | **95.1 s** | ~9.5 ms/file — the baseline V-3 was written against |
| the same import after the V-3 lever landed | **10.0 s** | re-measured 2026-08-18 on the same host; `check_i4` pins it at < 90 s so the guard survives a loaded CI box |
| 1 000 new files — CPU characterization | 25.6 s wall, **3.6 s user+sys** | **86 % I/O wait**: the fsync-per-object signature, not CPU |
| 3-file delta on the flat root catalog (21 k rows) | **0.34 s** | §I.3 "≪ 5 s" ✓ — no nesting needed for delta speed |
| one-time `--dirtab` nesting (`/sw/*`, `/images/*`) | 9.29 s | restructure cost, paid once |
| 3-file delta after nesting | 0.46 s | parity with flat at this size; nesting bounds long-term root-catalog growth |
| `repo fsck --data` after all of it | clean | the integrity oracle |

Memory is flat (15–19 MiB peak) regardless of tree size — the streaming
claims of the publish plane hold.

### V.2 Findings ledger

| # | Finding | Where it lands |
|---|---|---|
| V-1 | Both headline claims **validated**: alpine-class cold ingest 2.0 s, 3-file delta 0.34 s | §I.3 rows marked ✓; O.2/O.3 transcripts corrected to measured values |
| V-2 | The earlier "2.9 s for a 10 k cold import" was fiction: measured **95 s**, I/O-bound | O.3 rewritten; the honest story is *deltas* are the seconds path |
| V-3 | **The fsync-batching lever is semantically free**: publish.h's crash model (CAS puts idempotent, `.cvmfspublished` swapped last) only requires object durability *before the manifest fsync* — per-object fsync is stricter than the crash contract demands. Batching/syncfs before the swap preserves crash-safety by construction | **Delivered** in `shared/cvmfs/publish/publish.c`: `px.store.cas.no_fsync = 1` puts the CAS in batch mode and `pub_sync_store()` (one `syncfs` over the repo dir, `brix_plat_sync_tree`) is the barrier, run after `pub_finalize` and before `pub_swap_manifest` — the same window `BRIXCVMFS_PUBLISH_CRASH` injects into, so the D9 lane's `crash-rev-intact` + `fsck --data` checks are the crash-safety oracle for the lever itself. 95.1 s → **10.0 s** on the baseline host; see DRIFT 25 |
| V-4 | Delta cost did **not** scale with accumulated catalog size at 21 k rows (0.34 s flat vs 0.46 s nested) | Dirtab nesting is *not* urgent for speed; D8 still plants a dirtab row per image prefix as cheap insurance against long-term root-catalog growth (the option costs one config line) |
| V-5 | Real alpine:3.20 is **517 entries**, not the ~3.5 k earlier drafts assumed | §I.3 and O.2 corrected; sizing intuition recalibrated ~7× |

### V.3 Reproduction

```
ln -s client/bin/brixMount brixcvmfs
./brixcvmfs repo mkfs demo.brix.lab repo
./brixcvmfs repo transaction repo        # → repo/.brixtxn/upper
<populate upper>                         # rootfs copy / synthetic tree
/usr/bin/time ./brixcvmfs repo publish repo [--dirtab dirtab.txt]
./brixcvmfs repo fsck repo --data
```

The V.1 table is a one-command-per-row transcript of exactly this recipe;
the D9 perf lane automates it with the same synthetic trees (seeded
`random.seed(104)`, so the corpus is reproducible byte-for-byte).

## Appendix W — the mirror pull lab (executed 2026-08-17)

The Wave A claim, run for real: a **static file tree shaped like the D0
`/v2/` surface**, served over plain HTTP, must satisfy an unmodified
`podman pull` end-to-end. It did — cold-store and warm-store — and the
capture rewrote three assumptions. Protocol oracle: system nginx 1.20.1
(the module will live in *our* nginx; what is under test here is the
**client's** contract, which is nginx-version-independent). Client:
`containers/5.39.2 (github.com/containers/image)` — podman's own
transport library, i.e. the same code path Docker Hub sees.

### W.1 Setup — the D0 surface as seven files and three location rules

The Appendix U image (`brix-whlab`, manifest `ae84ad1a…`, 1 198 B) laid
out statically:

```
v2root/v2/brix-whlab/
├── manifests/demo                 # tag → manifest bytes (same file twice)
├── manifests/sha256:ae84ad1a…     # digest → identical bytes
└── blobs/
    ├── sha256:0684ec56…           # config  (image ID ≡ this digest)
    ├── sha256:c265cb3f…           # base layer  (alpine)
    └── sha256:fd2303e1…           # top layer   (the whiteout layer)
```

The entire serve-side "logic" is media-type mapping — the config-form
prototype of the D0 classifier:

```nginx
location = /v2/                     { default_type application/json;  return 200 '{}'; }
location ~ ^/v2/.+/manifests/       { default_type application/vnd.oci.image.manifest.v1+json; }
location ~ ^/v2/.+/blobs/           { default_type application/octet-stream; }
```

(Unprivileged-run trap for anyone repeating this with a distro nginx:
its compiled-in temp paths live under `/var/lib/nginx` — override all
five `*_temp_path` directives into the lab dir or `nginx -p` still
refuses to start.)

### W.2 Cold-store pull — the complete request trace

`podman --root <fresh> pull --tls-verify=false localhost:14100/brix-whlab:demo`,
against an empty containers-storage, access-log format
`'$request_method $uri $status accept="$http_accept"'`:

```
- - 400 accept="-"                                    ← TLS ClientHello on the plaintext port
GET /v2/                                    200       ← ping (no Accept header)
GET /v2/brix-whlab/manifests/demo           200 accept="application/vnd.oci.image.manifest.v1+json"
GET /v2/brix-whlab/blobs/sha256:0684ec56…   200       ← config FIRST
GET /v2/brix-whlab/blobs/sha256:fd2303e1…   200       ← top layer
GET /v2/brix-whlab/blobs/sha256:c265cb3f…   200       ← base layer
```

Pull result: image ID `0684ec56…` — **identical to the config digest**
(the R-5 identity, now reproduced against our own serving). The pulled
image *runs* correctly: `podman run --rm localhost:14100/brix-whlab:demo`
shows `/media` containing only `keep` and `/etc/motd` absent — the
Appendix U whiteout semantics survived a full pull round-trip.

### W.3 The raw manifest request — captured at the socket

nginx's `$http_accept` shows one value. The raw bytes (one-shot socket
capture on a fresh port) show why that is a trap:

```
GET /v2/anything/manifests/tag HTTP/1.1
Host: localhost:14102
User-Agent: containers/5.39.2 (github.com/containers/image)
Accept: application/vnd.oci.image.manifest.v1+json
Accept: application/vnd.docker.distribution.manifest.v2+json
Accept: application/vnd.docker.distribution.manifest.v1+prettyjws
Accept: application/vnd.docker.distribution.manifest.v1+json
Accept: application/vnd.docker.distribution.manifest.list.v2+json
Accept: application/vnd.oci.image.index.v1+json
Docker-Distribution-Api-Version: registry/2.0
Accept-Encoding: gzip
```

**Six separate `Accept:` header lines**, preference-ordered (OCI manifest
first, index last), not one comma-joined value. Also: the client sends
`Docker-Distribution-Api-Version: registry/2.0` *to* the server, and the
first connection on the port is always a TLS ClientHello — podman probes
HTTPS even under `--tls-verify=false` and falls back to HTTP only after
the handshake fails.

### W.4 Warm-store pull — the dedup trace

Same pull with the client's default store (which already held both layer
blobs from the U lab build):

```
GET /v2/                                    200
GET /v2/brix-whlab/manifests/demo           200
GET /v2/brix-whlab/blobs/sha256:0684ec56…   200       ← config only; zero layer GETs
```

The blob-info cache mapped both layer digests to locally-present content
and elided their fetches entirely.

### W.5 Findings ledger

| # | Finding | Where it lands |
|---|---|---|
| W-1 | Clients send **repeated `Accept` headers**, not a comma list | D0/D2 negotiation MUST walk the full `r->headers_in` header list and merge — first-header-wins silently degrades docker-manifest clients; and never debug negotiation from `$http_accept` (it logs only the first line) |
| W-2 | A TLS ClientHello precedes every plaintext client contact | one guaranteed 400-garbage request per client session: the D3 metrics must not count it as a classifier error and the guard-line/fail2ban filter must not trigger on it |
| W-3 | Blob fetch order is config-first, then layers concurrently (completion-ordered) | the J.1 coalesced-fill path must assume concurrent, unordered blob GETs — validated, no sequential-layer assumption anywhere in D2 |
| W-4 | Warm clients **elide** already-held blobs (W.4: zero layer GETs) | mirror egress is not proportional to image-size × pulls; D3 hit-rate metrics must be per-blob, and capacity planning uses unique-blob traffic |
| W-5 | A purely static tree + three media-type rules satisfied a real pull end-to-end | the D0 GET/HEAD surface really is "digest-addressed files + media-type map" — the serve-side simplicity claim in §Wave A is now demonstrated, not asserted |

### W.6 Reproduction

```
# tree: copy manifest to manifests/{demo,sha256:<digest>}, blobs to blobs/sha256:<digest>
nginx -p "$PWD/ngxlab" -c "$PWD/ngxlab/nginx.conf"     # W.1 location rules, port 14100
podman --root "$PWD/coldstore" --runroot "$PWD/coldrun" \
       pull --tls-verify=false localhost:14100/brix-whlab:demo
cat ngxlab/logs/access.log                             # → W.2 trace
podman run --rm localhost:14100/brix-whlab:demo ls /media
```

The D3 oracle lane automates exactly this shape — the lab's nginx config
is the mock-registry template for `tests/test_oci_mirror_*`.

## Appendix X — the dnf lane lab (executed 2026-08-17)

The Wave D claim, run for real: repodata emitted by a **clean-room
generator written from the Appendix E/Q byte walk** — no `createrepo_c`,
no rpm-python — must depsolve and install on a stock EL9 `dnf`. It did,
first try, and dnf's own request trace settled the D11 cache policy.

### X.1 The generator — D12's reference implementation

`repomdgen.py` (scratchpad; to be ported to C per the K headers): pure
`struct`/`gzip`/`hashlib`. It walks lead → signature header → 8-byte pad
→ main header (the Q walk, now as code), then emits
`primary.xml.gz` / `filelists.xml.gz` / `other.xml.gz` (hash-prefixed
filenames, `gzip mtime=0` for reproducible bytes) + `repomd.xml` with
per-document `checksum`/`open-checksum`/`size`/`open-size`. The three
rules that make the output *consumable*, all verified by the oracle run:

1. **rpmlib-dep filter** — any require with sense bit `1<<24`
   (`RPMSENSE_RPMLIB`) is dropped from `<rpm:requires>`; publishing them
   breaks depsolve. For brixdemo only `filesystem GE 3.0` survives
   (sense 12 = GT|EQ — the Q-6 decode, now round-tripped).
2. **primary file filter** — only `/etc/*`, paths containing `bin/`, and
   `/usr/lib/sendmail` appear in primary; everything appears in
   filelists (with `type="dir"` / `type="ghost"` from FILEMODES/FILEFLAGS).
3. **`rpm:header-range`** — `start` = main-header offset (sig end padded
   to 8), `end` = payload offset: 4504/6469 for brixdemo, byte-identical
   to the Q-4 walk.

`pkgid` = sha256 of the whole file (`35d640e5…` for the fixture).

### X.2 The oracle run

Stock `almalinux:9` container (`--network=host`), no `.repo` file:

```
dnf -y --repofrompath=brix,http://127.0.0.1:14100/rpm \
    --setopt=brix.gpgcheck=0 --disablerepo='*' --enablerepo=brix \
    install brixdemo
→ Installed: brixdemo-1.2-3.noarch
rpm -q brixdemo         → brixdemo-1.2-3.noarch
rpm -ql brixdemo        → /usr/share/brixdemo/hello.txt
cat …/hello.txt         → hello from brixdemo
```

Depsolve, download, signature policy, install scriptlets, payload
extraction — the entire consumer stack accepted the hand-rolled
metadata with zero warnings.

### X.3 dnf's request trace — and its raw headers

The complete fetch set for the install (nginx access log):

```
GET /rpm/repodata/repomd.xml                       200
GET /rpm/repodata/<sha256>-primary.xml.gz          200
GET /rpm/repodata/<sha256>-filelists.xml.gz        200
GET /rpm/brixdemo-1.2-3.noarch.rpm                 200
```

`other.xml.gz` was **never requested**. Raw first request (socket
capture):

```
GET /rpm/repodata/repomd.xml HTTP/1.1
Host: 127.0.0.1:14103
User-Agent: libdnf (AlmaLinux 9.8; generic; Linux.x86_64)
Accept: */*
Cache-Control: no-cache
Pragma: no-cache
```

### X.4 Findings ledger

| # | Finding | Where it lands |
|---|---|---|
| X-1 | Stock dnf accepted clean-room repodata first try | D12's scope is proven sufficient: the generator is the normative reference — the C port must match its bytes (same filters, same header-range, same checksum set) |
| X-2 | dnf sends `Cache-Control: no-cache` + `Pragma: no-cache` on `repomd.xml` | the D11 split is client-mandated, not just policy: `repomd.xml` = revalidate-always; hash-prefixed repodata + RPMs = immutable/cache-forever — **the same rule as OCI tag-vs-digest (D2)**, so one cache-policy kernel serves both planes |
| X-3 | EL9 dnf4 fetches primary **and filelists** unconditionally; `other` never | D11 warm-prefetch set is {repomd, primary, filelists}; `other` stays fetch-on-demand (dnf5 makes filelists optional — recheck when EL10 becomes a lane) |
| X-4 | rpmlib(…) requires must not reach primary (sense bit `1<<24`) | encoded as generator rule X.1-1 and a D12 unit assertion — publishing them is the one silent way to break every consumer |
| X-5 | `--repofrompath` + `gpgcheck=0` + `--network=host` is a complete one-command dnf harness | the G-spec dnf lane drives exactly this: one `podman run` per assertion, no `.repo` fixture files to manage |

### X.5 Reproduction

```
python3 repomdgen.py <repo>/brixdemo-1.2-3.noarch.rpm <repo>   # X.1 generator
nginx -p "$PWD/ngxlab" …                                       # serve <repo> at /rpm/
podman run --rm --network=host docker.io/library/almalinux:9 \
  dnf -y --repofrompath=brix,http://127.0.0.1:14100/rpm \
      --setopt=brix.gpgcheck=0 --disablerepo='*' --enablerepo=brix \
      install brixdemo
```

Fixture: the Appendix Q RPM (`brixdemo-1.2-3.noarch.rpm`, 6 587 B,
pkgid `35d640e5…`). The `tests/test_rpm_repodata_*` lane ports X.1's
generator assertions to the C emitter and reuses X.2 verbatim as its
oracle.

## Appendix Y — the push lab (executed 2026-08-17)

Wave B's wire, captured: a real `podman push` received by a minimal
capturing registry (`ycap.py`, ~150 lines of stdlib Python: 401 Bearer
challenge → `/token` → upload sessions → manifest PUT, every blob
sha256-verified server-side). Until this lab, nothing had ever pushed
into anything brix-shaped — the J.7 state machine and the D4.5
challenge were design, not evidence. Client:
`containers/5.39.2`, pushing the Appendix U image
(`localhost:14100/brix-whlab:demo → docker://localhost:14104/…`).

### Y.1 The token dance, client side

```
GET /v2/                                        (no Authorization)
← 401  Www-Authenticate: Bearer realm="http://127.0.0.1:14104/token",service="brixlab"
GET /token?scope=repository%3Abrix-whlab%3Apull%2Cpush&service=brixlab
                                                (anonymous — no Authorization)
← 200  {"token": "brixlab-tok-1", "expires_in": 300}
… later, a second token request:
GET /token?scope=repository%3Abrix-whlab%3Apull%2Cpush&scope=repository%3Abrix-whlab%3Apull&service=brixlab
```

Push scope is `repository:<name>:pull,push`; the refresh request carries
**two repeated `scope` parameters** in one URL. Every subsequent request
presented `Authorization: Bearer brixlab-tok-1` verbatim.

### Y.2 The upload sequence (annotated trace)

```
HEAD /v2/brix-whlab/blobs/sha256:ac2dcb9b… → 404      ┐ 5 existence probes
HEAD /v2/brix-whlab/blobs/sha256:08bc4e53… → 404      │ for 3 eventual
HEAD /v2/brix-whlab/blobs/sha256:25f1d6b1… → 404      │ uploads — candidate
HEAD /v2/brix-whlab/blobs/sha256:fd2303e1… → 404      │ compressed-digest
HEAD /v2/brix-whlab/blobs/sha256:0684ec56… → 404      ┘ variants probed too

POST /v2/brix-whlab/blobs/uploads/   Content-Length: 0          → 202 + Location + Docker-Upload-UUID
PATCH …/uploads/<uuid>   Transfer-Encoding: chunked  (212 B)    → 202 + Range: 0-211
PUT   …/uploads/<uuid>?digest=sha256%3Afd2303e1…  CL: 0         → 201   verify=OK
PATCH …/uploads/<uuid>   Transfer-Encoding: chunked (3 741 667 B) → 202  (base layer)
PUT   …?digest=sha256%3Ac265cb3f…  CL: 0                        → 201   verify=OK
PATCH …/uploads/<uuid>   Content-Length: 955                    → 202  (config: known size)
PUT   …?digest=sha256%3A0684ec56…  CL: 0                        → 201   verify=OK

PUT /v2/brix-whlab/manifests/demo
    Content-Type: application/vnd.oci.image.manifest.v1+json, 1 198 B
    → sha256:ae84ad1a…  — byte-identical to the U-lab OCI export
```

One PATCH per blob, then an **empty-body** `PUT ?digest=` to seal. No
cross-repo `?mount=` attempt was observed. Mid-push, the client reset
one kept-alive connection (tolerated, not an error).

### Y.3 Findings ledger

| # | Finding | Where it lands |
|---|---|---|
| Y-1 | The seal digest arrives **percent-encoded** (`sha256%3A…`) in the query string | D4/J.7 must percent-decode before comparison — this lab's own first run reported false mismatches on exactly this; a registry that string-compares raw query bytes rejects every real push |
| Y-2 | Layer PATCH bodies are `Transfer-Encoding: chunked` with **no Content-Range and no Content-Length** (client compresses on the fly); only the known-size config used Content-Length | J.7's append path must stream on byte-count, never on a declared length; `max_blob` enforcement is a running counter, not a header check |
| Y-3 | 5 HEAD probes for 3 uploads — existence-check is the hot path, and a 200 elides an entire upload | D4's blob HEAD must be a cheap stat (it is: store layout is digest-addressed); it is also the dedup lever that makes repeated pushes ~free |
| Y-4 | The token endpoint received **repeated `scope` query parameters** | same merge lesson as W-1's repeated Accept: parse all `scope=` occurrences — D4.5's challenge/token glue and any D1 upstream-dance test fixture must model this |
| Y-5 | The round-trip is deterministic: pushed layer digests and the manifest (`ae84ad1a…`) came out byte-identical to the original OCI export | digest-addressed storage dedups across pull/push directions for free; the D5 `brixoci copy` path inherits this |
| Y-6 | One kept-alive connection reset mid-push | like W-2: tolerate silently — not an error metric, not a guard signal |

### Y.4 Reproduction

```
python3 ycap.py > ylab-trace.log 2>&1 &          # port 14104
podman push --tls-verify=false localhost:14100/brix-whlab:demo \
            docker://localhost:14104/brix-whlab:demo
kill %1 && cat ylab-trace.log                    # → Y.1/Y.2 traces
```

`ycap.py` is the seed of the D4 test suite's *client-conformance*
fixture: the G-spec mock registry replays exactly these transitions, and
`tests/test_oci_registry_push.py`'s success leg asserts the J.7 matrix
against this trace shape.

## Appendix Z — the headline chain, executed end-to-end (2026-08-17)

The phase's reason to exist, run as one pipeline with **zero new C**:

```
OCI image (U)  →  flattened rootfs (U)  →  brixcvmfs repo publish (rev 8)
   →  static nginx serving the repo dir  →  brixcvmfs FUSE mount
   →  podman run --rootfs <mount>/images/whlab:O   →  correct output
```

The container that ran printed `marker` (the top layer's added file) and
`MOTD-GONE` (the whiteout) — layer semantics preserved through flatten →
publish → HTTP serve → cvmfs mount → overlay. Serve plane: system
nginx 1.20.1 with a single `location /cvmfs/demo.brix.lab/ { alias
<repo>/; }` — the second demonstration (after W-5) that the data plane
is static files.

### Z.1 The numbers

| Step | Measured | Notes |
|---|---|---|
| `repo publish` of the 518-entry rootfs (alpine ± 2 changes) | **0.75 s** wall, 19.3 MiB peak | vs 2.04 s publishing alpine into an *empty* repo (V.1): CAS idempotent puts skipped every object the V lab already stored — **incremental republish is free at the store layer** |
| mount + first file read | 6 GETs, **~32 KiB** | whitelist 406 B · manifest 513 B · certificate 756 B · root catalog 4 383 B · `/images` nested catalog 25 928 B · file object 15 B — §6.2 of the ops doc, now measured |
| `podman run --rootfs …:O`, cold | **4.07 s**, 4 GETs, **~903 KiB** | the run's true working set: 2 small `/etc`-class objects + 2 payload objects (496 KB + 406 KB compressed — busybox and its loader), out of an 8 MiB / 518-entry tree |
| same, warm | **1.98 s, 0 GETs** | everything from the verified client cache |

### Z.2 Findings ledger

| # | Finding | Where it lands |
|---|---|---|
| Z-1 | The headline claim is **demonstrated**: image → published revision → mounted → running container ≈ 6 s end-to-end on this workstation, no brix server C anywhere | the D8/D9/D14 composition is de-risked to "front-end work"; §I sizing keeps its shape |
| Z-2 | CAS dedup delivered incremental republish before D8's layer-set memo even exists (0.75 s vs 2.04 s) | the memo's job narrows to skipping the *flatten + scan*, not the store — D8.3's cost model updated accordingly |
| Z-3 | Laziness quantified: running the container fetched **11 %** of the tree's bytes; metadata cost was one nested-catalog GET, because the dirtab row for `/images/*` nested the subtree | V-4's "cheap insurance" now has a measured payoff at run time; D8 keeps planting per-image dirtab rows |
| Z-4 | Two rootless traps, both surfacing as misleading `ENOENT`: (a) the FUSE mount needs `-o allow_other` (+ `user_allow_other` in `/etc/fuse.conf`) or podman's userns cannot see *into* it; (b) podman's pause process snapshots the mount table at first use — a mount created afterwards does not exist in the userns until `podman system migrate` | D10's lane docs + `docs/05-operations/` runbook: both are pre-flight checks, and the D10 error leg asserts the *symptom text* so operators can grep their way out |
| Z-5 | `--rootfs <mnt>:O` (fuse-overlayfs upper over the brixcvmfs FUSE lower) works rootless | the documented CVMFS+podman idiom reproduces on our stack — D10's success leg runs exactly this |

### Z.3 Reproduction

```
./brixcvmfs repo transaction repo
cp -a whlab/rootfs/. repo/.brixtxn/upper/images/whlab/
./brixcvmfs repo publish repo --dirtab dirtab.txt        # → rev 8, 0.75 s
nginx -p "$PWD/ngxlab" -c "$PWD/zlab.conf"               # alias → repo/
export BRIXCVMFS_SERVER=http://127.0.0.1:14100/cvmfs/demo.brix.lab
export BRIXCVMFS_PUBKEY=$PWD/repo/keys/demo.brix.lab.pub
export BRIXCVMFS_CACHE=$PWD/zcache
./brixcvmfs demo.brix.lab "$PWD/mnt" -o allow_other
podman system migrate                                    # Z-4(b)!
podman run --rm --rootfs "$PWD/mnt/images/whlab:O" /bin/sh -c 'cat /media/keep'
fusermount3 -u "$PWD/mnt"                                # ALWAYS unmount
```

The D10 lane is this recipe with the official client substituted on the
mount leg and the tamper/error legs added; the orphaned-FUSE-mount fleet
gotcha is why the unmount line is part of the recipe, not an afterthought.

# Status

**DELIVERED (2026-08-19).** D0–D14 and D15.1–D15.10 are implemented, wired
into the build, documented and under test; what remains of D15 is the
containerd **snapshotter plugin** alone — Go inside containerd's process, as
distinct from the layer encodings this tree now both reads (§D15.7) and
writes (§D15.8) — and it stays deferred exactly as §D15 records it. No C in
this repository is left unwritten for it.
The design record below (body + Appendices A–Z) remains the normative
account of *why*; where the implementation and a design statement disagree,
the **DRIFT** table is the reconciliation and the code is the winner.

## Delivery map

| Feature | State | Lane | Tests |
|---|---|---|---|
| D0 `/v2/` classifier + gate | delivered | `tests/test_oci_mirror_classify.py` + `fuzz_oci_classify` | 40 + fuzz |
| D1 upstream Bearer dance + token zone | delivered | `tests/test_oci_mirror_authdance.py` + `fuzz_oci_challenge` | 16 + fuzz |
| D2 cache policy + `.ocimeta` sidecar | delivered | `tests/test_oci_mirror_cachepolicy.py` | 13 |
| D3 metrics + guard + podman oracle | delivered | `tests/test_oci_mirror_podman_pull.py` | 4 (1 opt-in skip) |
| D4 local registry push surface | delivered | `tests/test_oci_registry_push.py` | 29 |
| D5 `brixoci` CLI | delivered | `tests/test_oci_brixoci_copy.py` | 25 (13 + D15.2's 12) |
| D6 streaming tar reader | delivered | `tests/test_oci_tar_corpus.py` + `fuzz_tar_header` | 12 (+ D15.7's 5) + fuzz |
| D7 layer flattener → overlay grammar | delivered | `tests/test_oci_flatten.py` | 13 (+ D15.7's 2) |
| D8 `brixcvmfs ingest image` + `prune` + `--verify-diffids` | delivered | `tests/test_cvmfs_ingest_image.py` | 14 (+ D15.6's 6, D15.7's 2) |
| D9 `brixcvmfs ingest dir` | delivered | `tests/test_cvmfs_ingest_dir.py` (over `cmdscripts/cvmfs_ingest_dir.py`) | 5 |
| D10 official-client + `podman run --rootfs` oracle | delivered | `tests/test_cvmfs_ingest_oracle.py` | 4 |
| D11 dnf pull-through mirror (config recipe) | delivered; superseded as the default by §D15.9 | `tests/test_rpm_mirror_dnf.py` | 5 |
| D12 `brixrpm createrepo` | delivered | `tests/test_rpm_createrepo.py` + `fuzz_rpm_header` | 19 + fuzz |
| D13 rpm-repo → CVMFS runbook | delivered | `tests/test_rpm_cvmfs_compose.py` (over `cmdscripts/rpm_cvmfs_compose.py`) | 3 |
| D14 composition recipes | delivered | `tests/test_oci_compose_secure.py` | 8 |
| D15.1 referrers API + `OCI-Subject` | delivered | `tests/test_oci_registry_referrers.py` (+ 2 rows inside the D0 classify lane) | 31 |
| D15.2 IPv6-literal refs (shared authority grammar) | delivered | `tests/test_oci_brixoci_copy.py` | 12 (inside the D5 lane) |
| D15.3 registry GC (`brixoci gc`) | delivered | `tests/test_oci_registry_gc.py` | 14 |
| D15.4 sha512 digests end to end | delivered | rows inside the D0/D2/D4/D15.3 lanes, over `oci/mock_registry.py`'s all-sha512 `lab/sha512app` | 7 |
| D15.5 background in-proxy GC (`brix_oci_gc_interval`) | delivered | `tests/test_oci_registry_gc_background.py` | 6 |
| D15.6 non-flat layered publish (`--layout layered`) | delivered | rows inside `tests/test_cvmfs_ingest_image.py` | 6 |
| D15.7 lazy-pull layer encodings (eStargz, `zstd:chunked`) | delivered | rows inside `tests/test_oci_tar_corpus.py`, `tests/test_oci_flatten.py`, `tests/test_cvmfs_ingest_image.py` | 9 |
| D15.8 eStargz layer building (`brixoci convert --estargz`) | delivered | `tests/test_oci_stargz.py`, `tests/test_oci_convert_estargz.py` | 24 |
| D15.9 native RPM mirror (`brix_rpm_mirror`) | delivered | `tests/test_rpm_mirror_native.py` | 20 |
| D15.10 warm repodata prefetch (`brix_rpm_prefetch`) | delivered | rows inside `tests/test_rpm_mirror_native.py` | 4 |
| D15.11 explicit realm allowlist (`brix_oci_upstream_auth_realm`) | delivered | rows inside `tests/test_oci_mirror_authdance.py` | 4 |
| D15.12 `--require-digest` (ingest image) | delivered | rows inside `tests/test_cvmfs_ingest_image.py` | 3 |
| D15.12 `--paranoid` (createrepo memo) | delivered | rows inside `tests/test_rpm_createrepo.py` | 3 |
| D15.13 documented-flag guard (`check_client_flags_doc.py`) | delivered | rows inside `tests/test_ci_guards_b.py`, `tests/test_xrdcp_transport_opts.py` | 11 |
| D15 remainder (the containerd snapshotter plugin) | deferred, per §D15 | — | — |

Full phase-104 lane set on 2026-08-19 — the twenty-two
`tests/test_{oci,rpm,cvmfs_ingest}_*.py` files, **348 collected, 347 passed,
1 skipped** (the opt-in live-DockerHub leg, `BRIX_OCI_LIVE_DOCKERHUB=1`) in
221 s serial. (Earlier editions quoted 320/324 for "twenty-one lanes": that
figure was a stale hand-count that had dropped a lane, corrected here by
`--collect-only` over the same glob.) It was ~110 s before §D15.5, and the
difference is that lane's six rows waiting on a real 1 s timer rather than
driving a tool synchronously — a background feature can only be tested by
letting time pass. §D15.8's two lanes add the rest: the convert oracle pulls,
creates, exports and removes two images through podman, twice per comparison.
(§D15.9 + §D15.10's twenty-four rows cost about 42 s together.) §D15.12's six
rows add a second registry seed and a whole-file re-hash pass; the run-to-run
spread on this host is wider than that, so read the wall clock as an order of
magnitude, not a measurement. The numbers in
the map above are *collected* rows, so a parametrized case counts once per case
— which is why they exceed a `grep -c '^def test_'`.
Plus the four
libFuzzer kernels §H asked for — `fuzz_oci_classify`, `fuzz_oci_challenge`,
`fuzz_tar_header`, `fuzz_rpm_header` — in the opt-in protocol-fuzz lane
(`PHASE81_RUN_FUZZ_PORT=1 test_cmd_fuzz_all.py`, fourteen targets green;
the four new ones also run 180 s each with no finding; `fuzz_tar_header`
also fuzzes the diff-id capture, 29 840 runs clean after it landed). The
last three are D8.e's — an honest config verified, a lying config refused,
a short `diff_ids` list refused (DRIFT 24). The fifteen before them came
from auditing the delivered lanes against Appendix F's
roster: nine properties the roster named and no lane had pinned — namespace
expansion sharing one cache key, retag atomicity under a read hammer, the
idle-session reaper, the manifest document cap, cross-layer hardlinks, a
hardlink to a whiteouted target, the two metadata bombs, and the podman
export oracle — plus six that splitting the two aggregate drivers made
individually visible. Three of the nine found something the code or the
harness had wrong (DRIFT 20, 22, 23). Guards green:
`check_config_coverage`, `check_client_build_coverage`, `check_metric_names`,
`check_metric_cardinality`, `check_complexity`, `check_file_size`,
`check_vfs_seam`, `check_ports_doc`, `check_doc_paths`.

New fuzz kernels: `tests/fuzz/fuzz_{oci_classify,oci_challenge,tar_header,rpm_header}.c`
with their seeded corpora, registered in `cmdscripts/fuzz_all.BUILD_ARGS`
and carried by the existing `.github/workflows/fuzz.yml` lane.

New C: `src/protocols/oci/` (17 TUs + 7 headers), `shared/oci/` (14 TUs:
tar, tar_pax, tar_digest, flatten, stargz, stargz_toc, name, digest,
challenge, url, authority and the three unittest drivers),
`shared/rpm/` (rpmhdr, repomd_write), `client/apps/oci/` (front, copy pump,
the eStargz converter and the two `brixoci_gc*` TUs),
`client/apps/rpm/`, and the five `brixcvmfs_ingest*` TUs. Ports claimed in
`docs/10-reference/test-fleet-ports.md`: 14100–14121 (mirror + podman
oracle), 14140–14155 (`brixoci` mocks + registry push, referrers and gc), 14160–14162 (dnf
mirror), 14200–14212 (composition); the two ingest lanes take canonical
bases `srv_ingest` and `srv_ingest_oracle` inside the tiled cvmfs
conformance block rather than a row of their own.

Docs: `docs/04-protocols/oci.md`; `docs/05-operations/oci-mirror.md`,
`oci-registry.md`, `container-ingest.md`, `rpm-mirror.md`,
`rpm-on-cvmfs.md`; rows in `docs/index.md`; ROUTING + OP→FILE rows in
`docs/09-developer-guide/agent-guide-extended.md`. Operator recipes:
`deploy/oci-mirror/nginx.conf.example`,
`deploy/oci-mirror/full-stack.conf.example`,
`deploy/rpm-mirror/nginx.conf.example`, and the two fail2ban assets
(`xrootd-guard-ocipush` enabled, `xrootd-guard-oci_tamper` shipped
disabled — §D3.2's reasoning, made explicit in the jail comment).

## DRIFT — where the code and this document disagree

Each row is a place the implementation taught us something the plan had
wrong or under-specified. The code is authoritative; the row records the
correction so the appendices stay honest.

| # | Document says | Code does | Why the code is right |
|---|---|---|---|
| 1 | App. G.2: a forced `brix_cache_verify require` mode for digest objects | `brix_cache_verify oci-digest` is the whole spelling; a digest-named object is verified because the **key** names the digest | a second mode would be a way to spell "verify, but not really" |
| 2 | D0.3: `brix_oci_mirror_insecure` relaxes upstream TLS | it permits a **cleartext `http://` base** only; certificate verification is never disabled | one flag, one meaning, and the dangerous half is the one nobody needs |
| 3 | App. G.3: lanes register in `fleet_specs` | mirror lanes drive `LifecycleHarness` + `tests/oci/mirror_lane.py`; the compose lane holds a module-scoped harness of its own | these servers are per-test cache fixtures, not fleet members — "cold" has to mean cold |
| 4 | J.6: `$oci_cache` distinguishes `wait`/`reval`/`stale` | five values: `hit fill local refused error` | a coalesced waiter and a revalidation both **end** as the fill that satisfied them; staleness is on the response as a `Warning` header |
| 5 | D2.5: `Warning: 110` echoed from the tier | derived from the `.ocimeta` fetch time | the sidecar is the only record that survives a restart |
| 6 | D0.4: assert "zero upstream requests" for `GET /v2/` | asserted as "the mock recorded no hit" | there is no such thing as observing a request that was never made; the mock's hit ledger is the observable |
| 7 | App. F: `test_toomanyrequests_echoed_with_retry_after` | `test_toomanyrequests_maps_to_429_with_retry_after`; `Retry-After: 5` is **ours** | the upstream header does not survive the fill's thread-pool boundary, and our own next-attempt time is the honest number anyway |
| 8 | J.4: upstream 5xx → a 502 envelope | the fill tier's keep-alive **504** + `Retry-After: 2` | the tier owns retry/backoff; intercepting its exhaustion to re-dress it as 502 would lose the backoff signal |
| 9 | D1.5: token-endpoint failures surface as `ENOKEY` | they surface as our **502** with an `UNAVAILABLE` envelope | a registry client parses the envelope; an errno is not on the wire |
| 10 | App. B.2: a `sha256.ckpt` resume checkpoint file | the **staged part-file itself** is the session state | bytes on disk cannot disagree with reality; a checkpoint can |
| 11 | D4.5: "no issuer configured and anonymous off" as a distinct refusal | unreachable — it is the ordinary 401 + challenge | fewer shapes for a client to have to understand |
| 12 | D2.2: conditional revalidation upstream | the mirror never sends `If-None-Match`/`If-Modified-Since` | a tag manifest is small and a digest object is immutable; there is nothing a 304 would save |
| 13 | App. B.1: `etag` is the upstream's | the ETag we publish is the **strong digest** of the bytes we hold | our ETag must describe our bytes |
| 14 | App. B.1: `verified=1` for anything digest-checked | **tag** manifests record `verified=0` | a tag is not a digest; nothing was checked against a name that does not carry one |
| 15 | D3.2: one `deploy/fail2ban/brix-oci.conf` | the tree's `xrootd-guard-<signal>.conf` convention: `[xrootd-guard-ocipush]` and `[xrootd-guard-oci_tamper]` | one jail per signal is how every other guard here ships |
| 16 | D3.3: mirror-down leg answers 502; lane runs on docker or podman | 504; **podman specifically** | only podman can be told to trust a cleartext registry per invocation — editing `daemon.json` is not something a test may do |
| 17 | D1 (implicit) | two real defects the oracle exposed and fixed: a 1 KB header clip on JWT bearers, and a dropped redirect query on signed CDN URLs | both now have mock regressions in the authdance lane |
| 18 | D14: "wrong-token **403** remains terminal" | `brix_cvmfs_repo_authz_eval` answers **401** for invalid/expired/out-of-scope bearers; 403 is the x509 "verified but unlisted" shape | the property under test is **terminality**, and it is unchanged; the lane is `test_wrong_token_terminal_no_fallthrough`, and the 401/403 matrix is pinned separately on the gated Stratum-0 leg |
| 19 | D14: three legs | five, plus a parse test: the extras are `test_full_stack_serves_mirror_registry_and_stratum0`, `test_mirror_stays_read_only_inside_the_composition`, and a parametrized `nginx -t` of both shipped `deploy/oci-mirror/` recipes | the parse test earned its keep immediately — it caught `brix_oci_max_blob_size 8g` (nginx sizes take k/m) and a `brix_cvmfs` + `brix_webdav` collision on one listener in a recipe an operator would have pasted |

| 20 | D7.1: a hardlink whose target cannot be linked "degrades to a byte copy" | it does — but the copy path used to create the destination *before* opening the source, so a link to a target an earlier layer had whiteouted was refused **and** left a zero-length file standing under the link's name | the refusal is loud, yet the tree it left behind had a name that exists and does nothing: `bin/sh` present, exec silently succeeding. Source opened first now, and a copy that fails partway unlinks what it wrote (`shared/oci/flatten.c`, pinned by `test_hardlink_to_a_whiteouted_target_is_refused`) |
| 21 | App. F: `test_bomb_cases_bounded` covers a pax-record flood via `TAR_PAX_REC_MAX` | the 160 KiB whole-pax-body cap fires first and always: at five bytes per minimal record it bounds the count at ~32 k, half the record cap | the record cap is unreachable, which makes it a belt rather than the trousers — the lane pins the bound that actually holds, plus the separate `TAR_XATTR_MAX` flood that fits *inside* the byte cap and therefore needs its own bound |
| 22 | D10.3 offers `podman export` as the flattener's oracle without qualification | it is an oracle for everything except a **cross-layer hardlink**: containers/storage unpacks each layer into an empty directory before stacking it, so a link whose target arrived in an earlier layer fails the pull outright (`unpacking failed … no such file or directory`) — an in-layer link unpacks fine | the difference is in the unpacker, not in the grammar: a running overlay resolves the link against the merged tree, which is what our flattener models. `test_podman_export_diff_clean` therefore links within one layer and the cross-layer case keeps its own dedicated test — an oracle you cannot ask a question is better named than quietly narrowed |
| 23 | §H's fuzz registration checklist assumes the protocol-fuzz lane runs as-is once a corpus is added | the lane could not pass at all: `test_cmd_fuzz_all.py` carried no timeout mark, so the suite-wide 30 s default killed it during the sanitizer *builds*, before one input was tried — the opt-in gate meant nobody had noticed | a lane that cannot report green is not a lane. Its budget is now derived from the roster it will actually run (per-target build allowance + `$FUZZ_TIME`) rather than a guessed constant, so adding the eleventh kernel widened it automatically |
| 24 | Residuals: `--verify-diffids` costs "a second decompression of every layer", so it was cut | it costs **no** second inflate: the diff_id is a hash of the bytes the flattener is already decompressing, so `shared/oci/tar_digest.c` hangs a streaming sha256 on the reader's byte source and the check is one hash pass over data already in registers | the deferral had priced the *naive* implementation — fetch the layer again, inflate it again, hash it. Putting the hash where the bytes already flow turned a "second pass over every layer" into a flag with no data-plane cost at all, which is the difference between a feature worth cutting and one worth shipping. The blob ledger is identical with and without the flag, and `test_verify_diffids_accepts_an_honest_config` asserts exactly that |
| 25 | Residuals + App. V: "the fsync-batching lever V-3 is unclaimed", and I.3/O.3 quote a 95 s cold bulk import | the lever had already landed: `publish.c` runs the CAS in `no_fsync` batch mode and barriers the whole store with one `syncfs` before the manifest swap, which measures **10.0 s** for the same 10 k-file import | a doc that describes work as pending after the code has shipped it is the same class of error as one that claims work not done — both send the next reader to the wrong place. The lever's correctness argument is not prose either: the crash hook fires in exactly the window between the barrier and the swap, so `crash-rev-intact` and `fsck --data` in the D9 lane are what makes "semantically free" a tested claim rather than a plausible one |
| 26 | §D15 and the Non-goals list park the referrers API as "artifact clients still evolving", waiting on a site asking for server-side verification | it is **delivered** (§D15.1): `oci_referrers.c`, the `referrers/sha256/<subject>/<referrer>` store, `OCI-Subject` on the PUT, the `?artifactType=` filter with `OCI-Filters-Applied`, and the mirror-side uncached passthrough | the deferral had priced it as a new subsystem. It is not one: the classifier already matched reserved terminals right-to-left, the mirror already had an uncached-listing route, and the store already had the primitives — so the API is one small TU over seams that existed. What made it worth building anyway is that the cut had the cost backwards: a registry WITHOUT referrers is what pushes cosign onto the tag-schema fallback, and that fallback is the thing that ages badly, not the API |
| 27 | §D15 and the Non-goals list park IPv6-literal refs as a "grammar collision, zero observed demand", and §D5.1 says the parser refuses them cleanly | they are **delivered** (§D15.2): `brix_oci_url_authority()` in `shared/oci/authority.c` parses the authority for *both* the proxy's base-URL/realm grammar and the CLI's ref grammar, and `[::1]:5000/lab/app:v1` pulls over a real AF_INET6 dial | the collision was priced as a new grammar to write. It was the opposite: the grammar already existed and was already the security-critical one (a `realm=` names a host we are about to hand a credential to), so the honest fix was to *share* it — which also means a host the CLI will dial can no longer be a host the proxy would have refused. The build detail is the part that nearly bit: `ar` keys members by basename, so `shared/oci/url.c` in `LIB_SRCS` would have silently displaced `client/lib/net/url.c` inside `libbrix.a` — hence a separate TU, not a bigger one |
| 28 | §D15 defers registry-side GC on the grounds that "explicit `rm`/`prune` + **refcount marks** are enough at site scale"; §D4.4 says a blob is removed "when no marks remain (refcount walk)" | GC is **delivered** as the operator-run `brixoci gc` (§D15.3), and it computes liveness from **manifest bodies**, never from the marks — the marks are per-repository bookkeeping written at upload seal, so they can outlive the manifest that justified them (dropping the stale ones is itself one of the three sweeps) | a refcount you increment at seal time and never decrement at delete time is not a refcount, and the plan had leaned on it twice. Reading the manifests is the only source that cannot drift, because it *is* what the registry serves. The cut was right about one thing and the section keeps it: this belongs in a tool with a grace window and a whole-store read, not in a timer on the event loop |
| 30 | §0.0 calls the digest *grammar* parser "algorithm-agnostic" and prices sha512 as a "~10-line kernel addition (enum + EVP hookup)" | the parser was algorithm-agnostic and **nothing downstream of it was**: it returned an algorithm no caller read. sha512 (§D15.4) touched the checksum kernel, the mirror's verify-at-edge, the registry store and seal, the whole of `client/lib/oci/`, the image layout, `brixoci gc` and both ingest tools — and it found two latent defects on the way | pricing a feature off the layer that *parses* it is how a change that spans eight surfaces gets filed as ten lines. The parse was never the work; the work is every place that took the parsed value and threw the algorithm away. The two defects are the evidence that this was not busywork: `brix_oci_reg_manifest_del` held its digest in a `char[80]` and would have issued a DELETE against a **truncated** — that is, different — reference, and the ingest read its hex with `digest + 7`, a fixed skip past `"sha256:"` that silently mis-slices any other name |
| 31 | §D4.3, §D8 and §D15.3 spell the store's algorithm directory as the literal `sha256` (`blobs/sha256/<xx>/<hex>`, `.images/sha256/<hex>`, "a root that does not hold both `blobs/sha256` and `repos/`") | the layouts were right and only the *prose* was literal: the directory component is now `brix_oci_alg_name()`, so **no store on disk had to move**. What did change is that the GC marks under every algorithm before judging anything, and sweeps each `blobs/<alg>` | the layout had the algorithm in it from the start and the code kept writing the one constant into it — the same shape as DRIFT 30, one level down. The rule that let the flat things stay flat is worth keeping: no two registered algorithms share a hex width, so a bare hex re-parses to exactly one algorithm (`brix_oci_digest_parse_hex`, and `BRIX_OCI_ALG_COUNT` pinned to the table by `_Static_assert`). The mark-before-sweep ordering is the part with teeth: a mark walk that visits `manifests/sha256` alone does not fail loudly, it deletes live sha512 blobs |
| 29 | Cross-cutting/Build wiring sends `shared/{oci,rpm}/*.c` to `./config` **and** `client/Makefile` alike, on a "shared-tree convention" | that is not what shipped, and the whole-directory rule it implies is the wrong shape. `./config` names exactly five: `name.c`, `digest.c`, `challenge.c`, `url.c`, `authority.c`. The tar reader, its pax/digest halves, the flattener, the eStargz writer and its TOC half, and both `shared/rpm/` TUs are in `client/Makefile` alone; the three `*_unittest.c` drivers are in neither — the D6/D7/D15.8 lanes compile them on the spot | `./config` is the list that links a file into every nginx worker, so the discriminator is not which tree a file lives in but whether a worker evaluates it. A worker *does* parse a repository name, a digest, a `WWW-Authenticate` challenge and an authority — that is its URL surface and its auth dance — and those are the same grammars the CLI needs, which is the whole reason they are shared. A worker must never untar a layer or parse an RPM header (prime directive 1, the same G14 ruling DRIFT 12 records for the seam guard). Following the sentence literally would have pulled all three into the request path |
| 32 | §D15 defers a *background* in-proxy GC because "reclamation wants a whole-store read and a grace window, not a timer on the event loop", and the Non-goals list says it twice | it is **delivered** (§D15.5): `brix_oci_gc_interval` arms a worker-0 `cancelable` maintenance timer that hands the same `brix_oci_gc_run()` the tool calls to the `default` thread pool, one store at a time and never while a pass is in flight | the objection was sound and was an argument about *where the walk runs*, which the deferral then spent on *whether a schedule may start one*. Both of the things it protected are still true — the walk is not on the event loop, and the grace window is still what makes an unattended pass safe — and neither of them needed the feature withheld. What made it worth building is the deployment the cut had not costed: an appliance or a container image with one config file and no shell accepts `DELETE`s all day and has nobody to run `brixoci gc`. The move that made it cheap is that the kernel became `shared/oci/gc.{c,h}` with a context struct instead of a CLI options struct, so both callers run one implementation — a tool and a server that disagree about what garbage is would be a disagreement neither side could see |
| 33 | §D5.2 puts the manifest-walking JSON iterator in `client/lib/cli/json_iter.c`, "beside `client/lib/cli/jsonout.h`", and the file-roster row said the same | it lives in `src/core/compat/json_iter.{c,h}` — beside `json_min` itself, which is what its own header comment had claimed all along | the include roots decide this, not taste: the module builds with `-I$addon/src -I$addon/shared` and the client with `-Ilib -I$SRC -I../shared`, so a TU both trees compile may include from `src/` and `shared/` and never from `client/lib/`. The GC mark phase is the first server-side code to walk a manifest body, and it made the asymmetry load-bearing — the iterator could not be shared where the plan had filed it. Worth stating as a rule: `client/lib/` is where code goes *because* the server must not have it, so a file put there for proximity rather than for that reason is a file that will have to move |
| 34 | §D15 defers non-flat per-layer publish because "the CAS already dedups identical *files*", and the Non-goals list carries the same reasoning | it is **delivered** (§D15.6): `--layout layered` publishes `<prefix>/.layers/<alg>/<hex>/` per layer with a `.layers` descriptor on the image root, and a base layer already published is never fetched, decompressed or scanned again | the cut priced the feature against **storage** and won that argument — and then treated the answer as covering a question it had not asked. Deduplicating the stored bytes does nothing about the *work*: the flat layout has no name for "this layer, on its own", so every image off a base re-fetches, re-inflates and re-scans it. What the deferral was right about is now the flag's justification instead of its refusal: a flat image root is a runnable rootfs and a layered one needs a composing consumer, which is exactly why flat stays the default rather than why layered stays unbuilt |
| 35 | §D6 says the tar reader inflates gzip layers, and the D6 lane called that covered — every archive it built was a single gzip member | a **chain** of members or frames (what every lazy-pull converter emits) was read to the end of the FIRST one and reported success: a seven-entry eStargz layer dumped two entries and exited 0, and a `zstd:chunked` layer whose TOC frame leads the stream dumped none. Fixed in §D15.7: member/frame continuation, a skippable-frame-aware sniff, and eStargz's own entries dropped at the archive root | the reader was never *wrong* about a shape it had been shown; the corpus simply never showed it one, because Python's `tarfile` and every hand-built fixture write exactly one member. That is the shape of this defect: not an unimplemented feature but an untested axis of an implemented one, and the failure mode it hid was the worst available — silence. The counter-fixture is cheap and belongs beside the format tests it generalizes: build the corpus, then re-encode the SAME bytes in the shape the ecosystem ships |
| 36 | §D15 lists eStargz **building** as part of the deferred snapshotter row, i.e. as work that comes with the containerd plugin | it is **delivered** on its own (§D15.8): `brix_stargz_convert()` writes the format and `brixoci convert --estargz` rewrites the image around it, leaving the deferred row to the Go plugin alone — and it is an **image** rewrite, not a blob filter, because reframing changes each layer's diff_id and so invalidates the config that names it | the row had bundled two things that share a name and nothing else: a format an ordinary tool writes, and a runtime that lives inside containerd's process. Bundling them made the writable half look like it needed the plugin's architecture, when what it actually needed was the tar reader this phase already had — the converter emits no tar of its own, it copies the source's bytes through and rewrites only the gzip framing. The trap the build found is worth the row by itself: the 512-byte padding after a body has to ride in the **body's own** gzip member, and getting it wrong yields a blob that is valid gzip and invalid tar — which every check that only decompresses reports as fine |

| 37 | §D11 prices the RPM mirror as "config + policy; **no new C expected**", and the Delivery map recorded it as delivered config-only | the recipe shipped and stays shipped, but the plane it describes is now a protocol module (§D15.9): `brix_rpm_mirror`, a route classifier, a `rpm-repodata` verify mode, a 405-at-the-gate write refusal with its own guard signal, and its own metric family. The recipe is what a site puts in front of stock nginx; the module is what this server does | the estimate was right about the *cache* and wrong about everything a cache cannot do. `proxy_cache` can match `repomd.xml` and it cannot check that `<sha256>-primary.xml.gz` hashes to the name it arrived under — which is the one guarantee an RPM repository hands a mirror for free, and the same self-addressing grammar this phase had already implemented twice (`cvmfs-cas`, `oci-digest`). A recipe also cannot refuse: a `PUT` into a repository path reaches the upstream under `proxy_pass` and is answered 405 before the store is touched under the module. The second correction inside the row is the never-drop status: a transient upstream failure answers a keep-alive **504 + `Retry-After`**, not the 502 the D11 lane assumed, because the shared T20 fill plane holds a waiter to its deadline and then declines to invent a definitive answer — 404 means "the repository says no", 503 means "ask again", and collapsing the two is what turns a mirror hiccup into a client-side dependency error |
| 38 | Appendix X's finding X-3 was recorded as a **property of D11's cache policy** ("the D11 warm-prefetch set is {repomd, primary, filelists}"), i.e. as something the config recipe expressed | it was never expressible there at all, and is now a feature of its own (§D15.10): `brix_rpm_prefetch` reads the freshly filled index, re-checks each `<location href>` with the request grammar, and warms the two objects on the thread pool | the row is the same mistake §D11 made about verification, in a second place: a `proxy_cache` block can only cache what a client asked for, so a "prefetch set" written into a cache policy is a description of what the client will ask for next, not an instruction anything can act on. Naming it in the policy section made it look implemented. What made it cheap once the C plane existed is that nothing new had to be invented for it — the fill is `brix_sd_cache_fill_key()`, the safety check is `brix_rpm_classify()`, and the trigger is a disposition the handler already computes; the only genuinely new code is a reader for an XML shape createrepo writes and the composition of a sibling key. The one thing worth stating plainly is the direction of trust: `repomd.xml` is the only route in this plane that is not self-verifying, so its contents are treated as untrusted input that must survive the same grammar a client request survives — and what survives is digest-named, which means the warm fill verifies exactly like the client fetch it replaces |
| 39 | Appendix L promises the token-realm mitigation as "the upstream host **or its explicit `brix_oci_upstream_auth_realm` allowlist entry**", and cites an appendix (A.4) that is about image configs | only the derived half existed: `brix_oci_url_realm_allowed()` accepted the upstream host, its registrable parent or a sibling under it, and there was no directive of that name anywhere in the tree | the row is a promise made by a threat model about code that was never written, which is the most expensive kind of documentation error: it reads as a completed mitigation on review, and the gap only shows up as an operator who cannot mirror their own registry. The derived rule is right for every upstream that hosts its own token service and cannot express one that delegates to an unrelated identity host — a shape distribution's `auth.token.realm` makes ordinary — so for those upstreams the mirror was not strict, it was unusable, and an unusable check is one that gets switched off rather than configured. §D15.11 builds the missing half exactly as promised: exact hosts, no pattern form, the derived rule tried first, the same allowlist applied to every redirect hop, entries validated by the authority parser a realm itself goes through, and one INFO line whenever the widened boundary is the one actually used |
| 40 | Two risk-table rows name operator controls that do not exist — App. L offers `--require-digest` on the registry-MITM row, App. B.7 offers `--paranoid` on the memo — and App. E's P6 names `--skip-bad` | `brixcvmfs ingest image` parsed neither a `--require-digest` nor anything like it; `brixrpm createrepo` trusted `(size, mtime)` with no way to ask for more; `--skip-bad` described the DEFAULT behaviour, whose real opt-out is spelled `--strict` | the same defect as DRIFT 39, found by the same audit pointed at flags rather than directives, and it splits into the two kinds worth telling apart. The first two are missing code behind a promised control: a reader auditing the pull path sees a pinning option in the mitigation column and stops looking, and an operator who goes to type it finds nothing — so the threat is neither mitigated nor visibly unmitigated. The third is the cheaper kind, a real behaviour under a wrong name, which costs an operator one failed command rather than a false sense of cover; it is corrected in the table rather than aliased in the tool, because inventing `--skip-bad` to match a typo would leave two spellings of one default forever. §D15.12 builds the two controls and renames the third |
| 41 | Sixteen places across the README and seven operator pages tell the reader to run `xrdcp --allow-http` (one says `--allow-tls`), and fourteen plan/audit lines name flags nothing builds | this client's `xrdcp` parsed neither spelling: `--allow-http` was an unknown option, and `--allow-tls` is not a flag in stock XRootD either | found by mechanising DRIFT 40's audit as `tools/ci/check_client_flags_doc.py`, and it is the mirror image of that finding — not a doc promising code that does not exist, but code refusing a command line the whole field writes. `-A/--allow-http` is stock xrdcp's gate on the XrdClHttp plugin; this client has no such gate, so the flag asks for a permission already granted, and rejecting it broke every WebDAV recipe written for the stock binary, including this repo's own interop suite. §D15.13 accepts it as an exact-translation no-op (never a TLS relaxation — pinned by test), corrects the `--allow-tls` typo to `--tls`, and marks each of the fourteen honest proposals, quoted stock spellings and one third-party name collision (`xrd` = XrdRust) with the reason it is not ours to parse |
| 42 | `src/protocols/oci/` and `src/protocols/rpm/` carry no `README.md` | `check_readme_coverage.py` — a blocking guard — had been failing on both since §D0 and §D15.9 landed them | the orientation layer is what an auditor reads first, and its absence is exactly the kind of gap that a green-looking wave hides: every phase-104 test lane was passing while a required guard was red, because the lane set and the guard set are run by different commands. Both READMEs are written from the file headers (surfaces, gating, per-file responsibility, and the invariants each plane holds) rather than from the plan, so they describe what shipped |
Rows 32–36 came out of §D15.5 through §D15.8, and are the same two shapes one
more time: a parking-list row that had been priced as a subsystem, and a
plan sentence about *where a file lives* that the build's include roots
overruled. 34 adds a third: a cut whose cost argument was sound about the
axis it measured and silent about the one that mattered. 35 adds a fourth,
and the least comfortable: a feature that was implemented, tested and wrong
on an axis no fixture in the lane varied. 36 is the first shape again with a
twist worth naming: the deferral was not mispriced so much as **mis-bundled**
— two items under one heading, one of them a week of out-of-repo Go and the
other a writer over seams already in the tree.

37 is a fifth shape, and the only one in this table that is not about a
deferral: an estimate that measured the feature by the machinery it would
reuse and never asked what the reuse could not express. "No new C expected"
was true of the caching and false of the refusing, and the tell was there in
§D11's own prose — it describes filenames that carry their own checksums and
then proposes a mirror that never looks at one.

Rows 18–29 are the audit wave's own, and three of them came from writing a
test Appendix F had asked for and no lane had: 20 found a defect in the
flattener, 22 found the boundary of what the podman oracle can be asked, and
23 found that the protocol-fuzz lane could not have reported green for anyone.
24 is the tail item itself: a residual that stayed a residual only because
the plan had priced the wrong implementation, and 25 is its mirror image — a
residual that had already been implemented and never struck off. 26–28 are
three more of the first kind, all off the same §D15 parking list: each had
been priced as a subsystem and each turned out to be a small piece of work
over seams that already existed, which is worth noticing as a pattern rather
than three times as a coincidence. The rest were recorded as the waves
landed.

## Residuals

- The live-DockerHub mirror leg is opt-in (`BRIX_OCI_LIVE_DOCKERHUB=1`) and
  therefore does not run in CI. It is a weather check, not a gate.
- `--verify-diffids` (D8.e, App. A.4) is **delivered** and off by default —
  see DRIFT 24 for why the cost that had it deferred turned out not to exist.
- Registry-side GC is delivered twice over one kernel: the operator-run
  `brixoci gc` (§D15.3, DRIFT 28) and the `brix_oci_gc_interval` timer
  (§D15.5, DRIFT 32). The original objection is preserved rather than
  overturned — the walk still never runs on the event loop, and the grace
  window is still what a pass is safe by.
- Eight rows came off the D15 parking list and are **delivered**: the
  referrers API (§D15.1, DRIFT 26), IPv6-literal refs (§D15.2, DRIFT 27),
  registry GC (§D15.3, DRIFT 28), sha512 digests (§D15.4, DRIFT 30–31),
  background in-proxy GC (§D15.5, DRIFT 32), non-flat layered publish
  (§D15.6, DRIFT 34), reading the lazy-pull layer encodings (§D15.7,
  DRIFT 35) and writing eStargz (§D15.8, DRIFT 36). What remains deferred
  there is the containerd **snapshotter plugin** and nothing else: Go loaded
  into containerd's own process, over a `Range` blob surface both `/v2/`
  surfaces already serve and layers this tree now both reads and writes.
  There is no C left in that row.
- Appendix L's registry-MITM row and Appendix B.7's memo paragraph are closed
  by §D15.12 (DRIFT 40); Appendix E's P6 row named a flag that never existed
  for behaviour that always did, and now names the real one. The audit that
  found all three is the §D15.11 technique pointed at `--flags` instead of
  directives: extract every flag the document spells, diff against what the
  binaries parse. It is one command and it found three defects, two of them
  in security tables — so §D15.13 stopped running it by hand and made it
  `tools/ci/check_client_flags_doc.py`, blocking, over every document
  including the operations guides. The full-tree run found seventeen more
  (DRIFT 41), and the tree is now at zero with no backlog to grandfather.
- Appendix L's realm row is closed by §D15.11 (DRIFT 39). It is the only
  finding in this phase that came out of auditing the *document* against the
  tree rather than the tree against the document: every directive the file
  names was checked for a definition, and exactly one had none. That sweep is
  cheap and worth repeating per wave — a threat model that names a mitigation
  by directive is asserting a fact about the code, and nothing was checking it.
- Appendix X's finding X-3 is closed by §D15.10 (DRIFT 38): the warm set it
  named is a directive now, not a sentence in a cache-policy section. `other`
  stays out of it — dnf4 never fetches it and dnf5 makes filelists optional
  too, so the set is worth re-measuring the day EL10 becomes a lane.
- `--layout layered` has an honest limitation the runbook states plainly: a
  layered image root is not a runnable rootfs. `podman run --rootfs` wants
  the flat layout, and a layered one has to be composed (overlayfs
  `lowerdir=`, lowest last) from its `.layers` descriptor.
- The sha512 wave had one trap worth carrying forward:
  `tests/cmdscripts/cvmfs_ingest_dir.py` builds a standalone `ingesttool`
  from a **hand-listed** source set, so a new dependency inside an ingest TU
  surfaces as a link error in that lane rather than as a build error
  (`shared/oci/digest.c` had to be added to it). The second trap is the
  binary: the lanes default to `NGINX_BIN=/tmp/nginx-1.28.3/objs/nginx`, so a
  private `--add-module` build proves nothing about the server until that tree
  is rebuilt — a full green lane set against a stale nginx is the failure mode
  that looks exactly like success.
- The 2026-08-19 lane run first came back with one red row,
  `test_cvmfs_ingest_oracle.py::test_tampered_cas_object_refused`, and it was
  **not** a phase-104 defect: a second pytest session was live on the host, so
  this run printed `attaching WITHOUT lifecycle management` and joined a fleet
  it did not own — and the owner's `pytest_sessionfinish` `rmtree(TEST_ROOT)`
  deleted the shared temp tree mid-test. The give-away is in the failure
  itself: `statfs .../oracle0/pub: no such file or directory`, i.e. the
  fixture's own directory had ceased to exist, which no test body can cause.
  The lane is green alone (4 passed) and green with the two other ingest lanes
  (23 passed). Read a red oracle lane as a concurrency report until the host
  is checked for a second session.
- `tools/ci/check_doc_links.py` reports the six new docs (`04-protocols/oci.md`
  and the five `05-operations/` pages) as dead links while the wave is
  uncommitted: the guard resolves a link against the **git-tracked** set, so
  a file that exists on disk but is not yet tracked reads as missing.
  Simulating the tracked set shows every link resolving; the guard goes green
  with the commit. No git write was made — that needs explicit approval.
- App. V's correction of the fictional "2.9 s" 10 k cold import stands: the
  honest story is still that *deltas*, not bulk imports, are the seconds path.
  The V-3 fsync-batching lever is **delivered** (95.1 s → 10.0 s) — DRIFT 25.

Anchors were re-verified against the working tree on 2026-08-19. Keep the
appendices honest: an implementation that disagrees with an appendix byte, a
J-table transition, or a Q/R/U/V/W/X/Y/Z measured fact fixes one or the
other in the same change — or adds a DRIFT row above.
