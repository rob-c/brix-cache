# Phase 92 — Open-work audit: whole-tree verified remaining-work register (src · client · shared · tests)

**Status:** AUDIT EXECUTED 2026-08-01. This document is a **register only** — it
enumerates and verifies the remaining-work backlog; it does not itself land code
or edit the stale docs it identifies (the corrections in §2 are *owed*, not
applied). It supersedes the actionable slices of
`phase-88-open-work-audit.md` and `phase-90-plan-phase-remainder-register.md`
where noted, and is the current truth for what remains to complete the module.

**Scope:** the whole tree — `src/` (core · protocols · net · observability ·
tpc · fs · auth), `shared/`, `client/` (native clean-room tools), and the
`tests/` Python framework + `cmdscripts/` fleet harness. As with phase-88,
by-design XRootD parity gaps (`docs/10-reference/gaps-vs-xrootd.md`,
feature-matrix "not implemented" rows, documented won't-do rulings) are **out of
scope** and not listed as open work (§8).

**Method:** five parallel read-only sweeps, one per territory, each applying the
phase-88 discipline — *enumerate every open/deferred/stub/half-wired marker, then
verify each against the current tree* (grep for the caller, read the vtable slot,
open the gate test) rather than trusting a comment or a `Status:` header. A
comment saying "deferred"/"future"/"async" is, in this codebase, far more often a
description of already-shipped behaviour than a genuine gap; every candidate that
could not be shown to have a real missing piece was **dropped**, not listed. Each
surviving finding carries a `file:line` anchor, current state, the verified gap,
a classification, and a rough effort.

> **Working-tree caveat.** This audit was run against the working tree on
> 2026-08-01, which carries substantial **uncommitted** work (the phase-70
> STS/krb5 delegation legs, the phase-88 tail). Findings reflect that tree. The
> §2 doc corrections are a direct consequence: several registers were written
> before that work landed and now describe as "open" code that is wired.

---

## 1. Why this phase exists

`phase-88` (2026-07-20) reconciled the actionable-bug backlog; `phase-90`
(2026-07-25) reconciled the five plan-phases (70 · 27 · 28 · 54 · 55). Both were
snapshots, and the module has moved since — most consequentially the phase-70
credential-delegation origin legs (STS, krb5, SSS), which both prior registers
list as open but which the tree now drives end-to-end (§2). This phase is the
next reconciliation pass **plus** the first whole-tree sweep that deliberately
includes the `client/` native tools and the `tests/` framework alongside `src/`.

The recurring lesson from phase-88 §1 held again on every territory:
**`Status:` headers and mid-file "Remaining:" blocks go stale; the tree is the
truth.** The net finding is reassuring — the codebase is genuinely mature:
literal `TODO`/`FIXME` markers are at their terminal floor (2 in `src/`, both
noting *completed* XRootD parity work), the `shared/` tree has **zero**
open-work markers, and the ~1388 test skip/xfail references are overwhelmingly
environmental (missing stock xrootd, `/dev/fuse`, MinIO, KDC, perf host) or
documented profile divergences. What survives verification is a small, sharp
set: ~13 actionable local gaps, one major unstarted feature (phase-91 gsiftp
backend), and a stable infra-blocked tail.

**Completion at a glance** (verified 2026-08-01):

| Territory | State | Genuine open work |
|---|---|---|
| `src/core · net · tpc` | mature, fully wired | 1 metrics-plumbing gap (TPC bytes_total), 1 dead module (reservation.c), 1 dead API |
| `src/protocols` | mature | Content-Encoding→object PUT 501; scvmfs X.509 mode; GridFTP RETR parallelism dead field |
| `src/observability` | mature | FRM tape-stage metric family never incremented |
| `src/fs · shared` | mature | sd_remote/sd_http namespace ops; S3-tier static creds; cstore_scan enumerate fallback |
| `src/auth` + delegation | **fully wired e2e** | GridFTP VO-ACL enforcement gate + `require_vo` directive landed (:605); residual = authorized-VO *allow* (VOMS carry into gsiftp identity, needs VOMS-AC fixture). stale krb5-GSSAPI banners (cosmetic) |
| `client/` | mature, parity-strong | Task C2 (auto-refresh no-op; VFS-S3 env-only); recursive-S3 copy; ZIP64 append |
| `tests/` framework | clean harness | WLCG bearer RFC-6750 conformance; JWT hardening; slice-cache; coverage floor ungraduated |

---

## 2. Doc corrections owed (claimed open, verified done)

Same pattern as phase-88 §2 — registers that predate landed work. These edits are
**owed** (this audit does not apply them; correcting history is a separate pass,
and several source files here are uncommitted).

| Doc / file | Stale claim | Verified truth (tree, 2026-08-01) |
|---|---|---|
| `phase-90-plan-phase-remainder-register.md` §2.1 + §1 summary | STS/krb5/SSS origin-leg *drive* "not reachable from the dispatcher — no branch calls them"; quotes `vfs_deleg.c:314-358/385-416/440-457` | **Wholesale stale.** `brix_vfs_deleg_live_cred` (`src/fs/vfs/vfs_deleg.c:576-660`) has live, accept-gated branches for proxy · krb5 · STS · bearer · SSS. P90-70.1/.2 and the "SSS origin-leg drive" flag are all closed in code; live e2e green (`test_sts_runtime_e2e.py` 3/3, `test_krb5_cache_origin_e2e.py` 5/5, SSS suites). |
| `phase-88-open-work-audit.md` §4 "Phase-70 STS/krb5 origin legs" bullet | frames STS + krb5 origin legs as the open residual | **Partly stale.** The runtime *wire* has since landed for both (its own trailing UPDATE (v) records the krb5 closure); what remains is only the packaged live-lab invocation (→ §6). |
| `src/fs/vfs/vfs_internal.h:610-619` | §5.5/§5.7 STS+krb5 hooks "not yet driven from the cred gate" | Stale for STS — `brix_vfs_deleg_sts_cred` is invoked (`vfs_deleg.c:631`). (Still literally true for the *GSSAPI* krb5 hook, but that path is superseded — see §5 Auth-2.) |
| `src/fs/tier/tier_build.c:7` | header lists "(rados, tape)" as not-yet-a-tier | `tier_build_tape` is implemented + wired (`:293-302`, `:330-332`). Only rados is genuinely build-gated (librados). **APPLIED (phase-92, 2026-08-01):** header comment corrected. |
| `src/observability/metrics/frm_metrics.c:16` | comment claims `stage.c` populates the counters via `BRIX_FRM_METRIC_*` | Was false at audit time (zero callsites). **APPLIED (phase-92, 2026-08-01):** O-1 landed the callsites in `stage_request_registry_mutate.c` and the comment was corrected to attribute the counters to the registry lifecycle. |
| `src/core/config/credential_block` header | "X.509 fields parsed but not yet consumed" | Stale — consumed via `credential_block.c:298` → `runtime_server.c:173` → `fs/cache/*` origin fetch. |
| `phase-55` / `phase-27` / `phase-28` headers | "PLAN — not yet implemented / begun" | Contradicted by tree + phase-90 (55 storage-seam landed; 27 ~85–90%; 28 batch closed). Header-only correction. |

---

## 3. VERIFIED remaining work — actionable now (LOCAL)

Bugs and finish-the-feature gaps that can be closed in this environment. Ordered
by signal. Each re-verified 2026-08-01 with a `file:line` anchor.

1. **FRM tape-stage Prometheus metric family is emitted but NEVER incremented.**
   `src/observability/metrics/metrics_frm.h:39-58` declares ~13 `brix_frm_*`
   counters + a latency histogram; `frm_metrics.c:48-118` exports them all; but
   `BRIX_FRM_METRIC_INC/DEC/ADD` (`metrics_macros.h:145-168`) has **zero
   callsites** tree-wide and no field is written by any atomic either. With
   staging live (`conf->frm.enable`), every `brix_frm_*` series scrapes a
   constant 0 — an observability blind spot on a shipped feature. **Effort: M**
   (~1d — sprinkle INC/ADD at the ~13 stage lifecycle points + one latency
   observe; one metrics test).
   **RESOLVED (phase-92, 2026-08-01).** The durable stage-request registry now
   drives the counters at its lifecycle transitions in
   `stage_request_registry_mutate.c`: `add()` → `requests_total`+`in_flight`;
   the terminal `set_status()` block → `in_flight`−, and on `SRQ_ST_ONLINE`
   `stage_success_total`+ a latency-histogram observe, on `SRQ_ST_FAILED`
   `stage_fail_total[BRIX_FRM_FAIL_OTHER]`+ (both guarded on the *old* status
   being in-flight, so a repeated terminal transition never double-moves the
   gauge); `delete()`/reap of an in-flight record decrements `in_flight`. All
   writes go through `BRIX_FRM_METRIC_*`, which are NULL-SHM-safe no-ops until
   the metrics zone maps. Test: `tests/c/test_frm_stage_metrics.c` (runner
   `frm_stage_metrics`) — installs a fake metrics zone, drives a real on-disk
   registry through admit/complete/fail/idempotent-terminal, and asserts each
   counter moves exactly once (success + error + security-neg/idempotency, plus
   a Phase-A NULL-zone no-op). NOTE: the completion-side code that *sets*
   `SRQ_ST_ONLINE`/`SRQ_ST_FAILED` on real recall completion is a separate
   ledger-wiring item (tracked at finding #12); this closes the counters
   themselves against the registry's own lifecycle.

2. **WLCG bearer-token responses violate RFC 6750 MUSTs** (4 strict xfails,
   `tests/test_wlcg_token_conformance_bearer.py`): BEAR-09 (`:337`) — a missing
   credential returns **403** instead of **401 + `WWW-Authenticate: Bearer`**;
   BEAR-10 (`:380`) — an invalid/expired token returns 403 for all failures
   instead of **401 `invalid_token`**; BEAR-04 (`:185`) — header+query token in
   one request returns 200 (header-wins) instead of **400 `invalid_request`**;
   BEAR-06 (`:250`) — `?access_token=` replies omit `Cache-Control: no-store`.
   Fail-closed but wrong status/headers; genuine conformance bugs. **Effort: M**
   (status-code + header mapping across the three bearer fronts — WebDAV
   `access.c`, S3 `util.c`, root `op_path.c`).
   **RESOLVED (phase-92, 2026-08-01) — WebDAV front.** The four RFC-6750
   transport/error-response MUSTs now hold on the bearer-protected WebDAV export:
   - `src/protocols/webdav/access_auth.c` gained `webdav_bearer_enabled()` (JWKS
     keys OR macaroon secret OR token registry) and `access_bearer_challenge(r,
     status, error)` (RFC 6750 §3 `WWW-Authenticate: Bearer realm="brix"`, with an
     optional `error="…"` attribute). `access_authenticate` now captures the token
     tier's verdict (`token_rc`) and, in the auth=required reject branch on a
     bearer-enabled export, emits **401** — `error="invalid_token"` when a bearer
     was presented but failed (`token_rc == 401`), a bare challenge when the
     credential was simply absent — instead of the historical **403** (BEAR-09 /
     BEAR-10). A cert-only export keeps its 403; a valid-but-unscoped token still
     gets the authz tier's **403 insufficient_scope** (BEAR-11 unchanged).
   - A dual-transport request (header Bearer **and** a query token) short-circuits
     to **400 invalid_request** + the Bearer challenge, before any Basic/anonymous
     fallback (BEAR-04) — detected in `auth_token.c`'s `wt_parse_header` (sets a
     `header_bearer` flag, then probes `webdav_bearer_from_query`) and surfaced via
     `access_authenticate`'s `token_rc == 400` branch.
   - Any query-transported bearer now attaches **`Cache-Control: no-store`**
     (`webdav_add_nostore`, best-effort) and the query token is redacted from the
     logged URI (`wt_redact_query_token` → `brix_http_redact_query_token`) — BEAR-06.
   Verdict mapping is unaffected for the parity suites (401 and 403 both map to
   `reject`). Tests: `tests/test_wlcg_token_conformance_bearer.py` — the four
   `xfail(strict=True)` markers on BEAR-04/-06/-09/-10 are removed and the cases
   now assert the conformant status/headers (verified XPASS against a fresh
   in-sync webdav-token server; root:11097 claims2 stays 7/7). The S3 (`util.c`)
   and root (`op_path.c`) bearer fronts are NOT yet migrated — tracked as residual.

3. **Content-Encoding decode to object/driver-backed backends returns 501**
   (WebDAV `src/protocols/webdav/put_body.c:391-397`, S3
   `src/protocols/s3/put_stream.c:159-165`). A `Content-Encoding: gzip/zstd` PUT
   body is decoded to a raw kernel temp fd; a driver-backed object session (S3,
   Ceph) exposes no fd, so both handlers reject with 501 rather than corrupt.
   Secondary gap: coded bodies bypass the writer's CRC accumulator, so
   verify-on-write does not cover them even on POSIX. **Effort: M** (stream decode
   → staged-driver writer; extend CRC to the decode path).
   **RESOLVED (phase-92, 2026-08-01).** The decode engine now has a writer sink.
   `codec_ctx_t` gained a `brix_vfs_writer_t *writer` field and a `codec_sink()`
   helper that routes decoded output through `brix_vfs_writer_write()` when a
   writer is present and falls back to the raw-fd `pwrite` otherwise. The old
   `brix_http_body_decode_to_fd()` body was refactored into a shared static
   `codec_run(r, dst_fd, writer, …)`; a new public
   `brix_http_body_decode_to_writer()` (declared in `src/core/http/http_body.h`)
   is the writer wrapper. Both handlers now call it instead of returning 501:
   WebDAV `webdav_put_write_sync` (`put_body.c`) and S3 `s3put_stream_sync`
   (`put_stream.c`). Because the bytes flow through the writer session, this also
   closes the secondary gap — coded bodies are now fed to the writer's CRC
   accumulator, so verify-on-write covers them (POSIX fd and driver object alike).
   HTTP status mapping preserved: codec-unavailable → 415, decompression-bomb →
   413, bad stream → 400, else 500. Test:
   `tests/test_put_content_encoding_driver.py` (3 cases — gzip/deflate stored
   decompressed through the driver, corrupt gzip aborts with no object published)
   over a WebDAV front on a driver-backed s3:// origin
   (`tests/configs/nginx_ce_driver_s3.conf`); the sibling
   `test_put_content_encoding.py` covers the POSIX fd path. *Out of scope:* an S3
   **front** over an s3:// backend has a separate pre-existing whole-object
   staged-open ENOENT that also breaks a plain identity PUT — orthogonal to this
   decode fix; the S3 `put_stream.c` decode path calls the identical
   `brix_http_body_decode_to_writer` helper the WebDAV front exercises.

4. **`sd_remote` (S3 / remote-origin server backend) has no namespace ops.**
   `src/fs/backend/remote/sd_remote.c:341-368` — NULL `opendir/readdir`, `mkdir`,
   `rename`, `server_copy`, `setattr`, `setxattr/removexattr`. Cannot list a
   directory, create a collection, or rename/move an object. S3 exposes LIST and
   server-side COPY natively, so these are implementable (confirms phase-88 §2.1
   — **still true**). **Effort: M per verb** (opendir via LIST + server_copy via
   `x-amz-copy-source` are highest value).
   **PARTIALLY RESOLVED (phase-92, 2026-08-01) — `server_copy` landed.** The
   highest-value verb is now implemented: `sd_remote` registers `.server_copy =
   sd_remote_server_copy` (`sd_remote_meta.c`), a native S3 CopyObject over the
   new shared `sd_s3_copy` primitive (`sd_s3_meta.c` / `sd_s3.h`) — a single
   SigV4-signed PUT to the destination key carrying `x-amz-copy-source:
   /bucket/<src>`, reusing the existing `sd_s3_sign_ext` extra-header pipeline.
   The bytes never traverse this host; the source's user metadata is preserved
   (default COPY directive). HTTP status maps to POSIX via `sd_s3_status_err`
   (404→ENOENT, 401/403→EACCES, else EIO). It runs on the export's static
   service credential — a `fallback_deny` per-user request is refused upstream by
   `brix_sd_server_copy_maybe_cred` (no `server_copy_cred` slot to route to), so
   WebDAV COPY / xrdcp server-side copy over an s3:// backend no longer falls
   through to ENOSYS. Tests: `tests/c/test_sd_remote_server_copy.c` (runner
   `sd_remote_server_copy` in `c_regression_units.py`) — hermetic, injected fake
   transport, 3 cases: success (200 → NGX_OK + correct `x-amz-copy-source` +
   copied byte count), error (404 → ENOENT), security-neg (403 → EACCES;
   NULL/empty `copy_source` → EINVAL before any wire I/O).
   **PARTIALLY RESOLVED (phase-92, 2026-08-01) — `opendir/readdir/closedir`
   landed.** The second-highest-value verb group is now implemented: `sd_remote`
   registers `.opendir/.readdir/.closedir` (`sd_remote.c`) over a new shared
   `sd_s3_list_page` primitive (`src/fs/backend/s3/sd_s3_list.c` — a new TU, since
   `sd_s3_meta.c` is already at the 600-line cap). Each `opendir` derives an S3
   key-prefix from the export-relative path (leading `/` stripped, trailing `/`
   ensured, root → `""`) and is lazy — no I/O until the first `readdir`.
   `sd_s3_list_page` issues a delimited `ListObjectsV2` GET signed against the
   bucket-root canonical URI (`prefix`, `delimiter=/`, `max-keys=1000`,
   `continuation-token` all ride the SigV4-canonical query string), then walks the
   response with a bounded hand-rolled XML scanner (no libxml2 in the object path;
   the schema is fixed and small): `<Contents>` keys directly under the prefix are
   files, `<CommonPrefixes>` are sub-directories (basename emitted, trailing `/`
   dropped, `DT_DIR`/`DT_REG` set as a hint only — VFS still stats on
   `DT_UNKNOWN`). The directory-marker object (`Key == prefix`) and any entry not a
   direct child are skipped; named + numeric XML entities are unescaped.
   `readdir` pages lazily — it buffers one page, drains it, and re-fetches with the
   `NextContinuationToken` while `IsTruncated`, returning `NGX_DONE` only once the
   store reports no more pages; a non-2xx LIST surfaces as `NGX_ERROR` with errno
   from `sd_s3_status_err` (an auth refusal is never masked as an empty
   directory). Buffers are malloc-owned (sd_remote has no nginx pool) and freed in
   `closedir`. No new cap bit — S3 is key-prefix, not real directories, and the VFS
   gates `opendir` on slot presence, not on `CAP_DIRS`. This also unblocks
   `brix_cstore_scan` over a remote (S3) cache store (see #13). Tests:
   `tests/c/test_sd_remote_opendir.c` (runner `sd_remote_opendir` in
   `c_regression_units.py`, obj closure adds `sd_s3_list.o`) — hermetic, injected
   fake transport, 3 cases: success (one page → files + a sub-dir with correct
   `d_type`, derived `prefix=` in the request, `&amp;` unescaped, marker skipped,
   `NGX_DONE`), pagination (truncated first page threads its
   `NextContinuationToken` into the second request, both pages' entries surface),
   error/security-neg (403 LIST → `NGX_ERROR`/`EACCES` not an empty dir; NULL `cb`
   → `EINVAL` before any wire I/O).
   **RESOLVED (phase-92, 2026-08-01) — full namespace + metadata mutation landed.**
   `mkdir`/`rename`/`rmdir`/dir-`stat` landed first (below); `setattr` and
   `setxattr`/`removexattr` landed second (metadata-mutation block at the end of
   this finding). `sd_remote` now
   registers `.mkdir/.rename` (+ their `_cred` variants) and advertises
   `CAP_DIRS | CAP_DIRS_WRITE`, turning the S3 key-prefix namespace into a mutable
   catalog. S3 has no directories, so a folder is modelled as a zero-byte **`path/`
   marker object** (the standard AWS/MinIO/Ceph-RGW convention) via the new
   `sd_remote_s3_dirkey` helper. `mkdir` HEADs the marker for idempotency
   (→ `EEXIST`) then writes it with a zero-length `open_write`+`commit` (abort on
   commit failure). `rename` (`sd_remote_meta.c`): a `noreplace` request HEADs the
   destination first (→ `EEXIST`); a source **file** is a `sd_s3_copy`
   (CopyObject) + source `DELETE`; a source **directory** whose prefix has any
   child is refused `ENOTSUP` (S3 offers no atomic recursive rename — bytes would
   have to be re-copied per object), an empty dir moves its marker, and a source
   that is neither → `ENOENT`. `stat` recognises the export root and any live
   `path/` marker as `S_IFDIR`, a plain key as `S_IFREG`, else `ENOENT`. `rmdir`
   routes through `sd_remote_unlink(is_dir=1)`, which composes the `path/` marker
   key so the VFS rmtree deletes the marker after walking children. All slots honour
   the `sd_remote_cred_gate` (a `fallback_deny` per-user request with no usable S3
   keypair is refused `EACCES` before any wire I/O).
   *Decorator cap-parity fix (latent bug surfaced here):* the **stage** decorator
   (`sd_stage.c`) advertised the write/xattr/copy caps but **not**
   `CAP_DIRS|CAP_DIRS_WRITE`, unlike the cache decorator (`sd_cache.c`) which
   already did. Because `brix_stage` is on by default over a remote backend, the
   `vfs_{mkdir,rename,unlink}` catalog-mutation gate (which reads the *top*
   decorator's caps, then dispatches the op to the leaf via `brix_vfs_ns_leaf`)
   refused every staged namespace op with `EPERM`/403 before reaching the
   `sd_remote` leaf. Fixed by mirroring the two caps onto `brix_sd_stage_driver`
   (the leaf still enforces its real capability). Without this, *no* remote backend
   could ever mutate its namespace through the default staged path.
   Tests: `tests/c/test_sd_remote_rename.c` (runner `sd_remote_rename` in
   `cmdscripts/c_regression_units.py`, obj closure = the `sd_remote_opendir` set +
   `sd_s3_write.o`) — hermetic, injected fake transport keyed by an exist-registry
   that distinguishes a file `…/f` from a marker `…/f/`, 7 cases: mkdir→0-byte PUT,
   mkdir-existing→EEXIST-no-PUT, rename-file→copy+delete, rename-non-empty-dir
   →ENOTSUP + missing→ENOENT, rename-noreplace→EEXIST, rmdir marker DELETE +
   marker/root dir-stat, and `fallback_deny` cred→EACCES with no wire I/O. Plus
   `tests/test_s3_driver_namespace.py` (3 HTTP-edge cases over the WebDAV-front /
   staged-`s3://`-origin topology, which also pins the stage cap-parity fix):
   success MOVE (CopyObject+DELETE → 201, bytes moved, source gone), error MOVE of
   a missing source → 404, security-neg MOVE `Overwrite:F` over an existing dst
   → 412 with neither object clobbered.
   *Topology limitation (documented, not a defect):* the marker-dependent slots
   (mkdir/rmdir/dir-stat/deep-prefix auto-create) are **not** driven over the
   co-hosted **posix-backed** `brix_s3` origin — it recognises directories via a
   `.xrdcls3.dirsentinel` sentinel and cannot store a key ending in `/` (a staged
   commit to such a path fails `EINVAL`), so a `coll/` marker PUT 500s there though
   it is correct on any real object store. That surface is proven by the hermetic
   C unit above and would need a real S3 (MinIO — the same docker-gated topology
   `test_sts_minio_live.py` uses) for HTTP-edge coverage.
   **Metadata mutation (`setattr` + `setxattr`/`removexattr`) — LANDED
   (2026-08-01).** `sd_remote` now registers `.setxattr/.removexattr/.setattr` (+
   their `_cred` variants) and advertises `CAP_XATTR | CAP_XATTR_WRITE`, completing
   the read side (`getxattr`/`listxattr`, already present) with a coherent write
   side. All three live in a new TU **`src/fs/backend/remote/sd_remote_xattr.c`**
   (both `sd_remote.c`=614 and `sd_s3_meta.c`=618 are at the 600-line cap; the new
   file is 492). The design axiom is that **S3 has no in-place metadata edit** — any
   write REPLACES the object's *entire* user-metadata set via a copy-onto-self
   (`x-amz-metadata-directive: REPLACE`, the existing zero-caller `sd_s3_set_meta`).
   A single-attribute mutation therefore does **read-all → merge-one → rewrite-all**
   (`sd_remote_meta_load` enumerates every `x-amz-meta-*` via `sd_s3_list_meta`,
   fetches each value + the reserved advisory blob via `sd_s3_get_meta`, then
   `sd_remote_meta_store` rewrites the whole set) so no co-existing attribute — or
   the advisory unix-attr blob — is silently dropped. `setxattr` maps only the
   `user.*` namespace to `x-amz-meta-*` (else `ENOTSUP`), rejects a value carrying a
   header-breaking NUL/CR/LF (`EINVAL`), honours `XATTR_CREATE` (`EEXIST`) /
   `XATTR_REPLACE` (`ENODATA`), and lowercases the name (AWS user-meta contract).
   `removexattr` drops the entry (`ENODATA` when absent). `setattr` (chmod / times /
   owner) patches the reserved advisory blob (`x-amz-meta-xrd-unixattr`, `meta_advisory.h`
   `brix_meta_advisory_patch`) so a POSIX mode/mtime/owner change over an `s3://`
   export sticks and round-trips; it targets the file key, else falls back to the
   `path/` directory marker (`ENOENT` when neither exists); owner is set only when
   both uid AND gid are real (the blob carries them as a pair). Enumeration needs the
   transport's raw-header slot — without it every mutation degrades to `ENOTSUP`
   (never a blind clobber), exactly as `listxattr` already does; the production
   `brix_s3_origin_curl_transport` provides it. All `_cred` variants honour
   `sd_remote_cred_gate` (a `fallback_deny` request with no usable S3 keypair →
   `EACCES` before any wire I/O). The decorators (`sd_stage.c`/`sd_cache.c`) already
   relay these slots and advertise `CAP_XATTR|CAP_XATTR_WRITE`, so no decorator edit
   was needed. Tests: `tests/c/test_sd_remote_setattr.c` (runner `sd_remote_setattr`,
   obj closure = the `sd_remote_rename` set + `sd_remote_xattr.o`) — hermetic fake
   transport carrying a **real per-object metadata store** (HEAD emits the current
   `x-amz-meta-*` headers; the REPLACE PUT rebuilds the store from the request
   headers) so assertions inspect what actually survived the rewrite; 8 cases:
   setxattr-preserves-siblings+blob (success), `XATTR_CREATE`→EEXIST /
   `XATTR_REPLACE`-absent→ENODATA, non-user-ns→ENOTSUP + CR/LF-value→EINVAL,
   removexattr-drops-keeps-sibling + absent→ENODATA, setattr-chmod-patches-blob
   (decodes to the new mode, xattr kept), setattr dir-marker fallback,
   `fallback_deny` cred→EACCES for all three verbs (no I/O), and a no-raw-header
   transport→ENOTSUP (degradation, never a blind write).

5. **TPC dashboard `bytes_total` is dropped mid-pipeline.** The registry/transfer
   structs carry it (`transfer.h:57`, `registry.h:35`) and the dashboard publishes
   it (`api_transfers.c:326`), but `brix_tpc_progress_emit` discards it
   (`src/tpc/common/progress.c:29` `(void) bytes_total`) and
   `brix_tpc_registry_update` has no field to store it (`registry.c:343`), and the
   native/threaded paths register a literal 0. Result: `bytes_total` and any
   progress-% are always 0 for native + threaded TPC. **Effort: S-M** (thread a
   `bytes_total` param through `progress_emit`→`registry_update`).
   **RESOLVED (phase-92, 2026-08-01).** `brix_tpc_progress_emit` now forwards
   its `bytes_total` to the new public `brix_tpc_registry_update_progress(id,
   bytes_done, bytes_total, state, log)`, which sets the stored total only when
   `bytes_total > 0` (a 0 leaves the existing total untouched, so a transport
   that never learns the size cannot clobber a real total). `registry_update`
   keeps its old signature as a total-less shim. Test:
   `tests/c/test_tpc_progress_total.c` (runner `tpc_progress_total`) — drives
   the REAL SHM-backed registry (its own `shm_init` over a heap-backed slot
   table) and asserts a mid-flight total reaches the registry, a plain
   `update()` and an `update_progress(total=0)` both leave the total intact, the
   emit shim forwards end-to-end, and an unknown id DECLINEs / id==0 no-ops
   (success + idempotency + error/security-neg).

6. **Client Task C2 (a): credential auto-refresh is an unwired no-op.**
   `client/lib/auth/cred/cred_bearer.c:216-222` and `cred_x509.c:197-212` both
   `return 0` and never call the fully-written engine `brix_cred_autorefresh()`
   (`credrefresh.c:252`). The store *does* invoke the handler on near-expiry
   (`cred.c:343-403`), so the `--auto-refresh` CLI flag (`xrdcp_parse.c:334`) is
   accepted but silently does nothing. **Effort: S-M** (adapt the `(cfg,st)`
   handler onto the engine's `(want_write,oidc_account,verbose,out)` signature in
   two handlers).
   **RESOLVED (phase-92, 2026-08-01).** `credrefresh.c` now exposes two public
   per-kind entry points — `brix_cred_refresh_bearer(oidc_account, verbose, out)`
   (resolves a NULL/empty account from `$OIDC_ACCOUNT`, then re-mints via
   `refresh_bearer_token`) and `brix_cred_refresh_gsi(verbose, out)` (regenerates
   the proxy via `refresh_gsi_proxy`) — declared in `lib/brix_auth.h`. The umbrella
   `brix_cred_autorefresh` is refactored to call both (single source of account
   resolution, no behaviour change for the pre-transfer sweep or `xrd_mount`).
   `bearer_refresh` (`cred_bearer.c`) and `x509_refresh` (`cred_x509.c`) are no
   longer no-ops: they delegate to the matching wrapper, so the store's near-expiry
   refresh path (`cred.c` `should_refresh` → `h->refresh` → engine) actually
   re-acquires and `--auto-refresh` works end-to-end. The store discards the
   refresh return and re-acquires regardless, so both stay best-effort / fail-soft.
   Test: `client/tests/c/cred_refresh_unit.c` (client `make test` unit) — a fake
   `oidc-token` on `$PATH` (execvp) with a seeded expired-JWT `$BEARER_TOKEN`
   drives the bearer path end-to-end: success (token re-minted into `$BEARER_TOKEN`),
   edge (account resolved from `$OIDC_ACCOUNT`), security-neg (no account →
   fail-soft 0, token left intact; GSI with no discoverable cert → fail-soft 0).

7. **Client Task C2 (b): the VFS S3 backend ignores the credential store.**
   `client/lib/fs/backend/s3/vfs_s3_http.c:8-20` reads only `AWS_*` env vars and
   `(void) opts`. A complete `brix_cred_s3keys()` handler exists (`cred_s3.c`,
   parses `.aws`/`.s3cfg`) but is never consumed by the VFS backend (registered
   unconditionally at `vfs.c:74`). The *separate* xrdcp curl path already honours
   `o->s3_access`, so the gap is specific to the VFS S3 leg. **Effort: S** (thread
   `opts->{s3_access,s3_secret,s3_region}` + cred store, env as fallback).
   **RESOLVED (phase-92, 2026-08-01).** `s3_creds_load` (`vfs_s3_http.c`) now
   consults the credential store carried on the open (`opts->cred`, a
   `brix_cred_store *`) via `brix_cred_acquire(opts->cred, XRDC_CRED_S3KEYS, 0,
   &view, &st)` before falling back to `$AWS_*`. Because the S3KEYS handler
   (`cred_s3.c`) already folds CLI `--s3-access/--s3-secret` → `~/.aws`/`~/.s3cfg`
   → `$AWS_*` discovery, a complete store hit is a strict superset of the old
   env-only path. Only a COMPLETE access/secret pair is adopted from the store; a
   miss/partial result falls back to the `$AWS_*` pair **wholesale** so a store
   access key is never mixed with an env secret (which would mis-sign, not go
   anonymous). Region stays `$AWS_DEFAULT_REGION`/default (the view carries no
   region). An empty pair stays anonymous, as before. Test:
   `client/tests/c/vfs_s3_creds_unit.c` (client `make test` unit) — overrides the
   weak `brix_cred_s3keys()` accessor with a controllable stub: success (a complete
   store pair overrides env), edge (`opts->cred == NULL` → env + default region),
   security-neg (a partial store result does NOT mix keys — env pair used).

8. **S3 storage *tier* is anonymous/public-read only — static creds not wired.**
   `src/fs/tier/tier_build.c:245-266` (`tier_build_s3`) memzeros and never
   populates `access_key/secret_key/region`, even though `brix_sd_remote_cfg_t`
   has the fields (`sd_remote.h:44-46`) and the credential block parses them
   (`credential_block.h:83`). A private S3 bucket cannot back a configured
   cache/stage/backend tier. The per-request SigV4 path (`sd_remote_open_cred`)
   **is** wired — only the static service-credential tier build is missing.
   **Effort: S-M** (thread 3 fields through `tier_resolve_creds`→`tier_build_s3`).
   **RESOLVED (phase-92, 2026-08-01).** `tier_build_s3` now maps the tier
   credential's static S3 keys via a new non-static helper
   `brix_tier_s3_apply_creds(brix_sd_remote_cfg_t *cfg, const brix_credential_t
   *c)` (`tier_build.c`): each present (`len > 0`) `s3_access_key/s3_secret_key/
   s3_region` field is copied through `brix_str_cbuf`; an absent access-key
   leaves `cfg.access_key[0] == '\0'` so the origin stays anonymous (SP1) rather
   than half-signed, and region stays defaulted-in-driver. A NULL credential (or
   NULL cfg) is a no-op. Test: `tests/c/test_tier_s3_creds.c` (runner
   `tier_s3_creds`) — links the real `tier_build.o` and exercises the helper
   directly (`tier_build_s3` itself ends in a live `brix_sd_remote_create`):
   success (all three fields copied verbatim), edge (NULL credential + empty
   region left untouched), security-neg (empty access-key → origin stays
   anonymous even when a secret is present).

9. **JWT claim-validator hardening gaps** (`src/auth/token/validate.c`; 3 strict
   xfails). Server accepts tokens it should reject: `iat > exp` ordering not
   checked (`test_..._parity_ext.py:341`, `claims2.py:68`) and array-typed `sub`
   not rejected (`parity_ext.py:697`). Two missing RFC 7519 §4.1.2 guards, low
   blast-radius. **Effort: S**.
   **SPLIT on verification (phase-92, 2026-08-01) — the two halves are NOT
   equivalent:**
   - **array-typed `sub` → RESOLVED.** RFC 7519 §4.1.2 (rules 4/6) does mandate
     `sub` be a StringOrURI, and both tests (`claims2.py` CLM2-03,
     `parity_ext.py` EXTRA-05) were strict-xfails *expecting reject* — nothing
     asserted accept, so the fix breaks no passing test. `token_extract_claims`
     now rejects a **present-but-non-string** `sub`: `json_get_string(...) < 0 &&
     json_has_member(..., "sub")` → return −1. An **absent** `sub` stays valid
     (the claim is OPTIONAL — the `json_has_member` guard is exactly what keeps
     the reject from over-triggering). The two strict-xfails were flipped to
     normal reject-asserts; added forge `sub_absent()` + accept test
     `test_clm2_03b_sub_absent_accepted` (success=string sub via every existing
     accept test · error/security-neg=array/non-string sub rejected · edge=absent
     sub accepted).

     **Verification & residual infra note (2026-08-01):** the sub change lives in
     the *shared* `token_extract_claims` path exercised identically by the root
     (`kXR`), WebDAV, and S3 token servers, so it is fully proven by
     `test_wlcg_token_conformance_claims2.py` (7/7 on `NGINX_TOKEN_PORT` 11097,
     which runs the fresh session binary). The WebDAV/S3 variants in
     `parity_ext.py` (26 `_accept` reds) are **infra, not code**: ports 8446/9002
     are squatted by two orphan `nginx` workers (pids 679282/679768) reparented to
     `init` and running a `(deleted)` pre-change binary — untracked by
     `manage_test_servers`, so `stop-all`/`start-all` cannot reap them, and the
     fresh dedicated servers cannot rebind. Confirmed by `/proc/<pid>/exe`
     (root:11097 → fresh 13:58 binary → accepts the *identical* forged token;
     8446/9002 → deleted orphan binary → "bearer token validation failed"). This
     is the documented `fleet_key_desync_signature` (all `_accept` fail, all
     `_reject` pass). **CLEARED:** after the operator reaped pids 679282/679768 and
     the fleet restarted onto fresh 8446/9002 binaries, the full run is
     `claims2` + `parity_ext` = **75 passed, 2 xfailed** (the 2 remaining xfails
     are the intentional `iat > exp` characterizations below). Array-`sub` reject
     now confirmed green across root/WebDAV/S3. No code defect implied.
   - **`iat > exp` ordering → WON'T-DO (finding was wrong; doc-corrected).** This
     is NOT an accepted-but-should-reject bug. `test_clm2_04_iat_after_exp_accepted`
     (`claims2.py:84`) is a **passing** assertion that the token is *accepted*,
     with a correct rationale: RFC 7519 §4.1.6 makes `iat` purely informational
     and mandates no `iat`-vs-`exp` ordering check — the `exp` (+clock-skew) test
     alone governs validity (forge case exp=now−10 is inside the 30 s skew window
     → valid). Implementing an independent `iat > exp` reject would BREAK that
     passing, RFC-correct test. The `parity_ext.py` CLM2-02 strict-xfail merely
     *characterises* the divergence and is left as-is (its docstring already says
     "characterize", not a MUST). No code change.

10. **Client: recursive copy over S3 web endpoints not implemented.**
    `client/lib/protocols/http/weblist.c:533` (`s3:// listing not supported yet`)
    — recursive WebDAV works via PROPFIND, but S3 recursive download needs a
    SigV4-signed `ListObjectsV2` pager; recursive web *upload* is rejected outright
    (`copy_upload.c:358`). **Effort: M** (download); upload is larger.
    **RESOLVED (phase-92, 2026-08-01) — download half already landed; finding was
    stale.** Recursive S3 *download* is fully implemented and wired: `brix_s3_list`
    (`weblist.c:313`, committed) is a paginated SigV4-signed `ListObjectsV2` pager
    (`s3_list_req_t` page context + `s3_list_build_request` per-page signer +
    continuation-token loop), and `recursive_web_download`
    (`client/apps/copy/xrdcp_recursive.c:499`) dispatches every `u.is_s3` source to
    `recursive_s3_download` (same file, `:399`) — which lists the prefix, splits
    bucket/prefix, creates the destination collection, and copies each key to
    `dstdir/<key-minus-prefix>` (rejecting traversing keys via `rel_is_unsafe`)
    **before** `brix_webdav_list` is ever reached. The `weblist.c:533` error branch
    the finding cites lives in `brix_webdav_list`, which the S3 dispatch short-
    circuits, so it is now dead-but-defensive (never hit on the recursive path).
    Verified green: `tests/test_client_web_transfer.py::test_s3_recursive_download`
    (SigV4 `ListObjectsV2` prefix list → per-key download, tree preserved) passes,
    and the client links clean. **Still open (out of this finding's download
    scope):** recursive web *upload* — larger, as the finding itself notes.

11. **Client: `xrdcp --zip-append` rejects ZIP64 archives.**
    `client/lib/xfer/copy_zip.c:318-323` — append works for classic central
    directories but returns `XRDC_EUSAGE` on a ZIP64 target (EOCD/central-dir
    rewrite unimplemented). **Effort: M**.
    **RESOLVED (phase-92, 2026-08-01).** ZIP64 append now works; the rejection was
    over-conservative. The append machinery was already ZIP64-complete on both
    ends: `brix_zip_read_eocd` promotes the saturated (0xffff / 0xffffffff) classic
    EOCD fields to the real 64-bit central-directory offset/size/count (via
    `zip_promote_zip64` reading the ZIP64 EOCD record), `brix_zip_writer_new_append`
    seeds the writer with the **verbatim** old central-directory bytes (existing
    entries keep their offsets and their per-entry ZIP64 extra fields — no 64-bit
    CD *rewrite* is ever needed because append never relocates a member), and
    `brix_zip_writer_finish` already re-emits a ZIP64 EOCD record + locator whenever
    the combined offset/size/count still requires it. The only blocker was the
    explicit `if (z64) return -1` in `zip_read_seed` (`copy_zip.c`), which is
    removed; both the local (`copy_zip_store_local`) and remote
    (`copy_zip_store_remote`) `--zip-append` paths go through it, so both now accept
    ZIP64 targets. Stale comments corrected in `copy_zip.c` and `zip.h`. Tests:
    `tests/c/zip_write_test.c` gains `test_append_zip64_member` (runner
    `compression` in `c_regression_units.py`) — builds a > 0xfffe-entry archive
    (forcing a real ZIP64 EOCD), appends a new member in-place, and asserts (1)
    success: an original member and the new member both round-trip byte-exact
    through the library reader **and** stock `unzip -t`/`-p`; (2) error: `read_eocd`
    on a non-ZIP buffer fails cleanly; (3) security-neg: a corrupted ZIP64 locator
    offset is rejected by the bounds-checked reader, never dereferenced out of
    range.

12. **FRM stage-engine RECALL not wired into the read-fault recall path.** The
    unified `kind=tape` transfer-ledger line is emitted only on the `stage_engine`
    RECALL path; the `sd_frm` read-fault recall is synchronous and writes no
    ledger line (`test_frm_staging.py:252` skip). Verify-on-stage (F5) is deferred
    on the new engine (`test_frm_phase4_engines.py:232,239`). The async
    integration is the noted future step at `src/protocols/root/query/prepare.c`
    (`frm_stage_kick → brix_stage_submit(RECALL)`). **Effort: M** (ledger wiring
    LOCAL; F5 verify DESIGN).
    **RESOLVED (phase-92, 2026-08-01) — ledger wiring LANDED.** The synchronous
    tape→cache recall now books the ONE unified transfer-ledger line
    (`kind=tape dir=in`), the sync counterpart to the async stage_engine RECALL
    emit, so a read-fault recall is auditable in the same schema. `sd_frm.c`:
    `frm_ensure_online` gained an out-param reporting whether a genuine recall
    was initiated (never records an already-online cache hit or an absent
    object), and both recall entrypoints emit via `brix_xfer_finish`: the
    cache-fill verb `sd_frm_recall` (the path `sd_cache` drives every nearline
    miss through — byte count from a post-online residency probe) and the
    direct-export read-fault `sd_frm_open` (byte count from the online fstat). A
    terminal failure books `result != ok`; EAGAIN (async still in flight) is
    non-terminal and is deliberately NOT recorded (it would double-count against
    the eventual completion), and because a recall makes the object ONLINE the
    other entrypoint then sees a hit — so exactly one line is booked per recall
    (verified by the 8-opens→1-recall single-flight test). Tests
    (`tests/test_frm_staging.py`): `test_recall_emits_unified_tape_audit_line`
    (success — `kind=tape dir=in result=ok bytes=<size>` for a `/near.dat` read
    over `frm://exec`) and `test_failed_recall_emits_tape_error_line` (a
    terminally-failing MSS verb books `result != ok`, never masked as success).
    **Still open:** the async engine integration (`frm_stage_kick →
    brix_stage_submit(RECALL)` in `prepare.c` — recall-completion detection on a
    later poll) and F5 verify-on-stage, both DESIGN.

13. **`brix_cstore_scan` cannot scrub a store lacking `opendir`.**
    `src/fs/cache/cstore_scan.c:149-161` returns ENOSYS/DECLINED when the store
    driver has no `opendir/readdir`; a remote (S3/http) cache store (see #4) is
    therefore un-scrubbable/un-inventoried by the phase-87 G17 background scrub,
    and it never falls back to a `CAP_CATALOG` driver's `enumerate`. **Effort:
    S-M** (add `enumerate` fallback; ties to #4).
    **RESOLVED (phase-92, 2026-08-01).** `brix_cstore_scan` now takes the
    directory-walk path only when the store advertises the full `opendir`/
    `readdir`/`closedir` trio; otherwise, when the store advertises
    `BRIX_SD_CAP_CATALOG` **and** has a non-NULL `driver->enumerate`, it falls
    back to a native object-catalog enumerate (`want_stat=1`) and bridges each
    `brix_sd_catalog_ent_t` onto the eviction/scrub visitor via `cstore_enum_cb`:
    metadata sidecars are skipped by key suffix (the same predicate as the
    readdir scan), a regular-file `brix_sd_stat_t` is synthesised from the entry
    (size/mtime only when `have_stat`), and the cinfo is loaded when present
    (NULL otherwise). The visitor's early-abort code is captured in the bridge
    and returned even though `enumerate` reports `NGX_OK` after an aborted cb; a
    genuine enumerate failure surfaces as `NGX_ERROR`. A store with neither the
    directory verbs nor a `CAP_CATALOG` enumerate still returns
    `NGX_DECLINED`/`ENOSYS`, and the caps gate is honoured — a driver whose
    `enumerate` is set but that does not advertise `CAP_CATALOG` is never
    enumerated. This makes a remote object cache store (S3/http/rados, see #4)
    scrubbable/inventoriable by the phase-87 G17 background scrub. Test:
    `tests/c/test_cstore_scan_enumerate.c` (runner `cstore_scan_enumerate` in
    `c_object_units.py`) — links the built `cstore_scan.o`, stubs
    `brix_cstore_cinfo_load`, and drives a fake catalog driver: success (every
    object visited once, sidecar skipped, sizes carried through), edge (no
    dirs/no catalog → ENOSYS; enumerate failure → NGX_ERROR), security-neg
    (uncapped driver not enumerated · visitor early-abort short-circuits · NULL
    args rejected). The remaining half of this cluster — a real S3 `enumerate`
    verb — is finding #4 (`sd_remote` namespace ops), still open.

---

## 4. Feature backlog (designed/planned — not bugs)

Bounded features that are absent or partial by design. Not defects; scheduling
decisions.

- **phase-91 `gsiftp://` outbound storage backend — FIRST SLICE LANDED (major, XL).**
  `docs/refactor/phase-91-gsiftp-storage-backend.md` is a complete plan;
  `src/fs/backend/gsiftp/` now exists. The whole outbound control/data-channel
  client + full WLCG auth matrix (GSI/VOMS, delegated proxy, EEC, krb5/GSSAPI,
  mTLS, user/pass, anon) still remains. Depends on phases 55/70/82/60/80 (all
  landed). **Effort: XL** (doc self-estimates ~3–4 wk).

  **First slice — phase-92, 2026-08-02 (protocol-parser kernels).** The two
  genuinely-new, infra-independent, security-critical pieces the plan flags as
  "NEW; nothing parses replies today" (§5.1/§5.3) landed as pure, unit-tested C
  library kernels under `src/fs/backend/gsiftp/`, mirroring how `ftp_eblock.h`
  landed as a shared codec kernel:
  * `gftp_reply.{c,h}` — client-role control-channel reply parser: 3-digit +
    multiline `-` continuation framing (`gftp_reply_scan`, incremental — returns
    0 for "need more bytes" so the blocking session loop can rescan), plus the
    **SSRF-critical** `227` PASV/IPv4 and `229` EPSV (RFC 2428) address decoders,
    each bounds-checking every octet/port and rejecting out-of-range or malformed
    input *before* the address reaches the `net_target.h` screen.
  * `gftp_mlsx.{c,h}` — MLSD/MLST fact-line parser (RFC 3659 §7): inverts
    `type=;size=;modify=;…` into `is_dir`/`size`/UTC-`mtime`/`name`, rejects
    traversal (`/`) and control-byte (`NUL`/`CR`/`LF`) names, drops overflowing
    numeric facts, tolerates unknown/missing facts. Timezone-free `modify=`→epoch
    via Hinnant's civil-days algorithm (no libc `timegm`).
  Both are plain C over `<stddef.h>`/`<string.h>` (no nginx or socket deps), so
  the whole surface is exhaustively testable off any server. Tests:
  `tests/c/gftp_parse_test.c` — success + error + security-neg per parser
  (multiline vs. false-terminate framing; hostile `227` octet>255 / `229` short
  delimiter-run / port-0 / overflow reject; MLSx `../` and embedded-newline name
  reject; overflow-size drop). Fast-tier runner `gftp_parse`
  (`tests/cmdscripts/c_regression_units.py` + `test_c_regression_units.py`),
  compiled `-Wall -Wextra -Werror`, no objects/stubs. The SD-driver vtable
  (`sd_gsiftp*.c`) and `gftp_session/data/auth*.c` that consume these kernels are
  the next increment; per the "no uncalled code in the shipping binary" bar they
  are wired into `./config`/`fs_list.h`/the registry atomically with that first
  consumer, not now. README documents the module map + seam. **Remaining: L→XL**
  (control/data channel, GSI/krb5/mTLS auth matrix, config+census+tier wiring,
  live lab).

- **GridFTP/gsiftp gateway VO-ACL enforcement.** VOMS AC extraction is complete
  (`src/auth/voms/{collect,extract,loader}.c`) and VO-ACL is enforced on
  HTTP-driven planes (`auth_gate.c:452`), but the gsiftp plane carries no
  `require_vo` directive and never routes through `brix_check_vo_acl_identity`
  (`src/protocols/gridftp/*`). VO *interop* works; VO *authorization* on the
  gateway does not (matches phase-82 `:1906`, phase-88 `:314`). This is the **only
  genuine open item in the entire auth territory**. **Effort: ~1-2d**.

  **RESOLVED (enforcement gate + directive) — phase-92, 2026-08-02.** The gsiftp
  plane now carries a `brix_gridftp_require_vo <path> <vo>` directive and routes
  every namespace/transfer verb through `brix_check_vo_acl_identity`, closing the
  named gap. The rule shape (`brix_vo_rule_t`), longest-prefix matcher and
  allow-all-when-no-rule semantics are exactly the HTTP/root planes' — no new
  matcher. Implementation:
  * `ngx_stream_brix_ftp_srv_conf_t.vo_rules` (`ftp_gateway.h`) — the per-server
    rule array, so each stream `server{}` owns its own (no shared-array
    double-finalize).
  * `brix_ftp_set_require_vo` + the `brix_gridftp_require_vo` command entry
    (`ftp_module.c`) mirror `policy.c`'s `brix_conf_set_require_vo`
    (`brix_normalize_policy_path` → `.path`, `brix_copy_conf_string` → `.vo`).
  * `brix_ftp_merge_conf` deep-merges the array with `brix_merge_arrays` (child
    shadows parent) and finalizes `.path` → `.resolved` against the gateway's own
    `root_canon` via `brix_finalize_vo_rules` at config time.
  * The **single choke point** `brix_ftp_ev_resolve` (`ev/ftp_ev_path.c`) gates
    *after* `brix_http_resolve_path` confines the path: a resolved path covered
    by a rule is served only when the session identity's VO CSV lists the
    required VO; otherwise FTP 550. Every verb (RETR/STOR/LIST/MLST/DELE/MKD/
    RNFR/RNTO/SIZE/…) flows through it, so one gate covers the whole surface.
  Fail-closed by construction: a session with no VO (cleartext, or a GSI proxy
  carrying no VOMS FQAN) is refused on any VO-gated prefix — never a bypass.
  Tests (`tests/test_gridftp_vo_acl.py`, 4/4, cleartext gateway
  `configs/nginx_gridftp_vo.conf`, ledger `gridftp-vo`:30450): uncovered path
  served (allow-all branch); ENOENT on an uncovered path still 550s at resolve
  (gate runs after resolution, never masks normal errors); VO-gated RETR and LIST
  both refused 550 for a no-VO session.

  **RESIDUAL (authorized-VO *allow* on GSI).** For a GSI client's VOMS FQAN to
  *satisfy* (rather than only be denied by) a rule, the gsiftp AUTH GSSAPI
  handshake must carry the proxy's VOMS FQANs into the session identity
  (`brix_identity_set_vos_csv`), exactly as the HTTP plane does in
  `webdav_extract_and_set_voms_identity` (`auth_cert.c`). That carry is a thin
  wrapper over the already-shipped `brix_extract_voms_info`, but its allow-path
  e2e needs a VOMS-AC + LSC proxy fixture that the test tree does not yet have
  (`voms-proxy-fake` is present but fails AC generation here on the
  authorityKeyIdentifier extension). Deferred as a self-contained follow-on with
  its own VOMS-proxy fixture; the enforcement gate above already denies
  correctly regardless, so enabling `require_vo` on a gsiftp export is safe
  (deny-until-VOMS-carry) today.

- **Slice-granular read caching (per-slice window residency + slice-hit serving).**
  The VFS cache is whole-file; stream/root slice serving is xfail "until generic
  slice serving lands" (`test_slice_cache.py`, 7 xfails; `test_readv_security.py:684`).
  The generic partial/range-fill *primitive* did land (phase-64), so the residual
  is per-slice residency + slice-hit serving + its stream data-plane wiring; maps
  to `phase-26-slice-caching.md` (still Draft). **Effort: L**.

  > **RESOLVED (2026-08-02, UNCOMMITTED — confirmed delivered, no new code).**
  > This item is fully delivered by the **phase-64 VFS-level generic slice fill**
  > (`src/fs/backend/cache/sd_cache_partial.c`), NOT by the superseded phase-26
  > protocol-plane design (`slice.c`/`slice_read.c`/kXR_wait/`.__xrds_` files —
  > those files were never created; the phase-26 doc stays Draft as the historical
  > spec). When `brix_cache_slice_size > 0` (a positive multiple of 1 MiB,
  > validated in `server_conf_merge_security.c`) on a **LOCAL** posix cache store,
  > a read MISS builds a partial-serve object (`cache_open_miss_serve` →
  > `sd_cache_partial_open`, `sd_cache.c:143`): a **sparse cache fd** + a **cinfo
  > present-bitmap** give per-slice residency, and `brix_cstore_serve_pread`
  > range-fills only the blocks a read touches (source pread → cache pwrite →
  > `brix_cache_cinfo_record_block` + bitmap mark) so a Range read never pulls the
  > whole object. Slice-hit serving reads present blocks straight from the sparse
  > fd; a fully-filled object's cinfo flips COMPLETE and later opens take the
  > whole-file hit fast path. Per-user credentials are captured at open time
  > (`partial_capture_cred`) so a deferred block fill still authenticates as the
  > owner. It is **driver-agnostic** (phase-64 §14: works over any composed
  > backend, no `strcmp` on driver name) and **stream-wired**: a root:// client's
  > `kXR_read` reaches `sd_cache_pread` through the SD decorator on the VFS read
  > path — no separate protocol-plane serving needed. Verified green against this
  > build: `tests/test_cache_partial_fill.py` — **21 passed, 2 skipped**
  > (env-gated heavy backends) — covering per-slice residency (single/mid-file/
  > cross-boundary/disjoint/EOF-partial block marking, all asserted via
  > `xrdcinfo` cinfo residency), whole-file→COMPLETE promotion, warm-block
  > byte-exact slice-hit serving, generic-backend slice fill, and the
  > security-negatives (oversized-not-cached, allow/deny-prefix + include-regex
  > read-fill admission gating). The `test_slice_cache.py` integration cases stay
  > xfail as the executable spec for the *superseded* phase-26 protocol-plane
  > serving (their `.__xrds_`/kXR_wait/prefetch semantics do not map onto the
  > VFS-decorator architecture that actually shipped). **Effort: L — DONE (via
  > phase-64).**

- **`sd_http` origin has no directory enumeration / xattr / rename**
  (`src/fs/backend/http/sd_http.c:30-49`) — read + whole-object staged PUT + stat
  + unlink only; a writable/listable WebDAV backend needs opendir (via PROPFIND).
  **Effort: M**.

  **RESOLVED (directory enumeration) — phase-92, 2026-08-01.** The sd_http driver
  now registers `.opendir/.readdir/.closedir` + `.opendir_cred` and advertises
  `BRIX_SD_CAP_DIRS` (`sd_http.c:34,50-53`). Enumeration is a single WebDAV
  **PROPFIND Depth:1** against the collection URL (empty body = "allprop", RFC
  4918 §9.1), issued through the existing `sd_http_request_fo` failover path (it
  already sends a NULL body) with a `Depth: 1` header — no transport-layer body
  plumbing. The 207 Multistatus reply is parsed by a bounded, namespace-agnostic
  hand scanner (no libxml2 in the object path) in the new TU
  `src/fs/backend/http/sd_http_dir.c` (449 lines; `sd_http.c`/`sd_http_read.c` are
  near the 600-line cap): each `<D:response>` yields an `<D:href>` child and an
  is-collection flag from `<D:resourcetype><D:collection/>`. PROPFIND returns the
  whole level in ONE reply, so `opendir` fetches once and `readdir` cursors the
  buffered children. The **self entry** (the collection itself) is the shallowest
  href by `/`-segment count and children are exactly one segment deeper — that
  depth rule skips self WITHOUT needing the endpoint `base_path`, and works at the
  export root. `opendir_cred` presents the per-user bearer / x509-proxy exactly as
  `sd_http_open_cred`/`stat_cred` do (phase-70 §5.1), and the same `cred_gate`
  refuses a proxy-only + `fallback_deny` cred the transport cannot mutual-TLS —
  never a silent anonymous listing. Status mapping: 404→ENOENT, 401/403→EACCES,
  405/501 (plain HTTP, no DAV)→ENOTSUP, other non-207→EIO. The stage/cache
  decorators already relay the dir slots + advertise `CAP_DIRS`, so no decorator
  edit was needed. Tests: `tests/c/test_sd_http_dir.c` (runner `sd_http_dir` in
  `cmdscripts/c_regression_units.py`, obj closure `sd_http{,_select,_read,_write,
  _dir}.o` + libcrypto; ngx log seam stubbed, instances built `log=NULL` so
  `sd_http_live_log` short-circuits) — success (self skipped MID-list, `%20`
  decoded, subdir `DT_DIR`, root `/`), error (404/403/405 → distinct errno, never
  an empty dir), security-neg (proxy-only+deny → EACCES, zero wire I/O).

  **RESOLVED (rename + mkdir) — phase-92, 2026-08-02.** The sd_http driver now
  registers `.mkdir` (WebDAV **MKCOL**, RFC 4918 §9.3) and `.rename` (WebDAV
  **MOVE**, §9.9) and advertises `BRIX_SD_CAP_DIRS_WRITE | BRIX_SD_CAP_HARD_RENAME`
  (`sd_http.c:36-39,49-50`). Both live in `sd_http_write.c` beside the existing
  staged-PUT / DELETE (`unlink` already handled a collection DELETE via the same
  slot, so **rmdir was already covered** — only MKCOL + MOVE were genuinely
  missing for a mutable catalog). Writes never fail over (a mutation on a
  non-primary origin would split-brain the store), so both target **endpoint 0**
  via `sd_http_write_path`, exactly like `unlink`/`staged_commit`. `mkdir` ignores
  `mode` (a WebDAV collection has no POSIX mode). `rename` composes an **absolute**
  `Destination:` URI from endpoint-0 scheme/host/port + the write-path of `dst`
  (MOVE requires a full URI, not a bare path) and honours `noreplace` via
  `Overwrite: F` (existing dst → 412, refused) vs `Overwrite: T` (replace); the
  static auth header rides alongside. `CAP_HARD_RENAME` tells the VFS the MOVE is
  atomic on the origin so it never falls back to copy+delete. A shared
  `sd_http_status_to_errno` maps 401/403→EACCES, 404/409→ENOENT, 405/412→EEXIST,
  else EIO; a transport-layer failure (no status) → EIO. Tests:
  `tests/c/test_sd_http_mutate.c` (runner `sd_http_mutate`, same obj closure as
  `sd_http_dir`) — success (MKCOL 201/200→OK; MOVE 201/204→OK with an absolute
  `Destination` + `Overwrite: T`), error (each status→errno + transport-fail→EIO,
  never a false success), security-neg (a no-replace MOVE MUST send `Overwrite: F`
  so an existing dst is refused 412→EEXIST, never silently clobbered). Still open
  on this driver: **xattr** (WebDAV PROPPATCH) — deliberately out of scope; the
  origin is now read + staged-PUT + enumerate + mutable catalog (mkdir/rename/rmdir).

- **scvmfs (secure CVMFS) X.509/VOMS client-cert auth mode unimplemented.**
  `src/protocols/cvmfs/secure.c:14`; the `brix_scvmfs_authz` enum
  (`module.c:312`) offers only `none|bearer`. EXPERIMENTAL phase-68 T22 surface;
  needs a conf-independent cert-verify seam. **Effort: M-L**.

  **RESOLVED (X.509 mode) — phase-92, 2026-08-02.** The conf-independent
  cert-verify seam already existed as nginx's own `ssl_verify_client` chain plus
  the shared `brix_x509_oneline` / `brix_px_classify` / `brix_sp_glob_match`
  helpers — so X.509 authz is pure policy glue, no new crypto. Added
  `BRIX_SCVMFS_AUTHZ_X509` (`cvmfs.h`), the `x509` enum value (`module.c`), and
  `scvmfs_check_x509()` (`secure.c`): it requires a peer cert that verified
  `X509_V_OK` (a location that forgot `ssl_verify_client` presents no cert and
  fails CLOSED), resolves the end-entity cert (the leaf when the client used a
  bare cert, else the first non-proxy cert in the chain — RFC 3820 proxies chain
  leaf → EEC, so a GSI proxy authenticates as its issuing identity), renders the
  EEC subject DN, and gates it against an optional
  `brix_scvmfs_x509_dn <glob>;` allow-list (multi-occurrence, first match wins,
  `ngx_conf_set_str_array_slot`; empty list = accept any verified client). The
  validated DN becomes the F9 QoS / G15 attest subject (`ctx->token_sub`).
  Config field `scvmfs_x509_dn` on the cvmfs loc conf, `NGX_CONF_UNSET_PTR` +
  `ngx_conf_merge_ptr_value`. Tests (`tests/test_cvmfs_scvmfs_x509.py`, TLS +
  `ssl_verify_client optional` against a test CA): **success** — a CA-signed
  cert whose DN matches the glob serves the object + `.cvmfspublished`, and with
  no glob list any verified client is served; **error** — no client cert → 401;
  **security-neg** — a right-DN cert signed by an untrusted CA is rejected (DN
  spoofing blocked), and a verified cert whose DN is outside the allow-glob →
  403 (authenticated but out of policy).

  **RESOLVED (VOMS mode) — phase-92, 2026-08-02.** `brix_scvmfs_authz voms`
  layers a VOMS-VO authorisation gate on top of the x509 identity check. The
  peer is authenticated by its EEC DN exactly as x509; then `scvmfs_check_voms()`
  (`secure.c`) lifts the client proxy's VOMS Attribute Certificate via the shared
  `brix_extract_voms_info()` extractor (per-VO LSC trust dir
  `brix_scvmfs_vomsdir <dir>` + VOMS signing-CA `brix_scvmfs_voms_cert_dir <dir>`,
  both mandatory in voms mode — validated at merge) and gates the carried VO
  name(s) against an optional `brix_scvmfs_voms <glob>` allow-list
  (`ngx_conf_set_str_array_slot`; empty list = accept any client that carries at
  least one VO). A client that carries **no** VOMS AC is refused (403) — voms
  mode requires a VO, so a merely-authenticated peer is never a bypass. New enum
  `BRIX_SCVMFS_AUTHZ_VOMS`; loc-conf fields `scvmfs_vomsdir`,
  `scvmfs_voms_cert_dir`, `scvmfs_voms`. Because a GSI proxy chain is what carries
  the AC, a cvmfs postconfiguration hook (`brix_scvmfs_postconf_proxy_certs`,
  mirroring webdav's `proxy_certs` hook) sets `X509_V_FLAG_ALLOW_PROXY_CERTS` on
  the TLS context of any server that runs an scvmfs x509/voms location — nginx
  core rejects RFC 3820 proxy certs during `ssl_verify_client` chain validation
  otherwise. Since `scvmfs_authz` is a **location** directive and nginx has
  already folded the config-time location queue into the static location tree by
  module postconfiguration, the hook walks `clcf->static_locations` (+ regex
  locations) recursively to find scvmfs x509/voms locations rather than the
  (now-empty) `clcf->locations` queue. The VOMS runtime is dlopened at merge
  (`brix_voms_init`, before the availability check, as init otherwise runs only at
  postconfiguration) so a voms directive on a non-VOMS build fails config CLOSED.
  Tests (`tests/test_cvmfs_scvmfs_voms.py`, TLS + `ssl_verify_client optional`,
  openssl-native VOMS-AC + per-VO LSC fixture via `utils/voms_proxy_fake.py`):
  **success** — an /atlas VOMS proxy matching the allow-glob is served, and with
  no glob list any client carrying a VO is served; **error** — no client cert →
  401, and a plain GSI proxy carrying no AC → 403; **security-neg** — a /cms VOMS
  proxy (wrong VO) → 403 (a valid VO is not a wildcard). The earlier VOMS-AC
  fixture blocker (voms-proxy-fake AKID mismatch) was resolved by the phase-92
  openssl-native fixture (SKID/AKID-linked signer). Port block `srv_scvmfs_voms`.

- **`sd_block` has no server plane** (`src/fs/backend/block/sd_block.c:109-119`) —
  data-plane only (client `block://` endpoint); a block-backed *server* export
  needs open + extent namespace. Future. **Effort: L**.

  > **RESOLVED (2026-08-02, UNCOMMITTED).** `sd_block` now has a full server
  > plane. `brix_storage_backend block:<device>` (or `block://<device>`) exports a
  > block device — or a regular file used as one — as a flat, fixed-extent
  > namespace: the device capacity (`BLKGETSIZE64` for a real device, `st_size`
  > for a file) is divided into equal `extent_size` extents served as logical
  > objects `/0`..`/N-1`; an `extent_size` of 0 (the default, since
  > `brix_storage_backend` carries no `block_size` argument) makes the whole
  > device a single extent `/0`. The namespace exposes **only** the extent
  > indices — the root `/` is a read-only directory that lists them, any
  > non-numeric name is `ENOENT`, and an out-of-range index is `ENOENT` — so a
  > device export can never be walked into an arbitrary host path. The data plane
  > is the same raw-byte implementation the client already used: each object
  > carries an extent window (`base`/`len`) that `pread`/`preadv`/`pwrite` clamp
  > and base-shift before delegating to the POSIX raw ops; reads past the tail are
  > EOF and a write that would cross the extent boundary is refused with `ENOSPC`
  > (a fixed extent cannot grow). `read_sendfile_fd` is deliberately left NULL so
  > the extent base is always honoured (sendfile would ignore it). Wiring:
  > `block` is a `BACKEND` row in `core/types/fs_list.h` and a scheme in
  > `BRIX_FS_SCHEME_LIST`; the config directive is parsed by `vfs_parse_block_origin`
  > (`src/fs/vfs/vfs_backend_config.c`) into a registry entry, and the request path
  > builds the instance via `brix_vbr_build_block` in the
  > `brix_vbr_source_table` dispatch (`src/fs/vfs/vfs_backend_registry_source.c`);
  > cache/stage tiers compose it via `tier_build_block`. The ngx-coupled server ops
  > (`init`/`open`/`close`/`stat`/`opendir`/`readdir`) are `#ifndef XRDPROTO_NO_NGX`
  > so the ngx-free client `libxrdproto` still gets only the raw byte path. Tests:
  > `tests/cmdscripts/storage_backend_schemes.py` `block_data_plane()` — GET `/0`
  > byte-exact (whole-device extent) · stat `/0` reports the device capacity ·
  > GET `/1` out-of-range extent fails · GET a non-numeric name is rejected
  > (namespace exposes only `/N`) — all green alongside the `block:<device>` parse
  > check. **Effort: L — DONE.**

- **Client io_uring O_DIRECT tier deferred** (`client/lib/core/aio/uring.c:45`,
  `direct` slot reserved) — buffered-only ring works; O_DIRECT is a perf extra.
  **Effort: M**.

  > **RESOLVED (2026-08-02, UNCOMMITTED).** The `direct` parameter is now live.
  > `brix_disk_ring_create(..., direct=1)` flips the fd to `O_DIRECT` via
  > `brix_ring_enable_direct()` (fcntl `F_SETFL`), rounds the per-op buffer up to
  > `BRIX_URING_DIRECT_ALIGN` (4096), and allocates the slab with
  > `posix_memalign()` so every full-block read/write bypasses the page cache.
  > The final short (sub-block) write of a download — which `O_DIRECT` rejects
  > with `EINVAL` — is transparently re-issued through `brix_ring_direct_tail_write()`
  > (drain → clear `O_DIRECT` → buffered `pwrite` → restore); the fd flags are
  > always restored on fail/destroy. A filesystem that refuses `O_DIRECT` fails
  > create with `XRDC_EUNSUPPORTED`, so an **AUTO** ring silently falls back to the
  > buffered tier and an **ON** ring surfaces a clean error. Plumbed end-to-end:
  > `brix_vfs_open_opts.io_uring_direct` → `posix_ring_select`/`block_ring_select`
  > → `brix_copy_opts.io_uring_direct`, populated in `copy_local.c`/`copy_block.c`/
  > `copy_upload.c`, exposed as `xrdcp --io-uring-direct` (and `$XRDC_IO_URING_DIRECT`).
  > Tests: `client/tests/c/uring_direct_unit.c` (byte-exact round-trip incl. a
  > 1000-byte buffered tail through a direct read+write ring · oversize-chunk
  > rejection · clean refusal on a fd `O_DIRECT` cannot be enabled on), registered
  > in the client `test` target + `make uring-direct-unit`, driven by
  > `tests/test_uring_direct.py`. Man page + bash/zsh completions updated.

- **HTTP shared cache-fill: no remote-source passthrough streaming** — a
  non-cacheable object (driver returns DECLINED) yields 502 rather than a
  stream-from-source passthrough (`src/protocols/shared/http_cache_fill_worker.c:97`).
  Niche edge; **Effort: M** or document as won't-do.

  **RESOLVED (store-then-evict) — phase-92, 2026-08-02.** A true off-loop
  stream-from-source is a large rework of the fill spine (the worker fills into
  the cache store, then serves via the cache-hit reenter — there is no direct
  source→client relay). Instead we lifted the 502 with the semantically
  equivalent, far cheaper **store-then-evict** passthrough: when the admission
  policy DECLINES a remote object purely on the size cap but it still fits a
  bounded spool, fill it anyway, serve it through the normal cache-hit reenter,
  then **evict** it once every coalesced waiter has opened its serve fd (Linux
  keeps the open fds valid past the unlink). The object is delivered byte-exact
  without polluting the cache; nothing unbounded is ever spooled. New directives
  (both planes via the tier X-macro, **functional on the HTTP plane only** —
  passthrough rides the off-loop fill worker the root:// stream plane never
  uses): `brix_cache_passthrough on|off;` (default off — fail-closed opt-in) and
  `brix_cache_passthrough_max <size>;` (spool cap; 0 = fall back to the
  `cache_max_object` cap). Wiring: an `allow_pt`/`out_pt` opt-in threaded through
  `sd_cache_fill` → `sd_cache_fill_attempt` → `cache_fill_acquire`
  (`src/fs/backend/cache/sd_cache_fill.c`), gated by
  `sd_cache_passthrough_cap()` (`sd_cache_policy.c`); the HTTP worker opts in
  (`brix_sd_cache_fill_key_ex(..., 1, &t->passthrough)`) and evicts in
  `brix_http_cache_fill_done` (`http_cache_fill_worker.c`). Policy fields
  `passthrough`/`passthrough_max` on `brix_cache_policy_t` (`fs/tier/tier.h`),
  mapped from `common->cache_passthrough*` in `brix_tier_fill_cache_policy`
  (`runtime_server_backend_cache.c`). Tests (`tests/cmdscripts/cache_passthrough.py`
  + `tests/test_cmd_cache_passthrough.py`, WebDAV HTTP node over a remote
  root:// origin): **success** `serve-evict` — a small object caches+retains
  normally, a mid object over the caching cap but within the spool cap is served
  byte-exact then evicted (`event=passthrough-evict` logged, not left in the
  store); **error** — an object over the spool cap is refused 502 and never
  spooled; **security-neg** `disabled-declines` — with passthrough off a
  size-declined object is never served (502) and never lands in the store,
  proving the opt-in is fail-closed. A future true source→client relay remains
  possible but is now un-shadowed by the 502.

- **GridFTP `OPTS RETR Parallelism=N` is a dead field** — parsed/clamped/stored
  (`ftp_ev_dispatch.c:123`) but never read; RETR MODE-E is always single-stream
  (`ftp_ev_mode_e.c:99-141`, emits `Total Stripe Count: 1`). Single-stream is
  protocol-valid, so this is **wire-it-or-remove-it**: **XS** to remove, **L** for
  true parallel-stripe RETR.

  **RESOLVED (removed) — phase-92, 2026-08-02.** Confirmed the field was written
  at exactly one site (`ev_cmd_opts`) and read at **zero** sites tree-wide (a
  clamp-and-store with no consumer), so it was pure dead state pretending to a
  capability the RETR path never had. Removed `int parallelism` from `ftp_ev_t`
  (`ftp_ev.h`) and rewrote `ev_cmd_opts` (`ftp_ev_dispatch.c`) to a lenient 200
  for every option **without** parsing/clamping/storing the value — RETR stays
  single-stream (the honest, protocol-valid behaviour; MODE E still emits
  `Total Stripe Count: 1`). The wire contract is unchanged: a client's
  `OPTS RETR Parallelism=<n>` capability probe still gets its 200 ACK, so no
  session regresses; we simply stopped keeping a value nobody consumed. True
  parallel-stripe RETR (the "wire-it" alternative, **L**) remains a future item
  and is now un-shadowed by the dead field. Test:
  `tests/test_gridftp_verbs.py::test_opts_parallelism_accepted_but_single_stream`
  — success (`Parallelism=4` → 200), robustness (formerly-clamped `=999` and an
  unrelated OPTS token → 200, garbage never fails the session), behaviour-neg (a
  plain RETR after the probe returns the whole object byte-for-byte over one
  stream, proving the removed field never gated the transfer).

- **Client async pipelining disabled under request signing**
  (`client/lib/core/aio/aio.c:322`) — signed sessions fall back to synchronous
  I/O. Likely a permanent design boundary (per-request signature ordering vs
  out-of-order completion); flagged for confirmation. **Effort: L** if ever lifted.

---

## 5. Cosmetic / dead-code / doc-hygiene

Not open features; cleanup that reduces reader confusion or removes unreachable
code.

- **`reservation.c` bandwidth-reservation module is compiled but entirely
  unwired.** `src/net/ratelimit/reservation.c` (built via `config:1414`) is a full
  XrdBwm-style `brix_resv_*` grant/queue/release engine with **zero** callers, no
  directive to create a zone, and no test. Parked per ADR-3, but concretely dead
  code in every build. **Drop from build (S)** or **add directive + call-sites
  (M)**.
  **RESOLVED (phase-92, 2026-08-02) — wired to the root:// read-open path (option
  M).** The XrdBwm engine now enforces a per-worker read-bandwidth budget:
  - **Directives** (`NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1`, in
    `directives_auth.h`): `brix_throttle_bandwidth_zone <name>` +
    `brix_throttle_bandwidth_budget <size>` (both `""`/`0` = off). Stored on
    `brix_throttle_conf_t` (`conf_structs.h`); unset-init in `server_conf.c`,
    merged in `server_conf_merge_security.c`.
  - **Acquire** — `brix_open_apply_throttle`
    (`open_resolved_file_finalize.c`), right after the phase-59 open-files cap: a
    **read** open reserves its file size (`cached_size`, set by
    `brix_open_init_handle` immediately above) against the named zone via
    `brix_resv_zone_create` (idempotent) + `brix_resv_schedule`. Over-budget →
    refuse with `kXR_Overloaded` ("bandwidth reservation budget exhausted"),
    unwinding the open-files slot acquired in the same function. Write opens are
    exempt (no known size yet). The reserved byte count is stashed on the handle
    (`brix_file_t.bwm_reserved`, `core/types/file.h`).
  - **Release** — the single teardown choke point `brix_free_fhandle`
    (`fd_table_teardown.c`), which covers kXR_close, disconnect (via
    `brix_close_all_files`), and every open-path error unwind: returns exactly
    `bwm_reserved` bytes to the zone by name. `fhandle_reset_slot` zeroes the
    field so a reused slot never double-releases.
  - **Engine fix**: `brix_resv_done` was made **byte-precise** (now takes the
    released `bytes`, not an opaque handle) so a sibling transfer can reuse a
    freed grant while others are still outstanding, and a bogus over-release is
    clamped (no underflow). Signature updated in `reservation.{c,h}`.
  - **Tests**: hermetic C-unit `tests/c/test_reservation.c` (3/3 — byte-precise
    release · over-budget refuse+recover · security-neg no-overcommit/no-inflation;
    runner `reservation` in `c_regression_units.py`) **plus** the e2e wire suite
    `tests/test_phase92_bwm_reservation.py` (3/3 — grant→refuse→release over the
    kXR wire · reservation freed on hard disconnect · sub-budget file never
    refused). Ledger entry `lc-bwm-reserve` (port 31125,
    `xdist_group("lc-bwm")`) in `fleet_lifecycle_ports.py`. Clean `-Werror`
    build; `objs/nginx -t` accepts the directives.

  **TRAPs:** (a) the registry is a **per-worker static**, so the e2e config must
  run a single worker and the file must be `xdist_group`-serialised — otherwise
  two workers each own an independent budget and the aggregate assertions flake.
  (b) release is by **byte count resolved by zone name**, NOT a stored zone
  pointer — `brix_free_fhandle` already has the srv conf, so no per-handle zone
  pointer is kept (survives worker reload). (c) acquire is read-only and gated on
  `cached_size > 0`; a zero-length file reserves nothing (correct — it transfers
  nothing).

- **Stale krb5-GSSAPI `DEFERRED`/`call-ready` banners on superseded code.**
  `brix_vfs_deleg_krb5_token` (`vfs_deleg_hooks.c:99`), `brix_cache_origin_auth_krb5`
  (`origin_auth.c:332`), and the comment at `vfs_deleg.c:536` present the GSSAPI
  `gss_init_sec_context` dialect as the production/unfinished path. Verified: those
  functions have **no production caller** — the **raw AP-REQ** path
  (`origin_bs_auth_krb5` → `brix_cache_origin_auth_krb5_raw`,
  `origin_protocol_bootstrap.c:320-329`) drives krb5 fully (superseded per phase-88
  UPDATE (iv); stock XRootD speaks raw `krb5_rd_req`, not GSSAPI init tokens). The
  GSSAPI engine is deliberately retained-with-unit but its comments mislead (this
  is what led the fs-territory sweep to tentatively flag it INFRA-BLOCKED — it is
  not; it is retained-unused). **Re-label "retained reference dialect, superseded
  by raw AP-REQ" or delete. Effort: <0.5d.**
  **RESOLVED (phase-92, 2026-08-01) — re-labelled.** Verified tree-wide: the
  GSSAPI-init pair `brix_vfs_deleg_krb5_token` (`vfs_deleg_hooks.c`) and
  `brix_cache_origin_auth_krb5` (`origin_auth.c`) have **zero** production
  callers; the live origin leg is `brix_cache_origin_auth_krb5_raw`, dispatched
  from `origin_protocol_bootstrap.c:329`. Rewrote both banners from
  "DEFERRED / CALL-READY but not yet invoked" to **"RETAINED REFERENCE DIALECT —
  SUPERSEDED, not on the production path"**, naming the raw AP-REQ leg and
  explicitly warning that the absence of a caller is deliberate, NOT
  infra-blocked. Also corrected the *live* materialiser `brix_vfs_deleg_krb5`
  (`vfs_deleg.c`), whose comment misnamed the GSSAPI variant as its origin leg —
  it feeds the raw path. Comment-only; clean `-Werror` rebuild.

- **`brix_cns_count()` is a dead public API** (`src/net/cms/cns.c:205`) — zero
  callers; the unittest calls `brix_cns_inv_count` directly. Delete, or surface it
  as a CNS-inventory-size metric to give it a purpose. **Effort: XS**.
  **RESOLVED (phase-92, 2026-08-01) — deleted.** Removed the function body
  (`cns.c`) and its declaration (`cns.h`); the live inventory-size helper
  `brix_cns_inv_count` (public, exercised by `cns_inventory_unittest.c`) and its
  wrapper `cns_active_table` (still used by `brix_cns_stat`) are untouched. Clean
  `-Werror` rebuild, no orphaned statics.

- **Dead reserved flag `skip_cache_check`** (`src/fs/path/unified.h:19`) — zero
  readers tree-wide. **XS**.
  **RESOLVED (phase-92, 2026-08-01) — deleted.** Removed the bitfield from
  `brix_path_opts_t`; all initializers are designated (no positional brace-init
  depended on field order), so the removal is ABI-neutral for callers. Clean
  `-Werror` rebuild.

- **Client `xrd_diag compare` S3/HTTPS-davs oracle planes unimplemented**
  (`client/apps/diag/diag_compare.c:127`) — the cross-protocol consistency oracle
  covers root:// vs cleartext WebDAV only; S3 (SigV4) + HTTPS-davs planes emit a
  `deferred` note. Diagnostic-coverage extra. **Effort: S-M**.

  **PARTIALLY RESOLVED (HTTPS-davs plane) — phase-92, 2026-08-02.** Added the
  HTTPS WebDAV plane to the compare oracle. New `--davs-tls host:port` option
  (`diag_args.davs_tls`, wired in `xrddiag.c`); `diag_compare.c` gained a
  `http_plane_md5()` helper (mkstemp → `brix_http_download` streaming/TLS →
  `brix_cksum_fd` MD5) and, after the cleartext plane, a guarded HTTPS branch that
  fetches the same logical path over TLS (`tls=1`, verify follows
  `--no-verify-tls`, system trust store) and emits `davs-tls` + `davs-tls-md5`
  probes against the root:// MD5. TLS verification is enforced by default. The
  S3/SigV4 plane remains deferred (needs a SigV4 endpoint + static credentials +
  bucket/cred CLI wiring) — the note is now narrowed to `s3` only. Tests:
  `tests/test_xrddiag_compare_davs.py` +3 (success `davs-tls-md5` match with
  `--no-verify-tls`; security-neg — default verify rejects the self-signed peer;
  error — connect-refused → clean `[FAIL] davs-tls` with `XRDC_MAX_STALL_MS=0`),
  6/6 green. Config `nginx_xrddiag_compare_davs.conf` gained a TLS WebDAV listener
  on `{TLS_PORT}` (30449) over `{DATA_ROOT}`; port ledger updated. **S3 plane
  still open** (residual **Effort: M**, infra: MinIO + creds).

- **~~Dead test files (deletion candidates, not gaps)~~ — FINDING WITHDRAWN
  (phase-92, 2026-08-01): NOT dead; the four files carry live coverage.**
  A verification pass before any deletion (per the "look at the target before
  removing" rule) found that none of the four is wholesale dead — each was
  ALREADY refactored into live tests plus a small number of *documented*
  `@pytest.mark.skip` stubs retained deliberately to record the A-2 / frm cleanup.
  All four collect cleanly (`--collect-only` → **51 tests, 0 import errors**),
  which by itself refutes "bind to code that no longer exists":
  - `tests/test_phase21_proxy_filter.py` — 14 tests, ~5 skip-stubs (the deleted
    WebDAV reverse-proxy transport); the rest are LIVE introspect-filter tests on
    `nginx_xrdhttp_filter.conf` / `nginx_webdav_introspect.conf` via the lifecycle
    harness (`registry_server("introspect-idp")`).
  - `tests/test_phase23_admin_api.py` — 27 tests, ~2 skip-stubs; 25 LIVE (the
    admin API + proxy-pool JSON surface, read from a file, over `static-origin`).
  - `tests/test_frm_queue.py` — 7 LIVE tests (durable-queue reqid / restart
    survival / cancel / corrupt-record reclaim) on `nginx_lc_frm_queue.conf`; the
    `:242` line the finding cited is one assertion inside a live test, not a dead
    file.
  - `tests/test_frm_phase4.py` — 3 tests, 1 inline skip (`:79`, the retired F6
    purge-watermark monitor); the other 2 (directives-accepted, metrics-exported)
    are LIVE on `nginx_lc_frm_phase4.conf`.

  **No deletion performed.** The skip-stubs are intentional cleanup documentation;
  removing the files would delete passing coverage. If a future pass wants to
  trim, the target is the individual skip-stub *functions*, not the files — and
  even that is optional (they self-document what was retired).

- **Stale `Status:` headers** — `phase-55`/`phase-27`/`phase-28` ("PLAN"),
  `phase-26-slice-caching` ("Draft", though its *content* maps to §4 slice-cache).
  Header correction only (§2).
  **RESOLVED (phase-92, 2026-08-02) — headers reconciled.** Each of phase-27,
  phase-28 and phase-55 already carried a verified `> SUPERSEDED (2026-07-25)`
  blockquote *directly below* its stale one-line `**Status:** PLAN — not yet …`
  header; only the header itself had never been reconciled with its own note.
  All three now read `**Status:** SUPERSEDED — substantially LANDED (see the note
  below)`, so a reader no longer sees "not yet begun / not yet implemented" on a
  phase that in fact shipped. `phase-26-slice-caching` has **no** SUPERSEDED note
  and is genuinely still open (the §4 slice-cache item), so its "Draft" was
  honest but ambiguous with the three stale-but-done headers — it now reads
  `Draft (2026-06-11) — UNIMPLEMENTED; tracked open as the §4 slice-cache item`,
  distinguishing "designed, not built" from "built, header stale." Doc-only, no
  code path — no test.

### Build note — mixed-ABI hazard surfaced while landing O-1 (phase-92)

Landing O-1 exposed a real mixed-ABI condition on the shared binary, worth
recording for anyone touching `ngx_brix_metrics_t` or writing a C-unit that reads
its fields by name:

- The nginx addon Makefile does **not** track the metrics-header dependency, so
  uncommitted field additions ahead of `frm` in `metrics.h` left some objects on
  the old layout and others on the new one — metric writes landed at a different
  `offsetof(frm)` than the reader saw. Fix = a clean `rm -rf objs/addon` + full
  rebuild puts every object on one ABI (see memory `struct_field_abi_clean_rebuild`,
  `build_header_dep_mixed_abi`).
- **`-DBRIX_HAVE_SQLITE=1` shifts `offsetof(ngx_brix_metrics_t, frm)` by 16 bytes**
  (a pblock counter sits before `frm`). A C-unit that reads `frm` fields by name
  MUST compile with the **same** `-DBRIX_HAVE_*` feature defines as the linked
  object. `tests/cmdscripts/c_regression_units.py` now derives them at runtime via
  `_brix_have_defines()` (greps the build's `objs/Makefile`) so the harness can
  never silently drift from the build's feature set.

---

## 6. Infra-blocked (verified still open)

Genuinely un-closable from this shell; hardware/operator/container-gated. All
re-confirmed 2026-08-01.

- **P5 kTLS-on-HW-offload A/B** — needs a TLS-ULP/offload-capable NIC (host has no
  `tls` ULP). The software-kTLS safe half landed 2026-07-28; only the HW-offload
  measurement leg remains.
- **Throughput *magnitude* trend numbers** (phase-33 P3-B1/P3-B3/P1) — need a
  high-BDP perf host. Partially mitigated: the netem user+net-ns harness measured
  ~8× unprivileged (memory `phase88-netem-bdp-unblock-landed`); the absolute
  perf-host numbers remain.
- **Pelican cache registration** — the federation **POST** and its registry
  public-key handshake stay blocked on the operator running the `pelican` CLI
  out-of-band (no live Director, no registered key). **Document-construction half
  CLOSED — phase-92, 2026-08-02:** the `OriginAdvertiseV2` payload builders
  (`brix_pelican_build_ad` / `_caps_json` / `_rfc3339` in
  `src/fs/cache/origin/pelican_register.c`) are deterministic and now covered by
  an offline C unit (`tests/c/pelican_ad_test.c`, runner spec `pelican_ad`) that
  links the real object and parses the emitted JSON back with jansson — asserting
  the full advertise shape (name/serverId/registry-prefix/data-url/storageType/
  namespaces), the RFC3339 UTC timestamps and `expiry = now + interval + 30s`, the
  configured-vs-default namespace branch, empty-`data_url` fail-soft, and the
  security-relevant cache **capability contract** (`Write`/`Copies` MUST stay
  false — a cache never advertises writable). See the §7 entry below.
- **phase-70 STS / krb5 *live labs*** (P90-70.1 / P90-70.2) — ~~the runtime origin-leg
  **wire is landed and live-verified** (§2); what remains is only the packaged,
  repeatable lab invocation~~ **CLOSED — phase-92, 2026-08-02.** The packaged labs now
  RUN and are green on this host: the STS lab (`test_sts_minio_live.py`, 3/3) and both
  krb5 labs (`test_krb5_forward_live.py` 16/16, `test_krb5_cache_origin_e2e.py` 5/5)
  drive the production origin-leg objects against a real MinIO / unprivileged MIT KDC.
  See the re-probe block below for the one-line container-runtime fix that unblocked the
  STS lab and why the krb5 labs already ran. (The coverage-**floor** graduation, a
  distinct item, stays CI-gated.)
- **Coverage-floor graduation** — the coverage CI lane ships report-only;
  `COVERAGE_MIN` is never set. One clean full-tier fleet run in CI is needed to
  read the true number and set the enforcing floor. Needs the fleet to boot in CI.
  (This is the lone remaining engineering item in `QUALITY_ROADMAP.md`.)

  **Toolchain sub-blocker cleared — phase-92, 2026-08-02.** The host shipped no
  `lcov`, so `tools/ci/coverage.py` self-skipped even the *capture* half of the lane
  (it early-returns when `lcov`/`gcov` are absent). `lcov` 1.16 is now installed
  unprivileged (`~/.local/bin`, self-contained — the 2.x line pulls `Capture::Tiny`
  + friends that need CPAN/root; 1.16 is a single-Perl-script release with none of
  that) and verified end-to-end against a real `.gcda` (`gcc --coverage` target →
  `lcov --capture` → `--summary` reports 100% lines/fn). `coverage.py` finds it on
  `PATH` unchanged. What remains is **only the policy gate, not tooling**: per the
  hyper-hardening **B-1 lesson** a numeric gate must not be flipped to *blocking*
  before a *reviewed* baseline from a clean full-tier run exists — setting
  `COVERAGE_MIN` from an unreviewed local partial would violate exactly that
  principle (a partial run under-reports, so a floor read off it is either too low
  to bite or, if margin-padded, a guess). Graduation runbook, unchanged and
  CI-gated: (1) full-tier instrumented fleet run —
  `operator_build build_coverage && COVERAGE_TEST_CMD='<full fast+serial fleet>' python3 tools/ci/coverage.py`;
  (2) read `src/` + `client/` line% from the emitted `.info`; (3) commit
  `COVERAGE_MIN=<measured − small margin>` once reviewed. Blocked solely on the
  fleet booting green in CI (same gate as every §6 packaged-lab item), no longer on
  the absence of `lcov`.
- **WSL2 clock steps backwards** (memory `wsl2-clock-backwards-steps`) — host
  clocksource steps back ~2.7s/27s; blocks trustworthy timing/token-expiry/GSI/mtime
  tests until switched (needs sudo).

**Re-probe — phase-92, 2026-08-02 (qemu/minikube attempt).** Per the "try qemu for
hardware emulation, minikube for cluster" directive, every §6 item was re-checked
against what this shell actually offers. Verified environment: `qemu-system-*` is
**absent** (no CPU/NIC emulation path at all), `uid=1000` with **no passwordless
`sudo`** (`sudo -n` → "a password is required"), `tcp_available_ulp` = `mptcp` only
(**no `tls` ULP**, module unloaded — `modprobe tls` needs root), clocksource `tsc`
with `hyperv_clocksource_tsc_page` *available* but `current_clocksource` writable
only as root, and `pelican` absent. Outcome per item:
  - **P5 kTLS-HW offload** — doubly blocked: loading the `tls` ULP is root-only and,
    even loaded, HW offload needs a `tls`-ULP-capable NIC the WSL2 virtual adapter
    does not provide; qemu can't synthesise one (and is absent). **Stays blocked.**
  - **Throughput magnitude** — needs a real high-BDP perf host; qemu would only add
    virtualisation jitter, not BDP. The ~8× netem mitigation stands. **Stays blocked.**
  - **Pelican registration** — the *POST* stays blocked: `pelican` CLI absent *and*
    the blocker is an external federation-registry key handshake run by the operator,
    not a local tool. But the **document-construction half was closed this pass**
    (2026-08-02) rather than deferred wholesale: the three pure `OriginAdvertiseV2`
    builders were un-static'd behind a documented test seam and covered by an offline
    C unit (`pelican_ad`) that conformance-checks the advertise JSON, timestamps and
    the read-only capability contract against the real object — the deterministic
    part needs no Director. See the §6 Pelican bullet and §7 entry.
  - **WSL2 clock** — the fix (switch `current_clocksource` to a non-stepping source)
    is a root sysfs write; no passwordless sudo. **Stays blocked** (needs operator).
  - **phase-70 STS / krb5 live labs** — **CLOSED (2026-08-02).** On the second pass
    (identical directive, explicit "use minikube") these were driven to green rather
    than deferred:
    - **STS MinIO lab** (`test_sts_minio_live.py`) self-skipped on a **docker-only**
      gate (`shutil.which("docker")` → the whole suite `pytest.skip`) though the host
      ships rootless `podman` (CLI-compatible) with the `quay.io/minio/minio:latest`
      image already local. Fix = one reusable seam: `cmdscripts/container_runtime.py`
      `container_runtime()` returns the first runtime that is present **and** whose
      `<rt> info` exits 0 (docker→podman, `$BRIX_CONTAINER_RUNTIME` to pin), and the
      lab threads that string through image-pick / `run` / `rm`. It now stands up a
      real MinIO under podman and the production `brix_s3_sts_assume(flavor=MINIO)`
      mints temp creds that authenticate an S3 GET byte-for-byte — **3/3 green**
      (happy + two security-neg). Marked `slow` (it spawns a container on fixed port
      19922) so it rides the nightly/full tier, not the parallel PR gate.
    - **krb5 labs** (`test_krb5_forward_live.py`, `test_krb5_cache_origin_e2e.py`)
      are container-free — they stand up an **unprivileged MIT KDC** in a namespace;
      the MIT tooling (`krb5kdc`/`kadmin.local`/`kdb5_util`/`kinit`/`unshare`) **and**
      stock `xrootd`/`libXrdSeckrb5` are present, so both already run green here —
      **16/16 + 5/5** — no code change needed; verified this pass.
    The reusable `container_runtime` seam also positions the ceph / gridftp-interop
    labs to drop their docker-only gates the same way (not done here — out of §6/phase-92
    scope, kept surgical).
The remaining §6 items (kTLS-HW offload, throughput magnitude, pelican registration,
WSL2 clock, coverage-**floor** graduation) stay blocked on root / dedicated hardware /
an external operator, re-confirmed this pass. The STS/krb5 live labs are the one §6
item that closed — with a real code change (the runtime seam) and a running test, not
doc-only.

> **Reconciliation note:** the ASan+UBSan CI lane (B-2) and the fuzz entry-point
> carves (C-1/C-2) that `phase-90` §3.2/§4.2 still list as infra-blocked were
> **LANDED 2026-07-30** per `phase-88` §4 (`tools/ci/asan.py`, `asan.yml`, the
> carved fuzz TUs). Those phase-90 rows are stale; only the coverage-floor fleet
> run above is a genuinely-open CI-infra item.

---

## 7. Coverage register

Verified baseline (read locally, `docs/refactor/coverage-fast-tier-plan.md` +
`QUALITY_ROADMAP.md` §2.3): **`src/` 67.5% lines / 76.5% fn / 46.8% branch**,
**`client/` 53.4% lines**. Genuinely-open coverage work:

- **Wave 3/4 fast-tractable tests un-built** — W3.7 `cred_mint` live-capture, W3.8
  token-exchange TLS-stub, W4.9 `vfs_io_core.c` branch nudges. **Effort: M.**

  **PARTLY LANDED — phase-92, 2026-08-02.** W3.7 is subsumed: the gcda-capture fix
  above credits the existing `tests/c/test_cred_mint.c`, so `cred_mint.c` reads
  **81.06%** without a live driver (the plan's own "*or* add tests/c gcda to the
  lcov capture" alternative). W3.8's guard + connect-fail tier landed as a direct C
  unit `tests/c/exchange_test.c` (runner `exchange`) linking the real `exchange.o`
  — now that tests/c gcda is captured this moves `exchange.c` off 0% (entry-guards,
  RFC-8693 body build, https-only pin, connect-fail error map, http-refused
  security-neg). **W3.8 happy path now CLOSED in the fast tier (2026-08-02):**
  rather than stand up a trusted-CA TLS OIDC stub (fleet tier), the response-parse
  success branch is exercised deterministically by exposing `brix_tx_parse_response`
  (non-static, declared in `exchange.h`) and calling it directly from
  `tests/c/exchange_test.c` with synthetic RFC-8693 reply bodies — a well-formed
  `{"access_token":...}` yields NGX_OK with the pool-copied, NUL-terminated token
  (verbatim bytes asserted), plus a minimal-object case; the eight JSON rejection
  branches (malformed, empty, non-object, missing / integer / null / empty-string
  `access_token`, duplicate key) each return NGX_ERROR leaving a poisoned `out`
  slot untouched. This covers the previously-0% success path without a network and
  makes the TLS stub redundant for coverage. **Residual — documented tail, DEFERRED
  not churned:** (i) W4.9 `vfs_io_core.c` branch nudges — re-assessed
  net-negative: the candidate hosts are live-fleet differential tests that
  self-skip without the stock toolchain (so the added assertions wouldn't run in
  the fast tier they're scored in), the target functions are already line-covered
  by the existing page-boundary READ suite, and the remainder is pure branch-% on
  a flaky live fleet. Revisit only inside a reviewed full-tier run (§6). Full
  rationale in `coverage-fast-tier-plan.md` §W4.9.
- **Category-D gcda not captured** — `cred_mint.c` reads 0% because
  `tests/c/test_cred_mint.c`'s gcda is not in the lcov capture; a tests/c
  gcda-capture tooling fix. **Effort: S.**

  **RESOLVED — phase-92, 2026-08-02.** Root cause was a link-line defect, not a
  capture-path one: the cred_mint harness (`c_auth_units.run_cred_mint`) links the
  pre-built `cred_mint.o` object, but its `gcc` line carried no `--coverage`. Under
  the gcov build (`operator_build build_coverage` compiles every addon object with
  `--coverage`), that object exports `__gcov_init`/`__gcov_exit`/`__gcov_merge_*`;
  linking it without `--coverage` fails on those undefined symbols (so the unit
  never runs) and, even were it to link, the gcov runtime that flushes `.gcda` at
  exit would be absent. Fix: `_coverage_link_flags()` (`tests/cmdscripts/c_auth_units.py`)
  scans the link args for any `.o` with a sibling `.gcno` (the tell-tale of an
  instrumented build) and, only then, prepends `--coverage` to the harness link.
  Running the unit now flushes `cred_mint.gcda` to the path baked into the object
  at build time — under `objs/addon/backend/`, which `tools/ci/coverage.py`'s
  `lcov --directory <nginx_src>/objs` already captures. The C unit already runs in
  the fast fleet tier (`test_c_auth_units.py::test_c_auth_unit[cred_mint]`, not
  slow/serial), so no coverage-lane wiring change was needed. Zero effect on
  ordinary builds (no `.gcno` sibling → no flag). Verified end-to-end on a scratch
  instrumented `cred_mint.o` (host has `gcov` but not `lcov`): the harness links,
  passes, flushes the gcda, and `gcov` reports **cred_mint.c 81.06% lines / 67.16%
  branch (was 0%)**. Tests: `test_c_auth_units.py::test_coverage_link_flags_adds_flag_for_instrumented_object`
  (success: `.gcno` sibling → `['--coverage']`, incl. repo-relative object paths)
  and `::test_coverage_link_flags_noop_without_gcno` (negative: plain `.o` and
  source/lib args → `[]`). **Effort: S — DONE.**
- Category A/B dark files (gridftp ev/*, backends `sd_s3_*`/`cephfs_layout`/
  `sd_remote`) are marker/infra-excluded by design — **not** fast-tier defects;
  listed only so 0% is not mistaken for untested.
- **`pelican_register.c` — advertisement builders now covered (phase-92,
  2026-08-02).** Its network path (Director discovery + libcurl POST + ES256 JWT)
  stays infra-excluded, but the pure `OriginAdvertiseV2` document builders were
  un-static'd behind a documented test seam and are now exercised offline by the
  `pelican_ad` C unit (`tests/c/pelican_ad_test.c`), which links the real
  `origin/pelican_register.o` and parses the emitted JSON back with jansson. New
  runner spec in `tests/cmdscripts/c_object_units.py` — **note it must carry the
  `-DBRIX_HAVE_*` feature defines** the object was built with, since the advertise
  sub-struct sits past feature-gated fields in `ngx_stream_brix_srv_conf_t` and a
  layout skew otherwise reads config fields off the wrong offsets.

---

## 8. Out of scope

By-design XRootD parity gaps are documented decisions, not open work, and are not
listed: `metadata.c` QFinfo/Qvisa/Qopaque FSctl-unsupported (no XrdOfs plugin
layer), retired v5.2.0 opcodes returning `kXR_Unsupported`, WebDAV `ACL`
*mutation* refuse-stub (`acl.c:13`, discovery via PROPFIND works), S3 per-object
ACL/versioning subresources (`handler_object_route.c:161`, phase-43 non-goal),
stock `xrdcp --xrate` (throttle primitive wired only into xrdfs `dd`, deliberate
non-goal), and the ~25 documented `DIVERGENCE` xfails (profile/interop choices).
Compile-time build variants (`src/tpc/engine/noop.c`, the io_uring/seccomp stub
fallbacks) are intentional, not stubs. CVMFS conformance/automount/next-gen legs
(phase-84/85/87) carry their own registers.

---

## 9. Recommended sequencing

Cheap, high-value, no-infra first:

1. **§3.1 FRM metrics increment** + **§3.5 TPC bytes_total** — two observability
   blind spots on shipped features; both LOCAL, together ~1.5d, immediately
   visible on the dashboard/Prometheus.
2. **§3.2 WLCG bearer RFC-6750** + **§3.9 JWT hardening** — conformance/security,
   turns 7 strict xfails green.
3. **§3.6/§3.7 Client Task C2** (auto-refresh + VFS-S3 cred store) — makes two
   accepted CLI surfaces actually work; small.
4. **§3.4/§3.8/§3.13 S3 namespace + tier creds + cstore enumerate** — a coherent
   S3-as-first-class-backend cluster (opendir/server_copy + private buckets +
   scrub); medium, unlocks §4 sd_http follow-on.
5. **§3.3 Content-Encoding→object PUT** and **§3.12 FRM RECALL ledger**.
6. **§5 cleanup pass** (dead code + stale banners + dead tests) — low risk, one
   sweep.
7. **§4 features** by demand: GridFTP VO-ACL (small, high WLCG value) → slice-cache
   → phase-91 gsiftp backend (the big one).

Infra-blocked (§6) and the coverage floor (§7) proceed only as hardware / CI-fleet
/ operator access becomes available.
