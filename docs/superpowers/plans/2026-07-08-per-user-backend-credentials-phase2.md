# Per-User Backend Credentials — Phase 2 (the "out of scope" follow-ups) Implementation Plan

> Continues 2026-07-08-per-user-backend-credentials.md (Phase 1, COMPLETE). Extends the Phase-1 seam (brix_sd_cred_t, open_cred/staged_open_cred, brix_vfs_backend_cred gate, brix_stage_cred_t). Executed via superpowers:subagent-driven-development.

**Global Constraints:** NO goto; WHAT/WHY/HOW doc blocks; no new globals; borrowed pool pointers never in detached state (copy to char[]); unified directives in http_common.c + stream mirror; new .c → ./config + ./configure else make; -Werror; reject→EACCES→403; NO git writes without approval; concurrent sessions share tree+build (avoid io_uring/aio/handler.c/contrib); Phase-1 tests stay green.

---

### Task 1: Namespace-op credential scoping
DONE. (cred-scoped ns vtable slots + brix_vfs_ns_leaf unwrap + gate at every ns dispatch incl probe.)

### Task 2: Per-user bearer .token files
DONE. (ucred selects .pem then .token; brix_sd_cred_t.bearer; ztn override in origin bootstrap.)

### Task 3: Prometheus counters for credential outcomes
DONE. (cred_select_{user,fallback,deny}_total per-proto; brix_metric_cred_result; exporter.)

### Task 4: Deny-mode flush dead-letter
DONE. (attempts+age cap → move to journal/deadletter/; only DENIED dead-letters; restart honors cap.)

### Task 5: Deferred minor-finding cleanups (from Phase-1 + Phase-2 reviews)

**Files:** `src/core/config/http_common.c`, `src/fs/cache/origin_protocol.c`, `src/protocols/s3/put_aio.c`/`put_chunk.c`/`put_finalize.c`, `src/fs/backend/cache/sd_cache.c`, `src/fs/backend/ucred.c`, `src/fs/xfer/stage_engine.c`.

Pure cleanups, no behavior change except clearer diagnostics:
1. Move `brix_http_ucred_fallback_enum` below the `brix_cache_verify` doc comment so the comment is adjacent to its enum (http_common.c).
2. origin_protocol.c: distinct message for the `kXR_authmore`-no-advert per-user branch (x509 AND bearer) — "origin sent kXR_authmore with no auth advert for the per-user credential".
3. The three S3 probe-bind sites (put_aio/put_chunk/put_finalize): one-line comment that the bind decorates a probe/stat ctx (Phase-2-forward; no functional change today).
4. `sd_cache_staged_open_cred`: check `staged_open_cred || staged_open` (or delegate to `brix_sd_staged_open_maybe_cred`) instead of only `staged_open`.
5. ucred.c file-level doc comment: update "phase-1" → "phase-1 + phase-2 (bearer)".
6. stage_engine.c: fix the `%ldds` log typo → `%lds`.

- [ ] Apply the 6 edits. Build -Werror clean. Phase-1 + P2-T1..T4 tests stay green (no behavior change). Commit — ask Rob.

### Task 6: root:// stream-side per-user origin credentials

**Files:** `src/protocols/root/stream/module.c` (register `brix_storage_credential_dir`/`_fallback` on the stream srv conf — fields already exist on `common`), the remote-backed root:// VFS ctx-build sites (`src/protocols/root/read/open_cache.c`/`read.c`/`stat.c`, `src/protocols/root/write/*.c`) — pass `ctx->identity` (not NULL) + call `brix_vfs_ctx_bind_backend_cred(&vctx, &conf->common.storage_credential_dir, conf->common.storage_credential_fallback)`. Test: `tests/run_user_backend_cred_root.sh`.

The stream srv conf embeds `common` (already carries the fields from Phase 1) — only the directive-table registration (stream context) is new, plus threading `ctx->identity` (populated at bind, src/protocols/root/session/bind.c) + the bind at the remote-backed data-plane ctx sites. Local-export probe sites that pass NULL identity stay NULL; binding is a no-op when the cred dir is unset, so binding unconditionally on remote-backed data-plane paths is safe.

- [ ] Test: run_user_backend_cred_root.sh — a GSI root:// upload through a remote-backed cache export → origin sees the CLIENT DN; deny + no cred → kXR_NotAuthorized, origin never sees a service-cred write for it. Register the 2 stream directives; thread identity + bind at the remote-backed root:// read/write/open/sync VFS sites. Build; test + Phase-1/P2 green. Commit — ask Rob.

### Task 7: sd_http per-user bearer + assess sd_s3 / sd_ceph

**Files:** `src/fs/backend/http/sd_http.c`/`.h` — `open_cred` presenting `cred->bearer` as the per-open `Authorization: Bearer` header instead of the static `cfg->bearer_token`; else fall back to static/none. Register the slot. `docs/10-reference/per-user-backend-credentials.md` — the sd_s3/sd_ceph assessment (per-user AK/SK `<key>.s3` and CephX `<key>.keyring` file formats + the per-open re-init point, gated on external per-user provisioning at the store — documented as ready-to-build, NOT stubbed). Test: extend a bearer-checking HTTP/cvmfs origin variant if riggable, else a focused assertion that sd_http open_cred selects cred->bearer over cfg->bearer_token + NOTE.

- [ ] Implement sd_http open_cred (reuses T2 .token selection end to end for HTTP); write the sd_s3/sd_ceph assessment. Build; test + Phase-1/P2 green. Commit — ask Rob.

### Task 8: Delegation capture — authenticated proxy-upload endpoint (opt-in)

**Files:** new `src/protocols/webdav/delegation.c`/`.h`, registered in `src/protocols/webdav/dispatch.c`, directive `brix_delegation_endpoint on|off` (webdav location), `./config` (+delegation.c). Test: `tests/run_delegation_upload.sh`.

When `brix_delegation_endpoint on`, a PUT/POST to a well-known path (e.g. `/.well-known/brix-delegation`) with body = the client's RFC-3820 proxy PEM: (1) require GSI-cert-authenticated request (reuse auth_cert); (2) validate the uploaded proxy (parse chain, notAfter in the future, the proxy's EEC/issuer DN matches the authenticated client DN — a client may only delegate ITS OWN identity); (3) derive the key via `brix_sd_ucred_key(principal)` and write the PEM atomically (temp+rename, 0600) to `<storage_credential_dir>/<key>.pem`. Phase-1 selection then uses it. 403 on DN mismatch, 400 on unparseable/expired, 507 on write failure, 404/405 when off. Documented as proxy-UPLOAD delegation (full GridSite getProxyReq/putProxy two-step = further extension).

- [ ] Test: GSI-auth'd A uploads its proxy → 201 + `<cred_dir>/<key>.pem` exists; a SUBSEQUENT davs PUT by A (cred dir otherwise empty) authenticates to the origin as A. Negative: A uploads B's proxy → 403; expired proxy → 400; endpoint off → 404/405. Implement, ./config, ./configure, build; test + Phase-1/P2 green. Commit — ask Rob.

### Task 9: S3 SigV4 → x509 proxy minting (opt-in)

**Files:** new `src/fs/backend/cred_mint.c`/`.h` (OpenSSL minting), directives `brix_storage_credential_mint_ca <cert> <key>` + `brix_storage_credential_mint_ttl <secs>` (shared preamble fields + merge), `src/fs/vfs/vfs_cred.c` (on ucred miss + mint CA configured → mint), `./config`. Test: `tests/c/test_cred_mint.c` + runner + S3 e2e.

When the gate's `brix_sd_ucred_select` DECLINES (no pre-provisioned cred) AND a mint CA is configured: mint a short-lived x509 proxy — keypair, subject encodes the principal (e.g. `/O=brix-minted/CN=<principal>`), signed by the mint CA, notAfter = now+ttl, PEM (cert+key+chain) atomically written 0600 to `<cred_dir>/<key>.pem`, then proceed as a normal user cred. The ORIGIN must trust the mint CA (documented prominently — trust shifts to the frontend's mint CA). OFF unless the mint CA is configured (then behavior = Phase-1). Cache on disk + re-mint within a refresh window of expiry.

- [ ] Test: mint for a principal with a throwaway CA → PEM parses, notAfter≈now+ttl, issuer==mint CA, subject encodes principal; second call within refresh reuses cache; expired cache re-mints. S3 e2e: mint CA trusted by origin, S3 PUT by an access key with no .pem mints one, origin authenticates it. Implement, ./config, ./configure, build; unit + e2e + Phase-1/P2 green. Commit — ask Rob.

### Task 10: Documentation refresh

**Files:** `docs/10-reference/per-user-backend-credentials.md`, README rows.

- [ ] Move now-closed limitations to "Supported"; document each new directive + defaults + the mint-CA trust warning + the delegation-upload flow + flush dead-letter + the metrics families (+ note flush-deny is ledger-observable); keep honest remaining edges (sd_s3/sd_ceph per-user, full GridSite two-step). Run the doc-link guard (git-add note at commit). Commit — ask Rob.
