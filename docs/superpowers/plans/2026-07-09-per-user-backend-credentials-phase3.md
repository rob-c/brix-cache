# Per-User Backend Credentials — Phase 3 (remaining follow-ups) Implementation Plan

> Continues Phase 1 (2026-07-08-*.md) + Phase 2 (2026-07-08-*-phase2.md), both COMPLETE + reviewed. Finishes the Phase-2 deferred follow-ups. Executed via superpowers:subagent-driven-development.

**Global Constraints (binding, unchanged):** NO goto; WHAT/WHY/HOW doc blocks; no new globals; borrowed pool pointers never in detached state (copy to char[]); unified directives in http_common.c + stream mirror; new .c → ./config + ./configure else make; -Werror; reject→EACCES→403/kXR_NotAuthorized; NO git writes without approval; concurrent sessions share tree+build (avoid io_uring/aio/handler.c/contrib); all prior tests stay green; SDD scratch under .superpowers/sdd/pubc/.

**Feasibility facts (from research):** sd_s3 builds UNCONDITIONALLY (per-open ak/sk already in sd_s3_file); **librados ABSENT here so sd_ceph driver body is #if-compiled-out → sd_ceph per-user code can't be build-verified → DESIGN-ONLY (T5)**; root:// dirlist has NO wire op (write kXR_dirlist from scratch); GridSite two-step has the crypto (brix_gsi_build_pxyreq/assemble_proxy) but needs a delegation-ID store + 2 REST endpoints.

---

### Task 1: Small closures bundle (mint wiring + LOCK 403 + forwarder hardening + cosmetics)

**Files:** `src/protocols/root/stream/module.c` + root:// data-plane ctx sites (mint bind), `src/protocols/webdav/lock.c` (cred-deny→403), `src/fs/backend/sd.h` (forwarder refuse), plus any remaining cosmetic minors from the Phase-1/2 ledgers.

1. **root:// stream minting wiring:** register `brix_storage_credential_mint_ca`/`_mint_ttl` on the stream srv conf (fields exist on `common` if Phase-2 added them there; else add) and call `brix_vfs_ctx_bind_backend_mint(&vctx, ...)` at the same root:// data-plane sites T6 added `brix_vfs_ctx_bind_backend_cred` (open/read/write/stat/mv/checksum). Mirror the davs/S3 mint bind exactly. No-op when mint CA unset.
2. **LOCK cred-deny → 403:** the cred gate returns EACCES BEFORE the setxattr when a no-cred user is denied in deny mode — map THAT to 403 in lock.c's LOCK-create path. Distinguish it from the intentional impersonation-setxattr-EACCES→500 (service can't write a user-owned file): the gate-deny happens at the ctx-bind/gate check (before the op); the impersonation EACCES happens during the op. Map the gate-deny EACCES→403; leave the mid-op setxattr EACCES→500 as-is. If they can't be cleanly distinguished at the callsite, document precisely and leave 500 (honest).
3. **Forwarder refuse-when-no-_cred-slot:** in the `brix_sd_*_maybe_cred` forwarders (sd.h), when `cred != NULL && cred->fallback_deny && driver-><op>_cred == NULL && driver-><op> != NULL` (i.e. a per-user op would silently fall to the service-cred plain slot in DENY mode), refuse: errno=EACCES, return the op's error value (NULL / NGX_ERROR / -1), + one WARN. Do NOT change allow-mode (fallback allowed) or the no-op cases (setattr==NULL = no mutable metadata = fine). This is defensive hardening — today inert (no driver has that shape) but prevents a future silent leak.
4. **Cosmetics:** sweep the Phase-1/2 ledger MINOR notes still open (ucred.c file comment already fixed T5; mkpath_leaf errno; any authmore-msg leftovers) — apply the trivial ones.

- [ ] Tests: extend run_user_backend_cred_root.sh — a root:// upload by an access-keyless GSI user with a mint CA configured → origin sees a minted DN (or NOTE if root:// mint e2e is heavy); a unit/assertion for the forwarder-refuse (a fake driver with cred+fallback_deny+no _cred slot → EACCES). LOCK 403: a deny-mode LOCK by a no-cred user → 403 (davs). Build -Werror clean; all prior tests green. Commit — ask Rob.

---

### Task 2: root:// origin dirlist (kXR_dirlist wire + sd_xroot opendir/readdir/closedir)

**Files:** `src/fs/cache/origin_ns.c` (+ cache_internal.h decl) — a `brix_cache_origin_dirlist(t, oc, path, cb/buffer)` implementing kXR_dirlist against the origin; `src/fs/backend/xroot/sd_xroot_ns.c` — opendir/readdir/closedir + opendir_cred slots backed by it; `src/fs/backend/xroot/sd_xroot.c` — register the slots + advertise CAP_DIRS; wire spec at `/tmp/brix-src/src/XProtocol/XProtocol.hh` for kXR_dirlist framing.

Implement kXR_dirlist (opcode + dlen framing; the origin returns a newline-separated name list, optionally with stat via kXR_dstat). sd_xroot opendir issues it once, buffers the names, readdir yields them one per call, closedir frees. The cred variant threads the per-user cred (T1's brix_vfs_ns_leaf already dispatches opendir_cred on the leaf) so a remote dirlist authenticates as the user. This closes the "root:// dirlist over remote xroot" gap.

- [ ] Tests: extend run_user_backend_cred_root.sh (or run_user_backend_cred_ns.sh) — `xrdfs ls` of a remote-backed export returns the origin's entries AND (with per-user cred) the origin logs the user's DN on the dirlist. Verify against a real origin (the GSI fleet). Build -Werror clean; all prior green. Commit — ask Rob.

---

### Task 3: sd_s3 per-user credentials (`<key>.s3` → per-open SigV4 re-init)

**Files:** `src/fs/backend/ucred.{h,c}` (select `<key>.s3` = a 3rd cred kind: ak/sk/region), `src/fs/backend/sd.h` (brix_sd_cred_t += the s3 creds, OR a generic "extra" — prefer explicit `const char *s3_ak; const char *s3_sk; const char *s3_region;`), `src/fs/vfs/vfs_cred.c` (gate fills them), `src/fs/backend/s3/sd_s3.{c,h}` + sd_s3_internal.h (an open path that takes override ak/sk/region), and the seam that connects a per-open cred to sd_s3 (the S3-backend instance's open_cred). Test: `tests/c/test_ucred.c` (+ the `.s3` parse) + `tests/c/run_ucred_tests.sh`.

`<key>.s3` file format (document): 3 lines `ak`, `sk`, `region` (or `key=value`), 0600. ucred_resolve tries `.pem` → `.token` → `.s3` (mutually exclusive; document precedence). The gate sets the s3 fields on the cred; the S3-backend `open_cred` (find where the S3 backend is instantiated as a driver — sd_s3 plugs in via injection per the research; the driver open_cred passes the override ak/sk/region to sd_s3_open_read/write). Build UNCONDITIONAL (no gate). E2e needs an S3 origin with per-user IAM keys — if not riggable, unit-test the `.s3` selection + a check that the override ak/sk reach the signer, and NOTE the e2e gap (the sd_s3 SigV4 path itself is already exercised elsewhere).

- [ ] Tests: test_ucred `.s3` cases (present→selected with ak/sk/region; precedence .pem>.token>.s3; malformed→declined). Build -Werror clean; all prior green. Commit — ask Rob.

---

### Task 4: GridSite two-step delegation (getProxyReq / putProxy REST)

**Files:** `src/protocols/webdav/delegation.c`/`.h` (extend the T8 upload endpoint), a delegation-ID keyed store (in-memory per-worker with TTL, or a small on-disk store keyed by delegation-id; SHM only if cross-worker needed — prefer a per-worker in-memory map with a TTL sweep, documented), `./config` if a new file. Uses `brix_gsi_build_pxyreq` (proxy_req.c) + `brix_gsi_assemble_proxy`.

Two REST steps (GridSite portType, adapted to plain HTTP):
- `GET /.well-known/brix-delegation` (or `?getreq`) by a GSI-cert client → server generates a fresh keypair + CSR (brix_gsi_build_pxyreq against… the client has no parent cert on the server side, so generate a CSR whose subject = the client DN + a proxyCertInfo; the client will sign it with its EEC), returns a delegation-id + the CSR (PEM). Store {id, fresh_key, client_dn, created_at, expires_at} keyed by id (per-worker, TTL e.g. 10 min).
- `PUT /.well-known/brix-delegation/<id>` + body = the client-signed proxy cert chain → look up id (must belong to THIS authenticated client DN — reject cross-client), assemble the full proxy with the stored fresh_key (brix_gsi_assemble_proxy), validate (notAfter, DN match), store at `<cred_dir>/<key>.pem` (same atomic write as T8), drop the id.
SECURITY: the delegation-id must be bound to the authenticated client DN at getreq time and re-checked at putProxy (a client can only complete its OWN delegation); the stored fresh private key never leaves the server; ids are unguessable (CSPRNG). The proxy-UPLOAD form (T8) stays as the simple path.

- [ ] Tests: `tests/run_delegation_twostep.sh` — GSI client GETs a CSR+id, signs it with its EEC key (openssl), PUTs it back → `<cred_dir>/<key>.pem` exists + a subsequent davs op authenticates as the client at the origin. Negative: client B trying to complete client A's id → 403; expired id → 410/404; unsigned/garbage → 400. Build -Werror clean; all prior green. Commit — ask Rob.

---

### Task 5: sd_ceph per-user DESIGN + documentation close-out

**Files:** `docs/10-reference/per-user-backend-credentials.md`.

- sd_ceph per-user: a COMPLETE DESIGN (not code — librados absent here, can't build/verify; needs per-user CephX at the cluster): a `<key>.keyring` file → the S3-style `.s3`/`.token` selection extended to `.keyring`; the sd_ceph open_cred would create a per-user `rados_t` context (librados binds the user at cluster init, so per-user requires a new context, not a per-open ioctx) cached per (user,keyring) with a bounded LRU; the trust/provisioning prerequisite (per-user CephX identities at the cluster). State clearly it is design-only + why (build-gated + infra-gated), so it's ready-to-build when a librados environment + per-user CephX exist.
- Refresh the reference doc to add: root:// dirlist now supported (T2), sd_s3 per-user (T3), GridSite two-step (T4), forwarder hardening (T1), LOCK 403 (T1), root:// minting (T1). Update the "remaining follow-ups" to the now-true set (sd_ceph per-user design-only; anything still deferred).

- [ ] Update doc; verify every claim vs source; run the doc-link guard (untracked-dead-link flags expected). Commit — ask Rob.

---

## Self-review
Covers all Phase-2 deferred follow-ups: root:// stream minting (T1), LOCK 403 (T1), forwarder hardening (T1), cosmetics (T1), root:// dirlist (T2), sd_s3 per-user (T3), GridSite 2-step (T4), sd_ceph per-user (T5 design — honestly deferred, infra+build-gated), docs (T5). Invariant preserved: every new origin-touch routes through the gate; deny before origin op; no wrong-identity. Feature-off safe: every new path gated on its directive/cred-file.
