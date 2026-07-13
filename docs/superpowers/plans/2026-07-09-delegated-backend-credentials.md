# Plan — Delegate the user's GSI credential to the storage backend

**Date:** 2026-07-09
**Status:** DRAFT (planning only — no code written)
**Author context:** follows the diagnosis in `backend_write_proxy_requirement` and the uncommitted
per-user-backend-credentials Phase 1/2 (`per-user-backend-credentials`).

**One-line goal:** authenticate brix's upstream `root://` storage-backend leg *as the requesting
user*, using an RFC-3820 proxy the client **delegates during the inbound GSI handshake**, with **no
static proxy in the config** — only a writable credential directory.

---

## 0. TL;DR for the impatient

- The full credential pipeline (per-user cred → `sd_xroot` origin login → async-flush re-resolve)
  **already exists** and is on disk (uncommitted). So does inbound GSI delegation capture
  (`ctx->gsi.deleg_proxy_pem`). They are **not connected**.
- The feature = **persist the captured delegated proxy into the credential directory the
  select+flush machinery already reads**, keyed by `brix_sd_ucred_key(DN)`.
- New surface is tiny: one persist hook + one refactor (make an existing atomic-write helper
  shared) + one enable directive + a fallback refinement + a reaper + tests + docs.
- **Scope: `root://` only** (in-handshake delegation is an XRootD-GSI feature; davs/S3 have no
  delegation channel and keep the existing upload-endpoint / select paths).
- **Biggest risk is external:** stock `xrdcp` does not delegate unless the user sets
  `XrdSecGSIDELEGPROXY=1`; a prior session recorded stock xrdcp *declining* to delegate to us.

---

## 1. Problem statement & the exact failure it fixes

### 1.1 Current behaviour
A `root://` upload that flushes to a remote `root://` origin authenticates the backend leg with a
**static service proxy** resolved from a `brix_credential { x509_proxy … }` block:

```
tier_build.c:104  tier_resolve_creds()  →  c->x509_proxy (static, from brix_credential)
tier_build.c:106  brix_sd_xroot_create_origin(host, port, tls, bearer, proxy, cadir, …)
```

The origin session logs in as brix's own identity, not the user. With **no** proxy configured and a
GSI-only origin, the backend leg fails:

```
origin_protocol.c:172-191   needs_auth && no credential  →  kXR_AuthFailed
sd_xroot.c:36 sd_xroot_errno()  kXR_AuthFailed → default → EIO
stage_engine.c:224-231       "dest staged_open failed (xroot …) (5: Input/output error)"
```

(the exact symptom already observed on xrd1: file stuck in `/data/brix/staging`, deferred flush
`record kept`.)

### 1.2 Desired behaviour
The backend leg authenticates **as the user**, using the proxy the user delegated in the inbound
login. No `brix_credential`/`x509_proxy` in config. The origin's own authdb then applies per-user
policy natively, and backend logs/quota attribute the write to the real DN.

---

## 2. The storage-credential pipeline as it exists today

This is the machinery the feature reuses. Every row below is **already implemented** (Phase 1/2,
uncommitted but present on disk).

| Stage | Function / type | File:anchor |
|---|---|---|
| Identity extracted at GSI auth | `ctx->login.dn` set from `verify_res.dn_buf` | `src/auth/gsi/auth.c:345` |
| Bind cred dir + fallback onto request VFS ctx | `brix_vfs_ctx_bind_backend_cred(vctx, cred_dir, fallback_deny)` | `src/fs/vfs/vfs_cred.c:61` |
| Data-plane gate (open/staged_open) | `brix_vfs_backend_cred(ctx, store, cred, …)` → `vfs_backend_cred_decide()` | `src/fs/vfs/vfs_cred.c:119,231` |
| Principal → filename-key | `brix_sd_ucred_key(principal, key, cap)` (`x5h-`+SHA256 for DNs) | `src/fs/backend/ucred.h:108` |
| Select cred file by identity | `brix_sd_ucred_select(dir, id, out)` → `<dir>/<key>.pem` / `.token` | `src/fs/backend/ucred.h:156` |
| Re-resolve cred by exact key (flush) | `brix_sd_ucred_resolve(dir, key, out)` | `src/fs/backend/ucred.h:131` |
| Per-open cred descriptor (5+ fields) | `brix_sd_cred_t {x509_proxy,bearer,key,principal,cred_dir,fallback_deny}` | `src/fs/backend/sd.h:152` |
| Driver cred slots | `open_cred` / `staged_open_cred` vtable slots | `src/fs/backend/sd.h:394,397` |
| `sd_xroot` consumes cred | copies `cred->x509_proxy`/`bearer`/`principal` into `brix_cache_fill_t.cred_*` | `src/fs/backend/xroot/sd_xroot.c:100-112` |
| Origin login uses per-open cred | `brix_cache_origin_bootstrap` → gsi/ztn with `t->cred_*` | `src/fs/cache/origin_protocol.c:172-191` |
| Async-flush owner persisted | `brix_stage_cred_t` (reflush cred) in the stage journal record | `src/fs/backend/stage/sd_stage.h:34,61-65` |
| Atomic proxy write `<dir>/<key>.pem` | `delegation_store_pem(log, dir, key, pem, len)` — **static, webdav-only** | `src/protocols/webdav/delegation.c:182` |
| Config: cred dir / fallback (root:// stream) | `brix_storage_credential_dir`, `brix_storage_credential_fallback` | `src/protocols/root/stream/module.c:180,190` |
| Config: cred dir / fallback (HTTP) | same names, owned once | `src/core/config/http_common.c:112` |

### 2.1 Inbound delegation capture (also already implemented, root:// only)

| Step | Function | File:anchor |
|---|---|---|
| Enable + start delegation round after verified cert | gated `conf->tpc_delegate`; `brix_gsi_begin_delegation()` sends `kXGS_pxyreq` | `src/auth/gsi/auth.c:374-383` |
| Client returns `kXGC_sigpxy`; capture | `brix_gsi_handle_sigpxy()` → assembles proxy PEM incl. **private key + client chain** | `src/auth/gsi/auth.c:260-267`, `src/auth/gsi/delegation.c:294` |
| Stored blob | `ctx->gsi.deleg_proxy_pem` / `deleg_proxy_len` | `src/core/types/ctx_structs.h:127`; set at `delegation.c:393-395` |
| Freed on disconnect/reset | `brix_gsi_delegation_cleanup()` | `src/auth/gsi/delegation.c:132-135` |

**Consumers today:** TPC engine (`src/tpc/engine/launch.c:528`) and the tap-proxy
(`src/net/proxy/gsi_upstream_login.c:195`). **Never** the VFS/`sd_xroot` storage path.

---

## 3. The exact gap

`ctx->gsi.deleg_proxy_pem` is an **in-memory** blob that lives for the session and is freed on
disconnect. The storage-credential path sources proxies from a **directory** (`ucred_select`). The
two never meet:

```
      DELEGATION CAPTURE                          STORAGE CRED PIPELINE
  ┌───────────────────────┐                  ┌──────────────────────────────┐
  │ handle_sigpxy()        │                 │ ucred_select(dir, id)          │
  │  → deleg_proxy_pem (RAM)│   ← NO LINK →   │  → <dir>/<key>.pem             │
  │  freed on disconnect    │                 │ open_cred → sd_xroot → origin  │
  └───────────────────────┘                  │ flush: resolve(dir,key)        │
                                              └──────────────────────────────┘
```

The design closes it by making **capture a writer into `<dir>`**, so the pipeline picks the proxy up
with zero new plumbing:

```
  handle_sigpxy() → deleg_proxy_pem ──[persist]──▶ <cred_dir>/<key>.pem ──▶ ucred_select / resolve
                                       key = brix_sd_ucred_key(ctx->login.dn)
```

Why a file and not thread the RAM blob straight through: the **deferred/async flush** runs after the
session (and its RAM blob) is gone — possibly after a worker crash and restart. Only a durable,
key-addressable on-disk credential survives that. This is the exact reason the disk-backed select
model exists; delegation reuses it rather than inventing a parallel in-memory path.

---

## 4. Design

### 4.1 Chosen approach (A): persist delegated proxy into the credential directory
On a successful `root://` delegation capture, atomically write `ctx->gsi.deleg_proxy_pem` to
`<storage_credential_dir>/<key>.pem` where `key = brix_sd_ucred_key(ctx->login.dn)`. Everything
downstream (immediate open, deferred flush, expiry) then works unchanged.

**Config outcome:** no `brix_credential`/`x509_proxy`. Required config is
`brix_storage_credential_dir <writable-dir>;` + an enable flag + client-side delegation opt-in.

### 4.2 Rejected approaches
- **(B) In-memory-only** — add a PEM-blob field to `brix_sd_cred_t` and thread `deleg_proxy_pem`
  straight to `sd_xroot`. Avoids disk, but **cannot serve deferred/async flush or survive restart**
  (blob dies with the worker). Viable *only* for `brix_stage_flush sync` on the same worker.
  Keep as an optional fast-path later; not the primary design.
- **(C) Bespoke per-session credential pool** — most code, duplicates the seam that already exists.
  Rejected.

### 4.3 Key-agreement invariant (CRITICAL correctness constraint)
The persist side derives the key from `ctx->login.dn`; the consume side derives it from the request
VFS ctx `identity` via `brix_sd_ucred_select()` (which calls `brix_sd_ucred_principal()` → prefers
`id->dn`). **Both must derive from the byte-identical, identically-normalised DN string.** If the
root:// data-plane identity's DN differs from `ctx->login.dn` (different normalisation, VOMS suffix,
etc.), the key won't match and the just-delegated proxy won't be found.

**Requirement:** the persist hook MUST use the same principal→key derivation the consume side uses.
Implement the persist hook to call `brix_sd_ucred_principal(id)` + `brix_sd_ucred_key(principal)` on
the **same `brix_identity_t`** that the data plane binds to the VFS ctx — not a hand-copied DN. Add a
unit test asserting `key(persist) == key(select)` for a representative DN (see T7).

### 4.4 Lifecycle & timing (sequence)
```
1. Client GSI login (root://), delegation enabled both ends
2. auth.c: verify chain → ctx->login.dn set (auth.c:345)
3. auth.c:374 begin_delegation → kXGS_pxyreq
4. client → kXGC_sigpxy → handle_sigpxy → deleg_proxy_pem  (auth.c:260-267)
5. [NEW] persist: write <cred_dir>/<key>.pem (before complete_auth)   ◀── the one new seam
6. complete_auth → session authenticated
7. kXR_open(write) → staged_open_cred → sd_stage buffers on stage store,
   journal records brix_stage_cred_t{key,cred_dir}
8. close → flush:
     sync    → stage_engine_move now; resolve(cred_dir,key) → user proxy → origin login AS USER
     deferred→ later worker/after-restart: resolve(cred_dir,key) → same
9. disconnect → brix_gsi_delegation_cleanup frees RAM blob
     ⚠ the ON-DISK <key>.pem MUST persist (a deferred flush after disconnect needs it)
10. reaper (NEW, T5) unlinks the on-disk proxy after it expires
```

**Invariant:** disconnect frees RAM but must **not** unlink the file. Cleanup is expiry-driven (T5).

---

## 5. Work items (file-by-file)

### T1 — Extract the atomic proxy-store into a shared helper
**Why:** `delegation_store_pem()` is `static` in the webdav plane (`delegation.c:182`); the new
root:// capture path must write byte-identical files.

**Changes:**
- New file `src/fs/backend/cred_store.{c,h}`:
  ```c
  /* Atomic <dir>/<key>.pem writer: O_CREAT|O_EXCL|O_NOFOLLOW 0600 temp → write →
   * fsync → rename. Returns NGX_OK / NGX_ERROR. Shared by the davs upload endpoint
   * and the root:// delegation-capture persist hook. */
  ngx_int_t brix_cred_store_pem(ngx_log_t *log, const ngx_str_t *dir,
                                  const char *key, const u_char *pem, size_t len);
  ```
  Body = a verbatim move of `delegation_store_pem` (keep the `vfs-seam-allow` markers, the
  `O_NOFOLLOW`, the pid-suffixed temp name). Keep the existing tmp scheme
  `.<key>.pem.upload.<pid>` (single-threaded event loop → pid unique enough; cross-worker collisions
  differ by pid and the final `rename` is atomic).
- `src/protocols/webdav/delegation.c`: delete the static function, `#include
  "fs/backend/cred_store.h"`, call `brix_cred_store_pem(...)` at the current call site (`:338`).
- **`./config`:** add `src/fs/backend/cred_store.c` to `ngx_module_srcs` and `cred_store.h` to the
  header dep list. (New `.c` ⇒ requires `./configure` + full build, per BUILD GOVERNANCE.)
- No behaviour change to the davs endpoint (regression-guarded by existing
  `tests/run_delegation_upload.sh`).

### T2 — Persist the delegated proxy at capture (the one real new seam)
**Where:** single choke point in the GSI completion so it runs for the delegation path only.
Preferred insertion: at the end of `brix_gsi_handle_sigpxy` success handling, **or** in
`brix_gsi_complete_auth` guarded on `ctx->gsi.deleg_proxy_pem != NULL`. Do NOT put it inline at
`auth.c:266` twice — use one helper.

**New helper** (in `src/auth/gsi/delegation.c`, declared in `delegation.h`):
```c
/* Persist a captured delegated proxy into the storage credential directory so
 * the per-user backend-credential select/flush path can authenticate the origin
 * leg AS THE USER. No-op when the feature is off or no proxy was captured.
 * Best-effort: a write failure is logged and does NOT fail the login (the op
 * will later fall back / deny per policy). */
void brix_gsi_persist_delegated_cred(brix_ctx_t *ctx,
        ngx_stream_brix_srv_conf_t *conf);
```
**Body:**
1. Guard: return if `!conf->storage_cred_delegate` (T3) **or** `conf->storage_credential_dir.len==0`
   **or** `ctx->gsi.deleg_proxy_pem == NULL`.
2. Build the identity/principal exactly as the data plane will (see §4.3). Simplest correct form:
   derive principal from the **same** `brix_identity_t` the root:// data plane binds; if that struct
   isn't in hand here, construct it from `ctx->login` the identical way T6 does and assert equality
   in a unit test.
3. `char key[BRIX_UCRED_KEY_MAX]; brix_sd_ucred_key(principal, key, sizeof key);`
4. `brix_cred_store_pem(c->log, &conf->storage_credential_dir, key,
        ctx->gsi.deleg_proxy_pem, ctx->gsi.deleg_proxy_len);`
5. Drop a `.deleg` sidecar marker for the reaper (T5): `brix_cred_store_marker(dir, key)` writing an
   empty `<dir>/<key>.pem.deleg` (so the reaper never touches admin-provisioned files).
6. Log one line: `brix: stored delegated proxy for backend, dn="…", key=…, len=…`.

**Call site:** `brix_gsi_complete_auth()` (invoked from both `auth.c:266` and `auth.c:386`), so a
future non-delegated completion path never persists.

### T3 — Enablement directive & validation
**New directive** (recommended over overloading `brix_tpc_delegate`, whose name implies TPC):
- Name: `brix_storage_credential_delegate on|off` (default off).
- root:// stream table `src/protocols/root/stream/module.c` (beside `:180-210`), field on the stream
  srv conf (`src/core/config/config.h`, `NGX_CONF_UNSET`), merged in the stream `merge_*_conf`.
- **Capture gating change (required):** the capture at `auth.c:374` currently runs only when
  `conf->tpc_delegate`. Widen to:
  ```c
  if ((conf->tpc_delegate || conf->storage_cred_delegate)
      && !ctx->gsi.deleg_await && ctx->gsi.sess_keylen > 0) { … begin_delegation … }
  ```
  so enabling backend delegation triggers the handshake round without also enabling TPC.
- **Postconfig validation** (root:// postconfig): if `storage_cred_delegate` is on, require
  `storage_credential_dir` set and writable (do an `access(dir, W_OK)` probe and WARN/fail-fast,
  mirroring the audit-log-sink diagnostics recently added). If a static `brix_credential` proxy is
  *also* configured, log that delegation takes precedence for delegating clients and the static
  proxy is the read-fallback (per T4).
- HTTP plane: **do not** add delegate-capture (no channel). If someone sets the flag on an HTTP
  server, warn that davs/S3 have no in-handshake delegation and to use `brix_delegation_endpoint`.

### T4 — Fallback policy: strict-for-writes, fallback-for-reads
(Per the design decision.) Today `vfs_backend_cred_decide` uses one boolean `storage_cred_deny`.
Reads without a delegated proxy must still work (service/anon); writes must require the user proxy.

**Changes:**
- Extend the directive value set: `brix_storage_credential_fallback allow|deny|read-only`
  (`read-only` = fallback permitted for reads, denied for writes). Parse in the setter; store a
  tri-state enum on the conf.
- Thread an **op intent** into the gate. `brix_vfs_backend_cred` is called at open sites that already
  know read vs write; add an `int is_write` param (or reuse the existing SD open flags —
  `BRIX_SD_O_READ`/write — already available at those sites). Effective deny:
  ```
  deny_effective = (mode == deny) || (mode == read-only && is_write)
  ```
- The deny branch in `vfs_backend_cred_decide:155-` already returns `EACCES`; only the predicate
  changes. `EACCES` maps root:// → `kXR_NotAuthorized` and HTTP → 403 via the existing errno tables.
- Default remains `allow` (backward-compatible with the current single-boolean behaviour).

### T5 — Reaper for on-disk delegated proxies
**Why:** delegated proxies are ephemeral (bounded by the parent-proxy lifetime) and accumulate.
`ucred_select`/`resolve` already **skip** expired `.pem`, so this is hygiene, not correctness.

**Changes:**
- Per-worker hourly timer, modelled on the cache dirty reaper (`src/fs/cache/cache_reap.c` + the
  hourly per-worker timer pattern; see `unified_cache_state_engine` memory).
- Walk `<storage_credential_dir>`; for each `<key>.pem` that **has a `.deleg` sidecar marker** and is
  past `notAfter`, `unlink()` both the `.pem` and the marker. **Files without a marker (admin/upload
  provisioned) are never touched.**
- New directive `brix_storage_credential_reap_interval <time>` (default 1h); `0` disables.
- Guard against reaping a file currently mid-flush: expiry already gates *use*, and an expired proxy
  is never selected, so unlinking it cannot break an in-flight authorised flush (which resolved the
  file before it expired and holds an open origin session). Document this reasoning.

### T6 — (verify, likely no-op) root:// data-plane cred binding
Phase-2 T6 already wired root:// stream cred binding at read/write + `mv`. **Verify** the root://
data plane calls `brix_vfs_ctx_bind_backend_cred(vctx, &conf->storage_credential_dir,
fallback_deny)` and sets the ctx `identity` from `ctx->login` **using the same DN** the persist hook
uses (§4.3). If any data-plane site is unbound, bind it. No new design — just close any gap the key-
agreement invariant exposes.

### T7 — Tests (success + error + security, per project rule)
New `tests/run_delegated_backend_cred.sh` (model on `tests/run_credential_xroot_gsi.sh` +
`tests/run_root_stage_writeback.sh`), two-node origin O (GSI-required) + node B (delegate on, cred
dir set, **no static proxy**):
- **success/sync:** client with delegation enabled uploads via B `brix_stage_flush sync` → object on
  O **owned by the user DN** (assert via O access log / file owner), with no `brix_credential` in B.
- **success/deferred + restart:** `brix_stage_flush deferred`; kill+restart B worker before flush;
  assert flush still authenticates as the user (journal `key` re-resolved from the dir).
- **fallback read:** client **without** delegation → GET still served (service/anon); with
  `fallback read-only`.
- **strict write:** client without delegation + `fallback read-only` → write denied
  `kXR_NotAuthorized`/403; no bytes on O.
- **expiry + reaper:** short-lived delegated proxy → after expiry, select skips it and the reaper
  unlinks it; an admin-provisioned `.pem` (no marker) survives the reaper.
- **security:** stored file is `0600`; the `.pem` key derives from the **authenticated** DN; a DN
  whose delegated proxy names a different identity is impossible here (delegation is signed by the
  client's own proxy — note this is stronger than the upload endpoint's DN-match check).
- **C unit:** `key(persist)` == `key(select)` for a DN and for a token sub (the §4.3 invariant).

**Client delegation opt-in for the test:** run `xrdcp` with `XrdSecGSIDELEGPROXY=1` (or the client
that is known to delegate). If the bundled client cannot delegate, the success cases are `xfail` with
a clear skip reason — mirror the pre-existing delegation-capture test blocker.

### T8 — Docs
- Extend `docs/10-reference/per-user-backend-credentials.md` with a "Delegated source" section:
  the root://-only boundary, the `brix_storage_credential_delegate on;` +
  `brix_storage_credential_dir …;` recipe, client `XrdSecGSIDELEGPROXY=1`, fallback semantics, the
  reaper, and the private-key-on-disk security notes.
- Update `CLAUDE.md` OP→FILE only if new files warrant it (cred_store.c).
- Add a troubleshooting row to `docs/05-operations/troubleshooting-runbook.md`: "backend flush
  EIO/`kXR_AuthFailed` with delegation on" → check (a) client actually delegated
  (`XRD_LOGLEVEL=Debug` shows `dlgpxy`), (b) `<cred_dir>/<key>.pem` exists after login, (c) dir
  writable, (d) key-agreement (persist vs select DN).

---

## 6. Config grammar

### 6.1 Before (static service proxy)
```nginx
stream { server {
    listen 0.0.0.0:1095; brix_root on; brix_export /data/brix/export;
    brix_auth gsi; brix_allow_write on;
    brix_storage_backend root://origin.example:1094;
    brix_stage on; brix_stage_store posix:/data/brix/staging; brix_stage_flush deferred;

    brix_credential svc { x509_proxy /etc/grid-security/brix/backend-proxy.pem;
                          ca_dir /etc/grid-security/certificates; }
    brix_storage_credential svc;               # ← static service identity
} }
```

### 6.2 After (delegated user identity, no static proxy)
```nginx
stream { server {
    listen 0.0.0.0:1095; brix_root on; brix_export /data/brix/export;
    brix_auth gsi; brix_allow_write on;
    brix_storage_backend root://origin.example:1094;
    brix_stage on; brix_stage_store posix:/data/brix/staging; brix_stage_flush deferred;

    brix_storage_credential_delegate on;                       # NEW (T3)
    brix_storage_credential_dir      /var/lib/brix/deleg-creds; # writable, 0700, svc-owned
    brix_storage_credential_fallback read-only;                # NEW value (T4)
    # brix_storage_credential_reap_interval 1h;                # NEW (T5), default 1h
} }
```
Client side (per user / per pilot): `export XrdSecGSIDELEGPROXY=1` before `xrdcp`.

---

## 7. Fallback policy matrix (T4)

| Session has delegated proxy? | Op | `fallback allow` | `fallback read-only` | `fallback deny` |
|---|---|---|---|---|
| yes | read  | user proxy | user proxy | user proxy |
| yes | write | user proxy | user proxy | user proxy |
| no  | read  | service/anon | service/anon | **403/NotAuth** |
| no  | write | service/anon | **403/NotAuth** | **403/NotAuth** |

Recommended production setting: `read-only` (reads survive non-delegating clients; writes are always
user-attributed or refused). Default (unset): `allow` (backward-compatible).

---

## 8. Security analysis

- **Private key on disk.** `<cred_dir>/<key>.pem` contains the delegated proxy's private key (same as
  an admin-provisioned proxy). Mitigations: `0600` file / `0700` service-owned dir off any export
  root (already a `vfs-seam-allow` config dir, never reachable via the VFS); never log contents;
  prompt reaping (T5); short parent-proxy lifetimes bound exposure.
- **Key must be the authenticated DN.** Derive from `ctx->login.dn` set *after* `verify_chain`
  (`auth.c:299,345`), never from any wire-supplied name. `brix_sd_ucred_key`'s traversal guard
  already rejects leading `.`/`-`; DNs always hash to `x5h-…` so `/` never escapes the dir.
- **No CA minting, no replay.** The proxy is signed by the client's own credential during delegation;
  brix never fabricates identity. Conformance-clean (standard RFC-3820 delegation — the XrdPss/FTS
  mechanism).
- **Cross-user isolation.** One principal ↔ one key (SHA-256 stem); the select path only ever reads
  the file for the requesting identity's own key.
- **Concurrency.** Two sessions for the same DN both write `<key>.pem`; atomic `rename` ⇒ last valid
  proxy wins, both are valid for that identity. A flush reading during a rename sees a complete file
  either way.

---

## 9. Behaviour / failure matrix

| Condition | Result |
|---|---|
| Delegation on, client delegates, GSI origin | Backend login AS USER; write attributed to DN ✅ |
| Delegation on, client refuses to delegate | No `<key>.pem`; per §7 (read fallback / write deny) |
| Delegation on, `cred_dir` unset/unwritable | Postconfig WARN/fail (T3); if missed at runtime, persist logs error, op falls back/deny |
| Deferred flush after disconnect | Re-resolve from dir; login AS USER (file persisted) ✅ |
| Deferred flush after worker crash + restart | Same — journal key + on-disk file survive ✅ |
| Delegated proxy expired before flush | select/resolve DECLINED → per §7; reaper later unlinks |
| davs/S3 server with delegate flag on | WARN (no channel); use upload endpoint / select |
| Persist write fails (ENOSPC etc.) | Best-effort: login still succeeds; op later falls back/deny; error logged |

---

## 10. Operational runbook (for T8 docs)

- **Provision the dir:** `install -d -m 0700 -o nginx -g nginx /var/lib/brix/deleg-creds`.
- **Client must delegate:** users/pilots `export XrdSecGSIDELEGPROXY=1` (WMS/DIRAC/FTS already do).
- **Verify a login delegated:** `XRD_LOGLEVEL=Debug xrdcp …` shows the proxy-request round; after
  login `<cred_dir>/<key>.pem` should appear.
- **Origin authdb:** the delegated DN must have write on the origin export, else the flush next fails
  `EACCES` (a *different* error from the current `kXR_AuthFailed`).
- **Troubleshoot “still EIO”:** (1) did the client delegate? (2) does `<key>.pem` exist? (3) is the
  dir writable? (4) key-agreement (persist DN vs select DN, §4.3)?

---

## 11. Rollout / backward-compat

- All new directives default OFF / `allow` ⇒ zero behaviour change for existing deployments.
- The capture-gating change (`tpc_delegate || storage_cred_delegate`) is additive; `tpc_delegate`
  alone behaves exactly as before.
- T1 is a pure refactor guarded by the existing upload-endpoint test.
- Feature is independently switchable per server block; a static `brix_credential` may coexist as the
  read-fallback.

---

## 12. Open questions / risks (ranked)

1. **[external, high]** Will the target clients delegate? Stock `xrdcp` declined to delegate to our
   server in a prior session. **Must** be re-validated e2e against a delegating client before sign-off.
   If unresolved, the feature only benefits FTS/WMS-style writers; ad-hoc writers need the fallback
   or the upload endpoint.
2. **[correctness, med]** Key-agreement (§4.3). De-risk with the C unit test in T7 before wiring.
3. **[scope, low]** davs/S3 remain non-delegating by protocol; confirm that's acceptable (the upload
   endpoint already covers them).
4. **[policy, low]** Should `read-only` be the shipped default instead of `allow`? Leaning `allow`
   for compat, documenting `read-only` as the recommended production value.

---

## 13. Effort & sequencing

```
T1 refactor (cred_store)         ─┐  (needs ./configure + full build)
T3 directive + capture-gating    ─┤─ land together, build once
T2 persist hook                  ─┘
T4 fallback tri-state            ── independent, small
T6 verify/close data-plane bind  ── verification pass
T5 reaper                        ── independent
T7 tests                         ── after T1–T4
T8 docs                          ── last
```
Rough size: T2 ~40 LOC, T1 ~60 LOC move, T3 ~50 LOC, T4 ~40 LOC, T5 ~90 LOC, T7 ~1 script + 1 C unit,
T8 docs. The heavy lifting was already done by Phase 1/2.

---

## 14. Summary

~90% of the mechanism exists. The feature is **one persist seam** (`deleg_proxy_pem` →
`<cred_dir>/<key>.pem` at capture) plus small supporting work (shared store helper, enable directive,
fallback refinement, reaper, tests, docs). It needs **no config-defined proxy** — only a writable
credential directory — is conformance-clean and `root://`-scoped, and inherits deferred-flush and
crash-restart survival for free by reusing the disk-backed select machinery. The dominant risk is
external: client-side delegation opt-in.
```
