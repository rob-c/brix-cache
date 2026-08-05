# Credential delegation through BriX — the 2×2 matrix (credential × transport)

**2026-08-05.** Consolidated, origin-log-verified proof that a BriX gateway running as
unix user **bob**, placed in front of an **official XRootD** server, delegates the *end
user* **alice**'s credential to the origin — so the origin authenticates every op as
**alice**, never as bob — across both credential mechanisms and both transports.

Companions: `gsi-delegation-xrdhttp-fullmatrix.md` (x509/https detail),
`gsi-delegation-gsi-crl-revocation-conformance.md`, and the reusable rigs under
`brixbench/` (see each cell). All four cells were exercised live; the evidence below is
grepped straight from the **official XRootD origin's own log**.

## The matrix

| | **root://** | **https://** |
|---|---|---|
| **x509 GSI proxy** | ✅ PASS — full data+metadata matrix | ✅ PASS — full data+metadata matrix |
| **WLCG bearer token** | ✅ data + read-metadata delegate as alice (15/17); mkdir/locate not delegated | ✅ PASS — full data+metadata matrix (incl. mkdir/rename/delete, gap closed 2026-08-05) |

The delegated-identity evidence phrase differs by origin subsystem but always names **alice**:
- **GSI (both transports):** the XRootD auth log line `login as alice`.
- **Token / root:// (ZTN):** the SciTokens plugin maps the forwarded token subject to the
  login name, so it is *also* `login as alice`.
- **Token / https (XrdHttp+SciTokens):** `scitokens_Access: ... subject=alice`.

In every cell the negative control flips the origin's identity (bob's credential → the origin
sees **bob**; no credential → anonymous/denied), proving the identity is driven by the
*forwarded end-user credential*, not a fixed BriX service credential.

---

## Cell 1 — x509 GSI proxy over root:// — PASS

Rig: `brixbench/gsi_deleg_alice_bob.sh` (official xrootd GSI origin `:21197`, BriX GSI tap
proxy as bob `:21198`). Mode: per-user proxy delegation (BriX captures alice's delegated
proxy and re-presents it on the back leg).

Full client command matrix, all delegated: **DATA** — write/read small, write/read large
(byte-exact), vector read; **METADATA** — stat, exists, listdir, mkdir, rename, truncate,
chmod, checksum, locate, statvfs, query, rm, rmdir.

Origin log: **18 `login as alice`, 0 `login as bob`**. Negative control (delegation OFF): the
op is refused (rc 53) and the origin does **not** authenticate as alice.

## Cell 2 — x509 GSI proxy over https:// (XrdHttp) — PASS

Rig: `brixbench/gsi_xrdhttp_deleg/` (official XrdHttp+GSI origin `:21210`, BriX per-user
reverse-proxy delegation front as bob `:21212`, `$brix_delegated_cred` →
`proxy_ssl_certificate`).

Full client matrix through the delegation front — curl (MKCOL/PUT/GET/HEAD/PROPFIND 0&1/
range/Want-Digest/MOVE/DELETE), PyXRootD 11/11, XRootD.jl 9/9, go-hep 9/9.

Origin login delta through the front: **alice +44, bob +0, nobody +0**. Negative control
(remove the stored delegated proxy + reload): **alice +0, nobody +1** — restore → alice
again. (The Finding-1 fix — `ssl_session_tickets/cache off` — is what lets the resumption-heavy
XRootD.jl client delegate here; see `gsi-delegation-xrdhttp-fullmatrix.md`.)

## Cell 3 — WLCG bearer token over root:// (ZTN) — PASS

Rig: `brixbench/token_deleg/root_ztn/deleg_token_driver.py` (imports the proven
`cmdscripts/fwd_matrix_live.py` `ForwardHarness` for the OIDC/JWKS/CA-trust plumbing). Origin:
stock xrootd `sec.protocol ztn` + `ofs.authlib libXrdAccSciTokens-5.so`. Front: BriX root://
as bob with `brix_auth token` + `brix_credential origin_ca { ca_dir …; }` +
`brix_backend_delegation passthrough` (forwards the client's validated bearer verbatim).

Client = bundled `client/bin/xrdcp`+`xrdfs` presenting alice's token over ztn. **15/17** ops:
put/get small+large (byte-exact), stat, ls, mv, cksum, statvfs, query, truncate, rm, rmdir.

Origin log (`token_deleg/root_ztn/origin_login_evidence.log`): **22 `login as alice`, 3
`login as bob` (negative control), 0 service/nobody/anon**. Presenting **bob's** token flips
the origin to `login as bob`; presenting **no** token is denied at the front (rc 53, zero new
origin logins).

Two non-delegation gaps (BriX authenticated alice on both; neither is a forwarding failure):
- `mkdir` (rc 54) — remote whole-object backend directory-create returns io_error.
- `xrdfs locate` (rc 54) — the bundled client's auxiliary `locate` connection carries no
  token (client-side quirk), so it is inconclusive, not a forwarding defect.

## Cell 4 — WLCG bearer token over https:// (XrdHttp+SciTokens) — PASS

Rig: `brixbench/token_deleg/https_bearer/`. This path was previously unprovisioned; the origin
was built from scratch. **Enabling discovery:** stock `libXrdHttp-5.so` (v5.9.6) does not parse
`Authorization: Bearer` itself — the origin needs **`http.header2cgi Authorization authz`** so
XrdHttp hands the header to `libXrdAccSciTokens` (which strips `Bearer%20`). Without it every
token yields `login as nobody`.

- **Direct-to-origin baseline (GREEN):** alice GET → 200 with `scitokens_Access: … subject=
  alice`; no-token → 403; wrong-issuer → 403 ("not in list of allowed issuers").
- **Through BriX (read/metadata — PASS):** BriX front (`brix_webdav_auth required` + token
  jwks/issuer/audience, `brix_storage_backend https://…`, `brix_backend_delegation
  passthrough`) validates alice then forwards her JWT **verbatim** (confirmed byte-for-byte with
  a logging HTTPS sink). Origin log (`https_bearer/logs/origin_subject_evidence.log`): **7
  `subject=alice`** across GET / HEAD / range GET / Want-Digest / PROPFIND-Depth:0, **2
  `subject=bob`** (negative control), and no-token / wrong-issuer rejected at the front.
- **Write-back (FIXED 2026-08-05):** previously the commit PUT reached the origin **anonymous**
  → `login as nobody` + `Unable to create …; permission denied` → BriX 500, because the
  staged-commit write-back identity struct `brix_stage_cred_t` (`src/fs/xfer/stage_engine.h`)
  was x509-cred-store-only (`key`/`principal`/`dir`, resolved to a proxy **PEM** via
  `brix_sd_ucred_resolve()`) with **no bearer field**, and the whole staged-write path *gated
  the credential on the store key* — a keyless passthrough bearer was silently demoted to the
  service credential. **Fix (source):** (1) added an in-memory-only `bearer` slot to
  `brix_stage_cred_t` — NEVER persisted to the durable journal (a live secret, expired by
  replay time): the journal writers persist only `BRIX_SREQ_IDENTITY_SIZE` (identity prefix,
  stopping before the bearer) and `brix_sreq_decode` always force-zeroes it; (2)
  `stage_engine_run` presents a live bearer directly to the destination `staged_open_cred`
  (no store re-resolve — a bearer has no cred file), sync inline path only; (3)
  `sd_stage_record_cred` copies the bearer and the whole flush now gates on
  `sd_stage_cred_present()` = **key OR bearer**, so a keyless passthrough bearer
  (`brix_vfs_deleg_bearer`) is threaded to the backend PUT. The HTTP backend driver already
  consumed `cred->bearer` (`sd_http_staged_open_cred`, `src/fs/backend/http/sd_http_write.c`).
  **Live-verified:** alice PUT → **HTTP 201**, origin authorizes `operation=create` with
  `subject=alice` and the object lands (92 B, read back 200); bob control → `subject=bob`
  (evidence: `https_bearer/logs/writeback_fix_evidence.log`). Read/stat/metadata legs
  unaffected. **Async (tape) write-back note:** a bearer is intentionally not journaled, so a
  *deferred* token flush still falls back to key/dir resolution — token write-back is delegated
  on the inline (default whole-object gateway) path. Unit tests: `stage_bearer_thread`,
  `sreq_compat` (C-regression suite).

---

## Task-F full-surface re-verification (2026-08-05, fixed binary)

Both token cells were re-run end-to-end with the write-back-fixed binary
(`/tmp/xrdhttp-deleg/nginx-build/objs/nginx`), driving the whole client data+metadata
surface and grepping the **official origin's own log** per op. The delegated-vs-not split is
**identical on both transports** and is a property of which BriX backend legs carry the
forwarded token, not of the origin (a *direct*-to-origin control with the same alice token
does mkdir/rename/delete fine — 201/201/200 — so the origin fully supports them for alice).

- **root:// (ZTN):** 16/17 delegated as alice — **`login as alice`**, bob → `login as bob`
  (neg), 0 service (`root_ztn/origin_login_evidence_taskF.log`). `mkdir` **GAP CLOSED 2026-08-05**
  (was rc54 io_error; see below). Residual: `xrdfs locate` (client-side aux connection carries no
  token).
- **https:// (Bearer):** the full **data** surface (create/write-back incl. 32 MiB, GET,
  large GET, range GET) and the **read-side metadata** surface (HEAD/PROPFIND-d0 stat,
  PROPFIND-d1 listdir, Want-Digest checksum) all show `subject=alice` at the origin; bob → 
  `subject=bob`, no-token/wrong-issuer rejected at the front (401). Evidence:
  `https_bearer/logs/full_matrix_verify.log`.

### Task-F2 clean-room full-surface re-run (2026-08-05, all fixes in binary)

Re-ran BOTH cells with a per-op origin-log classifier and a fresh per-run namespace
(`verify_full_matrix.sh` under each rig dir). With the two 2026-08-05 root:// fixes below in
the binary, both transports are now **100% clean and deterministic across repeated runs**:

- **root:// (ZTN) — 15/15 PASS.** `mkdir · stat(dir/file) · ls · statvfs · upload · download ·
  cat · cksum · truncate · mv · rm · rmdir` every one **`login as alice`** (0 bob/nobody/service);
  negatives `bob:mkdir`/`bob:upload` → **`login as bob`**. Deterministic over 3 consecutive runs.
  Evidence: `root_ztn/logs/FINAL_root_matrix.log`.
- **https:// (Bearer) — 16/16 PASS.** `MKCOL · PUT · PUT-large · GET · GET-large · GET-range ·
  HEAD · PROPFIND-d0 · PROPFIND-d1 · Want-Digest · MOVE · DELETE(file/big/coll)` every one
  origin `subject=alice`; negatives `bob:MKCOL`/`bob:PUT` → `subject=bob`; no-token → 401,
  wrong-issuer → 401. Evidence: `https_bearer/logs/FINAL_https_matrix.log`.

**Two root:// source fixes this session made the previously-failing ops delegate:**
1. **`sd_xroot_mkdir_cred`** — closed the root:// `mkdir` io_error (rc54); see the root:// mkdir
   section below. (Missing `*_cred` slot → anonymous service session → ZTN login never happened.)
2. **`op_path.c` WRITE existence-gate skip for non-POSIX backends** — closed root:// `mv`, which
   had failed at the front with `invalid destination path (NotFound)` **before ever contacting the
   origin**. Root cause (SAME missing-credential-on-a-namespace-leg class): `mv`'s destination
   pre-check ran `op_path_existence_gate` in WRITE mode, which probes the dest **parent** via
   `op_path_probe` → `brix_vfs_probe` on a ctx with **no per-user credential bound**. On the
   delegated ZTN gateway that anonymous parent-stat is rejected by the auth-required origin →
   `NGX_DECLINED` → the front refuses a perfectly valid destination. The EXISTING-mode branch
   already **skipped** its probe for non-POSIX backends ("the driver is the single existence
   check"); the fix applies the identical skip to the WRITE branch, so the dest-parent validation
   is delegated to the backend rename (which runs as alice). POSIX exports are unchanged — the
   early-return is inside the `brix_vfs_backend_resolve(...) != NULL` guard. Verified: `mv` now
   rc0 with origin **`login as alice`** (2 conns); pathres C-unit still green.

**Known non-delegation residual (https bob write path):** the `bob:PUT`/`bob:MKCOL` negative
control is intermittently 500/403 with `subj:{none}` — a **front-side** failure that never reaches
the origin: `brix_webdav: async staged commit failed … (13: Permission denied)`. Even with
`brix_stage off` the WebDAV PUT can occasionally take the **async staged-commit** path, which fails
on a local staging-dir EACCES (worker-uid/ownership) — the write-back-determinism artifact tracked
in [[token-https-writeback-fix]]. Critically this is **never a delegation leak**: bob never appears
as `subject=alice`, and any write that does reach the origin carries the correct subject. The alice
surface (the deliverable) is 100% clean.

**https namespace/removal ops — GAP CLOSED 2026-08-05.** Previously `MKCOL`/mkdir, `MOVE`/rename
and gateway-object `DELETE` reached the origin **unauthenticated** (`ofs_mkdir`/`ofs_rename …
unknown.NN … permission denied`, no SciTokens `Grant`). Root cause: the HTTP storage driver
(`src/fs/backend/http/`) implemented only the *plain* (tokenless) `.mkdir`/`.rename`/`.unlink`
vtable slots — no `*_cred` variants — so `brix_sd_<op>_maybe_cred` fell back to the plain,
service-credential op even though the VFS gate (`brix_vfs_ns_cred`) had fully resolved the
forwarded bearer into `cred->bearer`. **Fix (source):** added `sd_http_mkdir_cred` /
`sd_http_rename_cred` / `sd_http_unlink_cred` (each a thin wrapper over a shared `_common` that
also backs the plain slot), presenting the user's bearer as the `Authorization` header (folded
into the MOVE `Destination` block too) or the x509 proxy as the mutual-TLS client cert — the same
`sd_http_cred_gate` + `sd_http_resolve_open_cred` the read/stat/staged-write legs use — and wired
the three `_cred` slots into the driver vtable. The MOVE header block was enlarged to hold a
forwarded JWT (`SD_HTTP_PATH_MAX + SD_HTTP_AUTH_MAX`) so a large token never truncates to a
spurious `ENAMETOOLONG`. **Live-verified:** MKCOL 201 / MOVE 201 / DELETE 204, origin authorizes
`operation=mkdir`/`mv`/`del` with `subject=alice` (zero `unknown`), bob control → `subject=bob`.
Unit test `sd_http_mutate` (C-regression suite) gained 3 cred cases: bearer/x509 threaded onto the
MKCOL/MOVE/DELETE wire; origin-denied forwarded cred → EACCES (never masked); proxy-only + deny +
no-mutual-TLS transport → EACCES with zero wire ops (no silent service-credential fallback).

**root:// mkdir `io_error` (rc54) — GAP CLOSED 2026-08-05 (same root cause class as https).** The
xroot driver had `stat_cred`/`unlink_cred`/`rename_cred` but **no `mkdir_cred`** slot, so a per-user
mkdir dispatched through `brix_sd_mkdir_maybe_cred` fell back to the *plain* `sd_xroot_mkdir`, which
opens the origin session with `sd_xroot_session(is->conf, NULL, …)` — the **anonymous / service**
session. Against the ZTN + SciTokens origin (CA-only credential, no service token) that session
cannot authenticate: the origin logged the connection upgrading to TLS then closing **with no
`login`** (`disc 0:00:00`), so `origin_request`'s `brix_cache_read_response` failed and
`brix_cache_origin_mkdir` returned `EIO` → front `op:mkdir status:io_error` → client rc54. It read as
an "io_error" rather than an `unknown`/`permission denied` precisely because the anonymous session
never even logged in — the same *missing-`*_cred`-slot → service-credential fallback* bug class as
the https namespace ops, just surfacing at the ZTN login step instead of at SciTokens authz. **Fix
(source):** added `sd_xroot_mkdir_cred` (`sd_xroot_ns_cred.c`) — the per-user variant of
`sd_xroot_mkdir` that opens the session under the caller's credential
(`sd_xroot_session(is->conf, cred, …)` → the forwarded alice proxy/bearer) and delegates the
`brix_cache_origin_mkdir` body verbatim, parity with `unlink_cred`/`rename_cred` — declared it in
`sd_xroot_internal.h` and wired `.mkdir_cred` into the driver vtable (`sd_xroot.c`). **Live-verified:**
`xrdfs mkdir` → rc0, directory created on the origin (stat 4096), origin logs **`login as alice`**;
bob negative control → **`login as bob`**; rmdir cleanup rc0. Evidence:
`root_ztn/mkdir_cred_fix_evidence.log`. **Unit test** `sd_mkdir_cred_forward` (C-regression suite)
pins the dispatch contract that makes the slot reachable: cred + slot → the cred slot (exact cred
threaded); NULL / allow-mode-missing-slot → plain slot; `fallback_deny` + no `mkdir_cred` slot →
`EACCES` with the plain service mkdir **never** called (no silent service-credential leak).
Residual: `xrdfs locate` uses a tokenless client-side aux connection — not an https-style gap.

**Write-back path determinism:** the Task-E bearer threading is on the **inline (sync)** commit
only. With the default write-staging tier a whole-object PUT can take the **async** staged path,
which by design never journals the bearer → the deferred commit falls back to the service
identity (`origin:unknown` → 500). Setting `brix_stage off` (or otherwise forcing the inline
commit) makes token write-back **deterministically** delegate as alice (verified 5/5, HTTP 201,
read-back as alice). This matches the "async (tape) write-back note" above.

**Bearer NUL-termination (root cause of the "intermittent bob-write 500/403" flake — FIXED
2026-08-05).** The earlier "intermittent async-staged-commit EACCES even with `brix_stage off`"
symptom was **misdiagnosed** as an async-path bearer-drop / local-staging `EACCES`. The real cause
was a **NUL-termination over-read on the sync inline path**: `brix_vfs_deleg_bearer`
(`src/fs/vfs/vfs_deleg.c`) materialised `cred->bearer` (a bare `const char *` that the sd_http /
sd_stage presenters format with `"Authorization: Bearer %s"`) by **borrowing** the captured bag
bearer's `.data` — but that bag bearer is a length-counted `ngx_str_t` allocated with **no trailing
NUL** (WebDAV `auth_token.c` `wt_check_claims` copies exactly `token_len` bytes). So `"%s"` read
**past** the token into adjacent `r->pool` bytes until a stray NUL, intermittently (pool-layout
dependent, worsening under concurrency) appending garbage → a malformed JWT the origin rejected
with 403 → surfaced front-side as `EACCES`/500. It was **never** a delegation *leak* (bob never
appeared as alice — the corrupted token simply failed origin authz → `unknown`/anonymous), but it
was a delegation *drop* causing spurious write failures. **Fix:** copy the captured bytes into a
NUL-terminated pool buffer at that single materialisation chokepoint (protocol-agnostic — covers
https, `root://`, and s3 passthrough, all of which funnel through `brix_vfs_deleg_bearer`).
**Verified:** 320/320 concurrent PUTs clean (was ~15% fail), https matrix 16/16 ×3, `root://`
15/15, bob negative control passing. **Regression test:** `deleg_gate_test.c` cases 18–19 back the
bag bearer with a buffer whose bytes **after** the captured length are non-zero (0xFF / stale
`'Z'` filler, no NUL) and assert `strlen(cred.bearer) == bearer.len` + exact `memcmp` — these FAIL
against the borrow-the-pointer code (`strlen` runs into the filler) and PASS with the copy.

---

## Reproduce

- Cell 1: `brixbench/gsi_deleg_alice_bob.sh`
- Cell 2: bring up `brixbench/gsi_xrdhttp_deleg/` (README), run the drivers through `:21212`
- Cell 3: `cd tests && PYTHONPATH=. python3 brixbench/token_deleg/root_ztn/deleg_token_driver.py /tmp/xrdhttp-deleg/nginx-build/objs/nginx` (`KEEP=1` leaves the rig up)
- Cell 4: configs under `brixbench/token_deleg/https_bearer/` (note `http.header2cgi Authorization authz`); `logging_https_sink.py` proves verbatim bearer forwarding

Captured origin-log evidence is stored alongside each rig under `brixbench/token_deleg/`.
