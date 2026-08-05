# Phase 91 — `gsiftp://` Storage Backend (Outbound GridFTP Gateway + Full Auth Matrix)

**Date:** 2026-07-28
**Status:** PLAN — the *storage driver* is not yet implemented. The two pure
kernels this plan calls for, `gftp_reply.c` (reply parser, incl. 227/229 address
extraction) and `gftp_mlsx.c` (MLSx fact-line parser), were landed early and sat
unwired; as of 2026-08-05 they are compiled into `libbrix.a` and consumed by the
**client-side** GridFTP engine (`client/lib/protocols/ftp/`, `xrdcp gsiftp://` —
see [native-client-tools.md](../04-protocols/native-client-tools.md) and
`tests/test_xrdcp_gsiftp.py`). The client is an *initiator*, not the outbound
`brix_sd_gsiftp` storage driver described below; that driver is still unwritten,
but its parsing layer now has a production consumer and live coverage.
**Depends on:** Phase 55 (storage-driver seam `brix_sd_*`), Phase 70 (full credential
delegation), Phase 82 (inbound GridFTP gateway — supplies reusable protocol/crypto
kernels), Phase 60/80 (`sd_remote`/S3 outbound-origin template), the unified VFS
(`src/fs/`).

> **One-line goal.** Add a new **outbound** storage-driver — `src/fs/backend/gsiftp/` —
> so any BriX export can be backed by an *existing remote GridFTP / gsiftp server*
> (dCache, DPM/StoRM, Globus GridFTP, XRootD-gsiftp), authenticating to it with **every**
> credential the WLCG GridFTP ecosystem uses: GSI X.509 proxies (with VOMS), delegated
> per-user proxies, plain EEC certs, Kerberos-5/GSSAPI, mutual-TLS client certs,
> username/password, and anonymous. Nothing above the storage seam changes — a gsiftp
> origin looks like any other backend to protocol handlers, cache, metrics, and TPC.

---

## 0. Reader contract / terminology

This phase reuses the Phase-55 vocabulary (Protocol handler / VFS / Storage Driver /
SD instance / Backend store / Logical path / Physical locator). Two additions:

| Term | Meaning |
|---|---|
| **gsiftp origin** | one configured remote GridFTP server (`gsiftp://host:2811/path`) bound to an export as its backend (and/or cache/stage) store |
| **control channel** | the RFC 959 + RFC 2228 FTP command connection (default TCP/2811), on which auth (`AUTH`/`ADAT`) and namespace/transfer commands are issued |
| **data channel** | the separate connection(s) the server nominates via `PASV`/`EPSV`, over which file bytes flow — MODE E (extended block) or MODE S (stream), optionally GSI/TLS-wrapped per `PROT` |

**Direction reminder.** Phase 82 is the *inbound* gateway: BriX **accepts** gsiftp
clients. Phase 91 is the *outbound* mirror: BriX **is** a gsiftp client dialling a
remote server. The FTP reply *parser* and the client-role (initiator/delegator) GSI
handshake are the genuinely new protocol code; the framing, crypto, and credential
plumbing already exist (§6).

---

## 1. Problem statement

WLCG sites still run GridFTP as the interoperability data-transfer protocol for a large
installed base (dCache, DPM, StoRM, EOS-gsiftp, Globus Connect). BriX can already *serve*
gsiftp (Phase 82) and can back an export with POSIX, S3, Ceph/RADOS, `root://`, and HTTP
origins (Phase 55/60/80). It cannot yet treat a **remote gsiftp endpoint** as a storage
backend — so BriX cannot front-end an existing GridFTP store to re-export it over XRootD,
WebDAV, S3, or HTTP, nor stage/cold-tier through one.

The gap is narrow and well-bounded: a new SD driver plus a client-role GridFTP protocol
adapter. The storage-seam, cache, tiering, TPC, metrics, and — critically — the entire
per-user credential acquisition/delegation/materialisation stack are already in place and
load-validated. This plan builds the adapter on top of them.

---

## 2. Architecture decision — SD driver, blocking-in-threadpool

Three shapes were considered; the driver model wins decisively.

| Option | Verdict |
|---|---|
| **(A) VFS SD driver, blocking sockets on the cache-fill worker thread** | **CHOSEN.** Matches `sd_remote` (S3) and the native `root://` outbound (`src/tpc/outbound/` + `src/fs/backend/xroot/`). The `brix_vfs_*` seam is defined in `pread/pwrite/opendir` terms; GridFTP maps onto those cleanly. All blocking I/O stays off the nginx event loop (Invariant: driver never touches nginx runtime — `sd_remote.h:22-27`). |
| (B) nginx event-loop client on the Phase-82 ev engine | Rejected for v1. The ev engine (`src/protocols/gridftp/ev/`) is a *server* content handler; an event-driven client would fight the SD seam's synchronous `pread` contract and duplicate the threadpool the cache layer already provides. Its outbound-connect and TLS-client primitives are still *reused* (§5). |
| (C) shell out to `globus-url-copy` | Rejected. No per-op `pread`, no confinement, process-spawn per op, opaque failure modes. |

**Placement.** `src/fs/backend/gsiftp/` — kind **ORIGIN** in the census (`fs_list.h`),
exactly like `xroot`. ORIGIN drivers are *not* name-registry drivers: the driver struct is
`static const` and instantiated by a bespoke `brix_sd_gsiftp_create(cfg, log)` factory
returning a **malloc-owned** instance (copy `sd_remote.c:366-393` / `sd_xroot.c:378-415`),
**never** routed through `brix_sd_instance_create`.

**Seam.** Everything under `src/fs/backend/gsiftp/` is auto-exempt from all three tiers of
`tools/ci/check_vfs_seam.py` (allow-regexes already cover `^src/fs/backend/`) — no guard
edits. All raw socket/GridFTP syscalls stay inside that directory; anything above goes
through `brix_vfs_*`.

---

## 3. File layout (new)

```
src/fs/backend/gsiftp/
  sd_gsiftp.c            driver struct + caps + brix_sd_gsiftp_create/destroy factory
  sd_gsiftp.h            brix_sd_gsiftp_cfg_t (host/port/path/tls/mode/auth/timeouts)
  sd_gsiftp_io.c         open/close/pread/preadv/fstat  → RETR / ERET / REST+stream
  sd_gsiftp_ns.c         stat/unlink/mkdir/rename/opendir/readdir → MLST/DELE/RMD/RNFR-RNTO/MLSD
  sd_gsiftp_ns_cred.c    the *_cred namespace slots (per-user proxy)
  sd_gsiftp_staged.c     staged_open/write/commit/abort → STOR/ESTO to temp + RNFR-RNTO promote
  gftp_session.c         control-channel session: connect, reply parser, command sender, FSM
  gftp_reply.c           FTP reply parser (3-digit + multiline "-" continuation; 227/229 addr)
  gftp_auth.c            client-role AUTH/ADAT dispatcher → GSI | krb5 | TLS | USER/PASS | anon
  gftp_auth_gsi.c        client-role GSI GSSAPI initiator + delegator (SSL_set_connect_state)
  gftp_data.c            data-channel: PASV/EPSV parse, connect-out, PBSZ/PROT/DCAU, MODE E/S
  gftp_mlsx.c            MLSD/MLST fact-line parser → brix_sd_stat_t / brix_sd_dirent_t
  README.md             module map + seam note (house convention)
```

Split rationale: one concern per file, each < 600 lines (repo cap). `gftp_session.c`
owns the blocking control loop; `gftp_data.c` owns byte movement; `gftp_auth*.c` owns the
handshake; the `sd_gsiftp_*.c` files are thin adapters mapping the SD vtable onto the
session.

---

## 4. The SD driver surface

Model the vtable on `sd_remote` (read-mostly gateway) with `sd_xroot`'s namespace ops.

**Driver struct** (`sd_gsiftp.c`, mirror `sd_remote.c:338-364`):

```c
static const brix_sd_driver_t brix_sd_gsiftp_driver = {
    .name        = "gsiftp",
    .caps        = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_DIRS
                 | BRIX_SD_CAP_HARD_RENAME | BRIX_SD_CAP_APPEND,   /* narrowed in init per server FEAT */
    .cred_accept = BRIX_SD_CRED_X509 | BRIX_SD_CRED_BEARER,       /* proxy / (future) macaroon */
    .init = ..., .cleanup = ...,
    .open = gsiftp_open, .close = gsiftp_close,
    .pread = gsiftp_pread, .preadv = gsiftp_preadv, .fstat = gsiftp_fstat,
    .stat = gsiftp_stat, .unlink = gsiftp_unlink, .mkdir = gsiftp_mkdir,
    .rename = gsiftp_rename,
    .opendir = gsiftp_opendir, .readdir = gsiftp_readdir, .closedir = gsiftp_closedir,
    .staged_open = gsiftp_staged_open, .staged_write = gsiftp_staged_write,
    .staged_commit = gsiftp_staged_commit, .staged_abort = gsiftp_staged_abort,
    .open_cred = gsiftp_open_cred, .staged_open_cred = gsiftp_staged_open_cred,
    /* *_cred namespace slots for per-user proxy (sd.h:444-478) */
};
```

**Caps** (`brix_sd_cap_t`, `sd.h:82-111`): `RANGE_READ` (ERET/REST offset reads), `DIRS`
+ `DIRS_WRITE` (MLSD/MKD/RMD), `HARD_RENAME` (RNFR/RNTO promote), `APPEND` (APPE). **No**
`FD`/`SENDFILE` — bytes are memory-served like `sd_remote` (`fd=NGX_INVALID_FILE`,
`heap_shell=1`, `sd_remote.c:104-164`). `SERVER_COPY` only if a same-origin third-party
`SPAS`/`SPOR` fast-path is added later (deferred, §11). Actual caps are **narrowed at
`init`** by probing the server `FEAT` reply (e.g. drop `RANGE_READ` if no `REST STREAM`/
`ESTO`), the same widen/narrow pattern as `brix_sd_instance_create` (`sd_registry.c:141`).

**VFS op → GridFTP command mapping:**

| SD vtable op | GridFTP realisation |
|---|---|
| `open` (read) | `SIZE` (or `MLST`) for length → build memory-served obj |
| `pread(off,len)` | `ERET P <off> <len>` if advertised; else `REST <off>` + `RETR` + read `len` in MODE S; MODE E offset-addressed blocks otherwise |
| `preadv` | coalesce adjacent ranges into one `ERET`/`REST+RETR`, scatter into a bounce buffer (mirror `sd_remote.c:262-326`) |
| `fstat` | return the open snapshot (`sd_remote.c:328-333`) |
| `stat` | `MLST <path>` → parse facts (`gftp_mlsx.c`); fall back to `SIZE`+`MDTM` |
| `opendir`/`readdir`/`closedir` | `MLSD <path>` on a data channel → parse fact-lines into `brix_sd_dirent_t` |
| `staged_open`/`write` | `STOR`/`ESTO` to a temp key on the data channel (MODE E framer) |
| `staged_commit` | `RNFR <temp>` + `RNTO <final>` (atomic promote); if cross-dir unsupported, `STOR` direct + fsync semantics |
| `staged_abort` | `DELE <temp>` |
| `unlink`/`mkdir`/`rename` | `DELE` / `MKD` / `RNFR`+`RNTO` |

---

## 5. GridFTP client protocol engine (new + reused)

### 5.1 Control channel — `gftp_session.c`

Blocking session on a threadpool worker: `connect()` (SSRF-screened via
`src/core/compat/net_target.h`) → read `220` greeting → auth (§7) → `TYPE I` → `MODE E`
(or `S`) → `PBSZ`/`PROT`/`DCAU`. A half-duplex send-command/parse-reply loop; one session
is bound per `brix_sd_obj` (or pooled per origin+identity, §8).

**Reply parser — `gftp_reply.c` (NEW; nothing parses replies today).** RFC 959 §4.2:
3-digit code, space (final) or `-` (continuation) after the code; multiline replies end at
`^ddd ` matching the opener. Extract host:port from `227 (h1,h2,h3,h4,p1,p2)` and
`229 (|||port|)`. GSS-wrapped replies (`6yz` after auth) are unwrapped first (§7).

**Command sender:** thin `gftp_send(sess, "RETR %s", path)` writing a CRLF line, GSS-wrapped
when the control channel is protected.

### 5.2 Data channel — `gftp_data.c`

- **Passive-mode connect-out.** BriX is the client → always drive `EPSV`/`PASV` (never
  `PORT`, to avoid inbound firewall/NAT issues), parse the nominated address, and dial it.
  Reuse the non-blocking connect primitive `brix_ftp_ev_data_open` active branch
  (`ftp_ev_data.c:415-468`) or a blocking `connect()`+`poll()` (`tpc/outbound/connect.c`)
  per the threadpool model.
- **Data-channel security.** `PBSZ 0` + `PROT P` (private) is the WLCG norm. Present the
  same credential on the data channel via the already-bidirectional
  `brix_ftp_dc_load_deleg` / `brix_ftp_dc_apply_policy` / `brix_ftp_dc_gsi_check`
  (`src/protocols/gridftp/ftp_dc_sec.c:30/113/166`) — these already run in the connect
  role for the Phase-82 gsiftp↔gsiftp TPC leg. TLS-client bring-up reuses
  `brix_ftp_ev_tls_begin(..., tls_client=1, ...)` (`ftp_ev_tls.c:69`).
- **MODE E codec — reuse verbatim.** `src/protocols/gridftp/ftp_eblock.h` is a pure,
  header-only 17-byte block pack/unpack (`ftp_eb_pack:41`/`ftp_eb_unpack:51`) with an
  overlap guard (`ftp_eb_range_overlaps:69`) and EOF/EOD flags (`:37-38`).
  - **RETR (pull):** reassemble out-of-order blocks — reuse the receive logic from
    `ftp_ev_mode_e_recv.c` (`ev_eb_reserve_range:242`, contiguity check
    `ev_eb_ranges_contiguous:153`, EOF/EOD accounting), re-pointing the sink from the
    inbound `brix_vfs_writer` to the driver's pread/cache buffer.
  - **STOR (push):** frame blocks with `ev_retr_mode_e_write` (`ftp_ev_mode_e.c:58`) +
    `ftp_eb_pack`; trailing `FTP_EB_EOF|FTP_EB_EOD` carries the EOD-count in the OFFSET
    field (a known Phase-82 gotcha, `:99`).
- **MODE S (stream)** fallback for servers without MODE E: `REST <off>` then `RETR`;
  partial read = read `len` bytes and abort/`ABOR` the rest, or read to EOF for whole-file.

### 5.3 Namespace listing — `gftp_mlsx.c` (NEW parser)

The Phase-82 engine only *emits* MLSD/MLST (`ev_list_fill:206`); a client must reverse the
fact grammar (`type=;size=;modify=;perm=;unix.mode=;`) into `brix_sd_stat_t` (`sd.h:189-199`)
and `brix_sd_dirent_t` (`sd.h:207-210`). The emitter documents the exact grammar to invert.

---

## 6. Authentication — the full matrix

GridFTP auth is RFC 2228 layered on FTP: `AUTH <mech>` → base64 `ADAT` token exchange →
optional `USER`/`PASS`. `gftp_auth.c` selects the mechanism from config/credential mode and
drives the handshake; every path reuses existing crypto and the Phase-70 credential
pipeline. **The credential *acquisition* is done — the new work is the RFC-2228 wire
adapter per mechanism.**

| # | Method | GridFTP realisation | Reused infra (file:line) | New work |
|---|---|---|---|---|
| 1 | **GSI X.509 proxy** (static or per-user) | `AUTH GSSAPI` + ADAT, GSI mechanism over OpenSSL mem-BIO TLS | proxy load `origin_auth_gsi.c:45/90/268`; chain verify `gsi_verify.h brix_gsi_verify_chain`; bytes→0600 `gsi_upstream.c:18` | client-role **initiator** (`SSL_set_connect_state`) mem-BIO pump — the mirror of the acceptor `gsi_mech.c:347-397` |
| 2 | **Delegated per-user proxy** (Phase-70 passthrough) — *primary* per-user path | as #1, presenting the materialised user proxy | full pipeline: `brix_vfs_deleg_bind` (`vfs_deleg_bind.c:189`), `brix_vfs_deleg_live_cred` (`vfs_deleg.c:546`), carrier `cache_internal.h:131-138`, mode enum `sd_cred_types.h:87` | `gsiftp_open_cred` reads `brix_sd_cred_t.x509_proxy` and runs #1 with it |
| 3 | **VOMS-extended proxy** | as #1/#2 — the VOMS AC is embedded in the forwarded proxy and rides for free | `voms/extract.c` (verify side); AC travels in the proxy PEM | none for outbound (AC presented in-band); optional client-side VO assertion logging |
| 4 | **Plain X.509 EEC** (no proxy) | as #1 with an end-entity cert+key | `cred_mint.c` (`brix_cred_mint`, EC P-256) or a configured cert path | reuse #1 loader with a non-proxy leaf |
| 5 | **Kerberos-5 / GSSAPI** | `AUTH GSSAPI` + ADAT, **krb5 mechanism** (`gss_init_sec_context`) | `krb5/forward.c` `brix_krb5_deleg_to_origin:138` (forwardable TGT `gss_init_sec_context`), `brix_gss_import_service:84`; gate `BRIX_HAVE_KRB5` | route ADAT tokens through the krb5 GSS context instead of the hand-rolled GSI one; needs a forwardable ticket delegated at the front door |
| 6 | **Mutual-TLS** (`AUTH TLS` / gsiftp-over-TLS, RFC 4217) | `AUTH TLS` → control channel TLS with a **client cert** | outbound SSL_CTX template `tpc/outbound/tls.c:35-60`; TLS-client handshake `ftp_ev_tls.c:69` | add `SSL_CTX_use_certificate_chain_file`/`use_PrivateKey_file` on the outbound CTX (no brix CTX loads a client cert today) |
| 7 | **Username / password** | `USER <u>` / `PASS <p>` (ideally under `AUTH TLS`) | config-plumbing `vfs_backend_config.c:63-105` | **static backend credential only** — inbound passwords are PBKDF2-only (`pwd/auth.c`), never retained, so *not* per-user forwardable (documented limit, not a TODO) |
| 8 | **Anonymous** | `USER anonymous` / `PASS <email>` | `vfs_cred.c` service/fallback decision (`:190/:228`) | map "no per-user cred + not deny-mode" → anonymous login |
| 9 | **SSH-transport GridFTP** (globus `gridftp` over SSH) | dial via SSH subsystem instead of TCP/2811 | — | **deferred** (§11); listed for completeness — requires an SSH client transport BriX does not have |

**DCAU/PBSZ/PROT** apply across #1–#6: default `DCAU A` (GSI self-auth on the data
channel) with `PROT P`; `DCAU N` + `PROT C` when the server or config requests cleartext
data (still SSRF/DN-pinned on the control channel).

**Selection precedence** (in `gftp_auth.c`, highest first): explicit per-origin
`brix_backend_*` directive → delegated live-bag cred (Phase-70) → per-user store lookup
(`brix_sd_ucred_select`, `ucred.c:317`) → minted proxy (`cred_mint.c`) → static configured
origin credential → anonymous (only if `brix_backend_anon on`). `fallback_deny` (Phase-70
`vfs_cred.c:197`) short-circuits to `EACCES→403` with **no** service-cred fallback when the
export is per-user-only.

---

## 7. Credential selection & delegation (reuse, no new infra)

The gsiftp driver is a pure *consumer* of `brix_sd_cred_t` (`sd_cred_types.h:87-117`):

```
front door captures identity + raw cred (GSI full-proxy / bearer / krb5)
  └─ brix_vfs_ctx_bind_backend_cred | *_bind_backend_deleg   (vfs_cred.c:62 / vfs_deleg_bind.c:40)
       └─ VFS gate resolves MODE → brix_sd_cred_t             (vfs_cred.c decide body)
            └─ gsiftp_open_cred(inst, path, flags, &cred)     (NEW — the only new consumer)
                 └─ gftp_auth.c picks mechanism from cred.mode + cred.x509_proxy/principal/bearer
```

MODE values (`brix_cred_mode`, `sd_cred_types.h:87`): `SELECT` (store lookup),
`PASSTHROUGH`/`EXCHANGE` (delegated live-bag), `MINT`, `DENY`. The gsiftp driver honours all
of them via the existing gate; it adds only the mechanism dispatch. Proxy bytes reach the
driver as a **0600 temp path** already (materialiser `vfs_deleg.c:372-422`, cleanup
unlink+zero `:47-82`), so the driver never handles raw key bytes — it hands the path to the
GSI initiator.

---

## 8. Connection pooling & lifecycle

GridFTP control-channel + GSSAPI setup is expensive (TLS + ADAT round-trips + proxy verify).
A per-op reconnect would be pathological. Pool **per (origin, identity-DN, auth-mode)**:

- Keyed cache of idle authenticated sessions (bounded, LRU, idle-timeout `NOOP` keepalive),
  mirroring the `sd_ceph` per-user cred-conn cache (`sd_ceph_cred.c`) and the S3 injected
  transport (`sd_remote` `cfg->transport`).
- Identity in the key is mandatory — never reuse user A's authenticated session for user B
  (the same fail-closed principle as Phase-70). Anonymous/static-cred sessions share one key.
- Sessions live in the driver's malloc pool (off the nginx event loop); closed on
  cleanup/idle. Data channels are per-transfer, never pooled.

---

## 9. Configuration

Follow the S3/xroot directive model exactly.

- **URL directive:** `brix_storage_backend gsiftp://host[:2811]/path?opts` (also usable as
  `brix_cache_store` / `brix_stage_store` / cold tier).
- **Config-time parser:** add `vfs_parse_gsiftp_origin` to the `NGX_DECLINED`-chain in
  `brix_vfs_backend_config_str` (`vfs_backend_config.c:107-146`), modelled on
  `vfs_parse_s3_origin` (`vfs_backend_config_s3.c:184-221`); entry-writer sets
  `e->backend="gsiftp"`, `origin_host/port/tls/path` (mirror `brix_vfs_backend_config_xroot`
  `:72-89`).
- **Credentials:** reuse `brix_vfs_backend_set_credential` (`vfs_backend_config.c:63-105`) —
  GSI maps onto `origin_x509_proxy` / `origin_x509_key` / `origin_ca_dir`; per-user
  delegation via the existing `brix_backend_delegation`/`brix_backend_token_*`/
  `brix_backend_krb5_forwardable` directives (`http_common.c:275-342`, `root/stream/module.c:219-230`).
- **Query opts:** `mode=e|s`, `prot=p|c`, `dcau=a|n`, `auth=gsi|krb5|tls|userpass|anon`,
  `streams=<n>` (future striping), `blocksize=<bytes>`, `ipv=4|6|auto`, `tcp_bufsize=`.
- **Resolve-time factory:** add `brix_vbr_build_gsiftp` (fills `brix_sd_gsiftp_cfg_t` from
  `e->origin_*`, calls `brix_sd_gsiftp_create`) + a `{"gsiftp", brix_vbr_build_gsiftp}` row in
  `brix_vbr_source_table` (`vfs_backend_registry_source.c:351-359`), modelling
  `brix_vbr_build_s3` (`:264-303`).
- **Tier stores:** add `S("gsiftp","gsiftp",…)` to `BRIX_FS_SCHEME_LIST` (`fs_list.h:99-112`)
  and a `tier_build_gsiftp` branch in `tier_build.c:317-336`.

---

## 10. Build wiring (`./config`, repo root)

- **Sources:** add `src/fs/backend/gsiftp/sd_gsiftp*.c` + `gftp_*.c` next to the
  s3/remote/xroot block (`./config:867-883`); add the new config-parse file if split
  (siblings `:785-788`).
- **Headers:** add public headers to `NGX_ADDON_DEPS` (`./config:454-476`, `633-647`).
- **Census:** add `X(GSIFTP, gsiftp, "gsiftp", ORIGIN)` to the CORE list (`fs_list.h:58-66`);
  ORIGIN → census/metrics id + label, **no** registry row, **no** `extern` in `sd.h`.
- **Optional library gate:** the design is **self-contained OpenSSL/GSSAPI** (no Globus
  dependency — reuse the hand-rolled GSI mech). Krb5 (#5) is already behind
  `BRIX_HAVE_KRB5` (`./config` krb5 probe; `ngx_brix_module.h:75`). No new mandatory lib.
- After source-list changes: re-`./configure --add-module=$REPO`, then `objs/nginx -t`.
  Run `bash -n config` after every `./config` edit (unbalanced-quote silent-drop gotcha).

---

## 11. Confinement & security invariants

- **SSRF.** Every outbound connect (control + each data channel, including server-nominated
  `PASV` addresses) passes `net_target.h` policy — a malicious server cannot redirect the
  data channel to a loopback/link-local/metadata address (the Phase-82 `PORT`/`EPRT`
  screening, now applied to *received* `227`/`229`).
- **DN pinning.** The control- and data-channel peer cert/proxy chain is PKIX-verified and
  DN-pinned (`brix_ftp_dc_gsi_check:166`, `brix_gsi_verify_chain`); a configured
  `origin_expect_dn` rejects a substituted endpoint.
- **Identity isolation.** Session pool keyed by identity (§8); `fallback_deny` exports never
  fall back to a service credential.
- **Seam.** All GridFTP syscalls under `src/fs/backend/gsiftp/`; physical locators
  (FTP paths) never leak above the SD. Logical→physical path join is confined in
  `sd_gsiftp_ns.c` (re-check, never trust the caller's path).
- **Credential hygiene.** Proxy PEMs arrive as 0600 temps with unlink+zero cleanup (Phase-70);
  the driver adds no new on-disk secret.

---

## 12. Testing plan

Per repo rule (3 tests per change: success + error + security-neg) and the fleet model.

1. **Unit / codec** (pure, no server): MODE E pack/unpack round-trip incl. out-of-order +
   overlap + EOD-count-in-OFFSET; FTP reply parser (multiline `-`, 227/229 extraction,
   truncated/oversize, GSS-wrapped); MLSX fact-line parser (all facts, missing facts,
   hostile bytes).
2. **Auth matrix** (one success + one reject + one security-neg per mechanism #1–#8):
   GSI proxy accept / expired-proxy reject / wrong-DN reject; delegated-proxy per-user
   isolation (user A cannot read via user B's session); krb5 accept / no-forwardable reject;
   mTLS accept / no-client-cert reject; anonymous allowed-only-when-configured.
3. **Live lab** (opt-in, like `ceph_live_lab`/`PHASE81_RUN_*`): a real GridFTP server
   (Globus/dCache container) behind a `gsiftp://` export re-exported over XRootD + WebDAV +
   S3; round-trip read/write/list/rename/delete; range reads; large-file MODE E; through-TPC.
4. **Fuzz/conformance:** extend `tests/fuzz_corpus.py` with a gsiftp **client-side** reply
   corpus (malformed 3-digit/continuation, hostile `227`/`229` addresses → SSRF guard,
   MLSX junk) driven against a stub server — the Phase-91 analogue of the existing
   `test_fuzz_*_conformance.py` (which fuzz the *inbound* parsers).
5. **Coverage floor:** new backend files enter the `src/` coverage tier (QUALITY_ROADMAP §2.3.3).

---

## 13. Work breakdown (increments)

| Wave | Deliverable | Depends |
|---|---|---|
| **A** | SD skeleton + factory + config parser + census + build wiring; anonymous read-only (`RETR`/`SIZE`/`MLSD`) against a plaintext FTP stub | §3,4,9,10 |
| **B** | FTP reply parser + control-channel FSM + MODE S read (`REST`+`RETR`); `pread`/`preadv`/`fstat`/`stat`/`opendir` | Wave A |
| **C** | MODE E read (reuse recv reassembler); staged write (`STOR`/`ESTO`) + `RNFR`/`RNTO` promote; `unlink`/`mkdir`/`rename` | Wave B |
| **D** | **GSI client initiator + delegator** (`gftp_auth_gsi.c`); `PBSZ`/`PROT P`/`DCAU`; data-channel GSI via `ftp_dc_sec.c`; per-user delegated proxy (`open_cred`) | Wave C, Phase-70 |
| **E** | mTLS (#6) client-cert outbound CTX; krb5/GSSAPI (#5) behind `BRIX_HAVE_KRB5`; VOMS in-band (#3); connection pool (§8) | Wave D |
| **F** | Tiering (`tier_build_gsiftp`), TPC-through, fuzz corpus, live lab, docs + `development-history.md` index entry | Waves A–E |
| **deferred** | `ERET`/`ESTO` true partial + `SPAS`/`SPOR` striped multi-stream (perf); SSH-transport GridFTP (#9); third-party same-origin `SERVER_COPY` | post-F |

---

## 14. Risks & open questions

- **Server FEAT variance.** dCache vs Globus vs DPM differ on `ERET`/`ESTO`/`MLSD`/`REST
  STREAM` support. Mitigation: probe `FEAT` at `init`, narrow caps, fall back MODE E→MODE S
  and `ERET`→`REST+RETR`.
- **Blocking control loop under load.** Each op holds a threadpool worker for a control
  round-trip. Mitigation: session pooling (§8) amortises setup; `preadv` coalescing cuts
  round-trips; consider a bounded per-origin worker budget.
- **GSI initiator correctness.** The delegator side (sign the server's CSR) is new; the
  signing kernels exist (`proxy_req*.c`) but were only exercised acceptor-side. Mitigation:
  interop-test against a real Globus server early in Wave D.
- **krb5 forwardable ticket availability** (#5): requires `GSS_C_DELEG_FLAG` at the front
  door; stock krb5 inbound auth does not guarantee it — may stay lab-gated (matches Phase-70
  §5.7 DEFERRED banner).
- **Password non-forwardability** (#7) is a documented limit, not a gap to close.

---

## 15. Key references (file:line)

- SD seam & vtable: `src/fs/backend/sd.h:82-111,189-268,275-479,504-513`;
  registry/factory `src/fs/backend/sd_registry.c:28-35,112-199`.
- Templates: `src/fs/backend/remote/sd_remote.c:104-164,262-333,338-403`;
  `src/fs/backend/xroot/sd_xroot.c:197,264-283,378-415`; `sd_ceph_cred.c` (per-user pool).
- Config/dispatch: `src/fs/vfs/vfs_backend_config.c:63-146`;
  `vfs_backend_config_s3.c:32-285`; `vfs_backend_registry_source.c:264-389`;
  `src/core/types/fs_list.h:35-112`; tiering `src/fs/tier/tier_build.c:246-336`.
- GridFTP reuse: MODE E codec `src/protocols/gridftp/ftp_eblock.h:37-69`;
  data-channel sec `src/protocols/gridftp/ftp_dc_sec.c:30,113,137,166`;
  TLS-client `src/protocols/gridftp/ev/ftp_ev_tls.c:69`; outbound connect
  `ftp_ev_data.c:264,415-468`; MODE E send/recv `ftp_ev_mode_e.c:58`,
  `ftp_ev_mode_e_recv.c:153,242,274,309`; acceptor GSI mech (mirror for the initiator)
  `src/auth/gssapi/gsi_mech.c:249,289,317,325,347,397,477,491`.
- Credentials: `src/fs/backend/sd_cred_types.h:87-117`;
  `src/fs/cache/origin_auth_gsi.c:45,90,227,268,397`;
  `src/fs/cache/cache_internal.h:131-138`;
  `src/fs/vfs/vfs_deleg.c:47-82,372-422,546`; `vfs_deleg_bind.c:40,189`;
  `vfs_cred.c:62,120,153,190,228`; `src/fs/backend/ucred.c:165,212,317`;
  `src/auth/krb5/forward.c:34,84,138`; `src/net/proxy/gsi_upstream.c:18`;
  `src/auth/crypto/gsi_verify.h` (`brix_gsi_verify_chain`); `src/core/compat/net_target.h`.
- Seam guard: `tools/ci/check_vfs_seam.py:73-121` (backend auto-exempt).
- Inbound counterpart (concepts, not layout): `docs/refactor/phase-82-gridftp-gateway.md`.
