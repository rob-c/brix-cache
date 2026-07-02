# Phase 57 — Native-TPC delegation, ZIP member access, WebDAV lock hardening

**Status:** Planned
**Author:** plan generated 2026-06-25 (source-verified against `src/`, `client/`, and `/tmp/xrootd-src`)
**Scope:** three independent workstreams (W1/W2/W3), each individually shippable.

---

## 0. How to read this document

Each workstream has the same shape:

1. **Verified current state** — what the source actually does today, with
   `file:line` evidence. (Several headline "gaps" turned out to be partly or
   fully implemented; the real remaining work is narrower and is called out.)
2. **Precise gap** — the exact missing behavior.
3. **Design** — data structures (C sketches), wire/byte layouts, function
   signatures, control flow.
4. **File-by-file change list** — new files + exact edits, with `config.h` /
   `./configure` / full-rebuild implications.
5. **Config + feature flags** — opt-in directives, defaults, merge rules.
6. **Tests** — named cases (success + error + security-negative, per CLAUDE.md).
7. **Risks & rollout.**

**Global rules (CLAUDE.md HARD BLOCKS — apply to every change here):**
no `goto`; functional/modular helpers (one job each, explicit `ctx`, no new
globals, pure helpers + side effects at the edges); use existing
path/auth/metrics/framing helpers (never reimplement); section-level
WHAT/WHY/HOW docblock on every new function; **3 tests per change** (success +
error + security-negative); register every new source in the top-level `./config`
script (the `$ngx_addon_dir/src/…c` srcs lists — see C0; **not**
`src/core/config/config.h`, contrary to CLAUDE.md) and only then run `./configure`;
never edit generated
Makefiles or nginx core; never run git mutating commands.

**Allocation reminders (CLAUDE.md FAQ):** stream plane uses `ngx_alloc/ngx_pcalloc`
(never raw `malloc` in event-thread code; the TPC thread-pool worker already uses
`malloc` because it runs off the event loop — keep that boundary); `ngx_str_t` is
not NUL-terminated; build responses as `ngx_chain_t` of `ngx_buf_t`; TLS buffers
are `b->memory=1` only, cleartext file-backed sendfile (INVARIANT #2).

---
---

# W1 — Native-TPC TLS + multi-round / multi-hop GSI delegation

> ⚠️ **READ [Part F](#part-f--w1-implementation-guide-investigation-revised) FIRST.**
> A 2026-06-26 hands-on investigation found the W1.1 table below is **wrong**:
> native server-side TPC over GSI **does not work today** — it is broken at two
> layers *beneath* delegation, and the existing test masks it. Part F is the
> authoritative, staged implementation guide (fix the foundation → multi-round →
> TLS → delegation). The W1.1–W1.7 sections remain as the original design
> rationale + wire spec, but their "current state" / "what works" claims are
> superseded by Part F.

## W1.1 Verified current state

| Capability | Evidence | State |
|---|---|---|
| Cache-fill outbound state machine `HANDSHAKE→PROTOCOL→TLS→LOGIN→AUTH→DONE` | `src/upstream/bootstrap.c:62`; enum `upstream_internal.h:31-36` | Done |
| Cache-fill outbound **`kXR_gotoTLS` upgrade** (detect flag, resend login over TLS) | `src/upstream/bootstrap.c:85-116` (`xrootd_upstream_start_tls`) | **Done** |
| Cache-fill outbound **single** `kXR_authmore` → token credential | `src/upstream/bootstrap.c:130-153`; `authmore_count` field `upstream_internal.h:73` | Done (1 round only) |
| TPC pull auth-method selection (ztn vs GSI), anchored `&P=` parse | `src/tpc/gsi_outbound_finish.c:27-86` (`tpc_outbound_finish_login`, `xrootd_sec_proto_advertised`) | Done |
| TPC pull outbound ztn JWT (`"ztn\0"`+token, seq 3) | `src/tpc/gsi_outbound_common.c:132` (`tpc_outbound_ztn`) | Done |
| TPC pull outbound GSI — **fixed 2 rounds** (certreq → DH cert exchange) | `src/tpc/gsi_outbound_certreq.c` (209 L), `gsi_outbound_exchange.c` (464 L); decl `tpc_internal.h:181-203` | Done (no ≥3 round) |
| OAuth2/OIDC token-exchange → reused outbound bearer | `src/tpc/tpc_token.c` → `xrootd_tpc_pull_t.delegated_token[65536]` (`tpc_internal.h:98`) | Done |
| TPC rendezvous key registry (cross-worker SHM) | `src/tpc/key_registry.h` — `xrootd_tpc_key_table_t`, 256×`{key[128],expiry,in_use}` | Done |
| `kXR_auth` frame builder (24-byte hdr, credtype @ body+12 = abs off 16) | `src/tpc/gsi_outbound_common.c:52-99` (`tpc_send_kxr_auth`) | Done |
| Server-side **inbound** GSI handshake — **2 rounds only** (certreq→cert) | `src/gsi/auth.c:235-258`; rejects any step past `kXGC_cert` at `:254-258` | Done (no delegation) |
| GSI delegation opcodes defined but **unused** | `src/protocol/gsi.h:20` `kXGS_pxyreq=2002`, `:23` `kXGC_sigpxy=1002` | Constants only |

**Conclusion:** TLS-upgraded origins and single-round token/GSI auth already work
for cache-fill, and TPC pull already does 2-round GSI. The title decomposes into
four concrete deltas (W1.2).

## W1.2 Precise gaps

1. **Cache-fill rejects multi-round auth.** `src/upstream/bootstrap.c:134-138`
   aborts when `authmore_count > 0`; `:163-174` aborts on a second `kXR_authmore`
   after `XRD_UP_BS_AUTH`. GSI on the sec layer is ≥2 rounds, so **no GSI origin
   can be a read-through cache-fill source.**
2. **TPC pull connects plaintext only.** `tpc/bootstrap.c`/`connect.c` have **no**
   `kXR_gotoTLS` handling (unlike `upstream/bootstrap.c:90`), so a TPC source that
   mandates in-protocol TLS upgrade cannot be pulled from.
3. **No X.509 proxy delegation (multi-hop).** Both outbound paths present the
   *gateway's own* credential (cache-fill: static `upstream_token_file`; TPC pull:
   module cert `conf->certificate`, `gsi_outbound_finish.c:54`, or a bearer). The
   server never captures the **client's** X.509 proxy at inbound login
   (`auth.c:254-258` ends at `kXGC_cert`) and never forwards a delegated proxy on
   the outbound hop, so a GSI source authorizes the read as the gateway, not the
   user.
4. **Two divergent handshake implementations** (`upstream/bootstrap.c` vs
   `tpc/gsi_outbound_*`) with different round handling — multi-round must not be
   written twice.

## W1.3 Background — the XrdSecgsi handshake & delegation wire (from `/tmp/xrootd-src`)

GSI runs as nested `XrdSutBuffer` messages inside `kXR_auth` frames. Each buffer
is `name("gsi\0") + step[4] + {type[4] len[4] data[len]}* + kXRS_none`. The
module already has the buffer codec: `xrootd_gbuf_*` and `xrootd_gsi_find_bucket`
(`src/gsi/gsi_core.h:13-33`).

**Step constants** — authoritative values from the module's `src/protocol/gsi.h`
(verified `:18-23`; these are what we implement against, not the stock enum
ordinal arithmetic):

| Direction | Step | Value | Meaning |
|---|---|---|---|
| client→server | `kXGC_certreq` | **1000** | round-1: request server cert + rtag |
| client→server | `kXGC_cert` | **1001** | round-2: client proxy chain (DH-encrypted) |
| client→server | `kXGC_sigpxy` | **1002** | **delegation: client returns SIGNED proxy** |
| server→client | `kXGS_init` | **2000** | initial exchange |
| server→client | `kXGS_cert` | **2001** | server cert + DH params + rtag |
| server→client | `kXGS_pxyreq` | **2002** | **delegation: server REQUESTS a proxy** |

**Delegation option bits** (`XrdSecProtocolgsi.hh:108-114`), carried in the
`kXRS_clnt_opts` bucket (`XrdSecProtocolgsi.cc:1587`):

| Bit | Const | Value | Meaning |
|---|---|---|---|
| 0x0001 | `kOptsDlgPxy` | 1 | client asks to create a delegated proxy |
| 0x0004 | `kOptsSigReq` | 4 | client accepts to sign a delegated proxy |
| 0x0008 | `kOptsSrvReq` | 8 | server requests a delegated proxy |
| 0x0010 | `kOptsPxFile` | 16 | save delegated proxy in a file |
| 0x0040 | `kOptsPxCred` | 64 | save delegated proxy as a credential |

**Delegation flow** (stock `XrdSecProtocolgsi.cc:2153-2163`): after the server
validates `kXGC_cert`, if `hs->Options & (kOptsFwdPxy|kOptsSigReq)` it sets
`nextstep = kXGS_pxyreq` (instead of `kXGS_none`). The server sends a proxy
*certificate request* (a fresh keypair + CSR). The client signs it with its own
proxy private key and returns `kXGC_sigpxy` carrying the signed delegated proxy
(`case kXGC_sigpxy:` at `:2159` → `kXGS_none`). The server assembles
`proxyChain` (`XrdSecProtocolgsi.hh:409`) — the delegated proxy usable to
authenticate downstream **as the user**.

## W1.4 Design

### W1.4.a One outbound auth state machine — `src/upstream/auth_handshake.{c,h}`

```c
/* auth_handshake.h */
typedef enum { XRD_OBA_INIT, XRD_OBA_CONT, XRD_OBA_DONE, XRD_OBA_FAIL } xrootd_oba_phase_t;
typedef enum { XRD_OBA_M_NONE, XRD_OBA_M_ZTN, XRD_OBA_M_GSI }          xrootd_oba_method_t;

#define XRD_OBA_MAX_ROUNDS 8   /* hard cap; replaces the authmore_count==1 limit */

typedef struct {
    xrootd_oba_method_t method;
    int        round;            /* 0-based; bounded by XRD_OBA_MAX_ROUNDS         */
    void      *mstate;           /* method-private GSI cert/DH/cipher material      */
    const u_char *deleg_proxy;   /* PEM delegated proxy (outbound use); NULL = none */
    size_t        deleg_proxy_len;
    /* credentials available locally (filled by caller before _select): */
    const char *bearer;          /* ztn token (delegated or file)                  */
    const char *cert, *key, *castore;  /* GSI module cert paths                     */
} xrootd_oba_ctx_t;

/* Anchored &P= parse (reuse src/protocol/sec_protocol.h) + local-credential
 * availability → chosen method (ztn preferred, GSI fallback — same policy as
 * gsi_outbound_finish.c:61-75). */
xrootd_oba_method_t xrootd_oba_select(const char *parms, size_t parms_len,
                                      const xrootd_oba_ctx_t *cred);

/* Drive ONE round. Consume the server authmore body (NULL/0 on the first call
 * for ztn), emit *out_cred/*out_len (malloc'd; caller frames via the existing
 * frame writer and frees). Returns CONT (more), DONE (kXR_ok expected next),
 * or FAIL (err filled). The GSI continuation indexes its sub-state by ->round. */
xrootd_oba_phase_t xrootd_oba_step(xrootd_oba_ctx_t *c,
                                   const u_char *authmore_body, size_t len,
                                   u_char **out_cred, uint32_t *out_len,
                                   char *err, size_t errsz);
void xrootd_oba_free(xrootd_oba_ctx_t *c);   /* releases mstate */
```

- **GSI continuation** is a mechanical lift of the existing bodies behind the
  `round` switch — **reusing** the OpenSSL/DH logic already on `gsi_core`:
  - `round 0` → emit certreq: `xrootd_gsi_build_certreq(cryptomod, version,
    issuer_hash, clnt_opts, rtag, rtaglen, &outlen)` (`gsi_core.h:129`). When
    delegation is requested set `clnt_opts |= kOptsDlgPxy|kOptsSigReq`.
  - `round 1` → parse `kXGS_init` (DH params + server cert + rtag via
    `xrootd_gsi_find_bucket`), derive the session cipher
    (`xrootd_gsi_cipher_*`), build the encrypted client cert chain — this is the
    body currently in `gsi_outbound_exchange.c`.
  - `round 2` (NEW, only if delegating) → handle `kXGS_pxyreq`: the *destination
    role does not sign here* — the destination is the one **using** a delegated
    proxy captured inbound, so on the pull side delegation is consumed via
    `deleg_proxy`, not produced. (Producing a signed proxy is the inbound client
    role, W1.4.c.)
- **ztn continuation** = one-shot, byte-identical to `tpc_outbound_ztn`
  (`"ztn\0"`+token).
- **Round cap** `XRD_OBA_MAX_ROUNDS` replaces `authmore_count>0` reject (gap 1)
  and bounds hostile authmore loops.

**Callers:**
- `src/upstream/bootstrap.c`: in `XRD_UP_BS_LOGIN`/`XRD_UP_BS_AUTH`, on each
  `kXR_authmore` call `xrootd_oba_step()`, frame via the existing upstream writer,
  stay in `XRD_UP_BS_AUTH` while `CONT`, advance to `XRD_UP_BS_DONE` on `DONE`.
  **Delete** `authmore_count` (field `upstream_internal.h:73` + checks at
  `bootstrap.c:134,167`).
- `src/tpc/thread.c`: replace the explicit `finish_login → outbound_gsi →
  outbound_gsi_exchange` ladder with `while (phase==CONT)`; frame via
  `tpc_send_kxr_auth` (`gsi_outbound_common.c:52`), recv via `tpc_recv_response`.
  `tpc_outbound_finish_login` becomes `xrootd_oba_select` + the loop.

### W1.4.b TPC pull TLS upgrade (gap 2)

Add `kXR_gotoTLS` detection to `tpc/bootstrap.c` mirroring
`upstream/bootstrap.c:85-116`: after the `kXR_protocol` reply, if
`ntohl(flags) & kXR_gotoTLS`, perform a blocking TLS handshake on the pull socket
(the TPC worker is a thread-pool blocking context, so it can use a synchronous
`SSL_connect` over the fd rather than nginx's async `ngx_ssl_handshake`). Gate on
a new `xrootd_tpc_outbound_tls` directive (or reuse `upstream_tls`). All `kXR_auth`
frames (W1.4.a) must then go over the TLS socket — the driver runs post-upgrade.

### W1.4.c X.509 proxy delegation — inbound capture + outbound use (gap 3)

Gated behind one opt-in directive `xrootd_tpc_delegate` (default **off**; when
off, behavior is byte-identical to today).

**Inbound capture (add the missing 3rd server round in `src/gsi/auth.c`).**
- Today `auth.c:254-258` rejects any GSI step that is not `kXGC_certreq`/
  `kXGC_cert`. Add: after a successful `kXGC_cert` parse, **if** delegation is
  enabled *and* this connection is a TPC-destination context (detected when the
  subsequent `kXR_open` carries `tpc.src`; see `open_request.c:185`) — but the
  open arrives *after* auth, so instead gate inbound delegation on the directive
  alone (capture proxy for every GSI login when `xrootd_tpc_delegate on`, cheap
  and reused if a TPC open follows; otherwise discard at session end).
- Emit `kXGS_pxyreq` (2002): generate a fresh keypair + a proxy CSR, send it in a
  new `kXRS_x509_req`-style bucket. **New `gsi_core` builders required:**
  ```c
  /* Build the server→client proxy request (kXGS_pxyreq): fresh EC/RSA key +
   * CSR for a limited proxy, encrypted under the session cipher. */
  uint8_t *xrootd_gsi_build_pxyreq(const xrootd_gsi_cipher_t *c, const uint8_t *key,
                                   EVP_PKEY **out_newkey, size_t *outlen);
  /* Parse the client→server kXGC_sigpxy reply: decrypt + assemble the signed
   * delegated proxy chain (PEM) into out_pem/out_len. */
  int xrootd_gsi_parse_sigpxy(const xrootd_gsi_cipher_t *c, const uint8_t *key,
                              EVP_PKEY *newkey, const uint8_t *body, size_t len,
                              u_char *out_pem, size_t out_max, size_t *out_len);
  ```
- On `kXGC_sigpxy` (1002), assemble the proxy PEM and stash it: keyed by the
  authenticated session, copied into the TPC key registry entry when the TPC
  rendezvous key is later generated (`open_request.c:219`
  `xrootd_tpc_generate_key`).

**Outbound use.** `xrootd_oba_ctx_t.deleg_proxy` is loaded from the registry
entry for this pull's key and signs the source challenge **instead of**
`conf->certificate`. Fallback when `deleg_proxy==NULL` → module cert (unchanged).
The proxy is zeroed on `xrootd_tpc_key_consume`/TTL-expiry so a short-lived
limited proxy is never retained past the transfer.

### W1.4.d Key registry extension — `src/tpc/key_registry.{h,c}`

```c
#define XROOTD_TPC_PROXY_MAX 8192      /* PEM proxy + issuer chain upper bound */
typedef struct {
    char        key[XROOTD_TPC_KEY_LEN];     /* 128 */
    ngx_msec_t  expiry;
    ngx_uint_t  in_use;
    uint32_t    proxy_len;                    /* 0 = no delegated proxy        */
    u_char      proxy_pem[XROOTD_TPC_PROXY_MAX];
} xrootd_tpc_key_entry_t;
```
SHM cost: 256 × ~8 KB ≈ 2 MB (document it; `xrootd_shm_table_alloc` per
INVARIANT #10 — spin+yield mutex, never POSIX-sem). Add:
```c
void xrootd_tpc_key_attach_proxy(const char *key, const u_char *pem, uint32_t len);
uint32_t xrootd_tpc_key_take_proxy(const char *key, u_char *buf, uint32_t bufsz); /* copies + zeroes source */
```

## W1.5 File-by-file changes
**New:** `src/upstream/auth_handshake.c` + `.h` (register in `./config` — see C0).
**Modify:**
- `src/upstream/bootstrap.c` — drive `LOGIN`/`AUTH` via the state machine; delete
  `authmore_count` logic.
- `src/upstream/upstream_internal.h` — remove `authmore_count` (`:73`).
- `src/tpc/thread.c` — auth loop via the state machine.
- `src/tpc/gsi_outbound_finish.c` — `tpc_outbound_finish_login` → `select`+loop wrapper.
- `src/tpc/gsi_outbound_certreq.c`, `gsi_outbound_exchange.c` — expose per-round bodies as the GSI `step()` callback (mechanical extraction; logic reused).
- `src/tpc/bootstrap.c` / `connect.c` — `kXR_gotoTLS` upgrade for the pull socket.
- `src/tpc/key_registry.{h,c}` — proxy-blob slot + attach/take helpers.
- `src/gsi/auth.c` — 3rd round (`kXGS_pxyreq`/`kXGC_sigpxy`) inbound capture.
- `src/gsi/gsi_core.{h,c}` — `xrootd_gsi_build_pxyreq` / `xrootd_gsi_parse_sigpxy`.
- `src/core/config/directives.c` + stream `*_conf` struct/merge — `xrootd_tpc_delegate`
  (`ngx_flag_t`, `NGX_CONF_UNSET`→0), `xrootd_tpc_outbound_tls` (or reuse `upstream_tls`).

**Build:** `./configure` (new source + new directives).

## W1.6 Tests (`tests/test_tpc_*.py`; resilience harness on high ports — see
`resilience_dedicated_instances` memory)
- `test_tpc_pull_gsi_tls_origin` — pull from a GSI-over-TLS source → success (W1.4.b + multi-round).
- `test_cachefill_gsi_origin` — read-through cache-fill from a GSI origin → success (closes gap 1).
- `test_tpc_delegation_identity` — `xrootd_tpc_delegate on` → source access log shows the **user** DN, not the gateway DN.
- `test_tpc_delegation_off_uses_module_cert` — default off → module-cert behavior unchanged (regression).
- security-neg `test_tpc_authmore_loop_bounded` — source sends endless `kXR_authmore` → reject at `XRD_OBA_MAX_ROUNDS`, no spin/CPU runaway.
- security-neg `test_tpc_deleg_proxy_expired` — expired/garbage delegated proxy → clean abort, **no** silent module-cert fallback when delegation on.
- security-neg `test_gsi_sigpxy_when_delegation_off` — a client sending `kXGC_sigpxy` to a server with delegation off → rejected exactly as the current `auth.c:254-258` path (no new attack surface).

## W1.7 Risks & rollout
- Inbound delegation (W1.4.c) is the **highest-risk** item: it adds a real GSI
  handshake round and proxy-signing wire that must be byte-validated against stock
  `xrdcp --tpc` + a real EOS GSI origin (use the `gsi_xcache_eos` setup). Treat
  `xrootd_gsi_build_pxyreq`/`parse_sigpxy` as the part most likely to need
  iteration against a packet capture.
- Land in order, each independently revertable: (i) state-machine refactor (no
  behavior change — prove via existing TPC tests), (ii) TPC `gotoTLS` +
  multi-round cache-fill, (iii) X.509 delegation behind the off-by-default flag.

---
---

# W2 — ZIP member access

## W2.1 Verified current state
- **No ZIP support.** The opaque carrier already exists: `open_extract_opaque()`
  (decl `src/read/open_request.c:16`) returns the substring after `?`, and the
  open path already scans it for `xrootd.compress=` (`open_request.c:62-88`) and
  `tpc.*` (`:176-184`). A `xrdcl.unzip=` scan slots into the **same** pattern with
  **no change to `src/path/extract.c`** (which only strips CGI to make the POSIX
  path for `open()`, `extract.c:43-48`).
- **Inflate is in-tree and explicitly intended for this.** `codec_core.h:12`
  lists *"ZIP member inflate"* as a target surface; `:65` mandates a bomb guard
  "for untrusted decode (PUT, **ZIP**)". `XROOTD_CODEC_DEFLATE` (raw zlib,
  `codec_core.h:36`) + `xrootd_codec_guard_t` (out_cap + ratio ceiling,
  `:68-79`) are exactly method-8 needs.
- **Virtual handles are an established pattern.** `xrootd_file_t`
  (`src/core/types/file.h:52`) already carries non-fd modes: `slice_mode:1` with
  `fd==-1` served from cache files (`:99-102`), and a `uint8_t read_codec`
  ordinal (`:80`). A `zip_mode` field follows precedent.
- **Data plane (INVARIANT #11):** `xrootd_vfs_open`/`..._file_sendfile_fd`/
  `..._close` (`src/fs/vfs.h:116-131`); `xrootd_vfs_io_execute()` for root://
  reads; `xrootd_vfs_stat()` for archive size.

## W2.2 Goal
Serve a single member of a ZIP archive as a standalone file across `root://`
(kXR_open + read/readv/pgread/stat) and WebDAV/S3 GET — matching `XrdZip`:
**read-only**, stored (method 0) + deflated (method 8).

## W2.3 ZIP wire layout (exact, from `/tmp/xrootd-src/src/XrdZip`)

All multi-byte fields are **little-endian**. Sentinel `0xFFFFFFFF`/`0xFFFF`
("`ovrflw`") in a 32/16-bit field means "the real value is in the ZIP64 extra".

**End Of Central Directory (EOCD)** — `XrdZipEOCD.hh`: sig `0x06054b50`, base 22 B,
found by scanning the last `22 + commentLen (≤65535)` bytes backward for the sig.
| off | size | field |
|---|---|---|
| 0 | 4 | sig `0x06054b50` |
| 8 | 2 | nbCdRecD |
| 10 | 2 | **nbCdRec** (total CD entries) |
| 12 | 4 | **cdSize** |
| 16 | 4 | **cdOffset** (start of central dir) |
| 20 | 2 | commentLength |

**ZIP64 EOCD locator** — `XrdZipZIP64EOCDL.hh`: sig `0x07064b50`, sits 20 B before
the EOCD; field @8 = `zip64EocdOffset` (uint64). **ZIP64 EOCD** —
`XrdZipZIP64EOCD.hh`: sig `0x06064b50`, base 56 B; @32 nbCdRec(u64), @40 cdSize(u64),
@48 cdOffset(u64). Trigger ZIP64 when EOCD `cdOffset==0xFFFFFFFF` or
`nbCdRec==0xFFFF`.

**Central Directory File Header (CDFH)** — `XrdZipCDFH.hh`: sig `0x02014b50`, base 46 B.
| off | size | field |
|---|---|---|
| 0 | 4 | sig `0x02014b50` |
| 10 | 2 | **compressionMethod** (0=store, 8=deflate) |
| 16 | 4 | **ZCRC32** (CRC-32 IEEE of uncompressed) |
| 20 | 4 | **compressedSize** (0xFFFFFFFF→ZIP64) |
| 24 | 4 | **uncompressedSize** (0xFFFFFFFF→ZIP64) |
| 28 | 2 | filenameLength |
| 30 | 2 | extraLength |
| 32 | 2 | commentLength |
| 38 | 4 | externAttr (mode<<16) |
| 42 | 4 | **offset** of local header (0xFFFFFFFF→ZIP64) |
| 46 | n | filename (filenameLength bytes) |
| 46+fn | m | extra (ZIP64 sizes/offset live here when overflown — `ParseExtra`) |

ZIP64 extra block id `0x0001`; fields appear **only** for overflown values, in
order uncompSize,compSize,offset (`XrdZipCDFH.hh:237-281`). `GetOffset()`
(`:227-232`) returns `extra->offset` when `offset==0xFFFFFFFF`.

**Local File Header (LFH)** — `XrdZipLFH.hh`: sig `0x04034b50`, base 30 B; @26
filenameLength, @28 extraLength. **Data starts at**
`local_hdr_off + 30 + lfh.filenameLength + lfh.extraLength`. (The LFH name/extra
lengths can differ from the CDFH's, so the LFH must be read to resolve `data_off`.)

**Data descriptor** — `generalBitFlag & 0x0008` (`XrdZipDataDescriptor`,
`CDFH::HasDataDescriptor()`): sizes are in a trailing descriptor, **not** known at
header time → **reject** such members (size required at open).

## W2.4 Design

### W2.4.a Opaque trigger
- `root://`: open with `?xrdcl.unzip=<member>` (stock XrdCl spelling). Detect in
  `xrootd_handle_open()` via a new `open_negotiate_zip_member()` helper mirroring
  `open_negotiate_compress_codec()` (`open_request.c:39-89`): extract opaque, scan
  for `xrdcl.unzip=` on a key boundary (`start`/`&`/`?` — same boundary check as
  `:67`), copy the member name.
- WebDAV/S3 GET: `?xrdcl.unzip=<member>` query arg + documented `X-Xrootd-Unzip`
  header alias, parsed near the Range handling in `src/webdav/get.c:68`.
- Validate the member name: reject empty, leading `/`, any `..` component, NUL —
  reuse the posture of `xrootd_reject_dotdot_path` (`open_request.c:397`). (Intra-
  archive only; cannot escape the fs, but a hostile name must not be trusted.)

### W2.4.b Central-directory reader — `src/zip/zip_dir.{c,h}` (ngx-free core)
```c
typedef struct {
    char      name[PATH_MAX];
    uint16_t  method;          /* 0 store / 8 deflate                    */
    uint64_t  comp_size;
    uint64_t  uncomp_size;
    uint64_t  data_off;        /* resolved first data byte (post-LFH)    */
    uint32_t  crc32;           /* expected IEEE CRC-32 of uncompressed   */
} xrootd_zip_member_t;

/* pread-based, bounded. Steps: (1) read last min(archive_size, 64KiB+22) bytes,
 * scan backward for EOCD sig; (2) if cdOffset/nbCdRec overflown, follow ZIP64
 * locator → ZIP64 EOCD; (3) pread the central directory [cdOffset, cdSize);
 * (4) walk CDFH records (sig-checked, bounds-checked) matching `member`;
 * (5) reject data-descriptor entries; (6) pread the LFH at `offset` to compute
 * data_off. Every offset/length validated < archive_size. */
ngx_int_t xrootd_zip_find_member(int archive_fd, off_t archive_size,
                                 const char *member, xrootd_zip_member_t *out,
                                 ngx_log_t *log);   /* NGX_OK / NGX_DECLINED / NGX_ERROR */
```
Per-worker LRU keyed by `(archive_path, mtime, size)` caches the parsed member to
avoid re-scanning on repeated opens (mirror `redir_cache`/`slice` caches). Cap the
CD read (e.g. ≤ 16 MiB) to bound memory on hostile archives.

### W2.4.c Member handle — append to `xrootd_file_t` (`src/core/types/file.h`)
```c
    unsigned   zip_mode:1;        /* this handle serves a ZIP member        */
    uint16_t   zip_method;        /* 0 store / 8 deflate                    */
    uint64_t   zip_data_off;      /* archive offset of member data          */
    uint64_t   zip_comp_size;
    uint64_t   zip_uncomp_size;   /* logical size (stat + EOF)              */
    uint32_t   zip_crc32;         /* expected IEEE CRC-32 (verify opt-in)   */
    void      *zip_inflate;       /* xrootd_codec_stream_t* (DEFLATE); lazy */
    uint64_t   zip_logical_pos;   /* next uncompressed offset produced      */
    uint64_t   zip_comp_pos;      /* next compressed offset consumed        */
```
- **Stored (method 0):** pure offset translation. read/readv/pgread add
  `zip_data_off`; sendfile via `xrootd_vfs_file_sendfile_fd()` with shifted offset,
  length clamped to `zip_uncomp_size`. **Full zero-copy + pgread per-page CRC32c
  parity** (INVARIANT #1) — bytes are uncompressed on disk.
- **Deflate (method 8):** `xrootd_codec_open(XROOTD_CODEC_DEFLATE,
  DIR_DECOMPRESS, -1, &guard)` with `guard.out_cap = zip_uncomp_size`,
  `guard.max_ratio` sane (e.g. 1000). Read loop pumps compressed bytes from
  `[zip_data_off + zip_comp_pos ..]` through `xrootd_codec_step()` into the output:
  ```
  while (out_produced < want && rc != END) {
      n = pread(fd, cbuf, min(CHUNK, zip_comp_size - zip_comp_pos), zip_data_off + zip_comp_pos);
      rc = xrootd_codec_step(s, cbuf, n, &in_pos, obuf, obuf_sz, &out_pos, n==0);
      zip_comp_pos += in_pos; copy obuf[..out_pos] to caller;
  }
  ```
  - Sequential reads reuse the stream (fast path: req offset == `zip_logical_pos`).
  - A seek re-opens the stream and inflates-from-start to the target (bounded by
    `zip_uncomp_size`) — acceptable v1.
  - **pgread/readv on a deflated member → reject (`kXR_Unsupported`) or plain-read
    fallback** — per-page CRC framing over a reconstructed stream is meaningless;
    upstream only zero-copies stored members. Document this.
- **stat** reports `zip_uncomp_size` from handle metadata — no per-read syscalls
  (INVARIANT #7).
- **Read-only:** write/pgwrite/truncate/sync/checkpoint on `zip_mode` →
  `kXR_NotAuthorized` (root) / 403 (HTTP).
- **Optional CRC verify** (`xrootd_zip_verify_crc`, default off): accumulate IEEE
  CRC-32 of delivered bytes; on the final read compare to `zip_crc32`, mismatch →
  `kXR_ChkSumErr` + log.

### W2.4.d Routing
- `xrootd_handle_open()`: auth runs against the **archive** path (access to a
  member ⇒ access to the archive). If a member arg is present, open the archive fd
  via the confined open and call `xrootd_zip_open_member()` to fill `zip_*` from
  `xrootd_zip_find_member()` instead of `xrootd_open_resolved_file()`
  (`open_request.c:658`).
- `src/read/read.c`, `readv.c`, `pgread.c`, `stat.c`, `close.c`: one early
  `if (fh->zip_mode)` dispatch to `zip_member.c` helpers (`xrootd_zip_read`,
  `..._stat`, `..._close`) — same shape as the `slice_mode` branch.
- `src/webdav/get.c` (+ optional `src/s3/get.c`): with the member arg, open the
  archive via VFS, resolve the member; stored → `xrootd_http_serve_file_ranged`
  with shifted offset (`get.c:226`); deflate → inflate into the `ngx_chain_t`
  (synthesized bytes are **memory-backed** `b->memory=1` in BOTH TLS and cleartext
  — not file-backed sendfile — because they are not contiguous on disk;
  INVARIANT #2 still holds since we never mix).

## W2.5 File-by-file changes
**New:** `src/zip/zip_dir.{c,h}`, `src/zip/zip_member.{c,h}`, `src/zip/README.md`
(register `.c` in `./config` — see C0).
**Modify:** `src/core/types/file.h` (handle fields), `src/read/open_request.c`
(`open_negotiate_zip_member()` + dispatch), `src/read/{read,readv,pgread,stat,close}.c`
(zip_mode branch), `src/webdav/get.c` (+ `s3/get.c` optional), `src/core/config/directives.c`.
**Build:** `./configure` (new sources + directives).

⚠️ **Full rebuild required** after the `file.h` struct change (memory
`build_header_dep_mixed_abi`): incremental linking against stale objects with the
old `xrootd_file_t` size SIGSEGVs. Run `make clean && make -j$(nproc)`.

## W2.6 Config + flags
- `xrootd_zip_access on|off` (default **off**) — master gate.
- `xrootd_zip_verify_crc on|off` (default off).
- `xrootd_zip_cd_max_bytes N` (cap central-dir read; default 16m).

## W2.7 Tests (`tests/test_zip_member.py`)
- `test_zip_stored_member_bytes` — bytes+size == `unzip -p archive member`.
- `test_zip_deflate_member_bytes` — same for a deflated member (sequential).
- `test_zip_deflate_midfile_seek` — Range/offset mid-file == reference.
- `test_zip_stat_uncompressed_size` — stat/HEAD reports uncompressed size.
- `test_zip64_member` — archive forced into ZIP64 (cdOffset>4GiB or >65535 members).
- `test_zip_readv_pgread_stored_ok` — readv/pgread on stored member CRC-correct.
- `test_zip_pgread_deflate_rejected` — pgread/readv on deflated member → documented reject/fallback.
- security-neg `test_zip_member_traversal` — `xrdcl.unzip=../../etc/passwd`, absolute names, embedded NUL → rejected.
- security-neg `test_zip_bomb_guarded` — high-ratio deflate member → `XROOTD_CODEC_ERR_BOMB`, bounded memory.
- security-neg `test_zip_corrupt_central_dir` — truncated/garbage EOCD/CDFH, bad sigs, oversize lengths → clean error, no OOB.
- security-neg `test_zip_data_descriptor_rejected` — member with bit-3 set → rejected (size unknown at open).
- `test_zip_member_write_rejected` — write/truncate on member handle → 403/kXR_NotAuthorized.

## W2.8 Risks & rollout
- Random-access into deflated members is the hard part. **Ship in slices:**
  (1) stored-member full support (zero-copy, readv/pgread) — highest value, lowest
  risk; (2) deflate sequential; (3) deflate random-access via periodic inflate
  checkpoints (follow-up if a workload needs it). Document the v1 limit.
- Get ZIP64 + data-descriptor handling right early (security-negative tests gate).

---
---

# W3 — WebDAV lock hardening

## W3.1 Verified current state (most of "persistence" is already done)

| Behavior | Evidence | State |
|---|---|---|
| Locks persisted as one xattr on the resource (survive restart **and** reload) | `src/webdav/lock.c:4-10`; `src/webdav/prop_xattr.c:60-194` | **Done** |
| Atomic create across workers (`XATTR_CREATE`→EEXIST→423) | `prop_xattr.c:122-150`; `lock.c:479-484` | Done |
| xattr value via the impersonating VFS xattr surface (Phase 40) | `prop_xattr.c:36-54,136-138` | Done |
| Opt-in startup sweep → ephemeral semantics (default **off**) | `lock.c:77-99`; `config.c:108,210`; `module.c:788` | Done |
| Shared vs exclusive scope parsed + stored | `lock.c:409,475`; `prop_xattr.c:66-70,109-110` | Done |
| Depth 0/infinity, owner XML, refresh, `If:` header, recursive child-lock checks | `lock.c:117-359,447-494` | Done |
| **Lock-null** (LOCK on missing path → zero-byte `O_CREAT\|O_EXCL` resource, RFC 4918 §9.10.1) | `lock.c:411-431` | **Already implemented** |

The earlier "locks lost on reload" framing and the SHM-1024-slot memories are
**obsolete**. The xattr schema today (`prop_xattr.c:65-70`) is:
`token=<t>|owner=<o>|expires=<msec>|scope=<exclusive|shared>|depth=<infinity|0>`.
Struct `webdav_lock_xattr_t` (`webdav.h:108`): `token,owner,expires(ngx_msec_t),
exclusive,depth_infinity`. Key `WEBDAV_LOCK_XATTR_KEY="user.nginx_xrootd.lock"`
(`webdav.h:85`), `WEBDAV_LOCK_XATTR_MAXLEN=512` (`:86`).

## W3.2 Precise gaps

1. **Expiry in monotonic-clock units → invalid across a reboot (bug).**
   `webdav_lock_xattr_t.expires` is `ngx_msec_t` from
   `webdav_lock_parse_timeout()` (= `ngx_current_msec + timeout`), serialized
   verbatim (`prop_xattr.c:66-68` `expires=%llu`) and compared after restart
   against `ngx_current_msec` (`lock.c:117,210,304,442,524`). `ngx_current_msec`
   is nginx's **monotonic** cache (CLOCK_MONOTONIC, since boot): fine across
   `nginx -s reload` (same boot, shared timeline) but **wrong across a machine
   reboot** — a persisted monotonic value vs a post-reboot monotonic value is
   meaningless (lock appears eternal or instantly expired). Persistence works;
   its **timeout does not survive a reboot.**
2. **One lock per resource regardless of scope — shared locks can't coexist
   (RFC 4918 §6.1).** State is a single xattr, so a 2nd **shared** LOCK on an
   already-shared-locked resource hits `XATTR_CREATE`→EEXIST→423
   (`lock.c:479-484`) even though shared locks should stack. Exclusive is correct;
   shared multiplicity is not.
3. **No reload/reboot-survival or lock-null lifecycle test coverage**, and the
   lock-null placeholder is **never reaped**: a LOCK of a missing path that the
   client never PUTs leaves a 0-byte file even after UNLOCK/expiry (strict RFC
   says the lock-null resource disappears).

## W3.3 Design

### W3.3.a Fix expiry → wall-clock (gap 1, the only correctness bug)
- Persist absolute **Unix seconds** (`ngx_time()`), not monotonic ms.
  - `webdav_lock_xattr_t`: add `int64_t expires_wall` (keep `expires` only if
    in-request convenience is wanted; cleaner to replace it).
  - `webdav_lock_parse_timeout()` (`locks/request.c`) returns
    `(int64_t) ngx_time() + seconds`.
  - Replace every `e.expires > ngx_current_msec` (and `<=`) at `lock.c:117,210,
    304,442,524` with `e.expires_wall > (int64_t) ngx_time()`.
  - `prop_xattr.c` encode/decode: `expires=<unix_seconds>` (`%lld`,
    `strtoll`), and the remaining-seconds math in `webdav_lock_xml_response`
    (`lock.c:117-118`) becomes `(e.expires_wall - ngx_time())`.
- **Schema migration:** add `v=2` as the first field. Decode treats a missing
  `v` (legacy monotonic `expires`) as **already expired** → released on first
  access. Safe because locks are short-lived; avoids interpreting an old
  monotonic value as wall-clock.

### W3.3.b Shared-lock coexistence (gap 2)
Keep one xattr, store **multiple shared holders** as a bounded array inside it:
- Bump `WEBDAV_LOCK_XATTR_MAXLEN` (e.g. 512→1024) and cap holders at `N=4`.
- Schema v2 gains repeating groups for shared:
  `v=2|scope=shared|h=<tok>:<owner>:<exp>|h=<tok>:<owner>:<exp>|...|depth=...`;
  exclusive stays single-holder (`scope=exclusive`).
- LOCK logic in `webdav_handle_lock_inner` (`lock.c:461-491`):
  - request `shared` + state shared (live) → append a holder via `XATTR_REPLACE`
    (read-modify-write; on `EEXIST`/lost-race re-read and merge — `XATTR_CREATE`
    still guards first creation).
  - request `exclusive` + any live holder → 423; request `shared` + live
    exclusive → 423.
- `webdav_check_locks`/`_descendants` (`lock.c:183,256`) iterate holders; the
  `If:` header matches if it carries **any** holder token
  (`webdav_lock_if_header_matches`).
- **Scope decision:** if no target client actually uses shared WebDAV locks, this
  sub-item may be **deferred** and the single-lock-per-resource limit *documented*
  instead. W3.3.a + W3.3.c are the must-haves.

### W3.3.c Lock-null reaping (gap 3)
- Tag lock-null creations (`lock.c:411-431`) with `null=1` in the xattr.
- On `UNLOCK` (`webdav_handle_unlock`, `lock.c:496`) and on lazy expiry cleanup
  (`webdav_lock_xattr_delete` sites at `lock.c:221,310,443`), if the resource is
  still zero-bytes **and** `null=1`, `unlink` the placeholder (confined) rather
  than only removing the xattr.
- A successful `PUT`/`MKCOL` by the holder clears `null` (resource is now real) —
  hook the existing PUT/MKCOL lock-enforcement sites.

## W3.4 File-by-file changes
**Modify:**
- `src/webdav/webdav.h` — `webdav_lock_xattr_t` (`:108`): add `expires_wall`
  (`int64_t`), `is_null` (`unsigned:1`), optional shared-holder array; bump
  `WEBDAV_LOCK_XATTR_MAXLEN` (`:86`) if doing W3.3.b.
- `src/webdav/prop_xattr.c` — encode/decode v2 schema (`:60-120`): wall-clock
  `expires`, `v=2`, `null=`, shared `h=` groups.
- `src/webdav/lock.c` — comparisons → wall-clock (`:117,210,304,442,524`);
  lock-null reaping (unlock/expiry); shared merge (`:461-491`); remaining-seconds
  math (`:117-118`).
- `src/webdav/locks/request.c` — `webdav_lock_parse_timeout` returns
  `ngx_time()+sec` (`int64_t`).
**No `./configure`** (no new directive required). No struct-size ABI risk beyond
WebDAV objects, but a clean rebuild of `src/webdav/*` is prudent.

## W3.5 Tests (extend `tests/test_http_webdav_lock.py` — currently 9 cases)
- `test_lock_survives_reload` — LOCK → `nginx -s reload` → PUT w/o token → 423;
  PUT w/ token → 200 (closes the missing reload coverage).
- `test_lock_expiry_wallclock` — LOCK short timeout → **restart** the server past
  expiry → access succeeds w/o token (proves wall-clock; FAILS today on a
  reboot-equivalent).
- `test_lock_null_create_then_put` — LOCK missing path → 201+token; PROPFIND shows
  lock-null; PUT by holder converts to real resource.
- `test_lock_null_reaped_on_unlock` — LOCK missing path → UNLOCK w/o PUT →
  placeholder gone (no orphan 0-byte file).
- `test_shared_locks_coexist` (if W3.3.b) — two shared LOCKs succeed; an exclusive
  LOCK then 423s.
- `test_startup_sweep_clears` — `xrootd_webdav_lock_startup_sweep on` → lock gone
  after restart.
- security-neg `test_lock_null_confined` — lock-null on a traversal/symlink target
  cannot escape the export root; a non-holder cannot convert/steal it.
- security-neg `test_lock_legacy_monotonic_dropped` — a planted legacy
  (`v`-less monotonic) lock xattr is treated as expired on first access (migration
  safety).

## W3.6 Risks & rollout
- W3.3.a is low-risk (schema bump + comparison swap) and the only behavioral
  correctness fix — ship first. W3.3.c (lock-null reaping) is contained. W3.3.b
  (shared locks) is the largest and **optional** — gate on whether any target
  client uses shared WebDAV locks; otherwise document the limit.

---
---

# Sequencing & cross-cutting

| Order | Workstream | Rationale | `./configure`? | Full rebuild? |
|---|---|---|---|---|
| 1 | **W3** lock hardening | Smallest; fixes a real reboot-expiry bug; closes stale-doc credibility gap | No | webdav only |
| 2 | **W2** ZIP member access | Independent; stored-member slice ships value early; reuses codec + VFS | Yes | **Yes** (`file.h`) |
| 3 | **W1** TPC delegation | Largest; inbound GSI delegation needs a real GSI origin to validate | Yes | No |

Within each workstream, land sub-items in the stated order (each independently
revertable). Every change honors the global rules in §0 and updates the touched
`src/` subdir `README.md`.

## Documentation debt to fix as these land
`docs/10-reference/gaps-vs-xrootd.md` (dated 2026-06-14) is stale:
- lists `host`/`pwd` auth as missing — both implemented + advertised (with `ztn`);
- describes WebDAV locks as lost on reload — they are xattr-persisted (the real
  bug is reboot-expiry, W3.2 gap 1) and lock-null is already implemented;
- understates outbound TLS/auth (cache-fill `gotoTLS` + single-round auth done,
  TPC pull does 2-round GSI) and the proxy file cache (`src/cache/` is a real
  read-through cache).
Also retire the obsolete OAK discovery memories describing the SHM-1024-slot lock
table.

## Cross-references
- TPC current architecture: `src/tpc/README.md`, `tpc_internal.h`,
  `key_registry.h`; GSI: `src/gsi/README.md`, `gsi_core.h`, `protocol/gsi.h`.
- Codec/inflate: `src/core/compat/codec_core.h` (note line 12 lists ZIP as a planned
  surface). Handle model: `src/core/types/file.h`. VFS data plane: `src/fs/README.md`,
  `src/fs/vfs.h` (INVARIANT #11).
- Reference wire spec: `/tmp/xrootd-src/src/XrdZip/*`,
  `/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.{hh,cc}`.

---
---

# Part B — Implementation Appendix

> Concrete diffs, full pseudocode, wire diagrams, config snippets, error maps,
> and a task checklist. Code blocks are **illustrative** — they encode the exact
> control flow and wire layout, but the implementer must match surrounding style
> (docblocks, naming, no-`goto`, helper decomposition) per the coding standard.

## B1. Wire sequence diagrams

### B1.1 Cache-fill outbound GSI — today vs. W1

```
TODAY (src/upstream/bootstrap.c)               W1 (auth_handshake state machine)
nginx ──► origin                               nginx ──► origin
  handshake/protocol/login (anon) ─►             handshake/protocol/login ─►
  ◄─ kXR_authmore (GSI)                          ◄─ kXR_authmore (parms: &P=gsi)
  send token (authmore_count=1) ─►               oba_step r0: kXGC_certreq ─►
  ◄─ kXR_authmore  (2nd!)                         ◄─ kXR_authmore (kXGS_init: srvcert+DH+rtag)
  ✗ ABORT "repeated kXR_authmore"                oba_step r1: kXGC_cert (DH-enc chain) ─►
                                                  ◄─ kXR_ok  → BS_DONE
```

### B1.2 TPC X.509 delegation — end-to-end (3 parties)

```
 client(user proxy)        nginx-DEST (gateway)            origin-SRC (GSI)
        │  kXR_login GSI         │                                │
        │ ─ certreq ───────────► │                                │
        │ ◄ kXGS_init ────────── │                                │
        │ ─ kXGC_cert ─────────► │  (auth.c: cert verified)       │
        │ ◄ kXGS_pxyreq ──────── │  NEW round (xrootd_tpc_delegate on)
        │ ─ kXGC_sigpxy ───────► │  signed delegated proxy        │
        │                        │  store PEM in key_registry[key]│
        │  kXR_open tpc.src=…&tpc.key=K                           │
        │ ─────────────────────► │  generate K, attach proxy      │
        │                        │  ── TPC pull thread ──────────►│ connect (+gotoTLS)
        │                        │  oba: GSI signs with DELEG PROXY│ login authmore
        │                        │  ◄──────────────────────────── │ kXR_ok (as USER)
        │                        │  pull bytes → dst, fsync, close │
        │ ◄ kXR_open OK (after sync) ───                           │
```

### B1.3 ZIP member open + first read (stored)

```
client ── kXR_open "/data/a.zip?xrdcl.unzip=dir/x.root" ──► nginx
   open_request.c: auth on ARCHIVE path "/data/a.zip"
   open archive fd (confined)  →  xrootd_zip_find_member(fd, size, "dir/x.root")
     pread tail → EOCD(0x06054b50) → [ZIP64?] → pread CD[cdOff,cdSize]
     walk CDFH(0x02014b50) match name → method,sizes,crc,lhdr_off
     pread LFH(0x04034b50)@lhdr_off → data_off = lhdr_off+30+fnLen+exLen
   fh->zip_mode=1; fh->zip_data_off=…; fh->zip_uncomp_size=…
client ◄ kXR_open OK (fhandle, stat=uncomp_size)
client ── kXR_read(fh, off=O, len=L) ──► read.c: if(zip_mode) →
   stored: pread(fd, buf, L, zip_data_off + O)  (clamp to uncomp_size)
client ◄ kXR_ok (L bytes)
```

## B2. Edit-site diffs (verified current code → proposed)

### B2.1 `src/tpc/bootstrap.c:116-123` — authmore dispatch unchanged; loop moves inside finish_login
The call site stays minimal; the multi-round loop lives in
`tpc_outbound_finish_login` (B3.1):
```c
    if (status == kXR_authmore) {
-       if (tpc_outbound_finish_login(t, fd, body, dlen) != 0) {
-           free(body);
-           return -1;
-       }
-       free(body);
-       return 0;
+       int rc = tpc_outbound_finish_login(t, fd, body, dlen); /* now loops */
+       free(body);
+       return (rc == 0) ? 0 : -1;
    }
```
Add a `kXR_gotoTLS` branch earlier (after the `kXR_protocol` reply parse) mirroring
`upstream/bootstrap.c:90-116`, gated on `xrootd_tpc_outbound_tls`.

### B2.2 `src/upstream/bootstrap.c:130-174` — delete the single-round cap
```c
    case XRD_UP_BS_LOGIN: {
        ...
        if (up->resp_status == kXR_authmore) {
-           if (up->authmore_count > 0) {
-               xrootd_upstream_abort(up,
-                   "upstream: repeated kXR_authmore (not supported)");
-               return;
-           }
-           up->authmore_count++;
-           ... send_token_auth(up, conf) ...
+           /* Drive one round of the shared outbound auth state machine; stay in
+            * BS_AUTH while OBA_CONT, advance to BS_DONE on OBA_OK.            */
+           if (xrootd_upstream_oba_round(up, conf) != NGX_OK) {
+               xrootd_upstream_abort(up, up->oba.err[0] ? up->oba.err
+                                                        : "upstream: auth failed");
+           }
            return;
        }
        ...
    }
    case XRD_UP_BS_AUTH:
-       if (up->resp_status != kXR_ok) {
-           xrootd_upstream_abort(up, "upstream: token auth rejected by server");
-           return;
-       }
-       up->bs_phase = XRD_UP_BS_DONE;
+       /* feed the authmore/ok back into the driver until it reports DONE */
+       if (xrootd_upstream_oba_round(up, conf) != NGX_OK) {
+           xrootd_upstream_abort(up, "upstream: auth rejected");
+       }
        break;
```
Remove `authmore_count` from `src/upstream/upstream_internal.h:73`; add an
`xrootd_oba_ctx_t oba;` field.

### B2.3 `src/read/read.c:131-133` — insert the zip branch before slice_mode
```c
    rconf = ngx_stream_get_module_srv_conf(...);

+   /* ZIP member handles: translate the read into the archive's byte range
+    * (stored = offset add; deflate = stream inflate). No backing-file sendfile
+    * for deflate. Mirrors the slice_mode early dispatch below. */
+   if (ctx->files[idx].zip_mode) {
+       return xrootd_zip_read(ctx, c, idx, offset, rlen);
+   }
+
    /* Phase 26: slice-mode handles have no backing fd; serve from the slice
     * cache ... */
    if (ctx->files[idx].slice_mode) {
```
Apply the same one-line early dispatch in `readv.c`, `pgread.c` (→ reject/fallback
for deflate), `stat.c` (→ `xrootd_zip_stat`), `close.c` (→ free `zip_inflate`).

### B2.4 `src/webdav/locks/request.c:8-39` — wall-clock timeout
```c
-ngx_msec_t
+int64_t                                  /* absolute Unix seconds */
 webdav_lock_parse_timeout(ngx_http_request_t *r,
                           ngx_http_xrootd_webdav_loc_conf_t *conf)
 {
     ...
     if (timeout < 1) timeout = 1;
     if (timeout > conf->lock_timeout) timeout = conf->lock_timeout;
-    return ngx_current_msec + timeout * 1000;
+    return (int64_t) ngx_time() + (int64_t) timeout;   /* seconds, not msec */
 }
```
Update the declaration in `locks/request.h:13` to `int64_t`. Note
`conf->lock_timeout` is currently in **seconds** as used here (`timeout` is a
seconds count, `Second-N`), so no unit change for the directive.

### B2.5 `src/webdav/prop_xattr.c:60-120` — v2 schema (wall-clock + null + shared)
```c
 ngx_int_t
 webdav_lock_xattr_encode(const webdav_lock_xattr_t *e, char *out, size_t outsz)
 {
     int n;
-    n = snprintf(out, outsz,
-                 "token=%s|owner=%s|expires=%llu|scope=%s|depth=%s",
-                 e->token, e->owner, (unsigned long long) e->expires,
-                 e->exclusive ? "exclusive" : "shared",
-                 e->depth_infinity ? "infinity" : "0");
+    n = snprintf(out, outsz,
+                 "v=2|token=%s|owner=%s|expires=%lld|scope=%s|depth=%s|null=%d",
+                 e->token, e->owner, (long long) e->expires_wall,
+                 e->exclusive ? "exclusive" : "shared",
+                 e->depth_infinity ? "infinity" : "0",
+                 e->is_null ? 1 : 0);
     return (n > 0 && (size_t) n < outsz) ? NGX_OK : NGX_ERROR;
 }
```
Decode (`:74-120`): add `v`, `null`, switch `expires` parse to
`e->expires_wall = strtoll(val,NULL,10)`; **a record with no `v=2` is rejected as
expired** (`return NGX_DECLINED` after setting a 0 expiry) — the legacy-monotonic
migration guard. (Shared `h=` group parsing only if W3.3.b is taken.)

### B2.6 `src/webdav/lock.c` — comparison swaps (5 sites)
At `:117,210,304,442,524` replace `e.expires {>,<=} ngx_current_msec` with
`e.expires_wall {>,<=} (int64_t) ngx_time()`; at `:117-118` the remaining-seconds
display becomes `(e.expires_wall > now_s) ? (ngx_uint_t)(e.expires_wall - now_s) : 0`
with `now_s = (int64_t) ngx_time()`.

## B3. New-function pseudocode (full bodies, illustrative)

### B3.1 `tpc_outbound_finish_login` → driver loop (replaces the 2-round ladder)
```c
int tpc_outbound_finish_login(xrootd_tpc_pull_t *t, int fd,
                              u_char *login_body, uint32_t login_dlen)
{
    xrootd_oba_ctx_t c; ngx_memzero(&c, sizeof(c));
    const char *parms = (char *) login_body + XROOTD_SESSION_ID_LEN;

    c.bearer  = (t->delegated_token[0] ? t->delegated_token
                : (t->conf->tpc_outbound_bearer_file.len ? "<file>" : NULL));
    c.cert    = cstr(&t->conf->certificate);
    c.key     = cstr(&t->conf->certificate_key);
    /* W1.4.c: load the delegated proxy for this pull's key, if any */
    static u_char proxy[XROOTD_TPC_PROXY_MAX];
    uint32_t plen = xrootd_tpc_key_take_proxy(t->tpc_key, proxy, sizeof(proxy));
    if (plen) { c.deleg_proxy = proxy; c.deleg_proxy_len = plen; }

    c.method = xrootd_oba_select(parms, login_dlen - XROOTD_SESSION_ID_LEN, &c);
    if (c.method == XRD_OBA_M_NONE) { /* err set */ return -1; }

    const u_char *amore = login_body; size_t amlen = login_dlen; /* first body */
    for (;;) {
        u_char *cred = NULL; uint32_t clen = 0;
        xrootd_oba_phase_t ph = xrootd_oba_step(&c, amore, amlen, &cred, &clen,
                                                t->err_msg, sizeof(t->err_msg));
        if (ph == XRD_OBA_FAIL) { xrootd_oba_free(&c); return -1; }
        if (cred) {
            if (tpc_send_kxr_auth(t, fd, (u_char)(3 + c.round), cred, clen) != 0) {
                free(cred); xrootd_oba_free(&c); return -1;
            }
            free(cred);
        }
        if (ph == XRD_OBA_DONE) { xrootd_oba_free(&c); return 0; }

        uint16_t st; u_char *body = NULL; uint32_t dlen;
        if (tpc_recv_response(fd, &st, &body, &dlen) != 0) { xrootd_oba_free(&c); return -1; }
        if (st == kXR_ok)       { free(body); xrootd_oba_free(&c); return 0; }
        if (st != kXR_authmore) { free(body); t->xrd_error = kXR_AuthFailed;
                                  xrootd_oba_free(&c); return -1; }
        amore = body; amlen = dlen;   /* feed next round; freed next iteration */
        if (++c.round >= XRD_OBA_MAX_ROUNDS) { free(body); xrootd_oba_free(&c);
            t->xrd_error = kXR_AuthFailed; return -1; }
    }
}
```

### B3.2 `xrootd_zip_find_member` (bounded, pread-based)
```c
ngx_int_t xrootd_zip_find_member(int fd, off_t sz, const char *member,
                                 xrootd_zip_member_t *out, ngx_log_t *log)
{
    if (sz < 22) return NGX_DECLINED;
    /* 1) read tail and scan backward for EOCD signature 0x06054b50 */
    size_t tail = MIN((size_t) sz, 22u + 65535u);
    u_char *buf = ngx_alloc(tail, log); if (!buf) return NGX_ERROR;
    if (pread_full(fd, buf, tail, sz - tail) != (ssize_t) tail) goto bad; /* NOTE: real impl: no goto — early-return helper */
    ssize_t e = -1;
    for (ssize_t o = (ssize_t) tail - 22; o >= 0; --o)
        if (rd32le(buf + o) == 0x06054b50u) { e = o; break; }
    if (e < 0) { ngx_free(buf); return NGX_DECLINED; }
    uint16_t nrec = rd16le(buf+e+10); uint32_t cdsz = rd32le(buf+e+12);
    uint64_t cdoff = rd32le(buf+e+16);
    /* 2) ZIP64 promotion */
    if (cdoff == 0xFFFFFFFFu || nrec == 0xFFFFu) {
        /* locate ZIP64 EOCD locator (0x07064b50) 20 B before EOCD; read z64 EOCD */
        ... cdoff = rd64le(z64+48); cdsz = (uint32_t) rd64le(z64+40);
            nrec = (uint16_t) rd64le(z64+32); ...
    }
    ngx_free(buf);
    /* 3) bounds-check + read the central directory */
    if (cdoff + cdsz > (uint64_t) sz || cdsz > ZIP_CD_MAX) return NGX_ERROR;
    u_char *cd = ngx_alloc(cdsz, log); if (!cd) return NGX_ERROR;
    if (pread_full(fd, cd, cdsz, cdoff) != (ssize_t) cdsz) { ngx_free(cd); return NGX_ERROR; }
    /* 4) walk CDFH records */
    size_t p = 0;
    for (uint16_t i = 0; i < nrec && p + 46 <= cdsz; i++) {
        if (rd32le(cd+p) != 0x02014b50u) { ngx_free(cd); return NGX_ERROR; }
        uint16_t meth = rd16le(cd+p+10), bits = rd16le(cd+p+8);
        uint16_t fn = rd16le(cd+p+28), ex = rd16le(cd+p+30), cm = rd16le(cd+p+32);
        if (p + 46 + fn > cdsz) { ngx_free(cd); return NGX_ERROR; }
        if (fn == strlen(member) && memcmp(cd+p+46, member, fn) == 0) {
            if (bits & 0x0008) { ngx_free(cd); return NGX_ERROR; } /* data descriptor */
            out->method = meth; out->crc32 = rd32le(cd+p+16);
            out->comp_size = rd32le(cd+p+20); out->uncomp_size = rd32le(cd+p+24);
            uint64_t lhdr = rd32le(cd+p+42);
            zip_parse_zip64_extra(cd+p+46+fn, ex, out, &lhdr); /* promote 0xFFF.. */
            ngx_free(cd);
            return zip_resolve_data_off(fd, sz, lhdr, out);     /* read LFH */
        }
        p += 46 + fn + ex + cm;
    }
    ngx_free(cd);
    return NGX_DECLINED;
}
```
*(The `goto bad` above is a sketch shorthand — the real implementation uses an
early-return cleanup helper per the no-`goto` rule.)*

### B3.3 `xrootd_zip_read` (stored fast path + deflate stream)
```c
ngx_int_t xrootd_zip_read(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                          int64_t off, size_t want)
{
    xrootd_file_t *fh = &ctx->files[idx];
    if ((uint64_t) off >= fh->zip_uncomp_size) return xrootd_send_ok(ctx, c, NULL, 0);
    if (off + want > fh->zip_uncomp_size) want = fh->zip_uncomp_size - off;

    if (fh->zip_method == 0) {                       /* STORED: offset add */
        u_char *b = ngx_palloc(c->pool, want);
        ssize_t n = pread_full(fh->fd, b, want, fh->zip_data_off + off);
        if (n < 0) return xrootd_send_error(ctx, c, kXR_IOError, "zip read");
        return xrootd_send_ok(ctx, c, b, n);
    }
    /* DEFLATE: ensure stream positioned at off (re-open + skip on backward seek) */
    if (!fh->zip_inflate || (uint64_t) off < fh->zip_logical_pos)
        zip_inflate_reset(fh);                       /* opens codec, pos=0 */
    if ((uint64_t) off > fh->zip_logical_pos)
        zip_inflate_skip(fh, off - fh->zip_logical_pos);  /* bounded */
    u_char *out = ngx_palloc(c->pool, want); size_t got = 0;
    while (got < want) {
        u_char cin[64*1024]; size_t ip = 0, op = 0;
        size_t cn = pread_full(fh->fd, cin,
                       MIN(sizeof cin, fh->zip_comp_size - fh->zip_comp_pos),
                       fh->zip_data_off + fh->zip_comp_pos);
        xrootd_codec_rc_t rc = xrootd_codec_step(fh->zip_inflate, cin, cn, &ip,
                                   out+got, want-got, &op, cn == 0);
        fh->zip_comp_pos += ip; got += op; fh->zip_logical_pos += op;
        if (rc == XROOTD_CODEC_ERR_BOMB) return xrootd_send_error(ctx,c,kXR_IOError,"zip bomb");
        if (rc < 0)  return xrootd_send_error(ctx, c, kXR_IOError, "zip inflate");
        if (rc == XROOTD_CODEC_END) break;
    }
    return xrootd_send_ok(ctx, c, out, got);
}
```

### B3.4 lock encode/decode v2 — see B2.5 (encode) and the decode guard description.

## B4. Config directives — exact `ngx_command_t` + merge

### W1 (stream, `src/stream/module.c` commands array; mirror `xrootd_upstream_tls:920`)
```c
    { ngx_string("xrootd_tpc_delegate"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_delegate),
      NULL },
    { ngx_string("xrootd_tpc_outbound_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_outbound_tls),
      NULL },
```
Struct fields (`ngx_flag_t tpc_delegate, tpc_outbound_tls;`), init `NGX_CONF_UNSET`,
merge in `merge_srv_conf`:
```c
    ngx_conf_merge_value(conf->tpc_delegate,     prev->tpc_delegate,     0);
    ngx_conf_merge_value(conf->tpc_outbound_tls, prev->tpc_outbound_tls, 0);
```

### W2 (WebDAV+stream loc/srv; gate read-side in `src/read`)
```c
    { ngx_string("xrootd_zip_access"),     ... offsetof(..., zip_access),     NULL },
    { ngx_string("xrootd_zip_verify_crc"), ... offsetof(..., zip_verify_crc), NULL },
    { ngx_string("xrootd_zip_cd_max_bytes"),
      NGX_..._CONF | NGX_CONF_TAKE1, ngx_conf_set_size_slot, ...,
      offsetof(..., zip_cd_max_bytes), NULL },
```
Merge: `ngx_conf_merge_value(...,0)` for the flags;
`ngx_conf_merge_size_value(conf->zip_cd_max_bytes, prev->..., 16*1024*1024)`.

## B5. Error mapping per feature

| Feature | Internal cause | root:// (`kXR_*`) | HTTP |
|---|---|---|---|
| W1 outbound auth | runaway authmore (>MAX_ROUNDS) | `kXR_AuthFailed` | n/a (server-internal) |
| W1 delegation | missing/expired delegated proxy | `kXR_AuthFailed` (no fallback when on) | n/a |
| W1 TLS | origin needs TLS, `tpc_outbound_tls off` | `kXR_AuthFailed` (err: set directive) | n/a |
| W2 zip | member not found | `kXR_NotFound` | 404 |
| W2 zip | corrupt CD / OOB / data-descriptor | `kXR_IOError` | 500 |
| W2 zip | deflate bomb | `kXR_IOError` ("zip bomb") | 500 |
| W2 zip | write/truncate on member | `kXR_NotAuthorized` | 403 |
| W2 zip | pgread/readv on deflate member | `kXR_Unsupported` (or plain fallback) | 416/200 |
| W3 lock | conflicting lock | n/a | 423 Locked |
| W3 lock | xattr encode/setxattr fail | n/a | 500 |
| W3 lock | XATTR_CREATE race | n/a | 423 |

(Uses the canonical errno→kXR→HTTP table in CLAUDE.md; no new mappings invented.)

## B6. Task & effort checklist (ordered; rough engineer-days)

**W3 — lock hardening (≈3–4 d)**
- [ ] `webdav.h`: `expires_wall:int64_t`, `is_null:1`; bump MAXLEN if W3.3.b (0.5)
- [ ] `prop_xattr.c`: v2 encode/decode + legacy-drop guard (1)
- [ ] `lock.c`: 5 comparison swaps + remaining-secs math (0.5)
- [ ] `locks/request.c` + `.h`: wall-clock timeout signature (0.25)
- [ ] lock-null reaping on unlock/expiry + PUT/MKCOL clear-null (1)
- [ ] (optional W3.3.b) shared-holder array (1.5)
- [ ] tests: 8 cases incl. reload/reboot survival (1)

**W2 — ZIP member access (≈6–9 d)**
- [ ] `src/zip/zip_dir.{c,h}`: EOCD/ZIP64/CDFH/LFH reader + LRU (2.5)
- [ ] `file.h` fields + **full rebuild**; handle lifecycle in `zip_member.{c,h}` (1)
- [ ] `open_request.c`: `open_negotiate_zip_member` + dispatch (0.5)
- [ ] read/readv/pgread/stat/close branches; stored zero-copy (1.5)
- [ ] deflate sequential inflate via codec_core + bomb guard (1.5)
- [ ] WebDAV/S3 GET member path (1)
- [ ] tests: 11 cases incl. ZIP64, bomb, traversal, corrupt CD (1.5)
- [ ] (follow-up) deflate random-access checkpoints (2)

**W1 — TPC delegation (≈8–12 d, highest risk)**
- [ ] `auth_handshake.{c,h}`: state machine + ztn/GSI continuations (2.5)
- [ ] refactor `upstream/bootstrap.c` + remove `authmore_count` (1)
- [ ] refactor `tpc/thread.c`+`finish_login` onto driver (1)
- [ ] TPC pull `kXR_gotoTLS` upgrade (`tpc/bootstrap.c`,`connect.c`) (1)
- [ ] `key_registry.{h,c}`: proxy-blob slot + attach/take (0.5)
- [ ] `gsi_core`: `build_pxyreq`/`parse_sigpxy` (delegation crypto) (2.5) ⚠ highest risk
- [ ] `gsi/auth.c`: inbound 3rd round capture (1.5)
- [ ] directives + merge (`tpc_delegate`,`tpc_outbound_tls`) (0.25)
- [ ] tests: 7 cases incl. GSI-TLS origin, identity, bounded loop (2) — needs real GSI origin

**Cross-cutting (all):** update each touched `src/*/README.md`; fix
`docs/10-reference/gaps-vs-xrootd.md`; retire stale OAK lock-table memories.

---
---

# Part C — File skeletons, build wiring, test skeletons, runbook

> The headers below are **complete and compilable** intent — drop-in starting
> points that already carry the WHAT/WHY/HOW docblocks the coding standard
> requires. The `.c` bodies follow the pseudocode in Part B.

## C0. Build wiring — the real source list is `./config`, NOT `src/core/config/config.h`

⚠️ **Correction to CLAUDE.md "BUILD GOVERNANCE":** the module's compiled source
list lives in the top-level nginx-addon script **`./config`** (entries of the
form `$ngx_addon_dir/src/<path>.c \` appended to the per-feature srcs shell
variables — e.g. the TPC block at `config:565-581`). `src/core/config/config.h` holds
config-field/command declarations, not the file list. A new `.c` must be added to
`./config` and then `./configure` re-run, or it will not compile.

**Exact additions to `./config`:**
```sh
# W1 — after config:572 ($ngx_addon_dir/src/tpc/bootstrap.c \), in the same block:
    $ngx_addon_dir/src/upstream/auth_handshake.c \
# (auth_handshake.c is shared by the upstream + tpc blocks; add once to the
#  variable that both link, or to each srcs list that references upstream/tpc.)

# W2 — add a new ZIP block near the read sources (config:750 region):
    $ngx_addon_dir/src/zip/zip_dir.c \
    $ngx_addon_dir/src/zip/zip_member.c \
```
Headers (`.h`) are added to the `*_DEPS`/header lists (e.g. the
`webdav/locks/request.h` entry at `config:407`); they do not compile on their own
but trigger rebuilds. After editing `./config`:
```sh
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
            --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)
```

## C1. `src/upstream/auth_handshake.h` (complete)
```c
/*
 * auth_handshake.h — shared outbound XRootD auth state machine (W1).
 *
 * WHAT: One driver that completes a multi-round kXR_authmore exchange on an
 *       outbound connection, for BOTH the read-through cache-fill path
 *       (src/upstream/bootstrap.c) and the native-TPC pull path (src/tpc/). It
 *       selects an auth method from the server's &P= login parameter block and
 *       emits the next kXR_auth credential payload each round until kXR_ok.
 * WHY:  Today cache-fill rejects a 2nd kXR_authmore (bootstrap.c) so no GSI
 *       origin works, and TPC pull hard-codes a fixed 2-round GSI flow — two
 *       divergent implementations. A single bounded driver fixes multi-round
 *       cache-fill and is the seam where an inbound-delegated X.509 proxy is
 *       used instead of the module cert.
 * HOW:  xrootd_oba_select() parses the anchored &P= list (sec_protocol.h) and the
 *       locally-available credentials into a method. xrootd_oba_step() consumes a
 *       server authmore body and produces the next credential; the GSI
 *       continuation indexes its sub-state by ->round (round 0 = certreq, round 1
 *       = DH cert exchange) reusing the gsi_core kernel. A round cap bounds
 *       hostile authmore loops. The caller frames each payload with the existing
 *       writer (tpc_send_kxr_auth / the upstream frame writer) and frees it.
 */
#ifndef XROOTD_UPSTREAM_AUTH_HANDSHAKE_H
#define XROOTD_UPSTREAM_AUTH_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

#define XRD_OBA_MAX_ROUNDS 8          /* hard cap on kXR_authmore rounds */
#define XRD_OBA_ERR_MAX    256

typedef enum { XRD_OBA_INIT, XRD_OBA_CONT, XRD_OBA_DONE, XRD_OBA_FAIL }
        xrootd_oba_phase_t;
typedef enum { XRD_OBA_M_NONE, XRD_OBA_M_ZTN, XRD_OBA_M_GSI }
        xrootd_oba_method_t;

typedef struct {
    xrootd_oba_method_t method;
    int                 round;        /* 0-based; bounded by MAX_ROUNDS */
    void               *mstate;       /* method-private (GSI cert/DH); freed by _free */

    /* credentials available locally (filled before _select): */
    const char         *bearer;       /* ztn token (delegated or "<file>") */
    const char         *cert, *key, *castore;  /* GSI module cert paths */
    const unsigned char *deleg_proxy; /* inbound-delegated PEM proxy; NULL = none */
    size_t              deleg_proxy_len;

    char                err[XRD_OBA_ERR_MAX];  /* set on XRD_OBA_FAIL */
} xrootd_oba_ctx_t;

/* Pick a method from the server &P= parms + local creds (ztn preferred, GSI
 * fallback — same policy as the former gsi_outbound_finish.c). Returns the chosen
 * method or XRD_OBA_M_NONE (with ->err set) when nothing is usable. */
xrootd_oba_method_t xrootd_oba_select(xrootd_oba_ctx_t *c,
                                      const char *parms, size_t parms_len);

/* Drive one round. authmore_body/len is the server's last reply payload (the
 * kXR_login authmore body on the first call; NULL/0 is valid for the ztn
 * one-shot). On XRD_OBA_CONT/XRD_OBA_DONE *out_cred/*out_len hold a malloc'd
 * credential to frame+send (may be NULL when no payload is due). The caller frees
 * *out_cred. Returns CONT (expect another authmore), DONE (expect kXR_ok), or
 * FAIL (->err set). */
xrootd_oba_phase_t xrootd_oba_step(xrootd_oba_ctx_t *c,
                                   const unsigned char *authmore_body, size_t len,
                                   unsigned char **out_cred, uint32_t *out_len);

/* Release ->mstate (idempotent; tolerates a zeroed ctx). */
void xrootd_oba_free(xrootd_oba_ctx_t *c);

#endif /* XROOTD_UPSTREAM_AUTH_HANDSHAKE_H */
```

## C2. `src/zip/zip_dir.h` (complete)
```c
/*
 * zip_dir.h — ZIP central-directory reader for member access (W2).
 *
 * WHAT: Resolves a single member of a ZIP archive (by name) to its on-disk byte
 *       range and metadata, by reading the End-Of-Central-Directory, optional
 *       ZIP64 records, the central directory, and the member's local file header.
 * WHY:  ZIP member access (xrdcl.unzip=) serves one file inside an archive as a
 *       standalone object. This is the read-only locator; the byte serving lives
 *       in zip_member.c. Matches XrdZip semantics (stored + deflate).
 * HOW:  pread-only, fully bounds-checked against archive_size. Tail-scan for the
 *       EOCD signature; promote to ZIP64 when 32-bit fields are 0xFFFFFFFF/0xFFFF;
 *       walk signature-checked CDFH records; reject data-descriptor entries
 *       (size unknown at open); read the LFH to compute the true data offset.
 *       Parsed results are cached per-worker keyed by (path, mtime, size).
 */
#ifndef XROOTD_ZIP_DIR_H
#define XROOTD_ZIP_DIR_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <sys/types.h>
#include <stdint.h>
#include <limits.h>

#define XROOTD_ZIP_METHOD_STORE   0
#define XROOTD_ZIP_METHOD_DEFLATE 8

typedef struct {
    char      name[PATH_MAX];
    uint16_t  method;        /* 0 store / 8 deflate */
    uint64_t  comp_size;
    uint64_t  uncomp_size;
    uint64_t  data_off;      /* archive offset of first data byte (post-LFH) */
    uint32_t  crc32;         /* expected IEEE CRC-32 of uncompressed data */
} xrootd_zip_member_t;

/* Resolve `member` within the archive open on `fd` (size `sz`). Returns:
 *   NGX_OK       — found; *out filled
 *   NGX_DECLINED — archive parsed but no such member
 *   NGX_ERROR    — corrupt/oversize/unsupported (data descriptor) / I/O error
 * Never reads outside [0, sz). `cd_max` caps the central-directory read. */
ngx_int_t xrootd_zip_find_member(int fd, off_t sz, const char *member,
                                 size_t cd_max, xrootd_zip_member_t *out,
                                 ngx_log_t *log);

#endif /* XROOTD_ZIP_DIR_H */
```

## C3. `src/zip/zip_member.h` (complete)
```c
/*
 * zip_member.h — ZIP member virtual-handle I/O (W2).
 *
 * WHAT: Open/read/stat/close for a ZIP member served as a standalone file over a
 *       single archive fd. Stored members are pure offset translation (zero-copy,
 *       readv/pgread-capable); deflate members stream-inflate via codec_core.
 * WHY:  Keeps the read/readv/pgread/stat/close opcode handlers thin — they branch
 *       once on fh->zip_mode and delegate here. Read-only by construction.
 * HOW:  xrootd_zip_open_member() fills the zip_* fields of xrootd_file_t from
 *       xrootd_zip_find_member(). xrootd_zip_read() adds zip_data_off for stored
 *       members, or pumps compressed bytes through a DEFLATE codec stream
 *       (bomb-guarded, out_cap = uncomp_size) for deflate. readv/pgread on a
 *       deflate member are rejected (kXR_Unsupported). All writes → kXR_NotAuthorized.
 */
#ifndef XROOTD_ZIP_MEMBER_H
#define XROOTD_ZIP_MEMBER_H

#include "../types/context.h"   /* xrootd_ctx_t, xrootd_file_t */

/* Build a zip_mode handle in ctx->files[idx] for `member` of the archive already
 * open on archive_fd (sz = archive size). Returns NGX_OK / NGX_DECLINED (no such
 * member → caller sends kXR_NotFound) / NGX_ERROR (corrupt → kXR_IOError). */
ngx_int_t xrootd_zip_open_member(xrootd_ctx_t *ctx, int idx, int archive_fd,
                                 off_t sz, const char *member,
                                 size_t cd_max, ngx_log_t *log);

/* kXR_read on a zip_mode handle (stored offset-add or deflate inflate). */
ngx_int_t xrootd_zip_read(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                          int64_t off, size_t want);

/* Fill stat for a zip_mode handle from cached metadata (uncomp_size). */
ngx_int_t xrootd_zip_stat(xrootd_ctx_t *ctx, int idx, struct stat *st);

/* Release the inflate stream (if any). Called from kXR_close / free_fhandle. */
void xrootd_zip_close(xrootd_file_t *fh);

#endif /* XROOTD_ZIP_MEMBER_H */
```

## C4. `src/zip/README.md` (skeleton)
```markdown
# src/zip — ZIP member access (read-only)

Serves one file inside a ZIP archive as a standalone object across root://,
WebDAV, and S3 GET (opaque `xrdcl.unzip=<member>`).

- `zip_dir.c` — central-directory reader (EOCD/ZIP64/CDFH/LFH); pure, pread-only,
  bounds-checked. Entry: `xrootd_zip_find_member()`.
- `zip_member.c` — virtual handle I/O over the archive fd. Stored = offset add
  (zero-copy, readv/pgread); deflate = streaming inflate via `../compat/codec_core.h`
  (bomb-guarded). Read-only.

Invariants: never reads outside the archive; pgread/readv rejected on deflate
members; writes → kXR_NotAuthorized/403; data-descriptor entries rejected (size
unknown at open). Gate: `xrootd_zip_access` (default off). See
`docs/refactor/phase-57-tpc-delegation-zip-locks.md` (W2).
```

## C5. Test skeletons (one representative per workstream; pytest)

### C5.1 `tests/test_zip_member.py` (representative)
```python
import subprocess, zipfile, os
import pytest
from helpers import xrdcp_get, http_get  # existing harness helpers

@pytest.fixture
def zip_archive(tmp_export):           # tmp_export = a path under the export root
    p = os.path.join(tmp_export, "a.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("dir/x.txt", b"hello-stored", compress_type=zipfile.ZIP_STORED)
        z.writestr("dir/y.txt", os.urandom(1 << 20), compress_type=zipfile.ZIP_DEFLATED)
    return p

def test_zip_stored_member_bytes(zip_archive, root_url):
    got = xrdcp_get(f"{root_url}//a.zip?xrdcl.unzip=dir/x.txt")
    assert got == b"hello-stored"

def test_zip_deflate_member_bytes(zip_archive, root_url):
    with zipfile.ZipFile(zip_archive) as z:
        want = z.read("dir/y.txt")
    assert xrdcp_get(f"{root_url}//a.zip?xrdcl.unzip=dir/y.txt") == want

@pytest.mark.parametrize("evil", ["../../etc/passwd", "/etc/passwd", "x\x00y"])
def test_zip_member_traversal_rejected(zip_archive, root_url, evil):
    with pytest.raises(Exception):           # kXR_NotFound / kXR_ArgInvalid
        xrdcp_get(f"{root_url}//a.zip?xrdcl.unzip={evil}")

def test_zip_member_write_rejected(zip_archive, root_url):
    rc = subprocess.run(["xrdcp", "/etc/hostname",
                         f"{root_url}//a.zip?xrdcl.unzip=dir/x.txt"]).returncode
    assert rc != 0                            # kXR_NotAuthorized
```

### C5.2 `tests/test_http_webdav_lock.py::test_lock_survives_reload` (representative)
```python
def test_lock_survives_reload(webdav_url, nginx_ctl, dav):
    tok = dav.lock(f"{webdav_url}/f.txt")["lock_token"]   # 201 + token
    nginx_ctl("reload")                                   # SIGHUP, same boot
    # Another client cannot write without the token:
    assert dav.put(f"{webdav_url}/f.txt", b"x").status == 423
    # The holder still can:
    assert dav.put(f"{webdav_url}/f.txt", b"x", if_token=tok).status in (200, 204)

def test_lock_expiry_wallclock(webdav_url, nginx_ctl, dav):
    dav.lock(f"{webdav_url}/g.txt", timeout="Second-2")
    nginx_ctl("restart")                                  # new process (reboot-like)
    time.sleep(3)
    assert dav.put(f"{webdav_url}/g.txt", b"x").status in (200, 204)  # lock expired
```

### C5.3 `tests/test_tpc_delegation.py::test_tpc_authmore_loop_bounded` (representative, security-neg)
```python
def test_tpc_authmore_loop_bounded(tpc_dest, evil_authmore_origin):
    # evil_authmore_origin replies kXR_authmore forever.
    t0 = time.time()
    rc = tpc_dest.pull(src=evil_authmore_origin.url, dst="/out")
    assert rc != 0                          # bounded reject (kXR_AuthFailed)
    assert time.time() - t0 < 5             # no spin: capped at XRD_OBA_MAX_ROUNDS
    assert evil_authmore_origin.authmore_count <= 8
```

## C6. Verification & rollback runbook

### Build & smoke (every workstream)
```sh
# After ./config edits (W1/W2) or webdav-only edits (W3):
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
            --with-http_dav_module --with-threads --add-module=$REPO
make clean && make -j$(nproc)              # clean rebuild is mandatory after file.h (W2)
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf
tests/manage_test_servers.sh restart
```

### Per-workstream gates
| WS | Pre-merge gate | Differential check |
|---|---|---|
| W1 | `pytest tests/test_tpc_*.py -v` green incl. delegation off (regression) | `XRD_LOGLEVEL=Debug xrdcp --tpc … ` vs stock; packet-capture the kXGS_pxyreq/kXGC_sigpxy round vs a real EOS GSI origin |
| W2 | `pytest tests/test_zip_member.py -v`; bytes == `unzip -p` reference | open the same archive with stock `xrdcp root://…?xrdcl.unzip=` and diff |
| W3 | `pytest tests/test_http_webdav_lock.py -v` incl. reload/restart cases | LOCK→reload→behavior matches RFC 4918 with a real WebDAV client (e.g. `gfal`, `davix`) |

### Rollback (each sub-item is independently revertable)
- **W1** is gated by `xrootd_tpc_delegate off` (default) and `xrootd_tpc_outbound_tls off`;
  the state-machine refactor preserves existing behavior, so reverting = turning the
  flags off (delegation/TLS) or reverting the `auth_handshake.c` commit (the call
  sites fall back to the prior inline logic if the refactor commit is reverted as a unit).
- **W2** is gated by `xrootd_zip_access off` (default). Disable to neutralize all
  member-access code paths without reverting source.
- **W3** has no flag for the expiry fix (it is a correctness bug fix) but the schema
  is forward-only: a `v=2` lock written by the new code is treated as *expired* by
  old code (which sees an unparseable `expires`), so a downgrade safely releases
  locks rather than corrupting them. `xrootd_webdav_lock_startup_sweep on` clears all
  locks if a clean slate is wanted after rollback.

### Observability hooks (reuse existing)
- W1: `XROOTD_*_METRIC_INC` on the TPC op counters; access-log the source identity
  (user DN vs gateway DN) to confirm delegation.
- W2: `OP_READ`/`OP_OPEN` metrics already cover member reads; add a low-cardinality
  `zip_member{result}` counter (NOT member names — INVARIANT #8).
- W3: existing WebDAV op metrics + access log; assert 423 vs 200 transitions.

---
---

# Part D — Formal behavior: state machines, edge cases, ownership, byte traces

> This part pins down behavior that prose leaves ambiguous: exact state×event
> tables, exhaustive corner-case matrices (the test oracle), buffer
> ownership/threading, and annotated wire bytes. Writing the W1 state table
> exposed a real bug in the §B3.1 sketch — see D1.1.

## D1. State-transition tables

### D1.1 Outbound auth state machine (`xrootd_oba_*`)

**Correction to §B3.1:** the loop must terminate on the **received** `kXR_ok`, not
on a step-returned `DONE`. The clean model: `xrootd_oba_step()` returns `CONT`
whenever it emits a credential that expects a server reply, and the **caller's
recv** is the sole terminator (`kXR_ok`→success, `kXR_authmore`→feed back,
else→fail). `DONE` is therefore vestigial — drop the early `return 0` on `DONE` in
§B3.1; always send → recv → branch. (ztn's single credential still gets its
final `kXR_ok` confirmed this way, matching the original `tpc_outbound_ztn`.)

Formal table (state = `(method, round)`; the recv result drives transitions):

| State | Event (server reply) | Action | Next state |
|---|---|---|---|
| `(—, —)` INIT | login → `kXR_authmore(&P=…)` | `oba_select` → method | `(method, 0)` |
| `(ztn, 0)` | — (drive) | emit `"ztn\0"+token`, send | recv |
| `(ztn, 0)` after send | `kXR_ok` | — | **SUCCESS** |
| `(ztn, 0)` after send | `kXR_error`/other | fail | **FAIL** `kXR_AuthFailed` |
| `(gsi, 0)` | — (drive) | emit `kXGC_certreq` (`build_certreq`, opts incl. DlgPxy if delegating), send | recv |
| `(gsi, 0)` after send | `kXR_authmore(kXGS_init)` | — | `(gsi, 1)` |
| `(gsi, 1)` | `kXGS_init` (DH+srvcert+rtag) | derive cipher, emit `kXGC_cert` (DH-enc chain, signed by **deleg_proxy** if set else module key), send | recv |
| `(gsi, 1)` after send | `kXR_ok` | — | **SUCCESS** |
| `(gsi, 1)` after send | `kXR_authmore(kXGS_pxyreq)` | *(dest pull role does not sign here; delegation is consumed inbound)* fail | **FAIL** |
| any | `kXR_authmore` with `round+1 ≥ XRD_OBA_MAX_ROUNDS` | fail | **FAIL** (bounded) |
| any | send/recv I/O error | fail | **FAIL** `kXR_ServerError` |

### D1.2 Inbound GSI server handshake with delegation (`src/gsi/auth.c`)

Current server recognizes only the first two rows; W1.4.c adds the last two
(gated by `xrootd_tpc_delegate on`). `step` = client `kXGC_*` value at
`auth.c:235`.

| Server state | Client step in | Action | Server step out | Next |
|---|---|---|---|---|
| fresh | `kXGC_certreq` (1000) | `xrootd_gsi_send_cert` (DH params+srvcert+rtag) | `kXGS_init` (2000) | await cert |
| await cert | `kXGC_cert` | `xrootd_gsi_parse_x509`, verify chain, extract DN/VOMS | — | **delegation off:** `auth_done=1` |
| await cert (deleg on) | `kXGC_cert` | verify chain **+** `xrootd_gsi_build_pxyreq` (new keypair+CSR) | `kXGS_pxyreq` (2002) | await sigpxy |
| await sigpxy | `kXGC_sigpxy` (1002) | `xrootd_gsi_parse_sigpxy` → assemble deleg proxy PEM → stash for key registry | — | `auth_done=1` |
| await sigpxy | anything else | reject (`auth.c:254-258` path) | — | **FAIL** |

### D1.3 WebDAV lock lifecycle (resource state)

| Resource state | Request | Guard | Result / next state |
|---|---|---|---|
| absent | `LOCK` | — | create 0-byte + xattr(`null=1`) → **lock-null** (201) |
| present-unlocked | `LOCK` | `XATTR_CREATE` ok | **locked** (201) |
| present-unlocked | `LOCK` | `XATTR_CREATE` EEXIST (race) | **locked-by-other** (423) |
| locked | `LOCK` same token | `If:` matches | refresh expiry, stay **locked** (200) |
| locked | `LOCK` other token | `If:` no match, not expired | **locked** (423) |
| locked | `LOCK` | expired (`expires_wall ≤ now`) | delete xattr → treat as unlocked → **locked** (201) |
| lock-null | `PUT`/`MKCOL` holder | `If:` matches | clear `null`, write data → **locked** (real) |
| lock-null | `UNLOCK`/expiry, still 0-byte | — | unlink placeholder → **absent** |
| locked | `UNLOCK` matching token | header present | delete xattr → **unlocked** |
| locked | `UNLOCK` wrong/no token | — | 400/409, stay **locked** |
| locked | reload (SIGHUP) | — | survives (xattr, same boot) |
| locked | restart/reboot past expiry | wall-clock | released on next access |

## D2. Exhaustive edge-case matrices (test oracle)

### D2.1 ZIP member (W2)
| Input / condition | Expected (`kXR_*` / HTTP) | Notes |
|---|---|---|
| member present, stored | OK; bytes == reference | zero-copy; readv/pgread OK |
| member present, deflate | OK; bytes == reference | sequential fast path |
| member not found | `kXR_NotFound` / 404 | |
| member name empty | `kXR_ArgInvalid` / 400 | |
| member name `../…`, absolute, embedded NUL | `kXR_ArgInvalid` / 400 | reject pre-resolve |
| **duplicate names in CD** | **last entry wins** | match XrdZip `cdmap[name]=i` overwrite semantics |
| name ends in `/` (dir entry) | `kXR_NotFound` (not a file) | dir entries have 0 data |
| zero-length stored member | OK; 0 bytes, EOF | `data_off` valid, size 0 |
| encrypted entry (genFlag bit 0) | `kXR_Unsupported` / 501 | no crypto |
| method ∉ {0,8} (e.g. 12/14) | `kXR_Unsupported` / 501 | bzip2/lzma not served |
| data-descriptor entry (genFlag bit 3) | `kXR_IOError` / 500 | size unknown at open |
| ZIP64 (size/offset/count overflow) | OK | promote via extra/locator |
| archive < 22 bytes / no EOCD | `kXR_IOError` / 500 | not a zip |
| corrupt CDFH sig / oversize lengths | `kXR_IOError` / 500 | bounds-checked, no OOB |
| CD larger than `zip_cd_max_bytes` | `kXR_IOError` / 500 | bomb guard on directory |
| pgread/readv on deflate member | `kXR_Unsupported` (or plain fallback) | documented |
| write/pgwrite/truncate/sync on member | `kXR_NotAuthorized` / 403 | read-only |
| archive mtime changes between opens | re-parse (LRU key = path,mtime,size) | open handle keeps its snapshot |
| deflate CRC mismatch (verify on) | `kXR_ChkSumErr` | opt-in only |

### D2.2 WebDAV lock (W3) — `Timeout`/`Depth` parsing (per `request.c`)
| Header | Parsed value |
|---|---|
| `Timeout` absent | 3600 s, then capped to `lock_timeout` |
| `Timeout: Second-N` | N, capped to `[1, lock_timeout]` |
| `Timeout: Infinite` | `lock_timeout` |
| `Timeout: Second-0` | clamped to 1 |
| `Timeout: garbage` | 3600 (fallback) |
| `Depth` absent | infinity |
| `Depth: 0` | shallow |
| `Depth: infinity` | recursive |
| `Depth: 1` | **400 Bad Request** |

### D2.3 Outbound auth selection (W1) — `xrootd_oba_select`
| Server `&P=` | Local creds | Chosen | If chosen fails |
|---|---|---|---|
| `ztn` | bearer | ztn | FAIL (no gsi to fall back) |
| `gsi` | cert | gsi | FAIL |
| `ztn,gsi` | bearer+cert | ztn | fall back to gsi |
| `ztn,gsi` | cert only | gsi | FAIL |
| `gsi` | none | — | FAIL `kXR_AuthFailed` immediately |
| `ztn` | none | — | FAIL |
| (delegation on) `gsi` | deleg_proxy present | gsi (signs w/ proxy) | FAIL, **no** silent module-cert fallback |
| (delegation off) `gsi` | cert | gsi (signs w/ module cert) | FAIL |

## D3. Memory ownership, lifetime & threading

| Buffer / object | Allocator | Freed by | Thread / context |
|---|---|---|---|
| `oba` `out_cred` payload | `malloc` (off-loop) | caller after `tpc_send_kxr_auth` | TPC pool thread |
| `oba.mstate` (GSI keys/DH) | `xrootd_oba_step` (OpenSSL) | `xrootd_oba_free` | TPC pool thread / event (upstream) |
| upstream `oba` payload | `ngx_alloc` (event loop) | after frame write | event thread (non-blocking per round) |
| key-registry `proxy_pem` | SHM (static slot) | zeroed on `key_consume`/TTL | any worker, **under SHM spin mutex** (INV #10) |
| ZIP central-dir buffer | `ngx_alloc` | `ngx_free` before return | event thread (open) |
| ZIP read output buffer | `ngx_palloc(c->pool)` | connection pool teardown | event thread |
| `zip_inflate` codec stream | `xrootd_codec_open` (malloc) | `xrootd_zip_close` (on kXR_close/free_fhandle) | event thread |
| lock xattr scratch | stack (`WEBDAV_LOCK_XATTR_MAXLEN`) | n/a | event thread (HTTP) |

**Concurrency notes:**
- **TPC pull** runs entirely on `ngx_thread_pool` (`thread.c:18`); `malloc` is
  correct there (it is off the event loop). The whole `oba` loop is single-owner
  on that thread — no shared mutable state.
- **Cache-fill `oba`** runs on the **event loop**: each `xrootd_oba_step` is one
  round between async reads (the state machine is re-entered per `kXR_authmore`
  reply, never blocking across rounds). The only blocking work inside a step is
  CPU-bound OpenSSL (small, acceptable).
- **ZIP LRU** is **per-worker** (no cross-worker sharing) → no lock. Each open
  handle holds an independent inflate stream; concurrent reads of the same archive
  are independent `pread`s.
- **Lock xattr** create is kernel-atomic (`XATTR_CREATE`). The W3.3.b shared-holder
  read-modify-write must re-read on `EEXIST`/lost race before retrying `XATTR_REPLACE`.
- **Key-registry proxy blob** copy in/out happens under the table's spin+yield
  mutex created via `xrootd_shm_table_alloc` (INVARIANT #10 — never POSIX-sem).

## D4. Annotated wire/byte traces (illustrative, structurally exact)

### D4.1 `kXR_open` with unzip opaque (client → server)
```
ClientRequestHdr (24 B) + path payload      ; all fields big-endian (network order)
 00 01            streamid[2]
 0b c2            requestid = kXR_open (3010 = 0x0BC2)        ; XProtocol.hh:123
 00 00            mode   (kXR_ur/kXR_uw etc; 0 for read)
 00 10            options = kXR_open_read (0x0010); no write bits → is_write=0
 00*12            reserved[12]
 00 00 00 21      dlen = 33  (length of path below)
 "/data/a.zip?xrdcl.unzip=dir/x.txt"        ; 33 bytes, NOT NUL-terminated
                                            ; extract.c strips at '?' for open();
                                            ; open_negotiate_zip_member() reads the opaque
```

### D4.2 ZIP EOCD record (little-endian; tail of archive)
```
50 4b 05 06   signature 0x06054b50
00 00         nbDisk
00 00         nbDiskCd
01 00         nbCdRecD   = 1
01 00         nbCdRec    = 1   (offset 10)
4e 00 00 00   cdSize     = 78  (offset 12)
a2 00 00 00   cdOffset   = 162 (offset 16)
00 00         commentLength = 0
```
(If `cdOffset==FF FF FF FF` or `nbCdRec==FF FF` → read the ZIP64 EOCD locator
`50 4b 06 07` sitting 20 B before this record; its `@8` u64 points at the ZIP64
EOCD `50 4b 06 06` whose `@48` u64 is the real `cdOffset`.)

### D4.3 ZIP CDFH record (the member entry)
```
50 4b 01 02   signature 0x02014b50
3f 00         zipVersion
0a 00         minZipVersion
00 00         generalBitFlag      (bit0=encrypted, bit3=data-descriptor → reject)
08 00         compressionMethod=8 (deflate)        (offset 10)
…             dos time/date
xx xx xx xx   ZCRC32                               (offset 16)
yy yy yy yy   compressedSize                       (offset 20)
zz zz zz zz   uncompressedSize                     (offset 24)
09 00         filenameLength = 9                   (offset 28)
00 00         extraLength    = 0                   (offset 30)
00 00         commentLength  = 0                   (offset 32)
…             disk/attrs
ww ww ww ww   offset of LFH                        (offset 42)
"dir/x.txt"   filename (9 bytes)                   (offset 46)
```
Resolve: `pread` LFH at `offset` (sig `50 4b 03 04`), read its own
`filenameLength@26` + `extraLength@28`, then
`data_off = LFH_offset + 30 + lfh.fnLen + lfh.exLen`.

### D4.4 GSI XrdSutBuffer (one kXR_auth body) — wrapped in a kXR_auth frame
```
ClientRequestHdr (24 B): requestid = kXR_auth (3000 = 0x0BB8)  ; credtype "gsi\0" @ body+12
XrdSutBuffer body:
"gsi\0"                       name (NUL-terminated)
00 00 03 e8                  step = 1000 (kXGC_certreq)   [big-endian; 1000=0x3E8]
00 00 0b bb  00 00 00 LL  ……  bucket: type[4 BE]=kXRS_cipher_alg(3025) len[4 BE]=LL data[LL]
   …repeated buckets (kXRS_cryptomod=3000, kXRS_main=3001, kXRS_x509=3022,
                      kXRS_clnt_opts=3019, kXRS_rtag=3006 …)
00 00 00 00                  kXRS_none (=0) terminator
```
For delegation the client's `kXRS_clnt_opts`(3019) bucket carries
`Options |= kOptsDlgPxy(1)|kOptsSigReq(4)`; the server replies step
`kXGS_pxyreq=2002` and the client returns step `kXGC_sigpxy=1002` with the signed
proxy in a `kXRS_x509`(3022) bucket. (Encode via `xrootd_gbuf_start(step)` +
`xrootd_gbuf_bucket(type,…)` + `xrootd_gbuf_end()`, `gsi_core.h:31-33`.)

All numeric values above are authoritative — see the constants table in **Part E**.

---
---

# Part E — Authoritative wire constants (resolved from source)

> Every magic number this plan relies on, resolved from the actual headers so the
> implementer copies values, not guesses. **A correction this pass surfaced:**
> earlier drafts wrote `kXGC_certreq=1001`; the module's `src/protocol/gsi.h:21`
> defines it as **1000** (`cert=1001`, `sigpxy=1002`). The W1.3 and D1/D4 tables
> have been corrected to match.

## E1. Request opcodes (`ClientRequestHdr.requestid`, big-endian on wire)
Source: `/tmp/xrootd-src/src/XProtocol/XProtocol.hh:112-146` (enum is sequential
from `kXR_auth=3000`).

| Opcode | Dec | Hex | Used by this plan |
|---|---|---|---|
| `kXR_auth` | 3000 | 0x0BB8 | W1 outbound/inbound GSI/ztn auth frames |
| `kXR_protocol` | 3006 | 0x0BBE | W1 bootstrap (gotoTLS flag in reply) |
| `kXR_login` | 3007 | 0x0BBF | W1 bootstrap |
| `kXR_open` | 3010 | 0x0BC2 | W2 member open; W1 TPC dest detect |
| `kXR_read` | 3013 | 0x0BC5 | W2 stored/deflate member read |
| `kXR_sync` | 3016 | 0x0BC8 | W1 TPC rendezvous drive |
| `kXR_stat` | 3017 | 0x0BC9 | W2 member stat |
| `kXR_close` | 3003 | 0x0BBB | W2 free inflate stream |
| `kXR_readv` | 3025 | 0x0BD1 | W2 (stored ok / deflate reject) |
| `kXR_pgread` | 3030 | 0x0BD6 | W2 (stored ok / deflate reject) |

## E2. GSI handshake steps (`XrdSutBuffer` step word, big-endian)
Source: `src/protocol/gsi.h:18-23` (module-authoritative).

| Step | Dec | Hex | Direction |
|---|---|---|---|
| `kXGC_certreq` | 1000 | 0x03E8 | client→server (round 1) |
| `kXGC_cert` | 1001 | 0x03E9 | client→server (round 2) |
| `kXGC_sigpxy` | 1002 | 0x03EA | client→server (delegation) |
| `kXGS_init` | 2000 | 0x07D0 | server→client |
| `kXGS_cert` | 2001 | 0x07D1 | server→client |
| `kXGS_pxyreq` | 2002 | 0x07D2 | server→client (delegation) |

## E3. GSI bucket type codes (`kXRS_*`, big-endian type word)
Source: `src/protocol/gsi.h:35-51`.

| Bucket | Dec | Purpose (this plan) |
|---|---|---|
| `kXRS_none` | 0 | end-of-message terminator |
| `kXRS_cryptomod` | 3000 | crypto module name ("ssl") |
| `kXRS_main` | 3001 | inner/encrypted main buffer |
| `kXRS_puk` | 3004 | server DH public key blob |
| `kXRS_cipher` | 3005 | DH public params / ciphertext |
| `kXRS_rtag` | 3006 | random challenge tag (proof-of-possession) |
| `kXRS_signed_rtag` | 3007 | signed random tag |
| `kXRS_clnt_opts` | 3019 | **client option flags (delegation bits live here)** |
| `kXRS_x509` | 3022 | **X.509 cert / delegated proxy PEM** |
| `kXRS_issuer_hash` | 3023 | CA subject hash |
| `kXRS_cipher_alg` | 3025 | supported cipher algorithms |

## E4. GSI delegation option bits (`kXRS_clnt_opts` value)
Source: `/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.hh:108-114`.

| Bit | Const | Meaning |
|---|---|---|
| 0x0001 | `kOptsDlgPxy` | client asks to create a delegated proxy |
| 0x0004 | `kOptsSigReq` | client accepts to sign a delegated proxy |
| 0x0008 | `kOptsSrvReq` | server requests a delegated proxy |
| 0x0010 | `kOptsPxFile` | save delegated proxy in a file |
| 0x0040 | `kOptsPxCred` | save delegated proxy as a credential |

W1.4.c outbound certreq sets `clnt_opts |= kOptsDlgPxy|kOptsSigReq` (= 0x0005)
when delegation is on.

## E5. `kXR_open` option bits (`ClientOpenRequest.options`, big-endian)
Source: `/tmp/xrootd-src/src/XProtocol/XProtocol.hh:470-499`.

| Bit | Const | Note |
|---|---|---|
| 0x0002 | `kXR_delete` | write intent |
| 0x0008 | `kXR_new` | create (→ AOP_Create) |
| 0x0010 | `kXR_open_read` | read |
| 0x0020 | `kXR_open_updt` | update (write) |
| 0x0040 | `kXR_async` | xrdcp upload sets this (mkpath trigger) |
| 0x0100 | `kXR_mkpath` | make parent dirs |
| 0x0200 | `kXR_open_apnd` | append (write) |
| 0x0400 | `kXR_retstat` | return stat in open reply |
| 0x8000 | `kXR_open_wrto` | write (truncate) |

`is_write` (open_request.c:155 `xrootd_open_options_is_write`) is the OR of the
write bits (`delete|new|open_updt|open_apnd|open_wrto`). A ZIP-member open is
read-only and **must** be rejected if any write bit is set (W2.4.c).

## E6. ZIP record signatures & key field offsets (little-endian)
Source: `/tmp/xrootd-src/src/XrdZip/*` (verified this phase).

| Record | Signature | Base size | Key fields (offset) |
|---|---|---|---|
| Local File Header | `0x04034b50` | 30 | fnLen@26, exLen@28 → `data_off = off+30+fnLen+exLen` |
| Central Dir File Header | `0x02014b50` | 46 | method@10, crc@16, compSz@20, uncompSz@24, fnLen@28, exLen@30, cmtLen@32, lhdrOff@42, name@46 |
| End Of Central Directory | `0x06054b50` | 22 | nbCdRec@10, cdSize@12, cdOffset@16, cmtLen@20 |
| ZIP64 EOCD locator | `0x07064b50` | 20 | z64EocdOffset@8 (u64) |
| ZIP64 EOCD | `0x06064b50` | 56 | nbCdRec@32, cdSize@40, cdOffset@48 (all u64) |

Overflow sentinels: a 32-bit field == `0xFFFFFFFF` (or 16-bit == `0xFFFF`) means
the true value is in the ZIP64 extra (CDFH `ParseExtra`) or ZIP64 EOCD.
Compression methods used: `0` = stored, `8` = deflate; all others → reject
(`kXR_Unsupported`). General-bit `0x0001` = encrypted (reject), `0x0008` = data
descriptor (reject — size unknown at open).

## E7. errno → kXR (canonical; CLAUDE.md) — features here
| errno | `kXR_*` | HTTP | Where used |
|---|---|---|---|
| ENOENT | `kXR_NotFound` | 404 | W2 member-not-found |
| EACCES/EPERM | `kXR_NotAuthorized` | 403 | W2 write-on-member; W1 deleg denied |
| EINVAL | `kXR_ArgInvalid` | 400 | W2 bad member name |
| EIO | `kXR_IOError` | 500 | W2 corrupt CD / inflate / bomb |
| (n/a) | `kXR_Unsupported` | 501 | W2 method∉{0,8}; pgread on deflate |
| (n/a) | `kXR_AuthFailed` | — | W1 auth/deleg failure, bounded loop |

> With Part E, the byte traces in D4 are authoritative end-to-end; no value in
> this plan is left to "resolve at implementation time."


---
---

# Part F — W1 Implementation Guide (investigation-revised)

> Written after a hands-on attempt on 2026-06-26. This part **supersedes** the
> "current state" claims in W1.1 and re-orders the work: W1 cannot start with the
> delegation crypto (W1.4.c) or even the state-machine refactor (W1.4.a) because
> **the native server-side TPC-over-GSI data path does not work at all today**,
> and the only existing test passes anyway (it exercises a client-side fallback).
> Build the foundation and a *real* gate first; layer delegation on last.

## F0. What is actually broken (verified, with evidence)

Two independent defects sit **beneath** delegation. Both were reproduced with the
self-contained `gsi_tpc` fixture in `tests/test_tpc_gsi_outbound.py` (stock
`xrootd` GSI source + nginx TPC destination + native `xrdcp`).

**Defect 1 — the existing test is not a real gate.**
`test_tpc_pull_over_gsi` runs `xrdcp --tpc first`. `--tpc first` **falls back to a
client-mediated copy** when server-side TPC fails: the client (which holds a valid
proxy) reads the GSI source itself and writes to the dest. So the test returns
rc=0 and the file lands **without the destination ever doing a server-side pull**.
Proof: a copy of the test forced to `--tpc only` (no fallback) fails with
**rc=54**, and the destination's `error_log … debug` shows **no TPC/GSI/pull
activity** — only startup lines.

**Defect 2 — the destination never initiates the outbound pull, and even if it
did, the GSI handshake is half-wired.**
- *Pull not triggered:* under both `--tpc only` and `--tpc first`, the dest debug
  log contains zero TPC lines. The destination is not reaching
  `xrootd_tpc_prepare_pull` / `xrootd_tpc_start_pull` for this scenario — i.e. the
  client→dest (or client→source) rendezvous that should arm the pull is not
  engaging the dest. Root cause is **not yet pinpointed** (needs the live trace in
  F1).
- *GSI round 2 is dead code:* the call graph is
  `tpc/thread.c:xrootd_tpc_pull_thread` → `tpc_connect` →
  `tpc/bootstrap.c:tpc_bootstrap` → on `kXR_authmore` →
  `gsi_outbound_finish.c:tpc_outbound_finish_login` →
  `gsi_outbound_certreq.c:tpc_outbound_gsi`. `tpc_outbound_gsi` performs **only
  round 1** (`kXGC_certreq`), frees its cert chain/key/BIOs via
  `tpc_outbound_gsi_finish`, and returns 0. `tpc_outbound_gsi_exchange`
  (`gsi_outbound_exchange.c` — the round-2 DH key exchange + encrypted client
  cert) is **declared and defined but called by nothing** (`grep -rn
  tpc_outbound_gsi_exchange src/` → only its own file + the header). So even once
  the pull is triggered, GSI auth to the source cannot complete.

**Environment hazards observed (factor into any work session):**
- A concurrent agent was editing `src/` (path/read/fs/acc/cache/upstream) and the
  memory files throughout the session; `pytest` tmp dirs were rotated mid-run;
  wall-clock vs file mtimes were skewed. Hold a **stable, committed** tree before
  doing delicate auth-crypto work, and prefer the self-contained fixture (its own
  nginx) over the shared `manage_test_servers.sh` instances.
- Build gotcha: `REPO=path ./configure --add-module=$REPO` expands `$REPO` in the
  parent shell (empty) → silently builds nginx **without the module**. Use the
  **literal absolute path** in `--add-module` (see [[build-source-list-location]]).

## F1. Stage 0 — a trustworthy regression gate (do this first)

Nothing else is safe to change without a gate that fails on the real defect.

1. Add a `--tpc only` variant to `tests/test_tpc_gsi_outbound.py` (or a sibling):
   reuse the `gsi_tpc` fixture; assert the pull **succeeds AND** the dest access
   log shows a server-side TPC open (not a plain `rd` of the archive). The
   access-log assertion is what distinguishes a real server pull from the
   client-fallback false-pass.
   ```python
   r = _run([XRDCP, "-f", "-s", "--tpc", "only", src, dst], env=gsi_tpc["env"])
   assert r.returncode == 0
   log = Path(gsi_tpc["logs"], "dst-access.log").read_text()
   assert any("tpc" in ln.lower() and "pull" in ln.lower() for ln in log.splitlines())
   ```
2. Keep the dest config at `error_log … debug` during development; the per-attempt
   diagnostic technique that worked is: truncate the log, run one `xrdcp`, then
   `grep -iE 'tpc|gsi|exchange|puk|cipher|authmore|pull|kXGC|kXGS' err.log`.
3. This test **must FAIL on `main`** before any fix — that is the proof it is a
   real gate (the current `--tpc first` test does not qualify).

**Exit criteria:** a red test that goes green only when the server actually pulls.

## F2. Stage 1a — make the destination initiate the pull

Goal: a `--tpc only` GSI pull reaches `xrootd_tpc_prepare_pull` →
`xrootd_tpc_start_pull` on the dest. **Root cause is unknown; this stage is
diagnosis-first.**

1. **Trace the real wire sequence** with `XRD_LOGLEVEL=Dump xrdcp --tpc only …`
   (client side) plus the dest debug log. Determine which step stalls:
   - client → **source** open with `tpc.dst=<dest>&tpc.key=<k>` (rendezvous
     registration over GSI), then
   - client → **dest** open (write) with `tpc.src=<source>&tpc.key=<k>` →
     dest detects TPC-destination (`src/read/open_request.c:185`,
     `is_write && tpc.has_src`) → `xrootd_tpc_prepare_pull`, then
   - client → dest `kXR_sync` → `xrootd_tpc_start_pull` posts the pull thread.
2. **Compare the native client's `--tpc only` emission to stock `xrdcp`.** The
   native client may not implement the full source-rendezvous (`tpc.dst`) leg, or
   may send a form the dest's `xrootd_tpc_parse_opaque` (`src/tpc/parse.c`) does
   not recognize. Capture both with `tcpdump`/`--wire-trace` and diff the opaque
   strings (`tpc.src` / `tpc.dst` / `tpc.key` / `tpc.org`).
3. **Likely fix locations** (confirm with the trace before editing):
   - native client TPC orchestration (`client/` — the `--tpc` driver) if it omits
     the rendezvous leg;
   - `src/read/open_request.c:176-339` (TPC detect) / `src/tpc/parse.c` if the
     dest mis-parses the opaque;
   - `src/tpc/launch.c` (`xrootd_tpc_prepare_pull` / `xrootd_tpc_start_pull`) if
     the prepare/sync hand-off is the stall.
4. Keep `tpc.org`/`tpc.key` SHM-registry flow (`src/tpc/key_registry.c`) in mind:
   the source registers the key on the `tpc.dst` open and consumes it on the
   `tpc.org` reconnect (`src/read/open_request.c:301-337`).

**Exit criteria:** dest debug log shows `xrootd_tpc_prepare_pull` + the pull thread
starting; the `--tpc only` failure now moves *into* the outbound GSI handshake
(i.e. Defect 2b, not "nothing happened").

## F3. Stage 1b — complete the outbound GSI handshake (round 2)

Once the pull is triggered, the outbound GSI auth to the source must finish.

1. **Wire `tpc_outbound_gsi_exchange` into the flow.** The cleanest place is
   inside `tpc_outbound_gsi` (`gsi_outbound_certreq.c`) right after the round-1
   `kXR_authmore` is received, since that function owns the cert chain/key/BIOs
   the exchange needs and frees them in `tpc_outbound_gsi_finish`.
2. **Ownership caveat (this bit me).** `tpc_outbound_gsi_exchange` consumes
   `body` (frees the round-1 reply on its normal paths) and does **not** free
   `chain`/`pkey`/`certreq`/`cbio`/`kbio` (the caller's `…_finish` does). After
   calling it, set `body = NULL` before `tpc_outbound_gsi_finish` to avoid a
   double free. NOTE: the early pre-keygen cert-verify-fail path in `exchange`
   returns *without* freeing `body` — so a blanket `body=NULL` leaks one buffer on
   that rare path. Prefer making `exchange` own `body` on **every** exit (free +
   not-touch by caller), then `body=NULL` is unconditionally correct.
3. **`exchange()` is never-run code — treat it as unproven.** It was dead since it
   was written; it may have its own bugs (DH param parse, cipher selection,
   `kXRS_puk`/`kXRS_main` framing). Validate against a packet capture of a stock
   `xrdcp --tpc` GSI pull (Parts A/E give the bucket/step constants:
   `kXGC_cert`, `kXRS_puk=3004`, `kXRS_cipher=3005`, `kXRS_main=3001`). Do **not**
   ship it until the Stage-0 `--tpc only` gate is green — I reverted my wiring
   precisely because I could not reach/verify it.

**Exit criteria:** `--tpc only` from a GSI source (`-dlgpxy:0`) **passes the
Stage-0 gate** (server-side pull, byte-exact file, source log shows the dest's DN
authenticating).

## F4. Stage 2 — unify on one outbound auth state machine (W1.4.a)

With a working, gated GSI pull, refactor the two divergent outbound auth paths
(`upstream/bootstrap.c` cache-fill vs `tpc/gsi_outbound_*` pull) onto the single
driver specified in **§W1.4.a** + **§B3.1** + the **D1.1 state table** (note the
D1.1 correction: the loop terminates on the *received* `kXR_ok`, not a
step-returned `DONE`).

- New `src/upstream/auth_handshake.{c,h}`; GSI continuation lifts the round
  bodies from `gsi_outbound_certreq.c`/`gsi_outbound_exchange.c` behind a
  `step(round)` callback (logic unchanged — this is the refactor that makes
  "multi-round" exist in one place).
- Delete the `authmore_count > 0` single-round cap (`upstream/bootstrap.c:134`,
  field `upstream_internal.h:73`); replace with `XRD_OBA_MAX_ROUNDS` (bounded
  loop, closes cache-fill gap + the hostile-loop security case).
- **Regression gates:** the Stage-0 `--tpc only` test **and**
  `tests/test_a_upstream_redirect.py::TestUpstreamAuth` (stub upstream servers
  exercising `kXR_authmore`/`kXR_gotoTLS` for cache-fill) must both stay green.
- This is a refactor of working crypto — land it as a no-behavior-change commit,
  proven by the gates, before adding any new capability.

## F5. Stage 3 — TPC pull `kXR_gotoTLS` (W1.4.b)

`tpc/bootstrap.c` connects plaintext only. Add the in-protocol TLS upgrade after
the `kXR_protocol` reply, mirroring `upstream/bootstrap.c:85-116`. The TPC worker
runs on the thread pool (blocking), so use a synchronous `SSL_connect` over the
pull fd rather than nginx's async `ngx_ssl_handshake`. Gate on a new
`xrootd_tpc_outbound_tls` directive. All `kXR_auth` frames (Stage 2 driver) then
run over the upgraded socket. **Gate:** a stock `xrootd` GSI source configured to
require TLS (`xrd.tls` + `sec.protbind … -tls`); `--tpc only` must still pass.

## F6. Stage 4 — X.509 proxy delegation, multi-hop (W1.4.c) — highest risk

Only after Stages 1–3 are green. Full design + wire spec are in **§W1.4.c**, the
**D1.2 inbound-handshake table**, and **Parts A/E** (steps `kXGS_pxyreq=2002` /
`kXGC_sigpxy=1002`; option bits `kOptsDlgPxy=1`, `kOptsSigReq=4`, `kOptsSrvReq=8`).
Opt-in via `xrootd_tpc_delegate` (default off → behavior identical to today).

Implementation order within the stage:
1. **`gsi_core` builders** (`src/gsi/gsi_core.{h,c}`): `xrootd_gsi_build_pxyreq`
   (server→client proxy CSR, encrypted under the session cipher) and
   `xrootd_gsi_parse_sigpxy` (assemble the signed delegated proxy PEM). These are
   the new crypto — **packet-validate against stock** `XrdSecgsi` with
   `dlgpxy:1`/`sigpxy` enabled on a real origin.
2. **Inbound capture** (`src/gsi/auth.c`): add the third server round. Today
   `auth.c:254-258` rejects any step past `kXGC_cert`; when `xrootd_tpc_delegate`
   is on, after a valid `kXGC_cert` emit `kXGS_pxyreq` and, on the client's
   `kXGC_sigpxy`, store the delegated proxy PEM.
3. **Carry the proxy cross-process** in the TPC key-registry slot
   (`src/tpc/key_registry.{h,c}` — add a bounded `proxy_pem[8192]`; ~2 MB SHM for
   256 slots; allocate via `xrootd_shm_table_alloc`, INVARIANT #10 spin-mutex).
   Zero it on `xrootd_tpc_key_consume`/TTL expiry.
4. **Outbound use** (the Stage-2 GSI continuation): sign the source challenge with
   the delegated proxy when present, else fall back to the module cert (unchanged
   default). Honour `xrootd_tpc_delegate` strictly: when on, an
   expired/garbage proxy is a clean abort — **no** silent module-cert fallback.

**Gates:** a `-dlgpxy:1` GSI source + `xrootd_tpc_delegate on`; the source access
log must show the **user's** DN, not the gateway's. Plus the security-negatives in
§W1.6 (`test_tpc_authmore_loop_bounded`, `test_tpc_deleg_proxy_expired`,
`test_gsi_sigpxy_when_delegation_off`).

## F7. Effort & ordering summary

| Stage | Work | Risk | Gate |
|---|---|---|---|
| F1 (Stage 0) | real `--tpc only` + access-log gate | low | red-on-main |
| F2 (Stage 1a) | diagnose+fix dest pull-not-triggering | **high (unknown root cause)** | dest reaches prepare/start_pull |
| F3 (Stage 1b) | wire+validate `exchange()` round 2 | high (unproven crypto) | `--tpc only` GSI passes |
| F4 (Stage 2) | shared `oba` state machine refactor | medium | Stage-0 + TestUpstreamAuth green |
| F5 (Stage 3) | TPC pull `gotoTLS` | medium | TLS-required source passes |
| F6 (Stage 4) | X.509 proxy delegation | **highest (new crypto)** | user-DN at source + sec-negatives |

Do **not** reorder: Stages 1a/1b are prerequisites for everything: without a
working, gated server-side GSI pull, Stages 2–4 are untestable and any code added
on top is unverifiable (the exact trap that stopped this from shipping). Each
stage is an independently revertable commit; F6 stays behind an off-by-default
flag so it can land incrementally without changing the default handshake.

---

## F8. Implementation progress + precise remaining work (2026-06-26)

A hands-on implementation pass replaced the F0 *guesses* with a verified
five-layer diagnosis (via `xrdcp --wire-trace` + a temporary `W1DIAG` log in
`tpc_bootstrap`). The earlier "dest never triggers a pull" was a *symptom*; the
real chain is below. **Three layers are fixed (build green, no regression on the
existing `--tpc first` test); two remain — the genuine GSI crypto.**

### Fixed (verified)
1. **Test fixture: the stock GSI source had no `ofs.tpc`** → it rejected every
   TPC open with `kXR_Unsupported "tpc not supported"`, so the client never even
   reached the destination. Fixed in `tests/test_tpc_gsi_outbound.py` (`ofs.tpc
   pgm /usr/bin/xrdcp`). This alone moved the failure from the source to the
   real dest path.
2. **`tpc_bootstrap` treated a `kXR_ok` login as "anonymous, done".** In XRootD a
   `kXR_ok` login still REQUIRES auth when its reply body carries the security
   token (session id + `&P=…` list) — exactly what stock XrdCl handles by sending
   `kXR_auth` after an OK login (verified in its trace: `login ok dlen=61` →
   `kXR_auth`). The dest skipped auth and opened the source unauthenticated →
   `kXR_InvalidRequest "user not authenticated"`. **Fix** (`src/tpc/bootstrap.c`):
   authenticate on `kXR_ok` OR `kXR_authmore` whenever `dlen >
   XROOTD_SESSION_ID_LEN` (a sec token is present); a bare session id is truly
   anonymous. *Bonus:* this also enables ZTN-over-TPC when the source returns an
   OK login (not authmore).
3. **Round-2 `tpc_outbound_gsi_exchange` was dead code** (called by nothing).
   **Fix** (`src/tpc/gsi_outbound_certreq.c`): call it after the round-1 authmore,
   clearing `body` afterwards; plus `gsi_outbound_exchange.c` now frees `body` on
   its cert-verify-fail early path so the caller's `body=NULL` is leak- and
   double-free-safe (exchange owns `body` on every exit).

After 1–3 the handshake advances two steps: `login(ok+sectoken)` → dest sends GSI
`kXGC_certreq` → source responds (instead of "user not authenticated").

### Remaining (the real GSI handshake — reference: `client/lib/sec/sec_gsi.c`)
The dest's outbound GSI is an incomplete *parallel* implementation of the client's
proven one. Current `--tpc only` error: **`TPC GSI expected kXR_authmore after
certreq (status=4003)`** — the source rejects the round-1 certreq.

4. **Round-1 certreq is a STUB.** `tpc_outbound_gsi` sends 16 bytes
   (`"gsi\0"+kXGC_certreq+kXRS_none`); a real certreq is ~112 bytes with the
   crypto module, version, issuer-hash, client-opts and a random `rtag`. **Fix:**
   thread the login parms (the `&P=gsi,v:…,c:ssl,ca:…` string, already in
   `finish_login`'s `login_body`) into `tpc_outbound_gsi`; parse them with
   `xrootd_gsi_parse_parms`; generate a per-pull `rtag` (add `uint8_t rtag[8]` to
   `xrootd_tpc_pull_t`); build via `xrootd_gsi_build_certreq(crypto, version, ca,
   0x80, rtag, 8, &len)`. Mirrors `sec_gsi.c:127-156`.
5. **Round-2 omits PROOF-OF-POSSESSION.** `exchange()` sends DH + the encrypted
   cert chain but never signs the server's `rtag`. Stock requires a
   `kXRS_signed_rtag` (the server's `rtag` signed with the proxy key). **Fix:** in
   `exchange()`, find the server's `kXRS_rtag` in the response, sign it with
   `xrootd_gsi_rsa_sign_raw(pkey, srtag, …)`, and add a `kXRS_signed_rtag` bucket
   to the round-2 message. Mirrors `sec_gsi.c:453-470`.

**Strategic note:** items 4–5 are the minimum to make the pull work, but they
deepen a second, parallel GSI implementation. The durable fix is **Stage 2
(W1.4.a/F4): share the client's `gsi_core`-based handshake** so there is one
GSI codepath. Recommend doing 4–5 only if a quick win is needed; otherwise fold
them into the F4 refactor.

**Gate for 4–5:** `--tpc only` against the now-`ofs.tpc` `gsi_tpc` fixture must
succeed with a server-side pull (the F1 access-log assertion). Each iteration is
~12 s (fixture spins up stock xrootd + nginx). Validate the certreq/round-2 bytes
against a `--wire-trace`/`tcpdump` capture of a stock `xrdcp --tpc` GSI pull.

### F8 update — items 4–5 implemented; GSI handshake now COMPLETES (2026-06-26, pass 2)

Items 4 and 5 are **done and verified**: the destination's outbound GSI handshake
to a real stock GSI source now authenticates end-to-end (proven by advancing the
`--tpc only` failure *through every auth step* into the post-auth file-open phase).

Implemented:
- **Item 4 (real certreq):** `tpc_outbound_gsi` now threads the login parms
  (`gsi_outbound_finish.c` passes `login_body`), parses them with
  `xrootd_gsi_parse_parms`, generates a per-pull rtag (`xrootd_tpc_pull_t.gsi_rtag`),
  and builds a proper round-1 via `xrootd_gsi_build_certreq(crypto, version, ca,
  0x80, rtag, 8)` — advertising version **10300** (unsigned-DH) so the source uses
  the `kXRS_puk` path `exchange()` implements. (Was a 16-byte stub → source
  `kXR_error`.)
- **Item 5 (proof-of-possession):** `gsi_outbound_exchange.c` now finds the
  server's `kXRS_rtag` (in the cleartext `kXRS_main` of `kXGS_init`), signs it with
  the proxy key via `xrootd_gsi_rsa_sign_raw`, and adds a `kXRS_signed_rtag` bucket
  to the encrypted round-2 inner. Also surfaces the source's error text on a
  round-2 reject (made this whole diagnosis possible).
- **Test fixture corrections** (`tests/test_tpc_gsi_outbound.py`): the stock source
  needs `ofs.tpc … ttl 300 300 pgm /usr/bin/xrdcp`, and the destination must
  present a PROXY chain (`xrdgsiproxy`-minted `destproxy.pem`, ≥2 certs) — a bare
  single cert is rejected ("expected ≥ 2"). These are real deployment requirements,
  not just test artifacts: a production dest needs a proxy (or host-cert→proxy)
  and the source needs TPC enabled with an adequate ttl.

Diagnosis ladder (each fix advanced one step): `tpc not supported` (source ofs.tpc)
→ `user not authenticated` (login auth-trigger) → `expected kXR_authmore after
certreq` (stub→real certreq) → `kXRS_puk missing` (advertise unsigned 10300) →
`authentication failed: wrong number of certificates … expected ≥ 2` (dest proxy
chain) → GSI **OK** → `tpc authorization expired` (source ttl) → reaches the TPC
file-open.

### Remaining — TPC DATA-PLANE orchestration (NOT GSI; F4 deferred)
With GSI working, the dest's `kXR_open` of the source returns **`kXR_waitresp`
(4006)** — the source answers the TPC open ASYNCHRONOUSLY (validate rendezvous →
deferred `kXR_attn` asynresp). `src/tpc/source.c` only accepts `kXR_ok`. A
prototype wait/waitresp+attn-unwrap loop was written and **reverted**: against the
test's `ofs.tpc pgm` (push-model) source the deferred `kXR_attn` never arrived
within the I/O timeout, so the dest pull thread BLOCKED (hanging even the
`--tpc first` fallback). Fast-fail (reject non-ok open) is restored — **no
regression** (`--tpc first` passes in ~12 s).

This is a distinct, deep layer: the dest-pull vs source-`pgm`-push TPC model +
correct async `kXR_wait`/`kXR_waitresp`→`kXR_attn` handling with tight bounds.
It needs a packet capture of a stock `xrdcp --tpc` source↔dest exchange to settle
the exact open semantics. **F4 (share the client `gsi_core` handshake) is deferred
until this data-plane layer yields a green `--tpc only` gate** — refactoring GSI
under a non-completing pull would be unverifiable (the trap §F0 warns about).

State kept (build green, `--tpc first` green, no regression): the GSI fixes above
in `bootstrap.c`, `gsi_outbound_certreq.c`, `gsi_outbound_exchange.c`,
`gsi_outbound_finish.c`, `tpc_internal.h`; the `source.c` note; the fixture fixes.

### F8 update — GREEN end-to-end GSI gate (2026-06-26, pass 3)

Items 4–5 are now verified **end-to-end with a full byte transfer**, not just at
the auth layer. New keepable gate **`tests/test_tpc_gsi_nginx_source.py`**: an
nginx DESTINATION performs a native `--tpc only` PULL from an **nginx GSI SOURCE**
(`xrootd_auth gsi`), authenticating with its own proxy chain — and the file
arrives byte-exact. PASSES.

Why nginx↔nginx (not the stock source): our nginx source serves the TPC open
**synchronously**, so it sidesteps the stock `ofs.tpc pgm` push-model's async
`kXR_waitresp` (the separate data-plane layer above). This isolates and proves the
**server-outbound GSI handshake** (certreq + unsigned-DH + proof-of-possession)
end-to-end. A self-contained nginx→nginx anon pull also passes (data path), and
`test_tpc_gsi_outbound.py` (`--tpc first`, stock source) + the 10
`test_tpc_token_mode.py` ztn tests still pass (no regression from the
bootstrap login-auth-trigger change).

**W1 status:**
- ✅ **Native TPC over GSI works, nginx↔nginx (green-gated).** items 4–5 done.
- ⛔ **Stock-source interop:** the dest-pull from a stock `ofs.tpc pgm` source
  still needs the async `kXR_wait`/`kXR_waitresp`→`kXR_attn` data-plane handling
  (prototype reverted — it hung because that source's attn never arrived; needs a
  stock `xrdcp --tpc` source↔dest packet capture to settle the open semantics).
  Also: signed-DH outbound (dest currently advertises unsigned 10300).
- **F4 (share the client `gsi_core` handshake)** is now DE-RISKED — there is a
  green dest gate AND the client GSI tests (`test_gsi_handshake.py`,
  `test_gsi_interop_guards.py`) to gate a refactor. It remains a large bidirectional
  change (extract `gsi_first`/`gsi_more` from `client/lib/sec/sec_gsi.c` into a
  state-passed `gsi_core` handshake; rewire client + `tpc_outbound_gsi`/`exchange`;
  delete the parallel impl). Recommended as the next focused effort — it would also
  give the dest the signed-DH path for free. Not folded in here to avoid risking
  the client's EOS-proven GSI at the tail of this pass.

### F4 DONE — one shared GSI round-2 kernel (2026-06-26)

The F4 refactor is complete and verified. The XrdSecgsi round-2 (kXGC_cert
response) now has a **single implementation**, `xrootd_gsi_build_cert_response()`
in `src/gsi/gsi_core.c` (ngx-free, both DH variants: unsigned kXRS_puk and
signed-DH kXRS_cipher). Both callers are thin drivers that supply their proxy
credential + map errors:

- **Native client** — `client/lib/sec/sec_gsi.c` `gsi_more()` is now a ~35-line
  wrapper (loads the proxy file → calls the kernel). Was ~410 lines (608→239 in
  the file): the round-2 logic + 4 private helpers (cert_pubkey,
  export_pubkey_pem, gsi_pick_md_alg, gsi_more_ctx/cleanup) moved into gsi_core.
- **TPC destination** — `src/tpc/gsi_outbound_exchange.c` is now a ~200-line
  driver (cert-verify → serialise chain PEM → call the kernel → send → recv); was
  509 lines of a parallel raw-OpenSSL DH/cipher reimplementation. **Bonus:** the
  destination gets the **signed-DH path for free** — whatever variant the server
  offers, the shared kernel handles it (the dest still advertises 10300/unsigned
  in certreq.c, so current wire behaviour is unchanged; flip to 10600 to use it).

Net: ~−380 LoC and the two GSI implementations can no longer drift.

**Verified (131 passed, 5 env-skipped, one run):**
- `test_gsi_handshake.py` (115) — client GSI vs nginx GSI server, byte-for-byte.
- `test_tpc_gsi_nginx_source.py` — dest `--tpc only` pull from an nginx GSI
  source, file byte-exact (both sides now via the shared kernel).
- `test_tpc_gsi_outbound.py` — stock-source `--tpc first`, no regression.
- `test_tpc_token_mode.py` (10) — ztn login-path unaffected.
- `test_gsi_interop_guards.py` — tripwires updated to enforce the **post-F4
  contract**: both sides must contain `xrootd_gsi_build_cert_response` (delegation)
  and the wire-critical facts (md_alg, cipher#ivlen, kXRS_none terminator) are
  asserted against the single shared kernel.

W1 is now functionally complete for nginx↔nginx with a unified, de-duplicated GSI
codepath. The only open item remains stock-source async TPC open
(kXR_waitresp→kXR_attn data-plane, §F8 above) — independent of GSI.

### F8 DONE — async kXR_open resolution (2026-06-26)

The remaining W1 data-plane gap is now closed. The TPC destination resolves an
**asynchronous source open**: `tpc_open_resolve()` (`src/tpc/source.c`) honours the
XRootD flow-control statuses a real source (EOS/dCache, or any server still
finishing the TPC rendezvous) returns before the open settles —

- **kXR_wait (4005)** — sleep the (clamped) retry-after, then RESEND the open.
- **kXR_waitresp (4006)** — do not resend; wait for the deferred
  **kXR_attn(kXR_asynresp)** and unwrap its embedded `ServerResponseHeader` + body
  as the real reply (which may itself be a wait → folded back into the loop).

Bounded on every axis so a silent source can never hang the pull thread (the prior
behaviour, which fast-failed): the caller tightens `SO_RCVTIMEO` to
`TPC_OPEN_WAIT_CAP_SEC` (15 s) for the negotiation and restores 60 s for the read
loop; plus a clamped single wait, a `TPC_OPEN_RESOLVE_MAX_ITERS` (16) round cap and
a `TPC_OPEN_RESOLVE_MAX_SEC` (120 s) wall-clock deadline. Runs on a thread-pool
worker, so the bounded sleeps block only that transfer's thread. A source that
answers `kXR_ok` immediately (our own nginx source) resolves on the first frame —
no behaviour change.

**Verified (`tests/test_tpc_async_open.py`, 2 cases):** a real native
`xrdcp --tpc only` pull, with a real nginx-xrootd DESTINATION pulling from an
in-process MOCK SOURCE that answers the dest's pull open asynchronously — both
`kXR_waitresp → kXR_attn(asynresp) → kXR_ok` and `kXR_wait → resend → kXR_ok` — and
serves the bytes. The file arrives byte-exact in each mode. No regression:
`test_tpc_gsi_outbound.py` (`--tpc first`, stock source whose `ofs.tpc-pgm` push
model never sends the attn) still passes — the dest now WAITS the bounded ~15 s for
the attn, finds none, fails cleanly and the client fallback completes in budget.

**W1 is complete.** Native TPC over GSI works nginx↔nginx with one unified GSI
codepath (items 4–5 + F4), and the destination resolves async source opens (F8).
A stock `ofs.tpc-pgm` *push*-model source still won't complete a `--tpc only`
PULL — that is a source-side configuration/model choice (it pushes, it doesn't let
the dest pull), not a dest gap; pull-capable sources (EOS/dCache, our nginx source,
any server that sends the asynresp) are now handled.

### Stage A (cache-fill multi-round) + F5 (TPC TLS) DONE (2026-06-26)

Two more W1 stages landed, each independently revertable and gated:

**Stage-2 residual — cache-fill multi-round kXR_authmore (bounded).**
`src/upstream/bootstrap.c` previously aborted on the *second* kXR_authmore
("repeated kXR_authmore (not supported)"), blocking any multi-round origin auth.
Replaced with one shared bounded helper `xrootd_upstream_continue_auth()` used by
both the LOGIN and AUTH phases, capped by `XRD_OBA_MAX_ROUNDS` (8) — closes the
hostile-loop case and creates the multi-round seam. **Gate:**
`tests/test_upstream_auth_multiround.py` (self-contained stub origin issuing 2
authmore rounds + dedicated redirector nginx) — the locate returns kXR_redirect and
both ztn creds are forwarded. (Full GSI-over-cache-fill — the async-driver
consumer of this seam — remains the larger W1.4.a event-loop work, deferred.)

**F5 (Stage 3) — TPC pull kXR_gotoTLS.** The TPC pull I/O (`src/tpc/io.c`) is now
TLS-aware: the three primitives thread `t` and route through `SSL_read`/`SSL_write`
when `t->tls` is set. `src/tpc/bootstrap.c` advertises `kXR_ableTLS` (when
`xrootd_tpc_outbound_tls on`) and, on a `kXR_gotoTLS` protocol reply, upgrades via
the new `src/tpc/tls.c` (`tpc_start_tls`: blocking client `SSL_connect` over the
pull fd in the thread-pool worker, CA-verified against `xrootd_trusted_ca`); login +
GSI/ztn auth + open/read/close then ride the TLS socket. Freed in `thread.c` via
`tpc_tls_teardown`. New directive `xrootd_tpc_outbound_tls` (default off →
behaviour identical to today; no `kXR_ableTLS`, so no source ever offers gotoTLS).
**Gate:** `tests/test_tpc_tls.py` — an nginx source with `xrootd_tls on` (TLS
required) ← an nginx dest with `xrootd_tpc_outbound_tls on`; `--tpc only` over TLS
delivers the file byte-exact. Plaintext TPC regression (async/GSI/token) stays
green after the I/O refactor.

**Remaining:** F6 (X.509 proxy delegation) — see below; off-by-default, needs a
stock `-dlgpxy:1` interop gate that cannot be stood up locally.

### F6 (X.509 proxy delegation) — status: designed, gated, NOT shipped (2026-06-26)

F6 is fully designed (§W1.4.c, §W1.4.d, §F6, Parts A/D/E) but is **deliberately not
implemented in this pass.** Its only correctness gate is a stock `-dlgpxy:1`
XrdSecgsi source whose access log must show the **user's** DN (not the gateway's) —
an interop fixture that cannot be stood up in this environment. Implementing the
~500 lines of new proxy-delegation crypto (the `kXGS_pxyreq` CSR builder, the
`kXGC_sigpxy` signed-proxy parser, the inbound 3rd GSI round in `src/gsi/auth.c`,
the SHM proxy-carry, and the outbound delegated-proxy signing) without that gate
would ship **unverified crypto** — precisely the trap §F7 warns against ("do not
add unverifiable code on top"). Off-by-default would also make it dead, untested
code, plus ~2 MB of SHM proxy-carry with no producer/consumer.

**Decision:** F6 stays as a precise, ready-to-execute design. It should be done as a
dedicated effort that *starts* by standing up the stock `-dlgpxy:1` source +
user-DN assertion gate (§F6 "Gates"), then implements the crypto under it
(builders → inbound capture → registry carry → outbound use), each step revertable
and behind `xrootd_tpc_delegate` (default off). The verified building blocks are
already in place: the shared GSI kernel (`xrootd_gsi_build_cert_response`, F4) for
the outbound signing, the bounded async open (F8), the TLS transport (F5), and the
key registry (`src/tpc/key_registry.{h,c}`) for the cross-worker carry.

**W1 net (phase-57):** F1–F5 + F8 done and gated (native TPC over GSI works
nginx↔nginx with one unified GSI codepath, async source opens, in-protocol TLS, and
bounded multi-round cache-fill auth). F6 (multi-hop X.509 proxy delegation) is the
sole remaining piece, blocked only on its interop gate.

### F6 interop GATE stood up (2026-06-26) — ready to implement against

The stock interop gate F6 was blocked on now EXISTS and is codified:
**`tests/test_tpc_delegation.py`** stands up a stock xrootd v5.9.5 GSI source with
proxy delegation + DN logging and is green for the gate mechanisms:

- `test_stock_gsi_source_logs_dn` ✅ — a user-proxy GSI download is authenticated and
  the source logs `secgsi_Authenticate: <user> Subject DN='<DN>'` (the assertion
  mechanism F6 will check).
- `test_stock_source_captures_delegation` ✅ — with `XrdSecGSIDELEGPROXY=2` the client
  delegates and the source logs `Delegated proxy saved` (the delegation round F6
  drives).
- `test_dest_pulls_as_user_via_delegation` 🔴 **xfail** — the F6 target: a delegating
  client → our nginx dest (`xrootd_tpc_delegate on`) → stock source; F6 must make
  the source authorise the dest's PULL as the **user** (the gateway DN must be
  absent from the pull). Flip `strict=True` / drop the xfail when F6 lands.

**PLAN CORRECTION (verified):** the stock option is **`-dlgpxy:request`**, not
`-dlgpxy:1`. XrdSecgsi parses delegation via `getOptVal(sDlgOpts,…)` over the named
table `{ignore, request}` (`XrdSecgsiOpts.hh:130`); a numeric `-dlgpxy:1` silently
resolves to `ignore` (confirmed in the source log banner: "Proxy delegation option:
ignore"). All §W1.4.c / §F6 references to `-dlgpxy:1` should read `-dlgpxy:request`.
Source gate config that works: `sec.protocol … gsi -gridmap:<map> -gmapopt:2
-dlgpxy:request -showdn:1 -exppxy:=creds` + a `.signing_policy` for the test CA.

The `xrootd_tpc_delegate` directive now parses (off by default, reserved) so the
gate's dest config loads. **F6 is now unblocked**: implement under this gate in the
§F6 order (gsi_core pxyreq/sigpxy builders → inbound 3rd round → registry carry →
outbound use), turning the xfail green.

### F6 building block 1 — proxy-request generator (2026-06-26)

Implementing F6 under the gate (§F6 step 1, first half). New ngx-free OpenSSL
module **`src/gsi/proxy_req.{c,h}`** with `xrootd_gsi_build_pxyreq()` — the
server→client `kXGS_pxyreq` proxy-certificate REQUEST our destination's inbound
GSI role will send to a delegating client. Ported faithfully from stock
XrdSecgsi `XrdCryptosslgsiAux.cc::XrdCryptosslX509CreateProxyReq`: fresh RSA key
(>= parent bits, >= 2048, e=65537); subject = parent + `/CN=<random serial>`;
critical `proxyCertInfo` extension (impersonation policy `1.3.6.1.5.5.7.21.1`,
OID `1.3.6.1.5.5.7.1.14`, pathlen from parent); copies the parent's other
extensions (minus SAN/pci); self-signed SHA-256; DER-exported. No goto (single
NULL-safe cleanup, ownership NULLed on transfer). Registered in `./config`.

**Verified** (standalone, no nginx / no stock interop):
`src/gsi/proxy_req_unittest.c` — 9/9 checks: builds 0; key >= 2048; request DER
parses; subject = parent (O,CN) + numeric CN; request self-signature verifies;
proxyCertInfo extension present AND critical.
`gcc -I src src/gsi/proxy_req.c src/gsi/proxy_req_unittest.c -lcrypto -o /tmp/pxr`.

**F6 remaining (each against tests/test_tpc_delegation.py's xfail):**
2. `xrootd_gsi_assemble_sigpxy()` — pair the client-signed proxy (kXGC_sigpxy) with
   the saved request key → the delegated proxy PEM (+ a sign helper to round-trip
   the create→sign→assemble crypto locally in the unit test).
3. Inbound 3rd round in `src/gsi/auth.c` (today ends at kXGC_cert): when
   `xrootd_tpc_delegate on`, emit kXGS_pxyreq after a valid kXGC_cert and capture
   the kXGC_sigpxy reply (uses the shared session cipher).
4. Cross-worker carry in `src/tpc/key_registry.{c,h}` (bounded `proxy_pem`, zeroed
   on consume/TTL).
5. Outbound use: the dest's GSI pull signs with the delegated proxy (via the F4
   `xrootd_gsi_build_cert_response`, swapping the credential) instead of the module
   cert → the stock source logs the USER's DN → the gate's xfail flips green.

### F6 crypto core complete + exhaustively tested (2026-06-26)

All three RFC-3820 proxy-delegation primitives now live in `src/gsi/proxy_req.{c,h}`
(ngx-free OpenSSL, ported faithfully from stock XrdCrypto):

- `xrootd_gsi_build_pxyreq` — REQUEST a proxy (server→client kXGS_pxyreq).
- `xrootd_gsi_sign_pxyreq`  — ISSUE/sign a proxy from a request (client kXGC_sigpxy):
  validates `<signer>/CN=<serial>`, builds the X.509v3 proxy (issuer = signer,
  pubkey = request key, validity = signer's remaining life), copies signer
  extensions (keyUsage required, SAN rejected), critical proxyCertInfo with the
  decremented path length, signs SHA-256.
- `xrootd_gsi_assemble_proxy` — ASSEMBLE the delegated credential (dest): verifies
  the signed proxy's key matches the saved request key, emits `<proxy><chain>` PEM.

**Tested exhaustively, standalone (no nginx / no stock interop):**
`src/gsi/proxy_req_unittest.c` — **25 checks, 0 failures**, compiled `-Werror` and
run in CI via **`tests/test_gsi_proxy_crypto.py`**. Coverage: request structure +
self-signature; issue (issuer/subject/serial/pubkey/critical-pci/validity); assemble
(key match, 2-cert credential, key-mismatch rejection); the full
create→sign→assemble **round-trip with RFC-3820 chain verification** (proxy→EEC→CA
under `X509_V_FLAG_ALLOW_PROXY_CERTS`); **two-level delegation** (proxy-of-a-proxy,
path length, proxy2→proxy1→EEC→CA verifies); negatives (subject mismatch, garbage
PEM/DER, NULL args). Registered in `./config`; module builds clean.
Run directly: `gcc -Wall -Wextra -I src src/gsi/proxy_req.c
src/gsi/proxy_req_unittest.c -lcrypto -o /tmp/pxr && /tmp/pxr`.

**F6 remaining — wiring the verified crypto (each flips the gate xfail greener):**
3. Inbound 3rd round in `src/gsi/auth.c` — after a valid kXGC_cert with
   `xrootd_tpc_delegate on`, `build_pxyreq` → send kXGS_pxyreq (encrypted under the
   session cipher) → on kXGC_sigpxy `assemble_proxy` → stash the delegated proxy.
4. Cross-worker carry in `src/tpc/key_registry.{c,h}` (bounded proxy_pem + key,
   zeroed on consume/TTL).
5. Outbound use — the dest's pull signs with the delegated proxy via the F4
   `xrootd_gsi_build_cert_response` → `test_dest_pulls_as_user_via_delegation` green.

### F6 inbound-round foundation: session-cipher persistence (2026-06-26)

Laid the safe, no-behavior-change foundation for the inbound 3rd GSI round
(kXGS_pxyreq/kXGC_sigpxy): the GSI session cipher is now persisted on the
connection so the extra round can encrypt/decrypt its main.
- `src/core/types/context.h`: + `gsi_sess_cipher[24]` / `gsi_sess_key[32]` /
  `gsi_sess_keylen` / `gsi_sess_use_iv` (session cipher), and the delegation-round
  state (`gsi_deleg_reqkey`, `gsi_deleg_await`, `gsi_deleg_chain_pem(+len)`,
  `gsi_deleg_proxy_pem(+len)`).
- `src/gsi/parse_x509.c`: `gsi_persist_session_cipher()` called in BOTH the
  unsigned (use_iv=0) and signed-DH (use_iv=1) round-2 paths, right where the key
  is derived (purely additive — copies the already-computed key + name + IV flag).

**Verified no-regression to working GSI auth:** clean full rebuild (EXIT=0;
note: editing `context.h` mid-struct requires `./configure` to recreate
`objs/addon/*` dirs after a clean — `rm -rf objs/addon` alone breaks `make`).
`tests/test_gsi_handshake.py`: 111 pass; the GSI auth path itself works (all
**uploads** — same parse_x509 auth — succeed). The 4 failures are a **client-side**
large-**download** bug (`xrdcp: disk ring chunk too large`, `client/lib/uring.c:210`)
in the 11:09 client binary — predates and is independent of this server-side F6
work (a concurrent client-lib refactor was in flight). `tests/test_gsi_proxy_crypto.py`
(25 crypto checks) still green.

**F6 remaining (behaviour-changing, e2e-gated):** build+send kXGS_pxyreq +
handle kXGC_sigpxy in `src/gsi/auth.c` (gated on `xrootd_tpc_delegate`, deferring
auth_done) → registry carry → outbound use → flips
`test_tpc_delegation.py::test_dest_pulls_as_user_via_delegation` green.

### F6 inbound round (kXGS_pxyreq/kXGC_sigpxy) implemented (2026-06-26)

The destination's inbound delegation round is wired and exercised against a REAL
stock xrootd v5.9.5 client. New `src/gsi/delegation.{c,h}`:
`xrootd_gsi_begin_delegation` (after a verified kXGC_cert, gated on
`xrootd_tpc_delegate`: RSA-sign the client's rtag → kXRS_signed_rtag, build the
proxy request via `xrootd_gsi_build_pxyreq`, encrypt {signed_rtag + fresh rtag +
kXRS_x509_req} under the session cipher, send kXGS_pxyreq as kXR_authmore) and
`xrootd_gsi_handle_sigpxy` (decrypt the reply, `xrootd_gsi_assemble_proxy`, stash
on ctx, complete the deferred auth). `src/gsi/parse_x509.c` now persists the
session cipher + captures the client rtag; `src/gsi/auth.c` factors
`xrootd_gsi_complete_auth` and adds the kXGC_sigpxy step; disconnect frees the
state. Off by default → no-regression (111 `test_gsi_handshake` pass; the 4 fails
are the unrelated client `uring.c` large-download bug).

**Verified against the stock client up to the sign step:** the dest sends a
well-formed kXGS_pxyreq, the client accepts it, verifies our signed rtag, and
reaches kXGC_sigpxy. `tests/test_tpc_delegation.py::test_dest_captures_delegated_proxy`
is xfail: the stock client only RETURNS a signed proxy when its delegation policy
is satisfied, which this synthetic-hostname WSL2 rig cannot fully provide.

**Multi-layer stock-interop findings (each was a separate blocker — invaluable for
finishing F6 in a real grid env):**
1. `gsi_ca_hash` is only computed when `xrootd_trusted_ca` is a CA **file**
   (config.c `fopen`+`PEM_read_X509`); a directory leaves `ca:00000000` and stock
   clients fail "unknown CA". (Our native client tolerates ca:0 — why this was
   never caught.)
2. Proxy delegation **requires signed-DH** — a stock client clears the delegation
   bits when the server's DH params aren't RSA-signed (`xrootd_gsi_signed_dh require`).
3. Client mode must be **`XrdSecGSIDELEGPROXY=1`** (dlgReqSign — sign our request);
   `=2` is *forward* (send the private key), which our request-based capture rejects.
4. The client **forbids delegation when it "used DNS"** to verify the server name —
   so the server cert CN must match the connect host **exactly (incl. case)**; the
   client lowercases the hostname, so an upper-case CN → DNS fallback → no delegation.
5. The pxyreq must carry the **rtag proof-chain** (kXRS_signed_rtag of the client's
   kXGC_cert rtag + a fresh kXRS_rtag), else the client rejects it "random tag missing".

**F6 remaining:** the outbound use (TPC pull presents the captured proxy) +
end-to-end green under a real grid host. The crypto + inbound round are in place.

### F6 outbound use — DONE; phase-57 code-complete (2026-06-26)

The final connector: the TPC pull now authenticates to the source AS THE USER with
the captured delegated proxy.
- `src/gsi/delegation.c` (handle_sigpxy): builds the full pull credential = proxy
  cert + issuer chain + the request private key (PEM, in that order) onto
  `ctx->gsi_deleg_proxy_pem`.
- `src/tpc/launch.c` (start_pull): when `xrootd_tpc_delegate` is on and a proxy was
  captured, malloc-copies the credential into the pull task (`t->deleg_cred_pem`).
- `src/tpc/gsi_outbound_certreq.c`: when `t->deleg_cred_pem` is set, loads the cert
  chain + key from that in-memory blob (two BIOs over it) instead of the gateway's
  `xrootd_certificate`, and skips the file-based credential validation; the existing
  GSI outbound handshake (F4 `xrootd_gsi_build_cert_response`) then presents the
  user's proxy. `src/tpc/thread.c` frees the blob.

Gated off by default (no captured proxy ⇒ unchanged behaviour). No regression: all
TPC gates (TLS, async-open, nginx-GSI-source) + the stock-delegation green tests +
the 25-check crypto suite pass.

**phase-57 is code-complete.** W2 (ZIP member access) + W3 (WebDAV lock hardening)
done; W1 = F1–F5 + F8 + F4 + cache-fill multi-round + F6 (RFC-3820 crypto core,
inbound kXGS_pxyreq/kXGC_sigpxy capture, outbound delegated-proxy use) all
implemented, off-by-default, no-regression. The sole item not green **end-to-end**
is F6 full delegation, which needs a real grid host (resolvable hostname + the stock
client's delegation policy: signed-DH, CA-file hash, exact-case cert CN, dlgReqSign)
— the dest-side code is complete and verified to kXGC_sigpxy against a real stock
client; `tests/test_tpc_delegation.py` carries the two xfail gates that flip green in
such an environment.
