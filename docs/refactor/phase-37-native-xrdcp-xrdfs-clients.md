# Native xrdcp / xrdfs Clients on a Shared XRootD Protocol Core

**Status:** historical plan; implementation has moved into `client/`
**Date:** 2026-06-14
**Author:** architecture

---

> Reviewer note: this file is retained as the clean-room/architecture planning
> artifact. It is no longer the authoritative client feature matrix. The current
> source-verified user-facing guide is
> [Native Client Tools](../04-protocols/native-client-tools.md). In particular,
> current `client/xrdcp` implements WebDAV/HTTP and S3 URL handling, so the
> original "declined/out of scope" statements for those schemes below are stale
> historical context rather than present-day behavior.

## 1. Context & goal

### Why

XRootD deployments depend on two ubiquitous command-line tools — `xrdcp` (file
transfer) and `xrdfs` (metadata / filesystem operations). Both ship today as
C++ binaries built on `libXrdCl`, which drags in the entire XrdCl/XrdSec/XrdSys
stack: an async PostMaster event loop, a plugin loader (`dlopen` of
`libXrdSecgsi.so`, `libXrdSeckrb5.so`, …), `XrdSys` threading primitives, and a
large transitive dependency surface. For a project whose explicit thesis is "a
dependency-free, auditable XRootD gateway", shipping clients that pull in the
upstream client stack is an architectural contradiction.

This project already contains, in `src/protocols/root/protocol/` and `src/core/compat/`, a
**byte-for-byte-correct, ngx-free description of the XRootD wire protocol** plus
the pure algorithmic kernels (CRC32C, hex, errno→kXR mapping, OpenSSL HMAC/SHA
wrappers) needed to speak it. The server uses these to frame and parse `root://`
traffic identically to a real XRootD `cmsd`/`xrootd`. The same definitions, with
nothing added, are sufficient to *drive* the protocol from the client side.

The goal is therefore to implement `xrdcp` and `xrdfs` as **pure-C binaries that
link the project's own protocol core** — so the tools are genuinely "built atop
the code in this project" rather than a parallel reimplementation. To make that
literally true (and to keep both sides from drifting), we first extract an
**ngx-free shared static library, `libxrdproto`**, that both the existing nginx
module and the new clients compile and link.

### What success looks like

- `xrdcp` and `xrdfs` binaries with **zero runtime dependency on `libXrdCl`,
  `libXrdSec*`, or any XRootD shared object** — link only `libssl`/`libcrypto`
  (mandatory) and `libkrb5` (optional, like the module).
- Behaviour matching the system `xrdcp`/`xrdfs` for the operation set the
  conformance suite already exercises: anonymous + GSI + token auth,
  download/upload/TPC, recursive copy, checksum verify, `stat`/`ls`/`locate`/
  `mkdir`/`rm`/`mv`/`chmod`/`query`/`prepare`/`xattr`, redirect/cluster
  following, in-protocol TLS (`roots://`).
- **Byte-exact + checksum-exact** round-trips against both the nginx fleet and
  the reference xrootd daemons in the existing harness
  (`tests/manage_test_servers.sh`, ports 11094–11123 nginx / 11098–11113 ref).
- The shared core (`libxrdproto`) compiles into **both** the nginx module
  (via `config`/`NGX_ADDON_SRCS`) and the standalone client build, with a CI
  guard that fails if it ever picks up an `ngx_*` symbol.
- Exit codes that match XrdCl's `GetShellCode()` formula so scripts that branch
  on `$?` are not surprised.

### Non-goals

- We do **not** aim for full XrdCl feature parity. Out of scope for the initial
  effort: metalink (`--tlsmetalink`), ZIP extraction (`--zip`), `pelican://`,
  `s3://`, `http(s)://`/`dav(s)://` copy sources, `xrootd`-as-a-library
  embedding, and the XrdCl plugin ABI. Historical correction: WebDAV/HTTP and
  S3 copy sources were later implemented in `client/xrdcp`; metalink, ZIP,
  `pelican://`, and the XrdCl plugin ABI remain outside the current source
  surface.
- We do **not** reimplement the nginx server's request *handling*; the clients
  are request *originators*. The server handlers stay as-is; only the shared
  primitives move under `libxrdproto`.
- We do **not** copy any XrdCl/XrdApps source. See §3.

---

## 2. Clean-room methodology

The implementation is **clean-room**: it is written from the published wire
contract and from observable CLI behaviour, never by transcribing upstream C++.

**Permitted inputs (the "interface" side of the room):**

- The wire specification headers, treated as a published interface document:
  - Canonical: `/tmp/xrootd-src/src/XProtocol/XProtocol.hh`.
  - This project's already-derived mirror: `src/protocols/root/protocol/*.h`
    (`protocol.h`, `types.h`, `opcodes.h`, `flags.h`, `wire.h`,
    `wire_core_requests.h`, `wire_write_extended_requests.h`, `gsi.h`).
    Per `src/protocols/root/protocol/README.md`, these are "wire facts, not policy" and are
    explicitly cross-checked against the XRootD Protocol Spec v5.2.0 plus the
    `dcache/xrootd4j` and `go-hep/hep` independent implementations.
- Observable CLI behaviour: option strings and semantics documented in
  `/tmp/xrootd-src/docs/man/xrdcp.1` and `xrdfs.1`, plus black-box runs of the
  system `xrdcp`/`xrdfs` (capture stdout/stderr/exit code; diff against ours).
- Public, stable third-party library APIs: OpenSSL `libcrypto`/`libssl`, MIT
  Kerberos `libkrb5` — used directly, not through XrdCrypto wrappers.

**Forbidden inputs (the "implementation" side of the room):**

- The C++ implementation bodies in `XrdCl/` (`XrdClXRootDTransport.cc`,
  `XrdClFS.cc`, `XrdClCopy.cc`, `XrdClClassicCopyJob.cc`, …), `XrdApps/`
  (`XrdCpConfig.cc`, `XrdCpFile.cc`), `XrdSec*/` protocol bodies, and the
  `XrdSut`/`XrdCrypto` containers. We may read them **only** to confirm a
  *wire fact* the spec leaves ambiguous (e.g. the exact `kXR_login` CGI string
  format), and when we do we record the fact, not the code.

**Recording the boundary.** Every non-obvious wire detail used in the client is
annotated in code with a one-line provenance comment of the form
`/* wire: XProtocol.hh <struct/field> — <one-line fact> */`. A
`docs/refactor/phase-37-clean-room-log.md` ledger lists each upstream file
consulted, the specific fact extracted, and an assertion that no implementation
logic was copied. This ledger is the audit artifact for the clean-room claim.

Where the research surfaced an ambiguity that the spec does not pin down, it is
listed in §13 as an open question to be resolved by *observation* (black-box
diff or packet capture against a reference server), never by reading upstream
implementation flow.

---

## 3. Architecture

### 3.1 Guiding principle: one protocol core, two consumers

The centerpiece is **`libxrdproto`** — an ngx-free static library containing the
wire framing, opcode/flag/struct vocabulary, CRC32C, hex, errno↔kXR mapping, and
the OpenSSL hash kernels. It is extracted from files that the research confirms
are already pure (category A) or near-pure (the crypto kernel, category B with
only a worker-lifecycle coupling). After extraction:

- the **nginx module** keeps compiling exactly the same objects, now sourced from
  the shared directory, registered through `config`/`NGX_ADDON_SRCS`;
- the **clients** link the same `libxrdproto.a`.

This is what makes the clients "built atop the project's code" in a literal,
mechanically-enforced sense rather than a copy-paste sense.

### 3.2 Directory & file layout

```
nginx-xrootd/
├── src/                         # existing nginx module (unchanged role)
│   ├── protocol/                # → MOVE under shared core (see 3.3); module includes via -I
│   ├── compat/                  # crc32c, hex, crypto, error_mapping → shared; rest stays
│   └── ...                      # all ngx-coupled handlers stay here
│
├── shared/                      # NEW: the ngx-free protocol core (libxrdproto)
│   └── xrdproto/
│       ├── include/xrdproto/    # public headers for both module and client
│       │   ├── protocol.h       # (moved) umbrella → types/opcodes/flags/wire/gsi
│       │   ├── types.h opcodes.h flags.h wire.h
│       │   ├── wire_core_requests.h wire_write_extended_requests.h gsi.h
│       │   ├── crc32c.h hex.h crypto.h
│       │   └── error_mapping.h  # (only errno→kXR; HTTP section excluded — see §5)
│       ├── crc32c.c             # (moved verbatim — zero deps)
│       ├── hex.c                # (moved verbatim — zero deps)
│       ├── crypto.c             # (moved; init/cleanup re-pointed off ngx worker lifecycle)
│       ├── error_mapping_core.c # (extracted errno→kXR + ns→kXR sections only)
│       ├── ns_status.h          # minimal xrootd_ns_status_t enum (6 values) for the above
│       └── Makefile             # builds libxrdproto.a (gcc/clang, -fPIC)
│
└── client/                      # NEW: the two CLI tools
    ├── lib/                     # client connection/session layer (libxrdclient)
    │   ├── sock.c sock.h        # blocking TCP connect/read/write, DNS, poll(2) timeouts
    │   ├── tls.c tls.h          # OpenSSL SSL_CTX/SSL_connect, in-protocol upgrade, peer verify
    │   ├── frame.c frame.h      # build ClientRequestHdr, read ServerResponseHdr+body
    │   ├── sid.c sid.h          # 2-byte streamid alloc/track/release; pending-request table
    │   ├── conn.c conn.h        # connection object: socket+tls+sid table+session state
    │   ├── handshake.c          # 20B init + kXR_protocol; parse caps (TLS/pgrw/posc)
    │   ├── login.c              # kXR_login; sessid[16]; parse &P= sec token list
    │   ├── auth.c auth.h        # auth-loop driver (kXR_auth/kXR_authmore); dispatch to sec/*
    │   ├── redirect.c           # kXR_redirect follow; tried/triedrc CGI; SSRF guard; limit
    │   ├── wait.c               # kXR_wait / kXR_waitresp backoff (sleep + jitter)
    │   ├── ops_file.c ops_file.h# open/read/readv/pgread/write/pgwrite/close/sync/truncate
    │   ├── ops_meta.c ops_meta.h# stat/statx/dirlist/locate/query/mkdir/rm/rmdir/mv/chmod/
    │   │                        #   prepare/fattr(xattr)
    │   ├── url.c url.h          # root://[user@]host[:port]//path, roots://, file://, '-'
    │   ├── status.c status.h    # XRootDStatus-equivalent: kXR error → message + shell code
    │   ├── checksum.c           # adler32 (zlib), crc32, md5/crc32c (openssl/core); cksum cfg
    │   └── sec/                 # client-side auth protocol modules
    │       ├── sec_unix.c       # geteuid/getegid → "unix" + user + group
    │       ├── sec_ztn.c        # bearer token discovery + retToken framing
    │       ├── sec_sss.c        # keytab load, BF-CFB64 encrypt, identity TLV, outer header
    │       ├── sec_krb5.c       # libkrb5 AP_REQ (optional, compile-gated)
    │       └── sec_gsi.c        # X.509 proxy + DH + AES + RSA-sign + bucket marshalling
    ├── apps/
    │   ├── xrdcp.c              # main(): CLI parse → copy orchestration → progress/exit
    │   ├── xrdcp_config.c/.h    # getopt_long table + flag bitmask (clean-room of XrdCpConfig)
    │   ├── xrdcp_copy.c         # download / upload / TPC drivers, retry, POSC, rate-limit
    │   ├── xrdcp_progress.c     # progress bar / BeginJob/JobProgress/EndJob callbacks
    │   ├── xrdfs.c              # main(): one-shot vs interactive REPL dispatch
    │   ├── xrdfs_repl.c         # readline/getline loop, history, prompt, BuildPath/CWD
    │   └── xrdfs_cmds.c         # 18 subcommands → ops_meta/ops_file calls, output format
    ├── tests/                   # client-local unit tests (frame round-trip, url, sid, cksum)
    ├── Makefile                 # builds libxrdclient.a, xrdcp, xrdfs; links libxrdproto.a
    └── CMakeLists.txt           # optional CMake mirror for packaging
```

### 3.3 What moves vs what stays

- **Moves to `shared/xrdproto/`** (becomes the single source for both sides):
  `src/protocols/root/protocol/*.h`, `src/core/compat/{crc32c,hex,crypto}.{c,h}`, and the
  errno→kXR / ns→kXR portions of `src/core/compat/error_mapping.{c,h}`.
- **Stays in `src/`** (ngx-coupled, server-only): everything else —
  `src/protocols/root/handshake/`, `src/protocols/root/session/`, `src/auth/gsi/`, `src/auth/sss/`, `src/auth/krb5/`,
  `src/auth/token/`, `src/protocols/root/read/`, `src/protocols/root/write/`, `src/protocols/root/dirlist/`, `src/protocols/root/response/`,
  `src/protocols/root/connection/`, `src/net/cms/`, `src/net/manager/`, `src/net/proxy/`, etc.
- The nginx module's `config` adds `-Ishared/xrdproto/include` and lists the
  moved `.c` files in `NGX_ADDON_SRCS`, so the module build is unchanged in
  behaviour. The HTTP-only error-mapping section (the nginx-specific Section 3 of
  `error_mapping.c`) stays module-side and is *not* part of `libxrdproto`.

### 3.4 Dependency graph

```
                 ┌─────────────────────────────────────────┐
                 │  shared/xrdproto  (libxrdproto.a)         │
                 │  protocol/*.h  crc32c  hex  crypto        │
                 │  error_mapping_core (errno→kXR, ns→kXR)   │
                 │  deps: libcrypto only (crypto.c)          │
                 └───────────────┬───────────────┬──────────┘
                                 │               │
              ┌──────────────────┘               └───────────────────┐
              ▼                                                       ▼
   ┌───────────────────────┐                          ┌──────────────────────────┐
   │ nginx module (src/)   │                          │ client/lib (libxrdclient)│
   │ ngx_*  +  libxrdproto │                          │ sock tls frame sid conn  │
   │ (loaded by nginx      │                          │ handshake login auth     │
   │  ./configure)         │                          │ redirect ops_* url status│
   └───────────────────────┘                          │ sec/{unix,ztn,sss,krb5,  │
                                                       │       gsi}               │
                                                       │ deps: libxrdproto,       │
                                                       │  libssl/libcrypto,       │
                                                       │  [libkrb5], [zlib]       │
                                                       └────────────┬─────────────┘
                                                                    │
                                                ┌───────────────────┴──────────────┐
                                                ▼                                   ▼
                                       ┌─────────────────┐               ┌──────────────────┐
                                       │ apps/xrdcp.c    │               │ apps/xrdfs.c     │
                                       │ (+xrdcp_*.c)    │               │ (+xrdfs_*.c)     │
                                       └─────────────────┘               └──────────────────┘
```

The arrows are link/include only; there are **no** edges from `libxrdproto` back
to `ngx_*` or to `client/lib`. That acyclicity is the invariant a CI check
enforces (§13).

---

## 4. Reuse map

Capability → disposition, grounded in the research's file-level ngx-coupling
analysis. "Reuse-as-is" = copy/link the project file unchanged.
"Reuse-after-extract" = the algorithm is pure but the file has a thin ngx wrapper
to strip. "Reimplement-client-side" = logic is ngx-coupled or is the opposite
(client) role of a server-side feature.

| Capability | Verdict | Source / note |
|---|---|---|
| Wire opcodes, flags, packed request/response structs | **reuse-as-is** | `src/protocols/root/protocol/*.h` — header-only, `#pragma pack(1)`, zero ngx. Becomes `shared/xrdproto/include/`. |
| CRC32C (SSE4.2 + software Castagnoli) | **reuse-as-is** | `src/core/compat/crc32c.{c,h}` — only `<stddef.h> <stdint.h> <string.h>`. For pgread/pgwrite + checksum. |
| Hex encode/decode | **reuse-as-is** | `src/core/compat/hex.{c,h}` — zero ngx. Checksum/ETag/DN display. |
| errno→kXR mapping | **reuse-after-extract** | `src/core/compat/error_mapping.c` Section 1–2 are pure; Section 3 (errno→HTTP) is nginx-only and excluded. Needs minimal `xrootd_ns_status_t` enum from `namespace_ops.h` → copy as `ns_status.h`. |
| HMAC-SHA256 / SHA-256 (OpenSSL EVP) | **reuse-after-extract** | `src/core/compat/crypto.{c,h}`. The only ngx coupling is the *worker* init/cleanup pattern; replace with `main()`-time `xrootd_crypto_init()` + `atexit(xrootd_crypto_cleanup())`. Hash bodies are identical. Used for GSI signing-key derivation + `kXR_sigver`. |
| Initial 20B handshake validate + reply | **reimplement-client-side** | `src/protocols/root/handshake/client_hello.c` logic is correct but uses `ngx_palloc`/`ngx_log_t`/`ngx_connection_t`; client side is also the *opposite* role (we *send* the 20B init, *receive* the reply). Constants reused. |
| `kXR_protocol` capability negotiation | **reimplement-client-side** | Parse `ServerResponseBody_Protocol` flags (`kXR_haveTLS`/`kXR_gotoTLS`/`kXR_suppgrw`/`kXR_supposc`) ourselves; struct from `protocol/wire.h`. |
| `kXR_login` + sessid + `&P=` sec-token parse | **reimplement-client-side** | `src/protocols/root/session/login.c` is ngx-coupled; we issue the request, store `sessid[16]`, split the sec string. |
| Auth state machine (`kXR_auth`/`kXR_authmore`) | **reimplement-client-side** | `src/protocols/root/session/`, `src/auth/gsi/`, `src/auth/sss/`, `src/auth/token/` are server-role + ngx-coupled. Client drives the loop. |
| GSI: X.509 chain, DH, AES, RSA-sign, buckets | **reimplement-client-side** (crypto reuse-after-extract) | `src/auth/gsi/`, `src/auth/crypto/gsi_verify.c` are server-role verification + ngx. Client builds the request side; low-level DH/AES/RSA/SHA come straight from OpenSSL `libcrypto`. Bucket frame format derived from `protocol/gsi.h` `kXRS_*`. |
| SSS: keytab load, BF-CFB64, identity TLV | **reimplement-client-side** | `src/auth/sss/` decrypts/verifies (server role); client encrypts. BF crypt kernel mirrors `auth_crypto_helpers.c`'s `xrootd_sss_bf32_crypt`. Keytab file format reverse-engineered (open question §13). |
| Token (ztn) bearer send | **reimplement-client-side** | `src/auth/token/` validates JWTs (server role); client merely *discovers and sends* the token. No client-side JWT verification needed. |
| Kerberos5 AP_REQ | **reimplement-client-side** (libkrb5 reuse-as-is) | `src/auth/krb5/auth.c` validates AP_REQ (server). Client uses `libkrb5` (`krb5_mk_req_extended`) directly, compile-gated `XROOTD_HAVE_KRB5`. |
| `kXR_sigver` request-signing envelope | **reimplement-client-side** (HMAC reuse-after-extract) | Envelope framing + sequence tracking reimplemented; `xrootd_hmac_sha256()` reused. |
| TCP socket I/O | **reimplement-client-side** | `src/protocols/root/connection/` is ngx event-loop. Client uses blocking sockets + `poll(2)` for timeouts. |
| TLS upgrade / `roots://` | **reimplement-client-side** | `src/protocols/root/session/tls.c` is ngx_ssl. Client uses OpenSSL `SSL_CTX`/`SSL_connect` directly. |
| streamid alloc + out-of-order matching | **reimplement-client-side** | Simple alloc/track/release + pending table. |
| Redirect follow + tried/triedrc | **reimplement-client-side** | Parse `ServerRedirectBody` (port+host); maintain visited-set CGI; SSRF guard + limit. |
| `kXR_wait`/`kXR_waitresp` backoff | **reimplement-client-side** | Sleep N seconds (+ jitter); transport-layer per research §"backoff". |
| File ops framing (open/read/write/close/…) | **reimplement-client-side** | Structs reused from `wire*.h`; loops are new. |
| Metadata ops + response parsing | **reimplement-client-side** | Structs reused; StatInfo/LocationInfo/dirlist parsing new. |
| Exit-code mapping | **reuse-as-is (formula)** | `(code/100)+50`; encode in `status.c`. |
| Local file I/O, getpwuid/getgrgid | **reuse-as-is (libc)** | POSIX directly. |
| MD5/SHA hashing for integrity | **reuse-as-is (OpenSSL)** | EVP directly. |
| CLI parsing, URL parse, path normalize, REPL, progress | **reimplement-client-side** | XrdCpConfig/XrdCpFile/XrdClFS are C++/STL; trivial clean-room C. |

---

## 5. Protocol coverage (client state machine)

The client implements the full main-stream state machine and the parallel-stream
sub-machine. States and transitions (from the wire contract, not XrdCl code):

```
DISCONNECTED
   │  TCP connect (sock.c)
   ▼
HANDSHAKE_SENT          send 20B ClientInitHandShake {0,0,0,htonl(4),htonl(2012)}
   │                    immediately followed by ClientProtocolRequest
   │                       requestid=kXR_protocol, clientpv=htonl(0x520),
   │                       flags |= kXR_ableTLS [| kXR_wantTLS if roots://],
   │                       expect=kXR_ExpLogin
   ▼  recv ServerInitHandShake (at off 4) + ServerResponseBody_Protocol
PROTOCOL_DONE           record server flags: kXR_haveTLS/kXR_gotoTLS,
   │                       kXR_suppgrw (pgread/pgwrite ok), kXR_supposc (POSC ok),
   │                       isServer/isManager; optional 'S'(secreqs)/'B'(bifreqs)
   │  [if kXR_gotoTLS or (kXR_wantTLS && kXR_haveTLS)] → TLS upgrade (tls.c) here
   ▼
LOGIN_SENT              send kXR_login {pid, username[8], ability/ability2,
   │                       capver|kXR_asyncap, CGI body "xrd.cc=..&xrd.tz=.."}
   ▼  recv ServerResponseBody_Login → sessid[16] + sec[] ("&P=gsi,..&P=unix..")
LOGIN_DONE
   │  sec[] empty ──────────────────────────────► CONNECTED
   │  sec[] non-empty: pick protocol by preference order (token>gsi>krb5>sss>unix
   │                   intersected with what we have credentials for)
   ▼
AUTH_SENT  ◄────────────┐  send kXR_auth {credtype[4], blob}
   │                    │
   ▼  recv …            │
   ├─ kXR_authmore(4002)┘  feed challenge back into sec/<proto> → next blob
   ├─ kXR_ok(0) ─────────► CONNECTED
   └─ kXR_error(4003) ──► fail (auth error, shell code 53)
                                   │
CONNECTED ─────────────────────────┘
   │  per data/metadata op: alloc streamid, send request, await matching response
   │  response dispatch by status:
   │    kXR_ok(0)        → consume body, complete op
   │    kXR_oksofar(4000)→ readv partial chunk; keep reading until kXR_ok
   │    kXR_error(4003)  → errnum+msg → status.c → maybe retry/failover
   │    kXR_redirect(4004)→ redirect.c: tear down, reconnect host:port, replay
   │    kXR_wait(4005)   → wait.c: sleep N then resend same request
   │    kXR_waitresp(4006)→ wait.c: keep connection, await async kXR_ok later
   │    kXR_status(4007) → pgread/pgwrite framing (see below)
   │    kXR_attn(4001)   → async attention (asyncms/asynresp) — minimal handling
   ▼
ENDSESS  send kXR_endsess{sessid[16]} → recv kXR_ok → close
```

**Parallel-stream sub-machine** (for `--streams N>0`): per extra stream, open a
new TCP connection, run DISCONNECTED→HANDSHAKE_SENT→PROTOCOL_DONE, then
`BIND_SENT` (send `kXR_bind{sessid[16]}` using the control stream's `sessid`) →
recv `ServerResponseBody_Bind` carrying the server-assigned `substreamid` →
CONNECTED. Subsequent `kXR_read`/`kXR_write` carry that stream's `pathid` to
route to the bound substream.

**pgread/pgwrite + `kXR_status` framing** (invariant #1 of the module):

- Request `kXR_pgread` (`ClientPgReadRequest` in
  `wire_write_extended_requests.h`): `fhandle[4]`, `offset[8]`, `rlen[4]`,
  optional `{pathid, reqflags}`.
- Response is `ServerResponseStatus` = 8B header + 16B body
  (`crc32c`, `streamID[2]`, `requestid`, `resptype`
  Final/Partial/Progress, `dlen`) followed by `ServerResponseBody_pgRead`
  `offset[8]` + payload. Payload is page-framed at `kXR_pgPageSZ`=4096 with a
  trailing 4-byte CRC32C per page (unit `kXR_pgUnitSZ`=4100). The client
  validates each page CRC via `xrootd_crc32c_value()` and the 16B-body
  `crc32c` over the remaining `dlen`. Mismatch → re-request the page(s).
- `kXR_pgwrite` (`ClientPgWriteRequest`): client computes per-page CRC32C, sends
  4096-multiple page data; response `ServerResponseBody_pgWrite{offset}` plus, on
  error, `ServerResponseBody_pgWrCSE{cseCRC,dlFirst,dlLast}` + array of bad-page
  offsets → client resends only the bad pages.

**Out-of-order matching:** `sid.c` allocates a 2-byte streamid per outstanding
request, maps streamid→handler/buffer in a pending table; on any response the
8-byte header's `streamid` selects the handler. The initial xrdcp/xrdfs use is
mostly synchronous (one in-flight per stream), but the table is the foundation
for `--streams` and readv pipelining.

---

## 6. Auth (client side)

The auth driver (`auth.c`) parses the `&P=proto,args` list from the `kXR_login`
sec token, intersects it with locally-available credentials, and dispatches to a
`sec/<proto>` module. Each module is a small state object exposing
`init(args)` → `step(server_blob) → {client_blob, done|more|fail}`.

| Proto | credtype | Credential discovery (env / default) | Crypto primitives | Reuse vs add |
|---|---|---|---|---|
| **unix** | `unix` | none — `geteuid()`/`getegid()` → user+group via `getpwuid`/`getgrgid` | none | reimplement (trivial) |
| **ztn** (token) | `ztn` | `BEARER_TOKEN` → `BEARER_TOKEN_FILE` → `$XDG_RUNTIME_DIR/bt_u<uid>` → `/tmp/bt_u<uid>` → `xrd.ztn` URL param. File must be mode `& (group|other) == 0`. Strip whitespace. | none (TLS provides confidentiality) | reimplement; framing = `TokenResp` hdr `{id="ztn",ver=0,opr='T',len:u16 BE}` + token |
| **sss** | `sss` | `$XrdSecSSSKT`/`$XrdSecsssKT` or generated default keytab path | Blowfish-CFB64 (CryptoLite BF32) + CRC32 integrity | crypto reuse-after-extract (`xrootd_sss_bf32_crypt`); keytab parse + identity TLV new |
| **krb5** | `krb5` | `$KRB5CCNAME` or `/tmp/krb5cc_<uid>` | MIT `libkrb5` (`krb5_init_context`, `krb5_cc_default`, `krb5_get_credentials`, `krb5_mk_req_extended` with `AP_OPTS_USE_SESSION_KEY`; `,fwd` → forwarded creds) | reuse libkrb5 as-is; compile-gated `XROOTD_HAVE_KRB5` |
| **gsi** | `gsi` | `$X509_USER_PROXY` or `/tmp/x509up_u<uid>`; `$X509_CERT_DIR` or `/etc/grid-security/certificates/` | OpenSSL: X.509 PEM/DER chain, DH key agreement, AES-128/256-CBC, RSA sign, SHA-256 | low-level all reuse-after-extract from OpenSSL; bucket marshalling new |

**GSI flow (the hard one), derived from the wire facts in `protocol/gsi.h`:**

1. Client sends `kXGC_certreq` (step from `gsi.h`).
2. Server replies `kXGS_cert`: server cert + DH params + random tag (`rtag`).
3. Client: parse server cert, generate own DH keypair, derive shared secret
   (`EVP_PKEY_derive` over FFDHE2048), build a session cipher (AES-CBC) keyed by
   the secret.
4. Client exports its X.509 **proxy chain** in DER and AES-encrypts it.
5. Client RSA-signs `rtag` with the proxy private key.
6. Client sends `kXGC_cert` carrying the buckets named in `gsi.h`:
   `kXRS_version`, `kXRS_issuer_hash`, `kXRS_cipher_alg`, `kXRS_md_alg`,
   `kXRS_puk` (client RSA pubkey), `kXRS_cipher` (DH pubkey, signed on v10.4+),
   `kXRS_x509` (encrypted proxy chain), `kXRS_rtag` (signed), `kXRS_main`
   (session-encrypted main buffer). Defaults: cipher list
   `aes-128-cbc:bf-cbc:des-ede3-cbc`, MD `sha256`, RSA 2048.
7. Server verifies; on success → `kXR_ok`. Client derives the `kXR_sigver`
   signing key as `SHA-256(DH-shared-secret)` (via `xrootd_sha256()`), then
   wraps subsequent requests in `kXR_sigver` HMAC envelopes
   (`xrootd_hmac_sha256()`) with a monotonic sequence number, **if** the server's
   `kXR_secreqs` 'S' section requested signing (`kXR_signNeeded`/`signLikely`).

**Bucket frame format** (`XrdSutBucket`-equivalent): each bucket = `{type:u32,
len:u32, bytes[len]}`; a buffer is a concatenation of buckets, optionally with a
`kXRS_main`-wrapped encrypted region. The exact numeric `kXRS_*` IDs come from
`src/protocols/root/protocol/gsi.h`; the binary container layout is recorded in the clean-room
ledger (§13 open question) once confirmed by capture against a reference server.

**Global env** honoured at startup (like XrdCl DefaultEnv, but minimal):
`XRD_LOGLEVEL`, `XRD_REDIRECTLIMIT`, `XRD_CPTPCTIMEOUT`, `XRD_REQUESTTIMEOUT`,
plus the credential env vars above. These set process-wide defaults; there is no
per-command env reload.

---

## 7. xrdcp design

### URL grammar (`url.c`)

```
root://[user@]host[:port]//abs/path     # // separates authority from absolute path
xroot://  = root://                      # alias
roots://  = root:// + kXR_wantTLS        # in-protocol TLS
xroots:// = roots://                      # alias
file:///local/path  |  /local/path  |  ./rel   # local (libc I/O)
-                                        # stdin (source) / stdout (destination)
```

Protocol detection by prefix match (clean-room of `XrdCpFile` PType logic).
Historical initial-scope note: `http(s)://`, `dav(s)://`, `s3://`,
`pelican://`, and metalink were declined in this plan. Current correction:
`client/xrdcp` now implements WebDAV/HTTP and S3 transfer paths; `pelican://`,
metalink, and ZIP extraction remain outside the current client surface.

### Copy directions (`xrdcp_copy.c`)

- **Download (remote→local):** `kXR_open(kXR_open_read)` → loop
  `kXR_read`/`kXR_pgread` (pgread when server advertised `kXR_suppgrw` and the
  caller wants per-page integrity) → local `write()` → `kXR_close`.
- **Upload (local→remote):** `kXR_open(kXR_open_wrto [| kXR_delete if --force]
  [| kXR_new if exclusive] [| kXR_mkpath] [| kXR_posc if -P])` → local `read()`
  → loop `kXR_write`/`kXR_pgwrite` → `kXR_sync` (optional) → `kXR_close`. On
  error with POSC/`--rm-bad-cksum`, the server discards the temp on un-clean
  close; client additionally issues `kXR_rm` if needed.
- **TPC (remote→remote):** `xrdcp --tpc first|only [delegate]`. Initiator opens
  source and destination; destination server pulls from source. With `delegate`
  (GSI only), client credentials are forwarded so the target authenticates to
  source as the user. Honour `XRD_CPTPCTIMEOUT`; poll for completion via the
  destination open's TPC opaque + a `kXR_query`/`stat` completion check.
  `first` falls back to classic copy on TPC failure; `only` fails hard.

### Features

- **Recursive (`-r`):** remote source → `kXR_dirlist` (with recurse/stat flags)
  to flatten the tree, preserving the directory offset so relative paths are
  reproduced under the destination directory (clean-room of `IndexRemote`/`Doff`
  logic). Local source → `nftw`/manual walk.
- **Checksum (`--cksum type:[value|source|print|auto]`):** `checksum.c`
  computes adler32 (zlib), crc32, md5, crc32c (OpenSSL/`xrootd_crc32c_*`) while
  streaming. `:source` fetches reference via `kXR_query`+`kXR_Qcksum`; `end2end`
  compares; `:print` reports only; `auto` infers from server config /extension.
  Mismatch + `--rm-bad-cksum` → delete dest, fail.
- **Parallel streams (`-S|--streams 1..15`):** establish N bound substreams
  (§5), assign read/write chunks round-robin to the least-loaded substream.
- **Multi-source (`-y|--sources 1..32`):** `kXR_locate` returns replicas;
  round-robin / failover; drop a slow source on `--xrate-threshold`.
- **POSC (`-P`):** sets `kXR_posc` (0x1000) on the write open.
- **Progress (`xrdcp_progress.c`):** `BeginJob`/`JobProgress`(≥1 s throttle)/
  `EndJob` callbacks; bar to stderr; suppressed by `-N|--nopbar`, `-s|--silent`,
  or non-tty.
- **Rate limit (`--xrate`, `--xrate-threshold`):** token-bucket / sleep at the
  copy-loop level when one side is local; threshold triggers source failover.
- **Retry (`--retry N`, `--retry-policy force|continue`):** `force` re-runs the
  job; `continue` (with `--continue`) resumes from the dest size queried via
  `kXR_stat`.
- **Exit codes:** `(XRootDStatus.code / 100) + 50` (e.g. socket 102→51), `0` on
  success, `50` for CLI/config errors (`status.c`).

### CLI options (clean-room `getopt_long` table in `xrdcp_config.c`)

Implemented first tier: `-f/--force`, `-r/--recursive`, `-P/--posc`,
`-S/--streams`, `-y/--sources`, `--cksum`, `--retry`, `--retry-policy`,
`-s/--silent`, `-N/--nopbar`, `-v/--verbose`, `-d/--debug`, `--xrate`,
`--xrate-threshold`, `--tpc [delegate] first|only`, `--continue`,
`--notlsok`, `--tlsnodata`, `-H/--license`, `-h/--help`, `-V/--version`.
Deferred / explicit-error: `-z/--zip*`, `--tlsmetalink`, `--xattr`, `--proxy`
(upstream-unimplemented anyway), `--dynamic-src`, `--server`.

---

## 8. xrdfs design

### Invocation (`xrdfs.c`)

- **One-shot:** `xrdfs [--no-cwd] host[:port] <command> [args]` → connect, run,
  print, exit with the command's shell code.
- **Interactive REPL (`xrdfs_repl.c`):** `xrdfs [--no-cwd] host[:port]` with no
  command → prompt `[host] /cwd > `. Line editing via `readline` if available
  (compile-gated `HAVE_READLINE`), else `getline()` fallback. History in
  `$HOME/.xrdquery.history`. Per-session `Env`: `CWD` (default `/`), `ServerURL`,
  `NoCWD`. `BuildPath()` resolves relative paths against `CWD`, collapses `.`/`..`,
  trims trailing slash — clean-room of the documented normalizer.

### Subcommand → wire op map (`xrdfs_cmds.c`)

| Command | Syntax (key flags) | Wire op(s) | Output |
|---|---|---|---|
| `cd` | `cd <path>` | `kXR_stat` (validate dir) | updates `Env[CWD]`, no print |
| `ls` | `ls [-l -u -R -D -Z -C -h] [dir]` | `kXR_dirlist` (+`kXR_dstat`/`kXR_dcksm`; `kXR_stat`) | `[d-][rwx]9 owner group size [cksum] mtime path` |
| `locate` | `locate [-n -r -d -m\|-h -i -p] <path>` | `kXR_locate` (`kXR_nowait`/refresh/prefname) | `addr type access` per replica |
| `stat` | `stat [-q flags] <path>...` | `kXR_stat` (+ extended) | Path/Id/Size/MTime/Flags(oct+names)[/Mode/Owner/Group]; `-q` → shell 55 on miss |
| `statvfs` | `statvfs <path>` | `kXR_stat` (vfs) | RW/staging node counts, sizes(MB), util% |
| `mkdir` | `mkdir [-p] [-m mode9] <dir>` | `kXR_mkdir` (`kXR_mkpath`) | status line |
| `rm` | `rm <file>...` | `kXR_rm` (parallel via streamid table) | `rm <path> : <status>` |
| `rmdir` | `rmdir <dir>` | `kXR_rmdir` | status |
| `mv` | `mv <a> <b>` | `kXR_mv` (space-separated wire form — see module memory) | status; reject move-into-own-subdir |
| `chmod` | `chmod <path> <mode9>` | `kXR_chmod` (UR..OX bitmask) | status |
| `truncate` | `truncate <file> <len>` | `kXR_truncate` (open or by-path) | status |
| `query` | `query <code> <param>` | `kXR_query` w/ `kXR_Qconfig`/`Qcksum`/`Qckscan`/`Qopaque`/`Qopaquf`/`Qspace`/`QStats`/`Qxattr`/`QPrep` | raw server response |
| `prepare` | `prepare [-c -f -s -w -e -p N -a id] files` | `kXR_prepare` (colocate/fresh/stage/write/cancel/evict, prio 0–3) | response if `-s` |
| `cat` | `cat [-o out] files...` | `kXR_open(read)`+`kXR_read` loop → stdout/file | streamed bytes |
| `tail` | `tail [-c N] [-f] file` | `kXR_open(read)`+`kXR_read` (poll on `-f`) | last N bytes / follow |
| `spaceinfo` | `spaceinfo <path>` | `kXR_query`/space utils | Total/Free/Used/Largest |
| `xattr` | `xattr <path> set\|get\|del\|list [arg]` | `kXR_fattr` (`kXR_fattrGet`/`Set`/`Del`/`List`) | `# file: <path>` + `name="value"` |
| `cache` | `cache evict\|fevict <path>` | `kXR_query`/raw cache cmd | response if present |
| `help` / `exit` | — | none | help text / quit |

Output formatting (`xrdfs_cmds.c`): column alignment via `printf` width
specifiers; human sizes via a small `genHumanSize` reimplementation; stat flags
rendered as `decimal (Name|Name|...)`. Argument tokenizer handles single/double
quotes and whitespace (clean-room of `getArguments`).

---

## 9. Build & packaging

### Shared core

`shared/xrdproto/Makefile` builds `libxrdproto.a` from `crc32c.c hex.c crypto.c
error_mapping_core.c` with `-I include`, `-fPIC`, and the same hardening flags
the module's `config` already applies (`-D_FORTIFY_SOURCE=2
-fstack-protector-strong -fstack-clash-protection -fcf-protection=full -Wformat
-Werror=format-security`, `-O3 -march=x86-64-v2` overridable via
`XROOTD_OPTIMIZE`). Only link dep: `libcrypto` (for `crypto.c`).

### nginx module

`config` is amended to (a) add `-Ishared/xrdproto/include` to `CFLAGS`, and
(b) list the moved `.c` files in `NGX_ADDON_SRCS` (so `./configure` compiles them
into the module exactly as before). No new top-level config block → no behaviour
change beyond the include path. Per BUILD GOVERNANCE, this is the only sanctioned
way to register the relocated sources.

### Clients

`client/Makefile` (primary) builds `libxrdclient.a` then links `xrdcp` and
`xrdfs`:

```
CLIENT_LIBS = -lssl -lcrypto                 # mandatory
ifdef XROOTD_HAVE_KRB5
  CLIENT_LIBS += $(shell pkg-config --libs krb5)
endif
HAVE_ZLIB  := $(shell pkg-config --exists zlib && echo 1)   # adler32
HAVE_READLINE := $(shell pkg-config --exists readline && echo 1)

xrdcp: apps/xrdcp.o xrdcp_config.o xrdcp_copy.o xrdcp_progress.o \
       libxrdclient.a ../shared/xrdproto/libxrdproto.a
	$(CC) $^ $(CLIENT_LIBS) -o $@
```

A parallel `CMakeLists.txt` (`find_package(OpenSSL REQUIRED)`,
`find_package(krb5)`, `find_package(ZLIB)`) mirrors the Makefile for distro
packaging. Krb5/zlib/readline are all soft-optional and compile-gated.

### Packaging

A new `packaging/rpm/nginx-xrootd-clients.spec` (sibling to
`nginx-mod-xrootd.spec`): `BuildRequires: openssl-devel, krb5-devel, zlib-devel,
readline-devel`; `Requires: openssl-libs, krb5-libs`; installs `xrdcp` and
`xrdfs` to `%{_bindir}`. `BUILD_INSTALL.md` gains a "native clients" section.
Keeping clients in a separate RPM avoids coupling the module's `.so` lifecycle to
the binaries.

---

## 10. Testing strategy

The clients drop into the existing harness, which already invokes
`xrdcp`/`xrdfs` via `subprocess.run([XRDCP_BIN, ...])` and selects the binary via
`settings.XRDCP_BIN`/`XRDFS_BIN` (default `xrdcp`/`xrdfs`). Pointing
`TEST_XRDCP_BIN`/`TEST_XRDFS_BIN` at our build runs the entire suite unchanged.

Layers:

1. **Unit (`client/tests/`):** frame build/parse round-trips; streamid
   alloc/match; URL parse table; path normalize; checksum vectors; GSI/SSS bucket
   marshalling against fixed golden bytes; pgread CRC32C against known pages.
2. **Round-trip vs nginx fleet + reference xrootd:** reuse
   `manage_test_servers.sh` (nginx 11094–11123, ref xrootd 11098–11113, PKI under
   `/tmp/xrd-test/pki`, seeds `test.txt`, `random.bin` 5 MB, `large200.bin`
   200 MB). New `tests/test_native_xrdcp_xrdfs.py` mirrors
   `test_e2e_redirector_xrdcp.py`: `xrdcp -f <url> <local>` and reverse, MD5
   byte-exact (chunked hashing for the 200 MB file), `xrdfs stat`/`ls` keyword +
   value checks.
3. **Byte-exact + checksum-exact:** MD5 of source vs sink for every transfer;
   plus `kXR_query`+`kXR_Qcksum` (adler32/crc32c) cross-check, as
   `test_conformance.py` already does for nginx-vs-xrootd.
4. **Conformance diff vs system `xrdcp`/`xrdfs`:** a new
   `tests/test_native_client_conformance.py` runs the *same* command through both
   our binary and the system binary against both the nginx and reference servers,
   asserting identical ok/error outcome, identical error code, identical exit
   code, and identical normalized output (set comparison for `ls`, value
   comparison for `stat`). This is the gating test for the clean-room behavioural
   claim and reuses the existing `CONFORMANCE_NGINX_URL` topology runner so the
   clients are also exercised through proxy/mesh/cluster/mirror front-ends.
5. **Auth matrix:** anon (11094), GSI (11095/TLS 11096) using
   `$X509_USER_PROXY`/`$X509_CERT_DIR` from the harness PKI, token (11097),
   SSS/krb5 where the harness provides keytabs/ccache.

CI guard: a script greps `libxrdproto.a` (and its objects) for any `ngx_`
symbol; non-empty result fails the build (enforces the ngx-free invariant).

---

## 11. Milestones / phasing

Each milestone is independently demoable and testable.

| M | Deliverable | Demo / gate |
|---|---|---|
| **M0** | Extract `libxrdproto`: move `protocol/*.h`, `crc32c`, `hex`, `crypto`, `error_mapping_core`; re-point module `config`; CI ngx-free guard | Module still builds & passes existing tests; `libxrdproto.a` produced; guard green |
| **M1** | `sock`+`frame`+`sid`+`handshake`+`login`(anon)+`ops_meta` stat/dirlist; `xrdfs stat`/`ls` one-shot | `xrdfs <anon> stat /file` & `ls /` match system xrdfs vs nginx 11094 + ref 11098 |
| **M2** | `ops_file` open/read/close + download driver; `xrdcp <url> <local>` | 5 MB + 200 MB download MD5 byte-exact vs origin |
| **M3** | write/close + upload driver; POSC; `--force`; `xrdcp <local> <url>` | Upload round-trip MD5-exact; POSC atomicity |
| **M4** | `auth.c` + `sec_gsi` (+`sec_unix`,`sec_ztn`); GSI download/upload | GSI (11095) + token (11097) round-trips pass |
| **M5** | `redirect.c` (tried/triedrc, SSRF guard, limit) + multi-source `locate` | Redirector/cluster topology copies (mirror existing `test_e2e_redirector_xrdcp`) |
| **M6** | pgread/pgwrite `kXR_status` CRC32C framing + `--cksum` end2end/source/print | Per-page CRC validated; checksum mismatch → fail+cleanup |
| **M7** | `tls.c` in-protocol TLS / `roots://`; `--notlsok`/`--tlsnodata`; peer verify | `roots://` (11096) round-trips; bad cert rejected |
| **M8** | `--streams` (kXR_bind substreams) + TPC (`--tpc first/only/delegate`) | Parallel-stream copy; server-to-server TPC completes |
| **M9** | Full `xrdfs`: REPL, all 18 subcommands, `xattr`/`query`/`prepare`/`mv`/`chmod`/`truncate`/`cat`/`tail` | Interactive session + every subcommand vs system xrdfs |
| **M10** | Conformance gate: `test_native_client_conformance.py` green across anon/GSI/token × nginx/ref × direct/proxy/cluster/mirror | Gating CI job; clean-room ledger finalized |

---

## 12. Risks & invariants

**Invariants to hold (carry the module's own rules into the clients):**

1. pgread/pgwrite **must** use `kXR_status` (4007) framing + per-page CRC32C
   (`kXR_pgPageSZ`=4096 / `kXR_pgUnitSZ`=4100) via `xrootd_crc32c_*`. No
   short-cutting to plain `kXR_read` when the caller asked for paged integrity.
2. `libxrdproto` stays **ngx-free** — no `ngx_*` symbol, no `ngx_config.h`
   include. Enforced by the CI grep guard. This is what keeps the "shared core"
   claim honest and prevents the client build from needing nginx.
3. Wire framing comes **only** from `shared/xrdproto/include/` structs — the
   client never hand-rolls a parallel struct definition (single source of truth,
   same rule the module's `protocol/README.md` states).
4. The shared core and the client never link `libXrdCl`/`libXrdSec*`.

**Risks & mitigations:**

- **Clean-room boundary breach.** Largest reputational/legal risk. Mitigation:
  the §3 ledger, per-line `wire:` provenance comments, and a review checklist
  item; resolve every §13 ambiguity by *observation* (capture/diff against a
  reference server), not by reading XrdCl `.cc` flow.
- **GSI client crypto complexity.** DH/AES/RSA-sign + the `XrdSutBucket`
  container is the densest, least-specified area (exact bucket binary layout,
  v10.4 vs v10.6 signed-DH behaviour are open questions). Mitigation: golden-byte
  unit tests captured from a real GSI handshake; isolate all of it behind
  `sec_gsi.c` so anon/token/unix ship in M1–M4 regardless.
- **Redirect / TLS correctness & security (SSRF on redirect).** A `kXR_redirect`
  names an arbitrary host:port; blindly following is an SSRF primitive.
  Mitigation: `redirect.c` enforces `XRD_REDIRECTLIMIT`, maintains a
  tried/triedrc visited-set, and applies an allowlist/loopback policy gate before
  reconnecting; TLS peer-certificate verification against `$X509_CERT_DIR` is
  **on by default** (a `--notlsok`-style downgrade must be explicit, never
  silent).
- **Keeping the shared core ngx-free under future edits.** The CI guard plus
  keeping the directory physically separate (`shared/` not `src/`) and a one-line
  rule in `CLAUDE.md`/`AGENTS.md` ("never add `ngx_*` to `shared/xrdproto`").
- **Behavioural drift from system tools.** Mitigation: M10 conformance gate
  diffs exit codes and normalized output for every supported op against the
  system binaries.
- **Async/concurrency scope creep.** Initial design is blocking-synchronous with
  `poll(2)` timeouts; the streamid pending-table is the only concurrency
  affordance, used for `--streams`/readv. Mitigation: keep a single in-flight
  request per stream until M8; do not introduce a thread pool unless a milestone
  demonstrably needs it.

---

## 13. Open questions (resolve by observation, not by reading XrdCl bodies)

These are the spec ambiguities surfaced in research; each is to be answered by
black-box diff or packet capture against a reference server, and recorded in the
clean-room ledger:

1. Exact binary layout of an `XrdSutBucket` (bucket type IDs from `gsi.h`; length
   encoding; encrypted-region marker) and whether DH params are RSA-signed on the
   server's `kXGS_cert` for v10.4 vs v10.6.
2. The `XrdSecsssKT` keytab on-disk format (entry framing, key serialization).
3. Exact `kXR_login` CGI body grammar (`xrd.cc=..&xrd.tz=..`) and escaping rules.
4. `kXR_readv`: one `kXR_oksofar` per chunk vs batched chunks per response.
5. `sessid[16]` semantics — fixed 16 bytes, opaque, echoed into `kXR_bind`/
   `kXR_endsess` (assume opaque token; confirm length).
6. Whether `kXR_wait` backoff is honoured at transport (resend) vs app layer
   (assume transport-layer resend of the same request with the same streamid).
7. `--continue` resume offset source (query dest `kXR_stat` size vs local
   tracking) and whether `--retry-policy continue` re-opens at offset.
8. `--xrate` enforcement point (socket throttle vs copy-loop pacing) and whether
   it counts control + data streams.
9. Handling of a `kXR_redirect` received mid-auth (between `kXR_login` and final
   `kXR_ok`) — treat as fatal-reconnect-from-scratch unless capture shows
   otherwise.

---

## 14. Adjacent client-side tools & libraries (extended roadmap atop the shared core)

`xrdcp` and `xrdfs` are the first two consumers, but the real leverage is the
**`libxrdproto` core (§3) + the `client/lib` connection/session layer**: once those
exist, almost the entire XRootD *client-side* family becomes a thin front-end over
them. Every item below qualifies because it is a request **originator** (or pure
local crypto) — never a server daemon or storage/auth *plugin* — and each one
inherits, unchanged, the clean-room methodology (§2), the reuse model (§4), the
standalone build (§9), and the conformance harness (§10: build it, point the
matching `TEST_*_BIN` at it, diff against the system tool). The inventory below was
taken from the XRootD `add_executable` targets; server-only and out-of-scope
targets are listed explicitly in §14.6 so the boundary is auditable.

### 14.1 The public C client library — `libxrdc` (`xrdclient.h`)  *(headline)*

The `client/lib/` layer (sock/tls/frame/sid/conn/handshake/login/auth/redirect/
ops_*/sec/*) built for `xrdcp`/`xrdfs` **is**, once stable, the clean-room
equivalent of `libXrdCl` for C consumers. Promote it from an internal `.a` to a
**public, SONAME-versioned, documented C API** so any C program (or language
binding) can speak `root://` with **no `libXrdCl`/`libXrdSec*`** — only
`libxrdproto` + OpenSSL.

- Handle-based, blocking-with-`poll(2)`-timeouts API mirroring `XrdCl::File` /
  `XrdCl::FileSystem` *semantics* (not its C++ shape):
  `xrdc_fs_open(url)` → `xrdc_stat/_statvfs/_dirlist/_locate/_query/_mkdir/_rm/
  _rmdir/_mv/_chmod/_truncate/_prepare/_fattr`;
  `xrdc_file_open()` → `xrdc_read/_pgread/_readv/_write/_pgwrite/_sync/_truncate/
  _close`; `xrdc_copy(src,dst,opts)` (the `xrdcp` engine exposed as a call);
  `xrdc_last_status()` → `{kXR code, errno, message, shellcode}`.
- Ships `libxrdc.{so,a}` + `xrdclient.h` + `xrdclient.pc` (pkg-config); thread
  model documented (one `conn` object per thread to start).
- This is what makes "tools **and libraries**" literal: `xrdcp`, `xrdfs`, and every
  tool below all collapse to thin front-ends over this single library.

### 14.2 Tier 1 — trivial CLI tools (land alongside the read/query path, ~M2/M6)

Each is a few-hundred-LoC front-end over primitives already being written.

| Tool | Does | Reuses | Note |
|---|---|---|---|
| `xrdcrc32c` | CRC32C of a local-or-`root://` file | **`libxrdproto/crc32c.c` (already present)** + `libxrdc` read | near-zero new code |
| `xrdadler32` | Adler32 of a local-or-`root://` file | `libxrdc` read + zlib `adler32` | shares the `xrdcp --cksum` code |
| `xrdprep` | issue `kXR_prepare` (stage/evict/cancel/fresh, prio) | `libxrdc` prepare | a scriptable subset of `xrdfs prepare` |
| `xrdqstats` | query + pretty-print server monitoring stats | `libxrdc` `kXR_query`(`QStats`) | parse the stats summary |
| `wait41` | block until a server accepts connections | `sock` + `handshake` | readiness helper the test harness already wants |

### 14.3 Tier 2 — credential & keytab tools (local crypto, little/no wire)

| Tool | Does | Reuses | Value |
|---|---|---|---|
| `xrdgsiproxy` | create / `info` / `destroy` an X.509 GSI proxy (`init`, `-valid`, `info`, `destroy`) | OpenSSL X509/RSA + RFC 3820 proxy extensions; `compat/crypto.c` | **HIGH** — users need a proxy *before* any GSI `xrdcp`; pure local OpenSSL, zero protocol |
| `xrdsssadmin` | create/add/list/install/del SSS keytab entries | the `sec_sss` keytab format (§6) | **MED** — pairs with `sss` auth; reuses the keytab parser/writer |
| `xrdgsitest` | GSI handshake self-test against a server | `sec_gsi` + `libxrdc` | LOW — debug aid; folds into the M4 GSI tests |

Clean-room note: proxy/keytab *file formats* are the published interface (RFC 3820
for proxies; the SSS keytab layout is the §13 open question, pinned by inspection).

### 14.4 Tier 3 — high-value integration libraries (atop a frozen `libxrdc`, post-M10)

- **POSIX preload shim — `libxrdposix_preload.so`** (clean-room of
  `libXrdPosix`/`XrdPosixPreload`): an `LD_PRELOAD` interposer for
  `open/openat/read/pread/write/pwrite/close/lseek/stat/fstat/opendir/readdir/…`
  that routes paths matching a configured `root://`/`roots://` prefix (or an
  `XROOTD_VMP`-style virtual-mount map) through `libxrdc`, and forwards everything
  else to the real libc symbols. Lets **unmodified** analysis binaries read remote
  data. Pure C; the substance is the symbol-interposition table + a shadow fd-table
  namespace — both ngx-free, both atop `libxrdc`.
- **FUSE filesystem — `xrootdfs`** (clean-room of `XrdFfs`/`xrootdfs`): mount a
  `root://` export as a local POSIX tree via `libfuse3`, mapping FUSE ops →
  `libxrdc` (`getattr`→stat, `readdir`→dirlist, `open/read/write/release`→file ops,
  `mkdir/unlink/rename/truncate/chmod`→metadata ops). Compile-gated on `libfuse3`.
  **HIGH** value for interactive browsing/mounting.

Both validate by running ordinary POSIX tools (`cat`/`ls`/`md5sum`/`cp`) *through*
them against the nginx fleet + reference xrootd and diffing bytes — reusing §10.

### 14.5 Tier 4 — cluster & diagnostic tools

| Tool | Does | Reuses | Priority |
|---|---|---|---|
| `xrdmapc` | query a cmsd/manager for the live cluster map (servers, free space, who-has-path) | `libxrdc` + a CMS/`kXR_locate` query | **MED** — operational parity with this project's manager/cluster features |
| `xrdreplay` | replay a captured request stream against a server (repro/load) | `libxrdc` + a log parser | LOW — overlaps the existing load harness |
| `mpxstats` | aggregate/relay the xrootd summary-stats stream | parse-only (no client lib) | LOW — monitoring glue, not protocol-core |

### 14.6 Explicitly out of scope (not client tools, or declined)

- **Server daemons / plugins** — not client code: `xrootd`, `cmsd`, `frm_admin`/
  `frm_purged`/`frm_xfrd`/`frm_xfragent` (file-residency manager), `cconfig`,
  `xrdacctest` (authz config test), `xrdthrottle`, `xrdceph` (Ceph OSS),
  `xrdhttp`/`xrdhttptpc` (HTTP server plugins — **this project already _is_ the
  HTTP/WebDAV server**), `xrdpfc`/`xrdpfc_print`/`xrdpinls` (XRootD proxy-cache
  server and its on-disk-format inspectors — not our cache format).
- **`xrdec`** (erasure-coding client) — large, niche; defer indefinitely.
- **`xrdpwdadmin`** — the `pwd` auth protocol is deprecated; decline.
- **`xrdscitokens`** — primarily a *server-side* SciTokens authz plugin/config
  tool; client token *presentation* is already covered by the `ztn` sec module
  (§6). A "inspect my token" helper could come later but needs no protocol core.
- **Metalink / ZIP / `pelican://`** — still outside the current client surface.
  Historical correction: `s3://` and `http(s)://`/`dav(s)://` copy paths were
  later implemented in `client/xrdcp`; see
  [Native Client Tools](../04-protocols/native-client-tools.md).
- **Language bindings (Python/Go)** — out of scope here, but §14.1's stable C ABI
  is deliberately the enabler: a future CFFI/cgo binding links `libxrdc` rather
  than `libXrdCl`.

### 14.7 Sequencing

These **extend, not block**, the §11 milestones. Tier 1 checksum/prep/stats tools
land next to **M2/M6** (they need only the read + query + checksum code already
being built). `xrdgsiproxy` lands with **M4** (the credential users need first).
`libxrdc` is *formalized* (public headers, SONAME, pkg-config) at **M9**, once the
API has settled against two real consumers. The POSIX preload and FUSE mount come
**after M10**, atop the frozen `libxrdc`. Every new tool adds one conformance row
(swap its `TEST_*_BIN`, §10) and one clean-room ledger entry (§2) — so the family
grows without re-litigating architecture, build, or provenance.

---

## 15. Diagnostic superpowers — debugging the server, the network, and the deployment

The stock `xrdcp`/`xrdfs` are deliberately terse: a transfer either works or prints
a one-line `XRootDStatus`. But because **we own both ends** (the client *and* the
nginx-xrootd server), share one wire vocabulary (`libxrdproto` can decode every
`kXR_*` struct it can build), and can talk every protocol surface the server
exposes (`root://`, `davs://`, S3) plus query the server's own observability plane
(`/metrics`, `/xrootd/api/v1/*`), the native clients can become a **deployment
diagnostic platform** that the upstream tools structurally cannot match. This
section is the roadmap for that — built as instrumentation *hooks in `libxrdc`*
plus decoders in `libxrdproto`, surfaced through layered flags, new `xrdfs`
subcommands, and one consolidated `xrddiag` binary.

### 15.0 Why the native client is uniquely positioned

- **Total wire visibility.** `libxrdproto` already defines every request/response
  struct; the client can decode and pretty-print *both directions* — no opaque
  `libXrdCl` event loop hiding the bytes.
- **Cross-protocol oracle.** This project *unifies* `root://`/`davs://`/S3 over one
  VFS (`docs/10-architecture/cross-protocol-unification.md`); a client that speaks
  all three can read the same object three ways and **diff** them — the divergence
  class `tests/test_integrity_matrix.py` targets, now a live tool.
- **Reference-diff built in.** The test harness already runs every op against both
  nginx-xrootd and a *reference* `xrootd` daemon; folding that comparison into the
  client turns "is the server behaving canonically?" into a one-command check.
- **Server self-observability.** The server publishes `/metrics` (Prometheus) and
  `/xrootd/api/v1/{cluster,transfers,ratelimit,cache,history,events,snapshot}`.
  The client can correlate what it *observes* (latency, errors, redirects) with
  what the server *reports* (active transfers, memory-budget gauges, rate-limit
  shedding, cache hit rate) in a single view.
- **The test corpus is a check library.** `test_conformance.py`,
  `test_integrity_matrix.py`, `test_attack_vectors.py`, `test_readv_security.py`,
  `test_metadata_stress.py`, `test_privilege_escalation.py`, `test_interop_*` encode
  hundreds of server-correctness assertions. The diagnostic modes are largely a
  *re-packaging* of these as a shippable binary.

### 15.1 Wire-level introspection (`--wire-trace`, capture/replay)

- `--wire-trace[=N]` on any tool: emit a timestamped, decoded log of every frame —
  direction, `streamid`, `requestid`/status name, `dlen`, key fields, and (at N≥2)
  a hexdump — via `libxrdproto` struct decoders. The thing you paste into a bug.
- **Session capture → portable bundle:** `--capture file.xrdcap` records the raw
  byte stream + negotiated caps + env + a `/metrics` snapshot; `xrddiag replay
  file.xrdcap` decodes it offline (no server needed) and `--replay` re-issues it
  for deterministic reproduction. This is the artifact attached to a server bug.
- **Per-opcode latency histograms:** `--timing` accumulates RTT per `kXR_*` op
  (open/read/stat/dirlist/auth) so a "slow `stat`, fast `read`" pathology is
  visible without `tcpdump`.

### 15.2 Connection / auth / TLS explainer (`xrdfs explain <url>`)

A read-only probe that performs the full handshake and *narrates* it instead of
hiding it:

- **Protocol caps:** decode `ServerResponseBody_Protocol` — `kXR_haveTLS`/
  `kXR_gotoTLS`, `kXR_suppgrw` (pgread/pgwrite), `kXR_supposc` (POSC),
  `isServer`/`isManager`, and the `kXR_secreqs` signing policy (0–4).
- **Auth negotiation:** the raw `&P=` sec-token list, which protocol the client
  *would* pick and **why the others were skipped** (no credential / not offered) —
  the fastest way to debug "why is it falling back to `unix`?".
- **Credential introspection:** for GSI, the proxy chain (subject, issuer, expiry,
  VOMS FQANs) and the server cert chain it verified against `$X509_CERT_DIR`; for
  tokens, the decoded claims/scopes/`aud`/`exp`; for SSS, the keytab path + id.
- **TLS facts:** negotiated version/cipher, peer cert SAN/expiry, whether **kTLS**
  is active, and an explicit **downgrade warning** if the server advertised
  `kXR_gotoTLS` but accepted cleartext.
- **Clock skew:** compare the server's `kXR_login` time hints / response timestamps
  with local time (a classic GSI/token "works on my box" cause).

### 15.3 Networking & throughput diagnostics

- **`curl -w`-style phase breakdown:** DNS → TCP connect → TLS handshake → login →
  auth → time-to-first-byte, printed per connection.
- **Kernel transport facts:** dump `TCP_INFO` (RTT, cwnd, retransmits, delivery
  rate), `SO_RCVBUF`/`SNDBUF`, and congestion-control algorithm — turns "the link
  is slow" into "cwnd-limited at 8 MB BDP, 0.3% retrans".
- **Happy-eyeballs / dual-stack:** report which address family actually connected
  (ties into phase-36 IPv6 work) and the candidate order, to debug v4/v6 asymmetry.
- **Throughput & shape probe (`xrddiag bench <url>`):** sweep read sizes to find the
  knee, measure single- vs N-stream (`kXR_bind`) scaling, and report whether the
  server served via sendfile/pgread/windowed path (cross-checked against `/metrics`
  counters) — directly exercises the data-plane perf work (phases 29–33).
- **SciTags / packet-marking verification:** confirm the flow is being marked
  (phase-34, `src/observability/pmark/`) — read back the experiment/activity flow-id the server
  applied so a "marking not reaching the NIC" misconfig is caught at the client.

### 15.4 Redirect / cluster / topology debugging

- **Redirect-chain trace:** show every `kXR_redirect` hop (host:port, opaque, the
  evolving `tried`/`triedrc` CGI) and flag **redirect loops** or exhaustion — the
  exact failure `xrootd_manager_tried_exhausted` (`src/net/manager/registry.c`) and the
  conformance-topology fix were about (a nonexistent path must converge to
  `kXR_NotFound`, not bounce forever).
- **Cluster topology mapper (`xrddiag topology` / a real `xrdmapc`):** walk the
  manager, enumerate data servers, free space, and per-server health; cross-check
  against `/xrootd/api/v1/cluster` so the **client's view of the cluster matches the
  server's registry**.
- **Stale-registration detector:** for a path, `kXR_locate` the advertised holders,
  then actually `kXR_stat`/open each — report holders that advertise but can't serve
  (the "ghost replica" bug), which a pure transfer never surfaces.

### 15.5 Server configuration / setup "doctor" (`xrddiag check <url>` / `xrdfs diagnose`)

A battery of read-mostly probes that each assert an *expected* server policy and
report the misconfigurations a deployment actually hits. The check bodies are the
existing pytest assertions, re-homed into C (or invoked via the shared harness):

| Check | What it catches | Backed by |
|---|---|---|
| **Auth-as-advertised** | server claims it requires `gsi`/`token` but accepts `unix`/anon | `test_*auth*`, `explain` |
| **No silent TLS downgrade** | `kXR_gotoTLS` advertised yet cleartext data accepted | §15.2 |
| **Path confinement holds** | `..`/symlink/abs-path escapes are *denied* (expect `kXR_NotAuthorized`) | `test_attack_vectors.py`, `test_privilege_escalation.py` |
| **VO ACL / authdb enforced** | a principal can reach a path it must not | `test_vo_acl.py`, `test_authdb.py` |
| **Checksum really works** | `kXR_query`+`Qcksum` advertised but errors or disagrees with a computed digest | `test_conformance.py` |
| **pgread/pgwrite integrity** | `kXR_suppgrw` advertised but page CRC32C wrong/missing | `test_readv_security.py` |
| **POSC atomicity** | failed upload leaves a partial file visible | `xrdcp -P` path |
| **dirlist dstat == per-entry stat** | the dstat/stat size divergence (a bug this very session hit) | `test_interop_query.py` |
| **Backpressure correctness** | over-budget load yields `kXR_wait`/`429` + recovery, not a crash | `test_metadata_stress.py`, memory-budget (phase-31) |
| **Request/handle limits** | oversized payloads / handle exhaustion fail gracefully (`kXR_NoMemory`), not corrupt | `test_readv_security.py`, phase-27 |
| **Clock skew / cert validity** | skew or near-expiry creds that will fail intermittently | §15.2 |

Output is a green/red report with the offending wire evidence inline — a
deployment "preflight" runnable against any endpoint.

### 15.6 Cross-protocol consistency oracle (`xrddiag compare`)

The capability no upstream tool has, because no upstream client speaks all three:
read the **same logical path** via `root://`, `davs://`, and S3 and assert
**byte-exact + checksum-exact + stat-consistent + ACL-consistent** results. This is
`test_integrity_matrix.py` as a live tool, and it catches the cross-protocol
divergence bugs unification is prone to (e.g. a metric double-count, an ETag/Qcksum
mismatch, a stat-flags difference between planes). A `--vs-reference root://refhost`
mode additionally diffs nginx-xrootd against a canonical `xrootd` for the same op
(`test_conformance.py` semantics), localising "where do *we* diverge from XRootD?".

### 15.7 Server-state correlation

`xrddiag status <url>` pulls `/metrics` + the dashboard JSON and renders one view:
active transfers, memory-budget high-water + `kXR_wait` count, rate-limit shed
counts per principal, cache hit/miss, manager registry size — alongside the
client's own observed latency/error tallies from the same session. Turns "my copy
was slow" into "server was at memory-budget cap, shedding with `kXR_wait`" without
shell-hopping onto the server.

### 15.8 Adversarial / robustness probing (gated, authorised use only)

`xrddiag probe-robustness <url>` replays the *negative* suites — malformed frames,
out-of-bounds `kXR_readv` segments, oversized `dlen`, path-escape attempts, auth
downgrade, slowloris-style partial frames (`test_attack_vectors.py`,
`test_readv_security.py`, `test_malicious_credentials.py`) — and asserts the server
**rejects** each cleanly (correct `kXR_*` error, connection survives). This makes
the security regression suite a shippable auditor. **Safety:** it is a fuzzing-class
tool; it must require an explicit `--i-am-authorised` flag and refuse non-loopback
targets without it, and the clean-room §2 boundary still applies (probes are built
from the wire spec + our own tests, never from XrdCl).

### 15.9 Tooling shape & reuse

- **Instrumentation hooks in `libxrdc` (design these in from M1):** an observer/
  callback API (`xrdc_set_trace_cb`, per-phase timing hooks, a frame-decode hook)
  so every diagnostic above is a *consumer* of one instrumented session layer, not
  a fork of it. Keeps `xrdcp`/`xrdfs` lean while `xrddiag` lights everything up.
- **Surfacing:** cheap, always-available flags on `xrdcp`/`xrdfs`
  (`--wire-trace`, `--timing`, `--explain`); richer `xrdfs` subcommands
  (`diagnose`, `explain`, `topology`, `compare`); and the consolidated **`xrddiag`**
  binary (`check`/`bench`/`topology`/`compare`/`status`/`replay`/`probe-robustness`)
  for the heavy modes — all thin front-ends over `libxrdc` + `libxrdproto`.
- **Check library reuse:** rather than re-encode hundreds of assertions, the C
  checks can be a thin layer while the *authoritative* battery stays the pytest
  suites; `xrddiag --suite=conformance|integrity|security` can even shell the
  existing harness against an arbitrary endpoint (`CONFORMANCE_NGINX_URL`,
  `TEST_*_BIN`), so the diagnostic tool and the CI gate never drift.

### 15.10 Architecture/setup bug classes this is designed to expose

Concrete failure modes — several of which this project has actually hit — that a
plain transfer hides but these modes surface:

- redirect loop / `tried`-list ignored on a nonexistent path (§15.4) — the
  conformance-topology bug;
- cert-generation / CA mismatch and silent auth fallback (§15.2/§15.5) — the GSI
  "host-load flakiness" root cause from this session;
- `dirlist` dstat vs per-entry `stat` size divergence (§15.5) — also hit this
  session;
- cross-protocol checksum/stat divergence and metric double-count (§15.6);
- memory-budget backpressure misbehaving under concurrency (§15.5/§15.7);
- TLS advertised-but-downgradable, or kTLS silently inactive (§15.2);
- v4/v6 asymmetric reachability and BDP/cwnd-limited throughput (§15.3);
- ghost replicas / stale manager registrations (§15.4).

### 15.11 Sequencing

The instrumentation **hooks** in `libxrdc` are designed in from **M1** (cheap, and
they make the base tools debuggable during their own bring-up). `--wire-trace`/
`--timing`/`explain` ride along **M1–M4**. The `doctor`/`compare`/`topology`/
`status` modes formalise after **M9** (they need the full op set + a stable
`libxrdc`). `bench` and `probe-robustness` land **after M10**, reusing the perf and
security suites. As with §14, each diagnostic mode adds at most a conformance row
and a clean-room ledger entry — never new architecture.
