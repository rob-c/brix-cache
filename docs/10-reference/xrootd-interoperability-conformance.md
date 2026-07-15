# Interoperability Conformance with the XRootD Project

**Scope:** This document describes the work to make `nginx-xrootd` a **drop-in,
wire-compatible member of the XRootD ecosystem** — so the reference XRootD C++
project's clients (`xrdcp`, `xrdfs`, `XrdCl`, `gfal2`, `davix`), managers
(`cmsd`/`XrdCms` clusters, EOS, dCache federations), and third-party-copy peers
interoperate with this implementation without protocol workarounds. Where the
previous two references
([token](wlcg-token-conformance-standards.md) /
[x509](wlcg-x509-conformance-standards.md)) document conformance to *auth
specifications*, this one documents conformance to the **XRootD project itself**
as the reference implementation and wire authority.

**At a glance**

| Metric | Value |
|---|---|
| Reference | The XRootD C++ project — wire authority `src/XProtocol/XProtocol.hh` (vendored at `/tmp/brix-src`) |
| Protocol version advertised | **v5.2.0** (`kXR_PROTOCOLVERSION = 0x00000520`) |
| Request opcodes implemented | The full standard `kXR_*` set (session, read, write, query) + 4 vendor extensions |
| Wire framing | Byte-exact with stock, including the hard cases (pgread/pgwrite CRC32c, writev, chkpoint `ckpXeq`) |
| Cluster protocol | `cmsd`/`XrdCms` (`kYR_*`) manager protocol for redirection/clustering |
| Test mechanisms | 7 (cross-backend, reference fleet, differential, real-client interop, hybrid mesh, load parity, byte-exact tap/relay/proxy) |
| Interop verification | MD5 byte-for-byte parity of transfers; identical client exit codes/status |

---

## 1. The interoperability goal and the quadrant model

The XRootD protocol is the *lingua franca* of WLCG/HEP storage. The objective is
not merely "our clients talk to our server" but that **any conformant XRootD
peer talks to us**, and we to it, in a mixed federation. Interoperability is
tested along the four quadrants the XRootD project itself uses
(`tests/official_interop_lib.py`):

| Quadrant | Client | Server | What it proves |
|---|---|---|---|
| Q1 | ours | ours | baseline self-consistency |
| Q2 | **ours** | stock XRootD | our client speaks the protocol correctly |
| Q3 | **stock XRootD** | **ours** | **our server speaks the protocol correctly — the gold standard** |
| Q4 | stock | stock | reference baseline for comparison |

Q3 is the load-bearing quadrant: a stock `xrdcp`/`xrdfs`/`XrdCl` driving *our*
server, byte-for-byte, is the proof of server conformance.

---

## 2. The reference

- **The XRootD project** (the Scalla/XRootD C++ implementation) is the reference
  implementation and the wire authority. The canonical protocol header
  `src/XProtocol/XProtocol.hh` (vendored at `/tmp/brix-src`) is the source of
  every `kXR_*` opcode, status, flag, and wire-structure constant; the module's
  `src/protocols/root/protocol/{opcodes.h,wire.h,flags.h}` mirror it directly.
- **Protocol version** advertised is **5.2.0** (`0x00000520`) — the module
  implements v5-era features (`kXR_clone`, `kXR_chkpoint`/`ckpXeq`,
  `kXR_pgread`/`kXR_pgwrite`, `kXR_writev`) and advertises the matching feature
  flags.
- **Adjacent protocols** the module speaks to interoperate: the `cmsd`/`XrdCms`
  cluster-management protocol (`kYR_*`), `XrdHttp`/WebDAV (RFC 4918) as the HTTP
  surface, the XRootD security protocols (`XrdSecgsi`, `XrdSecztn`, `XrdSecsss`,
  krb5, unix, host, pwd) advertised in the login handshake, and Third-Party Copy
  (TPC) for WLCG bulk transfer.

---

## 3. Wire-protocol conformance surface

### 3.1 Request opcodes

The dispatch table (`src/protocols/root/handshake/dispatch.c` → `dispatch_{session,read,write,signing}.c`)
implements the full standard set:

- **Session/handshake:** `kXR_protocol` (capability + security negotiation),
  `kXR_login` (session + `&P=…` auth advertisement), `kXR_auth`, `kXR_bind`
  (secondary streams), `kXR_ping`, `kXR_set`, `kXR_endsess`.
- **Read plane:** `kXR_stat`, `kXR_statx`, `kXR_open`, `kXR_read`, `kXR_readv`,
  `kXR_pgread`, `kXR_close`, `kXR_dirlist` (multi-frame `kXR_oksofar`),
  `kXR_locate`, `kXR_query` (`Qspace`/`Qconfig`/`Qcksum`/`Qxattr`/`QFinfo`),
  `kXR_prepare` (stage/cancel), `kXR_fattr` (xattr get/set/del/list),
  `kXR_clone` (server-side range copy, v5.2.0).
- **Write plane:** `kXR_write`, `kXR_pgwrite`, `kXR_writev`, `kXR_sync`,
  `kXR_truncate`, `kXR_mkdir`, `kXR_rm`, `kXR_rmdir`, `kXR_mv`, `kXR_chmod`,
  `kXR_chkpoint` (begin/commit/rollback/query/`ckpXeq`).
- **Signing:** `kXR_sigver` (HMAC-SHA256 request-signing envelope).
- An unrecognized opcode returns `kXR_InvalidRequest`, matching
  `XrdXrootdProtocol`.

### 3.2 Byte-exact framing of the hard cases

The subtle framing details — where naïve reimplementations diverge and break
stock clients — are made byte-identical to stock:

- **`kXR_pgread` / `kXR_pgwrite`** use the `kXR_status` (4007) response carrier
  with the 32-byte `ServerStatusResponse_pg*` layout and **per-page CRC32c**. The
  CRC position is intentionally inverted between the two (`crc` *before* each page
  on pgwrite, *after* on pgread), matching the spec; pgread encodes the CRC
  in-place in a gapped zero-copy buffer so the output is byte-identical to stock
  `xrdp_pg_encode`. A pgwrite page failing CRC produces the CSE
  (checksum-error) trailer that drives the client's `kXR_pgRetry`.
- **`kXR_writev`** frames only the 16-byte segment descriptors in the request
  header; the payload streams after (honoring `kXR_wv_doSync` on the final
  segment).
- **`kXR_chkpoint` `ckpXeq`** embeds a nested write sub-request (`kXR_write`/
  `pgwrite`/`writev`/`truncate`) under checkpoint protection; the `dlen` frames
  the nested header + data. (These `writev`/`ckpXeq` framing details were a
  specific stock-parity fix — the request header declares descriptors/embedded
  header only, and the body is streamed after — applied consistently across the
  server, proxy, tap, and guard code paths.)

### 3.3 Handshake, capabilities, errors, clustering

- **Handshake:** the 20-byte `ClientInitHandShake` is validated on the
  `htonl(2012)` (`ROOTD_PQ`) magic; the server replies with the v5 preamble
  (`ServerResponseHdr` + protover `0x00000520` + `kXR_DataServer`).
- **Capability negotiation** (`kXR_protocol`): the `ServerProtocolBody` flags
  advertise `kXR_isServer`, `kXR_suppgrw` (pg-rw), `kXR_supposc` (POSC), and
  conditionally `kXR_isManager`/`attrProxy`/`attrCache`/TLS bits; when the client
  sets `kXR_secreqs`, the `SecurityInfo` array lists the enabled protocols
  (`gsi`/`ztn`/`sss`/`unix`/`krb5`/`host`/`pwd`).
- **Login:** the `&P=…` parameter block matches XRootD client expectations
  (`&P=gsi,v:…`, `&P=ztn,v:10000`, `&P=sss,…`, etc.); a 16-byte session id is
  returned; client-chosen 2-byte stream ids are echoed on every response.
- **Errors:** the `kXR_error` (4003) reply carries a 4-byte big-endian code + text
  matching `XrdXrootdProtocol::Reply_Error`, fed by a consistent errno→kXR map
  (ENOENT→`kXR_NotFound`, EACCES/EPERM→`kXR_NotAuthorized`, EINVAL→`kXR_ArgInvalid`,
  EIO→`kXR_IOError`, ENOMEM→`kXR_NoMemory`, …) — the same map that drives the HTTP
  status codes on the WebDAV/S3 planes.
- **Clustering:** the module speaks the `cmsd`/`XrdCms` (`kYR_*`) protocol —
  `kYR_login` (XrdOucPup-encoded node announce), `kYR_load` (heartbeat),
  `kYR_locate`/`kYR_select`/`kYR_try` (redirection), and the Plane-B mutation
  forwards — so it can act as, or register under, a stock XRootD manager and emit
  `kXR_redirect` (4004) responses in the standard format.

---

## 4. How interoperability is tested

Seven complementary mechanisms, all driven from the standard test fleet
(`tests/manage_test_servers.sh`), which co-hosts real reference XRootD servers.

**1. Cross-backend testing** (`tests/backend_matrix.py`,
`run_cross_compatible_tests.sh`). The **same, unmodified** test source runs
against both backends via `TEST_CROSS_BACKEND={nginx|xrootd}`; a fixture resolves
the backend URL. Suites include `test_file_api.py`, `test_query.py`,
`test_protocol_edge_cases.py`, `test_privilege_escalation.py` (root://) and
`test_xrdhttp_webdav.py`, `test_xrdhttp_conformance.py` (davs:// vs `XrdHttp`).
Identical behaviour is required of both.

**2. The reference XRootD fleet** (`tests/lib/refxrootd.sh`, ports 11098–11113).
Real stock `xrootd` daemons run alongside the module and serve the *same* data
tree: `ref` (anon, 11098) as redirect target and parity baseline, `ref-gsi`
(11099) and `ref-shared` (11100) for GSI, `root-tpc-ref` (11111) as a TPC source,
and `XrdHttp` (11112/11113) as the HTTP surface. Each is readiness-probed with
`xrdfs stat /`.

**3. Differential tiers** — spec-first three-way comparison. The token
(`tests/token_differential.py`, `TEST_TOKEN_DIFF=1`) and x509
(`tests/x509_differential.py`, `x509_matrix_differential.py`, `TEST_X509_DIFF=1`)
tiers capture `{ours, xrootd, spec}` per scenario: **`ours == spec` is a hard
assertion**, while **`xrootd != spec` is recorded, not failed** (upstream
evidence). `BRIX_BIN`/`XROOTD_BIN` overrides the stock binary; absent stock,
they skip cleanly. Findings land in `docs/10-reference/*differential-findings.md`.

**4. Real XRootD-client interop.** Stock tools drive *our* server (Q3):
`test_native_xrdcp_xrdfs_b.py` runs `xrdcp`/`xrdfs` (upload/download/stat/ls/rm/
mkdir/rename/checksum) against both the module and the reference and requires
agreement; `test_xrdcp_root_anon_compare.py` asserts an `xrdcp` transfer through
the module and through stock produce **byte-identical MD5**. WebDAV/HTTP interop
uses `gfal-copy` (`test_gfal_interop.py`) and `davix`/`curl`
(`test_xrdhttp_webdav.py`); TPC interop uses `XrdCl` Python bindings
(`test_client_web_transfer.py`, `test_ipv6_tpc.py`). The
`official_interop_lib.py` harness organizes these into the Q2/Q3/Q4 quadrants.

**5. Hybrid mesh / redirect interop** (`tests/hybrid_mesh_lib.py`,
`test_hybrid_mesh.py`, `test_cms_mesh_interop.py`). A multi-tier mesh mixes
backends: a **stock XRootD redirector points at an nginx data server** (and vice
versa), with an `XrdCms` PSS proxy in between. `xrdcp` is driven through the full
hybrid chain (nginx-manager→stock-nodes and stock-redirector→nginx-leaf), proving
the redirection and registration protocols interoperate both directions.

**6. Load / throughput parity** (`tests/run_load_test.sh`, `load_test.py`).
The same workload runs against the module and stock XRootD in an isolated
environment across concurrency levels (1…200), read/write, with symmetric
data-plane TLS (`--data-tls`) for a fair comparison. (An observed sample: the
module ~297 vs native ~242 MiB/s single-stream anon reads — a
protocol/buffering difference, not a correctness gap.)

**7. Byte-exact tap / relay / proxy** (`src/net/tap/`,
`src/protocols/root/relay/`, `src/net/proxy/`). The tap decodes raw XRootD frames
(request/response headers, path capture, `writev` trailing data,
`chkpoint` embedded sub-requests) without allocation; the **relay**
(`brix_transparent_proxy`) passes every byte verbatim to an upstream stock
server while a non-consuming tap audits the frames; the **proxy** terminates,
translates file handles, and relays response bodies **byte-for-byte**
(`test_proxy_mode.py::test_binary_file_content_relayed_byte_for_byte` asserts
MD5 parity through the proxy vs direct). This both proves our decoder matches the
wire and lets the module sit transparently in front of, or behind, stock servers.

---

## 5. Results

- **Stock clients interoperate with our server (Q3).** `xrdcp`/`xrdfs`, `gfal2`,
  `davix`, and `XrdCl` (including TPC) drive the module with identical exit codes,
  status strings, and **byte-identical MD5** transfers versus stock XRootD.
- **Mixed federations work.** Stock `XrdCms` redirectors resolve through nginx
  data servers and nginx managers resolve through stock nodes, in a live hybrid
  mesh.
- **The module is demonstrably *more* conformant than stock in specific cases.**
  The differential tiers found stock `XrdHttp`, in its baseline CA-directory
  config, **accepting out-of-namespace, wrong-CA-policy, and revoked X.509
  certificates** where the module (and the specification) reject — recorded as
  upstream findings.
- **Throughput is parity-class** (same order, single-stream sample favouring the
  module), with no correctness regressions under load.

---

## 6. Documented differences (by design)

- **Vendor extensions** (`kXR_setattr` 3500, `kXR_symlink` 3501, `kXR_readlink`
  3502, `kXR_link` 3503) are additive opcodes gated behind an advertised
  `xrdfs.ext` capability, so a stock client that does not negotiate the capability
  never sees them — no interop hazard.
- **`kXR_gpfile`** (legacy grouped parallel fetch) is intentionally not
  implemented (retired in the v5 era).
- The relay carries **no credential** (client↔upstream auth is end-to-end); the
  proxy authenticates the client and then bootstraps upstream under a configured
  identity — both documented behaviours, not protocol deviations.

---

## 7. Running / reproducing

```bash
# Same suite against both backends (server-conformance / Q3 focus)
TEST_CROSS_BACKEND=nginx  pytest tests/test_file_api.py tests/test_query.py -v
TEST_CROSS_BACKEND=xrootd pytest tests/test_file_api.py tests/test_query.py -v

# Stock xrdcp/xrdfs byte-parity against our server
pytest tests/test_native_xrdcp_xrdfs_b.py tests/test_xrdcp_root_anon_compare.py -v

# Hybrid stock↔nginx redirect mesh
pytest tests/test_hybrid_mesh.py tests/test_cms_mesh_interop.py -v

# Differential vs stock (opt-in; skip-clean without a stock binary)
TEST_TOKEN_DIFF=1 tests/run_token_differential.sh
TEST_X509_DIFF=1  tests/run_x509_differential.sh

# Throughput parity
REF_BIN=/usr/bin/xrootd ./tests/run_load_test.sh both --suite root-anon --data-tls off
```

Reference-server binary is selected via `REF_BIN`/`BRIX_BIN` (default `xrootd`);
`SKIP_XRDFS_CHECK=1` bypasses readiness probes.

---

## 8. Companion documents

- [`wlcg-token-conformance-standards.md`](wlcg-token-conformance-standards.md) — bearer-token (JWT/SciTokens) RFC/profile conformance.
- [`wlcg-x509-conformance-standards.md`](wlcg-x509-conformance-standards.md) — X.509 / grid-PKI RFC/profile conformance.
- `*differential-findings.md` — generated stock-XRootD divergence evidence.
- `src/protocols/root/protocol/` — the wire structures mirroring `XProtocol.hh`.

---

## Appendix A — Glossary

- **`kXR_*`** the XRootD client-server request/response protocol opcodes and status codes (from `XProtocol.hh`).
- **`kYR_*`** the `XrdCms`/`cmsd` cluster-management protocol opcodes.
- **POSC** Persist-On-Successful-Close — a write-integrity mode advertised via `kXR_supposc`.
- **pg-read/pg-write** paged transfers carrying a per-4096-byte-page CRC32c for end-to-end integrity (`kXR_suppgrw`).
- **TPC** Third-Party Copy — server-to-server bulk transfer orchestrated by a client.
- **Redirector / data server / manager** the XRootD cluster roles; a manager (`cmsd`) redirects clients to the data server holding a path.
- **`xrdcp`/`xrdfs`/`XrdCl`** the reference XRootD copy tool, filesystem CLI, and client library; **`gfal2`/`davix`** the WLCG HTTP-transfer client stack.
- **Q3** the interop quadrant *stock client → our server* — the primary server-conformance proof.
