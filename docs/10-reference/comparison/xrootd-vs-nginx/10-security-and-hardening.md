# Security Posture & Hardening — Official XRootD vs. nginx-xrootd

> Part of the [XRootD vs nginx-xrootd comparison set](./README.md).

This document compares the **official XRootD C++** server with the
**nginx-xrootd** module on **security posture and hardening**: path confinement,
fail-closed authentication, input/framing robustness, credential handling
(OCSP/CRL, token expiry/issuer pinning), impersonation, DoS protection / rate
limiting, build hardening, and the overall attack surface.

Every claim below is grounded in source. The official side cites
`/tmp/xrootd-src/src` — principally `XrdXrootd/XrdXrootdXeq.cc` and
`XrdXrootdProtocol.cc` (request validation, `rpCheck`/`Squash` path checks),
`XrdSecgsi/XrdSecProtocolgsi.cc` (GSI + CRL), `XrdTls/XrdTlsContext.cc` (TLS CRL
refresh), and `XrdCrypto/` (X.509/CRL primitives). The nginx-xrootd side cites
this repository's `src/` tree. Where a behaviour was already verified by the
conformance / attack-vector suites, this doc **reuses** those facts rather than
re-deriving them:

- [`../conformance-findings.md`](../conformance-findings.md) — fixed wire divergences vs. the spec + stock tools (incl. the framing batch).
- `tests/test_conf_framing.py` — raw-socket malformed/boundary framing differential vs. the stock data server.
- `src/impersonate/README.md`, `src/path/README.md`, `src/ratelimit/README.md` — subsystem invariants.

---

## Scope

In scope: the **defensive** behaviour of each server — what stops a client from
escaping the export, reaching resources before authentication completes, crashing
or hanging the server with malformed input, presenting a revoked/forged
credential, escalating privilege, or starving other clients. The functional
correctness of each protocol is covered by the other comparison documents and is
referenced here only where it bears on security.

"Official XRootD" means the reference C++ implementation in `/tmp/xrootd-src`.
"nginx-xrootd" / "this module" means the server in `src/`. Two architectural
facts frame everything below:

- **Official XRootD is a multi-process C++ daemon** (`xrootd` + `cmsd` + plugin
  `.so`s) that typically runs as a dedicated service user and reaches the
  filesystem through the `XrdOfs`/`XrdOss` storage stack. Its path safety is
  **lexical** (string checks before handing the name to the OSS layer).
- **nginx-xrootd is an nginx module**: a master + unprivileged workers, a
  single-threaded event loop per worker, all I/O through nginx's allocator and
  buffer-chain machinery, and the filesystem reached through **kernel-enforced**
  `openat2(RESOLVE_BENEATH)` confinement. It inherits nginx's own hardened
  network front end (request parsing, timeouts, connection caps) for free.

---

## In official XRootD

The official server's security model is mature and field-proven, and is the
reference this module is measured against:

- **Lexical path safety.** Before any namespace op, `rpCheck()` scans the path
  for a `..` component and `Squash()` collapses `//` and `/./` then validates the
  result against the export list (`XrdXrootd/XrdXrootdXeq.cc:4374` and `:4435`).
  Every `do_*` handler calls both (open `:1600`, stat `:2450`, rename `:1313`,
  rm `:2919`, mkdir/dirlist/locate/query/...).
- **Request framing validation.** The protocol layer rejects a negative
  `dlen` with `kXR_ArgInvalid` and drops the link, and rejects an over-large
  argument with `kXR_ArgTooLong` (`XrdXrootdProtocol.cc:404`, `:420`).
- **Pluggable strong auth.** `XrdSec` with GSI (`XrdSecgsi`), Kerberos, SSS,
  unix, and ZTN/token protocols; GSI does X.509 chain + **CRL** verification
  (`CRLCheck` levels `do-not-care`/`use-if-available`/`require`/
  `require-not-expired`, optional download + periodic `CRLRefresh`,
  `XrdSecProtocolgsi.cc:154,510-518`). TLS-layer CRLs are refreshed by a
  background thread (`XrdTls/XrdTlsContext.cc:99`).
- **Identity → UNIX mapping.** GSI/Sec map a DN/principal to a username; the OSS
  layer can run as that user, and `sudo`/N2N plugins extend the mapping.
- **Authorization plugin** (`XrdAcc`) with a path/operation grammar.

Notably, official XRootD has **no OCSP** anywhere in the tree (`grep -rln OCSP
/tmp/xrootd-src/src` returns nothing) — revocation is CRL-only. Its DoS posture
relies on its own connection/threading limits and any external firewall; it is
not fronted by a general-purpose hardened HTTP/stream server.

---

## In nginx-xrootd

This module re-implements the same protections and adds several that the
nginx front end and a modern kernel make cheap:

- **Kernel-enforced confinement** via `openat2(RESOLVE_BENEATH |
  RESOLVE_NO_MAGICLINKS)` as the actual security boundary (`src/path/beneath.c`),
  with the lexical `..` check kept only for protocol-conformance parity with
  `rpCheck` (`src/path/helpers.c`, `src/path/extract.c`).
- **Fail-closed auth gating** on the *completed* auth verdict (`auth_done`), the
  three-tier `xrootd_auth_gate` (authdb/XrdAcc → VO ACL → token scope), and a
  ported `XrdAcc` engine that denies on a missing table.
- **Framing robustness** validated as a differential invariant against the stock
  server: never crash, never hang on any malformed/boundary input
  (`tests/test_conf_framing.py`).
- **Credential hardening**: OCSP (with a connect deadline) *and* CRL; mandatory
  token `exp`; issuer pinning for both JWT and macaroons; a per-worker auth-result
  cache; a per-worker in-flight GSI-handshake cap.
- **Optional per-request UNIX impersonation** via a privileged root broker that
  drops to `{CAP_SETUID, CAP_SETGID}` (off by default, `src/impersonate/`).
- **DoS controls**: nginx connection limits + this module's leaky-bucket rate /
  bandwidth / concurrency limiter, per-IP CMS caps, and connect/read/handshake
  deadlines.
- **Build hardening** (`config`): `-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`,
  `-fstack-clash-protection`, `-fcf-protection=full`, `-Werror=format-security`.

---

## Path confinement

This is the largest *posture* difference between the two servers.

### Official: lexical rejection (`rpCheck` + `Squash`)

Official XRootD's confinement is a **string check** performed before the path is
handed to the storage layer. `rpCheck()` walks the path and rejects it if any
`/`-delimited component is exactly `..`:

```c
// XrdXrootd/XrdXrootdXeq.cc:4374
while ((cp = index(fn, '/')))
      {fn = cp+1;
       if (fn[0] == '.' && fn[1] == '.' && (fn[2] == '/' || fn[2] == '\0'))
          return 1;            // reject: ".." component present
      }
```

`Squash()` then collapses redundant `//` and `/./` and validates the cleaned path
against the configured export prefix list (`:4435`). This is correct and battle-
tested, but it is a **lexical** boundary: it reasons about the *name*, not the
*filesystem*. A symlink **inside** the export that points outside it is followed
by the OSS layer at I/O time — by design, the stock server *follows* symlinks
(its safety is the export-prefix match plus whatever the underlying OSS allows),
and there is a TOCTOU gap in principle between the name check and the open.

### nginx-xrootd: kernel-enforced `RESOLVE_BENEATH`

This module makes the **kernel** the confinement authority. Every confined open
goes through one chokepoint, `do_openat2()`:

```c
// src/path/beneath.c
how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
return (int) syscall(SYS_openat2, rootfd, rel, &how, sizeof(how));
```

`rootfd` is a persistent per-worker `O_PATH` handle on the export root.
`RESOLVE_BENEATH` makes the kernel **atomically** refuse to resolve outside that
subtree — absolute paths, `..` traversal, and **symlinks that would leave the
tree** all return `EXDEV`/`ELOOP`, which the error mapper turns into
`kXR_NotAuthorized` / HTTP 403 (`beneath.h` header comment). `openat2` is a hard
build requirement (`#error` guards fail the compile on kernels < 5.6,
`beneath.c:63-69`). Why this is strong:

- **No TOCTOU.** The check and the open are the *same* syscall; there is no
  window between "name looked safe" and "file opened".
- **Symlink escape is impossible, not merely discouraged.** Unlike the stock
  server, an attacker who can plant a symlink inside the export still cannot use
  it to read `/etc/shadow` — the kernel refuses to traverse out of `rootfd`. This
  is a **deliberately stricter** choice than stock XRootD's symlink-following.
- **Magic-link escape blocked.** `RESOLVE_NO_MAGICLINKS` denies `/proc/<pid>/fd`
  and similar magic symlinks (`beneath.c:89`).

A crucial subtlety the code documents: `RESOLVE_BENEATH` protects only `openat2`
itself; the legacy `*at()` syscalls (`mkdirat`/`unlinkat`/`renameat`/`linkat`) do
**not** honour it. So every path-*mutating* op resolves the **parent** directory
under `RESOLVE_BENEATH` first, then operates on the final component name only
(`beneath_open_parent()`, `beneath.c:174-197`) — closing the
intermediate-symlink hole that a naive `mkdirat(rootfd, "a/b/c")` would leave.

Two cheaper, defence-in-depth lexical guards sit in front:

- **Embedded-NUL rejection at extract time.** `xrootd_extract_path()` rejects any
  path payload with a NUL that is not the final byte
  (`src/path/extract.c:30-39`) — this blocks the `"a\x00evil"` truncation class
  (where downstream C string handling sees `"a"` but a later layer sees more) and
  oversized payloads (`> XROOTD_MAX_PATH`). The login handler applies the same
  NUL/non-printable rejection to the 8-byte username (`src/session/login.c`,
  blocking truncation-impersonation).
- **Lexical `..` rejection for parity.** `xrootd_path_has_dotdot()`
  (`helpers.c:79`) and `xrootd_path_component_forbidden()` (`helpers.c:59`) reject
  a literal `..` component **outright**, matching `rpCheck`'s reject-don't-
  normalize contract. The in-code comment is explicit that this is a
  *protocol-conformance* guard, not the security boundary: an in-tree `..` would
  otherwise be silently collapsed by `RESOLVE_BENEATH` instead of rejected, and
  an out-of-tree `..` is *independently* confined by the kernel
  (`helpers.c:66-78`). Policy paths are likewise canonicalised and validated
  component-by-component before longest-prefix matching (`src/path/normalize.c`),
  so a policy bypass via path tricks cannot occur.

**Net.** Both servers reject `..` lexically. nginx-xrootd additionally makes
escape *physically impossible at the syscall layer* and refuses symlink escape
that the stock server permits — a strictly stronger confinement boundary, at the
cost of requiring a Linux ≥ 5.6 kernel.

---

## Fail-closed authentication

### The invariant: gate on the *completed* verdict only

The load-bearing rule in this module is: **gate access only on the COMPLETED auth
verdict (`auth_done`), never on an intermediate state (`logged_in`, "has a
token", "is mid-handshake")**. `kXR_login` sets `logged_in=1`; for any configured
auth (gsi/token/sss) `auth_done` stays `0` until `kXR_auth` completes; only
`auth=none` sets `auth_done=1` at login (`src/session/login.c:110-115`,
`session/session.h`).

The canonical bug this prevents is a **proxy fail-open**: a client sends
`kXR_login`, *skips* `kXR_auth`, and issues a filesystem opcode. If the proxy
dispatcher gated on `logged_in` it would forward that request to the upstream
under the proxy's own bridged credentials — an unauthenticated client reaching
authenticated resources. The fix gates on `auth_done`:

```c
// src/handshake/dispatch.c:71
if (conf->proxy_enable && ctx->auth_done) {
    return xrootd_proxy_dispatch(ctx, c, conf);
}
```

with an in-code comment spelling out exactly this attack ("Gating on logged_in
alone let a client send kXR_login then skip kXR_auth and still reach upstream
resources", `dispatch.c:57-71`). The same `auth_done` requirement is enforced on
the direct read/write dispatchers, and session teardown (`kXR_endsess` for the
connection's *own* session) clears both `logged_in` and `auth_done`
(`session/lifecycle.c:170`), so a session-end or a GSI proxy expiry de-authes
correctly. `kXR_bind` secondaries inherit `auth_done=1` only after a successful
registry lookup of the primary's session, and fail closed (`kXR_NotAuthorized`)
on an unknown sessid (`session/bind.c:123`).

### The authorization gate is fail-closed at every tier

`xrootd_auth_gate_op()` (`src/path/auth_gate.c`) runs a three-tier check —
authdb/XrdAcc → VO ACL → token scope — and on the **first** failure sends
`kXR_NotAuthorized` and returns `NGX_DONE`. The XrdAcc engine **denies on a
missing table** (`acc_tables == NULL` → `NGX_ERROR`, `auth_gate.c:36-38`): a
configuration that selected `xrdacc` but failed to load the rules denies rather
than allows. The auth-result cache keys on *every* verdict input (auth level,
operation, resolved + request paths, host, DN, VO, raw token scope, SHA-256'd);
a cached grant therefore can never be replayed for a different token, path,
operation, host, or access level (`auth_gate.c:131-190`). Brute-force /
CPU-amplification on the GSI/token verify path is bounded by an
`auth_fail_count` against `XROOTD_MAX_AUTH_ATTEMPTS` (`src/gsi/auth.c:414`).

### Official side

Official XRootD is also fail-closed by construction: `XrdSec` completes the auth
protocol before the protocol layer admits filesystem opcodes, and `XrdAcc`
denies by default. The distinction is not "official is unsafe" — it is that this
module's proxy/bridge layer introduced a *new* surface (forward-after-login) that
did not exist in the monolithic server, and the `auth_done`-only invariant is the
discipline that keeps that surface closed. The lesson, recorded as a project
memory, generalises: **never gate on intermediate auth state.**

---

## Input & framing robustness

### The invariant: a definite outcome, never a crash or hang

`tests/test_conf_framing.py` sends malformed / boundary / adversarial raw bytes
to **both** this server and the stock xrootd data server on a raw socket and
asserts the **same coarse outcome class** (accept / reject) and, above all, the
load-bearing invariant: **our server returns a definite outcome inside a sane
per-socket timeout — no crash, no indefinite hang.** A hang is a test failure to
investigate, never tolerated. Probes include: unknown opcodes, negative/oversized
`dlen`, partial sends, pre-login ops, path-length boundaries
(`XROOTD_PATH_MAX = 4096`), and embedded NULs.

Where the reference is exact the test pins the numeric `kXR_*` code; where the
exact code is build-version-specific it buckets to "rejected" (e.g. stock returns
`kXR_ArgMissing 3001` for an unknown opcode where this module and the C++
*reference* return `kXR_InvalidRequest 3006`; the conformance batch fixed this
module's unknown-opcode reply from `kXR_Unsupported 3013` to `kXR_InvalidRequest
3006`, [`../conformance-findings.md`](../conformance-findings.md) row 4).

### How each side validates a frame

Official: `dlen < 0` → `kXR_ArgInvalid` + drop link; oversized arg →
`kXR_ArgTooLong`; argument buffer is NUL-terminated by the server
(`XrdXrootdProtocol.cc:404-426`). nginx-xrootd: the path extractor enforces the
NUL/length contract (`extract.c`), the dispatcher rejects unknown opcodes and
pre-login ops, and the whole front end runs on nginx's own hardened request
reader — bounded buffers via `ngx_palloc`/`ngx_alloc`, `ngx_str_t` length-
prefixed strings (no `strlen`/`strcpy` on wire data), and the event loop's read
timers that turn a partial/stalled send into a connection close rather than a
blocked worker.

A real availability bug found and fixed in this class is the **`ngx_shmtx`
semaphore lost-wakeup**: a shared-memory table mutex created in stock POSIX-
semaphore mode could lose a wakeup under high cross-worker contention on the hot
`kXR_open` path, freezing a worker in `sem_wait` with the lock already free and
stalling every connection pinned to it for 60–450 s. The fix forces spin+yield
mode for all module SHM mutexes (`src/core/compat/shm_slots.c`); it is an INVARIANT in
`CLAUDE.md` and a documented postmortem. This is a hardening difference *in this
module's favour for availability* that has no analogue in the monolithic server
(which does not use nginx SHM zones).

---

## Credential & availability hardening

| Control | Official XRootD | nginx-xrootd |
|---|---|---|
| X.509 chain verify | yes (`XrdCrypto`/`XrdSecgsi`) | yes (`src/gsi/`, `src/crypto/pki_*`) |
| CRL revocation | yes — `CRLCheck` levels + optional download + `CRLRefresh` (`XrdSecProtocolgsi.cc:510`); TLS CRL refresh thread (`XrdTlsContext.cc`) | yes — PEM + Grid `hash.r0`/`.r1` loaders, regular-file-only filter (`src/crypto/pki_load.c`) |
| OCSP revocation | **none** (no OCSP in the tree) | **yes** — client check + staple fetch (`src/crypto/ocsp.c`) with a **5 s connect deadline** + I/O timeouts |
| Token `exp` | n/a (token via ZTN plugin) | **mandatory** — a token without a positive `exp` is rejected (`token/validate.c:335-341`) |
| Issuer pinning | per-plugin config | **JWT and macaroon** — `iss`/location must match `expected_issuer` (`validate.c:351`, `:201`); macaroon with no location is rejected |
| Auth-result cache | n/a | per-worker L1 (lockless) over SHM L2, keyed on full verdict inputs (`auth_gate.c`, `path/auth_gate_l1.c`) |
| GSI handshake DoS cap | thread/connection limits | **per-worker in-flight cap** — sheds excess with `kXR_wait` (`gsi/auth.c:244`) |

### OCSP with a connect deadline (E1)

X.509 chain verification alone does not catch a revoked-but-unexpired cert.
Official XRootD covers this with CRLs only. This module supports **both** CRL and
OCSP. The OCSP client is deliberately bounded: a black-holed or slow responder
would otherwise block the single-threaded worker event loop for the kernel TCP
timeout (~60-120 s), freezing *all* connections. So the connect phase uses a
non-blocking connect + `poll()` under a hard `XROOTD_OCSP_TIMEOUT_SECS = 5`
deadline (`SO_SNDTIMEO does not bound connect()`), and the handshake +
request/response phases are bounded with `SO_RCVTIMEO`/`SO_SNDTIMEO`
(`ocsp.c:43-109`). On timeout the fetch returns NULL and the caller applies its
`soft_fail` policy; a `REVOKED` verdict is **never** overridden by `soft_fail`
(`ocsp.c:491-499`). The request carries a nonce for replay protection
(`ocsp.c:214`), and HTTPS responders are verified with SNI + hostname check
(`ocsp.c:235-248`).

### Mandatory token expiry + issuer pinning

A JWT must carry a positive `exp`, or validation fails closed
(`validate.c:335-341`) — there is no "non-expiring token" acceptance path.
**Issuer-confusion** is closed for both token types: a JWT whose `iss` does not
match the configured `expected_issuer` is rejected (`validate.c:351`), and a
macaroon whose location packet does not match — *including one with no location
at all* — is rejected (`validate.c:193-209`). Audience is checked as a string or
RFC 7519 §4.1.3 array. Token claims that flow to the log are sanitised
(`token_sanitize_for_log`) to block log-forgery via injected newlines.

---

## Impersonation

### Official: Sec mapping + sudo

Official XRootD maps an authenticated DN/principal to a UNIX username through
`XrdSec`/GSI and can run the OSS op as that user; `sudo` and N2N plugins extend
the mapping. The mapping is a first-class, long-standing feature.

### nginx-xrootd: optional per-request broker, privilege-dropped, off by default

This module's impersonation (`src/impersonate/`, phase 40) is **off by default**
and strictly opt-in (`xrootd_impersonation off|single|map`). `off` and `single`
add no privilege and need no root; only `map` is privileged. Its design is
notably defensive:

- **Workers stay unprivileged.** In `map` mode a single, double-forked **root
  broker** performs each open/metadata syscall as the mapped user
  (`setgroups`+`setfsgid`+`setfsuid`) and returns the resulting fd to the worker
  via `SCM_RIGHTS` (`broker.c`, `impersonate/README.md`). The data plane then
  runs on the already-open fd as the worker — DAC was enforced at open time.
- **The broker drops to only `{CAP_SETUID, CAP_SETGID}`** plus
  `PR_SET_NO_NEW_PRIVS` and a cleared bounding set (`xrootd_imp_broker_drop_caps`,
  `broker.c:206-250`). Crucially it drops `CAP_DAC_OVERRIDE` /
  `CAP_DAC_READ_SEARCH` / `CAP_FOWNER` / `CAP_CHOWN` — whose presence would let a
  root broker bypass the impersonated user's DAC and make impersonation
  meaningless. With `xrootd_impersonation_broker_user` it further drops its real
  uid/gid to a non-root service account, keeping only those two caps
  (`imp_drop_to_service_user`, verified to "stick" via `getresuid`/`getresgid`,
  `broker.c:137-204`).
- **Reserved-id floor (uid/gid ≥ 1000), three independent layers.** The mapper
  denies any reserved id; `imp_become()` performs **no** `setfsuid` and the
  broker `_exit()`s loudly if a reserved cred reaches the syscall edge; and
  `imp_do_op()` re-reads fsuid/fsgid and returns `EPERM` before the actual file
  syscall (`broker.c:274-319`, `:545-549`, `:953-980`). The broker is the
  **only** credential-change site in the codebase.
- **Confused-deputy guards.** The broker structurally refuses to impersonate to
  its own uid or to the SO_PEERCRED-gated worker uid, config-independently
  (`broker.c:291-296`). The socket is `0600`, owned by the worker uid, and
  `SO_PEERCRED`-gated (`imp_peer_allowed`, `broker.c:65-78`).
- **Re-confined in the broker.** The broker re-applies
  `openat2(RESOLVE_BENEATH)` under its *own* rootfd, so a worker bug cannot
  escape the export even through the privileged path. It forces `O_NONBLOCK` on
  open and rejects FIFOs/sockets/devices, so one bad path cannot wedge the single
  broker process into a cross-tenant DoS (`broker.c:553-600`). It services only
  the `user.` xattr namespace and filters non-`user.` names out of `flistxattr`
  results (`broker.c:450-488`).
- **Fails closed.** An unreachable broker, a failed cap-drop, or an uncertain
  mapping all *deny* rather than fall back to privileged I/O
  (`impersonate/README.md`). Authorization stays in the worker's three-tier gate;
  the broker only maps + impersonates + confines.

The honest caveat the README documents: `CAP_SETUID` is inherently root-
equivalent if the broker process is *exploited* — the non-root base reduces
incidental-root exposure (idle state, NSS, path bugs run as the service uid) but
does not contain a code-execution exploit. This is comparable in kind to any
setuid-capable multi-user mapping, including the stock server's.

---

## DoS protection & rate limiting

This is largely **nginx-forward hardening** — much of it inherited from the
nginx core front end, plus this module's identity-aware limiter.

- **Connection front end (inherited).** nginx's accept loop, per-worker
  connection table, request read timers, and (this module's)
  connect/read/handshake deadlines + TCP keepalive / `TCP_USER_TIMEOUT` (phase
  39/51) mean a slow or stalled client is timed out rather than holding a worker.
  A `max_connections` cap bounds total concurrent connections.
- **Identity-aware leaky-bucket limiter** (`src/ratelimit/`, phase 25). Enforces
  **request-rate**, **bandwidth**, and **concurrency** (in-flight) limits keyed
  on XRootD identity dimensions — VO, token issuer, IP, GSI DN (hashed), or
  storage-volume path prefix. On the stream plane a throttled client gets
  `kXR_wait(seconds)` (connection stays open to retry); on the HTTP/WebDAV plane
  it gets `429 Too Many Requests` + `Retry-After`. State lives in a shared SHM
  slab zone with an LRU for O(1) eviction; a zone name shared between `http{}` and
  `stream{}` gives **cross-plane** accounting (a VO's `root://` and `davs://`
  traffic share one bucket). Bandwidth is charged *after* the response, on real
  bytes moved (`ratelimit/README.md`).
- **Anonymous fallback to IP.** VO/ISSUER/DN keys with no identity degrade to
  `ip:<addr>`, so unauthenticated bulk clients are *always* subject to at least
  an IP-keyed rule — fail-closed coverage for the limiter's *targeting*
  (`ratelimit_keys.c`).
- **Fail-open for the limiter itself.** By deliberate design the limiter returns
  *allow* on an internal failure (zone not attached, slab exhausted after
  eviction) — availability beats strict enforcement on a storage gateway
  (`ratelimit/README.md`). This is a conscious posture choice: the limiter is a
  DoS *shaper*, not an access-control gate, and access control (the auth gate)
  remains fail-*closed*.
- **CMS / cluster caps.** A frames-per-wakeup cap and a per-IP connection cap on
  the CMS path (phase 51) prevent a manager/peer flood from burying the loop, and
  GSI handshakes are capped in-flight per worker (above).
- **Auth-path amplification cap.** `auth_fail_count` vs.
  `XROOTD_MAX_AUTH_ATTEMPTS` bounds brute-force on the expensive GSI/VOMS verify
  path (`gsi/auth.c`).

Official XRootD has its own connection and threading limits but is not fronted by
a general-purpose hardened server, and has no built-in identity-keyed bandwidth/
concurrency shaper of this kind.

---

## Build hardening

The module's `config` script adds, on every build (`config:16`):

```
-D_FORTIFY_SOURCE=2          glibc runtime buffer-overflow detection
-fstack-protector-strong     stack canaries on functions with local buffers
-fstack-clash-protection     probe the stack to catch stack-clash attacks (GCC 8+)
-fcf-protection=full         Intel CET control-flow integrity (x86, GCC 8+)
-Wformat -Werror=format-security   format-string bugs are a compile error
```

Full RELRO + `BIND_NOW` are documented as a configure-time opt
(`--with-ld-opt="-Wl,-z,relro,-z,now"`, `config:15`). The performance profile is
`-O3 -march=x86-64-v2` by default (`config:40`). These are additive to nginx's
own CFLAGS. The coding standard forbids `goto` and raw `malloc`/`strcpy` in
`src/`, and mandates `ngx_palloc`/`ngx_alloc` + length-prefixed `ngx_str_t` —
which keeps wire-string handling off the classic C string-bug paths. Official
XRootD's hardening flags are whatever the distribution/CMake build sets and are
not fixed by this comparison.

---

## Admin security configuration

| Area | Official XRootD | nginx-xrootd |
|---|---|---|
| Path confinement | export-prefix list; symlinks **followed** | `RESOLVE_BENEATH` always on; symlink escape **refused** (no directive to disable) |
| Auth requirement | `sec.protocol` / `xrootd.seclib`; default depends on config | per-listener auth mode; `auth=none` is the only path that sets `auth_done` at login (explicit, secure-by-default ports per `CLAUDE.md` routing table) |
| Revocation | `CRLCheck require[-not-expired]`, `CRLRefresh` | CRL loaders + OCSP (`ocsp.c`); OCSP `soft_fail` policy; revoked is never softened |
| Token | ZTN plugin config | mandatory `exp`; `expected_issuer`/`expected_audience` pinning |
| Impersonation | Sec mapping + sudo, on by config | `off` by default; `map` requires root broker; reserved-id floor + cap-drop are non-optional |
| Rate / DoS | connection/thread limits | `xrootd_rate_limit_zone`/`_rule`/`xrootd_bandwidth_limit`/`xrootd_concurrency_limit`; `max_connections`; deadlines |
| Privilege model | typically one service user | unprivileged workers; only the optional broker is privileged, and it self-minimises |

The secure-by-default story differs in emphasis. Official XRootD is
secure-when-configured by an experienced operator (CRL `require`, a Sec protocol,
an Acc plugin). nginx-xrootd pushes more guarantees into code that an operator
**cannot** turn off: kernel confinement is unconditional, symlink escape cannot
be re-enabled, a token without `exp` cannot be accepted, the impersonation
reserved-id floor and cap-drop are not directives, and the auth gate denies on a
missing authz table.

---

## Parity, divergences, and posture

| Dimension | Official | nginx-xrootd | Posture |
|---|---|---|---|
| `..` lexical rejection | `rpCheck` (reject) | `has_dotdot`/`component_forbidden` (reject) | **parity** |
| Confinement mechanism | lexical export-prefix | kernel `RESOLVE_BENEATH` (syscall-atomic) | **nginx stronger** (no TOCTOU) |
| Symlink escape | followed (export-prefix bound) | refused by kernel | **nginx stricter** (deliberate) |
| Embedded-NUL / truncation | server NUL-terminates arg | rejected at extract + login | **parity / nginx explicit** |
| Negative / oversized `dlen` | `kXR_ArgInvalid` / `kXR_ArgTooLong` | rejected; never crash/hang (pinned by test) | **parity** |
| Fail-closed auth | Sec completes before ops | gate on `auth_done` only; XrdAcc denies on missing table | **parity** (nginx fixed a proxy fail-open class) |
| CRL revocation | yes (configurable levels, refresh) | yes (PEM + Grid hash) | **parity** |
| OCSP revocation | **none** | yes, bounded connect + staple | **nginx adds** |
| Mandatory token `exp` | plugin-dependent | enforced in code | **nginx stricter** |
| Issuer pinning (JWT + macaroon) | plugin config | enforced, incl. no-location macaroon reject | **nginx stricter** |
| Impersonation privilege model | Sec map + sudo | privilege-dropped root broker, off by default | **comparable; nginx more contained** |
| Identity-aware rate/bw/conc limiting | not built-in | leaky-bucket, cross-plane, `kXR_wait`/429 | **nginx adds** |
| Availability hardening | own limits | nginx front end + SHM-mutex spin fix + deadlines | **nginx adds** |
| Build hardening | distro/CMake-defined | FORTIFY + stack-protector + clash + CET fixed | **nginx fixed-on** |
| Maturity / field exposure | decades, huge deployment | newer; verified differentially against stock | **official more proven** |

**Bottom line.** On the *mechanisms* that matter most — confinement,
fail-closed auth, framing robustness, revocation — nginx-xrootd reaches parity
with official XRootD and, in several places, is **stricter** by deliberate
design: kernel-enforced (not lexical) confinement, refused (not followed) symlink
escape, mandatory token expiry, issuer pinning for both token types, and OCSP on
top of CRL. It also inherits a hardened network front end and adds an identity-
aware DoS shaper the monolithic server lacks. The honest counterweights are
maturity (official has far more field exposure), a hard kernel dependency
(`openat2` ≥ 5.6), the limiter's deliberate fail-*open* design, and the
inherent `CAP_SETUID` exposure of *any* impersonation broker if it is exploited.

---

## Source references

**Official XRootD (`/tmp/xrootd-src/src`):**

- `XrdXrootd/XrdXrootdXeq.cc:4374` (`rpCheck`), `:4435` (`Squash`); call sites at
  `:1600` (open), `:2450`/`:2521` (stat), `:1313` (rename), `:2919` (rm), and others.
- `XrdXrootd/XrdXrootdProtocol.cc:404` (negative `dlen` → `kXR_ArgInvalid`),
  `:420` (`kXR_ArgTooLong`), `:425` (server NUL-terminates the arg).
- `XrdSecgsi/XrdSecProtocolgsi.cc:142,154,501-543` (`CRLdir`, `CRLCheck`,
  `CRLDownload`, `CRLRefresh`).
- `XrdTls/XrdTlsContext.cc:85-111` (background CRL refresh thread).
- `grep -rln OCSP /tmp/xrootd-src/src` → empty (no OCSP).

**nginx-xrootd (this repository, `src/`):**

- Confinement: `path/beneath.c` (`do_openat2`, `beneath_open_parent`),
  `path/beneath.h`, `path/extract.c` (embedded-NUL + length), `path/helpers.c`
  (`xrootd_path_has_dotdot`, `xrootd_path_component_forbidden`),
  `path/normalize.c`.
- Fail-closed auth: `handshake/dispatch.c:57-71` (`auth_done` proxy gate),
  `path/auth_gate.c` (three-tier gate, missing-table deny, verdict cache key),
  `path/auth_gate_l1.c`, `session/login.c`, `session/lifecycle.c:170`,
  `session/bind.c:123`, `gsi/auth.c:414` (`auth_fail_count`).
- Credential hardening: `crypto/ocsp.c` (connect deadline, nonce, never-soften-
  revoked), `crypto/pki_load.c` (CRL loaders), `token/validate.c:193-209`
  (macaroon issuer), `:335-341` (mandatory `exp`), `:351` (JWT issuer),
  `gsi/auth.c:18-39,244,366` (in-flight handshake cap), `compat/shm_slots.c`
  (SHM-mutex spin fix).
- Impersonation: `impersonate/broker.c`, `impersonate/README.md`,
  `impersonate/idmap.c`.
- DoS / rate limiting: `ratelimit/README.md`, `ratelimit/ratelimit.c`,
  `ratelimit_stream.c` (`kXR_wait`), `ratelimit_http.c` (429),
  `ratelimit_keys.c` (IP fallback).
- Build hardening: `config:8-16,40` (FORTIFY / stack-protector / clash / CET /
  `-O3`).
- Verification: `tests/test_conf_framing.py` (never crash/hang),
  [`../conformance-findings.md`](../conformance-findings.md) (framing batch),
  `tests/userns/` (impersonation under an unprivileged user namespace).
