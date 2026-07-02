# Auth and cross-cutting optimizations

What makes auth fast: credential caching, JWKS key pinning, GSI handshake reuse, and where you can accidentally blow the budget.

[← Overview](optimizations.md)

## 25. Native GSI Request Signing Reuses HMAC State

### What Changed

The native GSI path now caches the server certificate's PEM serialization at
configuration time. The `kXGS_cert` response still contains per-session DH key
material, but it no longer reserializes the fixed server certificate on every
GSI login.

For GSI sessions that use `kXR_sigver`, the verifier also lazily creates the
OpenSSL HMAC implementation handle and MAC context once per connection and
reuses them for subsequent signed requests.

The verifier also fails closed if the HMAC calculation itself fails. Previously,
provider or context failures could leave `ok == 0` and still continue dispatch.

### Why It Helps

Signed XRootD requests are latency-sensitive at low concurrency. Fetching the
OpenSSL provider implementation and allocating a MAC context for every covered
request adds fixed CPU cost before the request reaches `open`, `read`, `stat`,
or `close`.

```text
  ONCE PER PROCESS        ONCE PER CONNECTION        PER SIGNED REQUEST
  (config time)           (first kXR_sigver)         (every covered op)
  ┌──────────────────┐    ┌──────────────────┐       ┌──────────────────┐
  │ server cert PEM  │    │ fetch HMAC impl  │       │ HMAC-update(req) │
  │ serialized & held│──▶ │ alloc MAC ctx    │ ────▶ │ compare to sigver│
  └──────────────────┘    │ (cached on ctx)  │       │ fail closed on   │
                          └──────────────────┘       │ any crypto error │
                                  ▲                   └────────┬─────────┘
                                  └─── reused ─────────────────┘
                            no reserialize, no provider lookup, no alloc
                            ───────────────────────────────────────────▶
       open · read · stat · close dispatch only after verify succeeds
```

Expected benefits:

- less repeated OpenSSL/BIO work during GSI session startup
- fewer OpenSSL provider lookups
- fewer heap allocations on signed request dispatch
- lower latency for GSI-protected `root://` sessions
- safer behavior if crypto setup unexpectedly fails

Relevant tests:

- `tests/test_sigver_verify.py`
- `tests/test_new_opcodes.py`

Relevant code:

- `src/auth/gsi/config.c`
- `src/auth/gsi/cert_response.c`
- `src/protocols/root/handshake/sigver.c`
- `src/protocols/root/session/signing.c`
- `src/core/types/context.h`
- `src/protocols/root/connection/disconnect.c`

---

## 26. Token Auth Is Local

### What Changed

The stream and WebDAV token paths load JWKS keys from disk and verify bearer
tokens locally.

### Why It Helps

The request path does not call an external identity provider. That removes an
entire network dependency from transfer startup and avoids unpredictable auth
latency.

```text
  REMOTE introspection (avoided)        LOCAL JWKS verify (this module)
  ──────────────────────────────        ───────────────────────────────
  bearer ─▶ POST /introspect ─▶ IdP     bearer ─▶ split header.payload.sig
            (network RTT, can stall)              │
            ◀── active? scopes? ──┘               ▼ verify sig with pinned
                  │                          JWKS key (RSA/EC, in memory)
                  ▼                               │
            outage in IdP =                       ▼ check exp/nbf/aud/scope
            transfer outage                       │
                                                  ▼ accept — no network,
                                            predictable µs-scale latency
```

Expected benefits:

- no per-request identity-provider lookup
- predictable token verification latency
- no transfer outage when an external control plane is temporarily unreachable

Relevant code:

- `src/auth/token/*.c`
- `src/protocols/webdav/auth_token.c`

---

## 27. Handle-Based Native Operations Reuse Open State

### What Changed

Once the native stream path opens a file, follow-up operations reuse the handle
state:

- open fd
- canonical path
- file size where safe
- per-handle counters

Handle-based `stat`, checksum queries, reads, writes, and close logging do not
need to rediscover the file from the pathname each time.

### Why It Helps

XRootD clients naturally operate on handles. Reusing handle state matches the
protocol model and avoids repeated path resolution.

Expected benefits:

- fewer path-resolution syscalls
- fewer repeated metadata queries
- simpler and cheaper logging
- more predictable behavior under path mutation

Relevant code:

- `src/core/types/file.h`
- `src/protocols/root/connection/fd_table.c`
- `src/protocols/root/read/*.c`
- `src/protocols/root/write/*.c`
- `src/protocols/root/query/*.c`

---

## 28. Metrics Use Atomic Counters, Not Heavy Request Objects

### What Changed

The module records operational metrics through shared-memory atomic counters
instead of constructing heavyweight per-request metric objects.

### Why It Helps

Metrics should make hot paths observable without becoming a major part of the
hot path. Atomic increments are still work, but they are much cheaper than
allocating or formatting records for every request.

Expected benefits:

- low-overhead counters for high-volume operations
- visibility into request and byte counts
- avoids per-request allocation for metrics

Relevant code:

- `src/observability/metrics/*.c`
- `src/core/types/tunables.h`
