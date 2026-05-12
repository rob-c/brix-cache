# Auth and cross-cutting optimizations

[← Overview](index.md)

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

- `src/gsi/config.c`
- `src/gsi/cert_response.c`
- `src/handshake/sigver.c`
- `src/session/signing.c`
- `src/types/context.h`
- `src/connection/disconnect.c`

---

## 26. Token Auth Is Local

### What Changed

The stream and WebDAV token paths load JWKS keys from disk and verify bearer
tokens locally.

### Why It Helps

The request path does not call an external identity provider. That removes an
entire network dependency from transfer startup and avoids unpredictable auth
latency.

Expected benefits:

- no per-request identity-provider lookup
- predictable token verification latency
- no transfer outage when an external control plane is temporarily unreachable

Relevant code:

- `src/token/*.c`
- `src/webdav/auth_token.c`

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

- `src/types/file.h`
- `src/connection/fd_table.c`
- `src/read/*.c`
- `src/write/*.c`
- `src/query/*.c`

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

- `src/metrics/*.c`
- `src/types/tunables.h`
