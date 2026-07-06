# Module quirks and compromises

> ⚠️ **Reference tier — design trade-offs.** Where XRootD, WebDAV, nginx, and OpenSSL don't line up cleanly, forcing implementation compromises. Useful for understanding *why* things work the way they do.
>
> **Skip if:** You just want to use or operate this module. These are implementation details, not operational concerns.
>
> Prerequisites: [XRootD Basics](../02-concepts/xrootd-basics.md), reading C source code comfortably.

Higher-level quirks and compromises in the native XRootD and WebDAV modules — the places where design trade-offs forced non-obvious choices.

It is different from [protocol-notes.md](protocol-notes.md):

- `protocol-notes.md` is about low-level wire behavior discovered by reverse
  engineering real clients
- this page is about the places where XRootD, WebDAV, nginx, and OpenSSL do
  not line up cleanly, so the implementation has to choose a compromise

None of these are necessarily bugs. Most are the result of fitting a
stateful storage protocol and a Grid-auth model into nginx's event-driven HTTP
and stream frameworks.

---

## Summary table

| Area | Why there is tension | Current compromise |
|---|---|---|
| native auth vs transport security | GSI auth and TLS are separate concepts in XRootD | GSI can run with or without TLS; `brix_tls` and `roots://` are separate choices |
| x509 proxies in WebDAV | nginx/OpenSSL does not naturally love RFC 3820 proxy chains | patch `SSL_CTX`, then verify proxy chains in module code |
| zero-copy vs TLS | file-backed send paths are easiest on cleartext sockets | cleartext native reads use sendfile-style chains; TLS paths fall back to memory-backed reads when needed |
| session model vs request model | native XRootD is session-oriented; WebDAV is HTTP request-oriented | stream keeps session state; WebDAV re-evaluates requests and uses caches to recover some session-like efficiency |
| token scopes | stream and WebDAV were implemented at different stages | stream enforces scopes on path-resolving operations; handle I/O inherits the open-time decision; WebDAV enforces scopes for bearer-token writes |
| third-party copy | root TPC and HTTP-TPC are different protocols | native root TPC has source/destination rendezvous with limited credential edge cases; WebDAV HTTP-TPC is implemented separately with helper/subprocess paths |
| nginx body handling | HTTP request bodies may be in memory or temp files | WebDAV `PUT` has separate fast paths for in-memory and spooled bodies |
| nginx connection context | HTTP module has fewer natural per-connection hooks than stream | WebDAV stores fd-cache state in SSL `ex_data` |
| real clients vs spec text | `xrdcp` behavior often differs from the nominal protocol docs | implementation follows working client behavior first |

---

## 1. Native GSI is not the same thing as transport TLS

This is one of the easiest things to misunderstand.

In the native `root://` path:

- GSI/x509 authentication proves identity and establishes the XRootD auth state
- transport TLS is separate

So these are all distinct deployments:

- `root://` + GSI auth, no transport TLS
- `root://` + GSI auth + `brix_tls on`
- `roots://` with nginx stream SSL

That split exists because it is how the XRootD ecosystem evolved. The module
does not try to pretend otherwise.

Practical consequence:

- "GSI enabled" does not automatically mean "all file data is inside TLS"

See [tls.md](../03-configuration/tls-config.md).

---

## 2. WebDAV x509 proxy auth has to work around nginx's defaults

Grid clients use RFC 3820 proxy certificates. nginx's built-in TLS client-cert
verification is not, by itself, a complete answer for that environment.

The module therefore does two things:

1. patches the `SSL_CTX` with `X509_V_FLAG_ALLOW_PROXY_CERTS`
2. keeps its own CA/CRL store and can verify the proxy chain manually

That is a deliberate compromise:

- nginx still does the TLS handshake
- the storage module keeps authority over the Grid-specific auth decision

Why not leave it all to nginx?

- because proxy-certificate acceptance and Grid CA/CRL policy need behavior that
  stock nginx deployments do not naturally provide

The result is slightly more complex than a vanilla HTTPS application, but it
matches real x509 proxy clients much better.

---

## 3. Session-oriented stream vs request-oriented WebDAV

The native stream module is connection/session oriented:

- one login
- one auth completion
- open file handles live in the session context
- later requests operate on those handles

WebDAV is HTTP-oriented:

- each request stands alone
- auth policy is checked per request
- there is no native "open handle" concept

The implementation compromise is:

- stream uses a rich per-connection state machine
- WebDAV uses request handlers plus caches where useful

Practical consequence:

- native `root://` feels like a long-lived protocol session
- `davs://` feels like repeated HTTP method calls, even when the TCP/TLS
  connection is reused underneath

---

## 4. Zero-copy style reads are best on cleartext sockets

For cleartext native `root://` reads of regular files, the module builds
file-backed nginx chain buffers so the send path can use the platform sendfile
implementation.

Under TLS that gets much less clean:

- the SSL send path has different constraints
- file-backed XRootD chains are not the reliable choice on every TLS setup

So the current compromise is:

- use the file-backed fast path on cleartext native reads
- fall back to memory-backed `pread()` responses when the stream is under TLS

This is not as elegant as "one perfect zero-copy path everywhere", but it is a
correct and explicit trade-off.

See also [optimizations.md](../09-developer-guide/optimizations.md).

---

## 5. `xrdcp` over WebDAV is not a thin wrapper around native XRootD

The `davs://` path is a different client stack:

- `OPTIONS`
- `PROPFIND`
- `GET`
- `PUT`
- `MKCOL`
- `DELETE`

That means the module has to satisfy the WebDAV expectations of the HTTP plugin,
not the opcode expectations of the stream client.

Examples:

- `OPTIONS` must advertise `PROPFIND`
- metadata comes from `PROPFIND`, not `kXR_stat`
- uploads are HTTP `PUT`, not `kXR_pgwrite`

So the implementation intentionally does not try to collapse the two worlds into
one internal abstraction. They share storage and auth concepts, but they are
still different protocol surfaces.

See [xrdcp-interactions.md](../04-protocols/xrootd-client-interaction.md).

---

## 6. Native root TPC and WebDAV HTTP-TPC are different features

There are two different "third-party copy" stories:

- native root TPC in the XRootD stream protocol
- HTTP-TPC via WebDAV `COPY`

The module has separate implementations with different limits:

- native root TPC implements destination-side pull when a write open carries
  `tpc.src=root://...` (and optional `tpc.key=`); the pull runs in the thread pool
- on the source, read-opens with `tpc.dst` + `tpc.key` register the rendezvous key;
  read-opens with `tpc.org` + `tpc.key` consume it before serving bytes
- the outbound pull client can complete ztn or GSI after `kXR_authmore` when
  configured; TLS-upgraded origins and multihop delegation remain deployment
  validation points
- WebDAV HTTP-TPC is handled in a dedicated helper path

The WebDAV TPC implementation is intentionally pragmatic:

- it uses curl/helper paths rather than embedding a full HTTP/OAuth2 stack in
  the nginx event loop
- it implements OAuth2/OIDC delegation modes, but the credential exchange still
  has subprocess/helper operational behavior

That is not as feature-rich as a full XRootD daemon, but it keeps the scope of
the nginx module manageable and makes the HTTP behavior predictable.

---

## 7. Token authorization is similar, but still protocol-shaped

The token story is now closer across native XRootD and WebDAV, but the two
protocols still enforce at different natural points:

- native stream:
  - validates JWTs
  - parses `scope` and `wlcg.groups`
  - enforces `storage.read`, `storage.write`, and `storage.create` on
    path-resolving operations
  - lets handle-based I/O inherit the authorization decision made at `kXR_open`
- WebDAV:
  - validates bearer tokens
  - enforces `storage.write` / `storage.create` for mutating requests like
    `PUT` and `COPY`

This is not a single shared middleware layer because native XRootD is
handle-oriented while WebDAV is request-oriented.

Practical consequence:

- do not assume stream and WebDAV token writes are checked at the same point in
  the request lifecycle

The docs call this out in multiple places because it matters operationally.

---

## 8. nginx's HTTP body model shapes the WebDAV upload path

By the time WebDAV `PUT` handling runs, nginx may have:

- the whole body in memory
- or a temp file under `client_body_temp_path`
- or a chain of both

So the module cannot treat every upload as one neat contiguous socket stream.
Instead it uses different strategies:

- in-memory body:
  - optionally coalesce and offload the write to a thread pool
- spooled temp file:
  - prefer `copy_file_range()`
  - fall back to buffered copy if needed

That compromise is a direct consequence of plugging into nginx's HTTP request
lifecycle instead of writing a standalone WebDAV server from scratch.

---

## 9. The HTTP module has weaker per-connection storage than the stream module

The stream module naturally owns a session object for the whole life of the
connection. The HTTP content module does not get quite the same kind of durable
per-connection storage hook.

The compromise in WebDAV is to stash some connection-level state in SSL
`ex_data`, notably:

- x509 auth caches
- the per-connection fd table for keepalive `GET` reuse

That is a practical solution, but it means the nicest fast path is tied to TLS
connections, because that is where the stable OpenSSL connection object exists.

---

## 10. Some "spec purity" had to yield to real `xrdcp` behavior

Several implementation choices are driven by what real clients do, not by what
the protocol specification suggests at first glance.

Examples:

- v5 handshake reply format
- `SecurityInfo` in `kXR_protocol`
- plain-text GSI login parameters
- `kXR_pgwrite` needing a 32-byte `kXR_status` response
- one trailing NUL inside path payload length
- `kXR_new | kXR_delete` meaning overwrite

Those are not really optional. If the server follows the paper spec but not the
real client behavior, `xrdcp` hangs, disconnects, or misparses responses.

That is why [protocol-notes.md](protocol-notes.md) exists, and why some code
paths look stricter or stranger than a casual reading of the protocol might
suggest.

---

## 11. Some limits are intentionally small and explicit

A few limits are chosen to keep failure modes predictable:

- up to 16 open files per native connection
- 16 MiB maximum write payload per native request
- 1024 `readv` segments per request
- 256 MiB maximum total `readv` response

These are compromises between performance, memory use, and implementation
complexity. They are not declarations that the XRootD protocol itself could
never support larger values.

Practical consequence:

- if a future client starts sending much larger per-request payloads, the module
  may need another round of limit work rather than "just working forever"

---

## 12. Logging and metrics intentionally leave information out

Another deliberate compromise: observability is useful, but user-controlled
identity and path data are dangerous in logs and poisonous in Prometheus label
sets.

So the module:

- sanitizes client-controlled log strings
- keeps metric labels low-cardinality
- does not try to turn usernames, DNs, token subjects, or paths into metrics

That can feel less convenient when debugging one specific user transfer, but it
is the safer default for a long-running service.

---

## 13. Thread pools are optional, so synchronous fallback still exists

Both modules can use nginx thread pools for blocking file I/O, but nginx thread
pools are still configuration, not a guaranteed runtime feature of every build.

The compromise is:

- use async thread-pool paths when available
- fall back to synchronous I/O when not

That keeps the module usable in simpler builds, but it also means a deployment
without thread pools can still behave very differently under load from a tuned
deployment.

---

## 14. The module prefers explicit behavior over pretending to be the full xrootd daemon

Across both the stream and WebDAV code, a repeated design choice is:

- implement the pieces needed for the target workflows well
- be explicit about unsupported or intentionally simplified areas

Examples:

- native root TPC has destination-pull and source rendezvous paths, while TLS
  upgrade and multihop delegation remain narrower than upstream
- WebDAV TPC is implemented separately and uses helper/subprocess paths for the
  most complex HTTP/OAuth2 interactions
- token authorization is checked at protocol-appropriate points rather than in
  one shared abstraction
- remote storage backends are out of scope
- read-through cache mode has a narrow origin client, not a general remote
  backend abstraction layer

This keeps the module understandable and maintainable inside nginx, even though
it means some advanced XRootD-daemon features are intentionally out of scope.

---

## 15. WebDAV COPY routes to three different handlers

`COPY` is unique in having three completely different handler paths:

```
COPY request
    │
    ├── Source: header → TPC pull (src/protocols/webdav/tpc.c)
    │       server fetches from remote URL into local path
    │
    ├── Destination: header + Credential: header → TPC push (src/protocols/webdav/tpc.c)
    │       server reads local file and streams to remote URL
    │
    └── Destination: header, no Credential: → server-side copy (src/protocols/webdav/copy.c)
            RFC 4918 §9.8 — local file copy within the export root
```

The `Credential:` header is the WLCG HTTP-TPC signal. Standard WebDAV COPY
(RFC 4918 §9.8) never includes it. Routing based on the Destination URL scheme
(`https://`) is tempting but wrong — a TPC request to a disabled-TPC server
would fall through to local copy and spuriously succeed.

This matters when debugging: a COPY that returns unexpected 200 may be routing
to the wrong handler. Check which headers the client sent first.

---

## 16. WebDAV LOCK tokens must be sent in If: header, not Authorization:

WebDAV LOCK tokens (format `urn:uuid:...`) are presented in the `If:` header
as a "condition list", not in `Authorization:`. A client that sends a bearer
token AND holds a lock must provide both headers on write requests:

```http
PUT /path HTTP/1.1
Authorization: Bearer eyJ...
If: (<urn:uuid:a1b2c3d4-...>)
```

The module checks `If:` for a matching lock token before allowing writes.
A PUT with a valid bearer token but a locked resource and no `If:` header
returns 423 Locked.

---

## 17. The WebDAV fd cache is TLS-connection-scoped

The per-connection file descriptor cache (`src/protocols/webdav/fd_cache.c`) reuses open
file descriptors across keepalive requests on the same connection. It is stored
in OpenSSL `ex_data` — which means it only exists on TLS connections that have
a stable `SSL` object.

On plain HTTP keepalive connections, the fd cache falls through to open-per-request
behavior. For HTTP clients (e.g. testing with plain `http://`) you may see higher
`open(2)` syscall counts than on `https://` connections even for identical access
patterns. This is expected behavior, not a bug.

---

## 18. S3 multipart upload IDs are not globally unique

The upload ID format is `<pid>.<timestamp_usec>`. This is locally unique across
concurrent uploads from one nginx worker but could theoretically collide across
worker restarts within the same microsecond. In practice this is not a problem
for typical HEP storage workloads, but it means:

- Do not use upload IDs as global identifiers across servers
- The staging directory namespace (`.KEYNAME.mpu-UPLOADID/`) is scoped to the
  filesystem path, so collisions across different keys are impossible even with
  identical IDs

If you need cryptographically strong upload IDs, the `s3_handle_multipart_initiate`
function in `src/protocols/s3/multipart.c` is the right place to change the generation logic.

---

## 19. S3 ListObjectsV2 does not support all query parameters

The S3 ListObjectsV2 implementation (`src/protocols/s3/list.c`) supports:

- `prefix` — filters keys by prefix
- `max-keys` — limits result count
- `continuation-token` — paginated listing

It does not currently support:
- `delimiter` — no virtual directory grouping (CommonPrefixes)
- `start-after` — cursor-based start position
- `fetch-owner` — owner fields are always empty

For AWS SDK clients that require these parameters, the server returns a valid XML
response but ignores the unsupported parameters. AWS SDK clients typically fall
back gracefully to listing without grouping. Clients that strictly require
`delimiter` behavior (e.g. for virtual directory browsing) may see incorrect
results.

---

## 20. The WebDAV TPC credential delegation uses a subprocess, not in-process async

HTTP-TPC credential delegation (`oidc-agent` mode and RFC 8693 token-exchange
mode) uses a `curl` subprocess rather than an in-process HTTP client. This means:

- Each TPC transfer with credential delegation forks a curl process
- The nginx event loop is not blocked (curl runs in the nginx thread pool)
- The curl subprocess inherits the configured CA bundle and TLS identity
- Credential exchange errors appear in the nginx error log from the subprocess

This is the same design used for TPC pull/push: keep complex external protocol
interactions out of the event loop and out of the nginx process itself. The
alternative would be embedding a full OAuth2 client library in C, which adds
significant maintenance surface for a rarely-invoked code path.

---

## `xrd` BusyBox-style POSIX verbs (phase 41)

The unified `xrd` front-end grows POSIX file utilities (`head`, `tail -n/-f`, `df`,
`touch`, `ln`, `readlink`, `chmod -R`, `mount` listing). A few non-obvious choices:

- **`head -c` beats `-n`.** GNU `head` lets the last-given option win; `xrd head`
  always prefers `-c` (byte mode) when both are present, because byte mode is exact
  and cheap on a remote file while line mode must scan. Pass only one to avoid surprise.
- **`tail -f` polls, it does not watch.** A remote XRootD namespace has no inotify
  equivalent, so follow mode `stat`s the file on an interval (`--interval`, default 1 s)
  and streams any growth, resyncing to the new EOF on truncation. It is SIGINT-clean
  (single connection, no detached threads), but latency is the poll interval, not instant.
- **`chmod` is octal-only; symbolic modes (`u+x`) are not supported.** Symbolic modes
  must be applied relative to the file's *current* permission bits, but the XRootD wire
  stat does not return the POSIX mode — `xrdc_statinfo` carries only
  `kXR_readable`/`kXR_writable`/`kXR_isDir` flags. Without the current mode there is no
  correct base to apply `+`/`-`/`=` against, so `xrd chmod` accepts only absolute octal
  modes (`chmod [-R] <path> <octal>`). `-R` recursion and octal work everywhere.
- **`ln -s` targets are stored verbatim and not confined.** Only the *link path* is
  resolved under the export root; the symlink *target* is opaque link content (matching
  real `ln -s` and `brix_handle_symlink`). The server still confines every path it
  *resolves through* the link, so this is not a confinement gap.
- **`touch` and the link/`readlink` verbs need `xrdfs.ext`.** `kXR_setattr`/`symlink`/
  `readlink`/`link` are capability-negotiated (advertised via
  `kXR_Qconfig "xrdfs.ext"`). This module advertises them unconditionally, but against a
  server without the extension these verbs fail cleanly with the server's
  `kXR_Unsupported` message (nonzero exit), rather than silently no-opping. `touch`'s
  create step and `chmod` use the always-present `kXR_open`/`kXR_chmod` opcodes.
- **No `chown`/`chgrp`.** `xrd` intentionally exposes no ownership-mutating verb; every
  `xrd touch` calls `xrdc_setattr` with `set_owner = 0`. Ownership changes are a
  DAC/impersonation surface and are out of scope (see the impersonation design).
- **`df` reads `kXR_Qspace`, not `statvfs`.** The module's `kXR_vfs` stat returns block
  count + flags (not free space), so `xrd df` uses the `oss.*` Qspace record
  (`oss.space`/`oss.free`/`oss.used`/`oss.maxf`) and falls back to printing the raw
  reply verbatim if the shape is unrecognized. Cluster-wide per-holder aggregation is
  `xrdmapc`'s job, not `xrd df`'s.
- **`xrd mount` with no positional args lists mounts** (like `mount(8)`), parsing
  `/proc/self/mountinfo`; with `<endpoint> <mountpoint>` it mounts. `xrd mounts` is an
  unambiguous spelling for scripts. Listing is Linux-only (procfs).

A second batch (the "inspect & verify" tools) adds `cksum`, `wc`, `cmp`, `xattr`,
`grep`, `hexdump`, `stage`/`evict`, `ping`, `replicas`, and `sync`:

- **`cmp` prefers checksums over bytes.** It first asks the server for an `adler32`
  checksum of each operand (cheap, no bulk transfer) and compares those; only if a
  checksum is unavailable does it fall back to streaming both files for a byte-exact
  compare. So a `cmp` "match" on a checksum-capable server means *checksums* matched,
  reported as such. Both operands must be on the same endpoint (like `mv`/`ln`).
- **`xattr` names round-trip; the namespace tag is hidden.** The server stores managed
  user attributes under the host `user.U.<name>` key and returns them from a list as
  `U.<name>` (a one-letter namespace tag + `.`). `xattr ls` strips that tag so the
  printed names feed straight back into `xattr get`/`set`. Only the user namespace is
  exposed. Read-only checksum attrs surface as `user.XrdCks.<algo>` via the FUSE driver,
  not here.
- **`grep`/`wc -l`/`wc -w`/`cmp`-fallback read the whole file.** There is no server-side
  search or line-count, so these stream the full object (line state is reassembled
  across read chunks). `wc -c` is the exception — it's answered from `stat`. Mind the
  cost on large remote files.
- **`stage`/`evict` are `prepare` with fixed flags.** `stage` = `kXR_prepare`+`kXR_stage`,
  `evict` = `kXR_prepare`+`kXR_evict`. `stage --wait` polls the file's residency
  (`kXR_offline` flag via `stat`) once a second until it clears or the timeout (default
  300 s) — polling, like `tail -f`.
- **`ping` measures stat-RTT, not ICMP.** It opens one session, then times N `stat /`
  round-trips (application-level latency including any TLS), reporting min/avg/max. For
  deeper network diagnostics use `xrd diag` (→ `xrddiag`).
- **`replicas` and `sync` are thin front-ends.** `replicas` execs `xrdmapc` (cluster
  holder + space map); `sync` execs `xrdcp -r --sync` (recursive mirror, skip same-size).
  They inherit those tools' behavior and flags verbatim.

The `dd`/`upload`/`download` trio adds windowed + **rate-limited** block I/O:

- **Rate limiting is client-side token-bucket pacing, not a network shaper.** Each
  verb (`dd`, `upload`, `download`) takes `rate=<bytes/s>` (K/M/G suffix). After each
  block it sleeps off any surplus so the running average stays at/below the cap. Because
  XRootD I/O is synchronous request/response, slowing the client's reads/writes
  back-pressures TCP flow control and effectively throttles the server side too — but
  it's *not* a precise `tc`/QoS shaper: granularity is one block (`bs=`, default 1 MiB;
  smaller `bs` = smoother), and it can't pace below a single round-trip. Good for "be
  polite on a shared link," "don't saturate a mount," or "simulate a slow client."
- **Three overlapping read/write tools, by destination.** `dd` reads a *window*
  (`skip=`/`count=` blocks) to *stdout*; `download` reads a whole file to a *local file*
  (defaults to the remote basename, like `get`); `upload` writes a *local file/stdin* to
  a remote path. `get`/`put` (→`xrdcp`) remain the non-throttled, feature-rich
  transfers; `dd`/`upload`/`download` are the native, rate-capable ones.
- **Overwrite semantics differ by side.** `upload` without `-f` uses `kXR_new` (fails if
  the *remote* exists, surfaced as `FileLocked`); `download` without `-f` uses local
  `O_EXCL` (fails if the *local* file exists). `-f` truncates/overwrites in both. `bs=`
  is capped at 256 MiB (a single block buffer is allocated).

The endpoint-diagnostic verbs (`certinfo`, `clockskew`, `whoami`, `caps`, and the
`doctor` that folds them in) have a few subtleties:

- **`certinfo` connects without authenticating and without verifying the chain.** It is
  an *inspection* tool, so it must see expired/self-signed/untrusted certs. It uses a
  dedicated no-login bring-up (`xrdc_connect_no_login`) — handshake + TLS upgrade but no
  `kXR_login` — and an `insecure_tls` opt that skips chain + host verification. That opt
  is **off by default for every other code path** (zero-initialized `xrdc_opts`); only
  `certinfo` (and `doctor`'s cert probe) set it, and never for data transfer. A cleartext
  `root://` endpoint legitimately has no peer cert and reports "no certificate".
- **`clockskew` resolution is ~1 second and it is not NTP.** The HTTP `Date` header is
  second-granular, and the `root://` create+stat path reads a second-granular mtime; both
  are RTT-compensated by halving the measured round-trip. It detects the
  minutes-to-hours skew that breaks token/GSI time checks, not sub-second drift. The
  `root://` path needs write access (it creates and removes a `/.xrd_clockskew_<pid>`
  temp file); read-only exports fall back to "not measured — need an HTTP endpoint or
  write access".
- **`whoami` shows what you *present*, not a server-side mapping.** XRootD's login does
  not return the mapped username, so `whoami` reports the negotiated auth protocol
  (`chosen_auth`), the server's offered `&P=` sec list, and your local token subject /
  proxy DN — which is what you need to debug "I have a token but get 403".
- **`caps` `=0` is ambiguous.** This module answers `chksum`/`readv`/`tpc`/`tpcdlg`/
  `xrdfs.ext` meaningfully and echoes `<key>=0` for any *other* probed key, so
  `version=0`/`role=0`/`sitename=0` against this module means "not answered" rather than
  a real zero; against stock XRootD those keys return real values. Role is taken from the
  protocol `server_flags`, not from Qconfig.
- **`doctor` makes two connections per endpoint.** One authenticated (liveness, auth,
  TLS posture, caps) and one no-login insecure probe (server cert) — so it can show cert
  expiry even when the main session is cleartext or the cert is untrusted. `doctor --json`
  emits one object (hand-rolled, dependency-free) covering connect/role/auth/tls/cert/
  clock/capabilities/credentials; `doctor` (human) additionally runs the local-credential
  diagnosis and will exit nonzero on a stray expired proxy/token even for an anon endpoint.

`doctor` also runs a **functional method battery** per endpoint (`--rw` for the write
cycle, `--also <url>` for extra protocol faces), reported in the `tests` array of the
JSON. A few things to know:

- **`--rw` mutates the namespace under a temp dir** (`/.xrd_doctor_<pid>` for root://,
  `/.xrd_doctor_<pid>/` collection for WebDAV, `/.xrd_doctor_<pid>.bin` object for S3)
  and cleans up after itself. It is **off by default** precisely because it writes; the
  read-only battery (stat/dirlist/statvfs/query/path-confinement) always runs.
- **`rm`/delete operate on the final component itself (POSIX unlink semantics).** The
  existence gate (`op_path_existence_gate`) and the delete probe (`brix_ns_delete`)
  both use **lstat**, not stat, so a symlink — including a dangling one — is removed as
  the link, never dereferenced (a regression of an earlier bug where `rm <symlink>`
  followed the link's stored absolute target, hit `RESOLVE_BENEATH`, and returned
  `NotFound`, leaving the link un-removable). The confined `*_beneath` unlink remains the
  security boundary; lstat in the ACL/logging gate weakens nothing. The doctor `--rw`
  battery still carries a defensive `rmdir` SKIP path for servers that genuinely cannot
  unlink symlinks, but this module passes the full `symlink+readlink` (create/readlink/
  unlink) and `rmdir` cycle.
- **`checksum-verify` compares server vs locally-computed adler32** of the exact bytes
  written (via a host tmpfile), so it catches silent corruption, not just "a checksum
  came back".
- **WebDAV/S3 batteries reuse the transfer primitives.** WebDAV drives `xrdc_http_req`
  + `xrdc_http_upload`/`download` (any method, TLS via the scheme); S3 signs each
  PUT/GET/DELETE with `xrdc_s3_sign_v4` and streams the body. A cleartext request to a
  TLS-only WebDAV port returns **HTTP 400** — this is nginx's standard "The plain HTTP
  request was sent to HTTPS port" `error_page`, a property of nginx's TLS-terminating
  listener, *not* the XRootD module. It does **not** match vanilla XRootD: stock
  `XrdHttp` on a TLS port rejects cleartext at the TLS handshake (the connection is
  reset / errors out with no HTTP response at all). The nginx 400 is benign and
  arguably friendlier — a readable diagnosis instead of a bare connection drop — and
  per build governance we do not patch nginx core to change it. Either way, use
  `https://`/`davs://` (not `http://`) for a TLS endpoint.
- **`--insecure` is for the probes only.** It disables TLS chain/host verification so
  doctor can test a self-signed/expired endpoint; it never relaxes verification for a
  real data transfer path.

## Related docs

- [protocol-notes.md](protocol-notes.md) - low-level wire quirks
- [xrdcp-interactions.md](../04-protocols/xrootd-client-interaction.md) - end-to-end client flow
- [optimizations.md](../09-developer-guide/optimizations.md) - performance-driven implementation choices
- [tls.md](../03-configuration/tls-config.md) - auth and transport layering
- [development.md](../09-developer-guide/dev-workflow.md) - source layout and workflow
- [webdav.md](../04-protocols/webdav-overview.md) - WebDAV RFC compliance and method reference
- [comparison-with-xrootd.md](design-rationale.md) - where design compromises affect deployment choices
