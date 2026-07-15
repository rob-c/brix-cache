# History — Native Client Tooling (xrdcp/xrdfs/FUSE/CVMFS), Decisions & Lessons

**Date:** 2026-07-15
**Status:** Living history — covers the native client program from its phase-37
clean-room origin (2026-06-15) through the phase-69 client concept-bucket
reorg (2026-07-04) and the brix Mount Platform (CVMFS, phase-68, landed
2026-07-04).
**Scope:** `client/` (native `xrdcp`/`xrdfs`/`xrd` busybox/`xrddiag`/`xrootdfs`
FUSE drivers/`libxrdc`), the shared `shared/cvmfs/` core and `brixMount`
platform, GSI interop with real XRootD/EOS, conformance vs stock `xrd*`, and
the resilience/UX/mount-speed work layered on top.

**Related:**
[../refactor/phase-37-native-xrdcp-xrdfs-clients.md](../refactor/phase-37-native-xrdcp-xrdfs-clients.md) ·
[../refactor/phase-37-swiss-army-plan.md](../refactor/phase-37-swiss-army-plan.md) ·
[../refactor/phase-37-clean-room-log.md](../refactor/phase-37-clean-room-log.md) ·
[../refactor/phase-41-xrd-busybox-posix.md](../refactor/phase-41-xrd-busybox-posix.md) ·
[../refactor/phase-48-native-client-xrdsecgsi-interop.md](../refactor/phase-48-native-client-xrdsecgsi-interop.md) ·
[../refactor/phase-49-client-code-sharing.md](../refactor/phase-49-client-code-sharing.md) ·
[../refactor/phase-68-cvmfs-site-cache.md](../refactor/phase-68-cvmfs-site-cache.md) ·
[../refactor/phase-69-client-map.tsv](../refactor/phase-69-client-map.tsv) ·
[fuse-async-resilient-driver.md](fuse-async-resilient-driver.md) ·
[xrdsecgsi-handshake.md](xrdsecgsi-handshake.md) ·
[../06-authentication/gsi-interop-eos-dcache.md](../06-authentication/gsi-interop-eos-dcache.md) ·
[lessons-migration-era-2026.md](lessons-migration-era-2026.md)

This document does not re-derive what the phase docs above already cover
(milestones, wire-format tables, per-phase task lists). It is the narrative
this project's memory accumulated around them: *why* the client program
exists in the shape it does, the concrete bugs it surfaced (in both our code
and third-party consumers), the decisions Rob made and the tradeoffs behind
them, and the gotchas that cost real debugging time.

---

## 0. The North Star: "swiss army knife" clients

Set 2026-06-15, still the standing directive for all client work
(`swiss_army_toolkit_vision`): grow the native clients (`xrdcp`/`xrdfs`/
`xrddiag`/`xrd`/`libxrdc`) to do everything official XRootD clients do, plus
more, for anyone scripting WLCG storage — with two hard constraints that
never relax:

1. **Compatibility is additive, never destructive** — keep official-client
   documented behavior/flags; new features are additions, not replacements.
2. **Stay clean-room.** `client/` links only `libxrdproto` + OpenSSL — no
   `libXrdCl`/`libXrdSec*`, no `goto`, no stubs. Every wire fact is
   independently verified against the spec or a real server, never copied
   from XrdCl/XrdApps source (enforced procedurally — see
   `phase-37-clean-room-log.md`).

All 7 originally-scoped protocol gaps (kXR_readv/writev, recursive copy, SRR
consumer, FRM tape-REST, s3/davs/http production transfer, async-TPC) closed
2026-06-15. Deliberately out of scope forever: cmsd S2S, SciTags firefly UDP,
traffic mirroring — these are server-internal protocols a client never
speaks. A real bug found along the way, distinct from the later EOS
capability-truncation fix in §6: `parse_redirect` (`lib/frame.c`) used to
drop the redirect's `?opaque` tail entirely — WLCG redirectors put a
data-node token or a fresh `&P=` there, so losing it broke reconnect;
fixed to capture and prefer the opaque tail on every redirect.

The vision document also records a **grounded-but-not-yet-built reframe**
(`swiss_army_toolkit_vision`) worth carrying forward: collapse today's ~9
ad-hoc client features behind a connect-time **capability engine** (one
batched `kXR_Qconfig` probe, cached, fail-open) and a **just-works auth
engine** (unify the 7 credential-discovery orders, `~/.xrdrc` profiles,
server-driven negotiation). Table-stakes items still unplanned as of
2026-07-15: OIDC device-flow token acquisition, RFC-8693 token-exchange for
TPC delegation, VOMS-FQAN selection, krb5 lifecycle, S3 STS/presigned/vhost.

---

## 1. Chronology

| When | Milestone | Doc |
|---|---|---|
| 2026-06-15 | Phase-37 clean-room `xrdcp`/`xrdfs` M0–M10 landed; 7 protocol gaps closed | phase-37-native-xrdcp-xrdfs-clients.md |
| 2026-06-15 | `xrootdfs_legacy.c` FUSE driver taken to production (pool/MT, random write, statfs/xattr) | this doc §3; xrootdfs_production |
| 2026-06-15 | Client robustness/UX overhaul: pre-flight diagnostics, atomic/cancellable transfers, auto-refresh | this doc §5 |
| 2026-06-21 | Async/resilient FUSE rewrite (epoll, RTT-adaptive, mid-transfer resume) | fuse-async-resilient-driver.md |
| 2026-06-21 | Firewall/loss resilience hardening + GSI xcache-in-front-of-EOS build | this doc §4, §6 |
| 2026-06-21 | IPv6→IPv4 sticky auto-downgrade | this doc §4 |
| 2026-06-21 | HTTP(S)/WebDAV transport unified into `xrootdfs` (single multi-call binary) | fuse-async-resilient-driver.md; phase-49 |
| 2026-06-22 | Native GSI ported to real `XrdSecgsi` wire compat; proven vs `root://eoslhcb.cern.ch` | phase-48-native-client-xrdsecgsi-interop.md |
| 2026-06-22 | `client-fast-fail-permanent-errors`: kill 15–30s hangs on permanent faults | this doc §7 |
| 2026-06-22 | `xrdfs` CLI network-resilience gap closed (parity with `xrootdfs`) | this doc §7 |
| 2026-06-21/26 | Phase-49 client code-sharing (headline workstreams W0/W1/W2/W4-FUSE) | phase-49-client-code-sharing.md |
| 2026-06-26 | ~1006-test clientconf differential-conformance suite vs stock `xrd*`; real divergences found+fixed | this doc §8 |
| 2026-06-26 | Credential/temp-file hardening (symlink/owner/perm-safe helpers) | this doc §9 |
| 2026-06-27 | Mount-speed optimization (parallel/lazy streams) | this doc §10 |
| 2026-06-29 | Client-side VFS seam closure (`client/lib/vfs.h`) | this doc §11 |
| 2026-07-02 | CVMFS Docker demo container landed | this doc §12 |
| 2026-07-04 | brix Mount Platform (`brixMount`, CVMFS-brix + XRootDFS-brix + shared `shared/cvmfs/` core) — all 7 sub-projects landed | phase-68-cvmfs-site-cache.md |
| 2026-07-04 | `client/` flat→concept-bucket reorg (phase-69) | phase-69-client-map.tsv |
| 2026-07-06 | Client feature-gap program (20 tasks, ~36 commits) landed on main | this doc §13 |
| 2026-07-15 | Correction: `phase37_native_clients`' "host load, not code" verdicts retracted — the load *was* an uninitialized-timer crash loop | `host_load_excuse_debunked` |

---

## 2. Why "clean room," and what it cost

The build-in-place decision (one source tree, compiled twice — into
`shared/xrdproto/libxrdproto.a` for the module and into `client/` for the
CLIs, `-DXRDPROTO_NO_NGX`, `check-ngx-free.sh` CI-gated) was Rob's explicit
choice over physically relocating shared files: **one source of truth**, no
drift between two copies of crc32c/hex/crypto/error_mapping/gsi_core/
checksum_core.

The cost of clean-room was accepted up front and stayed true throughout:
native TPC only speaks the SHM-registry sync-arm protocol, not real XrdCl's
async-TPC (`kXR_waitresp`/`kXR_attn`) — two ref-xrootd `--tpc only` tests fail
by design, not by bug. Streaming `davs`/`s3` production transfer in `xrdcp`
stayed a diagnostic-only capability for a long stretch (`xrdc_http_req` was
8MiB-capped, no streaming lib) — documented as deferred rather than silently
broken, and closed later in the feature-gap program (§13).

---

## 3. Two FUSE drivers, kept on purpose

`xrootdfs` shipped as **one multi-call binary** (`apps/xrootdfs_main.c`)
dispatching to two internal drivers:

- **async (default, since the 2026-06-21 rewrite)** — epoll loop, one
  `aconn` per open file, RTT-adaptive deadlines, worker-thread reconnect,
  transparent mid-transfer resume. Headline proof: a mid-4MiB `cat`/`dd`
  survives a server restart with 0 EIO and byte-exact data both directions.
- **legacy (`--legacy`, opt-in)** — pool-based, one dedicated connection per
  open file plus a shared metadata pool; taken to production earlier
  (2026-06-15) with random-write, statfs/readdir-plus/xattr, kernel-side
  caching.

Rob's call: **both stay shipped**, not a hard cutover — `xrootdfs_production`,
`xrootdfs_async_rewrite`. Phase-49 later found ~485 LoC of genuine stat/
statfs/xattr/buffering duplication between the two and extracted a shared
op-runner/read-ahead engine, but *deliberately did not* collapse the two
`fuse_operations` tables into one: the async and legacy drivers are
intentionally different systems (simple-and-fast vs. resilient+web+srv_path),
and the shared thunks capture the real duplication without erasing that
distinction.

Concurrency model, and why the pool exists at all: an `xrdc_conn` is
one-request-in-flight and not thread-safe, and an XRootD fhandle is only
valid on the connection that opened it — hence dedicated per-file connections
plus a separate metadata pool.

Honestly-documented, still-true gaps: `utimens`/`chown` are success no-ops
(XRootD has no set-mtime/chown wire op — `cp -p` "works" but doesn't
persist); `XATTR_REPLACE` isn't enforced. `symlink`/`readlink`/`link` were
added later via wire vendor extensions in the async rewrite.

Two gotchas from the async rewrite worth remembering if touching the
connection-attach path:
- A GSI request-signing connection is **rejected** by the async attach path
  and falls back to the sync pool; anon/ZTN/unix pipeline is unaffected.
- The TLS path has no `MSG_NOSIGNAL` equivalent — apps must
  `signal(SIGPIPE, SIG_IGN)` themselves; the sync client had never needed to,
  the async rewrite just exposed the latent bug.

Per-op Prometheus counters for the new vendor wire ops were attempted, then
**reverted** — they hit a pre-existing per-connection metrics-slot quirk
(single ops on a round-robin pooled connection aren't reliably attributable)
unrelated to the rewrite; existing CHMOD/MKDIR/STAT slots were reused
instead rather than chasing that quirk mid-rewrite.

Three real bugs surfaced while building the HTTP(S)/WebDAV transport into
`xrootdfs` (`fuse_http_transport`): `afh_pread`'s `root://` branch called
itself — infinite tail-recursion that `-O3` compiled into a literal spin,
wedging every `root://` FUSE read; the buffered HTTP path read to EOF while
XrdHttp sends `Connection: Close` but keeps the TLS socket open, hanging
every metadata request until the 30s timeout (fixed by framing on
Content-Length/chunked instead); and `root://` mounts ignored the URL path
base, breaking against official `xrootd` (which only exports `/data`, unlike
nginx which exports the whole dir). Separately, chained pattern rules in
`client/Makefile` let GNU make auto-delete intermediate `.o` files after
`make all`; a later incremental `make <tool>` invocation (e.g. a pytest
fixture) would then relink and, if that shell's pkg-config couldn't see the
codec libs, silently fail and delete the binary — fixed with `.SECONDARY:`.

---

## 4. Hardening against a hostile network

Client-side network resilience was built in three overlapping efforts, all
2026-06-21/22, all funneling through the **same chokepoints** so every tool
inherits the fix (a recurring architectural choice, see §7 for the
generalization to `xrdfs`):

**Firewall/loss resilience** (`client_firewall_resilience`) — bounded
bring-up (`nettmo.c`, a 15s process-wide connect timeout covering
handshake/TLS/login only, then restoring the normal 30s I/O timeout);
fire-and-forget `kXR_endsess` teardown (was blocking on reply — a second full
timeout on a black-holed connection — now capped at 2000ms and skipped when
`sessid` is zero); backoff+jitter on metadata retries. Verified against real
`xrootd` 5.9.5 through a fault-injection proxy: fixed a spurious-EIO (`mfile`
gave up after 11 fast tries, now deadline-bounded) and tuned backoff to
survive 12% packet loss. `xrdcp` download hardening added reconnect+reopen-
at-offset with **adaptive read-size halving down to a 256KB floor** — an 8MB
`kXR_read` spans ~128 proxy segments, so shrinking the read unit is the
actual lever; result was byte-exact transfers at 0–15% loss where official
`xrdcp` fails above 5%.

**IPv6→IPv4 sticky auto-downgrade** (`client_ipv6_v4_downgrade`) — one
chokepoint, `xrdc_tcp_connect` (`client/lib/sock.c`), carries a process-wide
sticky "demoted" state (`client/lib/netpref.c`, relaxed atomics). Two
triggers, both funneled through the same module: connect-time (an AF_INET
candidate succeeds after an AF_INET6 candidate fails) and **wire-error**
(an established IPv6 connection breaks mid-session — reset/timeout/truncated
read — demotes immediately, so reconnect skips v6 entirely and pays no v6
timeout). Rob asked for the wire-error trigger explicitly, three times,
before it was added — the connect-time trigger alone wasn't enough because a
connection can go bad *after* a successful v6 handshake. Self-heal is the
safety net: if an all-v4 retry fails, the demotion is undone and the next
attempt goes back to `AF_UNSPEC`, so an IPv6-only host that briefly tripped
the wire-error trigger is never stranded. Opt-out: `XRDC_NO_IPV6_FALLBACK=1`.

This effort also produced a **standing documentation convention**: every
env var unique to this project's native clients (not present in vanilla
XRootD) must be marked "(EXPANDED)" in user-facing docs, so operators don't
carry it to upstream XRootD by habit. Consolidated in
`docs/04-protocols/native-client-tools.md` "Environment Variables" and each
man page's `ENVIRONMENT` section.

**Permanent-vs-retryable classification** — see §7, the general principle
that came out of debugging the above.

---

## 5. Robustness + UX overhaul (2026-06-15)

Rob's three-part ask: (a) instant, specific auth errors instead of a generic
"permission denied"; (b) auto-get/refresh of tokens and proxies; (c) general
robustness. Rob's own sequencing decision was **c → a → b**, and — critically
— (c) is **client-side pre-flight only, with zero server changes**, to avoid
any server-side auth information leak.

- **(c) pre-flight** — `xrdc_cred_diagnose()` checks locally for
  expired/near-expiry tokens, read-only-token-on-write, expired/near GSI
  proxies; `xrdc_cred_hint_for_status()` fires only on
  `kXR_NotAuthorized`/`kXR_AuthFailed` so it never invents false positives.
- **(a) robustness** — atomic temp+rename for downloads (mirrors the existing
  web-GET pattern, never leaves a partial final file); cooperative
  SIGINT/SIGTERM cancel polled inside the socket/TLS poll loops so it's
  prompt even against a stalled peer; a **tri-state checksum result**
  (OK/MISMATCH/UNVERIFIED) so a transient `Qcksum` query failure no longer
  deletes a byte-perfect download — only a genuine mismatch does; dead-
  redirect fallback to the home manager. Adversarial review caught a real
  bug before ship: the download temp-file name was PID-keyed, which collided
  under `-j` (threads share a PID) and silently corrupted concurrent
  transfers — fixed with an atomic-sequence unique name generator.
- **(b) auto-refresh** — opt-in (`--auto-refresh`), fail-soft (never aborts
  the transfer on a failed refresh): forks `oidc-token <account>` for bearer
  tokens, calls the existing `xrdc_proxy_create()` primitive for a stale GSI
  proxy.

The code carries a `Phase 40 (a)/(b)/(c)` tag that **collides in name only**
with the unrelated server-side impersonation work (also tagged "Phase 40") —
noted so nobody conflates the two when grepping.

---

## 6. GSI: from stub to real interop, then into a production pattern

Native GSI started as a stub that only spoke to this project's own
non-standard server. The 2026-06-22 port made it speak real `XrdSecgsi` wire
compatibility (unsigned-DH, protocol version 10300) — proven live against
`root://eoslhcb.cern.ch` with a real VOMS proxy. Full protocol detail lives
in `phase-48-native-client-xrdsecgsi-interop.md` and
`xrdsecgsi-handshake.md`; kept here are the facts worth re-checking before
touching this code again:

- **Shared kernel, not two implementations.** `src/gsi/gsi_core.c` (ngx-free)
  implements the round-2 cert-response for both the native client
  (`client/lib/sec/sec_gsi.c`) and the server's outbound TPC GSI
  (`src/tpc/gsi_outbound_exchange.c`) — deliberately one implementation so
  they can't drift.
- **Two EOS-specific fixes**, still relevant, verify before assuming fixed:
  (1) EOS's open-redirect capability opaque is long — `parse_redirect` must
  split host vs. opaque *in place*; an old 256-byte host buffer used to
  truncate it, causing an endless manager↔DS redirect loop
  ("capability illegal"). (2) EOS's checksum-query format is
  `<path>?cks.type=<algo>`, not this project's legacy `"<algo> <path>"` — the
  server's own `Qcksum` now parses both for back-compat.
- **Wire facts worth keeping**: v10300 selects the unsigned-DH path (no
  RSA-signed cipher bucket); `HasPad=0`/`useIV=0` for protocol <10400 (else
  "error decrypting main buffer" — a garbage-but-padding-valid decrypt, a
  nasty false lead); the main buffer is length-delimited with no `kXRS_none`
  terminator; proof-of-possession = sign the server's cleartext `rtag` with
  the proxy's *private* key (`EVP_PKEY_sign`, PKCS1 padding, no digest hash
  applied); the session AES-128 key is the first 16 bytes of the DH secret.
- **A latent server-side bug found and fixed as part of this unification**:
  `src/gsi/cert_response.c` used to emit a bare `kXRS_puk` (no PEM DH
  params) instead of the standard `kXRS_cipher` — real stock `xrdcp`/
  `xrootd` couldn't GSI to this server until that was fixed.

**Production pattern that came out of interop with EOS**: a GSI-enabled
xcache in front of `root://eoslhcb.cern.ch`
(`gsi_xcache_eos`, 2026-06-21, four phases, all verified live). Because the
module's built-in origin client only speaks anonymous `kXR_login` (EOS
rejects that), the pattern used is **PSS-via-native-client**: `posix_spawn`
the built native `client/bin/xrdcp`/`xrdfs` with `X509_USER_PROXY`/
`X509_CERT_DIR` overridden in the child's environment, rather than linking
the native client in (which would duplicate shared-kernel symbols). This
covers read-fetch, namespace forward (dirlist/stat), GSI/VOMS trust
(including making `xrootd_trusted_ca` accept a *directory*, not just a file,
so real grid CA-path chains verify), and write-through.

This same effort found a **real silent-data-loss bug**, unrelated to GSI
itself: `src/read/close.c` discarded the return value of the write-through
flush on close, so a failed synchronous write-through still returned
`kXR_ok` — the client believed a write reached the origin when it hadn't.
Fixed by making the flush helper a pure status function and having every
caller (close.c, write/sync.c) send the single `kXR_error` itself on
failure, mirroring the existing POSC-rename convention. General handler rule
reaffirmed here: return the `send_*` result (`NGX_OK`) after queueing a
response; `NGX_ERROR` is connection-fatal, never return it after a response
is already queued.

Also documented as an **EOS-side finding, not our bug**: the test lhcb proxy
has read-only ACLs on its home directory tree; both this project's
write-through and stock `/usr/bin/xrdcp` are denied identically.

---

## 7. Resilience as a client-wide seam, not per-tool patches

Two related findings drove this section, both worth internalizing as a
pattern for any future client fault-handling work.

**Permanent vs. retryable classification** (`client_fast_fail_permanent_errors`,
2026-06-22). The resilient retry wrapper (`resilient.c`, gated on
`xrdc_status_retryable()`) retried any `ESOCK`/`EPROTO` fault within a stall
window — but several *permanent* failures were mistagged as one of those two
codes, so the client spun 15–30s before giving up, surfacing as flaky test
timeouts. Three concrete fixes: DNS `NXDOMAIN`/no-address now maps to a new
non-retryable `XRDC_ERESOLVE` (only `EAI_AGAIN` stays retryable) — cut a
30s hang to 1s; redirect loops now use `XRDC_EREDIRECT` instead of the
retryable `XRDC_EPROTO`, plus an explicit self-redirect check before any
reconnect — cut a 15s hang to instant; a handshake rejection (e.g. sending
`kXR_wantTLS` to a cleartext port) now propagates the server's real `kXR`
status code instead of a blanket retryable `EPROTO` — cut a 30s hang to 5ms.
**Rule of thumb that generalizes**: a failure that a byte-identical retry to
the same endpoint cannot possibly change is permanent — give it a status
code outside `xrdc_status_retryable()`'s set, and remember to add the new
code to `xrdc_shellcode()` too. The phase-49 code-sharing pass found the same
class of bug from the other direction: `xrdcp` against a refused endpoint
hung ~60s per retry because non-blocking `connect_one()` never pulled the
real error off `SO_ERROR`, so the failed connect looked retryable when it
wasn't — fixed to read `SO_ERROR` and fail immediately, cutting a dead-port
retry from ~60s to ~0.5s. The same program later found integrity
failures deserve the identical treatment: pgread/pgwrite CRC32c mismatches
were retried for ~60s as `EPROTO` before someone noticed a corrupt page
can't become correct by re-reading it — a new non-retryable `XRDC_EINTEGRITY`
now covers page CRC, header CRC, `--cksum` mismatch, and pgwrite server
rejection uniformly. **Principle: integrity failures are never retryable.**

**`xrdfs` CLI resilience gap** (`xrdfs_cli_resilience_gap`, found 2026-06-22).
The synchronous `xrdfs` CLI was *not* network-resilient at all, unlike the
`xrootdfs` FUSE driver — a single connection and a no-retry read loop meant
the first mid-transfer sever produced `rc=51 connection closed by peer`. All
the resilience primitives already existed in `libxrdc` (`xrdc_mgr_create`,
`xrdc_mfile_pread/pwrite`, `xrdc_reconnect`) — this was a pure app-level
wiring gap, not a missing capability. Fixed by building a **centralized
resilience seam** rather than per-command loops: new `client/lib/resilient.c`
(`xrdc_rfile_*` for streaming reopen+resume, `xrdc_with_resilience` as a
generic op-wrapper, idempotency classes READONLY/IDEMPOTENT/
MUTATION_NORMALIZE/UNSAFE with benign-errno normalization for reissued
mutations — e.g. `mkdir` EEXIST, `rm`/`rmdir`/`mv` ENOENT). Default ON, 30s
window (`XRDC_MAX_STALL_MS`, 0 disables). Rolled out to every `xrdfs`
subcommand (cat/head/tail/wc/grep/hexdump/dd/download/upload/slurp), the
preload shim, `xrootdfs_legacy`'s per-handle I/O, and checksum queries.
**Key catch**: even with every *operation* resilient, the *initial GSI
handshake* is itself loss-fragile (multi-RTT) — a dedicated
`xrdc_connect_resilient` had to be added and wired into every tool's connect
path, or tools still failed at bring-up under loss despite resilient ops.
Deliberately left non-resilient: `xrddiag`'s connects (a diagnostic tool
must surface faults, not mask them — `--no-retry` available everywhere as an
escape hatch) and the loopback-only metrics `xrdc_http_get`.

---

## 8. Conformance: proving parity, and what it found

The ~1006-test differential-conformance suite (`clientconf_suite`, built
2026-06-26, `tests/clientconf` + `test_clientconf_*.py`) proves the
reimplemented clients match stock `/usr/bin/xrd*` behavior, with an explicit
knob: off = strict differential parity, on = behavioral + bytes-invariant,
and any *unregistered* difference is a failure (deliberate divergences must
be enumerated, not silently tolerated). Because this project's `xrdcp`/
`xrdfs` use their own CLI flag vocabulary rather than stock's long-opt names,
"surface conformance" is implemented as an explicit flag map
(`surface_map.yaml`), not name identity.

Real divergences found and fixed in one pass (2026-06-26):

1. Stock `xrdcrc32c` cannot checksum any `root://` URL at all — it's a
   strictly-local tool with no `libXrdCl` linkage. Not a bug on either side;
   it just can't serve as a remote-checksum oracle.
2. Checksum-tool missing-file exit codes didn't match stock's *per-tool*
   codes (`xrdadler32`=1, `xrdcrc32c`=3, `xrdcrc64`=1) — fixed to match
   instead of using a uniform XrdCl-style shell code.
3. `xrdgsiproxy info` on a missing proxy: retagged from a USAGE error to
   ENOENT (rc=1 + message) to match stock. Kept one deliberate divergence:
   this project's `info` still honors `X509_USER_PROXY` where stock's
   ignores it — documented as a stock quirk, not something worth copying.
4. `xrdcp -r` had **three separate bugs**: (a) recursive copy flattened
   output instead of nesting under the source basename; (b) a real **remote
   DoS** — opening a FIFO or socket found inside an export with plain
   `O_RDONLY` (no `O_NONBLOCK`) wedged the single-threaded worker forever
   (fixed in `src/path/beneath.c`/`src/read/open_resolved_file.c` — note
   the fix is *not* `O_PATH|O_NONBLOCK`, which `openat2` rejects with
   EINVAL); (c) recursive download of an in-export symlink truncated to the
   `lstat` link-target length instead of the real served size (`kXR_other`
   entries now use `expected=-1`, EOF-driven, instead of trusting the link
   length).

Regression coverage for the DoS specifically: `tests/test_deep_tree_special_files.py`
(10 tests). Run the suite serially — `-n auto` xdist load drops ports
11094–11097 under rapid-connection pressure and the master goes bad-state.

---

## 9. Credential and temp-file hardening

A 2026-06-26 security audit of `client/` (`client_credfile_hardening`) found
a class of insecure credential/temp-file reads and replaced them with three
shared, symlink/owner/perm-safe helpers that any future credential or
download-temp code must use:

- `xrdc_open_credfile(path, secret, st)` — `O_NOFOLLOW|O_CLOEXEC`, requires
  a regular file owned by the euid, always rejects group/other write;
  `secret=1` (private keys, GSI proxies) additionally rejects group/other
  read, i.e. enforces 0600.
- `xrdc_credfile_bio(path, secret)` — same checks, returns an OpenSSL BIO.
- `open_download_temp(dst, tmp, sz, st)` — `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`
  with EEXIST retry, replacing a previous `O_CREAT|O_TRUNC` on a
  predictable `<dst>.xrdcp-tmp.<pid>.<seq>` name that an attacker could
  symlink-clobber ahead of time.

The two concrete vulnerabilities found: `/tmp/bt_u<uid>` (bearer token) and
`/tmp/x509up_u<uid>` (GSI proxy+key) were read via plain `fopen`/
`BIO_new_file`, letting an attacker who can write to `/tmp` pre-plant a
symlink (secret exfiltration) or an owned file (confused-deputy). The
existing `xrdc_sss_keytab_read` was already doing this correctly and served
as the template. Also swept in the same pass: `url.c` `strcpy`→`memcpy` at 4
call sites that were length-guarded but fragile.

---

## 10. Mount-speed: measure before optimizing

2026-06-27 goal: get `xrootdfs` mount and `xrdfs` invocation "as close to
0ms as possible." The diagnosis (via `strace` against localhost) mattered
more than the fix — process/loader overhead (24 shared libs) was cheap
(~140µs); the real cost was **serial connection setup**: `xrootdfs` opened
five serial connections plus handshake/auth (pool slot0 + a 4-stream
`xrdc_mgr_create` loop, one at a time, plus a config probe) before
returning. On a remote GSI server at ~30ms RTT with multi-round auth, that's
0.5–1.5s of pure serialization tax.

Fix: `xrdc_mgr_create` gained an `eager` parameter — eager streams connect
**in parallel** via short-lived worker threads (joined before return, never
crossing the FUSE `-f`/daemonize fork boundary); slots beyond `eager` are
lazy, connected on first pick under a double-checked lock. Rob's explicit
choice: **parallel-eager by default**, with `--lazy-streams` as opt-in
(1 stream at mount, the rest on first I/O) rather than lazy-by-default.
Secondary micro-wins: `AI_NUMERICSERV|AI_ADDRCONFIG` on getaddrinfo (skips
`/etc/services` and dead AAAA lookups on v4-only), preferring `$LOGNAME`/
`$USER` over a `getpwuid` NSS round-trip for the (informational-only)
username. One correctness fix required for the parallelism to be safe: GSI's
`g_client_rtag` was a file-static that was write-only (never read back) —
harmless when connections were serial, but parallel GSI connects would have
clobbered each other's rtag; moved to a stack-local.

Result: connection count 5→2 under default eager settings, 9→2 under
`--lazy-streams`; not measured on a real high-RTT link (no passwordless
`sudo` for `tc netem` in this environment) but the win is deterministic from
connection-count × RTT, not an estimate.

Two pre-existing issues surfaced but explicitly *not* attributed to this
work: 4 write-roundtrip tests fail because the server stages writes — after
`OPEN wr` succeeds the file exists on disk, but `kXR_stat` on the final path
returns ENOENT until CLOSE commits, so FUSE's getattr-after-create sees
ENOENT (reproduces identically on the legacy driver; likely the same
staging-visibility class as the upload_resume/`.part` work — flagged as
worth a dedicated look, not fixed here).

---

## 11. Client-side VFS seam

The server's `src/` VFS seam closure (invariant #12 in CLAUDE.md — raw data
syscalls confined to `src/fs/backend/`) has a client-side counterpart: the
client has its own VFS (`client/lib/vfs.h` → `vfs_posix`/`vfs_block`/`vfs_s3`)
whose byte I/O dispatches through the *same* shared storage-driver code path
as the server. 2026-06-29 extended the seam audit and guard
(`tools/ci/check_vfs_seam.sh`) to cover `client/`, migrating the two
remaining raw-I/O call sites: `copy_web_upload` (HTTP/DAV upload source was
a raw local `open`/`fstat`; changed the upload transport itself to pull from
a callback source rather than an fd, so both VFS and non-VFS callers — e.g.
the anonymous-tmpfile diagnostic in `xrd_battery.c` — can supply their own
source without re-plumbing) and `xrdfs upload`/`download` (local endpoint
now opens via the client VFS, with atomic temp+rename commit on download;
the `-` stdin/stdout pipe branches stay raw by design). The guard was seeded
with 3 grandfathered files that have no VFS seam to migrate onto yet
(`cks_verify.c` — the client VFS vtable has no xattr/read-by-name op;
`copy_zip.c`/`zip_write.c` — local ZIP-archive assembly).

---

## 12. CVMFS: from a Docker demo to a production-grade native client

Two threads converged into the brix Mount Platform.

**The demo** (`cvmfs_docker_demo`, landed 2026-07-02, commit `860a7f8`): a
single CentOS Stream 9 container running a real CVMFS forward-proxy cache
(Stratum-1 allowlist, CAS verify, never-drop) plus a dashboard, Prometheus,
and in-container fail2ban — smoke-tested against the real
`cvmfs-stratum-one.cern.ch`, including a real nftables ban blocking a
client. Notable gotchas for anyone touching that container again: `crb`
must be enabled on EL9 before `jansson-devel` is installable; the base
image's `libcurl-minimal` must *not* be upgraded to full `libcurl` (link
conflict, and the module links fine against minimal); `pblock`'s catalog
code needed a proper sqlite feature-gate (a no-sqlite build was silently
broken until fixed); the fail2ban polling backend lags real log writes by
~5s, so tests must poll ban status rather than sleep a fixed interval; WSL2
kernels can lack nftables modules, so the entrypoint probes and falls back
to a dummy ban action.

**The client** (`cvmfs_brix_client_plan`, phase-68, landed): a native
read-only CVMFS FUSE client (CVMFS-brix), unified under one entrypoint,
`brixMount <type> <endpoint> <mountdir>` (`cvmfs`/`eos`/`root`/`roots`),
built on a shared pure-C `shared/cvmfs/` core (grammar, failover, CAS-cache,
fetch, catalog, client config) that is reused unmodified by the server's own
`cvmfs://` proxy ring — one implementation of the CVMFS wire/crypto layer
serving both a client and a server component. All 7 sub-projects (A–G) plus
TTL refresh, magic xattrs, `--check`, a clever overlay cache, environment-
proxy pickup, and sticky-geo failover landed, gated by a 15/15 test suite
(9 unit + 6 live mounts against real `atlas.cern.ch`/`cms.cern.ch`/
`lhcb.cern.ch`).

Crypto/wire gotchas worth keeping if this code is touched again: the
manifest signature is RSA-PKCS1-SHA1, but the whitelist signature is *raw*
RSA-PKCS1 with no DigestInfo wrapper — verification must try both forms;
object hashes are SHA1 of the *compressed* bytes, never the decompressed
content; whitelist expiry is encoded in the `E<14digits>` line, not
necessarily line 0; and OpenSSL 3.0.18 blocks SHA-1 via the standard EVP
digest-sign path, so verification does SHA-1 by hand and calls
`EVP_PKEY_verify` directly with `RSA_PKCS1_PADDING` (never `EVP_PKEY_CTX_set_signature_md`).

Real-fault-proxy benchmarking against stock `cvmfs2` found this client
**more resilient to connection loss/resets** (survives roughly 5x atlas's
sever rate after HTTP range-resume was added) and roughly **equivalent under
reordering**, while stock `cvmfs2` remains ~2x faster on a clean network —
an honest, not universally-favorable, result.

A deliberate scope decision: server-side dedup of this failover engine with
the server's existing async thread-pool RTT probe was considered and
rejected — the two use different models and the marginal dedup wasn't worth
rearchitecting working code.

---

## 13. Client feature-gap program (2026-07-06)

The last major client push before this document's cutoff closed the
remaining user-facing gaps a WLCG operator migrating from `rclone`/`gfal`
would hit (plan `docs/superpowers/plans/2026-07-05-client-feature-gaps.md`,
~36 commits, every task independently reviewed, whole-branch review reaching
READY-TO-MERGE after one fix wave). Shipped: `xrdcp --dry-run --exclude
--include --sync-check size|mtime|cksum --delete --remove-source
--journal/--resume`; `xrdfs rm -r`, `--json` output for stat/ls/du, `cat -z`,
resilient `tail -f`, `--io-uring`; `xrdcksum tree`/`check --algo`
(hostile-manifest-safe); `xrddiag`/topology `--json` plus `.xrdcap`
truncation hardening; a `~/.xrdrc` config file (CLI > env > xrdrc > default,
6 resolvers); 9 man pages plus man7 install; bash completion.

Gotchas worth remembering for future client CLI work:

- `xrdfs`'s one-shot mode **connects before dispatch** — even a pure
  client-side validation error (bad flags, exit 50) needs a live server to
  reach the point where that validation runs, so e2e checks for usage errors
  must still be fleet-gated.
- `brix_rfile_close` does **not** poison the struct — a second close on an
  already-closed handle re-sends the stale file handle over the wire (a wire
  error, not a crash). Any new close path needs its own
  closed-exactly-once flag, following `tail_follow`'s pattern.
- **Flag-interaction blind spot**: `--delete` and `--remove-source` combined
  destroyed *both* trees (mirror semantics collided with move semantics) —
  each flag's own task review couldn't see this because it only reviewed its
  own flag. Now explicitly rejected (exit 50). Lesson for any plan adding
  multiple flags to the same code path: add an interaction-matrix review
  step, don't rely on per-task review alone.
- Concurrent same-session commits to `main` mean a review package's base
  commit must be the change's *true parent*, never "HEAD before dispatch
  started" — one implementer accidentally swept another session's untracked
  WIP into a commit this way (harmless in that instance, but misattributed).

---

## 14. Third-party interop as a bug-finding tool

Two consumer-side interop efforts (not this project's own clients) earned
their place here because both found real bugs that pure self-testing never
would have:

**gfal2** (`gfal2_interop`, WLCG/FTS/Rucio's actual client stack).
`root://` via the gfal xrootd plugin (which links real `libXrdCl`) was
10/10 clean — mkdir, upload, ls, stat, byte-identical download, adler32 and
crc32c checksums, rename, cat, rm. `davs://` exposed a real, self-inflicted
bug: `gfal-stat` reported a wildly varying ~839GB file size. Root cause:
this server's PROPFIND response emitted RFC-4331 quota properties
(`<D:quota-used-bytes>`, the *filesystem's* used-byte count) on **file**
resources, and davix maps `quota-used-bytes` straight to `st_size` — the
varying value was literally tracking `/tmp` disk usage. Quota properties are
collection-only per RFC 4331; fix was a one-line gate on `S_ISDIR` in
`src/webdav/propfind.c`. Framing worth keeping: gfal2 is a pure consumer
with zero wire code of its own, yet it still surfaced a *semantics* bug
(a correct property attached to the wrong resource type) — validate against
real production client stacks, not only this project's own `xrdcp`/`curl`,
because differential wire-format testing alone won't catch this class.

**Environment gotcha that recurs across every interop test involving system
tools**: run with `unset LD_LIBRARY_PATH` before invoking system
`xrdcp`/`xrdfs`/`gfal-*` — conda's OpenSSL (3.4.x) conflicts with the
system-linked `libXrdCl`/gfal plugins (`OPENSSL_3.4.0` symbol mismatch),
producing failures that look like protocol bugs but are pure environment
contamination. This bit `gsi_xcache_eos`, `native_client_gsi_interop`, and
`gfal2_interop` independently.

---

## 15. Test-infrastructure decisions specific to client work

A few infrastructure choices are worth recording here because they're easy
to silently regress:

- **Official XrdCl bindings run out-of-process, always**
  (`pyxrootd_isolation_worker`). A synchronous XrdCl call blocks its Python
  thread inside a C++ condvar wait *with the GIL released* — if XrdCl
  deadlocks, the whole pytest interpreter wedges and `pytest-timeout`'s
  SIGALRM handler can never fire (Python only services signals at bytecode
  boundaries). One hung op froze an entire ~4000-test session. Fix (Rob's
  explicit directive): every XrdCl call goes through a transparent shadow
  package (`tests/XRootD/`) into a separate worker process
  (`tests/_xrdcl_worker.py`) over newline-JSON RPC, with a per-call
  wall-clock timeout that kills the worker instead of the interpreter. The
  layer has several hard-won correctness rules baked in and documented
  in-file: GC finalizers must never take a lock or block (queue releases
  lock-free, flush on next call); JSON has no tuples (coerce list-of-pairs
  back to tuples for `vector_read`/`set_xattr`); encode/decode must
  round-trip primitives, tuple-vs-list, `XRootDStatus`, and bytes exactly;
  bare-bool-returning methods must not be coerced into a status shape;
  native exceptions (`ValueError`/`TypeError`) must re-raise as themselves,
  not a generic RPC failure.
- **Interpreter selection matters for that same worker**: it spawns via
  `sys.executable`, so the bindings must live in whatever Python runs
  pytest. The canonical test runner uses `python -m pytest` — bare `python`
  resolves to miniconda 3.13, which has the XRootD wheel and modern
  syntax support. Running with bare `pytest` instead resolves to system
  Python 3.9, which both lacks the bindings and can't even *collect* test
  modules using PEP-604 `X | None` annotations.
- **Native-suite parallelism**: run the phase-37 native test suite serially
  (`-p no:xdist`) — parallel xdist connection load makes the anonymous test
  server shed `ls /` with false 30s timeouts; this is harness contention,
  not a client bug, but it looks exactly like one.
- **Never build and test concurrently**: `make -C client` running
  concurrently with a pytest fixture that also invokes `make` causes an
  object-file race that links 0-symbol binaries. Related but distinct from
  the header-staleness gotcha below.

---

## 16. The recurring build gotcha: stale objects after a header change

This single failure mode was independently rediscovered and separately
documented at least four times across the client program's history
(`client_fast_fail_permanent_errors`, `phase37_native_clients`,
`phase49_client_code_sharing`, and referenced again in `client_ipv6_v4_downgrade`),
which is itself the lesson: **it is not obvious, and it costs real time
every time it's forgotten.**

Symptom: editing a widely-included client header (`client/lib/xrdc.h`, or
adding a new header like `fuse_ops.h`) and then running an *incremental*
`make -C client` leaves at least one `.o` compiled against the old struct
layout — the shared consumer's ABI goes mixed. Observed manifestations
varied: a SIGSEGV inside `xrdc_capture_frame` during login, a completely
broken FUSE readdir path (`EIO` on every `ls` of a mount while everything
else worked fine), an empty-symbol binary. Each one looked exactly like
harness flakiness or an unrelated regression, and cost up to ~30 minutes to
diagnose before the real cause (a stale object) was found.

**The only reliable fix is prevention**: after touching any client header,
always `make -C client clean && make -C client` — never trust an
incremental build across a header change. `client/Makefile` was also given
`-MMD -MP` auto-dependency generation to reduce (not eliminate) the risk.
This is the client-side twin of the server-side gotcha documented as
`build_header_dep_mixed_abi` in memory / the migration-era lessons doc.

---

## 17. Open items as of 2026-07-15

| Item | Status |
|---|---|
| Real `libXrdCl` async-TPC (`kXR_waitresp`/`kXR_attn`) | Out of scope by design — clean-room native TPC only speaks SHM-registry sync-arm |
| Capability engine + just-works auth engine (swiss-army reframe) | Grounded plan, not built |
| OIDC device-flow token acquisition, RFC-8693 token-exchange delegation, VOMS-FQAN selection, krb5 lifecycle, S3 STS/presigned/vhost | Table-stakes, unplanned |
| No X.509 client-cert TLS auth for the HTTP/WebDAV FUSE transport (bearer/anon only) | Documented gap |
| `xrdc_file_pump`/`walk.c` extraction (xrdfs hand-rolls the remote read loop ~9x); xrdcp's recursive WebDAV/S3 relay into `lib/copy.c`; ~35 `report_err` call sites in xrdfs | Deliberately deferred, low value |
| Async FUSE read-ahead prefetch | Deferred — flagged highest-risk (async UAF-on-close) and perf-only, unmeasurable on the WSL2 dev host |
| Write-staging visibility bug class (`OPEN wr` succeeds, `kXR_stat` of final path ENOENT until CLOSE commits — breaks FUSE getattr-after-create) | Surfaced twice (mount-speed work, upload_resume/`.part` staging); not yet root-caused as one issue |
| Post-feature-gap-program backlog (~20 triaged minors: xferjournal 4095 boundary, `rm -r` dir-symlink lstat-probe, `du -j` NDJSON shape, etc.) | Tracked in `.superpowers/sdd/progress.md` |
| `phase37_native_clients`' historical "host load, not code" failure verdicts | Retracted 2026-07-15 — the load was itself a crash loop (uninitialized reaper timer, fixed in `66efecd0`); do not trust those verdicts if re-reading old session logs |

---

## 18. Files with nothing lastingly client-tooling-specific

`oak_olmx_integration.md` is infrastructure/tooling configuration for local
AI code-intelligence services (OLMx model server, OAK CI, opencode's
codebase-index plugin) — unrelated to the native client program and not
represented in this document beyond this note.
