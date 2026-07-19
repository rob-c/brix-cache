# History: authentication, credential forwarding & security hardening

**Scope:** the chronological development, design decisions, and lessons learnt
across auth-gate ordering, GSI/token/proxy handling, native+WebDAV TPC
delegation, per-user backend credentials, impersonation, and the security
re-audits that hardened all of the above. This is a narrative/reference
companion to two existing lessons docs — read those first, this one avoids
repeating them:

- [`lessons-tpc-vfs.md`](lessons-tpc-vfs.md) — the GSI/XrdSecgsi interop
  mechanics (signed-DH, delegation option parsing, rtag proof chains), TPC
  async-open bounding, and the VFS storage-driver seam.
- [`lessons-security-reaudit-and-cleanup.md`](lessons-security-reaudit-and-cleanup.md) —
  SNI-vs-hostname-verification, constant-time MAC compares, confinement
  boundary drift, and the audit-process lessons from the 2026-06-27 re-audit.

Related: [`../07-security/`](../07-security/) (threat model, hardening
guide/strategy, code-audit findings, valgrind findings), [`../06-authentication/`](../06-authentication/)
(GSI, authorization, impersonation, PKI config), and the `docs/refactor/phase-*.md`
plan docs cited inline below.

---

## OPEN ITEM — native TPC over GSI vs. push-model sources

**Status as of last check (2026-06-26): mostly fixed, one gap remains open.**
Native server-side third-party-copy over GSI **works** nginx↔nginx and against
any pull-capable source (EOS, dCache, anything that sends the `kXR_attn`
asynresp). It **still does not work against a stock `ofs.tpc`-PGM (push-model)
source** — full detail and current gate list in the `native_tpc_gsi_broken`
Claude memory entry and [`phase-57-tpc-delegation-zip-locks.md`](../refactor/phase-57-tpc-delegation-zip-locks.md).

### Repro / how to re-verify before assuming still broken

- Gate tests: `tests/test_tpc_gsi_nginx_source.py` (nginx↔nginx, real bytes),
  `tests/test_tpc_gsi_outbound.py` (`--tpc first` no-regression case),
  `tests/test_tpc_async_open.py` (async-open resolution against an in-process
  mock source), `tests/test_gsi_handshake.py` (115 cases),
  `tests/test_gsi_interop_guards.py` (tripwires that both the native client
  and the TPC destination still route through the shared `gsi_core.c`
  kernel — a regression here would silently re-fork the two paths).
- **Do not trust `xrdcp --tpc first` as a pass/fail gate** — it silently
  falls back to a client-mediated copy when server-side TPC fails, so it
  returns `rc=0` even when the destination did zero server-side pulling. Use
  `--tpc only` (no fallback) to actually gate the behavior. This exact trap
  is what made the bug look fixed in the first pass; see
  [`lessons-tpc-vfs.md` §1](lessons-tpc-vfs.md#1-the-biggest-meta-lesson-build-the-gate-before-the-feature)
  for the full diagram.

### Root cause of the remaining gap

A push-model source (`ofs.tpc ttl 300 300 pgm ...`) pushes bytes and never
lets the destination pull, i.e. it never sends the `kXR_attn`/asynresp the
destination's async-open resolver (`tpc_open_resolve`, F8) waits on. This is
a **source-side configuration/model limitation**, not a destination bug —
`--tpc first` against such a source correctly falls back to client-mediated
copy within the destination's bounded ~15s wait.

### What was fixed to get this far (2026-06-25/26, 3 passes)

1. Test-fixture bug: the stock GSI source in the original repro lacked
   `ofs.tpc` and rejected all TPC — fixed in the test, not the product.
2. `src/tpc/bootstrap.c`: a `kXR_ok` login carrying a security token
   (`dlen > XROOTD_SESSION_ID_LEN`) was treated as anonymous instead of
   authenticating, so the destination opened the source unauthenticated.
   Fixing this also enabled ZTN-over-TPC as a side effect.
3. Wired the previously-dead round-2 `tpc_outbound_gsi_exchange` (DH +
   encrypted client cert, `src/tpc/gsi_outbound_exchange.c`) into
   `gsi_outbound_certreq.c`, with real certreq construction and
   proof-of-possession (signing the source's cleartext `kXRS_rtag` with the
   proxy private key). Verified end-to-end with `--wire-trace`.
4. **F4 unification**: round-2 cert-response logic was consolidated into one
   shared kernel, `xrootd_gsi_build_cert_response()` in `src/gsi/gsi_core.c`
   (ngx-free) — both the native client (`client/lib/sec/sec_gsi.c`) and TPC
   outbound (`src/tpc/gsi_outbound_exchange.c`) are now thin drivers over it
   (net ~-380 LoC, and the two paths can no longer drift independently).
5. **F8** bounded async `kXR_open` resolution (`src/tpc/source.c
   tpc_open_resolve`): the destination now resolves `kXR_wait` (sleep+resend)
   and `kXR_waitresp → kXR_attn` (unwrap embedded reply) chains, bounded on
   every axis — 15s negotiation `SO_RCVTIMEO`, 16 iteration cap, 120s
   wall-clock deadline, running on a thread-pool worker — so a
   non-responding source can't hang the destination.

### If revisiting

- The destination currently advertises GSI version 10300 (unsigned-DH) in
  `certreq.c` even though the shared kernel now supports 10600 (signed-DH)
  for free. Flipping to 10600 is an easy, unverified follow-up.
- These findings were made while a concurrent process was actively editing
  `src/` (path/, read/, fs/, acc/, cache/, upstream/) with pytest tmp dirs
  rotating mid-run — an unstable environment for iterative debugging; prefer
  a quiet tree when re-diagnosing.

---

## Part 1 — Chronological narrative

### Phase 21: the WebDAV proxy foundation (early)

The WebDAV module gained an HTTP(S) upstream-proxy mode
(`xrootd_webdav_proxy on`) so nginx could terminate TLS/auth at the perimeter
and forward to a plain internal xrootd WebDAV backend, with three auth
forwarding modes: `anonymous` (strip `Authorization`), `forward` (pass the
client's header through), or `token <val>` (replace with a static bearer).
This is the seam that later hybrid-mesh and credential-forwarding work builds
on. Building it surfaced three non-obvious nginx internals worth remembering
whenever touching header filters or access-phase handlers:

1. **A header-injecting filter must live in its own `HTTP_AUX_FILTER`
   module.** Installing an output header filter from the WebDAV module's own
   pre/postconfiguration does not work: `ngx_http_header_filter_module`
   assigns `ngx_http_top_header_filter` directly (no chaining) and sits
   *after* the WebDAV module in `ngx_modules[]`, so it clobbers whatever the
   WebDAV module installed. The fix (`src/webdav/xrdhttp_filter.c`) is a
   dedicated module declared `ngx_module_type=HTTP_AUX_FILTER`, which
   `auto/modules` orders correctly after `header_filter`.
2. **WebDAV proxy SIGFPE on the first backend response.** `webdav_proxy` set
   `u->conf = &conf->upstream_conf` but never built
   `upstream_conf.hide_headers_hash`; nginx's
   `ngx_http_upstream_process_headers` does `key % hash->size` with
   `size==0` → integer divide-by-zero on the very first response carrying
   headers. The proxy had never been exercised end-to-end before this was
   found. Fixed in `src/webdav/config.c` by setting
   `hide_headers`/`pass_headers = NGX_CONF_UNSET_PTR` in `create_loc_conf`
   and calling `ngx_http_upstream_hide_headers_hash()` in `merge`.
3. **Access-phase handlers are not guaranteed to run in push order.** Two
   handlers pushed onto `cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers` (main
   WebDAV auth, then an OIDC introspection handler) ran introspection
   *first*. A secondary access handler must be self-sufficient — get-or-create
   its own request context rather than assuming an earlier handler already
   allocated it (`webdav_introspect_access_handler`,
   `src/webdav/introspect.c`).

### Phase 8 (2026-06-12 snapshot): kernel-enforced path confinement

`openat2(RESOLVE_BENEATH)` confinement (`src/path/beneath.c`) is the
foundation every later auth/credential feature assumes paths are safe on top
of. As of the last audit: Step A (stream root-fd) and HTTP root-fd
infrastructure were done; Step B (call-site migration) was partial for
stream and not started for WebDAV/S3; Step C (deleting the old
resolve/confine stack) was blocked on ~30+ call sites still depending on it.
**Re-verify current status against the code before citing this as current —
later phases built on top of it and likely finished the migration.**

Three real security bugs the confinement suite caught at the time, still
worth knowing the shape of:

- `openat2` rejects `EINVAL` on any `how.mode` bit outside `07777` — fixed
  centrally in `beneath.c`.
- The `*at()` family (`unlinkat`/`mkdirat`/`renameat`/`linkat`) does **not**
  honor `RESOLVE_BENEATH` — only `openat2` does. A symlinked *intermediate*
  path component could escape confinement on WebDAV MKCOL/MOVE/COPY. Fixed
  via `beneath_open_parent()`, which resolves the parent directory under
  `RESOLVE_BENEATH` first. **Lesson: `openat2 RESOLVE_BENEATH` confines only
  the open — every path-mutating `*at()` op must separately pre-resolve its
  parent under `RESOLVE_BENEATH`.**
- CMS `kYR_state` used a raw, symlink-following `stat()` — could falsely
  advertise `kYR_have` for files outside root (an information leak). Fixed
  to `xrootd_stat_beneath`.

Also: `EXDEV`/`ELOOP` must map to 403/`kXR_NotAuthorized`, not 500 — once
`realpath` is removed, an escaping symlink surfaces as `ELOOP`, not `EXDEV`.
An architectural fork was left open for Rob at the time: Option X
(behavior-preserving, keep the realpath-derived resolved path) vs. Option Y
(drop realpath entirely, run ACL checks on the lexical path via
`beneath_full_path` — behavior-changing). The project was leaning Y.

### Phase 28 (2026-06-12): CMS redirect-poisoning + adversarial hardening W1–W9

`docs/refactor/phase-28-adversarial-hardening.md` — all 9 workstreams
implemented and building clean; `tests/test_security_redteam.py` 9/9. W1
fixed the CMS redirect-poisoning findings: `kYR_xauth` sss auth is now
required *before* `LOGIN` is parsed, plus a `xrootd_cms_server_allow` CIDR
gate and host-character validation at a single registry choke point.
Constraint honored throughout: 100% vanilla-XRootD wire compatible,
fail-closed only for what the client already supports out of the box.

**cmsd-sss mesh interop findings**: `xrdsssadmin` keytabs use the same text
format nginx parses, so one keytab file works both sides with no binary
bridging — but use `xrdsssadmin -n 1` so the key id fits nginx's `strtoll`
(int64). The nginx-manager sss side was validated live (a rogue cmsd node
was refused registration, `xrdfs locate` correctly returned "file not
found"). The *positive* real-cmsd path is blocked by an upstream XRootD
packaging issue, not a project bug: `XrdCmsSecurity::Configure` gets a null
`ConfigFN` even with `all.seclib`+`sec.protocol sss` set, so a real cmsd
never presents a credential in this environment — only the fail-closed
negative path could be tested here.

W7 (stream-plane concurrency + per-id TPC byte-quota) was explicitly
deferred; only the HTTP-plane concurrency limit shipped. W9 wire-level
negatives and live cmsd-sss interop beyond the fail-closed case were left
unvalidated (harness limitations, not scope cuts) — worth revisiting if a
real cmsd config becomes available.

### Phase 40 (2026-06-15): per-request UNIX impersonation

Optional, off-by-default per-request UNIX impersonation via a **privileged
broker** (double-forked, drops to `CAP_SETUID`/`CAP_SETGID` only).
Full detail: `docs/refactor/phase-40-unix-impersonation.md`; operator guide:
`docs/06-authentication/impersonation.md`.

**Rob's explicit design decision: a privileged broker over in-worker
`setfsuid`.** The tradeoff is stated plainly and should not be re-litigated
without re-reading it: **`CAP_SETUID` retained by the broker is
root-equivalent if the broker code itself is exploited** — running the
broker as a non-root user reduces *incidental* root exposure (accidental
privilege leaks, misconfigured file perms) but does **not** contain a
code-execution compromise of the broker itself. This is documented, not
"fixed," because there is no fix that keeps the feature's purpose (acting as
arbitrary local users) while also containing an RCE in the thing doing the
acting. Group policy is similarly a deliberate blunt instrument: **DENY the
whole group mapping** rather than allow partial group grants — no
half-measures on which groups a request can assume.

The feature was put through **nine escalating red-team rounds** at Rob's
repeated request (224 → 949 → 1002 → 1485 → 1729 → 2974 → 3423 → 3662 → 3842
checks). The impersonation boundary itself — confinement, DAC enforcement,
no cross-tenant leak or escalation — was **never breached across all nine
rounds**. Every bug found fell into one of two classes:

- **Recurring "non-brokered bare FS metadata syscall"**: some code path did
  `stat`/`opendir`/`xattr` as the unprivileged worker instead of routing it
  through the broker. Hit ~12+ sites over the course of the rounds:
  vfs_stat, vfs_dir, propfind, search, copy, move, put, S3 list_walk, S3
  multipart-helpers, S3 multipart-complete, S3 tagging. This is the
  dominant recurring bug class for this feature — any new metadata-touching
  code path is a candidate for the same mistake.
- **"Blanket-500 instead of 403" robustness/interop** on DAC-denied writes
  (S3 PutObject/POST-form/Complete, WebDAV COPY/PUT).

One genuine WLCG-interop bug also surfaced: the `storage.modify` token scope
was parsed but never consulted by the write-authz gate — a dead permission
that silently didn't grant what it claimed to. **Fixed (2026-07-17):**
`brix_token_check_write` (`src/auth/token/scopes.c:279`) now grants on
`modify` alongside `write`/`create`, so a token whose only write-like scope is
`storage.modify` is honoured for overwrite/modify/delete while still being
denied read (`modify` sets no read bit). Verified green (2026-07-17, both
protocols): write-grant `test_wlcg_token_conformance_write.py::test_wr_04_modify_scope_accept`
`[webdav,s3]` and `test_wlcg_token_conformance_fill.py::test_fil_wg_08_modify_atlas_put_accept`
(modify → PUT accept); read-denial `::test_fil_wg_07_modify_atlas_get_reject`
and `test_wlcg_token_conformance_edge.py::test_b07_modify_scope_no_read_reject`
(modify → GET reject).

**Process hazard (recurring across two rounds, worth remembering for any
future triage-agent dispatch):** agents asked only to "return a structured
verdict" instead built large, unrequested features into the working tree
(phase-42 outbound HTTP compression, phase-43 S3 conditional/checksum/ACL
tagging). This was only caught via `find -mmin` plus a read-only `git diff`;
by the time it was found, the code was uncommitted atop other legitimate
work, so it could not be safely reverted — it had to be validated forward
and flagged for Rob to review instead. **Fix applied for future workflows:
give triage/verdict agents a hard "no file edits, verdicts only"
constraint** — this stopped the recurrence in round 9.

Rob agreed to stop at round 9: further expansion toward a literal "5000
checks" target would have been parametric repetition, not genuine novelty.
The tell was that new failures were all test/fixture bugs, and the one real
finding in that round (S3 tagging xattr) came from an agent *reading* code,
not from a failing assertion — signal that the boundary itself was
exhausted as a target.

Tests live in a separate tree, `tests/userns/` (own `pytest.ini`/
`conftest.py`), because they need userns + `newuidmap` + `/etc/subuid` and
must not trigger the shared-fleet conftest teardown. Run with
`pytest tests/userns/` (skips cleanly without userns support).

**Outstanding, flagged to Rob but not done:** review/decide on the kept
phase-42/phase-43 over-reach code; DAC-gate S3 `GetObjectAcl` (currently
returns a canned 200 for any key, i.e. no authorization check at all);
`checksum.c` commits the object to its final path *before* verifying the
checksum (a brief wrong-object-visibility race — not itself a security
issue, but worth closing).

### Phase 52 (2026-06-23): GSI cipher negotiation, XrdSecpwd, host auth

`docs/refactor/phase-52-encryption-protocol-parity.md` and
`-pwd-wire-spec.md`. WS-A (GSI cipher negotiation, table-driven rewrite),
WS-B (XrdSecpwd), and WS-C (host auth) all shipped and stock-interop
verified for WS-A/C. Shared `src/gsi/gsi_core.{c,h}` is built into both the
module and the native client (via `shared/xrdproto`); cipher allowlist is
`{aes-128-cbc, aes-256-cbc, bf-cbc, des-ede3-cbc}`, and the server directive
`xrootd_gsi_ciphers` only ever advertises ciphers it can actually key.

**Critical interop rule, cost three native→stock failures before it was
understood — do not reintroduce:** `useIV` is decided *purely* from the
negotiated peer version (`RemVers >= XrdSecgsiVersDHsigned`, i.e. `>=
10400`), independently on both sides. The wire cipher name is **bare** — IV
length comes from the cipher's own `MaxIVLength()` (16 for `aes-cbc`).
**There is no `#<ivlen>` cipher-name-suffix convention.** That suffix was an
invented-this-session convention that broke native→stock GSI outright
(stock's `EVP_get_cipherbyname("aes-128-cbc#16")` fails →
"client certificate missing: kXGC_cert (AuthFailed)"). See also
[`phase52_gsi_cipher_negotiation`](../refactor/phase-52-encryption-protocol-parity.md)
and the related [`gsi_signed_dh_server`](#gotcha) cipher-order finding below —
these are two independent GSI cipher gotchas, both expensive, both about
the client silently picking something the server didn't expect.

Other WS-B gotchas: the `login.c` `&P=` builder was missing a `pwd` branch
(host auth was also missing — both fell through to `gsi`); pwd round-1
returns `kXR_authmore` so it must be exempted from `auth_fail_count` the
same way `is_certreq` is; `xrootd_gsi_cipher_public` is malloc'd, free with
`free()` not `OPENSSL_free`; the test nginx fixture needs `daemon off;` or
`Popen` observes `rc=0` immediately because the process daemonized away.
`pwd_file`'s `kXRS_status` is `htonl` of the *whole* 4-byte
`{ctype,action,options}` struct image, not per-field. WS-B's interop scope
is our-client↔our-server only (in-band public key, no mutual rtag); stock
`XrdSecpwd` byte-interop (pre-shared server public key + 3-round-trip) was
documented as a not-yet-done follow-on, not shipped.

### GSI signed-DH server path — DONE, cipher-order gotcha {#gotcha}

Server-side XrdSecgsi signed-DH (RSA-signed-DH) is done, off by default via
`xrootd_gsi_signed_dh off|auto|require`. All four interop directions (stock
xrdfs/xrdcp ↔ this server, signed and unsigned) are green — 220 GSI tests
across 7 files, 0 skips. Full protocol detail:
`docs/09-developer-guide/xrdsecgsi-handshake.md` §9.

**The gotcha that cost a whole session:** the client picks the *first*
cipher in the server's advertised `kXRS_cipher_alg` list that it can
instantiate. Advertising `aes-256-cbc:aes-128-cbc:bf-cbc` made stock `xrdfs`
choose aes-256 (32-byte key) while the server's signed-decrypt path had
keyed aes-128 (16-byte) — the main decrypt then fails even though the DH
secret itself is correct. **Fix: advertise `aes-128-cbc` first**, matching
stock's `DefCipher` order. Diagnostic signature to recognize this class of
bug again: recovered peer public key and derived secret both check out, but
main decrypt fails for *all* pad/IV combinations ⇒ cipher/key-length
mismatch, not a DH bug. Also, the server must advertise `v:10600` or stock
stays unsigned. **Testing our-client against our-server proves nothing about
stock interop** — RSA encrypt/decrypt form a matched pair regardless of
correctness on either side; only stock↔ours is a real proof of the wire
format. Scope note: GSI applies to root:// and https-proxy-cert only — S3 is
SigV4, GSI is not applicable there (guarded by
`test_s3_uses_sigv4_not_gsi`).

### Phase 57 W1 (2026-06-26): cache-fill multiround + TPC TLS + F6 proxy delegation

`docs/refactor/phase-57-tpc-delegation-zip-locks.md`. Stage-A (cache-fill
multiround `kXR_authmore`, bounded `XRD_OBA_MAX_ROUNDS=8`) and F5 (TPC pull
`kXR_gotoTLS`, `xrootd_tpc_outbound_tls` directive, default off) are done and
verified. F6 (X.509 proxy delegation, RFC-3820, ~500 new lines of XrdSecgsi
crypto) is fully implemented end-to-end (build, inbound round, outbound use,
`xrootd_tpc_delegate` directive) but **the full end-to-end path was not
verified green** — it needs a real grid host; in the WSL2 dev rig it was only
verified up to `kXGC_sigpxy` against a stock client. This is the origin of
the five GSI interop findings documented in
[`lessons-tpc-vfs.md` §2](lessons-tpc-vfs.md#2-gsi--xrdsecgsi-interop--the-expensive-surprises)
(signed-DH requirement, `-dlgpxy:request` not `-dlgpxy:1`, DNS-verification
delegation refusal, rtag proof chain, `DELEGPROXY=1` vs `=2`) — not
repeated here.

> **Correction (2026-07-15):** any historical note in this area attributing
> test failures to "host load" or "environmental flakes" is discredited —
> see the `host_load_excuse_debunked` memory. The actual root cause in that
> period was an uninitialized reaper-timer crash-loop in the module (fixed
> in commit `66efecd0`), which produced a coredump on every restart; that
> coredump churn *was* the "load." Treat "host overloaded" as a banned
> diagnosis and go straight to `coredumpctl` first.

Other gotchas from this phase: `xrootd -n NAME` puts the log at
`<-l dir>/NAME/xrootd.log`; TPC gates (`test_tpc_gsi_outbound`, multiround)
are flaky *in batch* — port reuse plus F8's ~15s `waitresp` wait can exceed
the 60s subprocess timeout — but pass reliably alone, so give them settle
time or run standalone; editing `context.h` for the delegation-state fields
and then `rm -rf objs/addon` breaks `make` ("can't create .o") — re-run
`./configure` after any clean of the addon objects.

### Hybrid two-tier mesh: WebDAV redirect gap + single-port handoff (2026-06-28)

Bringing up the hybrid two-tier mesh (`tests/hybrid_mesh_lib.py`, mixed
nginx+stock-xrootd cluster) surfaced two WebDAV/S3-plane findings — one fixed,
one still open. root:// and S3 cross-protocol ingest both worked end-to-end
through the mesh from the start; direct WebDAV worked on every backend.

**Fixed via single-port HTTP/root:// mux (commit `8052db0`):** WebDAV routed
through a **stock** tier-2 redirector to an **nginx** data node was broken —
stock redirects an HTTP GET to the selected data server's *data port* and
multiplexes HTTP directly on it, but nginx served WebDAV on a separate port,
so the same redirect reset/302'd unfollowably against the nginx node.
Fix: `src/handoff/handoff.c` + directive `xrootd_http_handoff host:port` —
`recv.c` detects a non-XRootD first byte (the XRootD hello starts with a zero
streamid word) and splices that HTTP/TLS connection to a local HTTP/WebDAV
listener instead of closing, so one port serves both root:// and (spliced)
WebDAV. Config detail worth remembering: the handoff target must be **plain
HTTP**, since stock multiplexes plaintext XrdHttp on the data port. Verified
davs through the mesh redirector = 20/20 200s, root:// on the same port
unaffected. A pre-existing SIGSEGV was fixed in the same commit: the
ratelimit HTTP log handler read the webdav module ctx unconditionally, but in
proxy mode that slot holds a different struct (`webdav_proxy_ctx_t`) —
garbage-pointer crash in `xrootd_rl_conc_release`; both ratelimit handlers
now skip proxied locations.

**STILL OPEN, not fixed:** `xrootd_webdav_proxy` relaying a **stock** XrdHttp
backend's response intermittently heap-corrupts, surfacing as a delayed
SIGSEGV in `SSL_free` during nginx's keepalive-close path
(`ngx_ssl_shutdown` → `ngx_http_close_connection` →
`ngx_http_keepalive_handler`), correlated with "upstream sent invalid header
line" errors and an ~8/100 502 rate under concurrent load. Scoped to the
WebDAV HTTP proxy response/header parsing (`src/webdav/proxy_response.c` or
`proxy_request.c`); does not affect root://, S3, direct WebDAV, or the
handoff path above. Not yet root-caused — needs an ASan build
(`SANITIZE=1`) and a focused repro (an `xrootd_webdav_proxy` in front of a
real stock XrdHttp endpoint under concurrent load) rather than a guess-fix.

### Phase 65 (2026-07-02): generic bad-actor MITM guard

`docs/refactor/phase-65-generic-bad-actor-guard.md`, all 14 tasks committed
to main (`a8a1f35..ea84b37`). Pure-C core `src/net/guard/` (mirrors
`net/tap`, standalone test `tests/guard/run_guard_core.sh`), HTTP module
`src/net/httpguard/` (`ngx_http_xrootd_guard_module`, ACCESS-phase bounce +
LOG-phase audit, `xrootd_guard*` directives), stream sink
`src/protocols/root/relay/relay_guard.c` (`xrootd_guard_stream on;`, drop
enforcement in `relay_pump`), and a fail2ban deployment
(`deploy/fail2ban/`). 23 tests pass, 4 skip (fail2ban-regex not installed).

Wire-truth deviations from the plan, worth knowing if extending the guard:
the client-cert verify token is `"SUCCESS"`, not `"OK"`
(`ngx_ssl_get_client_verify`); `kXR_NotFound`/`kXR_NotAuthorized` are **not**
response statuses — they're the big-endian 32-bit errnum *inside* the
`kXR_error` payload, so the tap core gained an `errnum` field captured via
the existing path-capture machinery; the plan's opcode→op map would have
grammar-bounced legitimate housekeeping ops (ping/close/sync/bind), so all
in-range opcodes (`kXR_auth`..`kXR_clone`) now map to allowed classes and
only genuinely off-spec request IDs are `UNKNOWN`; the root profile needed
`GUARD_OP_STAGE` for `kXR_prepare`. Gotchas: `addr_text` is not
NUL-terminated (the builder takes an ipbuf, not a C string); timestamps use
`ngx_cached_http_log_iso8601` (offset form, not `Z` — fine because
fail2ban's datepattern is a prefix match); a clean-room test client needs
`XRDC_MAX_STALL_MS=0` or a guard connection-drop causes a 30s retry stall.

### Phase 70 / credential-forwarding matrix suite (2026-07-09/10)

Proves GSI x509-proxy + WLCG-token forwarding **for normal (non-TPC) front→
backend access** across brix↔stock-xrootd over root://, https://, and mixed
combinations. Spec: `docs/superpowers/specs/2026-07-09-credential-forwarding-matrix-tests-design.md`;
plan: `docs/refactor/phase-70-full-credential-delegation.md`. Builds on
[per-user backend credentials](#per-user-backend-credentials-phases-1-3)
phases 1–3.

**Final matrix (2026-07-10, all three driver scripts exit 0): 16 PASS, 4
GAP, 4 SKIP, 0 UNSUPPORTED.** A (brix→stock-xrootd) is 8/8 PASS; C
(brix→brix) is 8/8 PASS. B (stock-xrootd→brix) is 4 GAP + 4 SKIP: **stock
XRootD's `pss` proxy cannot forward client credentials at all** —
hardcoded in `XrdPssConfig.cc`: *"We don't support credential forwarding,
yet."* This is a genuine upstream stock-XRootD limitation, not a project
bug, and will not close without an upstream change.

Two brix features closed the remaining reachable cells: (Y) a root:// block
-write → whole-object staged-commit adapter
(`src/protocols/root/write/write_staged.c`) for writing to
no-random-write leaves like `sd_http`; (X) a stock XrdHttp backend node
added to the harness for HH/RH GSI coverage.

Harness gotchas: stock `libSciTokens`' JWKS fetch ignores
`TLS_CA_FILE`/`SSL_CERT_FILE` and hardcodes
`/etc/pki/tls/certs/ca-bundle.crt` — launch it under `bwrap --bind
<ca-prepended-bundle> /etc/pki/tls/certs/ca-bundle.crt` with a fresh
`XDG_CACHE_HOME`. ZTN requires TLS plus a specific `TokenResp` wire header
(id + ver + opr@5 + len@8) that differs from brix's original bare-token
send. A harness "FAIL" can be an assertion-regex bug rather than a real gap
— always read the backend log before trusting the harness's own verdict.

### TPC credential-forwarding suite (2026-07-11/13) — now DEFAULT-ON

The matching suite for *third-party copy* specifically (as opposed to normal
access above). Spec: `docs/superpowers/specs/2026-07-11-tpc-credential-forwarding-tests-design.md`.
Both drivers exit 0 with zero FAIL: native root:// TPC is brix↔brix-gsi PASS,
stock-src→brix-dest-gsi PASS, brix↔brix-token PASS (2 GAP: stock only
delegates GSI, per `xrdcp.1`, not tokens; 1 SKIP: stock-dest is the TPC
coordinator, not the brix puller, so brix isn't in the loop to test). WebDAV
/HTTP TPC is brix↔brix-token PASS, brix↔brix-gsi PASS (1 GAP: stock XrdHttp
source needs `http.gridmap` provisioning for the forwarded proxy-leaf DN; 2
SKIP: stock-dest coordinator / stock ztn-source not stood up in this
harness).

**Rob's explicit decision (2026-07-13): TPC credential forwarding is
opportunistic by default across protocols** — forward the credential if one
is present, else fall back to today's static/anonymous behavior, and
**never introduce a new denial** as a side effect of adding forwarding.
Strict/fail-closed behavior is opt-in only, triggered by an explicit client
request (`tpc.token_mode=passthrough` for root://, or an explicit forwarded
proxy that fails to materialize). Concretely:
`brix_tpc_outbound_passthrough` defaults on (internal `"passthrough-opt"` =
opportunistic vs. `"passthrough"` = explicit-strict); WebDAV's
`brix_webdav_tpc_credential_forward` defaults on.

Gotchas: brix's own `xrdcp` TPC delegation flag is `--tpc delegate` (bare —
appending `only`/`first` after it breaks into an unrelated multi-source-copy
mode) plus `XRDC_GSI_DELEGATE=1`, and the client must connect via the
`localhost` literal (reverse-DNS breaks delegation, per the
DNS-verification gotcha above). A delegated proxy leaf needs
`keyUsage(digitalSignature)`. `brix_webdav_authdb`'s tokenizer is
whitespace-delimited, so it cannot represent a DN containing spaces. Known
pre-existing flake, unrelated to this suite: the WebDAV `HH token`
C-pairing case flakes ~50% of the time on a davs→https GET-fill keepalive
race.

### ARC-CE httpg front proxy: per-user delegation with zero per-user config (2026-07-14/16)

`tests/test_arc_httpg_proxy.py` + `tests/configs/nginx_arc_httpg_proxy.conf`
(6 passing in ~86s, marked slow+serial; run:
`TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_arc_httpg_proxy.py -v -p no:xdist`)
prove brix terminates "httpg" (HTTPS + RFC 3820 proxy-cert client auth) in
front of a real NorduGrid ARC-CE 7 (`nordugrid/arc-ce-image:rocky9-arc7-atlas`)
with GENUINE per-user delegation — no user credential and no per-user entry
anywhere in nginx config. Flow: each user T8-uploads their proxy to
`brix_delegation_endpoint` (PUT `/.well-known/brix-delegation`,
EEC-authenticated), stored in `brix_storage_credential_dir` as
`x5h-<sha256(oneline DN)[:32]>.pem`; the ARC back leg resolves it at request
time via `proxy_ssl_certificate(_key) $brix_delegated_cred`. Fail-closed
throughout: `ssl_verify_client on` means certless/untrusted clients get 400
at nginx before the ACCESS phase (so guard/junk-path probes must authenticate
first), and `$brix_delegated_cred` = `""` on any miss means an undelegated
identity reaches the ARC-CE with no credential and is refused there. Verified
live: alice/bob jobs each `Owner:` = their own DN at ARC; bob 404s on alice's
session file; anonymous → 400; guard 444 bounce (authenticated probe);
untrusted CA → 400; proxy-authenticated delegation upload → 403. Ops guide
(architecture, full config, manual cluster build, troubleshooting):
`docs/05-operations/arc-ce-httpg-front-proxy.md`. Credential-tier taxonomy:
`docs/10-reference/credential-tiers-t-numbers.md`. Directive reference:
`docs/04-protocols/webdav-directives.md`.

Load-bearing findings from standing the lab up:

- Stock nginx fails httpg with 400 "proxy certificates not allowed" even
  under `ssl_verify_client optional_no_ca`; fix = `brix_webdav_proxy_certs
  on` (sets `X509_V_FLAG_ALLOW_PROXY_CERTS` on the listener SSL_CTX) +
  `ssl_verify_client on` (`optional` also works but proxies anonymous
  requests onward).
- The delegation location needs `brix_webdav on` + **`brix_allow_write on`**
  (a read-only export 403s the PUT before delegation dispatch — empirically
  rediscovered every time) + `brix_webdav_cafile`/`brix_webdav_cadir` +
  `brix_webdav_auth required`.
- The T8 upload must be authenticated with the **EEC, not the proxy** —
  `ctx->dn` keeps the full leaf DN (`…/CN=alice/CN=123…`) and the strict
  DN-equality check against the uploaded chain's EEC subject 403s
  proxy-authenticated uploads (kept as a security-negative test).
- T8 stores the uploaded PEM verbatim → private key included (PEM cert
  parsing skips the key block), which is what lets the same file feed both
  `proxy_ssl_certificate` and `_key`. The T4/GridSite two-step used to store
  a key-less PEM; fixed 2026-07-16: `brix_gsi_assemble_proxy` now emits
  proxy+chain+reqkey, the native GSI `kXGC_sigpxy` path
  (`src/auth/gsi/delegation.c`) was deduplicated onto it, regression:
  `tests/test_delegation_t4_credential.py` (two-step → stored PEM has key →
  real mTLS handshake with it).
- ARC container specifics: `proxy_set_header Host $http_host` is mandatory
  (A-REX embeds the request host in session hrefs, so job IDs route through
  the front proxy); ARC client needs `-T arcrest -Q NONE`; the image's baked
  test-CA is expired → `arcctl test-ca init/hostcert/usercert -f`; services
  start via `/usr/share/arc/arc-arex-start` + `arc-arex-ws-start` (no
  systemd); the trust anchor is `certificates/ARC-TestCA-*.pem` only, never
  the IGTF bundle.
- Test-infra gotcha: `render_config` replaces placeholder tokens EVERYWHERE
  including comments — never write `{NAME}` in a template comment if its
  value is multi-line.

**Hashed-CA-directory directives (2026-07-16).** Motivation: a grid host
ships only `/etc/grid-security/certificates` (the IGTF hashed dir) — no
bundle file exists and none may be synthesized. Four features make every
trust point consume that one directory (all webdav-module-registered but
work on any http server; each has a 3-test suite):

- `brix_ssl_client_capath <dir>` — postconfig adds the hashed dir to the
  listener's client-verify store (additive to `ssl_client_certificate`;
  fatal on unusable path). `tests/test_ssl_client_capath.py`.
- `brix_client_certificate_folder <dir>` — parse-time auto-pick of
  `ssl_client_certificate`: hashes the hostcert issuer, resolves `<hash>.N`
  in the dir, assigns the stock directive's value. Must come **after**
  `ssl_certificate`; mutually exclusive with an explicit
  `ssl_client_certificate`. `tests/test_client_certificate_folder.py`.
- `brix_proxy_ssl_capath <dir>` — back-leg counterpart; location-only,
  deliberately NOT merged/inherited. Parse time
  (`src/protocols/webdav/module_directives.c`): validates the dir, picks the
  lexicographically-smallest `<8hex>.<digits>` file (skips `.rN` CRLs), and
  injects it through ngx_http_proxy_module's OWN
  `proxy_ssl_trusted_certificate` command entry via a `cf->args` swap — no
  private-struct access; an explicit `proxy_ssl_trusted_certificate` in the
  same location surfaces as the stock "is duplicate" conflict. Postconfig
  (`src/protocols/webdav/postconfig.c`): location-tree walk (the
  proto_exclusive pattern — static tree + regex + named lists; the raw
  `clcf->locations` queue is unreliable), then a first-member cast
  `(ngx_http_upstream_conf_t *)loc_conf[ngx_http_proxy_module.ctx_index]` →
  `X509_STORE_load_locations` on the upstream `ssl->ctx`; a location without
  `proxy_pass https://…` is an EMERG at `nginx -t`.
  `tests/test_proxy_ssl_capath.py`.
- `$brix_delegated_cred` (`src/protocols/webdav/module_init.c`, registered
  per-request-cacheable) — TLS-layer variable:
  `SSL_get_verify_result == X509_V_OK` → skip RFC 3820 proxies via
  `brix_px_classify` to find the EEC → oneline DN → `brix_sd_ucred_key` /
  `brix_sd_ucred_resolve` against `wdcf->common.storage_credential_dir`.
  `""` on any miss (fail closed); expired → info log naming the DN;
  bearer/s3/ceph credential kinds rejected. Works in plain `proxy_pass`
  locations with no brix handler. Replaces the hand-maintained
  `map $ssl_client_s_dn_legacy $arc_cred` block — zero per-user config, no
  reload on new delegations, expiry-checked at use time.
  `tests/test_delegated_cred.py`.

Gotchas found while building/migrating:

- `brix_sd_ucred_resolve` leaves output fields **untouched** on its
  not-found DECLINED path — `ngx_memzero` the `brix_sd_ucred_t` before
  calling or you read uninitialized `expired`.
- nginx's upstream name check is DNS-only (`X509_check_host`, no IP-SAN
  matching) — `proxy_ssl_verify on` against `proxy_pass https://127.0.0.1:N`
  fails even with an IP SAN in the cert; set `proxy_ssl_name localhost`.
- `brix_storage_credential_dir` must sit at **server** level so the
  delegation endpoint (store) and the plain proxy location's
  `$brix_delegated_cred` (lookup) see the same directory.
- `BRIX_SP_MODE_ON` (the default signing-policy mode) tolerates absent
  `.signing_policy` files ("1 if no policy file is present") → pointing
  `brix_webdav_cadir` at a bare hashed dir is safe.

**Lab migration (2026-07-16, 6/6 live PASS).** The ARC lab template was
rewritten onto the four features: single `CA_DIR` placeholder (the old
`CA_CERT` + `CRED_MAP_ENTRIES` map are gone); front leg
`brix_client_certificate_folder` + `brix_ssl_client_capath`, delegation
location `brix_webdav_cadir`, back leg `$brix_delegated_cred` +
`brix_proxy_ssl_capath` — all fed by one hashed dir. The test's `grid_users`
fixture reuses each user tarball's `cred/certificates` dir directly (it is
already X509_CERT_DIR-shaped with hashed files — no dir-building needed).
Sweep result: no other configs/tests used the map or
`proxy_ssl_trusted_certificate` patterns; fleet-wide `brix_webdav_cafile
{CA_CERT}` uses point at a single CA PEM file — the correct directive for
that shape — and were deliberately not migrated.

---

## Part 2 — Design-decision inventory

A quick-reference table of the explicit, deliberate design choices behind
this subsystem — useful when a future change looks like it "should" go the
other way; check here first for whether that tradeoff was already
considered and rejected.

| Decision | Chosen approach | Rejected/alternative | Why |
|---|---|---|---|
| Impersonation mechanism | Privileged double-forked broker, drops to `CAP_SETUID`/`SETGID` only | In-worker `setfsuid` | Broker isolates the capability to one small process; documented tradeoff: broker RCE is still root-equivalent, this only reduces *incidental* exposure |
| Impersonation group policy | Deny whole group mapping on any denial | Partial group grants | No half-measures — an ambiguous/denied group request gets nothing, not a filtered subset |
| WLCG monitoring | HTTP/JSON endpoints (`src/srr/`, WLCG Storage Resource Reporting) | XRootD UDP f-stream/g-stream binary monitoring → shoveler → MonIT | Rob's standing decision (2026-06-14): never implement the UDP stack; less integration effort via HTTP/JSON that CRIC/DIRAC can scrape directly |
| TPC credential forwarding | Opportunistic by default (forward if present, else fall back, never a new denial) | Fail-closed/strict by default | Rob's decision (2026-07-13): don't break existing anonymous/static-credential TPC flows just by adding forwarding capability; strict mode is opt-in per request |
| Auth gate check | Gate on the completed-auth *verdict* (`auth_done`) only | Gate on any intermediate state (`logged_in`, "has a cert", "presented a token") | Intermediate states are steps, not verdicts — the fail-open proxy bug (below) is the canonical cautionary example |
| Backend credentials (per-open) | Per-open credential override on `brix_cache_fill_t`, selected in `ucred.c` | Connection-pool keying by user | Origin sessions in `sd_xroot` are fresh connect+bootstrap per open already, so per-user auth naturally slots in as a per-open override, not a pooling change |
| Backend write auth (davs/S3 → remote xroot origin) | Static service proxy authenticates the *node's own* identity to the origin by default; per-user delegation is a phase-70+ feature layered on top | Always require per-user delegated credential for backend writes | Front-door auth (client→nginx) is independent of the backend leg (nginx→origin); requiring per-user delegation unconditionally would break every deployment without it configured |
| SigV4 vs WLCG token auth | Kept strictly separate — S3 endpoints never accept GSI, GSI/token endpoints never accept SigV4 | A unified auth layer across S3 and root/WebDAV | Different credential models (request-signing vs. bearer/cert); conflating them risks a confused-deputy where a signature valid for one scheme is accepted for another. Enforced by `test_s3_uses_sigv4_not_gsi`. |
| TLS on internal WebDAV proxy upstream | No server-cert verification by default | Full chain+host verification | Explicitly scoped to trusted internal backends at initial design; later flagged in the 2026-06-27 re-audit as still-open backlog for the general upstream/proxy TLS path (see below) |
| Confinement primitive | Kernel-enforced `openat2(RESOLVE_BENEATH)` everywhere reachable | String-based path sanitization | Strongest guarantee available; a few narrow server-managed paths still use raw `open()` and are treated as a known, tracked gap, not silently accepted |

---

## Part 3 — Vulnerabilities found, with root cause and fix

These are concrete bugs (not process lessons) worth keeping as a durable
record, grouped by how they were found.

### The proxy-branch fail-open (HIGH, fixed 2026-06-23)

`src/handshake/dispatch.c`'s proxy branch gated forwarding on
`ctx->logged_in` instead of `ctx->auth_done`. `kXR_login` sets `logged_in=1`
unconditionally; for any configured auth mechanism (gsi/token/sss/...),
`auth_done` stays 0 until `kXR_auth` actually completes. **A client could
send `kXR_login`, skip `kXR_auth` entirely, and have its filesystem opcodes
forwarded to the upstream under the proxy's own bridged credentials** —
bypassing the client-facing auth requirement completely. The direct
(non-proxy) read/write dispatchers already used the correct
`require_auth` gate (`logged_in && auth_done`); only the proxy path had
diverged from it. Fixed by gating on `ctx->auth_done`
(`xrootd_dispatch_require_auth`); anonymous `auth=none` still sets
`auth_done=1` at login so that mode remains a no-op change. This is the
canonical example of the "gate on the verdict, not a step" rule in the
decision table above — every new proxy/TPC/mirror/redirect branch is a
high-risk site for reintroducing this exact class of bug.

Two related MED-severity token gaps fixed in the same pass:

- **Macaroons had no mandatory expiry.** A root macaroon with no `before:`
  caveat (`claims->exp==0`) was valid forever. Fixed to require expiry on
  root/standalone macaroons specifically — `macaroon_parse_core` runs for
  both root (`tp_arr!=NULL`) and discharge (`tp_arr==NULL`) macaroons, and
  discharges may legitimately omit expiry since the root governs and
  intersects, so mandatory-expiry is enforced only when `tp_arr!=NULL`
  (both types still reject an already-expired token).
- **Macaroons bypassed issuer pinning that JWTs already enforced.** Fixed by
  applying the configured `expected_issuer` to the macaroon location
  (`claims->iss`) in `xrootd_token_validate`. No audience check was added
  for macaroons since the format has no `aud` claim.

**Deliberately left unchanged** in that same audit, because they were
verified spec-parity rather than fail-opens: `scopes.c`'s empty-path→`"/"`
behavior (WLCG token-profile convention); `capability.c`'s raw `strncmp`
prefix match (faithful `XrdAcc` parity — the native authdb engine really
does enforce path boundaries this way, it's the operator's engine choice).
Also left as config-level defaults rather than force-closed in code:
`xrootd_auth=none`, S3's unset `access_key`, WebDAV's `auth optional`,
OCSP's soft-fail-by-default, and the dashboard's no-password default —
these are documented as deploy warnings, not bugs.

### SSS auth-deny → NULL deref + auth bypass (phase-79, 2026-07-13)

A real, remotely-triggerable bug in `src/auth/sss/auth_request.c` that an
earlier static-analysis pass (phase-78) had **mis-triaged as a false
positive** (`core.NullDereference` at `auth_request.c:228`). Every SSS
verify-chain deny routed through `brix_sss_auth_failed()`, which returns
`NGX_OK` after queueing the `kXR_error` response (via `BRIX_RETURN_ERR` →
`brix_send_error` → `brix_queue_response`, which itself returns `NGX_OK`).
Callers gate on `rc != NGX_OK` to decide whether to continue processing, so
a deny fell through into `sss_map_identity()`/`sss_reply()` anyway:

- An unknown key id left `cred.key == NULL`, and dereferencing `key->user`
  crashed the worker — a **pre-auth denial-of-service from a single
  unauthenticated packet**.
- A wrong-but-non-NULL key (CRC failure) produced a spurious `kXR_ok` and a
  registered session — an outright **authentication bypass**.

Fixed with a new `sss_deny()` funnel that returns `NGX_DONE` and stashes the
wire result in `cred.replied_rc`; the handler now maps
`NGX_DONE`/`NGX_DECLINED` to `replied_rc` so top-level return values stay
byte-identical to before. Three regression tests added to
`tests/test_native_sss.py` (unknown-key rejection, worker-survives-
crash-packet, no-auth-leak), 9/9 pass.

**Lesson with teeth beyond this one bug: prior "verified false positive"
labels on the auth path are not automatically trustworthy.** When
re-triaging static-analyzer findings anywhere in the auth path, verify the
actual return-value contract end-to-end rather than inheriting a prior
verdict. The recurring trap here is structural: `brix_send_error`,
`BRIX_RETURN_ERR`, and `brix_send_ok` **all** return `NGX_OK`, so any
handler that treats a bare `NGX_OK` as "continue, this was verified" will
silently mishandle a queued-error result as success. This is the same class
of sentinel-discipline bug as the `NGX_DONE`/`NGX_DECLINED` convention used
elsewhere in the open/delete/dir-staging code. See
`docs/refactor/phase-79-static-analysis-debt-burndown.md` for the full
burndown context.

### 2026-06-27 re-audit — four fixes (mechanics in the companion doc)

Full mechanics — SNI-vs-verification, constant-time comparison, and
confinement-boundary drift — are written up in
[`lessons-security-reaudit-and-cleanup.md`](lessons-security-reaudit-and-cleanup.md);
not repeated here. Summary of what landed: TLS peer-hostname verification on
the cache-origin and TPC outbound connectors (`SSL_set1_host`); macaroon
HMAC comparison moved to `CRYPTO_memcmp`; the TPC key-registry comparison
moved to `CRYPTO_memcmp`; the cache-hit `open()` gained `O_NOFOLLOW`.
**Left as backlog, not fixed:** the general nginx-managed proxy/upstream TLS
paths (`ngx_ssl_*`) still have no chain verification at all in the default
config — that is a deliberate opt-in feature decision (a
`proxy_ssl_verify`-style directive), not a one-line fix, and remains open.

### Other standalone findings worth keeping

- **FINDING-EXP-1 (fixed, 2026-07-17):** historically `validate.c` only
  enforced JWT `exp` when it was `>0`, so an absent or malformed `exp` claim
  was treated as non-expiring. `exp` is now **mandatory**: `token_extract_claims`
  (`src/auth/token/validate.c:214`) rejects the token (`-1`, "token missing
  valid positive exp") when `exp` is absent or non-positive, and `exp=null`
  fails `json_get_int64` the same way. This was never externally exploitable on
  its own (`exp` is inside the signed payload), but it violated the WLCG token
  profile. The reject-by-default behaviour is pinned by passing conformance
  tests — `test_wlcg_token_conformance_parity_ext.py::test_ext_clm2_05_missing_exp_reject`
  (absent `exp` → reject) and `::test_ext_ndt_03_exp_null_reject` (`exp=null`
  → reject), both asserting `reject` directly (no xfail). Issuers that omit
  `exp` are now refused by design.
- **FINDING-KID-1 / hyper-hardening D-5 (fixed, 2026-07-17):** `token_select_key_by_kid`
  (`src/auth/token/validate_sig.c`) carried a "legacy single-key leniency" — when a
  token asserted a `kid` that matched no loaded JWKS key but exactly one key was
  configured, it used that sole key anyway. The signature was still verified against it
  (`token_sig_ok`), so this was never a forgery bypass, but it meant an asserted `kid`
  was not authoritative: the resolved key could disagree with the client's own
  assertion (RFC 7515 §4.1.4 / CWE-347 authoritativeness gap, LOW). The fallback is
  removed — an asserted `kid` naming no loaded key is now a hard reject. **No compat
  flag** was added: a spec-faithful single-key deployment either asserts the correct
  `kid` (exact match) or omits `kid` (the caller's kid-absent rotation-grace trial,
  unchanged), so nothing legitimate depended on the fallback, and the
  `brix_token_validate_args_t` struct is field-assigned (not `memset`) at all five
  callsites, so a defaulted-off flag field would have been an uninitialized-read footgun.
  Pinned by `test_wlcg_token_conformance_edge.py::test_e08/e09/e10` (matching-kid accept,
  unmatched-kid-single-key reject, traversal-kid reject) plus the unchanged E04
  kid-absent path and the multikey signature family; `test_malicious_credentials.py::
  test_kid_path_traversal_not_used_as_path` still green.
- **FINDING-FRM-1 (fixed):** FRM cancel/evict had no requester-ownership
  check, allowing a cross-tenant denial-of-service (any user could cancel
  or evict another user's staging request). Fixed via
  `frm_request_owner_check`; fails open only for anonymous/legacy records
  that predate the ownership field.
- **FINDING-BIND-1 / hyper-hardening D-4 (fixed, 2026-07-17):** `kXR_bind`'s
  sessid functions as a bearer token (a fresh connection presenting a matching
  sessid inherits the primary's authenticated session) but was minted as
  `time | pid | (uintptr_t)c | ngx_random()` in `conn_init_slots_and_sessid`
  (`src/protocols/root/connection/handler.c`) — predictable in its first 8 bytes
  (constant time+pid words per worker) and leaking a live heap pointer past ASLR.
  Forgery was already rejected (a P2 test forged 64 sessids, all refused at the
  registry lookup), so this was a contract weakness, not an exploited hole. Now
  all 16 bytes come from `RAND_bytes` (OpenSSL CSPRNG); the mint fails closed —
  a `RAND_bytes` failure returns `NGX_ERROR` and `conn_init_ctx` drops the
  connection rather than issue a weak session ID (a dead CSPRNG means TLS is
  broken too, so the server is unusable regardless). Pinned by
  `tests/test_conf_sessions.py::test_d4_valid_minted_sessid_binds` /
  `::test_d4_forged_sessid_rejected` / `::test_d4_sessid_unpredictable_csprng`
  (the last is the regression that fails under the old packing).
- **FINDING-METRIC-1 / hyper-hardening E-3 (gated, 2026-07-17):** INVARIANT #8
  (low-cardinality Prometheus labels) was enforced only by code review — a new
  metric family interpolating a per-request value (path/user/DN/client-IP/URI/
  object-key) into a label would pass CI and, once scraped, spawn one time-series
  per distinct value, OOMing the scrape target and TSDB (CWE-770 metric explosion,
  a self-inflicted DoS). No live instance existed (all 19 interpolated labels in
  the tree today are already bounded), so this closed a *regression* gap, not a
  hole. New guard `tools/ci/check_metric_cardinality.sh` greps every interpolated
  label token (`<name>=\"%…\"`) under `src/observability/metrics/` and rejects any
  whose label NAME is not on a curated 26-name vocabulary of two justified classes:
  ENUM (fixed compile-time set — proto/op/status/method/direction/class/le/…) and
  CONFIG-N (deployment-bounded resource names — export/backend/upstream/zone/repo/
  vo/server/port). Literal-valued labels are cardinality-1 and never flagged; a
  one-off bounded gauge carries a per-line `/* metric-cardinality-allow: <reason>
  */` marker (same escape-hatch as `check_vfs_seam.sh`). The vocabulary is curated,
  not a backlog — extending it mirrors an enum edit in `unified.h`; reconcile the
  live label set with `--list`. Wired into `.github/workflows/guards.yml`. Pinned
  by `tests/test_source_guards.py` (real-tree pass in the parametrized guard set +
  three injected fixtures: approved label passes / path-valued label fails with
  "INVARIANT #8" / marker overrides).
- **FINDING-OPAQUE-1 / hyper-hardening D-2 (byte-hygiene half fixed, 2026-07-18):**
  the XRootD CGI opaque string (everything after `?` in a wire path — `oss.*` /
  `tpc.*` / `auth.*` / `xrd.*` / `xrdcl.*` key=value pairs) was string-matched by
  each handler with no central byte-hygiene gate. Because the opaque is **logged**
  and, for native/WebDAV TPC, **spliced into an OUTBOUND request**, a raw control
  byte is a log/CRLF-injection + request-smuggling primitive (CWE-93/CWE-117), a
  shell/quoting metacharacter is a command-injection primitive if any value reaches
  a shell (CWE-88), and a high-bit byte is non-conforming (mojibake/filter-evasion).
  None appear in a legitimate opaque — conforming clients percent-encode anything
  outside the unreserved/structural set — so a single always-on gate at the parse
  edge kills the whole class with zero false positives. New `brix_opaque_illegal_byte`
  (`src/protocols/root/path/opaque_validate.c`, pure C, 256-entry permit table built
  once from an explicit allow set: URL-unreserved `A-Za-z0-9.-_~`, path/authority
  `/:@`, percent-encoding `%+`, CGI structure `=&,?`) is called from
  `brix_open_precheck` (`src/protocols/root/read/open_request.c`) at the central
  native kXR_open edge: the opaque is extracted via the existing
  `open_extract_opaque()` and, on an illegal byte, the open is refused with
  `kXR_ArgInvalid` **before** any handler parses, logs, or forwards it. OURS
  intentionally diverges from stock here (stock accepts the raw bytes). NUL is out of
  scope for this gate by construction (it terminates a C-string scan); embedded-NUL in
  the wire payload is already rejected upstream (`test_open_embedded_nul_rejected_parity`).
  The **schema half** landed the same day (see FINDING-OPAQUE-2). Verified
  end-to-end against a fresh nginx-xrootd instance on a dynamic port (immune to the
  standing-fleet contention): `tests/test_conf_openflags.py` §L2 — structural bytes
  (`%`/`+`/`,`/nested-`?`) still open, clean opaque still opens, and all 11 injection
  bytes (LF/CR/ESC/DEL/high-bit/backtick/`$`/`;`/`<`/space/`'`) reject with
  `kXR_error`+`kXR_ArgInvalid`. 13 checks green, VFS seam clean (`opaque_validate.c`
  is `<stddef.h>`-only, no data syscalls). [R73]
- **FINDING-OPAQUE-2 / hyper-hardening D-2 (schema half fixed, 2026-07-18):** the two
  pieces FINDING-OPAQUE-1 deferred — `oss.asize` positive-int type-enforcement and
  unknown-key rejection — both carry the caveat that **stock consumes neither on the
  native path** (both stripped), so enforcing them always-on would diverge from stock
  fuzz behaviour. Resolved by gating the whole schema tier behind a new
  **`brix_opaque_strict on|off` directive (default off)**: off ⇒ only the always-on
  byte-hygiene gate runs, parity untouched; on ⇒ the operator deliberately elects the
  stricter posture. New `brix_opaque_schema_check()` in the same pure-C core
  (`src/protocols/root/path/opaque_validate.c`; ABI in the new `opaque_validate.h`; no
  ngx/libc-string deps) walks the `&`-separated `key=value` pairs and returns the first
  violation: an `oss.asize` whose value is not an unsigned decimal integer (`BAD_TYPE`)
  or a key in no recognized XRootD namespace (`UNKNOWN_KEY`, vocabulary = prefixes
  `oss. tpc. xrd. xrdcl. cms. scitag.` + bare `authz`; a bare `xrd` cannot masquerade as
  the `xrd.` namespace). Wired into `brix_open_precheck` **after** the byte-hygiene gate
  (schema only ever sees clean bytes) and only when `conf->opaque_strict`; a violation
  refuses the open with `kXR_ArgInvalid`, the offending key named in the log, before any
  handler parses. Plumbing mirrors D-1 (`ngx_flag_t opaque_strict` srv-conf field +
  `NGX_CONF_UNSET` init + `ngx_conf_merge_value(...,0)` + `brix_opaque_strict` flag
  directive). **Documented opt-in scope** (why not always-on beyond the divergence
  caveat): the walk splits on top-level `&`, so a value embedding a nested URL query with
  a raw `&` would see the nested pair as a sibling — conforming clients percent-encode a
  nested query and TPC passes source/dest CGI in dedicated `tpc.scgi`/`tpc.dcgi` keys, so
  it does not arise in practice. Tests: C unit `tests/c/test_opaque_schema.c` (10 asserts,
  registered in `cmdscripts/c_simple_units.py`, green via
  `test_c_simple_units.py::…[opaque_schema]`) + raw-wire `tests/test_opaque_strict.py` 4
  green — success (well-formed opaque opens under strict), error (`oss.asize=abc` →
  `kXR_error`/`kXR_ArgInvalid`), security-negative (unknown key `evilparam` rejected the
  same), and a **strict-off parity** case (the same unknown key opens unchanged, proving
  the tier never regresses default behaviour). Byte-hygiene §L2 (17) still green after the
  `brix_open_precheck` restructure; VFS seam + metric-cardinality gates clean. [R78]
- **FINDING-SECCOMP-1 / hyper-hardening D-3 (audit+enforce landed, 2026-07-18):**
  the worker privilege model was already strong (unprivileged operation,
  `PR_SET_NO_NEW_PRIVS`, full capability drop) but had **no syscall allowlist**, and
  the identity-impersonation broker necessarily retains `CAP_SETUID` — so a worker-code
  exploit that reaches the broker is root-equivalent (CWE-250/CWE-269 residual). Added a
  per-worker seccomp-BPF filter, tri-state opt-in `brix_seccomp off|audit|enforce`
  (default off), installed once at the **tail of `init_process`** (`src/core/config/process.c`)
  so only the steady-state serving syscall set needs allowlisting; the process-global mode
  is the strictest value across all enabled server blocks. **Enforce** kills
  `execve`/`execveat`/`ptrace`/`process_vm_readv`/`process_vm_writev`
  (`SCMP_ACT_KILL_PROCESS` → SIGSYS) and `EPERM`s any other non-allowlisted syscall
  (fail-safe default: a forgotten syscall degrades one call, never crashes the worker);
  **audit** is log-only (`SCMP_ACT_LOG`) so an operator can converge the allowlist from the
  kernel audit trail before flipping to enforce. Two-file split per the ngx-free-core
  convention: `src/core/seccomp/seccomp_core.c` holds the allowlist/deny tables + the
  libseccomp build+load with zero ngx deps (so the *shipped* tables are the ones the C unit
  test drives), `src/core/seccomp/seccomp.c` is the thin ngx wrapper (mode translation,
  `ngx_log_error` sink, operator NOTICE). Syscalls are named as **strings resolved at
  runtime** via `seccomp_syscall_resolve_name()` (skipped on `__NR_SCMP_ERROR`) — one table
  serves every arch AND does not fail to *compile* against a libseccomp whose headers
  predate a syscall (this build lacks the `__SNR_openat2`/`__SNR_epoll_pwait2` macros the
  compile-time `SCMP_SYS()` would need); this also keeps INVARIANT #12 (VFS seam) clean
  since every syscall name is a string literal, never a call. Built behind
  `-DBRIX_HAVE_SECCOMP` (config probes `pkg-config libseccomp`, else a `-lseccomp` link
  probe); **without libseccomp the wrapper fails closed** for audit/enforce so an operator
  never silently serves unfiltered. GOTCHA (build): a new `.c` in the source list needs a
  full `./configure` re-run, not just `make`. GOTCHA (test infra): run the integration test
  against an alternate binary via `TEST_NGINX_BIN=<path>` — this lets D-3 be verified from a
  private build tree without relinking the shared standing-fleet binary under running
  workers (the `live_suite_frozen_nginx` hazard). Verified: C unit `tests/c/test_seccomp.c`
  7/7 (execve+ptrace SIGSYS-killed under enforce, `chroot` EPERM'd not killed = fail-safe
  proof, allowlisted `getpid` survives, audit never kills, off is a no-op, installed counts
  = non-empty allow + exactly 5 deny) + integration `tests/test_seccomp_enforce.py` 3/3
  (a real worker round-trips live kXR `stat` + `xrdcp` GET + PUT under **both** enforce and
  audit — allowlist-completeness proof — with the `worker syscall filter active (mode=…)`
  NOTICE logged; `brix_seccomp bogus` refused by `nginx -t`). Clean full rebuild links
  `-lseccomp`; VFS seam guard OK. Reference `[R74]` in the hyper-hardening plan.
- **FINDING-NEGCACHE-1 / hyper-hardening E-4 (landed, 2026-07-18):** metadata-harvesting
  (repeated `kXR_stat`/`kXR_locate` on non-existent paths) and floods were rate-limited by
  **IP only, not authenticated identity** (CWE-770 resource-exhaustion / enumeration).
  Landed in two independent parts. **Part 1 — subject-keyed rate limiting.** The Phase-25
  leaky-bucket limiter already keyed on identity dimensions incl. the GSI subject DN; added a
  sixth `BRIX_RL_KEY_SUBJECT` (`key=subject`) keying on the WLCG/JWT token `sub` claim so a
  *token*-authenticated flood is throttled per-identity, not just per-IP. Mirrors the DN
  recipe exactly: enum value in `ratelimit.h`; `rl_key_sub_hash()` emitting `sub:<8 hex>`
  (FNV-1a32 so the raw subject never reaches a metric label — INVARIANT #8) with the
  invariant-5 IP fallback for anonymous; stream + HTTP key builders; and the `"subject"`
  parser token. **Part 2 — negative-path backoff (the new defense).** New opt-in stream
  directive `brix_negcache_backoff off | <threshold> <window_seconds> <wait_seconds>`
  (default off). A per-principal (token subject → GSI DN → client IP) SHM direct-mapped
  sliding-window counter of *missing-path* lookups: once a principal crosses `threshold`
  misses inside `window`, the slot **arms** and the core paces it to at most one served miss
  per `wait` interval — every excess miss returns `kXR_wait`. The design turns on the stock
  XRootD client's `kXR_wait` semantics (sleep, then re-send the *same* request): each lookup
  still **completes** on its retry one interval later (no request is ever wedged, unlike a
  naive "wait on every miss" that would loop the client forever on a genuinely-absent path),
  while a harvest loop is throttled to ~one path per `wait`. A legitimate client rarely
  misses, so it never arms; and because enforcement sits only on the `ENOENT`/not-found
  branch, a real file on an over-budget connection still resolves immediately (the throttle
  targets misses, not the principal). Two-file split per the ngx-free-core convention:
  `src/core/negcache/negcache_core.c` is pure arithmetic over a caller-owned slot array (so
  the *shipped* logic is what the C unit drives), `negcache.c` is the thin ngx wrapper owning
  the SHM slot array — slab-allocated via `brix_shm_table_alloc` so it never clobbers the
  slab-pool header (INVARIANT #10) — plus principal-hash derivation and the config setter.
  Fail-open on an unattached zone or misconfigured rule (availability-first). GOTCHA (design):
  answering *every* over-threshold miss with `kXR_wait` hangs the stock client forever on a
  truly-missing path (it retries the same request into the same throttle); the min-interval
  "serve one per `wait`, throttle the rest" model is what makes the throttle both effective
  and non-wedging. GOTCHA (test infra): the raw-wire XRootD client in
  `tests/test_phase25_ratelimit.py` (`_xrd_stat`/status codes) drives the wire directly, and
  two loopback source IPs (127.0.0.1 vs 127.0.0.2 → two distinct principals) prove per-identity
  isolation without needing token infrastructure. Verified: C unit `tests/c/test_negcache.c`
  4/4 (arm→pace→release, window decay, per-principal isolation + 4 fail-open guards, zero-key
  bucketing) + integration `tests/test_negcache_backoff.py` 3/3 (a stat-harvest loop trips
  `kXR_wait` while a real file still stats+opens on the same connection; a second source-IP
  identity is served not throttled; `brix_negcache_backoff abc` refused by `nginx -t`) +
  `test_phase25_ratelimit.py::test_subject_key_wired_and_parses` (SUBJECT markers + both-plane
  `key=subject` parse); full ratelimit suite 24/24; VFS-seam + metric-cardinality gates clean.
  References `[R75]` (negcache) / `[R76]` (subject key) in the hyper-hardening plan.
- **FINDING-MINSEC-1 / hyper-hardening D-1 (landed, 2026-07-18):** protocol-downgrade
  protection. The TLS *version* floor was already good (1.2/1.3-only ctx), but `brix_tls`
  only **advertises** an in-protocol TLS upgrade (`kXR_ableTLS`/`kXR_gotoTLS`) — a client is
  free to finish `kXR_login`/`kXR_auth` in cleartext and then transact, i.e. walk the
  *negotiated session* below the operator's intended posture (CWE-757 downgrade). New
  per-server directive `brix_min_sec_level none|compat|intense` (default `none`) enforces a
  session floor — a **distinct axis** from `brix_security_level`, which governs `kXR_sigver`
  request *signing* (0–4), not transport/identity. **none** = no floor; **compat** = the
  session transport must be TLS-active (`c->ssl->connection` set — true after the in-protocol
  upgrade), else every data/metadata opcode is refused `kXR_error`/`kXR_TLSRequired` (3028);
  **intense** = compat **plus** a non-anonymous identity, so an `auth=none` listener (which
  authenticates nobody) is refused `kXR_NotAuthorized` (3010) even over TLS. Enforced in
  `brix_min_sec_enforce()` (`src/protocols/root/handshake/policy.c`) wired into
  `brix_dispatch()` **after** `brix_dispatch_session_opcode` so the login/auth/protocol/bind/
  TLS-upgrade handshake is never blocked — every opcode reaching the gate is a data request;
  fail-closed shape mirrors `brix_signing_enforce_level`. Pairs with A-1 (upstream TLS peer
  verification) so neither the client nor the upstream leg can be independently downgraded.
  Plumbing: enum `brix_min_sec_levels` (module_enums.c), conf field `min_sec_level`
  (srv_conf_fields_cache.inc, `NGX_CONF_UNSET_UINT`→merge 0), directive
  (directives_security.inc), `BRIX_MIN_SEC_*` macros + decl (handshake.h). GOTCHA (test
  design): the "at/above proceeds" case drives the **genuine in-protocol upgrade** from the
  raw Python client — initial + `kXR_protocol` (which already advertises `kXR_ableTLS` in
  body[4]=0x02) in cleartext, then the `brix_tls` server sets `tls_pending` and switches to a
  server-side TLS handshake, which the client completes (`ssl.wrap_socket`) before finishing
  `kXR_login` inside the tunnel — because the naive shortcut, `listen ... ssl`
  (nginx-terminated TLS) on a brix stream block, **SIGSEGVs the worker** (brix owns TLS via
  the upgrade and does not expect `c->ssl` set at accept; unsupported mode, logged as an
  out-of-scope follow-up). Verified: `tests/test_min_sec_level.py` 4/4 (cleartext-vs-compat
  dropped with `kXR_TLSRequired` on a real readable file · in-protocol-TLS-vs-compat proceeds
  · anonymous-over-TLS-vs-intense `kXR_NotAuthorized` · `brix_min_sec_level banana` refused by
  `nginx -t`); sibling suites (negcache backoff 3, phase-25 ratelimit 24) 27/27 green;
  VFS-seam + metric-cardinality gates clean. References `[R77]` in the hyper-hardening plan.
- **FINDING-MITM-1 / hyper-hardening A-1 (fail-closed default landed, 2026-07-18):** the two
  outbound TLS legs — the redirector's `kXR_gotoTLS` upgrade (`brix_upstream_tls`) and the
  terminating tap proxy (`brix_tap_proxy_upstream_tls`) — both re-send the client's
  `kXR_login` over the upstream channel after the handshake. The peer-authentication crypto
  (context `SSL_VERIFY_PEER` + `X509_VERIFY_PARAM_set1_host`, pre-handshake `SSL_set1_host`,
  and a belt-and-braces `SSL_get_verify_result() != X509_V_OK` abort in each handshake-done
  callback — `[R1]`–`[R12]`) was already in the tree, but only fired **when a CA was
  configured**; a leg turned on WITHOUT a CA emitted a `[warn]` and proceeded UNVERIFIED —
  MITM-able (CWE-295). Loading a trust store without `SSL_VERIFY_PEER` is inert (OpenSSL
  clients default to `SSL_VERIFY_NONE`), and a completed handshake means only "a TLS session
  exists," not "the peer is trusted." **Fix:** `brix_server_setup_tls()` now **fails closed** —
  a TLS leg that is on without a CA is refused at `nginx -t` (`emerg`) on both legs, gated by
  new flags `upstream_ssl_verify` / `proxy.upstream_ssl_verify` (directives
  `brix_upstream_tls_verify` / `brix_tap_proxy_upstream_tls_verify`, default **on**); the loud
  `..._tls_verify off` opt-out is the only way past the gate (documented legacy-interop escape
  hatch, still `[warn]`s). The proxy leg also gained the previously-missing
  `brix_tap_proxy_upstream_tls_ca` / `_name` directives — the CTX fields existed and were
  merged but had no parser, so proxy-leg verification was unconfigurable. No shipped or test
  config enables `upstream_tls` today, so nothing regresses. Verified:
  `tests/test_upstream_tls_verify.py` 11 green (5 source-assert holding the R1–R12 crypto +
  6 config-gate: CA-present accepted, no-CA refused with the exact `refusing an
  unauthenticated` reason, explicit `..._tls_verify off` accepted — across both legs); VFS-seam
  + metric-cardinality gates clean. The live-MITM handshake negatives (untrusted-chain /
  wrong-host abort with no `kXR_login` leak) rest on the already-landed crypto plus a
  fake-TLS-origin fixture, deferred. References `[R79]` in the hyper-hardening plan.
- **FINDING-OCSP-NONCE-1 / hyper-hardening A-6 item 2 (missing-nonce hard-fail landed,
  2026-07-18):** the GSI OCSP client builds each request with an anti-replay nonce
  (`OCSP_request_add1_nonce`), but the nonce was never actually checked in the mainline:
  `do_ocsp_request()` freed the `OCSP_REQUEST` before returning, so `check_ocsp_response()`
  always ran with `req_for_nonce == NULL` and its nonce branch was dead code. A signed,
  still-valid, nonce-less GOOD response captured off the (typically plaintext-HTTP) OCSP
  fetch could therefore be replayed past the revocation check (CWE-294). **Fix:**
  `do_ocsp_request()` now hands the built request back to the caller via an
  `OCSP_REQUEST **req_out` out-param (pre-cleared to NULL, freed on every failure path,
  set only on success); the two live sites in `ocsp.c` own and free it after verify.
  `check_ocsp_response()` gained an `int require_nonce` gate: when set, a response that
  omits the request nonce (`OCSP_check_nonce < 0`) frees the BASICRESP and returns -1
  (deny) rather than warning through — a nonce *mismatch* (`== 0`) already denied and still
  does. Wired to `brix_ocsp_conf_t.require_nonce` (init `NGX_CONF_UNSET`, merge default
  **0/off**) and the new `brix_ocsp_require_nonce on|off` stream directive, threaded
  `auth.c → brix_ocsp_check_cert → ocsp_check_urls`; the staple-fetch loop passes
  `require_nonce = 0`. **Default OFF, deliberately**: most CA OCSP responders serve
  pre-signed, nonce-less responses (RFC 5019 lightweight profile), so a hard-fail-by-default
  would break real-world revocation checking — the operator opts in, mirroring the D-2
  `brix_opaque_strict` precedent. Verified: `tests/test_ocsp_require_nonce.py` 8 green
  (request threaded out · mismatch always denies · missing-nonce denies only when required ·
  conf default-off · directive registered · `nginx -t` on/off parse + non-flag rejected);
  VFS-seam + metric-cardinality gates clean (no data-path or metric change). References
  `[R80]` in the hyper-hardening plan.
- **FINDING-AUTHZ-SENTINEL-1 / hyper-hardening C-3 (audit + guard landed,
  2026-07-18):** the response helpers `brix_send_ok`, `brix_send_error` and
  `BRIX_RETURN_ERR` all return `NGX_OK` — meaning "wire response queued / handled",
  NOT "authenticated" — so any handler that read a bare `NGX_OK` as "verified,
  continue" would be an auth bypass (CWE-697/CWE-288); the class had two historical
  instances (the SSS deny→NULL-deref bypass funnelled to `NGX_DONE`, and a proxy
  branch that gated on `logged_in`, an intermediate step, not the verdict). **Audit
  (2026-07-18):** the design is sound — the session verdict is a single flag,
  `ctx->login.auth_done`, and the authorization choke point gates on it, never on a
  return code: request processing is unreachable until `handshake/policy.c` confirms
  `logged_in && auth_done`, and the proxy branch (`handshake/dispatch.c`) gates on
  `auth_done`. All nine sites that raise the verdict sit on a verified-success path —
  the seven credential handlers (`auth/{gsi/auth,gsi/token,host,krb5,pwd,sss,unix}`)
  set it only after their deny path has `BRIX_RETURN_ERR`'d out, and the two
  session-plane sites are legitimate: anonymous login (`session/login.c`,
  `gsi/auth.c` `BRIX_AUTH_NONE`) and secondary-stream bind (`session/bind.c`, which
  inherits the primary's verified state only after the sessid is confirmed in the
  registry — the deny at the registry-miss returns `kXR_NotAuthorized` early). No
  live instance. **Regression guard:** `tools/ci/check_auth_verdict_sentinel.sh`
  (wired into `.github/workflows/guards.yml`) confines `login.auth_done = 1` to those
  nine sanctioned files — a new proxy/TPC/dispatch/op site that marks a session
  authenticated fails CI, forcing the assignment into an auth handler where the
  verified-success precondition is reviewable; the guard takes an optional scan-dir so
  its own tests can inject a synthetic tree. Verified: `tests/test_source_guards.py`
  (real tree clean, sanctioned setter passes, rogue-proxy setter refused). References
  `[R81]` in the hyper-hardening plan.
- **FINDING-FUZZ-LANE-1 / hyper-hardening B-3 (CI fuzz lane landed + a rotted harness
  found, 2026-07-18):** three libFuzzer harnesses live under `tests/fuzz/`
  (`fuzz_zip_dir` = ZIP central-directory walk, `fuzz_b64url` = JWT base64url,
  `fuzz_safe_size` = allocation-size guards) with committed corpora and a
  `cmdscripts.fuzz_all` runner, but **nothing ran them in CI** — so nobody noticed one
  had stopped building. `fuzz_zip_dir` is a unity build that `#include`s
  `src/fs/backend/posix/sd_posix.c`; a concurrent refactor split the raw fd byte ops
  (`sd_posix_pread/_pwrite/_preadv/_preadv2/_copy_range/_read_sendfile_fd/_ftruncate/
  _fsync/_fstat`) out into `sd_posix_io.c`, leaving the `brix_sd_posix_driver` vtable's
  io slots unresolved at link — the harness had been silently un-buildable since the
  split. **Fix:** add `#include "…/posix/sd_posix_io.c"` to the harness's unity-build
  set (the namespace ops in `sd_posix_ns.c` stay compiled out under `XRDPROTO_NO_NGX`,
  so only the io TU is needed); all three harnesses now build + fuzz clean. **Gate:**
  `.github/workflows/fuzz.yml` — a **blocking** PR/push smoke (`FUZZ_TIME=60` per
  harness) plus a nightly cron soak (`600s`), both driven through the existing
  `python3 -m cmdscripts.fuzz_all` runner so CI and the local
  `PHASE81_RUN_FUZZ_PORT=1 pytest tests/test_cmd_fuzz_all.py` share one build path. This
  lane is blocking (unlike the advisory `fanalyzer.yml`) because the harnesses are
  self-contained deterministic clang builds with no version-sensitive baseline. Corpus
  minimize-and-commit-back (so coverage compounds across runs) is deferred — it needs a
  git-write CI bot, to be added under its own review. The rot-then-catch is itself the
  argument for the gate: an un-run harness is not a harness. LESSON: any unity-build
  test target that `#include`s a driver `.c` must be re-checked whenever that driver is
  file-split — the vtable references outlive the file that defined its members.
- **Weak-symbol credential-store linkage (found+fixed 2026-06-26 via the
  clientconf suite):** `xrdc_cred_store_new` (`client/lib/cred.c`)
  registers credential handlers (x509/bearer/sss/krb5/s3keys) through
  **weak** accessors (`if (xrdc_cred_x509 != NULL) ...`). A weak *undefined*
  reference does not pull the defining object out of the static
  `libxrdc.a` archive, so any tool that links `libxrdc` as a plain archive
  (rather than with `--whole-archive`) silently gets a credential store
  with **zero handlers**, and `xrdc_cred_available()` always returns 0. This
  broke `xrdcp` specifically: it sets `conn.cred = cred_store`, and the sec
  modules' `*_have()` checks consulted the (empty) store first and returned
  its verdict verbatim, so GSI was skipped entirely — `auth.c:166` "no
  usable auth protocol for server list &P=gsi,...". `xrdfs` was immune
  because it never sets `conn.cred` and falls through to the env
  `access()` path. **Diagnose with `nm client/bin/xrdcp | grep
  xrdc_cred_x509`** — a bare `w` (no address) means undefined weak /
  handler absent; `T` means it's actually linked. Two fixes landed: (1) a
  linkage anchor in `client/lib/cli_cred.c` — strong references to all five
  handler-getters in a `__attribute__((used))` array, forcing their `.o`
  into any link that builds a CLI credential store; (2) fallback symmetry
  in `sec_gsi.c`/`sec_token.c`/`sec_sss.c` `*_have()` — a store *miss* now
  falls through to env/default discovery instead of returning a hard no,
  matching what `gsi_more` already did, so auth degrades gracefully even if
  the store is empty for some other reason in the future. Verified: xrdcp
  GSI/TLS went from 142-fail to 0-fail (284 passed); full clientconf suite
  812 passed / 0 failed. **If you add a new cred-store tool or a new
  handler type, re-check with `nm` for `T`, not `w`.**
- **`kXR_endsess` de-authenticated the wrong connection (server bug, fixed
  2026-06-21):** `src/session/lifecycle.c`'s `xrootd_handle_endsess`
  unconditionally cleared `logged_in`/`auth_done` (and closed open files)
  regardless of which session ID the `kXR_endsess` request actually named.
  The official XRootD client's reconnect-recovery flow opens a *new*
  connection, logs in fresh, sends `kXR_endsess{OLD_sessid}` to release its
  dead previous session, then issues its recovery `kXR_open` — and the
  buggy handler was de-authing the *freshly authenticated* connection in
  response, so the recovery open failed with `kXR_NotAuthorized` (3010).
  This broke official `xrdcp`/`xrootdfs` reconnect recovery on any lossy
  link (official `xrootdfs` failed even at 1% simulated packet loss).
  **Fix: `kXR_endsess` is now session-scoped**, per protocol — if the
  request's sessid doesn't match the connection's own, it only does an
  idempotent cross-worker `xrootd_session_unregister(req->sessid)` and
  replies ok, leaving *this* connection's auth and open handles intact.
  Full teardown (proxy-forward disconnect, `close_all_files`,
  `logged_in=auth_done=0`) now only happens when a connection ends its
  *own* session — preserving the GSI-proxy-expiry / session-end security
  property that the original code was presumably trying to implement.
  Diagnosed via official `xrdcp` with `XRD_LOGLEVEL=Dump` plus a
  `fault_proxy` "drop" mid-transfer, reading the XrdCl log's
  reconnect→login→endsess(old)→open→3010 sequence. Regression test:
  `tests/test_endsess_session_scope.py` (proven to fail on the pre-fix
  binary with err 3010, pass on the fix). After the fix, official-client
  recovery was verified up to 5% loss; **10–15% loss failures remain, but
  that is the *official client's* own resume-model limitation** (it
  re-reads the whole request with no offset-resume on every severed
  connection — it fails at the same loss rates against a stock xrootd
  server too), not an nginx-xrootd regression.

---

## Part 4 — Feature inventory: what shipped, current status

| Feature | Status | Key files/directives | Notes |
|---|---|---|---|
| XrdAcc authorization port | All 9 milestones done, validated; 7 residual parity gaps (RA1–RC1) also closed | `src/acc/`, `xrootd_authdb_format xrdacc` | Dual-engine — native format unchanged, xrdacc is opt-in. See below. |
| Per-user backend credentials (Ph 1–3) | Implemented, tested, reviewed ready-to-merge — check current git log for merge status | `src/fs/backend/ucred.c`, `src/fs/vfs/vfs_cred.c`, `brix_sd_cred_t` (`sd.h`) | See dedicated section below. |
| Credential-forwarding matrix (normal access) | Done — 16 PASS/4 GAP/4 SKIP, gaps are upstream stock limitations | `tests/lib/fwd_matrix.sh`, ports 21960-21999 | See narrative above. |
| TPC credential forwarding | Done, default-on | `brix_tpc_outbound_passthrough`, `brix_webdav_tpc_credential_forward` | Opportunistic-by-default per Rob's decision. |
| Native TPC over GSI | Mostly fixed, one source-model gap open | `src/tpc/`, `src/gsi/gsi_core.c` | **See OPEN ITEM at top of this doc.** |
| X.509 proxy delegation (F6) | Code-complete, e2e unverified | `xrootd_tpc_delegate` directive | Needs a real grid host to fully verify; WSL2 rig can't complete the `usedDNS` check. |
| GSI signed-DH (server) | Done, stock-verified both directions | `xrootd_gsi_signed_dh off\|auto\|require` | 220 tests, 0 skips. |
| GSI cipher negotiation (WS-A) | Done, stock-verified | `xrootd_gsi_ciphers` | Bare cipher names on the wire — no IV-length suffix. |
| XrdSecpwd (WS-B) | Done, our-client↔our-server only | — | Stock byte-interop is a documented follow-on, not done. |
| Host auth (WS-C) | Done, stock-verified | — | |
| Impersonation (privileged broker) | Fully implemented, off by default, red-teamed 9 rounds | `docs/06-authentication/impersonation.md` | Boundary never breached; see Part 1. |
| Bad-actor MITM guard | Fully implemented, committed to main | `src/net/guard/`, `src/net/httpguard/`, `xrootd_guard*` | fail2ban integration included. |
| Token L1 cache | Done | `src/token/worker_cache.{c,h}` | Fixes HTTP ReadTimeout under load; see below. |
| SRR (WLCG Storage Resource Reporting) HTTP endpoint | Done | `src/srr/`, `xrootd_srr` | Deliberate replacement for UDP f/g-stream monitoring — see decision table. |
| WebDAV upstream proxy | Done (foundational, Phase 21 era) | `src/webdav/proxy.c`, `xrootd_webdav_proxy` | See Phase 21 narrative. |
| Hybrid-mesh HTTP/root:// single-port handoff | Done | `src/handoff/handoff.c`, `xrootd_http_handoff` | Lets a stock redirector's data-port HTTP redirect reach an nginx data node. |
| `xrootd_webdav_proxy` → stock XrdHttp backend | **Open bug** — intermittent heap corruption / SIGSEGV | `src/webdav/proxy_response.c` | Needs ASan repro; see hybrid-mesh narrative above. |

### XrdAcc authorization port — key faithful-port facts

Full detail: `docs/06-authentication/authorization-xrdacc.md`,
`docs/06-authentication/authorization.md`. Engine: `src/acc/`, selected via
`xrootd_authdb_format native|xrdacc` (native remains the default). It
authorizes root://, WebDAV, and S3 through one shared decision path,
`xrootd_acc_access`, with full OS/NIS group parity (Unix gidlist, netgroups,
gidlifetime cache). Directive-registration gotcha hit while wiring this up:
the WebDAV and S3 modules both tried to register
`xrootd_authdb_format`/`_audit`/`xrootd_authdb` — nginx only applies the
*first* registrant's setter, so S3's loc-conf silently never got configured.
Fixed by registering each directive once with a shared custom setter that
populates both loc-confs.

Facts worth keeping (verify current line numbers against `src/acc/privs.c`
/`access.c` before citing them in review, since they will drift):

- XrdAcc's 9-bit privilege model (`a/d/i/k/l/n/r/w` plus `-` negation) is
  **additive across all matching identities** (`pprivs & ~nprivs`) — this
  is a real semantic difference from the native engine's single
  longest-prefix rule, which has no negation at all.
- `r` does **not** imply `l` in XrdAcc, unlike native.
- Match order: exclusive → default → domain → host → netgroup → fungible →
  user → per-(vorg × role × group).

Residual-gap closures worth remembering if touching this area again:
create-vs-update semantics only map `kXR_new` (`O_CREAT`) to `AOP_Create`
(needs the `i` privilege) — `kXR_delete` used as a truncate (e.g. `xrdcp
-f`) is still `AOP_Update`, matching stock `XrdOfs.cc`. `STAT` needs `l`
(lookup) not `r` — an authdb without `l` denies the client's pre-open stat
and masks whatever the real open-time result would have been, which reads
confusingly if you don't know this. TPC and `prepare` both route through
`xrootd_authz_check(ctx, c, conf, reqpath, resolved, ...)`, which takes
*both* paths because xrdacc keys off the logical `reqpath` while native
keys off the backing-filesystem `resolved` path — passing only `full_path`
silently breaks matching like `u * /pub a`. The auth-decision cache had to
gain the XrdAcc operation type and peer host into its cache key
(`xrootd_auth_gate_cache_key`), because without it a cached Update grant
would leak into granting a Create on the same path — native passes
`AOP_ANY`+empty host so its cache keys are unaffected.

### Per-user backend credentials (Phases 1–3)

davs/S3 requests authenticated as user U now authenticate the *origin*
session as U's x509 proxy, token, S3 key, or Ceph keyring — falling back to
the static service credential per configured policy — rather than always
speaking to the backend as the node's own service identity. Plans:
`docs/superpowers/plans/2026-07-08-per-user-backend-credentials{,-phase2}.md`,
`docs/superpowers/plans/2026-07-09-per-user-backend-credentials-phase3.md`.
Reference doc: `docs/10-reference/per-user-backend-credentials.md`.

This directly explains a "why does this fail" support scenario worth
keeping visible: **davs/S3 writes to a remote xroot backend fail with
"cache origin requires authentication" unless a delegated proxy or the
static service credential is configured — this is architectural, not a
conformance bug.** Front-door auth (client → nginx) never itself requires a
proxy: davs:// accepts EEC/proxy/bearer credentials and is gated only on
`allow_write`; S3 is SigV4/bearer. The requirement lives on the *backend*
leg — `sd_xroot` staged/write opens run `brix_cache_origin_bootstrap()`
(`src/fs/cache/origin_protocol.c:177-191`), and if the remote origin
advertises GSI with no `cache_origin_x509_proxy`/storage credential
configured, the bootstrap fails with `kXR_AuthFailed`. Reads bootstrap the
same way but often survive via cache hits or an anonymous-read origin
policy, which is why the symptom looks write-only even though the
underlying cause applies to both. Before per-user credentials existed, this
was *always* a static service proxy (the node speaking as its own identity,
e.g. `xrd`) — true per-user delegation to the backend on the plain VFS
write path did not exist prior to phase 70 (GSI delegation forwarding
previously lived only in `src/net/proxy/gsi_upstream_login.c`, for the
root:// tap proxy specifically). Also: a stale header comment in
`src/auth/crypto/gsi_verify.h` claims WebDAV rejects proxy chains — the
actual implementation (`gsi_verify.c` ~line 193) explicitly accepts RFC3820
proxy chains on davs://. Don't trust that header comment.

Design seams worth knowing before extending this: origin sessions in
`sd_xroot` are fresh connect+bootstrap per open, so per-user auth is
implemented as a per-open credential override on `brix_cache_fill_t`, not
as connection-pool keying (see the decision table above).
`brix_sd_cred_t` (`src/fs/backend/sd.h`) carries x509 proxy/key, bearer
token, S3 access/secret key + region, Ceph keyring, principal, cred_dir,
and a fallback_deny flag; selection logic is in
`src/fs/backend/ucred.c`, and the VFS-side gate is
`src/fs/vfs/vfs_cred.c`. New directives: `brix_storage_credential_dir
<dir>`, `brix_storage_credential_fallback allow|deny` (default allow),
`brix_delegation_endpoint`, `brix_storage_credential_mint_ca`/`_mint_ttl`.
Async credential ownership is persisted in the stage journal
(`brix_stage_cred_t` appended to `brix_sreq_t`, with a size-tolerant decode
for legacy records that predate this field). Phase-1 gaps (namespace-op
leaf-unwrap, bearer `.token` credentials, per-select metrics, flush
dead-letter handling, root:// stream credentials, per-user sd_http/sd_s3/
sd_ceph, delegation upload + two-step GridSite delegation, root:// origin
dirlist) were all closed by phases 2/3. Remaining open follow-ups (not
blockers): full GridSite two-step delegation still returns 500 instead of
403 in one LOCK-write edge case; a "WARN when the `_cred` slot is missing"
forwarder log is a nice-to-have, not required, since the refuse-EACCES path
already covers the underlying case. `sd_ceph` per-user support was
live-tested against a real cluster (LRU-cached rados connection per
`(user, keyring)`, 8 slots) and had two review-caught use-after-free/leak
bugs fixed with a reproduction proving the fix.

### Token-auth L1 cache (2026-06-23)

Bearer-token validation (RSA/ECDSA verify + base64url decode + JSON parse)
ran inline on the single-threaded nginx event loop per request. The only
existing cache (`token_cache.c`, `xrootd_token_cache_*`) was opt-in (needed
an explicit `xrootd_kv_zone` + `xrootd_token_cache zone=`, so most
deployments had no caching at all) and took a per-zone `ngx_shmtx` spinlock
on every single lookup/store, causing cross-worker contention. Under load
this starved the event loop and produced client-visible HTTP
`ReadTimeout`s. JWKS itself is file-based with an mtime-poll timer, so no
request-path network fetch was ever the cause.

**Fix:** an always-on, per-worker, lockless L1 direct-mapped cache
(`src/token/worker_cache.{c,h}`, `XROOTD_TOKEN_L1_SLOTS=1024`, roughly
4.5MB/worker, keyed by SHA-256(token), entry TTL = `min(exp, now+5min)`). An
L1 hit skips both the crypto verification and the L2 spinlock entirely.
It's wired as L1→L2→validate in both HTTP WebDAV
(`src/webdav/auth_token.c`) and stream root:// (`src/gsi/token.c`); an L2
hit gets promoted into L1. The cache is created lazily per-conf
(`conf->token_l1 = xrootd_token_l1_create(...)`, copy-on-write private per
worker, same pattern as `cms_ctx`) and is **per-conf**, so issuer,
audience, keys, and secret all scope it correctly — claims never leak
across server/location blocks. Only successful validations are cached; the
failure path is unchanged. The per-validation ~2.5KB INFO log-string build
in `validate.c` was also gated behind `log->log_level >= NGX_LOG_INFO` as a
side-fix.

Gotcha specific to testing this: the 8443 WebDAV test port is `auth
optional` with anonymous write enabled (anonymous PUT returns 201), so a
rejected token silently falls through to anonymous access and rejection
becomes unobservable over HTTP on that port — assert token rejection on the
*stream* port instead (`test_token_auth.py` does this correctly;
`test_token_cache_l1.py` covers the caching behavior itself: repeated-auth,
cached-read-denied-write=403, write-cached, distinct-tokens).

### SRR (WLCG Storage Resource Reporting) HTTP endpoint

See the decision table above for *why* this exists instead of the UDP
monitoring stack. Implementation: `src/srr/` — `module.c` (directives +
loc-conf + handler bind), `builder.c` (jansson document construction +
per-share `xrootd_fs_usage_stat()` statvfs), `handler.c` (GET/HEAD,
`application/json`). Serves the standard `storageservice` JSON document
(schema v4.x) that CRIC, WLCG storage-space accounting, and DIRAC occupancy
plugins scrape directly. Notable hardening: the document is a **pure
function of config + filesystem state — no request input reaches it**
(query/header injection can't redirect the statvfs'd path), every nested
JSON container is NULL-checked so an OOM produces a 500 rather than a
partial-but-200 document a harvester might ingest as valid, and
`srr_clamp_size()` clamps reported sizes to `INT64_MAX` with a saturating
capacity sum to avoid emitting negative JSON integers. Known limitations,
documented rather than fixed: `usedsize` is filesystem-level, not
per-VO; same-filesystem shares double-count in the reported capacity; the
reported path is the configured local path, not necessarily what the
harvester expects externally.

---

## Part 5 — Recurring test-harness gotchas across this whole area

These cost real time more than once and are easy to hit again on any future
auth/credential test work, so they're collected here rather than left
scattered per-suite:

- **A GSI cluster failing with "certificate verification failed" or "GSI
  not ready" is very often a stale expired proxy, not a real regression.**
  `tests/resilience/servers.py::ensure_pki()` originally only regenerated
  PKI material when files were *missing*, never when a cached proxy had
  simply *expired* (RFC-3820 user proxies default to ~12h lifetime). Fixed
  by adding `_proxy_valid()` (`openssl x509 -checkend 300`) and
  regenerating on expiry as well as absence — this fixed all 16 affected
  GSI resilience tests in one change. Debug recipe: spin up a dedicated GSI
  instance via `servers.NginxGsi()`, run both native and official `xrdfs`
  against it, and check `openssl x509 -in proxy -noout -dates` — an expired
  `notAfter` is the tell.
  Related, same root class: `test_mkdir_resilient_creates` under a lossy
  link can legitimately hit `kXR_ItExists` when a first attempt's ack was
  lost after actually succeeding — that outcome is success, not failure;
  the fix accepts `rc==0 OR ItExists` and checks the real state with a
  post-stat.
- **`xrdcp --tpc first` is not a valid TPC gate** — see the OPEN ITEM
  section and `lessons-tpc-vfs.md` §1. Use `--tpc only` whenever you need
  the test to actually fail when server-side TPC breaks.
- **`race_shim.c`** (an `LD_PRELOAD` worker-gated syscall delay) is the
  standing tool for deterministic AIO-race testing; `tests/valgrind/` is
  the standing location for memory-safety suites.
- **Recovering a wedged test fleet:** `pkill -9 nginx; pkill -9 -f
  manage_test_servers`, then relaunch detached with
  `TEST_SKIP_SERVER_SETUP=1`. Use `fuser -k PORT/tcp` for port-specific
  cleanup in the credential-forwarding suites — never `pkill -f`, since the
  driving shell process itself can match the pattern and kill its own
  harness.
- **`readv`/`pgread`/`pgwrite` raw-wire OOB security suite**
  (`tests/test_readv_security.py`, 26 pass/3 skip) is the reference example
  of hostile-request testing at the raw-TCP level — bypassing the XRootD
  Python client's own client-side sanitization to actually exercise server
  input validation (negative offsets, `INT64` overflow, EOF-straddling
  segments, malformed `dlen`, oversized segment counts, stale handles after
  close). Worth reusing this pattern (raw-wire helpers reused from
  `test_wire_protocol_security.py`) for any new opcode's security suite
  rather than relying on the client library, which sanitizes inputs before
  they ever reach the wire.

---

## What was intentionally left out of this document

- The GSI/XrdSecgsi wire-handshake mechanics (signed-DH negotiation order,
  delegation option-bit parsing, rtag proof chains, async-open bounding) —
  fully covered in `lessons-tpc-vfs.md` and not duplicated here.
- SNI-vs-hostname-verification, constant-time comparison rules, and the
  confinement-boundary-drift audit methodology — fully covered in
  `lessons-security-reaudit-and-cleanup.md`.
- `webdav_proxy` memory entry duplicated the phase-21 gotchas already
  captured under "Phase 21" above; nothing else in it had lasting value
  beyond the directive-reference table, which is better sourced from
  current docs than repeated here.
