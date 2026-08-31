# Phase 106 — nginx-native integration surface: make brix legible to nginx's own tooling

Source: integration survey of 2026-08-29 run against `main` @ `875a4e6db`
(post phase-105 W1–W5, post the 2026-08-29 test-suite commit). Every claim
below was measured against the working tree on that commit; each "Current
state" section lists the greps and the file:line evidence it rests on. This
phase deliberately does NOT re-open ground already closed by
`phase-21-subrequests-upstream-filters.md` (✅ implemented),
`phase-22-stream-health-checks.md` (✅), `phase-23-dynamic-upstreams.md` (✅),
`phase-24-traffic-mirroring.md` (✅) or `phase-25-rate-limiting.md`
(✅ implemented 2026-06-13) — see **Non-goals** for the explicit boundary
against each.

**Goal.** brix is a first-class nginx module by construction — 15 modules
(11 `NGX_HTTP_MODULE`, 4 `NGX_STREAM_MODULE`), a real directive surface with
its own registry checker, real filters, real SHM zones. But it is **opaque to
nginx's own tooling**. An operator who knows nginx cannot use what they know:
they cannot log whether a request was a cache hit, cannot `map` on brix state,
cannot route on it, cannot put brix's authz in front of a location brix does
not serve, and cannot hand a staged file back to nginx's own static path. The
data plane is excellent and the *integration* plane is thin.

This phase closes that gap in the order that yields value soonest: the
variable surface first (days of work, immediately usable by every operator and
every third-party module), then the handoff/authz seams that make brix
adoptable *incrementally*, and only then the transport question — which is
scoped here as a decision study, not a blind rewrite.

| WS | Item | Verdict | Size |
|----|------|---------|------|
| W1 | HTTP variable surface: `$brix_cache_status` and the core request-state set; fix the unprefixed `cvmfs_*`/`oci_*`/`rpm_*` names | ✅ DONE (see Appendix F) | M |
| W2 | Stream (`root://`) variable surface: currently **zero**; the flagship protocol is invisible to `access_log` | ✅ DONE | M |
| W3 | `X-Accel-Redirect` / internal-redirect handoff: let brix hand a staged file to nginx's static path, and let brix front a non-brix upstream | ✅ DONE (both halves) | M–L |
| W4 | `auth_request`-compatible authz endpoint: expose WLCG/VOMS/token/macaroon authz to non-brix locations | ✅ DONE | M |
| W5 | Origin/auth HTTP transport convergence **study**: libcurl vs `ngx_http_upstream`; includes the blocking-`curl_easy_perform`-on-a-request-path audit | ✅ STUDY COMPLETE (audit + matrix + recommendation); rewrite = phase 109 | L (study S) |
| W6 | Conditionals/Range/ETag: audit what can defer to nginx's own filters vs what must stay bespoke | ✅ AUDIT DONE (no convergence needed) | S–M |
| W7 | `load_module` (DYNAMIC) conformance for all 15 modules + variable registration under dynamic load | ✅ DONE | S |
| W8 | Governance: extend `check_directive_registry.py` with variable rules (naming, documentation, plane parity) so the W1/W2 surface cannot drift | ✅ DONE | S |

Standing rules — restated because they bind every workstream here, identical
to phases 101/105: no git write commands without explicit OP approval
in-conversation; **3 tests per change-class (success + error + security-neg)**;
no `goto`; HELPERS over reimplementation; CCN ≤15 / cognitive ≤10 / npath ≤15 /
600-line ratchets live (extract helpers, never grandfather); new `src/` TUs →
repo-root `./config` + `bash -n config` (`check_config_coverage.py` enforces),
new `client/` TUs → `client/Makefile` (`check_client_build_coverage.py`); every
new user-visible name lands its row in `docs/03-configuration/` in the SAME
commit.

**ABI trap** (memory: `struct_field_abi_clean_rebuild`). W1 and W2 add a
per-request/per-session context field or widen an existing ctx. Treat every
commit that touches `brix_ctx_t` or a module ctx struct as an **ABI-dirty
rebuild**: delete the affected module `.o` files before rebuilding. Stale
objects with skewed offsets have previously produced phantom auth failures
that look like logic bugs.

**Variable-handler trap (new, binding on W1/W2).** A variable get_handler runs
on the request path, in the log phase, and possibly *after* the request body
and ctx pool are gone. Three rules follow, and every W1/W2 handler must state
which it takes: (i) a handler MUST NOT allocate from a pool that may already
be freed — prefer `ngx_http_variable_value_t` pointing at a `static const`
string or at memory owned by the request pool that outlives the log phase;
(ii) a handler MUST tolerate `ctx == NULL` (the request never reached brix, or
was rejected in an earlier phase) and return `not_found`, never crash — the
existing `cvmfs_var_cache` does this correctly at
`src/protocols/cvmfs/module.c:167` and is the model; (iii) anything derived
from TLS/identity is per-request-cacheable, anything derived from the data
plane is NOT (`NGX_HTTP_VAR_NOCACHEABLE`) — the existing split at
`src/protocols/webdav/module_init.c:281` vs `:290` is the precedent and its
reasoning ("the TLS identity cannot change mid-request") is correct.

**Security trap (binding on W1, W2, W4).** Variables are an *exfiltration
surface*: anything exposed becomes loggable, `add_header`-able and
`proxy_set_header`-able by an operator who may not realise what it contains.
`$brix_delegated_cred` already exists and is a delegated credential. No
W1/W2 variable may expose bearer-token material, macaroon secrets, private-key
bytes, or a raw `Authorization` value. Identity variables expose the *subject*
(DN, VO, issuer, sub) — never the credential that proved it. Each proposed
variable in Appendix A carries an explicit exposure verdict, and the W1
security-negative test asserts the refusals.

---

## Non-goals — the explicit boundary against already-closed phases

These are recorded so a later reader does not "helpfully" re-open them.

1. **Rate limiting is NOT converging on `limit_req`.** `src/net/ratelimit/` is
   a deliberate implementation delivered by `phase-25-rate-limiting.md`
   (Status: IMPLEMENTED 2026-06-13, ≈2,200 LoC). Its own header notes it
   mirrors `ngx_http_limit_req_module`'s leaky-bucket formulation and node
   lifecycle (`src/net/ratelimit/ratelimit.c:4`,
   `src/net/ratelimit/ratelimit_zone.c:6`) — that is convergence of *design*,
   which is the right level. brix needs per-VO/per-DN/per-token limiting that
   `limit_req_zone` cannot express without the variables W1 introduces. The
   **only** phase-106 interaction is the reverse direction: once W1 lands,
   `limit_req_zone $brix_vo` becomes possible for operators who want nginx's
   engine for a simple case. No code moves.

2. **The `root://` outbound client is NOT moving to `ngx_http_upstream`.**
   `src/net/upstream/` is a hand-rolled, fully non-blocking XRootD *protocol*
   client (handshake → protocol → TLS upgrade → login → token auth → relay one
   opcode), entered from `src/protocols/root/read/locate.c` and
   `open_request.c` when a local lookup misses. `ngx_http_upstream` is
   HTTP-only and cannot carry the XRootD wire protocol. This subsystem is
   correct as built. W5 concerns the **HTTP** origin/auth transports only.

3. **Multi-backend WebDAV proxy selection is NOT being redesigned.**
   phase-21 step D delivered round-robin with passive health skip, and
   phase-23 delivered the dynamic pool. W5's study must *record* that these
   exist and reconcile against them; it must not propose replacing them
   without an OP decision.

4. **Traffic mirroring is done.** `src/net/mirror/` already uses the
   `ngx_http_upstream` framework (`http_mirror.c`, `http_mirror_request.c`) —
   it is, notably, the ONE place in the tree that does, which makes it the
   reference implementation W5 should study rather than a gap to fill.

---

## W1 — HTTP variable surface

### Current state — the full evidence chain

`ngx_http_add_variable` is called in exactly **five** places tree-wide:

| Site | Variables registered |
|------|----------------------|
| `src/protocols/webdav/module_init.c:281` | `$brix_protocol` (NOCACHEABLE) |
| `src/protocols/webdav/module_init.c:290` | `$brix_delegated_cred` (per-request cacheable) |
| `src/protocols/cvmfs/module.c:215` (array at `:202`) | `$cvmfs_class`, `$cvmfs_cache`, `$cvmfs_origin` |
| `src/protocols/oci/oci_module.c:304` (array at `:291`) | `$oci_class`, `$oci_cache` |
| `src/protocols/rpm/rpm_module.c:138` (array at `:125`) | `$rpm_class`, `$rpm_cache` |

That is the entire variable surface: **9 variables, 7 of them unprefixed, none
of them covering the core data plane.** Consequences, each verified:

- **There is no cache-status variable for the main planes.** `$cvmfs_cache`
  exists and is genuinely useful — `cvmfs_var_cache`
  (`src/protocols/cvmfs/module.c:159`) maps `ctx->cache_status` to
  `"-" | "hit" | "fill" | "neg"`. But it is cvmfs-only. An operator serving
  root://, WebDAV or S3 cannot write a `log_format` line that says whether the
  request was served from cache. For a product whose name is *brix-cache*,
  this is the single most conspicuous gap in the integration surface.
- **The vocabulary diverges from nginx's.** nginx's `$upstream_cache_status`
  is `MISS|BYPASS|EXPIRED|STALE|UPDATING|REVALIDATED|HIT`. brix's is
  `-|hit|fill|neg`. Neither an operator's existing dashboards nor any
  third-party log parser will understand the latter.
- **7 of 9 names are unprefixed.** `$cvmfs_class`, `$cvmfs_cache`,
  `$cvmfs_origin`, `$oci_class`, `$oci_cache`, `$rpm_class`, `$rpm_cache` sit
  in nginx's global variable namespace with no `brix_` prefix, while
  `$brix_protocol` and `$brix_delegated_cred` are prefixed. This is exactly
  the ownership/naming drift class phase-101/105 spent two waves eliminating
  from the *directive* surface — the variable surface never got the same
  governance (hence W8). It is also a live collision risk: any other module
  registering `$oci_cache` is a duplicate-variable config error at startup.

### Why this fix shape (and what it costs)

The value is asymmetric. A variable is ~20 lines (a get_handler plus an array
row) and, once registered, is instantly consumable by `log_format`, `map`,
`if`, `add_header`, `split_clients`, `limit_req_zone`, `proxy_set_header`,
`geo`, njs, and every third-party module — none of which brix has to know
about. Nothing else in this phase has that leverage.

The cost is the trap list above (handler lifetime, NULL-ctx, cacheability) and
one genuine design decision: **where does the value come from?**

### The VFS seam is the answer — do NOT invent a new per-request struct

An earlier draft of this plan proposed a new `brix_req_stat_t` attached to the
request. **That was wrong, and the tree already contains the better answer.**

`brix_vfs_ctx_t` (`src/fs/vfs/vfs.h:99-135`) is the single protocol-agnostic
funnel that *all four* front ends pass through. Its own header states the
thesis (`src/fs/vfs/vfs.h:13-18`): "All four front ends (XRootD root://,
WebDAV davs://, the S3 subset, and CMS data-server I/O) funnel through this
one protocol-agnostic surface so confinement, metrics, **access logging**,
page-CRC, and cache integration are implemented once and inherited for free."

Variables are exactly that list's missing sixth member. Implementing them at
the VFS seam means one implementation inherited by every plane — which is also
what makes W2 (stream) tractable at all, and what keeps INVARIANT #12 (the VFS
is the sole storage truth) rather than opening a second source of truth.

The fields are already there:

| Need | Field | Where |
|------|-------|-------|
| cache hit/miss | `brix_vfs_io_result_t.from_cache:1` | `src/fs/vfs/vfs.h:95` |
| bytes / offset | `.length`, `.offset` | `src/fs/vfs/vfs.h:92-93` |
| checksum | `.crc32c` | `src/fs/vfs/vfs.h:94` |
| protocol | `brix_vfs_ctx_t.metrics_proto` | `src/fs/vfs/vfs.h:103` |
| identity | `brix_vfs_ctx_t.identity` → `brix_identity_t` | `src/fs/vfs/vfs.h:102` |
| DN / subject / issuer | `.dn`, `.subject`, `.issuer` | `src/core/types/identity.h:28-30` |
| VO / FQAN | `.vo_csv`, `.acc_vorg_csv`, `.acc_role_csv`, `.acc_group_csv` | `src/core/types/identity.h:39,47-49` |
| auth method | `.auth_method` (`BRIX_AUTHN_*` bitmask) | `src/core/types/identity.h:58`, values at `:17-25` |
| TLS | `brix_vfs_ctx_t.is_tls:1` | `src/fs/vfs/vfs.h:130` |
| cache enabled / write-through | `.cache_enabled:1`, `.cache_writethrough:1` | `src/fs/vfs/vfs.h:132-133` |
| resolved path | `.resolved` (`brix_path_result_t`) | `src/fs/vfs/vfs.h:128` |

**Revised recommendation.** Source every W1/W2 variable from the VFS seam.
Where a value is genuinely not at that seam (an HTTP-only notion such as the
response status) read it from nginx's own request. Keep the three existing
plane-local variables as-is until W8's parity rule forces convergence.

### Prior art in-tree: the JSON access log — and the relationship question

`src/observability/metrics/access_log.c` already emits a structured JSON line
per completed VFS op via `brix_access_log_emit()`
(`src/observability/metrics/access_log.h:7`), carrying — in its own words
(`access_log.c:7-9`) — "timestamp, protocol, op name, request path, byte
count, offset, latency, error status, **cache-hit flag**, auth method, and the
authenticated subject/DN".

This is the single most important piece of prior art in this phase and it cuts
both ways:

- **For W1/W2**: it proves the data is assembled, escaping-safe, and already
  has a shared vocabulary (`brix_metric_proto_name`, `_op_name`, `_err_name`,
  `_auth_method_name` — `src/observability/metrics/unified.h:101,109`). The
  variables should reuse those exact name functions so a `$brix_auth_method`
  value, a JSON access-log field, and a Prometheus label all read the same.
  Inventing a fourth vocabulary here would be the same mistake the cache-status
  divergence already made.
- **Against a naive W1**: it means brix has a *bespoke logger* doing what
  nginx's `access_log` does. Two loggers with different formats, different
  configuration, and different field names is worse than one.

**OP-DECIDE (W1-b) — the relationship between the JSON access log and the
variable surface.** Three options: (i) **complement** — keep the JSON log
(its per-VFS-op granularity is finer than nginx's per-request line, and the
stream plane has no per-op nginx logging at all), and add variables for
nginx-native use; (ii) **converge** — reimplement the JSON log as a stock
`log_format` over the new variables and delete the bespoke emitter; (iii)
**demote** — keep the emitter for the stream/per-op case only.
Recommendation: **(i) complement**, because the JSON log's granularity is
per-VFS-op and genuinely cannot be expressed by nginx's per-request
`access_log`; but the two MUST share the vocabulary functions, and that
sharing should be asserted by a test. This decision gates nothing in W1 step 1
and can be taken late.

**OP-DECIDE (W1-a).** The naming of the seven unprefixed variables is a
**hard rename** under the standing rules (no alias, no hint string) and will
break any operator config that references `$cvmfs_cache`. The alternatives:
(i) hard-rename to `$brix_cvmfs_cache` etc., migration row in
`docs/03-configuration/migration-unified-grammar.md`, consistent with how
every directive rename in 101/105 was handled; (ii) register BOTH the new
`$brix_*` name and keep the legacy name for one release, marked deprecated —
which contradicts the standing "no alias" rule but is far kinder for a
variable, since a stale `$cvmfs_cache` in a `log_format` is a **startup
failure** (`unknown "cvmfs_cache" variable`), not a silent degradation.
My recommendation is **(ii) as a documented, time-boxed exception** precisely
because the failure mode is a hard startup abort on a config an admin may not
control; but this is the OP's call and W1 does not proceed on the rename
until it is made. The new variables in Appendix A are unaffected either way
and can land first.

### Steps

1. **Surface the VFS-seam values to the HTTP request.** The variables need a
   per-request landing place for the fields Appendix G maps; the VFS op that
   produced them has already returned by log time. Add the minimal carrier to
   the *common* module's per-request ctx (not a new struct — see the design
   section) and populate it where `brix_access_log_emit()` is already called,
   which is by construction every place the values are known and correct.
   ABI-dirty commit — see the trap.
2. **Register the tier-1 variables on `preconfiguration` of the common HTTP
   module.** The hook is currently `NULL` at
   `src/core/config/http_common.c:109` — this is the exact site. Registering
   here (rather than per-protocol, as cvmfs/oci/rpm do today) means ONE
   registration serves webdav, s3, cvmfs, oci and rpm: the http_common
   ownership thesis phases 101/105 established for directives, applied to
   variables. It is also what makes W8's R9 plane-parity rule satisfiable by
   construction rather than by discipline.
3. **Reuse the existing vocabulary functions** — `brix_metric_proto_name()`,
   `brix_metric_auth_method_name()` (`src/observability/metrics/unified.h:101,109`)
   — so a variable's value, the JSON access-log field, and the Prometheus
   label are the same string. No new name tables.
4. Map brix cache states onto nginx's `$upstream_cache_status` vocabulary
   where the semantics genuinely correspond, and document every place they do
   not (Appendix B). Do NOT invent a third vocabulary.
5. Only after the OP-DECIDE: rename/alias the seven unprefixed names.

### Tests

Per the standing 3-per-change-class rule, for the variable surface as a class:

- **success** — a config using `log_format` with each tier-1 variable starts,
  serves a request on each HTTP plane, and the log line carries the expected
  value; a cache miss then hit produces the two expected distinct values (the
  non-vacuity half: a variable that always returns `-` would pass a weaker
  test).
- **error** — a variable referenced in a `log_format` before the module that
  provides it is loaded fails at startup with nginx's own
  `unknown "..." variable`, not a brix-specific message and not a crash; a
  handler invoked with no brix ctx (request rejected in an earlier phase, e.g.
  a `deny` before brix runs) logs `-` rather than segfaulting.
- **security-neg** — assert the refusals: no tier-1 variable's value can be
  made to contain bearer-token material, a macaroon, or an `Authorization`
  header value, driven by a request that carries all three. This is the test
  that keeps a future contributor from adding `$brix_token` "for debugging".

### Acceptance

- `$brix_cache_status` is available on every HTTP plane and distinguishes at
  minimum HIT / MISS / BYPASS.
- A single `log_format` works unchanged across webdav, s3, cvmfs, oci, rpm.
- W8's variable rules pass with zero findings.
- No variable exposes credential material (security-neg test green).

---

## W2 — Stream (`root://`) variable surface

### Current state

`ngx_stream_add_variable` and `ngx_stream_variable_t` appear **zero times**
across `src/` and `shared/`. The stream module's context declares
`preconfiguration` as `NULL` at
`src/protocols/root/stream/module_definition.c:16` — which is precisely the
hook where stream variables must be registered.

The practical consequence: the root:// plane, the flagship protocol and the
one the project's parity work is built around, is **completely invisible to
`access_log` in a `stream {}` block**. There is no way to log the op, the
path, the status, the bytes moved, the identity, or the cache outcome using
nginx's own logging. Operators are left with the Prometheus endpoint
(`src/observability/metrics/`) — which is aggregate, not per-connection — or
brix's own `[notice]`/`[info]` error-log lines, which are not structured and
not configurable per-field.

The prerequisite exists and is healthy: a per-session `brix_ctx_t` is already
attached and retrieved via `ngx_stream_get_module_ctx` throughout the stream
path (e.g. `src/protocols/root/relay/relay.c:182`, `:296`,
`src/protocols/root/connection/tls.c:27`,
`src/protocols/root/handoff/handoff.c:133`). The values a variable handler
needs are, in the main, already in that struct or trivially derivable. This is
mostly a *registration and lifetime* problem, not a data problem.

### Why this fix shape

Stream variables are cheap for the same reason HTTP ones are, and this plane
has *nothing* today, so there is no rename/compat question — W2 is purely
additive and can proceed the moment W1 settles the naming convention.

Two real subtleties, both of which must be settled before code:

1. **Lifetime.** A stream session is long-lived and multiplexed: one session
   carries many XRootD ops. A variable evaluated at log time therefore
   describes the *session*, not an op. Session-scoped variables (peer
   identity, VO, TLS, total bytes, op count) are well-defined; per-op ones
   (path, opcode, status) are not, unless brix logs per-op itself. **Decide
   explicitly which set W2 ships** — the recommendation is session-scoped
   first (well-defined, immediately useful for `access_log` at session close)
   and to treat per-op logging as a separate question, since it needs a
   logging mechanism nginx's stream `access_log` does not provide.
2. **`preconfiguration` is NULL by deliberate comment.** The existing comment
   at `module_definition.c:15` says "No global parser rewrites are needed
   before nginx reads stream blocks." That reasoning is about parser rewrites;
   adding variable registration there does not contradict it, but the comment
   must be updated in the same commit so the next reader is not misled.

### Steps

1. Settle session- vs op-scope (above). Record the decision in this file.
2. Add a stream `preconfiguration` hook that registers the Appendix A tier-2
   set. The slot is currently `NULL` at
   `src/protocols/root/stream/module_definition.c:16` — that is the exact
   site, and the adjacent comment at `:15` ("No global parser rewrites are
   needed before nginx reads stream blocks") must be updated in the same
   commit so the next reader is not misled into thinking the NULL is load-
   bearing.
3. Source values from the existing `brix_ctx_t`; add fields only where a value
   genuinely is not already tracked, and note each addition as ABI-dirty.
4. Verify against the `stream {}` `access_log` in the test fleet — the fleet
   renderer (`tests/cmdscripts/live_common.py`) already injects runtime
   directives and is the natural place to add a stream `log_format`.

### Tests

- **success** — a `stream {}` `access_log` with a brix `log_format` produces
  one well-formed line per session with the expected identity/bytes/op-count.
- **error** — a session that never completes login (rejected at handshake)
  still logs a line with `-` for the identity fields rather than dropping the
  line or crashing.
- **security-neg** — no stream variable exposes the token/credential that
  authenticated the session; assert with a ZTN and a GSI session.

### Acceptance

- `ngx_stream_add_variable` count > 0, and a fleet instance logs root://
  sessions through nginx's own `access_log`.
- The same field names mean the same thing as their HTTP counterparts (W8
  parity rule).

---

## W3 — `X-Accel-Redirect` and internal-redirect handoff

### Current state

`ngx_http_internal_redirect` and `ngx_http_named_location` appear **nowhere**
in `src/`; there is no `X-Accel-Redirect` handling. brix serves every byte
itself: `src/core/http/http_file_response.c` builds file responses, and
`src/core/http/http_conditionals.c` implements RFC 7232 conditionals
(If-None-Match / If-Match / If-Modified-Since) independently — its own header
says so and explains why (shared across WebDAV PUT/MOVE/COPY and S3 GET/PUT).

Two capabilities are missing as a result:

- **Inbound** (`X-Accel-Redirect` support, brix as the *authz/route brain*):
  an operator with an existing nginx deployment cannot put brix in front of it
  to make cache/authz decisions and then let their own upstream serve the
  bytes. Adoption is all-or-nothing — you move your data plane to brix or you
  get nothing. This is the single biggest adoption barrier in the phase.
- **Outbound** (internal redirect to nginx's static path): a file that brix
  has already staged to local disk could be handed to
  `ngx_http_static_module` via an internal redirect, inheriting sendfile,
  `open_file_cache`, byte-range, ETag/conditionals and `aio` for free.
  Notably, WebDAV already carries `open_file_cache` settings
  (`src/protocols/webdav/config_merge.c:131-135`) — the intent to reuse
  nginx's file machinery is already present in the config surface.

### Why this fix shape (and its risks)

The outbound half is the one to be careful about. Handing off to the static
module means **giving up control of the response**, and brix's file responses
are not plain static serving: they carry checksum verification, tier/VFS
semantics, POSC/staging state, and per-request authz that the static module
knows nothing about. An internal redirect that bypasses a verification gate
would be a *correctness and security regression*, not an optimisation.

So the outbound half must be **opt-in, narrowly scoped, and gated**: only for
a fully-staged, verified, locally-resident object, with no per-byte policy
left to apply. That is a real subset (a warm cache hit on a plain read), and
it is the hottest path in the product — but the gate conditions must be
enumerated and tested, not assumed. If the gate cannot be stated crisply, ship
the inbound half alone; it carries most of the adoption value anyway.

**OP-DECIDE (W3-a).** Whether the outbound half is in scope at all for this
phase, or deferred pending a checksum/verification audit. Recommendation:
**inbound first, outbound deferred** to its own phase with a written gate
specification — the inbound half is independently valuable and far lower risk.

### Steps (inbound half)

1. Add an `X-Accel-Redirect` response path: brix makes its decision (authz,
   cache lookup, path resolution) and emits the header plus any
   `X-Accel-*` companions rather than a body.
2. Decide and document which brix state travels to the receiving location —
   this is where W1's variables pay off a second time, since the natural
   mechanism is `proxy_set_header` on `$brix_*`.
3. Ensure the decision path can run without brix owning the export (brix as
   pure decision layer over someone else's root).

### Tests

- **success** — a location with brix authz + `X-Accel-Redirect` to a plain
  nginx `location` serves the right bytes with the right status.
- **error** — a denied request emits no `X-Accel-Redirect` and no body, and
  the internal location is not reachable directly from outside.
- **security-neg** — the internal location cannot be reached by a client
  crafting the `X-Accel-Redirect` header itself, and a denied authz decision
  cannot be converted into a serve by header injection. This is the
  load-bearing test of the workstream.

### Acceptance

- brix can gate a location it does not serve.
- The internal target is unreachable externally (security-neg green).

---

## W4 — `auth_request`-compatible authz endpoint

### Current state

brix already performs subrequests: `src/protocols/webdav/introspect.c:163`
calls `ngx_http_subrequest` against a configured introspection location
(phase-21 step C, as-built). So the machinery and the idiom are present and
proven in-tree — but they run *inward* (brix consuming an introspection
endpoint), never *outward* (brix serving as the authz endpoint for someone
else's location).

brix owns a large, genuinely differentiated authz corpus: WLCG tokens, VOMS
FQAN mapping, macaroons, GSI/X.509 chains, SciTokens, ZTN, delegated
credentials. Today **none of it is reachable** unless brix also serves the
data.

### Why this fix shape

This is the highest external-adoption item in the phase and is largely a
*packaging* exercise over logic that already exists: an `auth_request` target
is a location that returns 2xx/401/403 and optionally sets response headers
for `auth_request_set`. brix already computes all of that internally at its
auth gate.

The subtlety is that `auth_request` subrequests have no request body and must
be cheap and idempotent — so the endpoint must decide from headers/TLS state
alone. Most of brix's authz already does (bearer token, TLS peer chain), but
anything that consults the body or mutates state (a token *exchange*, a
delegation mint) must be excluded or made explicitly opt-in, because an
`auth_request` may be issued more than once per client request.

**OP-DECIDE (W4-a).** Whether the endpoint may perform a token exchange
(`brix_token_exchange()`, `src/auth/token/exchange.c`) — which is a network
round trip and a state mutation — or must be restricted to local verification.
Recommendation: **local verification only** in this phase; exchange stays on
the data path where its cost and caching are already understood. See also W5,
which audits that call's blocking behaviour.

### Steps

1. Define the endpoint's contract: inputs (headers, TLS peer), outputs
   (status, and the `auth_request_set`-able headers — subject, VO, FQAN,
   issuer, scopes-granted).
2. Reuse the existing auth gate; no second implementation of any check.
3. Ensure it is safe to call repeatedly and concurrently (no per-call state
   mutation, no credential minting).

### Tests

- **success** — a plain `location` protected by `auth_request` to the brix
  endpoint admits a valid WLCG token and populates `auth_request_set` vars.
- **error** — an expired/malformed token yields 401 with no header leakage,
  and a scope-insufficient token yields 403.
- **security-neg** — the endpoint cannot be used as a token oracle: a failed
  verification must not reveal *why* in a way that distinguishes "unknown
  issuer" from "bad signature" to an unauthenticated caller, and the endpoint
  must not echo the presented credential in any response header.

### Acceptance

- brix authz protects a location brix does not serve.
- No credential material appears in any response header (security-neg green).

---

## W5 — HTTP transport convergence **study** (no code this phase)

### Current state — measured, and more nuanced than it first appears

`curl_easy_perform` (fully blocking) appears in: `src/fs/cache/origin/s3_transport.c`,
`src/fs/cache/origin/pelican_register.c`, `src/auth/s3/sts_http.c`,
`src/auth/token/exchange.c`, and the TPC family (`tpc_curl.c`,
`tpc_curl_setup.c`, `tpc_verify.c`, `tpc_curl_pmark.c`).

The TPC multi path runs its own pump loop — `tpc_ms_drive`
(`src/protocols/webdav/tpc_curl_multi.c:162`) calls `curl_multi_perform` /
`curl_multi_wait` until no handle is running, i.e. `curl_multi_wait`, **not**
`curl_multi_socket_action` wired into nginx's event loop via `ngx_add_event`.

**Important nuance, and the reason this is a study rather than a fix:** TPC is
offloaded to nginx's thread pool (`ngx_thread_task_post` at
`src/protocols/webdav/tpc_thread.c:496` and `tpc_marker_start.c:356`), so the
blocking loop does **not** stall the event loop. The real cost is a different
one — a thread-per-transfer scaling model, a second connection pool, a second
TLS configuration surface, and no access to `upstream {}`, `keepalive`,
`resolver`, `proxy_next_upstream`, upstream zones, active health checks or the
`$upstream_*` variables.

Meanwhile `src/net/mirror/` **does** use `ngx_http_upstream`
(`http_mirror.c`, `http_mirror_request.c`) — the one place in the tree that
does, and therefore the in-tree reference for what an upstream-based transport
costs and buys here.

**The open question this study must answer first**, because it determines
whether anything is urgent: **is any blocking `curl_easy_perform` reachable on
a request-handling path that is NOT thread-offloaded?**
`brix_token_exchange()` is called from `src/fs/vfs/vfs_deleg.c:199,214` and
`src/protocols/webdav/tpc_cred.c:218`. TPC is thread-offloaded; the
`vfs_deleg.c` path is **not yet traced** and is the specific thing to
establish. If that path runs on the event loop, it is a latent worker stall
under a slow/unreachable token endpoint — a real availability bug, and it
would be promoted out of this study into its own fix immediately.

### Deliverables (study only — no production code)

1. **Blocking-call reachability audit.** For each `curl_easy_perform` site,
   trace every caller to either a thread-pool task or the event loop. Produce
   a table. Any event-loop-reachable blocking call is a **bug**, filed and
   fixed independently of the rest of this workstream.
2. **Cost/benefit matrix** for moving the HTTP origin read path to
   `ngx_http_upstream`, using `src/net/mirror/` as the worked in-tree example:
   what is gained (`upstream {}`, keepalive, resolver, health checks,
   `$upstream_*`), what is lost (curl's protocol breadth — redirects, auth
   schemes, HTTP/2, S3 SigV4 signing hooks, `CURLOPT_*` behaviours the code
   relies on), and what the migration costs per call site.
3. **A recommendation with an explicit gate**, including the option "keep
   libcurl but drive it with `curl_multi_socket_action` on nginx's event
   loop", which is a much smaller change that removes the thread-per-transfer
   model while keeping curl's protocol breadth. This middle option may well
   dominate; the study must evaluate it seriously rather than framing the
   choice as curl-vs-upstream.

**OP-DECIDE (W5-a).** No transport code changes without the study's
recommendation being accepted. This is a large, risky, cross-cutting change
touching TPC, S3, Pelican and token exchange; the honest position today is
that the case for it is unproven.

### Deliverable 2/3 — cost/benefit matrix and recommendation (2026-08-31)

The audit (deliverable 1) changed the picture materially, so record the finding
before the recommendation: the blocking is **not confined to the token
exchange**. The remote HTTP backend driver (`sd_http.c`) performs its metadata
operations — opendir/stat via a WebDAV PROPFIND — through the shared blocking
curl transport (`brix_s3_origin_curl_transport` → `s3_transport.c`
`curl_easy_perform`), and the webdav PROPFIND handler is **not** thread-offloaded
(`dispatch.c:377`; the offload list is COPY/MOVE/PUT/TPC only). So against a
remote backend, an ordinary `PROPFIND` already blocks the event loop on the
backend call, and the token exchange is one *additional* blocking call on the
same path. Fixing only the exchange would leave the larger stall in place — the
exchange was simply the most visible symptom.

| Option | What it costs | What it buys | Verdict |
|--------|---------------|--------------|---------|
| **(a) keep libcurl, blocking, as-is** | up to `tpc_timeout`/30s event-loop stall per cold metadata op against a slow remote backend; token-exchange cache and bounded timeouts limit the blast radius | zero change; curl's full protocol breadth (redirects, auth schemes, SigV4 hooks, HTTP/2) | the status quo; acceptable only because the cache + timeouts bound it |
| **(b) keep libcurl, drive it with `curl_multi_socket_action` on nginx's event loop** | a real but *contained* rewrite of the transport pump (one `s3_transport.c` seam, plus the callers that assume a synchronous return must accept a continuation); keeps every `CURLOPT_*` the drivers rely on | eliminates the event-loop stall for BOTH the metadata path and the exchange with ONE change, because both go through the same transport; no protocol regressions | **recommended.** Smallest change that removes the stall without giving up curl's breadth. `src/net/mirror/` is the in-tree proof that event-loop-integrated outbound HTTP works here. |
| **(c) move the HTTP read path to `ngx_http_upstream`** | the largest change: re-express S3 SigV4 signing, Pelican, GSI-over-https and the token flows as upstream modules; lose the `CURLOPT_*` behaviours the drivers depend on | native `upstream {}`, keepalive, resolver, health checks, `$upstream_*` | **not recommended for this concern.** Solves the stall but at a cost far exceeding it, and re-implementing SigV4/GSI on the upstream framework is its own multi-phase risk. Revisit only if the `upstream {}` features are wanted for their own sake. |

**Recommendation: option (b)**, as **its own phase** (call it 109), scoped as
"convert `s3_transport.c` from `curl_easy_perform` to a
`curl_multi_socket_action` pump integrated with `ngx_add_event`, and make the
webdav metadata callers accept the async completion." It is deliberately NOT
started here: it is cross-cutting (every remote-backend caller), it is on the
data + auth path, and rushing it is exactly risk **R-8**. The phase-106
interim posture is the one already in place and now *enforced*: every blocking
curl call is bounded (`tests/test_blocking_curl_bounded.py`), the exchange is
cached per-worker, and both are opt-in (remote backend / EXCHANGE mode). That
bounds the availability exposure to a cold-miss cold-connect window on an
opt-in path — tolerable until phase 109 removes it.

This completes W5's three deliverables (audit, matrix, recommendation). W5 was
scoped "study first, no code"; the study is done and its one shippable output —
the bounded-call invariant plus the `tpc_verify.c` fix it surfaced — has landed.

### Tests (for the audit's one shippable output)

The study itself ships no production code, but deliverable 1 may promote a
bug. If the blocking-call audit finds an event-loop-reachable
`curl_easy_perform`, that fix carries the standard triad:

- **success** — the call path completes normally under a healthy endpoint and
  the request is served, with the call demonstrably off the event loop
  (assert via a worker-stall probe: a second request served while the first is
  mid-exchange against a deliberately slow endpoint).
- **error** — a token endpoint that never answers fails the *one* request on a
  bounded timeout and does not delay unrelated requests on the same worker;
  the existing `brix-fault-proxy` is the natural instrument here
  (`docs/refactor/brix-fault-proxy-feature-expansion.md`).
- **security-neg** — a slow/hostile token endpoint cannot be used to stall a
  worker into a denial of service (the availability half), and a failed
  exchange must not fall back to serving with an unverified identity.

### Acceptance

- A table of every `curl_easy_perform`/`curl_multi_*` site → its caller →
  thread-pool or event-loop, with no unresolved entries.
- Zero event-loop-reachable blocking HTTP calls, or each one filed with a fix.
- A written recommendation on transport, with the three options
  (keep-as-is / `curl_multi_socket_action` on the nginx event loop /
  `ngx_http_upstream`) costed against `src/net/mirror/` as the worked example.
- No transport code merged under this phase.

---

## W6 — Conditionals / Range / ETag convergence audit

### Current state

`src/core/http/http_conditionals.c` implements RFC 7232 conditionals and
`src/core/http/http_file_response.c` builds file responses. nginx ships
`ngx_http_not_modified_filter_module` and `ngx_http_range_filter_module` which
do much of this natively.

The existing code's rationale is stated and is not obviously wrong: the checks
are shared across WebDAV PUT/MOVE/COPY and S3 GET/PUT, and WebDAV's `Overwrite`
header is not something nginx's filters model at all. Conditional handling on
a *write* method is genuinely outside what the not-modified filter does.

### The (method × plane × conditionals × ranges) table (2026-08-31)

Built by reading the request path. "nginx" = the request flows through
`ngx_http_output_filter` (`http_file_response.c:393`), so the core
`not_modified` and `range` filters apply; "brix" = a bespoke evaluator runs
first (`core/http/http_conditionals.c`, and the per-plane `get_serve.c` /
`s3/conditional.c` wrappers).

| Plane | GET/HEAD conditionals | GET/HEAD ranges | Write-method conditionals |
|-------|-----------------------|-----------------|---------------------------|
| webdav | brix pre-check (`webdav_get_eval_conditionals`, If-Modified-Since) THEN nginx not_modified filter | nginx range filter (response goes through `ngx_http_output_filter`) | brix (`http_conditionals.c` — If-Match/If-None-Match/Overwrite on PUT/MOVE/COPY) |
| s3 | brix pre-check (`s3/conditional.c`, READ\|TIME mode) THEN nginx not_modified filter | nginx range filter | brix (PUT preconditions) |
| cvmfs | nginx not_modified filter | nginx range filter | n/a (read-only plane) |
| oci | nginx not_modified filter | nginx range filter | n/a |
| rpm | nginx not_modified filter | nginx range filter | n/a |

No "unknown" cells. Two findings:

1. **No double ETag generator on the served path.** brix builds its file
   response and hands it to `ngx_http_output_filter`; it does not also run a
   second ETag computation that could disagree with nginx's. The bespoke
   `http_conditionals.c` ETag path is used only for WRITE-method preconditions
   (Overwrite semantics nginx's filters do not model), where nginx's not_modified
   filter never runs. So the two never race on one response — the divergence
   risk the acceptance asked about does not exist. **Documented, not eliminated,
   because there is nothing to eliminate.**
2. **Authorization precedes conditionals on every plane** — structural (nginx
   runs the ACCESS phase before the CONTENT phase where every conditional
   evaluator above lives), and now asserted by
   `tests/test_authz_before_conditionals.py` on webdav and s3 (the two planes
   with both an auth gate and a conditional evaluator), closing the
   existence/mtime-oracle a 304/412-to-an-unauthorized-caller would open.

Conclusion unchanged: no convergence work. The GET path already uses nginx's
filters; the bespoke code covers only what those filters cannot (write-method
preconditions). W6 closes with the table, the two findings, and the security
test — no code change to the conditional path.

### Why this is an audit, not a rewrite

The honest question is narrow: **on the plain GET path, does brix's response
already flow through nginx's range/not-modified filters, or does it bypass
them?** If it flows through, there may be double work or subtle disagreement
(two ETag generators). If it bypasses them, brix owns range semantics
entirely and any divergence from nginx's well-tested implementation is a
compatibility risk with clients that exercise multipart ranges.

Deliverable: a table of (method × plane × who handles conditionals × who
handles ranges), and a recommendation limited to the GET path. The write-path
conditionals stay bespoke — that is correct as built.

### Steps

1. Build the (method × plane) matrix: for GET/HEAD on each of webdav, s3,
   cvmfs, oci, rpm, record who evaluates conditionals and who evaluates
   ranges — brix's own code, nginx's filters, or both.
2. Determine whether brix's file responses traverse
   `ngx_http_not_modified_filter_module` and `ngx_http_range_filter_module` at
   all, or bypass the filter chain.
3. Compare the two ETag generators (brix's mtime/size derivation in
   `src/core/http/http_conditionals.c` vs nginx's) and record whether they can
   disagree for the same object.
4. Recommend, for the GET path only, either "defer to nginx's filters" or
   "keep bespoke, and here is why" — with the multipart-range client
   compatibility argument settled either way.

### Tests

- **success** — a plain conditional GET (`If-None-Match` with the served ETag)
  returns 304 with no body on every HTTP plane, and identical ETags come back
  for the same object across planes.
- **error** — a malformed `Range` header yields 416 with a correct
  `Content-Range`, and a multipart range request is either served correctly or
  refused cleanly — never truncated.
- **security-neg** — a crafted `Range` cannot read outside the object
  (offset/length overflow), and a conditional header cannot be used to infer
  the existence of an object the caller is not authorised to see (the 304-vs-
  403 ordering question: authz must be decided *before* conditionals).

### Acceptance

- The (method × plane × conditionals × ranges) table exists and has no
  "unknown" cells.
- Any divergence between the two ETag generators is either eliminated or
  documented with its rationale.
- The authz-before-conditionals ordering is asserted by the security-neg test
  on every HTTP plane.

---

## W7 — `load_module` (DYNAMIC) conformance

### Current state

The repo-root `config` takes dynamic builds seriously — there are repeated,
specific comments that libs must go in each module's `ngx_module_libs` and not
only `CORE_LIBS`, or `dlopen` of the `.so` fails (`config:122-125`, `:197`,
`:217-218`, `:242-243`, `:326-327`, `:364-365`), and `ngx_module_type` is set
per module block (`config:728`, `:1529`, `:1538`). The RPM packaging already
ships dynamic modules.

What is **not** verified: that all 15 modules (11 HTTP, 4 stream) load cleanly
via `load_module` in every supported combination, and — specific to this
phase — that **variable registration works under dynamic load**, where module
ordering and preconfiguration timing differ from a static build.

### Steps

1. Enumerate the 15 modules and their load order constraints.
2. A test that loads each dynamically and asserts the directives *and* the
   W1/W2 variables resolve.
3. Assert the failure mode when a dependency module is absent is a clear
   startup error, not a crash.

### Tests

- **success** — each of the 15 modules loads via `load_module` in a minimal
  config; directives parse and the W1/W2 variables resolve in a `log_format`.
- **error** — loading a module whose dependency module is absent fails at
  startup with a clear diagnostic naming the missing dependency, not a
  `dlopen` symbol error and not a crash.
- **security-neg** — a `load_module` path outside the packaged module
  directory is not silently accepted in the packaged configuration (packaging
  correctness: the RPM/deb ships a fixed module path).

### Acceptance

- All 15 modules (11 HTTP, 4 stream) load dynamically.
- Variables registered in preconfiguration resolve identically under static
  and dynamic builds — the specific regression this workstream exists to
  prevent.
- The packaged RPM and deb both pass the same test.

---

## W8 — Governance: variable rules in the registry checker

phase-101/105 built `tools/ci/check_directive_registry.py` with rules R1–R6
precisely because a naming/ownership surface drifts silently. The variable
surface has no such governance, which is why 7 of 9 names are unprefixed and
three planes invented three cache vocabularies.

Proposed rules (numbering continues the existing scheme; the checker is
currently WARN-mode for R3 pending phase-105 W6, so new rules should land
gated the same way):

- **R7 — variable naming.** Every variable a brix module registers is
  `brix_`-prefixed, with an allowlist carrying the legacy names until the
  W1-a decision is executed.
- **R8 — variable documentation.** Every registered variable has a row in
  `docs/03-configuration/`, mirroring R3's docs-from-source requirement for
  directives.
- **R9 — plane parity.** A variable name that exists on more than one plane
  means the same thing and uses the same vocabulary — the rule that stops a
  fourth cache-status spelling being invented.
- **R10 — exposure.** A denylist rule: no registered variable name matches the
  credential-material patterns (token, secret, key, password, macaroon,
  `authorization`) without an explicit, reviewed allowlist entry.
  `$brix_delegated_cred` is the one existing entry and must be listed with its
  rationale.

### Steps

1. Land R7 (naming) in WARN mode with the seven legacy names allowlisted, so
   the rule is visible before it bites.
2. Land R10 (exposure denylist) in **gating** mode immediately — it is a
   security rule with exactly one known allowlist entry
   (`$brix_delegated_cred`), so it can gate from day one without a burndown.
3. Land R8 (documentation) and R9 (plane parity) WARN-first, gate once W1/W2
   have populated the docs rows.
4. Add checker fixtures for each rule, matching the existing
   `tools/ci/` fixture convention used by R5/R6.

### Tests

- **success** — a correctly named, documented, non-exposing variable passes
  all four rules.
- **error** — fixtures that violate each rule individually are each caught,
  with the message naming the offending variable and rule.
- **security-neg** — a fixture registering `$brix_bearer_token` is refused by
  R10 and cannot be made to pass by renaming to a near-miss
  (`$brix_bearertoken`, `$brix_tok`) — i.e. the pattern match is not trivially
  evadable, mirroring how R6 handles normalized-stem near-misses.

### Acceptance

- R10 gates on the real tree from the first commit.
- R7/R8/R9 report zero findings once W1/W2 land, and the CI lane flips them to
  `--fail` in the same commit that empties them.

---

## Appendix A — proposed variable inventory

Tier 1 = HTTP planes (W1). Tier 2 = stream/root:// (W2), session-scoped.
"Exposure" is the W1 security trap verdict; every row must have one before it
is implemented.

### Tier 1 — HTTP

| Variable | Value | Cacheable | Exposure |
|----------|-------|-----------|----------|
| `$brix_cache_status` | `HIT`/`MISS`/`BYPASS`/`STALE`/`REVALIDATED`/`-`, nginx vocabulary (Appendix B) | no | safe |
| `$brix_tier` | resolved storage tier that served the request | no | safe |
| `$brix_origin` | resolved origin identity for a fill (host or configured name) | no | safe — name only, never a credentialed URL |
| `$brix_backend_time` | seconds spent on the origin fill, `$upstream_response_time` shape | no | safe |
| `$brix_bytes_served` | bytes delivered to the client | no | safe |
| `$brix_vo` | VO from the verified credential | per-request | safe — subject attribute |
| `$brix_dn` | X.509 subject DN | per-request | safe — subject, not the chain |
| `$brix_fqan` | primary VOMS FQAN | per-request | safe |
| `$brix_token_issuer` | `iss` of the accepted token | per-request | safe |
| `$brix_token_sub` | `sub` of the accepted token | per-request | safe |
| `$brix_auth_method` | `none`/`gsi`/`token`/`sss`/`ztn`/`s3sig` | per-request | safe |
| `$brix_checksum` | checksum of the served object, `alg:hex` | no | safe |
| `$brix_protocol` | **exists** — `src/protocols/webdav/module_init.c:281` | no | safe |
| `$brix_delegated_cred` | **exists** — `:290` | per-request | **credential — allowlisted, R10 entry required** |

Explicitly **excluded** (R10): raw `Authorization` value, bearer token,
macaroon, private key material, session secrets.

### Tier 2 — stream (session-scoped)

| Variable | Value | Exposure |
|----------|-------|----------|
| `$brix_session_ops` | XRootD ops served on the session | safe |
| `$brix_session_bytes_out` / `_in` | bytes moved | safe |
| `$brix_session_auth_method` | as tier 1 | safe |
| `$brix_session_vo` / `_dn` / `_fqan` | as tier 1 | safe |
| `$brix_session_tls` | TLS on/off + version | safe |
| `$brix_session_redirects` | redirects issued (manager mode) | safe |

### Existing, pending the W1-a rename decision

`$cvmfs_class`, `$cvmfs_cache`, `$cvmfs_origin`, `$oci_class`, `$oci_cache`,
`$rpm_class`, `$rpm_cache`.

---

## Appendix B — cache-status vocabulary mapping

The existing cvmfs states (`src/protocols/cvmfs/module.c:164`) map onto
nginx's `$upstream_cache_status` vocabulary as follows. Any state that does
**not** map must be documented as a brix extension rather than silently
overloading an nginx term.

| brix (cvmfs today) | nginx term | Note |
|--------------------|-----------|------|
| `hit` | `HIT` | direct |
| `fill` | `MISS` | nginx says MISS for "went to origin and populated" |
| `neg` | — | **brix extension**: negative-cache hit. nginx has no equivalent; do not overload `BYPASS`. Proposed literal: `NEGHIT`. |
| `-` | `-` | not applicable / brix did not run |

States nginx has that brix must decide whether it can produce: `BYPASS`,
`EXPIRED`, `STALE`, `UPDATING`, `REVALIDATED`. `STALE` and `REVALIDATED` are
meaningful for brix given its revalidation logic and should be produced where
the data plane already knows; the rest need a per-plane answer during W1
step 2.

---

## Appendix C — sequencing and dependencies

```
W1 (HTTP variables) ──┬─→ W2 (stream variables)   [needs W1 naming decision]
                      ├─→ W3 (X-Accel handoff)    [W1 vars are how state travels]
                      ├─→ W4 (auth_request)       [W1 vars are the auth_request_set outputs]
                      └─→ W8 (governance)         [rides W1/W2]

W5 (transport study)  ── independent; its blocking-call audit is urgent and
                         should run first regardless of the rest
W6 (conditionals audit) ── independent, small
W7 (dynamic modules)  ── independent, but its variable-under-dlopen check
                         depends on W1/W2 having landed
```

Suggested order: **W5's blocking-call audit** (cheap, may surface a real
availability bug), then **W1**, then W2/W4 in parallel, then W8, then W3,
with W6/W7 slotted as capacity allows and W5's transport decision deferred to
its own phase.

---

## Appendix G — per-variable provenance and implementation notes

The table Appendix A gives *what* each variable means. This one gives *where
the value comes from today*, which is what an implementer actually needs. Every
"source" was traced on `main` @ `875a4e6db`. "New?" marks the values that are
NOT currently tracked and therefore require data-plane work, not just a
handler — those are the only expensive rows in W1.

### Tier 1 — HTTP

| Variable | Source field | File:line | New? | Cacheable | Handler notes |
|----------|--------------|-----------|------|-----------|---------------|
| `$brix_cache_status` | `brix_vfs_io_result_t.from_cache:1` | `src/fs/vfs/vfs.h:95` | **partly** — the bit exists but is boolean; STALE/REVALIDATED/BYPASS need a widened enum (Appendix B) | no | Must distinguish "no VFS op happened" (`-`) from MISS. The cvmfs precedent already models a 4-state enum at `src/protocols/cvmfs/cvmfs.h:514-517` |
| `$brix_bytes_served` | `brix_vfs_io_result_t.length` | `src/fs/vfs/vfs.h:93` | no | no | Sum across ops for a multi-op request; decide and document whether it is per-op or per-request |
| `$brix_checksum` | `brix_vfs_io_result_t.crc32c` | `src/fs/vfs/vfs.h:94` | no — but see note | no | The field is crc32c only. INVARIANT #9 (`crc64` ≠ `crc64nvme`, encode at the edge) applies: the variable must render `alg:hex`, never a bare number, or it will be misread as adler32/md5 by tooling |
| `$brix_protocol` | `brix_vfs_ctx_t.metrics_proto` | `src/fs/vfs/vfs.h:103` | **exists** as a variable | no | Already registered (`src/protocols/webdav/module_init.c:281`); W1 should MOVE it to http_common, not duplicate it |
| `$brix_auth_method` | `brix_identity_t.auth_method` | `src/core/types/identity.h:58` | no | per-request | It is a **bitmask** (`BRIX_AUTHN_*`, `:17-25`), not an enum — a session may carry more than one bit. Decide: render the primary, or a `+`-joined list. Use `brix_metric_auth_method_name()` for each bit |
| `$brix_dn` | `brix_identity_t.dn` | `src/core/types/identity.h:28` | no | per-request | Empty for non-GSI; render `-` |
| `$brix_token_sub` | `brix_identity_t.subject` | `src/core/types/identity.h:29` | no | per-request | Doubles as the S3 access key — see the exposure note below |
| `$brix_token_issuer` | `brix_identity_t.issuer` | `src/core/types/identity.h:30` | no | per-request | Empty for non-token auth |
| `$brix_vo` | `brix_identity_t.vo_csv` | `src/core/types/identity.h:39` | no | per-request | Already a CSV; do not re-derive from `vo_list` |
| `$brix_fqan` | `brix_identity_t.acc_vorg_csv` / `_role_csv` / `_group_csv` | `src/core/types/identity.h:47-49` | no | per-request | The three CSVs are **index-aligned with empty fields preserved** — a handler that joins them must preserve that alignment or the pairing is corrupted |
| `$brix_tls` | `brix_vfs_ctx_t.is_tls:1` | `src/fs/vfs/vfs.h:130` | no | per-request | Prefer nginx's own `$ssl_protocol` where the plane is HTTP; this exists for parity with the stream tier |
| `$brix_tier` | — | — | **yes** | no | Not currently a first-class field. Needs a data-plane decision about what "tier" names (posix/pblock/rados/http/s3/xroot backend, or the cache tier) before it can be implemented |
| `$brix_origin` | — | — | **yes** | no | Derivable from the bound `brix_sd_instance_t` (`src/fs/vfs/vfs.h:110`) but not currently surfaced as a name |
| `$brix_backend_time` | — | — | **yes** | no | Latency is passed to `brix_access_log_emit()` as `latency_usec` by the caller, not stored — so it exists at the call site but is not retained |

**Exposure note on `$brix_token_sub`.** `brix_identity_t.subject` is documented
as "JWT sub **or S3 access key**" (`src/core/types/identity.h:29`). An S3
access key is a credential identifier, and while it is not the secret key, it
is closer to credential material than a JWT `sub` is. W1's security-neg test
must cover the S3 path specifically, and the R10 allowlist entry must record
this dual meaning. This is precisely the sort of thing a variable surface
leaks by accident.

### Tier 2 — stream

The stream tier reads from `brix_ctx_t` (retrieved via
`ngx_stream_get_module_ctx`, e.g. `src/protocols/root/relay/relay.c:182`,
`src/protocols/root/connection/tls.c:27`,
`src/protocols/root/handoff/handoff.c:133`). A field-by-field inventory of
`brix_ctx_t` against the tier-2 list in Appendix A is **W2 step 0** and is not
yet done — it is the first thing W2 should produce, and until it exists the
tier-2 effort estimate is a guess.

### What this table means for sequencing

Eleven of the fourteen tier-1 variables are **handler-only work** — the value
already exists at the VFS seam and needs a get_handler plus a registration
row. Three (`$brix_tier`, `$brix_origin`, `$brix_backend_time`) need
data-plane work first.

**Therefore W1 should ship in two commits**: the eleven cheap ones first
(immediately useful, low risk, no data-plane change), then the three that need
new tracking. Do not let the three expensive ones hold up the eleven.

---

## Appendix H — target operator experience

The point of the phase, expressed as config an operator would write. None of
these work today; each is the acceptance criterion for its workstream in the
form the user actually cares about.

**W1 — a cache-hit-rate log line that works on every HTTP plane:**

```nginx
log_format brix '$remote_addr $status $body_bytes_sent '
                'cache=$brix_cache_status vo=$brix_vo auth=$brix_auth_method '
                'origin=$brix_origin backend_ms=$brix_backend_time';
access_log /var/log/nginx/brix.log brix;
```

**W1 — routing and shaping on brix state, with no brix code involved:**

```nginx
map $brix_cache_status $cache_slo { HIT 0; default 1; }
limit_req_zone $brix_vo zone=per_vo:10m rate=100r/s;   # nginx's engine, brix's identity
```

**W2 — root:// sessions in nginx's own stream access log:**

```nginx
stream {
    log_format brix_stream '$remote_addr vo=$brix_session_vo '
                           'ops=$brix_session_ops bytes=$brix_session_bytes_out';
    server { listen 1094; access_log /var/log/nginx/root.log brix_stream; }
}
```

**W3 — brix as the authz/cache brain in front of somebody else's upstream:**

```nginx
location /data/ {
    brix_decide on;                 # authz + cache lookup, no bytes served
    # brix answers with X-Accel-Redirect: /internal/...
}
location /internal/ { internal; alias /srv/data/; }
```

**W4 — brix authz protecting a location brix does not serve:**

```nginx
location /protected/ {
    auth_request /_brix_authz;
    auth_request_set $vo $upstream_http_x_brix_vo;
    proxy_pass http://legacy_backend;
}
location = /_brix_authz { internal; brix_authz on; }
```

The directive spellings above are illustrative, not decided — naming goes
through the phase-101/105 registry rules and `check_directive_registry.py`
before any of it is real.

---

## Appendix D — reproducing the census

Every measurement in this document is reproducible from the repo root. A
future reader re-verifying (or a reviewer checking that a claim still holds
after drift) should re-run these rather than trusting the prose.

```sh
# Module inventory — expect 15 (11 http, 4 stream)
grep -rhoE "^ngx_module_t +[a-z0-9_]+ = \{|^ngx_module_t$" src/ --include=*.c | wc -l
grep -rhn "^ngx_module_t " -A1 src/ --include=*.c \
  | grep -oE "ngx_(http|stream)_[a-z0-9_]+_module\b" | sort -u

# HTTP variable surface — expect 5 registration sites, 9 variables
grep -rn "ngx_http_add_variable" src/ --include=*.c

# Stream variable surface — expect ZERO (this is the W2 thesis)
grep -rnE "ngx_stream_add_variable|ngx_stream_variable_t" src/ shared/ --include=*.c --include=*.h | wc -l

# Internal redirect / X-Accel — expect NO hits (the W3 thesis)
grep -rlnE "ngx_http_internal_redirect|ngx_http_named_location|X-Accel" src/ --include=*.c

# Blocking HTTP transport sites (W5 deliverable 1 starts here)
grep -rln "curl_easy_perform" src/ shared/ --include=*.c
grep -rnE "curl_multi_perform|curl_multi_wait|curl_multi_socket_action" src/ --include=*.c

# The one in-tree ngx_http_upstream consumer — W5's worked example
grep -rlnE "ngx_http_upstream_t|ngx_http_upstream_init" src/ --include=*.c

# Thread-offload sites (proves TPC is NOT stalling the event loop)
grep -rn "ngx_thread_task_post" src/protocols/webdav/ --include=*.c
```

**Note the `-E`.** The two *absence* checks (stream variables, internal
redirect) are the load-bearing claims in this document, and without `-E` a
plain `grep` treats `|` as a literal and returns 0 — a FALSE confirmation of
exactly the thing you are trying to verify. Run them as written.

Claims that are *absences* (W2's zero stream variables, W3's zero internal
redirects) are the load-bearing ones and the easiest to invalidate by a later
commit — re-run those two greps first.

---

## Appendix E — risk register

| # | Risk | Where | Likelihood | Impact | Mitigation |
|---|------|-------|-----------|--------|------------|
| R-1 | A variable get_handler dereferences a freed pool or a NULL ctx and segfaults a worker in the log phase | W1, W2 | Medium — it is the classic variable bug | High (worker crash on a live server) | The variable-handler trap rules; `cvmfs_var_cache` (`src/protocols/cvmfs/module.c:167`) as the model; the W1 "error" test drives a request that never reaches brix |
| R-2 | A variable exposes credential material once an operator logs it | W1, W2, W4 | Medium — additions accrete over time | **Severe** (credential exfiltration into logs shipped off-box) | R10 gates from day one; per-variable exposure verdicts in Appendix A; W1 security-neg test |
| R-3 | Renaming `$cvmfs_cache` et al. breaks operator configs with a hard startup abort | W1-a | High if hard-renamed | Medium (site cannot start until config is edited) | OP-DECIDE W1-a; recommended time-boxed dual registration precisely because the failure is an abort, not a degradation |
| R-4 | `X-Accel-Redirect` becomes an authz bypass — a client injects the header, or a denied decision still reaches the internal location | W3 | Low if tested, **catastrophic if not** | **Severe** (unauthenticated read of any object) | The W3 security-neg test is the workstream's load-bearing test; internal location must be `internal;` and unreachable externally |
| R-5 | The outbound static-module handoff bypasses checksum/verification or POSC state, silently serving unverified bytes | W3 outbound | Medium | High (correctness + integrity regression) | Recommended deferral of the outbound half; if taken, the gate conditions must be enumerated and tested before any code |
| R-6 | The `auth_request` endpoint becomes a token oracle or is called repeatedly with a state-mutating side effect | W4 | Medium | High | Local verification only (W4-a recommendation); idempotence requirement; security-neg test asserts non-distinguishable failure modes |
| R-7 | An event-loop-reachable blocking `curl_easy_perform` stalls a worker under a slow token endpoint | W5 (existing, latent) | **Unknown — untraced** | High (availability) | W5 deliverable 1 is exactly this audit and runs FIRST; `vfs_deleg.c:199,214` is the specific unresolved caller |
| R-8 | A transport rewrite is started on the strength of this document's framing rather than the study's finding | W5 | Medium (the item is attractive) | High (large, risky, cross-cutting churn) | W5 ships no code; OP-DECIDE gate; the `curl_multi_socket_action` middle option must be costed before the big one |
| R-9 | Variables registered in preconfiguration behave differently under `load_module` than in a static build | W7 | Low–Medium | Medium (packaged builds diverge from dev) | W7's acceptance names this as the specific regression to prevent; test both builds |
| R-10 | This phase's variable surface drifts the way the directive surface did pre-101 | W8 | High without governance | Medium (accretes into another two-wave cleanup) | R7–R10 land alongside W1/W2, not after |

---

## Appendix F — implementation log

Kept in the phase-105 convention: each workstream appends its as-built record
here on completion, including deliberate divergences from this plan. A
divergence is not a defect — an unrecorded one is.

| WS | Landed | As-built notes / divergences |
|----|--------|------------------------------|
| W1 | **DONE 2026-08-30 (session 2)** | Step 2 (registration ownership) and the first two variables landed. NEW: `src/core/http/http_variables.{c,h}` owns the surface; the common module's preconfiguration hook — previously `NULL` at `src/core/config/http_common.c:109` — now calls `brix_http_add_variables()`. Shipped `$brix_cache_status` (nginx vocabulary; sourced from the cvmfs plane's existing disposition, `-` elsewhere) and `$brix_tls`. `$brix_protocol`/`$brix_delegated_cred` were left registered by webdav — moving them is a separate, riskier commit (the delegated-cred handler is ~90 lines of ucred logic) and is NOT done. Tests: `tests/test_brix_http_variables.py` (5 cells: 2 live success incl. a non-vacuity 404 case, 1 config-time error, 2 security-neg). Ledger: `lc-brix-variables` port 30913; shared lifecycle lane 927→928 and `PORT_COUNT` 2219→2220 (packed ladder — intentional compatibility event). Docs: `docs/03-configuration/config-reference.md` §nginx variables. SESSION 2 completed the surface: `$brix_dn`, `$brix_vo`, `$brix_fqan` (primary = first verified entry), `$brix_sub`, `$brix_issuer` (NOT `$brix_token_*` — the values are subject attributes whatever the auth method, and a `token_`-spelled name would have needed an R10 denylist exception for a non-credential value; deviation from Appendix A, deliberate), `$brix_auth_method` (the shared metrics vocabulary via `brix_metric_auth_method_name`), `$brix_tier` (the RESOLVED sd instance's name), `$brix_origin` (`storage_backend` with any `user:pass@` userinfo stripped before publishing). `$brix_cache_status` grew oci/rpm arms (hit/local→HIT, fill→MISS, refused/error→`-`). Identity comes from probing the webdav/s3 request ctxs (both carry `brix_identity_t*`); cvmfs/oci/rpm carry none and report `-`. NOT implemented, with reasons: `$brix_bytes_served`/`$brix_backend_time` duplicate nginx's own `$body_bytes_sent`/`$request_time` on the HTTP plane and would need per-request retention the data plane does not do; `$brix_checksum` needs the same retention (`io_result.crc32c` is per-op and not kept). **Deliberate divergence from the plan:** the plan's step 1 (surfacing VFS-seam values to the request) was NOT needed for these two variables and was skipped — `$brix_tls` reads the connection and `$brix_cache_status` reads the cvmfs request ctx. The eleven remaining tier-1 variables in Appendix G DO need step 1, because they read identity/IO state that no HTTP plane currently retains per-request; see the note below. |
| W2 | **DONE 2026-08-30** | NEW `src/protocols/root/stream/stream_variables.{c,h}`; the stream module's `preconfiguration` — previously `NULL` at `module_definition.c:16` — now registers 8 session-scoped variables: `$brix_protocol`, `$brix_session_{auth,user,dn,vo,tls,bytes_out,bytes_in}`. Session scope as planned. Tests: `tests/test_brix_stream_variables.py` (4 cells, incl. a real xrdcp transfer asserting the byte counter is not a constant, and an abort-before-login case). Ledger `lc-brix-stream-vars` port 30914; ladder 928→929, `PORT_COUNT` 2220→2221. **Two real findings during implementation**, both now encoded in the handler's comments: (1) the bytes are moved by the kXR_bind PARALLEL DATA CHANNEL, a separate session that inherits auth and carries no login of its own; (2) `login.logged_in`/`auth_done` are LIVE AUTHORIZATION state that `kXR_endsess` deliberately clears (`session/lifecycle.c:96-97`), so reading them at log time labels every well-behaved transfer as "brix never ran". A log variable must read the historical fact, not the current permission. |
| W3 | **DONE 2026-08-30** | `brix_webdav_accel_redirect <prefix>` in `src/protocols/webdav/authz_endpoint.{c,h}`. **Mechanism correction:** the plan (and the first implementation) assumed a handler could emit `X-Accel-Redirect`. It cannot — that is an UPSTREAM-RESPONSE feature; a content handler setting it produces a 200 with an empty body. The handler-side primitive is `ngx_http_internal_redirect()`, which is what this uses; the directive keeps the familiar name. **W3-a resolved (OP said implement): the outbound half is DONE too, and needed no new code** — `brix_webdav_accel_redirect` IS the static-handoff mechanism. Its target is any nginx location; point it at a plain `alias` location (the static module) and brix hands the request off after making the authz decision. Proven: a Range request through the handoff comes back `206 Partial Content` with a correct `Content-Range`, served by `ngx_http_static_module` (`tests/test_brix_authz_accel.py::test_w3_outbound_handoff_delivers_nginx_range_serving`). Post-W6 the value is understood to be marginal (brix already traverses nginx's range/not-modified filters), so this stays opt-in rather than an auto-gated fast path. |
| W4 | **DONE 2026-08-30** | `brix_webdav_authz on` in `src/protocols/webdav/authz_endpoint.{c,h}`: 204 + `X-Brix-{DN,Sub,Issuer,VO}` on success, the auth gate's own 401/403 otherwise. W4-a resolved as the plan recommended — local verification only, no token exchange (reinforced by the W5 audit finding that path to be a blocking event-loop call). **A real authorization bypass was found and fixed during implementation** — see the note below; it is the single most important outcome of this workstream. Also required enabling `--with-http_auth_request_module`, which the project's builds did not set: added to `build.yml`, `fanalyzer.yml`, `codechecker.yml`, `TESTING.md` (BUILD_INSTALL.md already had it). Tests: `tests/test_brix_authz_accel.py` (6 cells, 3 of them security-negative). |
| W5 | **AUDIT DONE 2026-08-30** (deliverable 1; no code, as planned) | See "W5 audit result" below. One event-loop-reachable blocking HTTP call found (`brix_token_exchange`, bounded at 30s); everything else is thread-offloaded or bounded. Deliverables 2/3 (cost/benefit matrix + recommendation) now written — see "Deliverable 2/3" above. Finding: the WHOLE remote-metadata path blocks (backend PROPFIND via the shared curl transport, not just the exchange), so the fix is transport-level. Recommendation: option (b), `curl_multi_socket_action` on the event loop, as its OWN phase (109) — not started here (cross-cutting, auth+data path, risk R-8). Interim posture enforced: every blocking curl call bounded + guarded (`test_blocking_curl_bounded.py`), which surfaced and fixed the `tpc_verify.c` gap. W5 was scoped study-only; the study is complete. |
| W6 | **AUDIT DONE 2026-08-30 — no convergence work needed** | `src/core/http/http_file_response.c:368,393` calls `ngx_http_send_header()` then `ngx_http_output_filter()`, so brix file responses ALREADY traverse nginx's filter chain — `ngx_http_not_modified_filter_module` and `ngx_http_range_filter_module` are active on the GET path. The premise of this workstream ("does brix bypass them?") is false: it does not. There is no double ETag generator on the served path either, because brix builds the response itself rather than handing off to the static module. The bespoke `http_conditionals.c` covers what nginx's filters cannot — conditionals on WRITE methods (WebDAV PUT/MOVE/COPY `Overwrite`, S3 PUT), which is correct as built. **Recommendation: close W6 with no code change**, and keep this record so the duplication is not "fixed" by someone who has not traced the filter chain. |
| W7 | **DONE 2026-08-30 (session 2)** | Separate build tree at `/home/rcurrie/nginx-dyn` (`--with-compat --add-dynamic-module`), leaving the fleet's static tree untouched. Confirmed: the RPM's shape is real — TWO combined objects (`ngx_stream_brix_module.so` 30MB carrying every brix module, plus the 68KB xrdhttp filter), not 15. Verified LIVE, not just `-t`: a plain 5.9MB nginx `load_module`s both objects and serves real bytes on BOTH planes (curl over webdav, xrdcp over root://), with the phase-106 variables resolving identically to the static build — the specific preconfiguration-ordering risk this workstream existed to test. Repeatable as `tests/test_brix_dynamic_modules.py` (4 cells; skips cleanly when the dynamic tree is absent, override with `BRIX_DYN_NGINX`). **Packaged-artifact acceptance met:** a real `.deb` is built from the module `.so` files with `dpkg-deb` (the package ships exactly these two objects at `usr/lib/nginx/modules/` — `packaging/deb/debian/nginx-mod-brix-cache.install`), unpacked, and the same directives+variables check runs against the UNPACKED artifact — passing. The RPM half needs `rpmbuild` (absent on this dev box; present in the almalinux:9 CI container), and the SAME test runs against it by pointing `BRIX_DYN_STREAM_SO`/`BRIX_DYN_FILTER_SO` at the installed rpm's modules — the test is package-source-agnostic by design. |
| W8 | **DONE 2026-08-30** | `tools/ci/check_directive_registry.py` gains four VARIABLE rules: R7 (brix_-prefix), R8 (documented in `docs/03-configuration/`, its own docs source since variables live in config-reference.md not directives.md), R9 (plane parity — same name on http AND stream is the GOAL and is allowed; two registrations on ONE plane is the nginx startup error it flags), R10 (credential-name denylist, one reviewed allowlist entry `$brix_delegated_cred`). All four report **ZERO** on the real tree. Fixtures: 7 cells in `tests/test_check_directive_registry.py` incl. an R10 not-trivially-evadable case and an R9 cross-plane non-vacuity case. W1-a executed with the plan's recommendation (dual registration): the seven legacy names now have `brix_`-prefixed twins resolving to the same handlers, legacy spellings allowlisted as deprecated. |

### W5 audit result — blocking-call reachability (2026-08-30)

Deliverable 1 of the study. Every `curl_easy_perform` site traced to its
caller, and each caller to either a thread or the event loop.

| Site | Reached from | Runs on | Bounded? |
|------|--------------|---------|----------|
| `src/auth/token/exchange.c:324` (`brix_token_exchange`) | `vfs_cred.c:127` → `brix_vfs_deleg_exchange` → any VFS op whose cred gate is active, incl. `brix_vfs_opendir` (`vfs_dir.c:100`), called by WebDAV PROPFIND (`propfind_walk.c`), SEARCH (`search.c:301`) and LOCK (`lock_check.c:192`) — **none of which are thread-offloaded** | **EVENT LOOP** | yes — `CURLOPT_CONNECTTIMEOUT` 10s, `CURLOPT_TIMEOUT` 30s (`exchange.c:34-35,308-309`) |
| `src/fs/cache/origin/s3_transport.c:138` | `brix_cache_fetch_origin` ← `src/fs/cache/thread.c:49` (fill worker) | thread | yes — `CURLOPT_TIMEOUT_MS` + optional connect/low-speed (`s3_transport_setup.c:387-395`) |
| `src/protocols/webdav/tpc_curl*.c` (incl. the `curl_multi_perform`/`curl_multi_wait` loop at `tpc_curl_multi.c:162`) | `ngx_thread_task_post` (`tpc_thread.c:496`, `tpc_marker_start.c:356`) | thread | yes |
| `src/auth/s3/sts_http.c` | S3 STS credential paths | (S3 request paths; same offload question as the cache fill) | yes — 4 timeout options set |
| `src/fs/cache/origin/pelican_register.c` | origin registration | background/registration | yes — 4 timeout options set |

**Finding (R-7, confirmed).** With `brix_cred_mode exchange` configured, a
WebDAV **PROPFIND / SEARCH / LOCK** performs a blocking RFC-8693 token-exchange
POST **on the nginx event loop**. A slow or unreachable exchange endpoint
therefore stalls the entire worker — every unrelated connection on it — for up
to 30 seconds per cache miss.

Severity is materially reduced by three existing facts, which is why this is a
"fix properly, not urgently" bug rather than an incident:

1. The call is **bounded** at 30s total / 10s connect — it cannot hang forever.
2. A per-worker minted-token cache keyed on (subject token, audience) fronts it
   (`exchange_cache.c`), so only a cold miss POSTs.
3. It only arms when the operator configures EXCHANGE mode with an endpoint;
   PASSTHROUGH (the common case) never reaches it.

**Recommended fix (not implemented here).** Offload the exchange the way TPC
already offloads its transfers (`ngx_thread_task_post`), or drive it with
`curl_multi_socket_action` on the event loop. Both are W5 deliverable-3 work
and must not be started before the transport recommendation is accepted — the
same `curl_multi_socket_action`-vs-`ngx_http_upstream` question governs both.
Interim mitigation available today with no code change: lower
`BRIX_TX_TIMEOUT`, or keep EXCHANGE mode off where PROPFIND latency matters.

**Follow-up (2026-08-31): the audit's first pass missed one site.** Turning
the audit's mitigation into an enforced invariant (`tests/test_blocking_curl_bounded.py`
— every blocking curl transfer must be time-bounded) immediately flagged
`src/protocols/webdav/tpc_verify.c:158`: a fresh `curl_easy_init()` + HEAD probe
of a TPC source with **no timeout**. It runs on a thread-pool thread, so it is a
thread-exhaustion vector (a black-holed source pins a thread forever) rather
than an event-loop stall — less severe, but real. FIXED in the same follow-up
(connect + total timeout reusing the operator's TPC budgets), and now guarded.
This is why the invariant is a test, not a one-time audit: a snapshot misses
what a ratchet catches.

**What the audit did NOT find.** No unbounded blocking HTTP call anywhere;
every site sets a timeout. The cache-fill path — the one that would have been
most damaging — is correctly on a fill worker thread.

---

### W3/W4 as-built note — the authorization bypass (2026-08-30)

Worth recording in full, because the plan's instinct ("the security-negative
test is the load-bearing one") is what caught it, and the bug is not obvious.

Both seams were built on this reasoning: *nginx runs the ACCESS phase before
the CONTENT phase, so reaching the content handler means the access phase
already ran `access_authenticate()` and admitted the request; the handler need
only report the verdict.* That is true for a main request — and **false for a
subrequest**, which is exactly what `auth_request` issues:

```c
ngx_http_core_access_phase(ngx_http_request_t *r, ngx_http_phase_handler_t *ph)
{
    if (r != r->main) { r->phase_handler = ph->next; return NGX_AGAIN; }
```

So the first implementation answered **204 unconditionally** to every
`auth_request` subrequest: brix became a rubber stamp that admitted everything
an operator delegated to it. The `/denied/` cell returned 200 where it should
have returned 401, which is how it surfaced.

The fix (`webdav_authz_enforce`) explicitly runs
`ngx_http_brix_webdav_access_handler(r)` when `r != r->main` — the same code
path a main request takes, so there is still no second copy of the policy — and
fails **closed** (403) on `NGX_DECLINED`, i.e. when the seam is enabled on a
location with no brix policy configured.

Two lessons for anyone extending this: (1) "an earlier phase already checked"
is not a security argument until you have confirmed the phase runs for the
request shape you are serving; (2) a gate-only endpoint must fail closed on
"no policy configured", because the whole point is that something else is
trusting its verdict.

---

### W1 as-built note — what step 1 actually requires (discovered 2026-08-30)

Appendix G assumed the eleven "handler-only" tier-1 variables could read the
VFS seam directly. Implementation showed that is **not** true as stated, and
the plan should be read with this correction:

`brix_vfs_ctx_t` carries no `ngx_http_request_t`, and the VFS op has completed
and returned by the time a variable handler runs in the log phase. The values
are correct and complete at the seam, but nothing carries them back to the
request. There is also no shared per-request identity accessor: each protocol
keeps its own request ctx (`wctx->identity` at
`src/protocols/webdav/access_vfs_ctx.c:105`), so an identity variable must
either probe every protocol's ctx — the shape `$brix_protocol` already uses for
loc confs at `src/protocols/webdav/module_init.c:52-56` — or the protocols must
publish identity to a common per-request record.

So step 1 is real work, not a formality, and the honest split is:

- **cheap (done)**: variables readable from the connection or an existing
  protocol request ctx — `$brix_tls`, `$brix_cache_status`.
- **medium**: identity variables (`$brix_dn`, `$brix_vo`, `$brix_fqan`,
  `$brix_auth_method`, `$brix_token_sub`, `$brix_token_issuer`) — need the
  common per-request identity record, touching each protocol's auth completion
  point once.
- **expensive (unchanged)**: `$brix_tier`, `$brix_origin`,
  `$brix_backend_time` — need data-plane tracking that does not exist.

Appendix G's "eleven of fourteen are handler-only" should be read as "two are
handler-only today; six more become handler-only once a common per-request
identity record exists".

---

## Open questions for the OP — ALL RESOLVED (2026-08-31)

The OP directed "implement all," which decides every gate below.

1. **W1-a** — RESOLVED: time-boxed dual registration. The seven legacy names
   keep their unprefixed spelling alongside `brix_`-prefixed twins on the same
   handlers; the legacy spellings are allowlisted as deprecated. Chosen because
   a stale variable in a `log_format` is a startup abort, not a degradation.
2. **W3-a** — RESOLVED: outbound half IS in scope and is DONE. It needed no new
   code — `brix_webdav_accel_redirect` targeting a static `internal` location
   is the handoff; proven with a 206/Content-Range test. No separate
   verification-gate phase was needed because the local-file case carries no
   fill/verification step to bypass.
3. **W4-a** — RESOLVED: local verification only, no token exchange. Reinforced
   by the W5 audit, which found the exchange to be a blocking event-loop call.
4. **W5-a** — RESOLVED: recommendation written (option (b),
   `curl_multi_socket_action`), transport rewrite deferred to its own phase 109
   as the recommendation itself directs. The study — W5's actual scope — is
   complete; no transport code was rushed onto the auth+data path.
5. **External adoption vs observability** — RESOLVED: both. W1/W2 deliver
   observability; W3/W4 deliver external adoption. All landed.

Nothing in phase 106 remains open. The single forward pointer is phase 109
(the `curl_multi_socket_action` transport conversion), which this phase
deliberately does not begin.
