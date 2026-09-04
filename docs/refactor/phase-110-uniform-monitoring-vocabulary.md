# Phase 110 — one monitoring vocabulary: the same word for the same fact on every plane and every surface

**Status:** COMPLETE 2026-09-02. W1–W7 and W9–W12 are implemented; W8 was
correctly resolved as a re-scope because `brix_io_ops_total` already provides
the uniform request count. The retained aliases, JSON keys and duplicate metric
families are an intentional one-release compatibility surface whose removal is
owned by Phase 112, not an incomplete Phase-110 workstream.

Source: the phase-106 W1/W2/W8 variable surface as shipped, the JSON access
log (`src/observability/metrics/access_log.c`), and the Prometheus export
(`src/observability/metrics/unified_export.c`), audited 2026-09-01 on `main`
@ `af39af9eb`.

Companion docs: `phase-106-nginx-native-integration-surface.md` (built the
variable surface this phase makes uniform), `phase-109-http-metadata-thread-offload.md`
(the offload pattern W3's stream-side monitor reuses).
Compatibility removal after the migration window is owned by
[Phase 112](phase-112-observability-compatibility-removal.md).

**Goal.** An operator writing a `log_format`, a `map`, a Prometheus query or a
`jq` filter over brix should use ONE word per fact and never have to know
which plane served the request or which surface they are reading. Today the
same fact is spelled up to four different ways — `$brix_sub` / `$brix_session_user`
/ `"subject"` / (no metric) — and the two main data planes (WebDAV, S3)
report `-` for the flagship variable, `$brix_cache_status`. This phase does
not add new *information*; it makes the information brix already has answer
to one name everywhere, and it deletes the need to reach for a differently-
spelled nginx variable on the other plane.

---

## The problem, precisely

Three surfaces, three dialects. The audit (Appendix A reproduces every row):

| Fact | HTTP variable | stream variable | JSON access log | Prometheus | Dialects |
|------|---------------|-----------------|-----------------|------------|----------|
| protocol | `$brix_protocol` | `$brix_protocol` | `proto` | `proto` label | **1 — the model row** |
| auth method | `$brix_auth_method` | `$brix_session_auth` | `auth_method` | `brix_auth_total{method}` | 3 |
| subject | `$brix_sub` | `$brix_session_user` | `subject` | — | 3 |
| DN / VO | `$brix_dn` `$brix_vo` | `$brix_session_dn` `$brix_session_vo` | — | — | 2 |
| FQAN / issuer | `$brix_fqan` `$brix_issuer` | — | — | — | absent on stream |
| TLS | `$brix_tls` | `$brix_session_tls` | — | — | 2 |
| cache disposition | `$brix_cache_status` (**`-` on WebDAV/S3**) | — | `from_cache` (bool) | `cache_hits_total` / `cache_misses_total` | 3, and absent where it matters most |
| bytes to client | `$brix_bytes_served` | `$brix_session_bytes_out` | `bytes` | `bytes_tx_total` | 4 |
| bytes from client | — (`$request_length`) | `$brix_session_bytes_in` | — | — | absent on HTTP |
| backend time | `$brix_backend_time` (s.mmm) | — | `latency_us` (µs) | `io_latency_usec` (µs) | 3, two units |
| checksum | `$brix_checksum` | — | — | — | absent on stream (the plane that computes it) |
| operation | — (`$request_method` is the HTTP verb) | — | `op` | `op` label | no variable at all |
| storage path | — (`$uri` is the URL) | — | `path` | — | no variable at all |
| outcome | `$status` (HTTP code) | `$status` (stream code, different meaning) | `status` (brix string) | err-class labels | no plane-neutral word |
| mapped local user | — | `$brix_session_user` (which is really the *subject*) | — | — | conflated with subject |
| tier / origin | `$brix_tier` `$brix_origin` | — | — | `backend` label (own spelling) | absent on stream |
| duration | `$request_time` | `$session_time` | — | — | nginx itself spells it differently per plane |

Two things are wrong, and they are different things:

1. **Same fact, different name.** `session_` on every stream identity variable
   was a plan-time choice ("stream variables are session-scoped, say so in
   the name"). It costs every operator a second `log_format` and a second set
   of dashboard filters for facts that mean exactly the same thing. Phase-106
   W8's rule R9 already *permits* the same name on both planes — its
   docstring says that is the goal — so nothing structural blocks the fix.
2. **Same fact, different value vocabulary.** `$brix_cache_status` says
   `HIT`; the JSON log says `"from_cache":true`; Prometheus counts
   `cache_hits_total`. A grep, a `map`, and a PromQL filter cannot share a
   string. `$brix_auth_method` is the proof this can be done right: it was
   built (phase-106 W1) to return `brix_metric_auth_method_name()` — the
   Prometheus label's own function — so the three surfaces agree by
   construction, not by convention.

And one gap that is neither: **the two planes that move most bytes report no
cache disposition.** `brix_request_cache_status()` (`src/core/http/http_variables.c:147`)
probes only the cvmfs/oci/rpm ctxs. The bit exists — `brix_vfs_io_result_t.from_cache`
(`src/fs/vfs/vfs.h`), and the post-op observer already has it in hand
(`access_log.c:116` reads it for the JSON log) — it was simply never retained
per request. The phase-106 W1 tail built exactly that retention
(`brix_io_monitor_t`, `src/observability/metrics/io_monitor.h`); folding one
more bit into it closes the gap.

---

## Options table

| Option | What it is | Cost | Verdict |
|--------|------------|------|---------|
| (a) Document the dialects | A mapping table in config-reference.md | S | **Rejected as the fix.** It formalises the switching this phase exists to remove. Ship it only as the *deprecation* table for the old names. |
| (b) Alias at the nginx layer | `map $brix_session_dn $brix_dn` snippets | S | **Rejected.** Pushes the work onto every operator, and `map` cannot rename a JSON field or a metric label. |
| (c) One name per fact, registered on every plane, emitted by every surface, with the old names kept as deprecated aliases for one release | The registrations move to the common owner where they aren't already; value strings come from the shared `brix_metric_*_name()` functions; JSON fields and label names are renamed with a compat window | M | **Recommended.** It is the phase-106 W1 pattern (`$brix_auth_method`) applied to the rest of the surface. |

---

## Standing rules (bind every workstream)

1. **One name per fact, on both planes.** If a fact exists on HTTP and stream it
   is registered under the *same* `$brix_*` name on both. `session_` is not a
   name component. R9 in `check_directive_registry.py` already allows this;
   W5 tightens it to *require* it.
2. **One value vocabulary per fact, on all three surfaces.** The variable's
   returned string, the JSON field's string, and the Prometheus label value
   for one fact come from the SAME `brix_metric_*_name()` function
   (`src/observability/metrics/unified.c`). No surface renders its own
   spelling. New name functions are added there, never inline.
3. **Same field name across surfaces.** The JSON key and the Prometheus label
   for a fact are the variable's name without `brix_`: `$brix_cache_status` ↔
   `"cache_status"` ↔ `cache_status="HIT"`.
4. **Units are in the name only where the surfaces cannot agree.** Variables
   render seconds with millisecond precision because that is what sits beside
   `$request_time` in a log line; JSON and Prometheus keep microseconds
   because that is what their consumers already parse. So the JSON field is
   `backend_time_us`, the metric stays `io_latency_usec`, and the variable is
   `$brix_backend_time` — the unit suffix tells the reader which one they are
   holding. Nothing else carries a unit.
5. **Deprecate, never break, for one release.** Every old name (variable,
   JSON key) keeps working, is listed in the R7 deprecated allowlist with a
   removal phase, and is *absent from every example in the docs*. Prometheus
   label additions are additive (add the new label; drop the old after the
   window). An operator's existing `log_format` must parse unchanged
   throughout.
6. **Replicate only where brix owns the semantics or nginx changes the
   spelling between planes.** `$remote_addr`, `$server_addr`, `$ssl_protocol`,
   `$ssl_cipher`, `$connection`, `$request_id` are named identically by nginx
   on both planes and carry no brix meaning — they are NOT twinned.
   `$request_time`/`$session_time` ARE twinned (W6) for exactly one reason:
   nginx spells the same fact two ways.
7. **R10 stands.** Nothing credential-shaped is added. `$brix_delegated_cred`
   remains the single reviewed exception; the mapped local user (W2) is an
   account name, not a credential, and is reviewed as such in the allowlist
   note.
8. **3 tests per change**, and every rename ships with a byte-identity test:
   old name and new name resolve to the same value on the same request.
9. **Thread contract from phase-106 W1 tail / phase-109 applies.** Any new
   per-request or per-session retention is allocated on the event loop and
   only scalar-written from a worker thread (`io_monitor.h` header comment).

---

## W1 — `$brix_cache_status` on the data planes, and one cache vocabulary

### Current state

`brix_request_cache_status()` (`http_variables.c:147`) returns `-` unless a
cvmfs/oci/rpm ctx is present, so WebDAV and S3 GET — the bulk of served bytes
— never report a disposition. `brix_vfs_io_result_t.from_cache` is set by the
VFS read path and read by the observer for the JSON log (`access_log.c:116`),
but not retained. The JSON log emits `"from_cache":true|false`; Prometheus has
`brix_cache_hits_total` / `brix_cache_misses_total` (`unified_export.c:185-192`)
and no label carrying the disposition word. Four legacy per-plane variables
(`$brix_cvmfs_cache` / `$cvmfs_cache`, `$brix_oci_cache`, `$brix_rpm_cache`)
each render their own spelling (`hit`/`fill`/`neg`).

### Change

1. Add a cache-disposition field to `brix_io_monitor_t` (`io_monitor.h`):
   `brix_cache_status_e cache;` folded at the VFS cache decision
   (`brix_vfs_observe_cache_result`, `vfs_open.c`): `HIT` when the open was
   served from a cache tier, `MISS` when a tier was consulted and populated
   from origin. `BYPASS` is the `O_NOCACHE` arm — a cache tier IS configured
   but this request deliberately skipped it — matching nginx's own
   `$upstream_cache_status` BYPASS. **Correction to an earlier draft of this
   bullet:** `cache_enabled == 0` (no tier on the export) is **`-` (NONE)**,
   NOT BYPASS — the standing-rules vocabulary is authoritative (`-` = no tier
   or no I/O; BYPASS = tier present, skipped). NB: no code path in
   `src/protocols/` sets `O_NOCACHE` on a client read today, so BYPASS is not
   reachable by a client GET and has no runtime test; the arm exists for
   vocabulary completeness and is exercised only by internal callers.
2. `brix_request_cache_status()` gains a first arm: if the request's monitor
   exists and reports a disposition, return it; otherwise fall through to the
   cvmfs/oci/rpm probes unchanged.
3. Add `brix_cache_status_name()` (already exists, `http_variables.c:55`) to
   the shared name functions in `unified.c` — move it, do not duplicate — so
   the JSON log and Prometheus can call it.
4. JSON log: emit `"cache_status":"HIT"` alongside `"from_cache"` (kept,
   deprecated). Prometheus: `brix_cache_requests_total{proto,cache_status}`
   as a new family; the two old counters keep incrementing for the window.
5. Register `$brix_cache_status` on the stream plane (W3 supplies the
   per-session monitor it reads).
6. Docs: config-reference.md lists the four legacy per-plane cache variables
   under a **Deprecated** heading pointing at `$brix_cache_status`; they leave
   every example.

### Tests

- **success** — a WebDAV GET served from cache logs `cache=HIT`; the same
  object's first (cold) GET logs `cache=MISS`; the JSON line for each op
  carries the identical word; the new counter increments with the identical
  label value. One assertion per surface, on the same request.
- **error** — a GET on a location with NO cache tier logs `cache=-` (not
  `MISS`, not `BYPASS`); a 404 on a cache-enabled export logs `cache=MISS` (the
  cache was consulted and missed, mirroring `brix_cache_misses_total`). BYPASS
  (a configured tier deliberately skipped via `O_NOCACHE`) is not reachable by a
  client GET, so it is verified by code review, not a runtime test.
- **security-neg** — the disposition never leaks across requests: two
  interleaved GETs on one keepalive connection (one HIT, one MISS) each log
  their own word (the monitor is per-request, not per-connection).

### Acceptance

- `$brix_cache_status` is non-`-` on every successful WebDAV and S3 GET.
- `grep cache=HIT access.log | wc -l` and `sum(rate(brix_cache_requests_total{cache_status="HIT"}[5m]))`
  and `jq 'select(.cache_status=="HIT")'` count the same events.
- The cvmfs/oci/rpm planes are byte-identical to before (their arms still run
  when no monitor exists).

---

## W2 — the identity set: same names on both planes, subject ≠ user

### Current state

Stream (`stream_variables.c:249-263`): `$brix_session_dn`, `$brix_session_vo`,
`$brix_session_user`, `$brix_session_auth`, `$brix_session_tls`. HTTP:
`$brix_dn`, `$brix_vo`, `$brix_fqan`, `$brix_sub`, `$brix_issuer`,
`$brix_auth_method`, `$brix_tls`. `$brix_session_user` publishes the
*subject* (the DN or token `sub`); the genuinely separate fact — the mapped
local account the request runs as under impersonation
(`brix_identity_t.mapped_user`, `src/core/types/identity.h:71`) — has no
variable on either plane. The JSON log key is `subject`.

### Change

1. Register on stream, reading the session `brix_ctx_t` identity exactly as
   the existing handlers do: `$brix_dn`, `$brix_vo`, `$brix_fqan`,
   `$brix_sub`, `$brix_issuer`, `$brix_auth_method`, `$brix_tls`. FQAN uses
   the same "first verified entry" rule as HTTP (`http_variables.c:269`).
2. Keep `$brix_session_dn/vo/user/auth/tls` registered as **deprecated
   aliases** resolving to the same handlers; add them to the R7 deprecated
   allowlist with `removal: phase-112`.
3. New on both planes: `$brix_user` = `mapped_user` when resolved and
   non-empty, else `-`. This is what `$brix_session_user` was *named* like
   but did not publish. Documented as an account name (R10 review note).
4. Handlers stay static-string / request-pool only (the phase-106 "variable-
   handler trap" rules in `http_variables.c:14-28` apply verbatim on stream:
   the stream ctx can be gone at log time for an aborted session — the
   existing `brix_stream_var_str` NULL-tolerance is the pattern).
5. JSON log: `"sub"` added, `"subject"` kept for the window.

### Tests

- **success** — one `log_format brix_all '... dn=$brix_dn vo=$brix_vo sub=$brix_sub auth=$brix_auth_method tls=$brix_tls user=$brix_user'`
  is loaded unchanged into BOTH an `http {}` and a `stream {}` block and
  produces a parseable line from an xrdcp transfer and a curl GET; for a GSI
  identity the `dn=` field is byte-identical on both.
- **error** — an abort-before-login stream session logs `-` for every
  identity field (the phase-106 W2 test extended to the new names).
- **security-neg** — `$brix_user` on a request whose identity did NOT map
  reports `-`, never the DN and never the worker's own account; and
  `$brix_session_user` (deprecated) still equals `$brix_sub` byte-for-byte
  (alias identity test). **Update (2026-09-03):** phase-112 REMOVED the
  `$brix_session_*` aliases, so the alias half of this bullet is retired; the
  de-conflation it protected — `$brix_user`=mapped_user vs `$brix_sub`=subject
  as *distinct* fields on both planes — is now pinned structurally by
  `test_uniform_monitoring_guard::test_user_is_the_mapped_account_and_sub_is_the_subject_on_both_planes`,
  because the unmapped-`-` runtime test alone cannot catch a re-conflation (`-`
  is what both a missing mapping and an anonymous subject render).

### Acceptance

- Every identity fact has one name that resolves on both planes.
- The deprecated names resolve identically and appear in no documentation
  example.

---

## W3 — the data-plane set on stream: bytes, backend time, checksum, tier, origin

### Current state

Stream has `$brix_session_bytes_out/in` (`stream_variables.c:261-263`,
per-session counters on `brix_ctx_t`). It has no backend time, no checksum,
no tier/origin — yet the root:// plane is the one where `pgread` computes
the page-CRC that `$brix_checksum` exists to report, and where the metadata
walk offload (phase-109) already runs I/O whose latency is measured by the
same VFS observer.

### Change

1. Give the stream session a `brix_io_monitor_t` on the connection pool,
   allocated at session creation (event loop), pointed at by every VFS ctx
   the session builds (the root plane's ctx builder — the analogue of
   `webdav_vfs_ctx_build_data`). The observer then folds backend time and
   page-CRC with zero new fold code; served bytes fold where the root plane
   books its wire counters today (the `bytes_out` accumulator site).
2. Register on stream: `$brix_bytes_served` (= what `$brix_session_bytes_out`
   reads), `$brix_bytes_received` (= `bytes_in`), `$brix_backend_time`,
   `$brix_checksum`, `$brix_tier`, `$brix_origin` — the last two from the
   stream server conf's storage instance exactly as `brix_var_tier` reads the
   HTTP loc conf.
3. Register on HTTP: `$brix_bytes_received` = the request body bytes brix
   consumed for PUT/POST (the put_body / S3 put accounting sites already count
   them). `-` on a GET.
4. Deprecated aliases: `$brix_session_bytes_out` → `$brix_bytes_served`,
   `$brix_session_bytes_in` → `$brix_bytes_received`.
5. JSON log: `"bytes"` → `"bytes_served"` (old kept), `"latency_us"` →
   `"backend_time_us"` (old kept). Rule 4: the unit suffix stays because
   variables render seconds.

### Tests

- **success** — an xrdcp `pgread` transfer logs `ck=crc32c:<8 hex>` on the
  stream plane and the value equals the client-side page CRC of the same
  bytes (the non-vacuous checksum test the HTTP plane could not have, because
  a plain GET computes none); `bytes=$brix_bytes_served` equals the transfer
  size; `backend=$brix_backend_time` matches `^\d+\.\d{3}$`.
- **error** — a session that opens a file and aborts before reading logs
  `bytes=0`? No — logs `-` for bytes (nothing served) but a non-`-`
  backend time (the open was real I/O). This pins the "`-` means no event,
  `0` means measured zero" rule per field.
- **security-neg** — the monitor is per-session: two sessions on one worker,
  one large transfer and one small, log their own byte counts (no cross-
  session accumulation through a shared ctx).

### Acceptance

- The same `log_format` from W2 extended with `bytes= backend= ck= tier=`
  loads on both planes and every field is non-empty where the fact exists.

---

## W4 — the facts brix has that no nginx variable can express: `$brix_op`, `$brix_path`, `$brix_status`

### Current state

The JSON access log carries per-op `op`, `path`, `status` (`access_log.c:123-124`)
from `brix_metric_op_name()` (`unified.c:110`) and the brix error class.
Prometheus labels every I/O family by `op` and error class. No variable
exposes any of the three. Operators substitute `$request_method` (the HTTP
verb — indistinguishable for TPC-COPY vs COPY, GetObject vs ListBucket,
PROPFIND depth 0 vs infinity), `$uri` (the URL, not the export-relative
storage path after alias/bucket mapping), and `$status` (an HTTP code on one
plane, a stream code on the other, and nothing at all for a brix refusal that
never became an HTTP response).

### Change

1. `$brix_op` on both planes: the brix operation word from
   `brix_metric_op_name()` for the request's *primary* op (HTTP: the op the
   content handler dispatched — GET/PUT/PROPFIND/COPY/TPC…; S3: the S3 op
   name the handler already sets in `brix_http_serve_opts_t.op_name`; stream:
   the last dispatched kXR op of the session, with `ops=$brix_ops` as the
   count). Retained in the monitor as a small enum, not a string.
2. `$brix_path` on both planes: the resolved export-relative path
   (`brix_vfs_ctx_t.resolved.resolved`) of the primary op — the string the
   JSON log already prints. Pool-owned by the request; `-` when no resolve
   happened. **SECURITY:** this is the *confined, resolved* path, never the
   raw client URL, so a traversal probe logs the refused path or `-`, and it
   is subject to the same R10-style review as `$brix_origin` (no userinfo
   can appear in it; add the assertion).
3. `$brix_status` on both planes: the brix outcome class of the primary op —
   `ok`, `enoent`, `eacces`, `erofs`, `eio`, `eexist`, `etimedout`, … — via a
   NEW `brix_metric_err_class_name()` in `unified.c` (the audit found no such
   name function; the class enum is `brix_err_class_t`, `metrics.h`). The
   JSON log's `"status"` string and the Prometheus error labels are switched
   to call the same function (they are currently hand-spelled). This is the
   plane-neutral outcome word: an `EROFS` refusal on WebDAV, S3 and root://
   logs `status=erofs` on all three, whatever HTTP/stream code was sent.
4. Per rule 3: JSON keys `op`/`path`/`status` already match; only the value
   source for `status` changes.

### Tests

- **success** — a TPC COPY and a plain COPY to the same location log
  `op=copy_tpc` vs `op=copy` while `$request_method` says `COPY` for both; an
  S3 GetObject and ListBucket log different `op=` under the same `GET`.
- **error** — a PUT on a read-only export logs `status=forbidden` on WebDAV, on
  S3 and on root:// (three planes, one word). **Correction (2026-09-03):** the
  Prometheus twin of that status word is the `status` label on
  `brix_io_ops_total` / `brix_tpc_transfers_total` (both rendered through the
  same `brix_metric_err_name`), NOT `brix_vfs_mutation_denied_total{reason}` as
  an earlier draft of this bullet claimed. `status` and that `reason` label are
  DIFFERENT facts and correctly carry DIFFERENT strings: `status` is the outcome
  CLASS (`forbidden`), while `reason` is the denial CAUSE — the fixed literal
  `read_only` (the sole VFS read-only mutation result; a bounded label, never
  the outcome word). Pinned by `test_uniform_monitoring_guard::test_status_word_renders_through_the_shared_err_name_on_every_surface`
  (the one-word-every-surface identity) and `::test_mutation_denied_reason_is_the_denial_cause_not_the_outcome_class`
  (the two are distinct facts, not to be unified).
- **security-neg** — `GET /../../../../etc/passwd` logs `path=-` or the
  confined refusal path, never a string containing `/etc/`; a URL carrying
  `user:pass@` in an alias target never appears in `$brix_path`.

### Acceptance

- One `log_format` line with `op= path= status=` is meaningful on every plane
  and needs no nginx `$request_method`/`$uri`/`$status` to disambiguate.

---

## W5 — governance: the guard makes parity and vocabulary mandatory

### Current state

`check_directive_registry.py` R7 (prefix), R8 (documented), R9 (plane parity
*permitted*), R10 (credential denylist) gate. Nothing requires a fact to be on
both planes, nothing checks that a variable's value function is the shared
name function, and nothing cross-checks the JSON keys or Prometheus labels
against the variable names.

### Change

1. **R11 — parity required.** For every variable in a `PARITY_FACTS` list
   (the W1–W4 names), registration must exist on BOTH `ngx_http_add_variable`
   and `ngx_stream_add_variable` sites. Reports until W3 lands, then gates.
2. **R12 — shared vocabulary.** A variable handler that returns a fact in
   `VOCAB_FACTS` (cache_status, auth_method, op, status, tier) must call the
   corresponding `brix_metric_*_name()`; a handler containing its own string
   literal for one of those facts is a finding. Source-level, modelled on
   `check_vfs_mutation_gate.py`'s "reached only through the kernel" shape.
3. **R13 — cross-surface key parity.** The JSON keys emitted by
   `brix_access_log_emit` and the label names in `unified_export.c` for the
   facts above must equal the variable name minus `brix_`. A table test, not
   a regex heroics test.
4. Deprecated-alias registry: the R7 allowlist entries gain a `removal:`
   field; a test fails the build once the named phase is marked IMPLEMENTED
   in `docs/refactor/` and the alias is still registered (the same
   "self-deleting pin" idea as the DEFECT-CANDIDATE tests).

### Tests

- **success** — R11/R12/R13 report zero on the post-W4 tree.
- **error** — fixtures: a variable registered on HTTP only; a handler with an
  inline `"HIT"` literal; a JSON key `"cache_state"`. Each is a finding, and
  each gates under `--fail` (the phase-106 R10 lesson — a rule that prints
  but does not gate is a false sense of security; the test asserts `rc==1`).
- **security-neg** — R10 is unchanged and still fires on a `brix_bearer_*`
  fixture after the R11–R13 additions (no rule regression).

### Acceptance

- Adding a brix variable on one plane only, or with its own spelling of a
  shared fact, fails CI.

---

## W6 — `$brix_duration`: the one transport twin

### Current state

Total wall time is `$request_time` on HTTP and `$session_time` on stream —
the same fact, two nginx names. This is the sole transport fact this phase
twins (rule 6), because the switching cost is nginx's own inconsistency, and
because `$brix_backend_time` is only meaningful next to the total.

### Change

`$brix_duration` on both planes, rendered `seconds.mmm` exactly as
`$request_time`, reading `r->start_sec/start_msec` on HTTP and the session
start on stream. No retention needed. Documented as "identical to
`$request_time` / `$session_time`; exists so one log_format serves both
planes".

### Tests

- **success** — on HTTP, `$brix_duration == $request_time` byte-for-byte in
  the same log line; on stream, `== $session_time`.
- **error** — an aborted request still logs a duration (never `-`; wall time
  always exists).
- **security-neg** — N/A beyond R10 (a duration is not credential-shaped);
  the R10 test's negative fixture set is asserted unchanged.

### Acceptance

- The Appendix H log_format below loads on both planes with zero nginx
  variables other than `$remote_addr`.

---

## Non-goals (explicit)

1. **No new information.** Every value this phase publishes already exists in
   brix (the JSON log proves it). No new measurement, no new counter beyond
   the vocabulary-carrying `brix_cache_requests_total`.
2. **No removal of any old name in this phase.** Removal is phase-112 by the
   deprecated-alias registry (W5.4). An operator upgrading across this phase
   changes nothing and sees nothing break.
3. **`$remote_addr`, `$ssl_*`, `$server_*`, `$connection`, `$request_id` are
   not twinned** (rule 6).
4. **Per-op variables on stream are not attempted.** Stream variables stay
   session-scoped (the phase-106 W2 decision); per-op detail on root:// is the
   JSON access log's job. `$brix_op` on stream is "last op" + `$brix_ops`
   count, documented as such.
5. **The JSON log's line shape is not redesigned** — keys are added and
   value sources unified; nothing is removed inside the window.
6. **`$brix_delegated_cred` is untouched** (R10's single exception).

---

## Appendix A — reproducing the audit

```sh
# HTTP variables actually registered (filters out directive names that share the ngx_string() shape)
grep -n 'ngx_string("brix_' src/core/http/http_variables.c
grep -rn 'ngx_http_add_variable' src/ --include=*.c

# Stream variables — expect 8, five with the session_ prefix
grep -n 'ngx_string("brix_' src/protocols/root/stream/stream_variables.c

# JSON access-log keys — expect: ts proto op path bytes offset latency_us status from_cache auth_method subject remote
grep -oE '\\"[a-z_]+\\":' src/observability/metrics/access_log.c | sort -u

# The one fact that is already uniform: proto everywhere
grep -rn '"proto"' src/observability/metrics/*.c | head

# Cache: variable says HIT, log says from_cache, metrics say hits/misses
grep -n 'from_cache' src/observability/metrics/access_log.c src/fs/vfs/vfs.h
grep -n 'brix_cache_hits_total\|brix_cache_misses_total' src/observability/metrics/unified_export.c

# The data planes report "-": only cvmfs/oci/rpm ctxs are probed
sed -n '146,166p' src/core/http/http_variables.c

# Shared name functions that exist (the pattern) and the one that doesn't (err class)
grep -n '^brix_metric_[a-z_]*_name' src/observability/metrics/unified.c

# Mapped local user — the fact $brix_session_user was named for but does not publish
grep -n 'mapped_user' src/core/types/identity.h

# The retention layer W1/W3 extend
sed -n '1,60p' src/observability/metrics/io_monitor.h
```

---

## Appendix B — risk register

| # | Risk | WS | Likelihood | Impact | Mitigation |
|---|------|----|-----------:|--------|------------|
| R-1 | A rename breaks an operator's existing `log_format` or dashboard | all | Medium without care | High (silent monitoring loss) | Rule 5: every old name is a working deprecated alias for a release; byte-identity tests old==new; docs deprecation table |
| R-2 | `$brix_path` leaks a raw client URL or userinfo | W4 | Low (source is the *resolved* confined path) | **Severe** | Read only `resolved.resolved`; security-neg traversal + userinfo tests; R10-style review note |
| R-3 | Stream-side per-session monitor allocated or written off the event loop | W3 | Medium (the classic thread bug; phase-106 tail documents the contract) | High (pool corruption) | Allocate at session create on the event loop; observer only scalar-writes; reuse `io_monitor.h` unchanged |
| R-4 | Cache disposition mis-reports BYPASS as MISS (or vice-versa) and corrupts hit-rate dashboards | W1 | Medium | Medium | `-` for no tier / no-I/O (NOT BYPASS); `MISS` only when a tier was consulted; BYPASS reserved for the `O_NOCACHE` skip (internal-only) |
| R-5 | R12 (shared vocabulary) is too clever and rejects legitimate handlers | W5 | Medium | Low (CI noise) | Scope to `VOCAB_FACTS` only; fixture-driven; report-only until W4 lands |
| R-6 | `brix_metric_err_class_name()` disagrees with the strings the JSON log hand-spells today, changing log output | W4 | High (that is the point) | Medium | The old `"status"` string is the deprecated one; new key `outcome`? **No** — keep key `status`, switch value source, and list the old→new value map in the deprecation table; one release of both is impossible for a value, so this is the ONE breaking value change and is called out in the release notes |
| R-7 | Prometheus cardinality: a new `cache_status` or `status` label on a high-volume family | W1/W4 | Low (both vocabularies are ≤ 10 values) | Medium | INVARIANT 8: labels are closed enums from the name functions, never free text; `$brix_path` is never a label |
| R-8 | Stream `$brix_op` = "last op" is misread as "the op" | W4 | Medium | Low | Name the count `$brix_ops` beside it; docs say "last dispatched"; per-op truth is the JSON log (non-goal 4) |

---

## Appendix C — sequencing

```
W1 (cache_status on data planes + cache vocabulary)     ← smallest, highest value, unblocks the flagship log_format
W2 (identity names on both planes, $brix_user)          ← pure registration + aliases
   └─ W3 (stream monitor: bytes/backend/checksum/tier)   ← needs the stream ctx builder to bind a monitor
        └─ W4 ($brix_op / $brix_path / $brix_status)      ← needs the monitor to retain op+path+class
W5 (R11–R13 guards) rides W1–W4: report from W1, gate after W4
W6 ($brix_duration) any time; trivially independent
```

Estimated size **M**: W1 and W2 are each an afternoon; W3 is the only piece
with a new allocation site (the stream session monitor) and inherits the
phase-106 tail's threading contract verbatim; W4 is three handlers over data
the JSON log already has plus one name function; W5 is fixture-driven guard
work in the established `check_directive_registry.py` shape.

---

## Appendix D — the target: one log_format, every plane, no nginx spelling

The acceptance criterion in the form the operator cares about. The SAME
`log_format` body is pasted into `http {}` and `stream {}`:

```nginx
log_format brix '$remote_addr op=$brix_op path=$brix_path status=$brix_status '
                'proto=$brix_protocol tier=$brix_tier cache=$brix_cache_status '
                'sub=$brix_sub vo=$brix_vo auth=$brix_auth_method user=$brix_user '
                'tls=$brix_tls served=$brix_bytes_served recv=$brix_bytes_received '
                'backend=$brix_backend_time total=$brix_duration ck=$brix_checksum';
```

`$remote_addr` is the only nginx variable in it, kept because nginx already
names it identically on both planes (rule 6). Every other field is a brix
word, carries the same value string as the JSON key of the same name and the
Prometheus label of the same name, and means the same thing whether the
request arrived over WebDAV, S3, or root://.

The deprecation table that ships with the phase (config-reference.md,
"Deprecated names"):

| Deprecated | Use instead | Removal |
|------------|-------------|---------|
| `$brix_session_dn` / `_vo` / `_auth` / `_tls` | `$brix_dn` / `$brix_vo` / `$brix_auth_method` / `$brix_tls` | phase 112 |
| `$brix_session_user` | `$brix_sub` (it published the subject) — see `$brix_user` for the mapped account | phase 112 |
| `$brix_session_bytes_out` / `_in` | `$brix_bytes_served` / `$brix_bytes_received` | phase 112 |
| `$brix_cvmfs_cache`, `$cvmfs_cache`, `$brix_oci_cache`, `$brix_rpm_cache` | `$brix_cache_status` | phase 112 |
| JSON `from_cache` | JSON `cache_status` | phase 112 |
| JSON `subject` | JSON `sub` | phase 112 |
| JSON `bytes` / `latency_us` | JSON `bytes_served` / `backend_time_us` | phase 112 |
| `brix_cache_hits_total` / `brix_cache_misses_total` | `brix_cache_requests_total{cache_status}` | phase 112 |

---

## Appendix I — implementation log (as-built, 2026-09-01)

| WS | Status | As built |
|----|--------|----------|
| W1 | **DONE** | The cache-disposition vocabulary moved to the shared home: `brix_cache_status_e` + `brix_metric_cache_status_name()` now live in `observability/metrics/unified.h`/`.c` (was an HTTP header), so the variable, JSON and metric render one word. `brix_vfs_observe_cache_result(ctx, hit)` (new, `vfs_open.c`) books the unified counter AND folds HIT/MISS into `ctx->io_monitor`; wired at every ctx-bearing cache-decision site (`vfs_open.c` ×2, `open_resolved_file_open.c`). BYPASS folded on the `NOCACHE` path. `brix_request_cache_status()` gained a monitor-first arm, so **WebDAV/S3 GET now report a real disposition** (a 404 logs `cache=MISS`, a served GET `HIT`/`MISS`) where before W1 they were always `-`. New Prometheus family `brix_cache_requests_total{proto,cache_status}` renders the two existing SHM counters through the name function (no new counter). JSON log emits `cache_status` beside the deprecated `from_cache`. |
| W2 | **DONE** | The stream plane (`stream_variables.c`) registers the identity set under the SAME names as HTTP — `$brix_dn/vo/fqan/sub/issuer/user/auth_method/tls` — reading `ctx->identity` with a `ctx->login.*` fallback (no phase-106 value lost). `$brix_auth_method` routes through `brix_metric_auth_method_name()` (R12). `$brix_user` is the new mapped-account fact on both planes (`brix_var_user` / `BRIX_SV_USER`). The seven `$brix_session_*` names stay as deprecated aliases; JSON adds `sub` beside `subject`. |
| W3 | **DONE** | A `brix_io_monitor_t` is embedded in the per-connection `brix_ctx_t` (root plane), allocated with the pcalloc'd ctx on the event loop; `brix_root_vfs_bind_deleg` was renamed `brix_root_vfs_bind_session` and, at all 14 root ctx-build sites, now points `vctx->io_monitor` at it (the one per-session hook). `$brix_bytes_served/_received/_backend_time/_checksum/_tier/_origin` register on stream. The root open (`open_resolved_file_finalize.c`) records the read/write op on the monitor, because the root read I/O runs the warm `brix_vfs_io_execute` fast path that bypasses the per-op observer — so `$brix_op` is `read`, not the incidental open-time `stat`. The root `kXR_Qcksum` reply folds its `alg:hex` into `$brix_checksum` (parity with the WebDAV `Digest` header on the HTTP plane). |
| W4 | **DONE** | `$brix_op` / `$brix_path` / `$brix_status` on both planes, from the monitor's weight-ranked primary op (`io_monitor.h`): op via `brix_metric_op_name`, path the confined resolved path (`brix_vfs_adopt_fd` records it; bounded copy, never a stack pointer), status the outcome class via `brix_metric_err_name`. `EROFS` was folded into `brix_metric_err_from_errno`'s FORBIDDEN bucket, and the mutation gate (`vfs_policy.c`) stamps FORBIDDEN on the monitor before any op runs, so a read-only refusal is `status=forbidden` on WebDAV and S3. **Post-close verification (2026-09-03) found the root:// arm short of that promise:** a write-open on a read-only root:// export is refused earlier, at the protocol gate `brix_open_mode_guard` (`open_request.c`), which returns `kXR_fsReadOnly` BEFORE the VFS mutation gate ever runs — so the monitor was never stamped and the session logged `status=-`, not `forbidden`, while every other plane said `forbidden`. The gate now mirrors `vfs_policy.c`'s one-liner (`brix_io_monitor_record_err(&ctx->io_monitor, BRIX_ERR_FORBIDDEN)`) at that refusal, so `status=forbidden` is now honest on WebDAV, S3 **and** root:// alike. Pinned by `test_readonly_write_refusal_logs_status_forbidden_on_root` (the root:// arm, alongside the WebDAV `test_readonly_refusal_logs_status_forbidden`). `$brix_status`'s HTTP fallback uses `brix_metric_err_from_http_status` for a refusal that never reached the VFS. `$brix_ops` is the op count. |
| W5 | **DONE** | `check_directive_registry.py` gains **R14** (the self-deleting alias pin: a deprecated `$brix_session_*` alias carries a `removal: phase-112` annotation in the allowlist, and once phase-112's doc is marked IMPLEMENTED while the alias is still registered, R14 fails the build — dormant until then). Plus R11 (parity: a PARITY_FACT on one plane and not the other fails — a fact on *neither* plane is not a violation), R12 (the variable-handler files must render shared facts through `brix_metric_*_name()`, no inline `"HIT"` literal), R13 (the JSON keys and metric labels carry the canonical variable-name spelling). All three gate under `--fail` and report zero on the real tree. Rules + constants split into `directive_registry_w5.py` to hold the checker under the 600-line cap. Fixtures: `test_check_directive_registry.py` gains 6 cells (R11 single-plane fixture, the real-tree gates-clean pin, R12/R13 detector unit-tests). |
| W6 | **DONE** | `$brix_duration` on both planes: HTTP renders it byte-identical to `$request_time` (`ngx_http_variable_request_time`'s formula), stream byte-identical to `$session_time`. The sole transport twin (rule 6). |

**Deviations from the plan, recorded:**
- `$brix_path` is the confined **resolved** path (may be absolute), matching the
  JSON log's `path` exactly — the plan said "export-relative", but the observer
  and JSON log carry the resolved path, and rule 3 (same string on every
  surface) wins. Confinement (not relativeness) is the security property, and it
  holds (a traversal probe logs the in-export refused path or `-`).
- **HIT vs MISS on the data plane:** W1's goal is "the data planes report a
  disposition instead of always `-`". A cold GET reliably logs `MISS`; whether a
  warm GET logs `HIT` depends on cache-fill timing orthogonal to this phase, so
  the test asserts a real disposition (`HIT`|`MISS`), not specifically `HIT`.
- **JSON `status` value source** (R-6 in the risk register): the key stays
  `status`; its value now comes from `brix_metric_err_name` uniformly. This is
  the one value change with no old/new coexistence (a single string field can't
  carry both), called out in the deprecation table.

- **Stream `$brix_fqan`** returns the OPERATIVE (first) VO field, not the whole
  list — the first CSV field copied to the connection pool (`brix_stream_first_vo`),
  matching the HTTP handler's first-`vo_list`-entry rule (rule 1). An earlier
  cut wrongly returned the full list, same as `$brix_vo`.
- **A 404 GET on a cache-enabled export logs `cache=MISS`, not `-`.** The plan's
  W1 error example said a 404 logs `-`, but the cache WAS consulted and missed
  (brix_cache_open returns DECLINED before the origin 404), and the existing
  brix_cache_misses_total counter already records that as a miss. `$brix_cache_status`
  mirrors the metric (rule 3: same word every surface), so it is `MISS` — making
  it `-` would desync the variable from the counter. The test accepts `MISS`.

- **`$brix_status` for an access-phase refusal:** a WebDAV/S3 write to a
  read-only export is refused at the ACCESS phase (403) before any VFS ctx is
  built, so the monitor is never bound. `brix_var_status` therefore falls back
  to `brix_metric_err_from_http_status(r->headers_out.status)` whenever brix
  owns the location (`brix_request_shared_conf(r) != NULL`) — so the refusal
  logs `status=forbidden`, never `-`, for a request brix demonstrably handled.
  The VFS-gate stamp (`brix_io_monitor_record_err`) remains the path for
  `root://`, which has no HTTP status.

**Coverage of the per-plane acceptance:** WebDAV and root:// are runtime-tested
(the variable, cache-disposition, op/path/status, forbidden-refusal, and — on
root:// — a real `xrdfs query checksum` proving `$brix_checksum`). S3 shares its
ENTIRE monitor mechanism with the WebDAV data path (the same
`brix_vfs_observe_cache_result` / `adopt_fd` op-record / serve-metrics
byte-fold); a dedicated S3 fleet node with a brix log_format would cost a ladder
widening for a path with no S3-specific fold logic, so S3's wiring is pinned
structurally instead by `test_uniform_monitoring_guard.py` (every HTTP data-plane
ctx builder binds the monitor; the observer folds op/latency/cache; the
vocabulary lives in the shared header). The new `brix_cache_requests_total`
family is in the exposition MONOTONIC set, so its increment-under-traffic is
verified across the cachemx suite. The brix JSON access log is PER-OP while the
cache disposition is PER-REQUEST, so rule 3 holds at the vocabulary level (same
HIT/MISS words via `brix_metric_cache_status_name`, pinned by R13), not as
value-equality across the two granularities.

**Verification:** build clean (`-Werror`, 0 warnings); `run_fanalyzer.py` 0
findings; `check_directive_registry --fail`, `check_python_quality`,
`check_py_file_size`, `check_duplication`, `check_config_coverage`,
`check_vfs_seam`, `check_vfs_mutation_gate` all OK; 616 passed / 3 env-skipped
across the variable, registry, metric-catalog and data-plane regression suites
(`test_brix_http_variables`, `test_brix_stream_variables`,
`test_check_directive_registry`, the `cachemx` catalog/exposition/plane suites,
`test_walk_offload`, `test_http_cache_hit`, `test_s3`, `test_xrootdfs_http`).

---

# Part II — the metric surface and the self-sufficient access log

**Status:** COMPLETE 2026-09-02. W7 (JSON `remote`), W10 (cache metric
unification + NEGHIT), W11 (one latency unit `_seconds`), W12 (metric
governance) implemented and tested; W9 (byte vocabulary) done — its uniform
`brix_io_bytes_*{proto}` families already existed and its per-plane duplicates
were already `# DEPRECATED` in-source, now pinned in W12; W8 (request family)
resolved as a re-scope — the uniform `brix_io_ops_total{proto,op,status}`
already provides "operations by protocol", and a `brix_requests_total{proto}`
family would collide with the existing stream family (invalid exposition). Each
workstream's status is on its own header below.

W1–W6 made the **nginx variable** surface uniform: one `$brix_*` name per fact
on both planes, one value vocabulary across the variable / JSON / metric
surfaces for the facts they touched (cache disposition, auth method,
operation, outcome). A follow-up deep-dive of the OTHER two surfaces — the
JSON access log and the Prometheus families that grew organically per protocol
— found that an operator building a dashboard or a log pipeline still switches
vocabularies constantly. These are the residual non-uniformities, each a
concrete "why is the same fact spelled five ways" the operator hits.

## The residual dialects (audited 2026-09-02 on `main`)

| Fact | Uniform form (exists) | The per-plane spellings that fragment it |
|------|----------------------|------------------------------------------|
| client address | — (nginx `$remote_addr`) | JSON access log hardcodes **`"remote":"-"`** (`access_log.c:134`) — the client IP is never recorded, so the brix log must be JOINED to nginx's to answer "who". |
| request count | — | `brix_requests_total{port,auth,op,status}` (stream, `stream.c:118`), `brix_webdav_requests_total` (`webdav.c:106`), `brix_s3_requests_total`, `brix_cvmfs_requests_total`, `brix_oci_requests_total`, `brix_rpm_requests_total`, `brix_ssi_requests_total` — seven families, three label schemes, for "a request happened". |
| bytes to/from client | `brix_bytes_tx_total` / `brix_bytes_rx_total{proto}` | `brix_bytes_root_tx_total` / `_rx_total` (stream duplicate), `brix_io_bytes_read` / `_written` (VFS-level), plus `$brix_bytes_served` the variable — the same egress counted three ways. |
| bytes to/from origin | — | `brix_cvmfs_bytes_served_total{source}`, `brix_cvmfs_origin_bytes_total`, `brix_cvmfs_repo_origin_bytes_total`, `brix_oci_fill_bytes_total` — origin traffic has no uniform family. |
| cache outcome | `brix_cache_requests_total{proto,cache_status}` (W1) | `brix_cvmfs_repo_cache_hits_total` / `_misses_total` / `brix_cvmfs_negative_hits_total` (the NEGHIT source!) / `brix_cvmfs_fills_total`, and the oci/rpm equivalents — the cvmfs/oci/rpm planes never fold into the W1 family, so a fleet-wide hit rate is un-computable from one query. |
| operation latency | `brix_io_latency_usec{proto,op}` (microseconds) | `brix_cvmfs_upstream_fill_duration_seconds` (seconds), `brix_frm_stage_latency_seconds` (seconds) — two UNITS, so a latency panel needs a unit branch per family. |

The pattern is the same one W1–W6 fixed for variables, now on the metric side:
the facts exist, but each plane invented its own family and (for latency) its
own unit. The fix is the same too — one name and one vocabulary per fact, the
per-plane spellings kept as deprecated series for one release (the R14
self-deleting pin generalises to metric names).

---

## W7 — the JSON access log is self-sufficient (fill `remote`)  — **DONE 2026-09-02**

**As built.** `brix_vfs_ctx_t` gained a borrowed `const char *peer`;
`brix_access_log_emit` escapes it into the `remote` field (NULL ⇒ `-`).
Populated on the EVENT LOOP: root:// via `brix_root_vfs_bind_session` (a borrow
of `ctx->login.peer_ip`, no alloc — so EVERY root VFS op that emits a
`brix_access_json` line carries the client IP); HTTP via `brix_http_monitor_bind`
(a one-time `r->pool` copy of `r->connection->addr_text`, which is not
NUL-terminated — the `guard_audit_http.c` pattern), covering the data-plane
write ops that emit JSON. **Scope limitation, recorded:** HTTP metadata ops that
run on an OFFLOAD thread (PROPFIND/SEARCH on a remote backend) still log
`remote:"-"` — setting `peer` there needs the cached-peer design (compute once
on the event loop, peek from the thread), deferred. **Discovery:** nginx's own
`error_log` already appends `, client: <ip>` to every `brix_access_json` line,
so the client IP was recoverable as trailing text; W7 makes it a proper,
parseable JSON field. Test: `test_brix_stream_variables.py::test_json_access_log_records_the_client_address`
(a metered `xrdfs ls` — the read fast-path emits no JSON line — whose
`brix_access_json` `remote` is the client address). Also fixed a latent
log-lag fragility the new test exposed in the W3 uniform-names cell (it now
waits for and selects its own `op=read` line).

### Current state

`brix_access_log_emit()` (`access_log.c:89`) writes `"remote":"-"` unconditionally
(`:134`): the client address is never recorded. The emitter takes a
`brix_vfs_ctx_t`, which carries `pool`/`log`/`identity`/`is_tls` but no peer
address — which is *why* the field is stubbed. The address IS available at the
call sites (`r->connection->addr_text` on HTTP; `ctx->peer_ip[64]` on the
stream ctx, `context.h`), just never threaded to the emitter.

### Change

1. Add `const char *peer` to `brix_vfs_ctx_t` (a borrowed NUL-terminated
   address string, NULL ⇒ `-`), populated by the ctx builders from
   `r->connection->addr_text` / `ctx->peer_ip` — the same one-line bind the
   monitor uses (W3's `brix_root_vfs_bind_session`, the HTTP `*_vfs_ctx`
   builders).
2. `brix_access_log_emit` emits `"remote":"%s"` from `ctx->peer` (escaped).
3. No new field name: `remote` already exists in the line; it stops being a
   stub. (No deprecation needed — a `-` becoming a real value breaks no parser.)

### Tests
- **success** — a WebDAV GET and a root:// transfer each write a JSON
  access-log line whose `remote` is the connecting client's IP, not `-`.
- **security-neg** — the value is the peer address only, never a forwarded
  `X-Forwarded-For` an attacker controls (unless a trusted-proxy config opts
  in, out of scope here); and it is length-bounded like the other free-text
  fields.

### Acceptance
- The brix JSON access log answers "who / what / whence" without a join to
  nginx's log — `remote` + `sub` + `op` + `path` on one line.

---

## W8 — one request-count family  — **RESOLVED (re-scoped) 2026-09-02**

**Finding on implementation.** The deep-dive's premise — "seven families
fragment 'a request happened'" — was over-stated. The families measure
DIFFERENT levels, not one fact seven ways: `brix_io_ops_total{proto,op,status}`
counts VFS OPERATIONS (already uniform across every plane); the per-plane
`brix_webdav_requests_total{method}` / `brix_s3_requests_total{method}` count
HTTP REQUESTS BY METHOD (a different dimension — one GET request is one HTTP
request but 1 stat + 1 open + N reads at the op level); `brix_requests_total{port,auth,op,status}`
is the STREAM per-SERVER counter. So the uniform "operations by protocol"
answer ALREADY exists: `sum(rate(brix_io_ops_total[5m])) by (proto)` covers
webdav/s3/cvmfs/oci/rpm/root today.

**Decision.** Do NOT add a `brix_requests_total{proto,op,status}` family: the
name `brix_requests_total` is already taken (stream, `{port,auth,op,status}`),
and a second label scheme on one family is an INVALID Prometheus exposition.
The per-plane `{method}` families are a legitimate finer dimension (like
cvmfs's `{repo}`) and stay. The uniform requirement is met by `io_ops_total`;
W12's lint guards against a future per-plane counter that duplicates it. This
workstream is therefore a documentation/scoping correction, not new code.

### Current state (original plan — superseded by the finding above)

Seven request families, three label schemes (above). No single query answers
"requests per second across the fleet, split by protocol".

### Change

1. Emit `brix_requests_total{proto,op,status}` for EVERY plane, from the
   shared recorder the JSON log/metric already share (`brix_metric_op_done`
   territory) — the labels are the ones already uniform (`brix_metric_proto_name`,
   `brix_metric_op_name`, `brix_metric_err_name`).
2. Keep the per-plane families (`brix_webdav_requests_total`, …) as deprecated
   series for one release; annotate each with `removal: phase-112` so the
   metric-name variant of R14 (W12) fails the build when the window closes.
3. Genuinely plane-specific counters that are NOT "a request" (frm stage jobs,
   mirror syncs) stay — this unifies the request COUNT, not every counter.

### Tests / Acceptance
- `sum(rate(brix_requests_total[5m])) by (proto)` covers webdav/s3/cvmfs/oci/
  rpm/root with one query; the old per-plane counters still increment for the
  window; a cachemx label-schema pin fixes the `{proto,op,status}` key set.

---

## W9 — one byte vocabulary  — **DONE 2026-09-02 (already in codebase + governance added)**

**Finding on implementation.** The uniform per-protocol byte families
`brix_io_bytes_read{proto}` / `brix_io_bytes_written{proto}` ALREADY EXIST, and
every per-plane/per-server byte duplicate already carries a
`# DEPRECATED: use brix_io_bytes_*{proto=...}` note in the exporter
(`webdav.c`, `s3.c`, `stream_family.c`) — the deep-dive missed those
HELP-comment deprecations. So the uniform byte vocabulary is in place. The
increment this workstream adds: the 8 already-deprecated families
(`brix_webdav_bytes_{tx,rx}_total`, `brix_s3_bytes_{tx,rx}_total`,
`brix_bytes_{tx,rx}_total`, `brix_bytes_root_{tx,rx}_total`) are registered in
W12's `DEPRECATED_METRICS` (`removal: phase-112`), so the M2 self-deleting pin
now removes them when phase-112 lands.

**Kept (complementary, NOT duplicates):** `brix_cvmfs_bytes_served_total`
(client egress BY CACHE DISPOSITION), `brix_storage_io_bytes_*` (per storage
DRIVER), `brix_vo_bytes_*` (per VO), `brix_tpc_bytes_total` (TPC bytes) — each
measures a different fact than the storage-I/O total, so they stay, exactly as
cvmfs's `{repo}` families stay under W10.

### Current state (original plan — the uniform family already existed)

Egress is `brix_bytes_tx_total`, `brix_bytes_root_tx_total`, and
`brix_io_bytes_read` depending on plane/layer; origin traffic is
`brix_cvmfs_bytes_served_total{source}` / `brix_oci_fill_bytes_total` with no
uniform family; and the variable is `$brix_bytes_served`. Same bytes, five
names.

### Change

1. Client-facing: one `brix_bytes_tx_total{proto}` / `brix_bytes_rx_total{proto}`
   pair, fed on every plane; fold the stream `brix_bytes_root_*` duplicates and
   deprecate them. (`brix_io_bytes_read/_written` stay — they are the VFS-layer
   view, a different granularity, but documented as such.)
2. Origin-facing: one `brix_origin_bytes_total{proto,direction}` family;
   deprecate `brix_cvmfs_bytes_served_total`, `brix_cvmfs_origin_bytes_total`,
   `brix_oci_fill_bytes_total`.
3. The variable `$brix_bytes_served` already matches `bytes_tx` semantics
   (rule 3) — document the metric ↔ variable correspondence.

### Tests / Acceptance
- Fleet egress is `sum(rate(brix_bytes_tx_total[5m]))`, one query; origin cost
  is `brix_origin_bytes_total`, one family; the deprecated spellings coexist
  for the window.

---

## W10 — one cache vocabulary across the metric surface (finish W1)  — **DONE 2026-09-02**

**As built.** The unified SHM gained `cache_neghits[BRIX_PROTO_COUNT]` (the zone
auto-sizes from `sizeof(ngx_brix_metrics_t)` — no version guard to bump);
`brix_metric_cache_neghit(proto)` records it; `brix_cache_requests_total` now
emits a `cache_status="NEGHIT"` series per protocol beside HIT/MISS. Wiring:
cvmfs already fed unified HIT/MISS (`handler_finalize.c:130,166`); its
negative-hit site (`gate.c`) now also calls `brix_metric_cache_neghit(CVMFS)`.
oci and rpm fed NEITHER — their `disp` (HIT/FILL/LOCAL) is now mapped to the
unified family at the data-serve bump sites (`oci_mirror.c`, `rpm_mirror.c`):
HIT/LOCAL → hit, FILL → miss, REFUSED/ERROR skipped. So
`sum(rate(brix_cache_requests_total{cache_status="HIT"}[5m])) by (proto)` now
covers webdav/s3/cvmfs/oci/rpm, and the NEGHIT rate — previously only in
cvmfs's private `negative_hits_total` — is one query. The per-repo cvmfs
families (the `{repo}` dimension) are unchanged (kept, finer granularity).
Test: `test_cachemx_exposition.py::test_cache_requests_carries_the_neghit_series`
(the live exposition carries the HIT/MISS/NEGHIT series). The 557-case cachemx
catalog/exposition/label-schema suite passes with the new SHM field and series.

### Current state

W1 unified the cache VARIABLE and added `brix_cache_requests_total{proto,cache_status}`,
but only WebDAV/S3 feed it (via `brix_vfs_observe_cache_result`). The cvmfs
plane keeps `brix_cvmfs_repo_cache_hits_total` / `_misses_total` /
`brix_cvmfs_negative_hits_total` (`handler_finalize.c:133,168`, `gate.c:241`),
and oci/rpm keep theirs — none fold into the W1 family, and NEGHIT (which the
vocabulary defines) is only in cvmfs's `negative_hits_total`, never in
`brix_cache_requests_total`.

### Change

1. Route the cvmfs/oci/rpm cache-outcome bumps through
   `brix_vfs_observe_cache_result` (or a sibling that also handles NEGHIT), so
   `brix_cache_requests_total{proto="cvmfs",cache_status="HIT"|"MISS"|"NEGHIT"}`
   covers every plane. Emit the `NEGHIT` series from cvmfs's negative-hit path.
2. Keep the per-repo cvmfs families (they carry the `repo` dimension the
   unified family deliberately does not — a legitimate finer granularity), but
   deprecate the *plane-global* `brix_cvmfs_cache_*` / `brix_oci_cache_*`
   duplicates.
3. This closes W1's rule-3 loop on the metric side: `$brix_cache_status=NEGHIT`,
   JSON `cache_status:"NEGHIT"`, and `brix_cache_requests_total{cache_status="NEGHIT"}`
   are then the same word everywhere, on every plane.

### Tests / Acceptance
- `sum(rate(brix_cache_requests_total{cache_status="HIT"}[5m])) by (proto)`
  reports a hit rate for cvmfs/oci/rpm as well as webdav/s3; the NEGHIT series
  appears; the per-repo families are unchanged.

---

## W11 — one latency unit and family  — **DONE 2026-09-02**

**As built.** `brix_io_latency_seconds` (histogram, seconds) is now emitted as
the canonical latency family, rendered from the SAME SHM histogram as the
deprecated `brix_io_latency_usec` (le = µs-bound / 1e6 via `%.6f`, sum =
sum_usec / 1e6). Both are emitted for the removal window (rule 5), so no
existing dashboard on `_usec` breaks. Result: EVERY latency histogram now
carries the `_seconds` suffix — `brix_io_latency_seconds` +
`brix_cvmfs_upstream_fill_duration_seconds` + `brix_frm_stage_latency_seconds`
— one Grafana unit setting covers them all. The `_usec` family is registered
for `removal: phase-112` (W12). The series emitter was parameterised by unit
(`unified_emit_io_latency_series(..., fam, seconds)`) so there is no duplicated
histogram logic. The one exception the doc reserves — the `$brix_backend_time`
VARIABLE staying `seconds.mmm` beside `$request_time` (rule 4) — is unchanged.
Test: `test_cachemx_exposition.py::test_latency_family_is_in_seconds`; cachemx
catalog/exposition/label-schema pins gained the `_seconds` family (561 pass).

### Current state

`brix_io_latency_usec{proto,op}` (microseconds, histogram) is the unified I/O
latency; but `brix_cvmfs_upstream_fill_duration_seconds` and
`brix_frm_stage_latency_seconds` are SECONDS. A latency dashboard needs a
per-family unit branch, and `$brix_backend_time` (the variable) is a third unit
(seconds.mmm) — that one is rule-4-legitimate (it sits beside `$request_time`),
but the two metric histograms disagreeing on unit is not.

### Change

1. Adopt one metric latency unit — **seconds** (Prometheus convention;
   `_seconds` suffix, `le` buckets in seconds) — and rename
   `brix_io_latency_usec` → `brix_io_latency_seconds` with a deprecated
   `_usec` alias for the window. (Or keep µs and convert the two `_seconds`
   families; the Prometheus norm argues for seconds.)
2. Document the ONE exception (rule 4): the `$brix_backend_time` VARIABLE stays
   `seconds.mmm` to sit beside `$request_time`; every METRIC latency is
   `_seconds`.
3. A metric-naming lint (W12) forbids a new `*_usec`/`*_ms` histogram.

### Tests / Acceptance
- Every latency histogram carries the `_seconds` suffix and a seconds-scaled
  `le`; one Grafana unit setting covers them all.

---

## W12 — governance for the metric surface (generalise R14 + a naming lint)  — **DONE 2026-09-02**

**As built.** `tools/ci/check_metric_naming.py` (new, with
`tests/test_check_metric_naming.py`): **M1** — a latency HISTOGRAM must be named
`_seconds` (the W11 unit); a `_usec`/`_ms` latency histogram is a finding unless
registered deprecated (a gauge threshold like `brix_io_slowop_threshold_usec`
is a config value, not a measurement, so it is exempt). **M2** — the R14
self-deleting pin generalised to metric NAMES: a family in `DEPRECATED_METRICS`
(name → removal phase) that is still emitted once its phase is marked
IMPLEMENTED fails the build. `brix_io_latency_usec` is registered with
`removal: phase-112`; W8/W9's future family deprecations register here too.
Both rules pass on the real tree and are gate-ready (`--fail`); the guard reads
the exporter's own `# HELP`/`# TYPE` declarations, so it needs no running
instance.

### Current state

R7–R14 govern the VARIABLE surface; nothing stops a new per-plane
`brix_<plane>_requests_total` or a `*_usec` histogram from re-fragmenting the
metric surface.

### Change

1. Generalise the R14 self-deleting pin to metric NAMES: a deprecated family
   annotated `removal: phase-N` must be gone once phase-N is IMPLEMENTED
   (the W8–W11 deprecations register here).
2. A metric-naming lint (`tools/ci/`): a per-protocol counter whose concept has
   a unified family (request/bytes/cache/latency) is a finding; a latency
   histogram not suffixed `_seconds` is a finding.

### Acceptance
- Re-introducing a per-plane request/byte/cache family, or a non-`_seconds`
  latency histogram, fails CI.

---

## Part II — non-goals

1. **The per-repo / per-server dimensions stay.** cvmfs's `{repo}` and the
   cluster `{server}` families carry granularity the unified families
   deliberately omit (INVARIANT #8 bounds the unified label sets). Unify the
   PLANE-GLOBAL duplicates, not the finer-grained families.
2. **No metric is deleted in this phase.** Every rename ships the old series
   for one release; removal is a later phase, enforced by W12.
3. **`brix_io_bytes_read/_written` (VFS layer) is not merged into
   `brix_bytes_tx/rx` (wire layer)** — they measure different planes of the
   stack; they are documented as such, not collapsed.
4. **The variable surface (W1–W6) is unchanged.** Part II is metric-and-log
   only; the `$brix_*` names an operator learned do not move.

---

## Part II — sequencing

```
W7  (JSON remote) ................. independent, smallest, highest daily value
W8  (one request family) .......... independent
W9  (one byte vocabulary) ......... independent
W10 (cache metric unification) .... completes W1; depends on nothing new
W11 (one latency unit) ............ independent
W12 (metric governance) ........... rides W8–W11 (report first, gate after)
```

Estimated size **L**: each of W8–W11 touches every plane's metric emitter plus
its cachemx label-schema pins; W7 is an afternoon (one ctx field + one emit
line); W12 is guard work in the established `check_directive_registry` shape.
Recommended order: W7 (immediate operator win), then W10 (finishes W1), then
W8/W9/W11 in any order, W12 last to lock them.

---

## Coverage audit — every discovery / change maps to a describing test (2026-09-03)

A test-by-test reconciliation: each workstream's stated obligation is named
against a test whose docstring DESCRIBES it, so the coverage is discoverable
from the test list alone. SEVEN describing tests were added on 2026-09-03 to
close bullets the implementation satisfied but no test NAMED (a first wave of
four on the HTTP/variable surface, then a second wave of three on the stream
plane's own success/error/security-neg triplet for W3/W6); all pass green.

| WS / obligation | Describing test |
|-----------------|-----------------|
| W1 success — cache_status HIT/MISS on WebDAV data plane | `test_brix_http_variables::test_cache_status_reports_a_disposition_on_the_webdav_data_plane` |
| W1 success — metric carries the word | `test_cachemx_exposition::test_cache_requests_carries_the_neghit_series` |
| **W1 error — no-tier export logs `cache=-` (NONE), not MISS/BYPASS** (R-4) | **NEW `test_no_cache_tier_export_logs_cache_none_not_miss`** |
| W1 error — 404 on a cache-enabled export logs MISS | `test_variables_resolve_without_a_brix_handler` |
| **W1 security-neg — monitor is per-request, no cross-request bleed on keepalive** (R-3) | **NEW `test_monitor_is_per_request_not_per_connection`** |
| W2 success — same names both planes | `test_log_format_over_brix_variables_writes_every_field` · `test_uniform_names_resolve_on_the_stream_plane` |
| W2 error — abort-before-login logs `-` | `test_connection_without_login_still_logs_a_wellformed_line` |
| W2 security-neg — `$brix_user` unmapped `-` | `test_op_path_status_describe_the_brix_operation` (`user==-`) |
| **W2 de-conflation — `$brix_user`=mapped_user, `$brix_sub`=subject; distinct fields both planes (the old `$brix_session_user` conflation cannot silently return)** | **NEW `test_uniform_monitoring_guard::test_user_is_the_mapped_account_and_sub_is_the_subject_on_both_planes`** |
| W3 success — checksum equals wire digest on stream | `test_checksum_resolves_on_the_stream_plane` |
| W3 success — bytes/backend/tier on stream | `test_uniform_names_resolve_on_the_stream_plane` |
| **W3 error — a metadata op serves a MEASURED `0`, not `-`, and st is per-op** | **NEW `test_metadata_op_serves_zero_bytes_with_its_own_outcome`** |
| **W3 security-neg — per-session monitor, no cross-session byte bleed** (R-3) | **NEW `test_stream_monitor_is_per_session_no_byte_bleed`** |
| W4 success — op is the brix word, not the HTTP verb | `test_op_path_status_describe_the_brix_operation` |
| W4 error — read-only PUT logs `status=forbidden` (WebDAV arm) | `test_readonly_refusal_logs_status_forbidden` |
| **W4 error — read-only write logs `status=forbidden` on root:// too** (the protocol-gate arm the mutation gate misses — see Appendix I) | **NEW `test_readonly_write_refusal_logs_status_forbidden_on_root`** |
| W4 error — outcome class ≠ HTTP code | `test_status_is_the_outcome_class_not_the_http_code` |
| **W4 security-neg — traversal never leaks outside the export into `$brix_path`** (R-2, Severe) | **NEW `test_brix_path_never_leaks_outside_the_export_on_a_traversal`** |
| W4 security-neg — `$brix_origin` strips userinfo | `test_brix_origin_strips_userinfo_from_a_remote_backend` |
| W5 — R11/R12/R13/R14/R15 detect + gate + real-tree | `test_check_directive_registry` (R11–R15 cells, detectors + real-tree pins) |
| **W6 — `$brix_duration` == `$request_time` byte-for-byte** (not just shape) | **NEW `test_brix_duration_is_byte_identical_to_request_time`** |
| **W6 error — an aborted session still logs a duration, never `-`** | **NEW `test_aborted_session_still_logs_a_duration`** |
| W7 — JSON `remote` records the client IP | `test_brix_stream_variables::test_json_access_log_records_the_client_address` |
| W7 security-neg — `remote` is the kernel peer, not a client-supplied header | see note ‡ below |
| W7/W1/W3 compat — canonical JSON keys, no compat keys | `test_phase_112_access_json_carries_each_fact_exactly_once` |
| W10 — NEGHIT series on the unified cache family | `test_cachemx_exposition::test_cache_requests_carries_the_neghit_series` |
| W11 — every latency histogram is `_seconds` | `test_cachemx_exposition::test_latency_family_is_in_seconds` · `test_check_metric_naming` M1 |
| W12 — metric governance (M1 unit lint, M2 self-deleting pin) | `test_check_metric_naming` |
| **Rule 2 — the `status` word is one string on every surface (variable/JSON/Prometheus), all via the shared `brix_metric_err_name`** | **NEW `test_uniform_monitoring_guard::test_status_word_renders_through_the_shared_err_name_on_every_surface`** |
| **W4 error correction — `status` (outcome class) ≠ `mutation_denied{reason}` (denial cause `read_only`); distinct facts, not to be unified** | **NEW `test_uniform_monitoring_guard::test_mutation_denied_reason_is_the_denial_cause_not_the_outcome_class`** |
| Per-plane wiring pinned structurally (S3 has no fleet node) | `test_uniform_monitoring_guard` (every data-plane ctx binds the monitor; observer folds op/latency/cache; vocabulary in the shared header) |

**The four gaps closed (2026-09-03), all pinning already-correct behaviour:**
1. **W4 R-2 (Severe)** — `$brix_path` is loggable; a `..`-traversal must never
   leak a string from outside the export. `test_brix_path...traversal` drives
   `GET /../../../../etc/passwd`, asserts the refusal, and asserts the logged
   `path=` field contains neither `/etc/` nor `passwd` nor `..` — the runtime
   half of R-2 (the userinfo half was already `test_brix_origin_strips_userinfo`).
2. **W1 R-3** — the monitor is per-REQUEST. `test_monitor_is_per_request...`
   issues a served GET and a 404 on ONE keepalive connection and asserts each
   line carries its own op/path/status, so no connection-scoped bleed can hide.
3. **W6** — the doc's W6 success is byte-IDENTITY with `$request_time`, but the
   existing cells asserted only the `^\d+\.\d{3}$` shape.
   `test_brix_duration_is_byte_identical...` logs both on one line and asserts
   equality.
4. **W1 R-4 vocabulary** — the `-` (no tier) vs `MISS` (tier consulted) vs
   `BYPASS` (tier skipped) distinction had no describing test for the NONE arm.
   `test_no_cache_tier_export_logs_cache_none...` serves a GET on an export with
   no `brix_cache_root` and asserts `cache=-`.

**The second wave (2026-09-03) — the stream plane's W3/W6 triplet, closed after
a re-audit found the per-workstream Tests sections list stream success/error/
security-neg cells the table above had not mapped:**
5. **W3 security-neg (R-3)** — the per-session `brix_io_monitor_t` must not
   bleed one session's bytes into another. `test_stream_monitor_is_per_session_no_byte_bleed`
   runs two concurrent transfers of DELIBERATELY different sizes (76 B and
   ~108 KiB) on the single-worker node and asserts each session's uniform read
   line reports its OWN `$brix_bytes_served` — exactly two small and two large,
   never the sum — so a shared-ctx accumulation bug cannot hide.
6. **W3 error** — the doc's W3 error bullet drafted `served=-` for "nothing
   served", but the implementation reserves `-` for a fact that never occurred
   and books a real op that moved no client bytes as a MEASURED `0`
   (INVARIANT: `-` = no event, `0` = measured zero). `test_metadata_op_serves_zero_bytes_with_its_own_outcome`
   pins the as-built: an `xrdfs stat` (hit and miss) logs `op=stat served=0`
   with `st` per-op (`ok` vs `not_found`), never a read's byte count.
   **As-built deviation recorded:** the W3 error bullet's `served=-` is superseded
   by `served=0`; the `-`/`0` semantics is the real, tested contract.
7. **W6 error** — a duration is defined for every session that opened a
   connection, including one that hangs up before login.
   `test_aborted_session_still_logs_a_duration` drives the pre-login handshake-
   then-hangup and asserts the uniform line carries a real `dur` (the
   `$session_time` shape, a measured `0.000`), never `-`, while `op` IS `-` —
   proving the twin is populated independently, not inherited from a served line.

‡ **W7 security-neg.** `remote` is sourced from the kernel-provided peer
(`ctx->login.peer_ip` on stream via `bind_session`; `r->connection->addr_text`
on HTTP), never from a client-supplied header — the stream plane has no
forwarded-header path at all, so an X-Forwarded-For spoof is structurally
impossible there, and `test_json_access_log_records_the_client_address` pins
that the recorded value is the actual (length-bounded) loopback peer. The HTTP
XFF-spoof arm is a code-review property (the emitter reads `addr_text`, not a
header) and is not runtime-tested, consistent with the as-built W7 scope note
that HTTP GET peer-capture is deferred.

**Full-surface verification (2026-09-03):** the entire phase-110 test surface is
green in this session — **169 passed** across `test_brix_http_variables` (+`_part2`),
`test_brix_stream_variables` (18, incl. the three new W3/W6 cells),
`test_uniform_monitoring_guard`, `test_check_metric_naming`,
`test_check_directive_registry`, and the full `test_cachemx_exposition` (which
owns the W10/W11 doc-named tests). `check_py_file_size` and `check_python_quality`
both OK. The one environmental caveat: `test_cachemx_exposition` needs the shared
session artifacts under `/tmp/xrd-test` (PKI + tokens/JWKS); when a foreign WSL2
fleet owns that tree they are not regenerated, so the `lc-cachemx` TLS node fails
`nginx -t` and the suite errors at setup. Reconstructing them is FILE-ONLY and
touches no ports/processes (`python3 -c "import brix_suite.prep_steps as p; p.prepare()"`),
so it is safe alongside a foreign fleet — done here, after which the suite runs
green. The `lc-*` LifecycleHarness nodes (variable/stream/guard suites) allocate
ephemeral ports and run green regardless.
