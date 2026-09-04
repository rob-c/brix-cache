# Phase 109 — take the event-loop stall off the metadata path (don't rewrite the transport)

**Status:** IMPLEMENTED / CLOSED (reconciled 2026-09-03) for PROPFIND and
SEARCH. The as-built record is in the implementation log at the bottom. LOCK
was deliberately excluded because its walk mutates expired lock-null resources
and lock-table state. Phase 113 closed without implementation because no
measurable LOCK stall triggered the higher-risk mutation/revalidation protocol;
the bounded inline path is the supported behavior.

Source: the phase-106 W5 transport audit
(`docs/refactor/phase-106-nginx-native-integration-surface.md`, "Deliverable
2/3"), plus a code investigation on `main` @ `37364b251` that **changed the
recommendation**. phase-106 W5 pointed here with "option (b),
`curl_multi_socket_action` on the event loop." Investigating the actual call
graph for this plan shows that is the wrong tool — see **The correction** below.
Every file:line in this document was verified against the working tree at that
commit.

**Goal.** Eliminate the one real availability defect phase-106 W5 found: a
WebDAV metadata request (`PROPFIND` / `SEARCH` / `LOCK`) against a **remote**
storage backend, or under **EXCHANGE**-mode delegated credentials, performs
blocking libcurl on the **nginx event loop**, stalling every connection on that
worker for up to the bounded timeout. Do it with the smallest correct change,
not the largest.

---

## The defect, precisely (from the phase-106 W5 audit)

`brix_token_exchange()` (`src/auth/token/exchange.c:324`, a blocking
`curl_easy_perform`, bounded 10s connect / 30s total) is reached on the event
loop via:

```
webdav PROPFIND / SEARCH / LOCK handler   (NOT thread-offloaded)
  → brix_vfs_opendir_quiet / brix_vfs_opendir
      (webdav/propfind_walk.c, search.c:301, lock_check.c:191)
  → vfs_cred.c:127  vfs_cred_live_bag  (EXCHANGE mode)
  → brix_vfs_deleg_exchange  (vfs_deleg.c:199,214)
  → brix_token_exchange      → curl_easy_perform   [EVENT LOOP]
```

And, independently of the exchange, the **remote HTTP backend itself** blocks:
the same `brix_vfs_opendir` on a remote backend runs a WebDAV `PROPFIND` against
the origin through the shared blocking curl transport
(`sd_http.c` → `brix_s3_origin_curl_transport` → `s3_transport.c:138`
`curl_easy_perform`). So even with no token exchange, a metadata op against a
remote backend blocks the event loop on the backend call.

**Scope of the stall.** Only the three metadata methods, and only when the
backend is remote or EXCHANGE mode is on. Everything else is already correct:

- `GET` / `PUT` / `COPY` / `MOVE` are **already thread-offloaded**
  (`ngx_thread_task_post`, e.g. `put_body.c:314`, `copy_collection.c:273`,
  `move.c:264`), so their blocking backend I/O runs on a thread — where blocking
  I/O belongs.
- Against a **local POSIX** backend, `brix_vfs_opendir` is a fast syscall; there
  is no stall and nothing to fix.
- The token exchange is **cached per-worker** (`exchange_cache.c`, keyed on
  subject-token + audience), so only a cold miss pays, and it is **opt-in**
  (EXCHANGE mode with a configured endpoint).

Interim posture, already enforced by phase-106: every blocking curl call is
time-bounded (`tests/test_blocking_curl_bounded.py`), so the stall is bounded,
not indefinite. This phase removes it.

---

## The correction — why NOT a transport rewrite

phase-106 W5's written recommendation was **option (b),
`curl_multi_socket_action` on the event loop**. The investigation for this plan
found three facts that reject it, and reject the `ngx_http_upstream` option too:

1. **`curl_multi_socket_action` has ZERO in-tree precedent.**
   `grep -rln "curl_multi_socket_action|CURLMOPT_SOCKETFUNCTION" src` is empty.
   The only event-loop-integrated outbound HTTP in the tree is the mirror, and
   it uses `ngx_http_upstream` (`src/net/mirror/http_mirror.c:82,117`), not
   curl_multi. Introducing a hand-wired `curl_multi` ↔ `ngx_add_event` pump is a
   brand-new, easy-to-get-wrong async pattern on the auth+data path.

2. **The transport vtable is deliberately synchronous and ngx-free, and is
   called synchronously from many sites.** `brix_s3_transport_t`
   (`sd_s3_transport.h:14`) is "one synchronous request op." Its `request` slot
   is called synchronously from `sd_s3.c:80,173,234`, `sd_s3_archive.c:139` and
   `sd_http.c`. Making it async would force a continuation-passing rewrite of
   **every** caller — the S3 driver, the HTTP driver, Pelican, the archive
   path — most of which already run on threads and have no event-loop problem.

3. **The blocking transport is already thread-safe and thread-designed.**
   `s3o_request_impl` acquires "this thread's persistent, warm handle"
   (`s3_transport.c:118`). It is built to run on the thread pool. It does not
   need to become non-blocking; the few callers that run it on the **event
   loop** need to move to a thread — which is what the other methods already do.

`ngx_http_upstream` (option c) is rejected for the same cost reason phase-106
already gave: it would mean re-expressing S3 SigV4, Pelican and GSI-over-https
as upstream modules — a multi-phase effort far exceeding this bug, justified
only if the `upstream {}` feature set is wanted for its own sake (it is not the
subject here).

**Corrected recommendation: extend the existing thread-offload to the three
metadata methods.** Smallest change, uses the pattern PUT already uses, touches
no transport code, no curl integration, no auth *verification* logic, and no
synchronous caller outside the three handlers. phase-106's W5 forward pointer
should be read as superseded by this document.

> **Ledger note.** phase-106 W5 recommended option (b); this plan supersedes
> that after tracing the call graph. If phase-106's doc is revised, update its
> W5 pointer and R-7 row to reference "phase 109 = metadata thread-offload,"
> not "curl_multi_socket_action."

---

## Options table

| Option | Change | Risk | Verdict |
|--------|--------|------|---------|
| **A — status quo (blocking, bounded)** | none | low | The current enforced posture; leaves a bounded cold-miss stall on an opt-in path. The baseline this phase improves on. |
| **B — `curl_multi_socket_action` on the event loop** | rewrite the transport pump; wire curl ↔ `ngx_add_event`; convert every synchronous caller to a continuation | **high** — zero precedent, breaks the synchronous vtable, touches callers that have no problem | **Rejected.** Big, novel async surgery to fix three handlers. |
| **C — `ngx_http_upstream`** | re-express S3 SigV4 / Pelican / GSI as upstream modules | **very high** | **Rejected** for this concern (revisit only for `upstream {}` features themselves). |
| **D — thread-offload the metadata methods** | move `PROPFIND`/`SEARCH`/`LOCK`'s backend I/O onto the existing thread pool, conditional on remote-backend / EXCHANGE mode | **medium-low** — reuses `put_body.c`'s task+done pattern; the risk is identity/impersonation carriage, a solved problem | **Recommended.** |

---

## Standing rules (bind every workstream)

Identical to phases 101/105/106: no git write commands without explicit OP
approval in-conversation; **3 tests per change-class (success + error +
security-neg)**; no `goto`; HELPERS over reimplementation; CCN ≤15 / cognitive
≤10 / npath ≤15 / 600-line ratchets live; new `src/` TUs → repo-root `./config`
(`check_config_coverage.py`); every user-visible name → `docs/03-configuration/`
in the same commit.

**Two hard traps, load-bearing on this phase:**

1. **The impersonation bracket must cross the thread boundary.** A metadata op
   authorises and reads AS THE MAPPED USER. `put_body.c` shows the pattern
   (`auth/impersonate/lifecycle.h`; the done-handler at `:204` re-establishes
   the mapped identity because "this event-loop completion lost the per-request
   [identity]"). A thread task carries the identity BY VALUE and re-enters the
   impersonation bracket on the thread; the event-loop done-handler runs the
   response emission. Getting this wrong is a **security regression** (a walk
   executed as the worker, not the caller — INVARIANT-class), so it is the
   subject of W1's security-negative test.

2. **The offload must be CONDITIONAL, not blanket.** Offloading a local-POSIX
   `opendir` adds a thread hop for no benefit and would regress latency on the
   common case. Gate on `brix_storage_backend_is_remote(&conf->common)` OR an
   active EXCHANGE-mode live-cred bag. A local anonymous PROPFIND must stay
   inline and behave byte-identically.

---

## W1 — Offload PROPFIND

### Current state

`webdav_handle_propfind` (`dispatch.c:379`) runs inline. Its recursive walk
(`propfind_walk.c`) calls `brix_vfs_opendir` per level, bounded by a shared
`max_entries` counter (`propfind_walk.c:61`) — so the walk is already
bounded-work, which makes it a clean unit to move onto a thread. The XML
response is built from the walk result (pure computation).

### Change

Route PROPFIND through the `put_body.c` task pattern when the offload gate
(above) is on:

1. Resolve the pool: `brix_shared_thread_pool(&conf->common)`; if NULL (no pool
   configured), stay inline — the existing fallback.
2. Snapshot the request-props, target path, Depth, entry cap and the **carried
   identity** into a heap task ctx (like `webdav_put_body_ctx_t`).
3. Thread body: enter the impersonation bracket for the carried identity, run
   `propfind_walk` (its VFS calls, including any remote-backend PROPFIND and any
   EXCHANGE token mint, now run on the thread), accumulate the response body,
   leave the bracket.
4. Done-handler (event loop): emit the accumulated response, or the error the
   walk recorded; finalize.

No change to `propfind_walk` itself, to the VFS, to the transport, or to the
conditional evaluator.

### Tests

- **success** — a PROPFIND Depth:1 and Depth:infinity against a REMOTE backend
  returns the same multistatus body it returns today, and a second unrelated
  request on the same worker is served *while the PROPFIND's backend call is in
  flight* (a slow-origin shim) — proving the event loop is not stalled.
- **error** — a PROPFIND against an unreachable remote origin fails with the
  same status as today (no hang, bounded), and the failure does not wedge the
  worker.
- **security-neg** — the walk runs AS THE MAPPED USER on the thread: a PROPFIND
  by an identity mapped to a restricted local user must NOT enumerate entries
  that user cannot read (assert against a directory with mixed perms), proving
  the impersonation bracket crossed the thread boundary. This is the load-
  bearing test.

### Acceptance

- PROPFIND against a remote backend no longer blocks the event loop (the
  concurrent-request test passes).
- A local anonymous PROPFIND is byte-identical to today and stays inline (gate
  respected).
- The walk executes with the caller's mapped identity, not the worker's.

---

## W2 — Offload SEARCH and LOCK

### Current state

`SEARCH` (`search.c:301`) and `LOCK` (`lock_check.c:191`) each call
`brix_vfs_opendir_quiet` inline — the identical event-loop exposure as PROPFIND,
via the same VFS seam. LOCK additionally stats children (`lock_check.c:243`).

### Change

The same offload wrapper as W1, applied to the SEARCH and LOCK handlers behind
the same gate. Factor the task+done+impersonation scaffolding W1 builds into a
shared helper (`webdav_vfs_walk_offload.{c,h}`, new) so SEARCH/LOCK reuse it
rather than copying it — the duplication guard would reject three copies, and a
single seam is where W1's security bracket is enforced once.

### Tests

- **success** — SEARCH (basicsearch) and LOCK against a remote backend return
  their normal results; concurrent-request non-stall proven as in W1.
- **error** — an unreachable origin yields the normal error, bounded.
- **security-neg** — SEARCH results and LOCK's child stats are computed as the
  mapped user (same restricted-perms assertion as W1, on both methods).

### Acceptance

- SEARCH no longer blocks the event loop against a remote backend, and goes
  through the shared offload helper (duplication guard clean).
- **LOCK is an accepted exclusion, confirmed at the code level.** Its conflict
  walk (`check_locks_descendants`, `lock_check.c`) is not a read-only
  discovery prefix: inside the walk loop it calls
  `webdav_lock_expired_cleanup(r, child, &e, 1 /* reap lock-null */)`
  (`lock_check.c:231`), a VFS *mutation* (lock-xattr removal + lock-null
  reap), interleaved with the readdir/stat it performs to detect conflicts.
  There is therefore no clean build(thread)/send(event-loop) split as there is
  for PROPFIND/SEARCH — offloading it would move a mutation across the thread
  boundary, which the impersonation/mutation-gate discipline forbids (under
  impersonation the reap would run as the worker, not the mapped principal).
  LOCK is a rare method and its inline stall is already `max_entries`-bounded,
  so the risk of splitting a mutation flow is out of proportion to the gain.
  Revisit only if `webdav_lock_expired_cleanup` is first lifted out of the
  walk into a post-walk pass (collect expired paths on the thread, reap on the
  event loop) — a separate change with its own lock-table TOCTOU review.

---

## W3 — The token-exchange path rides the offload (no separate fix)

### Current state

`brix_token_exchange` is reached only through the VFS cred gate inside
`brix_vfs_opendir` (and the write-method opens, which are already offloaded). So
once W1/W2 move the three metadata `opendir`s onto the thread, **the exchange
runs on the thread too** — it needs no independent change. The write paths that
also mint (`vfs_cred.c` from PUT/COPY) are already on threads.

### Deliverable

A test asserting the exchange is no longer event-loop-reachable: with EXCHANGE
mode configured against a deliberately slow token endpoint and a LOCAL backend
(so the only blocking call is the exchange), a PROPFIND must not stall a second
concurrent request. This closes phase-106 R-7 as an enforced property rather
than a bounded-but-present one.

### Acceptance

- With EXCHANGE mode + a slow token endpoint, a metadata op does not stall the
  worker; phase-106 R-7 is downgraded from "confirmed, bounded" to "closed."

---

## W4 — Governance: the gate cannot silently regress

### Current state

There is no guard preventing a future metadata handler (or a refactor) from
doing backend I/O inline again. phase-106's `test_blocking_curl_bounded.py`
bounds the stall but does not forbid it.

### Change

A source-level guard (`tools/ci/check_metadata_offload.py` + a test) asserting
that the three metadata handlers reach `brix_vfs_opendir*` only through the
shared offload helper (W2), or behind the local-backend inline gate — never a
bare inline call on a path that can be remote. Model it on the VFS-seam and
mutation-gate guards (`check_vfs_seam.py`, `check_vfs_mutation_gate.py`), which
already enforce "this syscall only reached through that seam."

### Acceptance

- The guard reports zero on the post-W1/W2 tree and fails on a fixture that
  reintroduces an inline remote-capable metadata `opendir`.

---

## Non-goals (explicit)

1. **The transport is NOT rewritten.** `s3_transport.c`, `sd_http.c`, the
   `brix_s3_transport_t` vtable and every synchronous caller are untouched. This
   is the whole point of the correction above.
2. **GET/PUT/COPY/MOVE are NOT changed.** They are already correctly offloaded.
3. **`ngx_http_upstream` / `curl_multi_socket_action` are NOT introduced.**
4. **No auth *verification* logic changes.** The exchange, the cred gate, and
   the impersonation mapping are reused verbatim; only the thread they run on
   changes.

---

## Appendix A — reproducing the finding

```sh
# The three unoffloaded metadata handlers doing inline VFS opendir:
grep -n "brix_vfs_opendir" src/protocols/webdav/propfind_walk.c \
     src/protocols/webdav/search.c src/protocols/webdav/lock_check.c

# The methods that ARE offloaded (the pattern to reuse):
grep -rln "ngx_thread_task_post" src/protocols/webdav/

# The blocking transport is per-thread warm-handle (thread-designed):
grep -n "this thread's persistent" src/fs/cache/origin/s3_transport.c

# curl_multi_socket_action has NO in-tree precedent (option b is novel):
grep -rln "curl_multi_socket_action" src/ ; echo "exit $?  (empty = none)"

# The only event-loop-integrated outbound HTTP uses ngx_http_upstream:
grep -n "ngx_http_upstream_init" src/net/mirror/http_mirror.c

# The transport vtable is called synchronously from many sites:
grep -rn "transport->request\|->request(" src/fs/backend/s3/
```

## Appendix B — risk register

| # | Risk | Where | Likelihood | Impact | Mitigation |
|---|------|-------|-----------|--------|------------|
| R-1 | The offloaded walk runs as the WORKER, not the mapped caller — a privilege escalation / info leak | W1/W2 | Medium (the classic thread-boundary identity bug; `put_body.c:207` documents hitting it) | **Severe** | The impersonation bracket crosses the boundary by value; W1/W2 security-neg tests assert restricted-perms enumeration |
| R-2 | The offload fires on a LOCAL backend, regressing common-case latency with a needless thread hop | W1 | Medium if the gate is wrong | Medium | Gate on `brix_storage_backend_is_remote` / active EXCHANGE bag; a local-anonymous test asserts inline + byte-identical |
| R-3 | A future metadata handler reintroduces an inline remote-capable `opendir` | after W1/W2 | High without a guard | Medium (the stall returns) | W4 guard forbids it structurally |
| R-4 | Three copies of the task/done/bracket scaffolding | W2 | Medium | Low | Shared `webdav_vfs_walk_offload` helper; duplication guard enforces |
| R-5 | A very deep Depth:infinity walk now holds a thread-pool thread for a long time | W1 | Low–Medium | Medium (thread-pool pressure) | The walk is already `max_entries`-bounded (`propfind_walk.c:61`); a thread is the RIGHT place for it (it was blocking the event loop before) — but size the pool / cap accordingly and note it |

---

## Appendix C — sequencing

```
W1 (PROPFIND offload + the shared bracket)
  └─ W2 (SEARCH/LOCK reuse the helper)
       └─ W3 (exchange rides the offload — a test, no new code)
W4 (guard) rides W1/W2.
```

Suggested order: W1 first (it builds the shared offload helper and settles the
impersonation-across-threads pattern, which is the whole risk); W2 is then
mechanical reuse; W3 is a test; W4 locks it. Estimated size: **M** — one new
helper TU, three handler call-site changes, one guard, and their tests. No
transport code, no new async pattern.


---

## Implementation log (as-built, 2026-08-31)

| WS | Landed | As-built notes / divergences |
|----|--------|------------------------------|
| W1 | **DONE** | `src/protocols/webdav/walk_offload.{c,h}` (new). `propfind_do` split into `propfind_build` (thread: resolve/stat, the walk, per-prop residency, XML assembly) + `propfind_send` (event loop) — the split the function's own structure already suggested. **Task-private pool**: the build allocates via `webdav_req_pool(r)` (new inline in webdav.h; `propfind_pool` delegates), which returns the per-task pool while offloaded; the pool is registered as a cleanup on `r->pool` so response chains outlive the send. 17 `r->pool` sites routed (propfind.c/walk/props/props_acl + `resource.c`'s `webdav_resolve_stat` vctx). Request held with `r->main->count++`, balanced in the done handler (the put_body.c pattern). |
| W2 | **DONE for SEARCH; LOCK deferred (deviation)** | `walk_offload` generalized to a `{build, send}` callback pair; `webdav_search_do` split the same way (its `webdav_search_finalize` was already the send half). **LOCK is NOT offloaded, deliberately**: its conflict walk is interleaved with the lock-null resource *creation* (`lock.c:217` — a mutation) and the lock-table update, so the clean build/send split does not exist; offloading would mean splitting a mutation flow, a risk out of proportion to LOCK's exposure (rare method, stall still bounded). Recorded here so nobody assumes it was missed. |
| W3 | **DONE, differently than planned** | The plan wanted a slow-token-endpoint test with a LOCAL backend. Investigation showed the offload gate needed an EXCHANGE arm instead: `webdav_walk_offload_wanted` offloads when the backend is remote **or `conf->common.backend_delegation == BRIX_CRED_EXCHANGE`** — so the RFC-8693 mint inside the walk's cred gate rides the offload even on local storage. With that arm, every metadata path that can reach `brix_token_exchange` is off the event loop; phase-106 R-7 is closed for the metadata methods. |
| W4 | **DONE (as a suite guard, not tools/ci)** | `tests/test_metadata_offload_guard.py`: adopters dispatch offload-before-inline; thread-side files (`propfind*`, `search.c`, `resource.c`) never touch bare `r->pool`; the gate's `brix_imp_enabled()` decline exists and is FIRST; non-vacuity cell. A suite test is enforced by the same fast lane as a tools/ci script and matches the `test_suite_parallel_hygiene.py` precedent. |

**The load-bearing verification** (`tests/test_walk_offload.py`, 5 cells): with a
mock origin answering PROPFIND after 5s, a remote-backend PROPFIND is in flight
on a **single-worker** instance and an unrelated request completes in <3s —
the pre-109 inline path blocks the only event loop for the full origin wait
(observed ~20s: the transport retries a stalled attempt ~4×, pre-existing
sd_http behaviour). Plus: listing correctness, dead-origin bounded failure +
worker survival, local-stays-inline (byte-identical, gate respected), and
traversal still refused through the offloaded walk.

**Impersonation**: resolved exactly as the plan's trap #1 demanded, via the
copy_collection.c precedent — the gate DECLINES under `brix_imp_enabled()`
(single-user broker socket; the task lacks the principal), so impersonated
walks stay inline where the principal is set. The guard pins the decline as the
gate's first check.

**Collateral fixed en route** (blocking the zero gates, inherited from the
rebased phase-105 VFS commit, not this phase's code): 7 gcc-13 `-fanalyzer`
CWE-476 findings — the cross-TU `brix_vfs_require_confined_mutation` hid its
`ctx != NULL` contract from the analyzer. Fixed with the catalogue shapes:
the composition is now a `vfs_internal.h` inline (one-point fix for 5 sites)
and `brix_vfs_staged_commit` snapshots `st->ctx` after its NULL check
(3 sites). fanalyzer back to **0 findings**. Also: replacing my search.c
restructure re-triggered a pre-existing header-push clone family
(search/xrdhttp_stats/s3 handler) — all four sites now use the existing
`brix_http_set_header*` HELPERS.

Ports: `lc-walk-offload` (30918 + ORIGIN_PORT/LOCAL_PORT extras); shared
lifecycle lane 933→936, `PORT_COUNT` 2225→2228.

---

## Coverage audit — every workstream maps to a describing test (2026-09-03)

A closing pass walked W1–W4's test obligations against the landed suite so that
every discovery / compat / security property / behaviour change is named by a
test discoverable from the test list alone. Two obligations had accurate
prose but no self-naming test; both are now landed and green.

**Newly landed to close the audit.**

| obligation | as landed | what it now pins |
|---|---|---|
| W3 — the exchange rides the offload (phase-106 R-7 closed) | `test_gate_offloads_local_exchange_mode`, `test_metadata_offload_guard.py` | the gate's local-backend decline carries the `BRIX_CRED_EXCHANGE` exception, so a LOCAL EXCHANGE-mode metadata walk still offloads and its RFC-8693 mint leaves the event loop. This is the *only* test of the W3 arm — dropping the exception silently reopens R-7 (the gate still 'works', it just blocks the worker on every cold token mint); modelled on W4's "cannot silently regress" bar rather than a heavyweight slow-token runtime lane, since the stall mechanism itself is already exercised by the PROPFIND load-bearing cell through the shared `walk_offload` helper |
| W1 — Depth:infinity rides the offload | `test_remote_walk_depth_infinity_rides_the_offload`, `test_walk_offload.py` | the doc named both Depth:1 and Depth:infinity; the deep walk (Appendix-B R-5, the longest thread hold) now has its own cell asserting a well-formed 207 listing through the offloaded build. (Depth:1 and infinity are not byte-identical — infinity recurses — so the cell pins that the deep walk rides the offload and lists the tree, not a false depth-equality) |

**Already covered — equivalent name, source pin, or shared mechanism.**

- **W1 success (non-stall)** — `test_slow_origin_no_longer_stalls_the_worker`
  (load-bearing, single-worker probe under a 5s origin) + the listing cell.
- **W1 error** — `test_unreachable_origin_fails_cleanly_and_worker_survives`.
- **W1 security-neg** — the plan's "walk runs as the mapped user on the thread"
  was resolved by the gate DECLINING under impersonation (the copy_collection.c
  precedent), so impersonated walks stay INLINE where the phase-106 authz tests
  already enforce mapped-user enumeration. Pinned by
  `test_gate_declines_under_impersonation` (the decline is present and FIRST) +
  the runtime `test_offloaded_walk_still_refuses_traversal` and
  `test_local_backend_stays_inline_and_correct`.
- **W2 SEARCH** — `test_adopters_dispatch_through_the_offload` names `search.c →
  webdav_search_offload` (dispatches through the offload before its inline
  fallback); functional correctness stays covered by the local `test_webdav_search.py`
  suite (depth-1/infinity/filters), and the non-stall property holds through the
  same shared `walk_offload` helper the PROPFIND load-bearing cell exercises.
- **W2 LOCK exclusion** — `test_lock_is_not_offloaded_while_its_walk_mutates`
  pins both that LOCK does NOT dispatch through the offload and that its
  in-walk mutation (`webdav_lock_expired_cleanup`) still exists — so the
  exclusion rationale can't go stale unnoticed.
- **W4 guard** — the whole `test_metadata_offload_guard.py`: adopter order,
  thread-side no-bare-`r->pool`, the impersonation decline, and
  `test_detector_is_not_vacuous` (the order check really rejects inline-first).

Runtime lane `test_walk_offload.py` 6/6 and guard `test_metadata_offload_guard.py`
6/6 green post-audit. No W1–W4 obligation now lacks a describing test; LOCK
remains the one deliberate, test-pinned exclusion (its offload is
[Phase 113](phase-113-webdav-lock-mutation-offload.md)).
