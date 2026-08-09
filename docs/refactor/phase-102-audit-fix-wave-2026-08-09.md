# Phase 102 — Audit fix wave (2026-08-09)

**Date:** 2026-08-09
**Source:** `docs/refactor/xrootd-feature-parity-audit-2026-08-04.md` — the six
small/high-leverage items left after the phase-100 metalink + extreme-copy work.

**Status:** ✅ IMPLEMENTED & TESTED. Five items needed code; one was already
fixed and its audit row was stale. Two further defects were found *while
testing* and are folded in.

Tests: `tests/test_audit_fixes_2026_08_09.py` (13 cases) +
`client/tests/c/kxr_errors_unit.c` (4 cases). Both green; the pytest suite was
run three consecutive times to confirm the timing-sensitive cache case is
stable.

---

## 1. What each item turned out to be

### 1.1 §6.3 / §9.2 — "TPC push skips the Layer-2 egress allowlist"

**No code needed — the row was stale.** The push branch of
`ngx_http_brix_webdav_tpc_handle_copy()` already runs `webdav_tpc_source_guard()`
on the `Destination` authority before `webdav_tpc_handle_push()`
(`src/protocols/webdav/tpc.c:347-363`) — same verdict core, same 403, same
`signal=tpc_egress` audit line as a pull. It landed 2026-08-04 alongside four
cases in `tests/test_webdav_tpc_source_egress_guard.py::TestWebdavPushGuardRefuse`
(see `testsuite-combinatorial-coverage-audit-2026-08-04.md` §2.2); the parity
audit was written from the pre-fix state and never updated.

Verified rather than assumed: the guard suites were run and pass 9/9. The audit
rows are corrected.

### 1.2 §1 gap 5 — missing kXR error constants

Six reference codes BriX had no spelling for:

| Code | Value | errno | Retryable |
|---|---|---|---|
| `kXR_SigVerErr` | 3022 | `EACCES` | no |
| `kXR_DecryptErr` | 3023 | `EACCES` | no |
| `kXR_BadPayload` | 3026 | `EINVAL` | no |
| `kXR_noReplicas` | 3029 | `EHOSTUNREACH` | **yes** |
| `kXR_ReqTimedOut` | 3034 | `ETIMEDOUT` | **yes** |
| `kXR_TimerExpired` | 3035 | `ETIMEDOUT` | **yes** |

Defined in `protocol/opcodes.h` (the gaps at 3022/3023/3026/3029 in the existing
table line up exactly, which self-validates the values), named in
`core/compat/kxr_names.c`, mapped in `core/compat/error_mapping.c`.

The behavioural half is the retryable classification in
`client/lib/core/types/status.c`: these are codes a **stock** server sends, and
the client previously decoded them as `"Unknown"`, mapped them to no errno, and
treated every one as fatal — so a stock-side timeout or a momentarily
unavailable replica aborted a whole transfer that a retry would have completed.

**Deliberately NOT done:** re-coding BriX's *own* sigver responses to
`kXR_SigVerErr`. Stock `XrdSecProtect` does use it, but `test_sigver_verify.py`
and `test_sigver_wire_conformance.py` lock `kXR_NotAuthorized` on the wire, and
changing what BriX emits is an interop decision, not a constant definition.

### 1.3 §7.5 — `--tpc delegate` silently emitted `tpc.dlgon=0`

The hardcoded `0` was only half the bug.

- **Wire half:** `tpc_build_dst_opaque` now emits `tpc.dlgon=1` for
  `XRDC_TPC_DELEGATE` and `0` otherwise. Before, `--tpc delegate` produced a
  byte-identical request to `--tpc first`, so a destination honouring `dlgon`
  never ran the delegated flow.
- **Capability half (found while writing the test):** even with the flag set,
  the client *refused* the destination's `kXGS_pxyreq` delegation round unless
  `$XRDC_GSI_DELEGATE` was set, and its GSI certreq advertised no delegation
  capability (`clnt_opts` `0x80` only) — so a stock destination would never even
  ask. `--tpc delegate` now sets `brix_opts.gsi_delegate`, and **one** predicate
  (`gsi_delegation_enabled`) drives both the `kOptsSigReq` advertisement and the
  sigpxy round, so advertise-vs-honour cannot disagree again. Delegation stays
  opt-in — signing the peer's request hands it a credential that speaks as the
  user — and the refusal names both ways to enable it.

### 1.4 §7.4 — `tried=` / `triedrc=` never emitted

BriX's manager has parsed this protocol since forever
(`brix_manager_tried_exhausted`, `registry_select.c`) to converge to
`kXR_NotFound` once a client has visited every candidate — but no BriX client
ever emitted it, so that path was unreachable from our own tools.

`client/lib/protocols/root/frame_roundtrip.c`: when a redirect target is
unreachable and the client falls back to its home manager, the replayed request
now carries `tried=<hostport>&triedrc=<reason>` using the stock reason tokens
(`enoent`/`ioerr`/`fserr`/`srverr`; an unreachable endpoint is `ioerr`).

Two scope decisions:

- **Which opcodes.** Only `kXR_open` / `kXR_stat` / `kXR_query` — exactly the
  set BriX's own manager parses `tried=` for (`open_manager.c`,
  `stat_manager.c`, `checksum_qcksum_path.c`), so emission and consumption
  cannot drift. Appending CGI to a payload that is not a single path (e.g.
  `kXR_mv`'s two paths, or the data opcodes) would corrupt it.
- **Which failures.** The dead-redirect-target → manager-fallback path, which is
  the case where the client already returns to the manager and the manager can
  act on the information. Retrying at the manager when a *data server returns an
  error* is a behaviour change (it adds a retry), not an emission gap, and is
  left open.

The redirect-capability opaque and the tried CGI now share one
`rt_rebuild_payload()` that always rebuilds from the ORIGINAL path, which is
what stops successive redirects accumulating stale opaques.

### 1.5 §4.2 / §4.4 — the cache policy pair

**`brix_cache_cold_max_age <time>`** (default `0` = off) — age-based purge of
CLEAN read-through fills, independent of occupancy (upstream
`pfc.purgecoldfiles`). The watermark reaper only runs once the filesystem
crosses its high-water mark, so on a roomy cache a cold object was kept forever.

- New `BRIX_CACHE_REAP_COLD` reason on
  `brix_cache_dirty_reaped_total{reason="cold"}`.
- Age = the **later of atime and mtime**. atime alone is untrustworthy —
  `relatime` coarsens it and `noatime` freezes it, which would make every file
  look ancient and purge a hot cache. The later-of-two degrades safely: on
  `noatime` the age is measured from the fill, so the purge can only be too
  slow, never too eager.
- The reaper walk is now armed by **either** horizon (it was gated on the dirty
  one alone).
- Off by default on purpose: unlike the dirty horizon (which bounds a leak),
  this one discards otherwise-serviceable cache.

**`brix_cache_only_if_cached on|off`** (default `off`) — serve only what is
already cached; a read MISS returns `ENOENT` → `kXR_NotFound` instead of filling
from the origin (upstream `pfc.onlyifcached`). The refusal is deliberately
not-found rather than a server error: a client retries a server error against
the same node but fails over from a not-found, which is the whole point.

Gate placement is load-bearing and fixed: **after** the cache-hit test (a cached
object still serves) and **before** the admission filter and the fill /
nearline-recall paths — otherwise an admission-declined path would still reach
the source, the exact bypass the mode exists to prevent. Writes always pass
through. `minsize`/`minfrac` partial-hit thresholds are not implemented (a
partial hit counts as a miss).

### 1.6 §5.2 — signing silently unenforced off-GSI

`brix_signing_enforce_level()` returned `BRIX_DISPATCH_CONTINUE` *before running
any check* whenever `signing_active == 0`. Only GSI arms a session signing key,
so on an `sss`/`ztn`/`krb5`/`unix`/`host`/anonymous session
`brix_security_level intense` enforced **nothing** and logged **nothing** — the
tamper protection an operator configured was simply absent.

Now the case is handled explicitly:

- Always **logged**: one `WARN` per session (the condition is a property of the
  session's auth protocol, so per-request would flood with no new information)
  naming the level and stating whether requests are `accepted UNSIGNED` or
  `REFUSED`.
- Optionally **closed**: new `brix_signing_required on|off` (default `off`).
  On, the request is refused with `kXR_NotAuthorized`.
- Default off because turning it on rejects every client whose protocol cannot
  sign — including stock `sss`/`ztn`/`krb5` clients. That is a deployment
  decision, not a default.
- Handshake opcodes stay exempt at every level, so this can never lock out the
  session state machine.

**Deliberately NOT done:** actually deriving signing keys for `sss`/`krb5`.
Both carry key material and stock signs `sss`, but that is a wire change
requiring matched client *and* server derivation, and shipping only the server
half would break every existing non-GSI client. The audit row is updated to
split the closed half from the open half rather than marking §5.2 done.

---

## 2. Defects found while testing (not in the original list)

### 2.1 The cache reaper reported unverified removals as successes

The cold-purge test failed while the log said the file had been purged.
`reap_remove()` called the cstore evict adapter (best-effort by contract — it
returns OK even on a failed unlink) and then logged + counted the reap
**without checking**. A data file the adapter failed to remove was therefore
reported as reaped, lost its `.cinfo` sidecar to `reap_unlink_sidecars()`, and
from then on looked *untracked* to `reap_classify()` on every later pass — so it
was never revisited. A disk leak that logged as a success, affecting the
pre-existing `abandoned`/`incomplete`/`completed` reasons too, not just the new
one.

`reap_remove()` now verifies with `lstat`, falls back to a direct `unlink`, and
logs `cache reaper could not remove "<path>" (left in place)` at error level
without counting the metric if the file still survives. The adapter path is also
skipped when the data-root prefix is empty (a store-configured cache leaves
`cache_root` unset, which made the prefix test match everything and produced a
bogus key).

### 2.2 The client refused the delegation it advertised

Covered in §1.3 — recording it here because it is the same class of bug as 2.1:
a code path that *reported* doing something it did not do.

---

## 3. Test coverage

**`client/tests/c/kxr_errors_unit.c`** (in `make -C client test`): wire values
(plus the untouched neighbours, so a transposed digit is caught), name-table
resolution including the preserved `"Unknown"` fallback, errno mapping, and the
retryable split — the three transient codes must retry, the three definite ones
must not.

**`tests/test_audit_fixes_2026_08_09.py`** — one class per fix:

- `TestTriedEmission` (3) — a stub redirector hands out a dead port; the
  manager-fallback replay must carry `tried=` naming the dead endpoint and a
  `triedrc=` from the stock token set; a request that never fails over must go
  out byte-identical (emitting `tried=` on a first attempt would tell a
  redirector this client had visited servers it had not).
- `TestTpcDelegate` (4) — reads the destination-open opaque off the wire:
  `delegate` → `dlgon=1`, `first`/`only` → `dlgon=0`, plus a source-level check
  that advertise-and-honour share one predicate.
- `TestOnlyIfCached` (2) — an uncached read is refused **and leaves the cache
  store empty** (which is what proves the source was never pulled from); the
  refusal is `kXR_NotFound` so clients fail over.
- `TestColdFilePurge` (1) — fill, back-date atime/mtime past the horizon
  (deterministic equivalent of waiting), then nudge the reaper and assert the
  object is gone.
- `TestSigningFailClosed` (3) — required-off still serves **and logs the WARN**
  (the gap must not be silent); required-on refuses with `kXR_NotAuthorized`;
  handshake opcodes stay reachable so the mode is usable rather than a lockout.

Three lifecycle instances were added
(`lc-audit-onlyifcached`/`-coldpurge`/`-signing`), which required an intentional
`port_ladder.py` exclusive-width bump (137 → 140). The signing pair shares one
instance via `reconfigure()` + `restart()` so the two cases differ in exactly
the directive under test and cost one ladder slot instead of two.

**Also fixed:** `tests/test_cache_reap_metrics.py` could not run in this
environment at all — it links `objs/addon/cache/cinfo.o` from a sanitized nginx
tree with a plain `cc`, dying at LD time on `undefined reference to __asan_*`.
It now probes with one `nm` pass and adds the matching `-fsanitize` flags, the
same helper idea as `cmdscripts/c_regression_units.py::_sanitizer_flags`, plus
`ASAN_OPTIONS=detect_leaks=0` for the planter run.

---

## 4. Documentation updated

- `docs/refactor/xrootd-feature-parity-audit-2026-08-04.md` — rows §1.5, §4.2,
  §4.4, §5.2, §6.3, §7.4, §7.5 and the §9.2 punch list; the executive summary
  gained a wave summary. §6.3 is marked stale-not-broken; §5.2 splits the closed
  half from the open half.
- `docs/03-configuration/directives.md` — new entries for
  `brix_cache_only_if_cached`, `brix_cache_cold_max_age` and
  `brix_signing_required`, plus the unified-storage directive index.
- `docs/08-metrics-monitoring/metrics-overview.md` — the `reason="cold"` row on
  `brix_cache_dirty_reaped_total`, and a note that a removal the reaper cannot
  complete logs an error instead of advancing the counter.
- `client/man/xrdcp.1` — `--tpc` modes broken out, with what `delegate` now
  actually does and why delegation is opt-in.

## 5. Still open (explicitly not in this wave)

- Keying `sss`/`krb5` sessions for real (§5.2) — wire change, needs matched
  client+server derivation.
- The rest of the §5.2 signing-level *table* conformance (compatible/standard/
  intense opcode sets, `relaxed`/`force`, `kXR_signLikely`).
- `tried=` on a data-server **error** (retry-at-manager) — a behaviour change,
  not an emission gap.
- `onlyifcached` `minsize`/`minfrac` partial-hit thresholds.
- Re-coding BriX's own sigver refusals to `kXR_SigVerErr` (interop decision).
