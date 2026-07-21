# Phase-64 follow-up — generic slice/partial fill + read-fill admission

**Status:** ~~BACKLOG~~ **DONE — both items landed (verified against the tree
2026-07-21, phase-89 doc truth sweep).**

> **SUPERSEDED (2026-07-21).** Both gaps below are closed in the tree:
> - **§1 generic slice fill:** the Group-2 strict-xfails in
>   `tests/test_cache_partial_fill.py` are now passing capability tests — the
>   composable `sd_cache` range-fills any backend (the test comment reads
>   "Formerly a strict xfail: the legacy…"; the phase-64 umbrella §14 status
>   block records the flip landing with the legacy-grammar removal).
> - **§2 read-fill admission:** `test_admission_prefix_regex_gating` is an
>   active (un-skipped) test asserting the `sd_cache` read-fill enforces the
>   deny/allow-prefix + include-regex admission policy, bridged from the srv
>   conf into the tier policy — read parity with write-through
>   (`src/fs/cache/writethrough_decision.c` includes `cache_admit.h`
>   "shared admission filter (read+write parity)").
>
> Only the Group-5 env-gated heavy-backend legs still skip on a bare box (by
> design). Remaining phase-64 work is tracked in
> `phase-89-design-backlog-burndown.md` §D. The text below is the historical
> record of the original findings.

(Original status: BACKLOG — surfaced by the read-cache partial-fill test suite,
`tests/test_cache_partial_fill.py`, 2026-07-01.)

## 1. Generic slice/partial fill over any backend

**Gap.** `src/fs/cache/cache_storage.c` composes the `sd_cache` slice decorator only
when `cache_slice_size > 0 && cache_origin_host.len > 0`, hardwiring the source to
`xrootd_sd_xroot_create_origin(...)`. So sparse partial fill works only for a
`root://` origin configured via `xrootd_cache_origin`; a `posix`/`pblock`/`http`/
`s3`/`rados` `xrootd_storage_backend` silently ignores `xrootd_cache_slice` and
does whole-file fill.

**Change.** When `cache_slice_size > 0` and no `cache_origin_host` is set, compose
`xrootd_sd_cache_create(conf->cache_storage_inst /* generic source */, store,
&pol, root, log)` over the already-built generic backend instance, instead of
requiring the xroot origin. Keep it driver-agnostic (phase-64 P3 — no `strcmp`
on driver name).

**Acceptance signal.** These are `xfail(strict=True)` today and turn green with the
assertion already written (`flags == ["PARTIAL"]`, `present_blocks == [0]`) — no
test rewrite:
- `test_cache_partial_fill.py::test_generic_backend_slice_size_is_ignored[posix]`
- `test_cache_partial_fill.py::test_generic_backend_slice_size_is_ignored[pblock]`
- (and the Group-5 gated `test_gated_backend_partial_read_is_whole_file` once its
  env/harness is provided.)

## 2. Read-fill admission filter (deny/allow prefix, include-regex, max_file_size)

**Finding.** `xrootd_cache_admit` (`src/fs/cache/cache_admit.c`) is invoked from
`src/fs/cache/fetch.c` (`xrootd_cache_fill_from_source`, the `cache_origin` fetch
spine) with `deny_prefixes` / `allow_prefixes` / `size_limit`(=`cache_max_file_size`)
/ `include_regex`. In the partial-fill suite, **none of these gated a READ fill** on
any exercised config — a denied-prefix / oversized (via `max_file_size`) file was
cached regardless; `include_regex` is (correctly) a size-cap *override*, not a
whitelist. The size gate that DOES take effect on the read path is
`xrootd_cache_max_object` (`test_oversized_file_not_cached`).

**Hypothesis.** The composable `xrootd_storage_backend` fill and the
`cache_origin` slice fill do not route through the `fetch.c` `fill_from_source`
admit call for a READ, so the `cache_admit` filter only governs some fills (likely
S3/http origin whole-file), not the local/slice read paths. Needs a dedicated
trace of which fill path each backend takes and where `cache_admit` should be
enforced for read parity with write (`writethrough_decision.c`).

**Acceptance signal.** `test_cache_partial_fill.py::test_admission_prefix_regex_gating`
is `skip`-marked with this finding; unskip and assert `{"absent": True}` once the
read-fill admit path is confirmed and wired.

## Not in scope of the test suite
Implementing either change above is production work with its own spec→plan→build
cycle; the suite documents current behavior and provides the executable acceptance
signals.
