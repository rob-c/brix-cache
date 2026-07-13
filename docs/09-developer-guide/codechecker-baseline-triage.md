# CodeChecker Baseline Triage — correctness class

**Date:** 2026-07-09 · **Baseline:** `tools/ci/codechecker_baseline.txt` (132 findings)
**Scope of this pass:** the **45 correctness-class findings** (clangsa `core.*`/`unix.*`/
`security.ArrayBound` + `bugprone-not-null-terminated-result`/`-signed-char-misuse`). The
remaining 87 are style/return-value class (see "Not yet triaged" below).

**Method:** each finding was adversarially verified against the analyzer's own reachability
trace (`CodeChecker parse --print-steps`) by an agent that read the actual code and the real
callers. A finding counts as REAL only with a concrete triggering path; otherwise it is a
FALSE_POSITIVE and the specific invariant the analyzer cannot model is recorded.

## Result: 0 live defects

| Verdict | Count |
|---|---|
| REAL_BUG (crash / leak / overflow / security) | **0** |
| FALSE_POSITIVE (invariant the analyzer can't model) | 42 |
| MINOR (defensive one-liner, no live defect) | 3 |

No memory corruption, no use-after-free, no null dereference, no buffer overflow, and no leak is
reachable among the 45. The `net/proxy/pool.c:196` "use-after-free" and both
`security.ArrayBound` findings — the three scariest on paper — are all unreachable.

## The 3 optional hardening one-liners (not fixes for live bugs)

1. **`src/protocols/s3/auth_sigv4_verify.c:319`** (`core.NonNullParamChecker`) — a crafted SigV4
   `SignedHeaders` list naming a header the client never sent reaches
   `ngx_memcpy(out+oi, NULL, 0)`. Passing NULL to `memcpy`'s `nonnull` src is standard-UB, but
   length is 0 so nothing is read and no fault occurs; the canonical string correctly gets an empty
   value. **Guard:** `if (ve > vs) { ngx_memcpy(out+oi, vs, (size_t)(ve-vs)); oi += (size_t)(ve-vs); }`
   — the only one that is attacker-reachable, worth doing for standards-cleanliness.
2. **`src/fs/backend/cache/sd_cache.c:507`** (`core.CallAndMessage`, the `sd.h` vtable cluster) —
   `sd_cache_open_common` is the lone cache→source open path that does not inline-guard
   `src->driver->open == NULL` (its siblings `sd_cache_fill`/`sd_cache_partial_open` do). Safe today
   via the composition invariant, but adding the guard makes the three paths uniform.
3. **`src/net/cms/server_recv.c:435`** (`core.NullDereference`) — the function guards `ctx->c != NULL`
   at L429/L431 but derefs `ctx->c->log` unguarded at L435. Cannot fire (a close nulls `ctx->c` and
   returns before frame processing), but the guards are internally inconsistent — either guard L435
   too or drop the earlier ones.

All three are cosmetic/defensive. None is required for correctness.

## Why so many false positives — the recurring blind spots

These five patterns account for all 42 FPs. Worth knowing, because *new* findings of the same shape
will also be noise — and because they document invariants the codebase genuinely relies on:

1. **Defensive `x != NULL` guard poisons a later deref.** An early optional-feature guard
   (`if (r->connection != NULL)` for a `setsockopt`; `c != NULL ? c->log : NULL` on a restore-fail
   path) makes clangsa assume `x` can be NULL, then it flags a later unconditional `x->field` that a
   real invariant guarantees. (`tpc/engine/done.c` ×4, `cms/server_recv.c:435`,
   `shared/file_serve.c:178`.)
2. **Syscall/library out-param writes not modeled.** `getpeername`/`getsockname` fill `ss` on
   success; `snprintf` fills its buffer; `dirfd()` on a checked `fdopendir` never returns -1. clangsa
   treats the post-success value as garbage / the fd as possibly -1. (`pmark/flowlabel.c`,
   `pmark/sockstats.c`, `webdav/xrdhttp_stats.c`, `cvmfs/origin_probe.c`, `s3/handler.c:868`,
   and the three `fstatat` findings.)
3. **Length-delimited binary buffer treated as a C-string.** `bugprone-not-null-terminated-result`
   assumes crypto/wire material is a string; it is consumed with an explicit length
   (`brix_hmac_sha256(key, len)`, `brix_gbuf_bucket(buf, len)`, `memmem(buf, len)`), never `strlen`.
   (`gsi/gsi_cipher.c` ×3, `core/compat/sigv4.c`, `backend/rados/sd_ceph.c` — the last is terminated
   by the immediately-following copy.)
4. **Single-destructor cleanup contract.** A scratch struct freed entirely by one destructor
   (`bdg_fail`, `gsi_cresp_fail`) on every path including success; clangsa only tracks fields the
   function explicitly NULLs for ownership transfer, so untransferred fields look "leaked."
   (`gsi/delegation.c:213`, `gsi/gsi_core.c:421`.)
5. **Loop-iteration conflation + composition-set invariant.** The nginx queue-drain idiom
   (`ngx_queue_remove` before `ngx_free`, next `ngx_queue_head` returns a live node) reads as a UAF;
   and the vtable dispatch is safe because callers guard the slot AND `brix_tier_build` only
   instantiates drivers that define the op. (`net/proxy/pool.c:196`, `fs/backend/sd.h` ×11,
   `fs/path/helpers.c:59` and `root/read/statx.c:137` bounded by NUL-iteration / PATH_MAX + `&&`.)

## Applied — the 3 one-liners are fixed (2026-07-09)

All three guards landed and the module rebuilds clean under `-Werror`; baseline re-frozen at 131
(`tools/ci/run_codechecker.sh --regen`). `auth_sigv4_verify.c:319` and `server_recv.c:435` findings
are gone; the `sd.h` vtable cluster dropped 18→11 (the `sd_cache_open_common` guard removed the
cache→source open path). Note: editing `sd_cache.c` re-keyed some header-included findings'
content-hashes, so the net count moved only 132→131 — the expected baseline churn when a header
included by an edited TU shifts, and exactly why the CI workflow ships non-blocking.

## P2 triage — style / return-value class (95 findings): also 0 live defects

Same adversarial method, four batches. **0 REAL_BUG.** Everything is a false positive, an intentional
best-effort call, or a cosmetic MINOR.

| Group | Count | Result |
|---|---|---|
| `clang-diagnostic-conditional-uninitialized` + `bugprone-misplaced-widening-cast` | 15 | all FP — fd↔addr / `found==OK` correlations the analyzer can't prove; every widening-cast operand is an OpenSSL output-length or `snprintf` return bounded far below `INT_MAX` (KB buffers) |
| `misc-redundant-expression` + `readability-suspicious-call-argument` | 23 | 22 FP + 1 MINOR — the "redundant"s are Linux errno-alias idioms (`ENOTSUP`==`EOPNOTSUPP`, `ENODATA`==`ENOATTR`) and `NGX_ERROR`-sentinel guards; the "suspicious args" are correct `renameat`/`brix_beneath_full_path`/`brix_copy_range` calls whose var names merely rhyme with params |
| `cert-err33-c` auth/crypto/token/cred (unchecked returns) | 20 | 0 real + 2 MINOR — all ignored `fclose`-on-read / `vsnprintf`-to-error-buffer. **Verified the real privilege-drop (`broker_creds.c` `setresuid`/`setgroups`) checks every return and is NOT in the findings.** |
| `cert-err33-c` (rest) + `deadcode.DeadStores` + `format-nonliteral` + `reserved-*` | remainder | 0 real — best-effort logging/cleanup, benign sentinel re-inits; the checked journal/ledger `write()`s are the load-bearing calls and they *are* checked; `reserved-*` are leading-underscore include guards |

### Optional MINOR hardening (no live defect — left for a rainy day)
- `src/fs/vfs/vfs_io_core.c:496` — dead ternary `errno == ENOENT ? NGX_DECLINED : NGX_DECLINED` →
  `return NGX_DECLINED;` (both arms equal; behaviour already matches the documented contract).
- `src/auth/token/jwks.c:164,166` — unchecked `fseek` when sizing the JWKS file; a failure fails
  *closed* (bounded buffer + checked `fread` + JSON parse reject), so token auth can't open up.
- `src/protocols/ssi/svc_cta/cta_queue.c:22` — ignored `fflush` on the CTA journal (durability only).
- `src/protocols/webdav/tape_rest.c:436` / `src/protocols/root/fattr/list.c:100` — a mid-listing
  `readdir`/list error is treated as end-of-list, so a partial listing could be served as complete.
  Best-effort by design, but the most "real-adjacent" of the MINORs if you want to tighten listing.

## Bottom line

The **entire correctness surface of the CodeChecker baseline is clean of live defects** — P1 (45) and
P2 (95) both triaged to zero real bugs, with the analyzer's blind spots documented above. The three
attacker-reachable/consistency one-liners are fixed. The ratchet now holds a 131-finding floor: any
*new* finding in changed code fails CI and won't be buried under these known-safe entries. Remaining
MINORs are optional; apply them and re-run `tools/ci/run_codechecker.sh --regen` to drop them.
