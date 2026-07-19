# Phase 84 — CVMFS conformance corpus (500 server + 500 fuse)

Status: CORPUS COMPLETE — Wave-4 burndown done (2026-07-17). 1188 tests / 16
files collected clean; findings recorded below. UNCOMMITTED (awaiting OP git
approval).

## Goal

Two 500-test conformance corpora hunting corner cases where nginx-xrootd's CVMFS
components might diverge from expected CVMFS behavior:

- **Server corpus** — the `brix_cvmfs` site-cache module (`src/protocols/cvmfs/`):
  gate/classifier, manifest TTL semantics, CAS verify-on-fill, HTTP protocol
  surface, proxy mode, GeoAPI, resilience, config-load contracts.
- **Fuse corpus** — the `brixcvmfs` client (`client/apps/fs/brixcvmfs.c` +
  `shared/cvmfs/`): manifest/whitelist parsing, trust chain, catalog semantics,
  read/chunk semantics, cache/quota, refresh/failover, POSIX surface.

**Reference-correctness rule:** the official CVMFS implementation is presumed
correct. A test asserts documented/official behavior; where brix intentionally
diverges, the test is `xfail` with a `# DIVERGENCE:` comment citing the design
doc. A divergence between CVMFS *documentation* and the *official client* is a
candidate upstream bug — record it in the "Findings" section below, never
"fix" the test to hide it.

## Naming, tiering, counts

- Files: `tests/test_cvmfs_conformance_srv_<topic>.py` and
  `tests/test_cvmfs_conformance_fuse_<topic>.py`. The `conformance` substring
  auto-tags them `slow` (nightly tier) via `_SLOW_MODULE_HINTS` — they must NOT
  slow the <5min PR gate.
- All tests always-runnable on a dev box: in-process mock origin + LiveRun
  nginx (server corpus), unprivileged libfuse3 mounts (fuse corpus). Skip-guard
  fuse corpus on `fusermount3`/`client/bin/brixMount` presence; no root, no
  network, no `PHASE81_RUN_*` gate needed. Stock-`cvmfs2` differential checks
  stay in the existing matrix suites, not here.
- Count target: ≥500 collected per corpus (`pytest --collect-only -q`), reached
  by honest parameterization (each param row a distinct behavioral assertion,
  not the same assertion on cosmetic inputs).
- Per-test default timeout is 30s; long scenarios take `@pytest.mark.timeout(N)`.
  Prefer module-scoped server/mount fixtures; per-test state isolation via
  distinct objects/paths, not fixture teardown.

## Shared infrastructure (Wave 1)

1. `tests/cvmfs/repo_forge.py` — pure-Python signed-repo builder, the fuse
   corpus workhorse. Replicates `brix_mkrepo.c` formats exactly (verify against
   `shared/cvmfs/signature/{manifest,whitelist,verify}.c`, `catalog/catalog.c`,
   `object/object.c`): zlib CAS objects named by hash-of-stored-bytes, sqlite
   catalogs (catalog/nested_catalogs/properties/chunks tables, md5path keying),
   X509 cert object (`X` suffix), whitelist + manifest with raw
   RSA-PKCS#1-v1.5 signatures (via `openssl pkeyutl` subprocess — stdlib has no
   RSA). Builder API is declarative (dict-tree of files/dirs/symlinks/chunked
   files/nested catalogs) with **tamper knobs**: flip bytes in any artifact,
   substitute keys/certs, edit manifest/whitelist fields, drop CAS objects,
   store objects uncompressed, oversize fields.
2. `tests/cvmfs/mock_stratum1.py` extensions (backward-compatible — existing
   `test_cvmfs_mock.py` and live cmdscripts must stay green): `--webroot DIR`
   mode serving a forged repo tree from disk; per-path fault targeting
   (`/ctl/fault` gains optional `path_re`); new fault modes `truncate`,
   `wrong_length`, `http500`, `slowdrip`; `/ctl/reset-log`.
3. `tests/cvmfs/conformance_common.py` — shared helpers: nginx-config builder
   over `cmdscripts/live_common.py::LiveRun` with `brix_cvmfs*` knobs; mount /
   umount context manager for `brixcvmfs` (env pinning via `BRIXCVMFS_SERVER`,
   `BRIXCVMFS_PUBKEY`, `BRIXCVMFS_CACHE`, `BRIXCVMFS_TMP`); port allocation
   (below); http helpers.

### Port blocks (no collisions under parallel authoring/xdist)

Each file owns a 20-port block: srv_gate 13100, srv_manifest 13120,
srv_cas 13140, srv_http 13160, srv_proxy 13180, srv_geo 13200,
srv_resilience 13220, srv_config 13240, fuse files 13300+ (same 20-stride,
alphabetical). Mock origins use block base+0..9, nginx instances base+10..19.

## Server corpus — file budgets (≈500)

| file | ≈ | themes (corner-case emphasis) |
|---|---|---|
| srv_gate | 80 | URL grammar: CAS hex lengths {40,64,96,128} accepted vs {39,41,63,127,129,0} rejected; suffix alphabet valid/invalid; uppercase/non-hex; `..` + `%2e%2e` + `//` traversal; repo-name grammar; query/fragment; non-/cvmfs paths → 403 + one-line `cvmfs-reject:`; methods PUT/POST/DELETE/OPTIONS/PROPFIND/TRACE → 405; GET/HEAD allowed |
| srv_manifest | 60 | `.cvmfspublished`/`.cvmfswhitelist`/`.cvmfsreflog` TTL cache: origin-fetch counts inside/after TTL; stale-if-error inside vs beyond 10×TTL; revision-bump propagation; HEAD/GET parity; IMS/304 on metadata |
| srv_cas | 65 | verify-on-fill: corrupt → quarantine dir + not served + refetch; truncated/wrong-length fills; each hash length + suffix through verify; cache-hit byte identity + single origin fetch; negative-404 memo: absorb count, per-object isolation, negative_ttl expiry, memo vs new object |
| srv_http | 65 | Range: single/suffix/open-ended/multi-clause/malformed/`bytes=` off-by-one at EOF/416 + Content-Range; conditional IMS/304; weak ETag stability across hits; HEAD header parity vs GET; Content-Length exactness on cached vs filled serve |
| srv_proxy | 60 | absolute-form request-line corpus (ports 0/65535/65536/absent, IPv6 literal, userinfo, scheme case, bad schemes); `upstream_allow` enforcement + bypass attempts; `upstream_max` cap; `shared_cache` dedup across two upstreams; `unified_origin` hides dead named origin; validation of unified_origin config contract |
| srv_geo | 50 | geo passthrough vs `geo_answer rtt`: reply is permutation of input list; empty/1/dup/unresolvable/>max_servers lists; malformed geo paths; geo never cached; rtt cache TTL; fallback-to-passthrough on parse failure |
| srv_resilience | 70 | stall detection (stall_timeout/stall_bytes/attempt_timeout); failover vs force-primary retry; N concurrent clients → 1 origin fetch (coalescing) at various N; client_hold bound; fill_max_life; reuse_conn on/off connection counts; mid-fill reset → full object or clean 502, never truncated 200, never RST to client |
| srv_config | 50 | config-load EMERG rejections (`brix_stage`/`brix_cache_slice_size`/`brix_allow_write` × cvmfs); directive defaults/duplicates/bad values; scvmfs bearer authz matrix (none/bearer × no-token/bad/good → 200/401/403); public-by-design (auth adds nothing) |

## Fuse corpus — file budgets (≈500)

| file | ≈ | themes |
|---|---|---|
| fuse_manifest_parse | 65 | `.cvmfspublished` field corpus: missing C/N/S/T/D/X; bad hex lens; unknown field letters; CRLF; missing `--`; oversized (>64K scratch); huge S/D values; **signed-hash vs actual-digest binding** (mkrepo signs literal `1111…` — does verify.c bind the printed hash to the real digest of the signed range? official client does) |
| fuse_whitelist | 60 | expiry timestamp past/future/malformed/short; 0/1/16/17 fingerprints (16 = fixed cap); fingerprint case/format; repo-name N mismatch; wrong master key; tampered signature byte |
| fuse_catalog | 75 | forged-catalog semantics: deep paths; 255-byte names; unicode; empty dirs; dot-prefixed names; symlink targets rel/abs/dangling; mode/uid/gid surfacing; hardlink counts; mtime; nested-catalog transitions (ROOT/MOUNT flags, missing nested row, nested object absent); readdir completeness vs sqlite truth |
| fuse_read | 70 | offsets at/past EOF; zero-len reads; sub-page reads; whole-file; uncompressed-store objects; chunked files: boundary first/last byte, chunk-spanning reads, missing chunk object → EIO, chunk list gaps/overlaps; read after cache-evict |
| fuse_trust | 60 | end-to-end tamper matrix: manifest byte, whitelist byte, cert object byte, catalog object byte, content object byte, wrong pubkey, expired whitelist → mount refused or EIO, never wrong bytes served; `--check` exit codes |
| fuse_cache | 55 | warm-cache hit (no origin fetch); offline serve after warm; on-disk cache entry corrupted → refetch not trust; quota high-watermark reap to 75%; `-o cache=`/`BRIXCVMFS_CACHE` precedence; `.brixcache` hidden from readdir |
| fuse_refresh_failover | 65 | TTL-gated refresh: new revision visible after D-TTL; refresh failure → old catalog keeps serving; mirror failover order + retry budget (no-progress only); range-resume mid-transfer sever; proxy env precedence env→config→direct; `-o fresh`/`-o tls` |
| fuse_posix | 50 | every mutating op → EROFS (create/unlink/mkdir/rmdir/rename/chmod/chown/truncate/utimens/write, O_WRONLY/O_RDWR open); xattrs: exact 7-name set, values match mount state, listxattr set equality, ENODATA otherwise; statfs sanity; getattr↔catalog consistency; dirent stability across rereads |

## Waves

- **W0** this doc. **W1** infra (repo_forge, mock extensions, conformance_common)
  + smoke + existing-suite regression. **W2** 8 server files (parallel).
  **W3** 8 fuse files (parallel). **W4** full-corpus burndown; classify failures
  as (a) test bug, (b) brix divergence → fix or xfail+DIVERGENCE, (c) doc-vs-
  official mismatch → Findings; update this doc + development-history pointer.

## Findings (doc-vs-implementation / upstream candidates)

**Framing.** Every finding below is **brix diverging from official CVMFS**, which
is exactly what the corpus set out to find ("corner cases where nginx-xrootd's
CVMFS components might not behave as expected"). We did **not** prove a single
genuine *upstream* bug (a mismatch between CVMFS *documentation* and the
*official client*) — where a test asserts documented behavior, the official
client honors it and only brix diverges. Each divergence is pinned
`xfail(strict=True)` + `# DIVERGENCE:` so it flips to a hard failure the moment
brix closes the gap. Totals: **24 DIVERGENCE-annotated behaviors, 47 strict
xfail pins**, 1188 tests collected across 16 files.

> **2026-07-17 hardening burndown:** the client-side trust/refresh/failover/cache
> divergences (items 1–5, 7–9, plus D5/D6 below) are **FIXED in source and
> un-pinned** — their tests now assert official behavior positively. See
> "Hardening burndown (client transport & trust)" at the end of this doc for the
> mechanism of each fix. Remaining open: item 6 (server gate log over-read),
> 10–18 (server resilience/HTTP/POSIX surface), and the curl connection-reuse
> divergence (item 11).

### A. Security-critical — trust chain (brix accepts forged / replayed / expired repos)

These let a party *without* the master key serve trusted-looking content, or let
a stale/rolled-back repo mount. Highest priority.

> **STATUS (fixed):** all six gaps below are now **closed in source** and the
> oracle tests flipped from `xfail(strict=True)` to passing REFUSED/exact-log
> assertions. The `fuse_trust` matrix (64 tests) is green with each former
> divergence now producing a stable trust-error code, and the C core unit gained
> a body-tamper-under-valid-signature security-negative. **One residual** is
> tracked separately under §B.7: the persistent *monotonic revision floor* on the
> **refresh** path (rejecting a fully-consistent older revision re-published after
> a healthy mount) is a deeper fix entangled with the pre-verify in-place
> `cl->manifest` mutation, and remains `xfail`
> (`fuse_refresh_failover::test_rollback_rejected_*`). A.5's one-shot form —
> a manifest whose `S` disagrees with the root catalog's `revision` — is closed.
> The one-shot check fires only when the manifest actually carries a revision
> (`m->revision != 0`): a legitimately-signed `S`-less manifest keeps its prior
> tolerated ACCEPT (matching official field-defaulting and
> `fuse_manifest_parse::test_missing_field[S]`), and body-binding already blocks
> an attacker from *stripping* a signed `S` to dodge the check.

1. **Whitelist expiry never enforced** — *FIXED.* `load_trust_and_catalog` now
   passes wall-clock `time(NULL)` (not `mono_now()`/`CLOCK_MONOTONIC`) to
   `cvmfs_whitelist_expired`, so an expired whitelist trips `-6`. Official CVMFS
   refuses. — `fuse_trust::test_tamper_refused[expired_whitelist]` (→ `-6`),
   `fuse_whitelist` expiry_year_2000 / _yesterday / _now_minus_* (refuse).
2. **Substitute-cert forgery accepted** — *FIXED.* `cvmfs_verify_whitelist` now
   binds the whitelist body to the master-signed hash-line
   (`body_bound_to_hash`, `verify.c`), so a keyless fingerprint appended to the
   unsigned body no longer verifies (`-5`). Official CVMFS signs the whole
   whitelist body. — `fuse_trust::test_tamper_refused[substitute_cert]`.
3. **Manifest body not signature-bound** — *FIXED.* `cvmfs_verify_manifest`
   recomputes `sha1(signed body)` and compares it to the signed hash-line, so a
   byte flipped in any KV field (B/S/N/T/D) under a valid signature is refused
   (`-9`). — `fuse_trust::test_tamper_refused[man_field_{B,S,N,T,D}]`.
4. **Whitelist body not signature-bound** — *FIXED.* Same body-binding as A.2/A.3
   in `cvmfs_verify_whitelist`; the `N<repo>` line and fingerprint list are now
   covered by the master signature (`-5`). — `fuse_trust::test_tamper_refused[wl_nline]`.
   (Note: *whitelist* N-line-vs-repo validation — refusing a body-consistent
   whitelist whose `N` names a different fqrn — is now *FIXED* too: `-12` in
   `load_trust_and_catalog` refuses a whitelist whose `N<fqrn>` != the mounted
   repo, closing the replay-across-repos gap. — `fuse_whitelist::nline_*` (green).
   The *manifest* `N` field is deliberately **not** gated against the fqrn:
   stock CVMFS binds repository identity through the whitelist `N` line + cert
   fingerprint, and publishers routinely serve one signed manifest under several
   fqrns, so a manifest-N gate would refuse legitimate mounts. `fuse_manifest_parse`
   asserts manifest-N absence/mismatch is *tolerated* (`test_missing_N_field_tolerated`,
   `test_N_mismatch_tolerated`) — matching official, no divergence retained.)
5. **Revision rollback / replay accepted** — *FIXED (one-shot).* After opening the
   root catalog, `load_trust_and_catalog` cross-checks the catalog's `revision`
   property against the manifest `S`; a mismatch (a downgraded manifest over a
   newer catalog) is refused `-11`. `mkrepo`/`repo_forge` now stamp the catalog
   `revision` property. — `fuse_trust::test_tamper_refused[replay_downgrade]`.
   **Residual:** the cross-refresh monotonic floor (a fully-consistent older
   revision re-published post-mount) stays `xfail` — see the STATUS banner and §B.7.
   *Corpus alignment (2026-07-18):* the `-11` cross-check also governs
   `fuse_manifest_parse`'s numeric-tolerance suite. An extreme manifest `S` that
   parses to a non-zero value mismatching the stamped catalog revision (forge
   default `1`) is refused `-11`; only `S=0` / non-numeric (`atol→0`, gate
   skipped) stay in `test_extreme_numeric_tolerated`. The three mismatching
   extremes (`2^63`, `2^63-1`, `-1`) moved to a dedicated
   `test_extreme_revision_mismatch_refused` documenting the deliberate hardening
   (parser tolerates the value cleanly; the revision gate rejects it) — brix
   EXTRA hardening, not a divergence to remove. This was masked until the harness
   `write_manifest` hash bug was fixed: it had hashed the manifest body
   *including* the trailing `--\n` separator (stock CVMFS + `verify.c` hash the
   body **excluding** it), so every crafted-manifest ACCEPT case was spuriously
   refused `-9` (body-binding). The harness now hashes `text[:-3]`, matching
   `repo_forge._write_manifest`.
6. **Reject-line URI log over-read** — *FIXED.* `cvmfs_reject` and
   `cvmfs_gate_cas` (`gate.c`) now copy at most `uri.len` bytes into a bounded,
   NUL-terminated stack buffer (mirroring `handler.c:359-364`) before
   `brix_sanitize_log_string`, so the logged `uri="…"` field cannot over-read the
   raw request buffer. — `srv_gate::test_reject_line_uri_field_is_exact`.

### B. Correctness / resilience — integrity preserved, availability or state wrong

7. **Refresh commits manifest state before verify / catalog-fetch**
   (`client.c` step 2 vs step 3): `load_trust_and_catalog` parses the fetched
   manifest into `cl->manifest` *before* signature verification, so a rejected or
   tampered refresh still bumps `user.revision`/`user.root_hash` to rev2 while the
   rev1 catalog keeps serving — and a subsequently *repaired* refresh sees
   `old_root(=rev2) == new(=rev2)`, discards the freshly loaded catalog as "same
   revision", and **permanently wedges** the mount on rev1 with rev2 metadata. —
   `fuse_refresh_failover` (4 pins: pre-verify, pre-catalog-fetch, wedge-recovery).
8. **Corrupt cached content entry never re-verified** — `serve_from_cache`
   (`shared/cvmfs/fetch/fetch.c`) trusts on-disk bytes; a damaged entry is served
   (a truncated entry surfaces as an **empty file**) with **zero** refetch.
   Official CVMFS treats a damaged local entry as a cache miss. —
   `fuse_cache::test_corrupt_cached_entry_triggers_refetch` and companions.
9. **Corrupt cached *catalog* entry aborts the mount** (~13s trust-chain backoff
   re-serving the same corrupt entry) instead of refetching the pristine object
   still at the origin. — `fuse_cache::test_corrupt_cached_catalog_entry_remount_recovers`.
10. **EBADMSG verify retries never rotate endpoints** (`fill_retry.c` +
    `sd_http_select`): a verify failure does not raise the endpoint's transport
    `fail_score`, so a corrupt primary + clean secondary yields a 502 with the
    clean copy one endpoint away, unconsulted (observed primary=3 secondary=0). —
    `srv_resilience::test_corrupt_primary_fails_over_to_clean_secondary`.
11. **No origin connection reuse** — `brixcvmfs` opens+destroys a curl easy handle
    per fetch (`http_get_range`), so even without `-o fresh` every request opens a
    fresh TCP connection to a keepalive origin. —
    `fuse_refresh_failover::test_default_mount_reuses_connections`.
    **FIXED (2026-07-18):** persistent `g_curl` easy handle (libcurl's connection
    cache lives on the handle); every per-request option re-set each call so no
    stale resume/freshness state survives reuse, `-o fresh` sets
    `FRESH_CONNECT`/`FORBID_REUSE` unconditionally per request, handle torn down
    at the three `curl_global_cleanup` sites. FUSE loop is single-threaded (`-s`)
    so no locking. Reuse test un-pinned (xfail removed) + fresh-forbids
    security-neg both green.

### C. POSIX / metadata surface

12. **uid/gid squash incomplete** — official CVMFS presents every entry as owned
    by the mounting user (catalog uid/gid ignored); brix squashes only
    `uid==0`/`gid==0` and surfaces nonzero catalog uid/gid verbatim
    (`brixcvmfs.c:212`). — `fuse_catalog::test_official_{uid,gid}_squash_all_entries`.
13. **readdir does not descend nested catalogs** — `brixcvmfs_op_readdir` queries
    only the root catalog, so a nested mountpoint lists empty even though
    stat/read of its children work via `resolve` descent (`brixcvmfs.c:232`). —
    `fuse_catalog::test_readdir_nested_mountpoint_lists_children` (+ one level down).
14. **Non-implemented mutations return the wrong errno** — brix implements only
    open/mkdir/unlink/write refusals; other mutating ops surface kernel
    ENOSYS/EPERM/ENOTSUP instead of the documented EROFS. —
    `fuse_posix::test_mutation_official_erofs`.

### D. HTTP protocol surface (server / Stratum-1 interop)

15. **416 omits `Content-Range: bytes */len`** (RFC 9110 §15.5.17;
    `serve_range_unsatisfiable`, `src/protocols/shared/file_serve.c`). —
    `srv_http::test_416_carries_content_range_star`.
16. **304 omits ETag / validators** (RFC 9110 §15.4.5;
    `handler.c cvmfs_tier_open_respond`). — `srv_http::test_304_carries_etag`.
17. **Malformed `bytes=` specifier → 416** where Apache/official Stratum-1
    ignores → 200 (RFC-tolerable per §14.2, but an interop divergence). —
    `srv_http::test_malformed_bytes_spec_ignored_200`.
18. **CAS hex-length gate over-permissive** — accepts the whole 40..128 range and
    tier-404s, rather than restricting to the published shape set
    {40 sha1/rmd160, 64 sha256, 96 sha384, 128 sha512} with a 403
    (`classify.c:33`). — `srv_gate::test_cas_hex_length_nondigest_rejected`.

## Wave-4 burndown notes

- **Collection:** 1188 tests across the 16 corpus files (+ smoke), all collect
  clean (`pytest tests/test_cvmfs_conformance_*.py --collect-only`). The
  `conformance` substring auto-tags every file `slow` (nightly), out of the
  <5min PR gate as designed.
- **Green under normal load; flaky only under host saturation.** Every corpus
  test passes in isolation in ~1s. Full-file `fuse_cache` runs are green at load
  <~2; at load 6–21 (driven by *other* concurrent sessions on this box) a
  *random* 1–3 tests fail, always at **brixMount bring-up** and never the same
  test twice. Root cause is proven, not assumed: `coredumpctl` shows **no
  brixMount crash**; the failing tests each pass solo even at load 21; brixMount
  exits cleanly because the *in-process Python origin* (`ThreadingHTTPServer`,
  sharing the starved pytest process) cannot answer its bring-up fetch in time.
- **Bring-up hardening applied** (`fuse_cache` mount helpers; ceilings, free on
  healthy runs): `_wait_mounted_or_dead` (proc-aware, detects a dead brixMount in
  ~0.1s instead of burning the full ceiling); respawn **only** on early-exit
  (never thrash a live-but-slow process); escalating backoff between respawns so
  they span a load spike; `bringup_retries` default 3→4; widened per-test
  timeouts. Negative/xfail mounts that *expect* failure keep `bringup_retries=1`.
- **One genuine test-bug fixed during burndown** (not a brix divergence):
  `test_quota_fill_past_watermark_reaps_to_75pct` over-specified the reap floor.
  The synchronous quota reap fires when a fill would cross the *hard* quota,
  evicting LRU to the 75% low-watermark; whether the cache rests at the watermark
  or one object above it depends on whether the *final* fill crossed the quota
  (600K+300K=900K < 1M ⇒ no reap on the last fill ⇒ legitimately rests at 3
  objects, still under quota). Assertion loosened to the real invariant: bounded
  under the hard quota, within one object of the 75% target, and demonstrably
  reaped (< full 2.4MB).
- **No orphan mounts / no port leakage:** every full-file run ends with
  `mount | grep brixcvmfs` clean (always-unmount teardown in the mount
  contextmanagers); `mock_stratum1` reaped between runs. Port blocks per the
  table above; no cross-file collisions observed under serial or `-n` runs.

## Hardening burndown (client transport & trust) — 2026-07-17

Goal: harden the FUSE driver against bad networking, DPI middleboxes, timeouts,
data corruption and reordering. All fixes are in the shared pure-C core (so the
nginx module inherits them) or the FUSE binding; every retired divergence's
strict-xfail pin was flipped to a positive assertion in the same change.

**Trust chain (items 1–5, landed just before this burndown, pins realigned):**
wall-clock whitelist expiry (`client.c` passes `time(NULL)`); signature
body-binding for manifest AND whitelist (`verify.c body_bound_to_hash` — the
signed hash-line must be the digest of the body; per stock CVMFS the digest
covers the body up to but EXCLUDING the `--\n` separator, and the test forges
in `tests/cvmfs/repo_forge.py` + the whitelist suite's `_compose` follow the
same convention),
which closes the substitute-cert forgery, unsigned-KV edits, and N-line edits;
manifest-revision vs root-catalog-revision cross-check (`client.c`, code -11).
Stable refusal taxonomy pinned in `fuse_trust::_STABLE_CODES`. **Corpus impact:**
the `fuse_whitelist` forge previously emitted a free-form hash-line (mimicking
the old gap) — `_compose` now emits a real `sha1(body)` hash-line by default,
as official publishers do; boundary expiry cases were re-margined since expiry
is now actually enforced. Likewise `fuse_refresh_failover::publish_revision`
now stamps `forge.properties["revision"]` alongside the manifest `S` — an
incoherent test publisher (catalog says rev 1, manifest says rev 2) is exactly
what the -11 cross-check refuses, which surfaced as "refresh never lands" in
the TTL/recovery scenarios until the forge was made coherent. A third forge
casualty of the same enforcement: `RepoForge.rewrite_manifest`/`rewrite_whitelist`
used to default the hash-line to the PREVIOUS body's digest (`hash_text or
self.manifest_hash`) — harmless while hash-lines were unverified, but once
body-binding landed any rewrite that changed a field self-tampered and drew -9
before the code under test could fire (seen as `fuse_trust::replay_downgrade`
returning -9 instead of -11). Both rewrites now default to an honest recompute;
forging a stale/bogus hash-line requires an explicit `hash_text=`.

**Suite-running gotcha (timeouts masquerade as refusals):** `fuse_manifest_parse`
accept-cases retry `--check` on `TimeoutExpired`, but if every attempt times out
the helper returns its initial `rc = REFUSE` — so a saturated box (load ≳30 from
concurrent sessions/suites) can present as 30+ deterministic-looking "refusals"
that all pass solo. Verify one case solo before touching source, and don't run
the 24-thread whitelist pool concurrently with this suite.

**Refresh atomicity + wedge (item 7):** `load_trust_and_catalog` now stages the
fetched manifest in a scratch buffer (`cl->manifest_stage`) and installs NOTHING
until the full chain (signature → whitelist → cert fingerprint → catalog fetch +
revision cross-check) verifies; `commit_manifest()` is the single install point.
A tampered/failed refresh leaves `user.revision`/`user.root_hash` untouched and
recovery is no longer discarded as "same revision" — the permanent wedge is gone.

**Rollback protection (item 5, refresh path):** `cvmfs_client_refresh` refuses a
staged manifest whose revision is below the installed one — a properly-signed
replay/downgrade is ignored and the current revision keeps serving.

**Cache re-verification (items 8–9):** the CAS cache stores verified PLAINTEXT,
whose bytes do not hash to the object name for compressed objects — so
`fetch.c` now writes an integrity sidecar (`<key>.chk`: plaintext hash +
length) at store time and `serve_from_cache` re-verifies every hit against it.
Damaged, truncated, or unverifiable entries (including pre-sidecar caches,
which self-heal once) are purged (`brix_cas_del`, new) and transparently
refetched — corrupt content AND corrupt cached catalogs recover instead of
serving bad bytes / aborting the mount.

**D5 — replica failover dead under DIRECT (`failover.c`):**
`cvmfs_failover_record` no longer blacklists the synthesized DIRECT
pseudo-proxy on failure; a host failure marks only that host, so `select()`
hands back the next replica instead of reporting offline. Dead-primary mounts
and mid-session replica failover now work (6 pins flipped).

**D6 — Range-blind origins (`brixcvmfs.c` transport):** libcurl aborts a resume
answered 200 with `CURLE_RANGE_ERROR` before any body bytes, so the old
200-slide was dead code and transfers stalled. The transport now treats
`CURLE_RANGE_ERROR` as "origin is Range-blind": discards the partial prefix and
restarts the object from byte 0 (hash verification keeps it safe; a persistent
mid-body sever still ends in a clean EIO, never bad bytes).

Item 11 (origin connection reuse) landed 2026-07-18 — persistent curl easy
handle in `brixcvmfs.c`, reuse test un-pinned; full refresh_failover suite 87/87.

**Redirect / scheme confinement (`brixcvmfs.c` transport, 2026-07-19):**
`CURLOPT_FOLLOWLOCATION` was on with no protocol restriction and no redirect
cap, so a poisoned mirror or a DPI middlebox could answer any CAS fetch with a
3xx to `file:///etc/passwd`, an internal metadata IP (169.254.169.254), `scp://`,
`gopher://`, … and libcurl would chase it. Content is CAS-hash-verified so a
*wrong body* is caught, but that is no defence against the redirect's SSRF /
local-file-read **side effect** (libcurl actually opening the resource). Now
confined: `CURLOPT_PROTOCOLS` + `CURLOPT_REDIR_PROTOCOLS` = `HTTP|HTTPS`
(bitmask form for alma8-era libcurl portability), `CURLOPT_MAXREDIRS=4` so a
redirect loop can't wedge the mount, and `SSL_VERIFYPEER=1`/`VERIFYHOST=2` made
explicit so `-o tls` fails closed against an intercepting proxy. Tests
(`fuse_refresh_failover::TestRedirectConfinement`, new `redirect:`/
`redirect_host:` fault modes in `LocalOrigin`): file:// redirect to a
**valid-content** bait file is still refused (proves the scheme block, not the
hash backstop); a self-referential redirect loop fails with EIO in <30s (not a
hang); a legitimate cross-host http→http mirror redirect is still followed to a
byte-exact success. Suite 91/91.

**Build gotcha (mixed-epoch shared objects → phantom -5 refusals):** `client/`'s
`make clean` does not remove `../shared/cvmfs/**/*.o`, and after the
`cvmfs_whitelist_t`/manifest struct growth (body-binding `signed_hash`, whitelist
`repo_name`) an incremental `make brixMount` linked a `manifest.o` from an older
header epoch against fresh `verify.o`/`client.o`. Result: garbage
`signed_hash`/`signed_body` offsets → every mount refused with -5 (whitelist
verify) even though every suite that compiles per-fixture binaries stayed green.
If brixMount starts refusing pristine forges after a struct change, `rm -f
shared/cvmfs/*/*.{o,d}` and relink before suspecting the crypto.

**Trust-suite standalone-compile fix (2026-07-19):** the phase-86 `brix_cpool`
pooling migration made `brixcvmfs.c` `#include "net/cpool.h"`, which silently broke
the trust suite's from-source `--check` binary — all 64 `test_cvmfs_conformance_fuse_trust`
cases began SKIPPING with "cannot build brixcvmfs --check binary". A trust/tamper
security suite that mis-runs as a no-op is a hole in itself, so it was repaired rather
than left skipping: `_build_brixcvmfs` now adds `-I client/lib -I src`, compiles
`brixcvmfs_rw.c` + `shared/cvmfs/walk/walk.c`, and links `client/libbrix.a` +
`shared/xrdproto/libxrdproto.a` plus the full transitive lib set, with an
archive-existence guard and captured `_BUILD_ERR` so a genuine link failure surfaces in
the skip reason instead of hiding behind a generic "unsupported". Restored to 64/64
(confirmed on a clean serial rerun, 160s); the occasional lone `clean` -9 under the
12-worker pool is the free_port TOCTOU load-flake, not a verify failure.
