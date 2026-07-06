# Lessons Learned — The BriX Rebrand & Test-Suite Stabilization (July 2026)

**Status:** Complete — namespace rebrand landed (`v1.0.8`), full PR test gate green (`run_suite.sh --pr` PASS), 28 commits `5fabb4d..6e8bca0`.
**Scope:** whole-tree symbol rebrand (`xrootd_`→`brix_`), the pre-existing bug cluster it surfaced when the suite was run end-to-end, a storage-format migration's test-drift, one build-system heap-corruption trap, and a concurrent kTLS/CSI enhancement committed alongside.
**Related:** [lessons-migration-era-2026.md](lessons-migration-era-2026.md) · [coding-standards.md](coding-standards.md) · plan: [docs/refactor/2026-07-03-brix-symbol-rebrand.md](../refactor/2026-07-03-brix-symbol-rebrand.md) · [brix-rename-migration.md](../refactor/brix-rename-migration.md)

---

## 0. What happened, in one paragraph

The project's public identity was rebranded from *XRootD-flavored* symbols to **BriX**: every internal symbol/namespace `xrootd_`→`brix_`, `XROOTD_`→`BRIX_`, `ngx_xrootd*`→`ngx_brix*`, the client library `libxrdc`→`libbrix` and its `xrdc_`→`brix_` symbols, dashboard routes `/xrootd`→`/brix`, log-line prefixes, env vars, and log filenames — while **deliberately keeping** everything that names the upstream project, protocol, or wire constants (`root://`, `kXR_*`, `XrdCl`/`XrdHttp`, the `xrdcp`/`xrdfs`/`xrootdfs` tool binaries, the `nginx-xrootd` module identity, and the `.ngx-xrootd-*` on-disk sentinels). The rename itself was mechanical and clean. The *value* of the exercise was everything that fell out afterward: running the full test suite end-to-end surfaced **~50 genuine pre-existing bugs** (not rebrand fallout), almost all concentrated in one place — the storage-driver (`brix_storage_backend`) code path, a second implementation of the POSIX path that had never been exercised with buffered/bound/integrity/checkpoint reads. A separate storage-format migration (the cache/integrity record moving from a `.cinfo` sidecar to a `user.xrd.cinfo` xattr) had silently broken every test that still read the old carrier. And one struct-size change hidden behind a cross-directory header produced a spectacular mixed-ABI heap corruption that the build system reported as a clean `build=0`.

The rebrand was the easy part. **This document is about the long tail.**

---

## 1. The rebrand mechanics — what worked

The approach mirrored the "map-driven, idempotent, sequenced" playbook from the [migration era](lessons-migration-era-2026.md), applied to a symbol rename instead of a file move.

- **A rename engine, not hand edits.** `tools/refactor/brix_rebrand.py` (gitignored, local-only) drove anchored, case-sensitive regex rules (S1–S5 server scope, C1–C5 client scope) with `--scope`, `--dry-run`, `--emit-map`. Rules were **confluent and idempotent** — re-running produced no change, so a partial run could always be re-driven.
- **A verifier, not trust.** `tools/refactor/brix_verify.sh` did a residual-token scan **and** a KEEP-token invariance check — proving both that no `xrootd_` symbol survived *and* that every intentionally-kept token (`root://`, `kXR_*`, tool names, module identity) was untouched. "Zero residual" and "KEEP-set invariant" are two separate assertions; both must pass.
- **Blame preservation.** Each mechanical rename SHA was recorded in `.git-blame-ignore-revs` so `git blame` still points at the real author of each line, not the rename.
- **A hyper-detailed plan up front** (`docs/refactor/2026-07-03-brix-symbol-rebrand.md`, 992 lines) with the exact rule set, the KEEP list, and a per-subtree checklist.

> **Meta-lesson (reconfirmed):** for a mechanical change, the deliverable is *the tool + the verifier + the plan*, not the diff. The diff is a byproduct you can regenerate.

---

## 2. The rebrand's long tail — the plan's scope list was incomplete

Every one of these was a place the rename *should* have reached but the plan's scope enumeration missed. They are catalogued because the failure mode is generic: **a namespace rename touches more surfaces than any human enumerates up front.**

| Missed surface | Symptom | Fix |
|---|---|---|
| `shared/xrdproto/` tree | Makefile passed `-DXROOTD_HAVE_ZLIB` while renamed source checked `BRIX_HAVE_ZLIB` → **all client codecs silently stubbed** ("cannot decode codec N") | Rename `shared/` too; `rm -rf shared/xrdproto/build` (`make clean` does **not** remove `build/*.o`) |
| Header files themselves | `#include` paths rewritten to `ngx_brix_module.h` but the file was still `ngx_xrootd_module.h` → "No rule to make target" | Fold `git mv` of the headers **into** the symbol-rename commit (rewriting includes and renaming files must be atomic) |
| `-lxrdc` linker flag | `\bxrdc\b` word-boundary regex does **not** match `-lxrdc` (the `l` before `x` blocks the boundary) | Explicit `-lxrdc`→`-lbrix` substitution |
| Prefix-length constants | `config_download.c` hard-coded `len >= 7` (length of `"xrootd_"`) for a prefix check; after rename the prefix is `"brix_"` (length 5) | Change the literal `7`→`5`. **The only such magic-length bug in the tree** — caught by a canary test |
| Dashboard routes in *client tools* | Server + tests + docs got `/xrootd`→`/brix`, but `xrdstorascan`/`diag_topology` still `POST /xrootd/login` → 404 "dashboard login failed" | Slash-anchored route sed applied to client tools too |
| Test module that imports a renamed peer | `from test_libxrdc import` rewritten to `test_libbrix` but the file was left as `test_libxrdc.py` → 3 collection ERRORs | `git mv tests/test_libxrdc.py tests/test_libbrix.py` |
| Missed subdirectories | `client/tests`, `client/man` not in the default build target, so the rename pass skipped them | Explicit pass over the missed dirs |
| Tracked build artifacts | `make clean` removed `client/libbrix.so.{0,0.1.0}` before `git add -u` staged the deletion → tracked artifact dropped from git | `make -C client lib` + `git add -f` |

**The generic lesson:** after a rename, the residual/invariance scan must run over **every** tree the build or tests touch — including generated Makefile defines, linker flags, tracked binaries, sibling test imports, and any embedded route/path string — not just `src/`. A rename is "done" when the verifier is green over the *union* of build inputs and test inputs, not when `src/` compiles.

### 2a. The subtler rename trap: over-application to KEEP-named references

The rename correctly kept `test_xrootd_performance_conformance.py`'s filename (it tests XRootD *protocol* conformance — a KEEP token), but it rewrote the **import string** inside that file to a non-existent `_test_brix_performance_conformance_helpers` → `ModuleNotFoundError` on collection (`1df4270`). The rule matched a substring of a token it should have left whole.

> **Lesson:** a KEEP list must protect not just the *definition* of a kept name but every *reference* to it — including import strings, `#include` paths, and doc mentions. When a file's name is kept but a rule renames the symbols that reference it, you get a dangling reference that only surfaces at import/link time, not at compile time.

---

## 3. The bug cluster the suite surfaced — the storage-driver path was a second, under-tested implementation

This is the headline finding. The VFS storage plane routes `proto → VFS → SD driver` (`src/fs/backend/`). There are effectively **two open/read/write code paths**: the direct POSIX path (plain `brix_export` export) and the **driver path** (`brix_storage_backend posix:…`, `brix_open_resolved_via_driver`). The direct path was battle-tested; the driver path had been exercised for *basic* reads (which survive via `sendfile` reading the fd directly) but **not** for buffered reads, bound reads, integrity-checked reads, clones, or checkpoints. Every one of those was broken, and each looked like a different unrelated failure.

All were proven **pre-existing** (not rebrand-caused) by rebuilding the pre-rename commit `37b97c4` in a git worktree and reproducing identically.

| # | Bug | Root cause | Surfaced as | Commit |
|---|---|---|---|---|
| 1 | Driver `kXR_open` → `cached_size = 0` | `brix_open_resolved_via_driver` synthesized `struct stat` from the driver's open snapshot, but `sd_posix_open` **deliberately skips `fstat` at open**, so `snap.size == 0` for every driver open. Plain reads survived (sendfile reads the fd), but the **buffered path** (inline read compression `brix_read_compress`, any non-sendfile serve) saw `offset >= file_size == 0` → EOF → 0 bytes | ~30 compression tests ("short read: got 0 of N"), io_edge_cases | `b1da138` |
| 2 | Driver open publishes `st_dev = 0` | The synthesized `struct stat` left `st_dev == 0`; the published-handle table recorded device 0. A **bound** secondary read reopens the file (real `fstat`, real `st_dev`) and revalidates device+inode against the published entry — a `0` vs real-device mismatch **revoked every bound read** with `kXR_error` (4003) | test_session_bind (4), part of the "4003 read cluster" | `e5e18ef` |
| 3 | `kXR_clone` → integrity EIO | Clone copies bytes with `copy_file_range`/`pread`-`pwrite`, **bypassing the write path's per-block CRC32c fold**. A csi-tracked destination kept its pre-clone block CRCs; a later read of the (now different) data failed verification with `kXR_IOError` | test_new_opcodes clone | `de4d73a` |
| 4 | Read-after-write on any integrity file → EIO | `brix_csi_verify_read` verified read data against the **on-disk** block CRC, which is only recomputed at flush/close. So a read of a block written earlier in the same session (`kXR_write`/`kXR_clone`/ckpXeq write, then a read on the same handle) verified *new* bytes against the *pre-write* CRC → EIO. Fix: skip verification for blocks overlapping the handle's written extent (`dirty_lo..dirty_hi`) — there is no disk-corruption risk in bytes you just wrote | clone-in-full-run, chkpoint begin/commit read-after, ckpXeq write read-back | `c925d43` |
| 5 | ckpXeq write/pgwrite read-back → EIO | The checkpoint write sub-ops (`ckp_xeq_write`/`ckp_xeq_pgwrite`) drain straight through `brix_vfs_io_execute`, bypassing `brix_csi_write_update`, so the written extent was never marked dirty and the read-back verified against the stale on-disk CRC (bug #4's mechanism, via a different write path). Fix: fold the written bytes into the handle's csi engine after each ckpXeq write | test_new_opcodes_b TestChkpointXeq (4) | `5538266` |
| 6 | Driver path serves special files (FIFO/socket/device) | The non-driver path opens `O_NONBLOCK` then refuses any non-regular file (anti-wedge); the driver path had **no such gate**. A FIFO read-open returned success instead of an error (a subsequent read would spin on `EAGAIN` and wedge the single worker) | test_deep_tree_special_files `[fifo0]` | `ec2fc6b` |

> **Lesson (the important one):** when a subsystem has a pluggable/decorator seam (here the SD driver), **the seam creates a second copy of every code path**, and the new copy inherits none of the hard-won edge-case handling of the original. Anti-wedge gates, metadata synthesis, integrity folding, and identity publication all had to be *re-established* on the driver path. Audit a new seam against the *specific defensive behaviors* of the path it parallels — not just its happy path. The tell that you have this problem: "basic reads work, but every advanced feature is broken on backend X."

> **Corollary — `sendfile` hides missing metadata.** Bug #1 was invisible for the plain read path precisely because `sendfile` reads the fd directly and never consults `cached_size`. Any code path that trusts a *cached* value (compression, buffered serve, bound-read revalidation) is where a missing/zeroed metadata field first bites. When adding a fast path that bypasses cached state, you are also removing your own test coverage of that state.

---

## 4. Storage-format migration test-drift — the record changed carriers, the tests didn't follow

Independent of the rebrand, the unified-metadata (xmeta) work had moved the cache/integrity record from a **`.cinfo` sidecar file** to an **xattr-preferred** carrier: on an xattr-capable filesystem the record now rides the object's `user.xrd.cinfo` xattr with *no sidecar*, falling back to a sidecar only where xattrs are unsupported. The server was correct. Every test/helper that still read the **sidecar** silently saw "absent."

| Site | Symptom | Fix |
|---|---|---|
| `brix_cache_meta_read` (server) | Only consulted the xmeta record; a pre-migration `.meta` sidecar (whose on-disk layout **is** the `brix_cache_meta_t` legacy 72-byte base) was treated as a miss → origin served instead of cache | Added a legacy `.meta` reader used when no unified record exists — *also* real migration compat for pre-existing caches (`5295f1b`) |
| `test_cache_reap_metrics` | Asserted `os.path.exists(f + ".cinfo")`; on an xattr fs the record rides the xattr (removed with the file), no sidecar | Made record-presence checks xattr-or-sidecar aware (`5295f1b`) |
| `residency()` helper (16 tests) | Ran `xrdcinfo` on the `.cinfo` **sidecar** only → `{"absent":true}` → every `residency(...)["complete"]` raised `KeyError` | Fall back to `xrdcinfo --xattr <object>` when the sidecar is absent (`a89fbe0`) |

**Diagnosis detail that mattered:** the "16 failing tests in one file with `KeyError`" looked catastrophic but was one root cause. Instrumenting the helper to dump the store on "absent" showed `listing=['ok.bin']` (no sidecar), `data_exists=True`, and `xattr_out={…,"complete":true,…}` — i.e. **the record was written correctly, to the other carrier.** That single observation reclassified 16 "failures" as one line of test-drift.

> **Lesson:** a storage-format/carrier migration is a **fan-out break**. Every reader of the old carrier — server fallback paths, test helpers, ops tools — breaks at once, and the failures look unrelated (a `KeyError` here, an "origin served" there, a missing-sidecar assertion elsewhere). Before shipping a carrier migration, grep for *every* reader of the old carrier (sidecar path suffix, xattr name, magic bytes) and either add a compat fallback in the reader or migrate the reader. A passing writer proves nothing about the readers.

> **Corollary:** keep a backward-compat *reader* for at least one release after moving a persisted format. The `.meta` legacy fallback (`5295f1b`) both fixed a test and gave real operators with pre-migration caches a working upgrade — the same code served both needs.

---

## 5. The build system lied — a struct-size change behind a cross-dir header → mixed-ABI heap corruption

**The most dangerous problem of the whole exercise**, because the compiler reported success.

A concurrent enhancement (§7) added a pointer field to `brix_csi_t` in `src/fs/backend/csi_tagstore.h` (and pulled in `fs/meta/xmeta.h`), changing `sizeof(brix_csi_t)`. An **incremental** `make` recompiled `csi_tagstore.o` (which now `memset`s the *larger* struct in `brix_csi_open`) but **did not** recompile `open_resolved_file.o`, `read.o`, or `fd_table.o` — the files that `ngx_alloc(sizeof(brix_csi_t))` the struct — because nginx's addon build does **not** track cross-directory `-I` header dependencies. Result: those callers allocated the **old, smaller** struct while `brix_csi_open` wrote the **new, larger** one → a write past the allocation corrupted the adjacent heap chunk header.

Runtime signature:
- `worker process … exited on signal 6` (SIGABRT) — **402 times** across the fleet.
- glibc's `malloc(): invalid size (unsorted)` on the worker's *next* `malloc` (heap-metadata corruption, detected later than the actual overflow).
- Because it is a per-worker heap poison, a corruption caused by a **read** connection aborted an unrelated **write** connection's worker mid-handshake ("connection closed by peer (read 0/8)"), making the failures look random and global.

Diagnosis path that worked (and the dead ends):
1. The csi unit test passed clean under ASan (29/29) — **ruling out a logic bug** and pointing at integration/concurrency.
2. `getfattr`/logic inspection of the refactor found no overflow in the changed C — correct, because the overflow was at an *unchanged* `ngx_alloc` call site compiled against the old header.
3. The tell was the object timestamps: `csi_tagstore.h` newer than `open_resolved_file.o`/`read.o`/`fd_table.o`. `STALE: obj older than header` → mixed ABI.
4. Fix: **`rm -rf objs && ./configure && make`** — zero code change. Crash gone, byte-exact reads, 0 SIGABRTs, full suite green.

> **Hard rule (add to muscle memory):** **any change to a struct laid out in a header requires a full clean rebuild** (`rm -rf objs && ./configure && make`), never an incremental `make`. The nginx addon build tracks same-dir header deps only; a `src`-rooted cross-directory include that changes a type is invisible to it. This is the same class as the migration-era "`./configure` over old objs ⇒ mixed-ABI garbage" gotcha — it recurs whenever a shared type grows.

> **Detection tooling for next time:** a struct-size change is detectable pre-run by comparing header mtimes against the mtimes of every `.o` whose `.c` includes it. When in doubt after touching a header that defines a `typedef struct`, clean-build. The cost of a full rebuild is minutes; the cost of shipping a mixed-ABI binary is a day of chasing phantom "random crashes."

---

## 6. Diagnosis methodology — the traps that cost the most time

These are process lessons, each earned by going down the wrong road first.

### 6a. "The server sends success but the test fails" → the failing assert is a *later* operation

For days the ckpXeq-pgwrite failure looked like the pgwrite returning `4003`. Server-side instrumentation proved the pgwrite *succeeds* (decode OK, write OK, sends `kXR_status` 4007). A byte-identical raw-socket repro *passed*. The truth only appeared when the **client** socket was dumped: the `4007` was correct; the `4003` came from the **next** operation — a `_read` after the pgwrite, failing the csi read-after-write bug (§3 #5).

> **Lesson:** when server debug shows a success response but the test still fails, **stop instrumenting the operation you suspect and dump the client's received bytes.** The failing assertion is often a *subsequent* op. Instrument the transport, not the handler.

### 6b. A byte-identical repro that passes while the test fails → it's state/environment, not logic

Multiple failures produced a maddening pattern: a hand-written raw-socket repro of the *exact* wire bytes passed, but the pytest test failed. Every time, the difference was **accumulated state**, not code:
- A stale `<file>.ckp` snapshot left by a prior killed run made `ckpBegin`'s `O_EXCL` create fail `EEXIST` on the *next* run (the server does not reclaim orphaned checkpoint snapshots).
- Orphaned nginx masters / fleet pollution from earlier killed runs.

> **Lesson:** if a faithful repro passes but the harness fails, suspect **persisted state between runs** (lock/snapshot files, xattrs, orphaned processes) before suspecting logic. Clean the state, re-run the repro *and* the test from the same baseline, and compare.

### 6c. Never rewrite a file with a "read → transform → write" one-liner

While instrumenting, a Python one-liner intended to edit `test_new_opcodes_b.py` in place instead wrote the *embedded 20-line snippet* as the entire file, truncating 992 lines to 19. Recovery required `git checkout HEAD -- <file>` (the only recovery for deleted lines; the sole uncommitted change was the throwaway debug print, so nothing of value was lost).

> **Lesson:** to add temporary debug to a file, use a **surgical in-place edit** (the Edit tool / a matched-anchor replace), never `open(f,"w").write(transform(open(f).read()))` where a bug can substitute the whole file. And remove debug via an equally surgical edit. (The one legitimate git-restore here was of a file whose *only* uncommitted delta was disposable — that is the narrow exception to "never git-restore over uncommitted work.")

---

## 7. Concurrency & multi-session hygiene (the kTLS/CSI enhancement)

Partway through, a **concurrent session** on the same working tree produced two enhancements (later examined, verified, and committed as `6e8bca0`):
- **kTLS unification** — `SSL_OP_ENABLE_KTLS` default-ON across root://, WebDAV, S3 behind one `brix_ktls on|off` knob (offload-gated no-op); new header-only `src/core/http/ktls.h` helper.
- **CSI read-record snapshot** — read handles cache the at-rest xmeta record once at open (§5's struct-size change), eliminating per-read getxattr+parse+malloc on the multi-threaded read hot path.

Handling it surfaced its own lessons:
- **Don't commit or revert another session's uncommitted work without authorization.** The changes appeared as unexplained modified files; they were flagged and left untouched until the owner explicitly directed a commit. Reverting would have destroyed in-flight work (and is a project hard-block); committing blind would have shipped unverified code.
- **An untracked dependency of a committed file breaks the checkout.** `ktls.h` was **untracked** (`??`), while the *committed* `postconfig.c` `#include`d it. Committing the `.c` without `git add`-ing the new header would leave a tree that fails to build on fresh checkout. Always check that every `#include` a commit introduces resolves to a *tracked* file.
- **Verify before committing code you did not write.** Before the commit: clean full rebuild (`build=0`), the refactor's own unit test (29/29), and the full `--pr` gate green — then a hyper-detailed, sectioned message documenting each file. The §5 struct-size build note was recorded *in the commit message* so the next builder does not repeat the mixed-ABI trap.

---

## 8. Test-harness & box hygiene

- **A flake-rerun lane is not optional on a loaded box.** `run_suite.sh`'s "re-run the failures serially" step reclassified, across runs, *different* sets of load-induced flakes (gsi_tls cross-check, lifecycle boot timing, ha_failover handle-leak, zip s3 member, xrdhttp digest-range) as green. Real failures persist across the serial rerun; flakes do not. Judge a run by what survives the rerun, never by the first parallel pass.
- **Orphaned fleets and stale state poison subsequent runs.** Killed suite runs leave nginx masters, `pytest-of-rcurrie` dedicated servers, and `.ckp`/`.cinfo` state; the next run inherits the pollution and produces phantom failures. Between heavy runs: `manage_test_servers.sh stop-all` + `brutal_teardown.sh` + `pkill -x nginx`, and clean stray `*.ckp`.
- **The box itself degrades under repeated heavy runs.** Load climbing to 13–20 with 100+ orphan masters made even `-n12` xdist workers crash and tests hang (exit 124). Diagnosis is unreliable on a degraded box; let it settle (or reset it) before instrumenting a subtle failure.
- **Use the right Python.** The runner uses miniconda 3.13 (`python -m pytest`); a stray 3.9 `pytest` on `PATH` produces false `dict | None` collection errors. Focused repros must use the same interpreter as the runner.

---

## 9. Consolidated checklist for a future namespace rename or format migration

**Before:**
- [ ] Write the rule set + KEEP list + per-subtree plan as a document. Build the rename **engine** and the **residual+invariance verifier** first.
- [ ] Enumerate *all* build inputs and test inputs, not just `src/`: generated Makefile `-D` defines, linker flags, tracked binaries, sibling test imports, embedded route/path strings, `shared/`, `client/tests`, `client/man`.

**During:**
- [ ] Run the engine; re-run to prove idempotence. Fold header *file* renames into the same commit that rewrites their includes.
- [ ] For a **format/carrier** migration: grep for every *reader* of the old carrier (sidecar suffix, xattr name, magic base layout) and add a compat fallback or migrate it. A passing writer proves nothing.

**After (verification — this is where the value is):**
- [ ] Run the **entire** suite end-to-end, not a representative subset. The bugs hide in the paths a targeted run skips (buffered/bound/integrity/checkpoint reads on backend seams).
- [ ] Prove each failure **pre-existing vs regression** by rebuilding the pre-change commit in a worktree and reproducing — do not judge by absolute pass count.
- [ ] After **any** change to a header-defined struct: `rm -rf objs && ./configure && make`. Never incremental. Check `.o` mtimes vs the header if unsure.
- [ ] Judge the run by what survives the serial flake-rerun; reset the box between heavy runs.
- [ ] Confirm every new `#include` in a commit resolves to a **tracked** file; record any struct-size / full-rebuild requirement in the commit message.

---

## 10. Open items carried forward

- **The SD driver path still parallels the POSIX path.** Six defensive behaviors were re-established on it (§3); treat the driver seam as a standing audit target — the next advanced feature added to the POSIX path must be checked against the driver path in the same PR.
- **`ckpBegin` does not reclaim an orphaned `.ckp` snapshot.** A crashed client leaves a checkpoint snapshot that makes the next `ckpBegin` fail `O_EXCL`/`EEXIST` on the same file until the file is cleaned. A dead-owner reclaim (mirroring the O_EXCL cache-lock reclaim) is warranted.
- **Software kTLS default-ON is a no-op-when-uncapable, but on AES-NI CPUs without an offload NIC it can be slower** than userspace OpenSSL — operators there should `brix_ktls off`. Documented in the directive help; watch for real-world guidance needs.
- **The rename engine + verifier are gitignored/local-only.** If another rebrand is ever needed, they must be reconstructed from the plan doc — consider promoting them into `tools/refactor/` if a second rename becomes likely.

---

*Compiled 2026-07-04. Commit range `5fabb4d..6e8bca0` (28 commits): rebrand `5fabb4d..4936bd0`, pre-existing bug fixes `b1da138..ec2fc6b`, kTLS/CSI enhancement `6e8bca0`.*
