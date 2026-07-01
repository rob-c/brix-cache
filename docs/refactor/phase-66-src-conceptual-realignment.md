# Phase 66 — `src/` conceptual re-alignment: concept-bucketed directory topology

**Status: DRAFT (design only) — 2026-07-01. Depends on Phase-64 landing first.
No code touched. This is a topology plan: every file keeps its content, name, and
logic; only paths move.**

> **One-line intent.** Collapse the 48 flat top-level directories under `src/`
> (973 `.c`/`.h` files) into six concept buckets — `core/ protocols/ fs/ auth/
> net/ observability/` — so a newcomer can locate any subsystem from its concept
> alone, lowering the barrier to entry the same way the phase-62 VFS seam lowered
> the barrier to reasoning about storage.

---

## 0. Decisions locked (2026-07-01)

| Decision | Choice |
|---|---|
| Bucketing depth | **6 buckets** — `core/ protocols/ fs/ auth/ net/ observability/` |
| `protocols/root/` scope | **Everything root-specific** — including `session/`, `handshake/`, `protocol/`, `connection/` machinery that only root:// uses |
| Split-dirs (`path/`, `mirror/`) | **Split by concept** — file-granularity, not whole-dir |
| Persistence | This doc (phase-66); no `src/` change until executed |

---

## 1. Goal & hard constraint

Pure directory-topology change. **Content-identical, path-only.** No logic edit,
no rename of a file's basename, no behavioural change. The deliverable of the
*execution* phase is a tree where every `.c`/`.h` is byte-identical to today except
its `#include` lines, and a `./config` regenerated to match.

Non-goals: no dead-code removal, no helper consolidation, no API change. Those are
separate phases — mixing them here makes the move unreviewable.

---

## 2. Current-state facts (measured 2026-07-01 — these drive the effort estimate)

| Fact | Value | Consequence |
|---|---|---|
| Top-level dirs under `src/` | 48 | The thing being reduced |
| `.c`/`.h` files | 973 | Migration surface |
| `.c` source refs in `./config` | **611** | Each is a hard-coded path → regenerate |
| Header dep-list entries in `./config` | hundreds (`ngx_xrootd_stream_deps`, per-module) | Also hard-coded paths |
| Include search dirs added by build | **exactly one**: `ngx_module_incs="$ngx_addon_dir/src"` (config:557,1293) | The lever that makes this feasible |
| `#include "../…"` (depth-relative) | **1167** | Break when a dir's depth changes |
| `#include "subdir/x.h"` (src-rooted) | ~200 | Break when the target's src-relative path changes |
| `#include "x.h"` (same-dir bare) | 917 | **Survive** if a whole dir moves as a unit |
| Cross-tree includes into `src/` | `tests/`, `client/tests/`, `tools/ci/` | External refs to update |

**Key leverage:** the build already adds `-I src`, and 917 includes are same-dir
bare. Moving a directory *as an intact unit* preserves those for free. The whole
cost concentrates in three mechanical surfaces (§4), not across all 973 files.

---

## 3. Target tree

```
src/
├─ core/                platform + lifecycle primitives (no protocol knowledge)
│   ├─ compat/          (107 files — crc, shm_slots, tmp_path, codec, log_diag, lifecycle_timing…)
│   ├─ types/  config/  shm/  aio/
│   └─ (connection/ session/ protocol/ moved to protocols/root — see §0 decision)
│
├─ protocols/           one subdir per wire protocol / edge surface
│   ├─ root/            handshake/ session/ protocol/ connection/ read/ write/ dirlist/
│   │                   query/ fattr/ zip/ stream/ handoff/ relay/ response/
│   ├─ webdav/          (was src/webdav)
│   ├─ s3/              (was src/s3)
│   ├─ ssi/             (XrdSsi framework + CTA service)
│   ├─ srr/             (SRR HTTP/JSON reporting)
│   └─ dig/             (XrdDig-style remote diagnostics)
│
├─ fs/                  storage plane (VFS = sole source of storage truth)
│   ├─ core/            (vfs_*.c, vfs_walk, vfs_scratch, vfs_io_core) + path-canon/confine half of path/
│   ├─ backend/         (posix rados s3 pblock block http remote xroot cache stage frm — the SD drivers)
│   ├─ cache/           (read-through: cinfo cstore evict fetch origin/ writethrough…)
│   ├─ frm/             (file residency manager / staging)
│   ├─ scan/            (namespace↔catalog fsck)
│   └─ mirror/          (DATA-write mirroring half of mirror/)
│
├─ auth/                identity, credentials, authz
│   ├─ gsi/ token/ sss/ krb5/ pwd/ unix/ host/ voms/
│   ├─ crypto/          (pki_build, shared X509_STORE)
│   ├─ authz/           (ACL half of path/ + the acc/ xrdacc engine)
│   └─ impersonate/     (idmap + user-mapping broker)
│
├─ net/                 clustering, proxying, traffic shaping
│   ├─ cms/ manager/ upstream/ proxy/ ratelimit/ tap/
│   └─ mirror-stream/   (STREAM-mirror half of mirror/)
│
├─ observability/
│   └─ metrics/ pmark/ dashboard/
│
└─ tpc/                 cross-plane (native SHM key registry + WebDAV curl COPY) — kept top-level
```

### 3.1 Full 48-dir disposition

| Current dir | Target | Note |
|---|---|---|
| compat | core/compat | 107 files, unit-move |
| types, config, shm, aio | core/* | primitives |
| connection, session, protocol | protocols/root/* | root-only machinery (§0) |
| handshake, read, write, dirlist, query, fattr, zip, stream, handoff, relay, response | protocols/root/* | root:// handlers |
| webdav, s3, ssi, srr, dig | protocols/* | edge surfaces |
| fs | fs/core + fs/backend | backend already nested |
| cache, frm, scan | fs/* | storage plane |
| gsi, token, sss, krb5, pwd, unix, host, voms, crypto, impersonate | auth/* | identity/creds |
| acc | auth/authz | authz engine |
| cms, manager, upstream, proxy, ratelimit, tap | net/* | cluster/proxy |
| metrics, pmark, dashboard | observability/* | |
| tpc | tpc/ (top-level) | cross-plane, not force-fit |
| **path** | **split** → fs/core (canon/confine) + auth/authz (ACL) | file-granularity |
| **mirror** | **split** → fs/mirror (data) + net/mirror-stream (stream) | file-granularity |

---

## 4. What breaks, and the fix for each

| Surface | Breakage | Fix |
|---|---|---|
| **`./config`** (611 src refs + dep lists) | Every path stale | **Regenerate, never hand-edit.** A filename-keyed generator walks the new tree and emits `NGX_ADDON_SRCS`/dep lists. Filename-keyed (not path-keyed) so the conditional blocks — `XROOTD_HAVE_CEPH / SQLITE / liburing / libxml2 / jansson / krb5` — survive. |
| **1167 `../` includes** | Break on depth change | Convert **all** cross-dir includes to **src-rooted** form (`#include "auth/gsi/parse.h"`). Legal today (`-I src` exists). Permanently removes depth-fragility. |
| **~200 src-rooted includes** | Target path changed | Same rewrite pass, driven by the old→new map. |
| **917 same-dir includes** | Survive | No change — reason to move whole dirs as units. |
| **Cross-tree** (`tests/`, `client/tests/`, `tools/`) | Stale `../../src/…` | Map-driven rewrite extended to those trees. |
| **`tools/ci/check_vfs_seam.sh`** + `vfs_seam_backlog*.txt` | Greps `src/fs/…` paths | Update globs + backlog paths; guard MUST stay green (tier-2 & tier-3 = 0). |
| **Docs** (CLAUDE.md OP→FILE/ROUTING tables, `docs/refactor/*`) | Stale paths | Map-driven find/replace; CLAUDE.md routing tables get a real editorial pass. |

---

## 5. Migration methodology

1. **Freeze point.** Land Phase-64; start from a clean tree (the current working
   set is large — it must land or park first).
2. **Author one machine-readable map** `old_path → new_path`, at *file* granularity
   for the split dirs (`path/`, `mirror/`), dir granularity elsewhere.
3. **Step 0 — include normalization (do this BEFORE any move).** Rewrite every
   cross-dir include in `src/` to src-rooted form against *today's* layout. Once
   done, each subsequent `git mv` needs only a `./config` regen — no include edits.
   **This single step collapses most of the risk.**
4. **`git mv` only** (never delete+add) so blame/history follow every file. One
   commit per bucket keeps review tractable.
5. **Include-rewriter** (map-driven, idempotent) rewrites include *targets* to the
   new src-rooted paths across `src/`, `tests/`, `client/`, `tools/`. Dry-run diff first.
6. **Regenerate `./config`** from the new tree.
7. **`rm -rf objs && ./configure && make -j$(nproc)`** — full rebuild mandatory
   (configure-over-old-objs = mixed-ABI SIGSEGV / EBADF; known gotcha).
8. **Validate:** `nginx -t`; VFS seam guard green; `pytest tests/ --tb=short`;
   C unit tests; `TEST_CROSS_BACKEND=nginx` sample.

---

## 6. Sequencing (each step independently buildable + testable)

0. **Include normalization** (no move) — see §5.3.
1. `core/` (compat, types, config, aio, shm)
2. `auth/` (all sec protocols + crypto + authz + impersonate; ACL split from path/)
3. `fs/` (cache, frm, scan + fs/core; canon split from path/; data-mirror split)
4. `net/` (cms, manager, upstream, proxy, ratelimit, tap; stream-mirror split)
5. `observability/` (metrics, pmark, dashboard)
6. `protocols/` — **root last**: largest and most coupled (§7).

---

## 7. Risks

- **`protocols/root/` is the hard one.** root:// spans ~13 dirs with dense coupling.
  Pulling `connection/`/`session/`/`protocol/` under it (the locked decision) is the
  largest include-churn and the riskiest single commit → sequence last, after step 0
  has already made every include depth-independent.
- **Conditional-compile blocks in `./config`** must survive regen — the generator is
  filename-keyed and must be tested against a *no-optional-libs* build too.
- **Merge conflicts.** A mass move conflicts with any in-flight branch. Needs a quiet
  window; the current uncommitted set must land or park first.
- **Reviewability.** 973-file moves are unreviewable as one diff → per-bucket commits
  + the enforced invariant "content-identical, path-only" (verify with
  `git show --stat` per file = pure rename, zero content hunks outside `#include`).

---

## 8. Build-fact correction (supersedes CLAUDE.md imprecision)

New `.c` files register in the **top-level `./config`** (`$ngx_addon_dir/src/…c`
lists), **not** `src/config/config.h`. CLAUDE.md's BUILD GOVERNANCE section names
`config.h`; the live source list is in `./config`. The §4/§5 regen target here is
`./config`.

---

## 9. Open items (not blocking the draft)

- Exact file-level split of `path/` and `mirror/` — enumerate at execution time.
- Whether `handoff/`, `relay/`, `tap/` belong under `protocols/root/` (they serve the
  stream listener) or `net/` (they're pass-through/observation). Draft puts
  handoff+relay+response under root, tap under net; revisit during step 6.
- `response/` (native `kXR_attn`) — root-only today → `protocols/root`; if a second
  protocol ever emits attn, promote to shared.
