# Phase 66 — `src/` conceptual re-alignment: concept-bucketed directory topology

**Status: EXECUTED 2026-07-02** — the plan below (v2, re-measured the same day against
the post-phase-64 tree) was carried out in 8 commits: step 0 include normalization +
one commit per bucket (core, auth, fs, net, observability, protocols, protocols/root),
each validated with a full clean rebuild, `nginx -t`, the VFS seam guard, and
per-plane smoke tests; a final commit swept the guards/docs. `src/` now contains
exactly `auth/ core/ fs/ net/ observability/ protocols/ tpc/`. Every move was a pure
`git mv` (content-identical outside `#include` lines, enforced by
`tools/refactor/p66_apply.py --verify`); the executable mapping is
[phase-66-map.tsv](phase-66-map.tsv). Historical plan text below is unchanged and
still uses the pre-move paths by design.

> **One-line intent.** Collapse the 51 flat top-level directories under `src/`
> (959 `.c`/`.h` files) into seven concept buckets — `core/ protocols/ fs/ auth/
> net/ observability/ tpc/` — so a newcomer can locate any subsystem from its
> concept alone, lowering the barrier to entry the same way the phase-62 VFS seam
> lowered the barrier to reasoning about storage.

---

## 0. Decisions locked, and v2 revisions

### 0.1 Locked 2026-07-01 (v1) — still standing

| Decision | Choice |
|---|---|
| Bucketing depth | **6 concept buckets + `tpc/`** — `core/ protocols/ fs/ auth/ net/ observability/` with `tpc/` kept top-level (cross-plane) |
| `protocols/root/` scope | **Everything root-specific** — including `session/`, `handshake/`, `protocol/`, `connection/` machinery that only root:// uses |
| Split-dirs | **Split by concept** — file granularity, not whole-dir |
| Persistence | This doc (phase-66); no `src/` change until executed |

### 0.2 Revised in v2 (2026-07-02) — forced by codebase drift since v1

| v1 said | v2 says | Why it changed |
|---|---|---|
| `fs/frm/` bucket for `src/frm/` | **Bucket deleted — `src/frm/` no longer exists.** | Phase-64 P6 (`a9da9b9`) dissolved `src/frm/`: tape staging re-homed onto `src/fs/backend/frm/` (sd_frm driver), `src/fs/xfer/` (stage engine/waiter/ledger/mover), and `src/config/tape_stage_conf.c`. All three are already inside their correct v2 buckets. |
| Split `mirror/` → `fs/mirror` (data) + `net/mirror-stream` (stream) | **Unit move: `mirror/` → `net/mirror/` intact.** | v1 mischaracterized `mirror/`. Reading the sources: it is Phase-24 *traffic* mirroring — fire-and-forget replay of requests to shadow backends with divergence counting (`http_mirror.c` = WebDAV subrequest mirror, `stream_mirror.c`/`stream_wmirror.c` = shadow XRootD client connection reusing the upstream bootstrap). Nothing in it is storage-plane; it is one concept (shadow-traffic replay) with two protocol front-ends. Splitting it would separate `stream_mirror_io.c` (shared framing) from one of its users. |
| `fs/core/` = `vfs_*.c` + canon half of `path/` | **`src/fs/` internal layout is untouched; canon half of `path/` becomes a new `fs/path/`.** | `src/fs/core/` already exists and means something specific: the ngx-free VFS verb kernel (`vfs_core.c`) consumed by the native client via `shared/xrdproto`. Overloading that name for "the vfs_*.c files" would collide. The `vfs_*.c` seam files stay at `fs/` top level exactly as today. |
| `path/` split 2-way (canon vs ACL) | **`path/` split is 5-way** (see §3.2 per-file table): auth/authz (10 files), fs/path (13), protocols/root (5), core/config (1), observability (1). | File-level reading of all 30 files. `merge.c` is a generic config-array merge helper; `access_log.c` is the stream access-log formatter; `extract.c`/`strip_cgi.c`/`stat_body.c`/`op_path.c` are wire-protocol path plumbing, not filesystem confinement. |
| (absent) | **`src/shared/` needs a disposition** — split: HTTP-serving trio → `protocols/shared/`, `safe_size.h` → `core/compat/`. | `src/shared/` (7 files) post-dates v1's table: cross-protocol HTTP ranged file serving (`file_serve`, `http_cache_fill`, `http_serve_offload`) + header-only overflow-safe size math (`safe_size.h`, used codebase-wide). |
| (absent) | **The ngx-free build-in-place surface is a first-class breakage surface** (§4.5). | `shared/xrdproto/Makefile` and `client/Makefile` compile `src/` files *in place* via hard-coded paths (`src/compat`, `src/protocol{,/codec}`, `src/gsi`, `src/token`, `src/sss`, `src/zip`, `src/fs/backend`, `src/fs/core`) and the client sources use src-rooted includes (`"compat/crypto.h"`, `"protocol/frame_hdr.h"`, `"fs/backend/sd.h"`, …). `./configure && make` does NOT build these — a stale path here fails *silently* until someone builds the client. v1 did not mention this surface at all. |
| "Depends on Phase-64 landing first" | **Satisfied** — phase-64 P6 landed as `a9da9b9`. Remaining precondition: the large *uncommitted* working set (≈50 modified tracked files + the AF-bridging/tap/proxy work) must land or park (§7). | |

---

## 1. Goal & hard constraint

Pure directory-topology change. **Content-identical, path-only.** No logic edit, no
rename of a file's basename, no behavioural change. The deliverable of the *execution*
phase is a tree where every `.c`/`.h` is byte-identical to today except its `#include`
lines, plus a regenerated `./config` and updated cross-tree Makefiles/guards.

Non-goals: no dead-code removal, no helper consolidation, no API change, no header
splitting (even where a header now spans two buckets — see `path.h`, §3.2 note).
Those are separate phases — mixing them here makes the move unreviewable.

---

## 2. Current-state facts (re-measured 2026-07-02 at `a9da9b9` + working set)

All numbers below were produced by the commands in Appendix A — re-run them before
executing; this tree moves fast (v1's numbers drifted in one day).

| Fact | Value | Consequence |
|---|---|---|
| Top-level dirs under `src/` | **51** | The thing being reduced |
| `.c` / `.h` files under `src/` | **624 / 335 = 959** | Migration surface |
| Files directly in `src/` root | 2 (`ngx_xrootd_module.h`, `feature_flags.h`) + `README.md` | Need a home (→ `core/`); `ngx_xrootd_module.h` is the single most-included header (105 `../ngx_xrootd_module.h` lines) |
| Unique `.c` paths in `./config` | **594** | Every one is a hard-coded path → regenerate |
| Unique `.h` paths in `./config` (dep lists) | **192** | Same |
| Total `$ngx_addon_dir/src/…` lines in `./config` | **820** | Sizing the regen |
| Module registrations in `./config` | **7** + 1 combined-dynamic block (§4.1) | Generator must reproduce all of them |
| Include search dirs added by the build | **exactly one**: `ngx_module_incs="$ngx_addon_dir/src"` (config:554, config:1278) | The lever that makes this feasible |
| `#include "../…"` (depth-relative) | **1154** total — 1103 one-level (`../x/y.h`), 51 two-level (`../../…`, from depth-2 dirs: `fs/backend/*`, `cache/origin`, `protocol/codec`, `ssi/svc_cta`, `fs/xfer`, …) | Break when a dir's depth changes — i.e. on *every* bucket move |
| `#include "sub/x.h"` (slash, non-`../`) | **175** — a *mix* of includer-relative subdir includes (`"backend/sd.h"` from `src/fs/`, `"origin/x.h"` from `src/cache/`) and true src-rooted includes | Includer-relative ones survive when parent+child move together; src-rooted ones break when the target moves (§4.2 explains the resolution order) |
| `#include "x.h"` (same-dir bare) | **899** | **Survive** if a whole dir moves as a unit |
| Cross-tree C `#include` lines into `src/` | **24** lines across ~21 files: `tests/*.c`, `tests/c/`, `tests/unit/`, `tests/fuzz/`, `client/tests/c/` | Rewrite with the same map |
| Files under `tests/`, `client/`, `tools/` referencing `src/` paths at all (C, Makefiles, shell, python) | **≈244** | Map-driven grep sweep, most are build scripts |
| Build-in-place Makefiles compiling `src/` files | `shared/xrdproto/Makefile` (9 src dirs), `client/Makefile` (`-I$(REPO)/src`) | §4.5 — not exercised by `./configure`; silent-breakage risk |
| Seam guard | `tools/ci/check_vfs_seam.sh` — `ALLOW`/`RAW_ALLOW`/`TIER3_ALLOW` regexes anchored on `^src/…` paths + 3 backlog files | §4.6. Already carries a **stale** `^src/frm/` allow (frm is gone) — evidence that guards accrete dead paths; the move is the moment to scrub them |

### 2.1 What moved between v1 (2026-07-01) and this measurement

- `src/frm/` **deleted** (phase-64 P6); its contents became `src/fs/backend/frm/`,
  `src/fs/xfer/` (12 files: stage_engine, stage_waiter, stage_request_registry,
  xfer_core/ledger/mover/spawn/resume_sweep), and `src/config/tape_stage_conf.{c,h}`.
- `src/fs/` grew internal structure: `core/` (ngx-free VFS kernel), `tier/`
  (tier_build/tier_config — phase-64 SP1 composable tiers), `xfer/`, and backend
  subdirs `backend/{block,cache,frm,http,pblock,posix,rados,remote,s3,stage,xroot}`.
- `src/shared/` exists (cross-protocol HTTP serve + safe_size) — absent from v1's table.
- File count 973 → 959; dir count 48 → 51 (v1's headline "48" also under-counted its
  own 51-row disposition table; both numbers are superseded).
- `./config` source refs 611 → 594 unique `.c`.

**Key leverage (unchanged from v1, numbers refreshed):** the build already adds
`-I src`, and 899 includes are same-dir bare. Moving a directory *as an intact unit*
preserves those for free. The whole cost concentrates in the mechanical surfaces of
§4 — not across all 959 files.

---

## 3. Target tree

Per-bucket counts are `.c`+`.h` files, computed from today's per-dir census (§3.1);
they sum to 959.

```
src/
├─ core/                    ~152 files — platform + lifecycle primitives (no protocol knowledge)
│   ├─ ngx_xrootd_module.h  feature_flags.h          (from src/ root)
│   ├─ compat/              (107 — crc/codec/shm_slots/tmp_path/log_diag/lifecycle_timing/
│   │                        safe_size.h lands here too, from src/shared)
│   ├─ types/   (7)         config/  (18+1: +path/merge.c)
│   ├─ shm/     (4)         aio/     (12)
│   └─ (connection/ session/ protocol/ → protocols/root — §0.1 locked decision)
│
├─ protocols/               ~338 files — one subdir per wire protocol / edge surface
│   ├─ root/                ~165: handshake/(9) connection/(20) session/(10) protocol/(25)
│   │                        read/(22) write/(25) dirlist/(4) query/(14) fattr/(7) zip/(9)
│   │                        stream/(4: module registration) handoff/(2) relay/(2)
│   │                        response/(7) + 5 wire-path files from path/ (§3.2)
│   ├─ webdav/  (76)        (was src/webdav)
│   ├─ s3/      (45)        (was src/s3)
│   ├─ ssi/     (40)        (XrdSsi framework + svc_cta/)
│   ├─ srr/     (4)         (SRR HTTP/JSON reporting)
│   ├─ dig/     (2)         (XrdDig-style remote diagnostics)
│   └─ shared/  (6)         (was src/shared minus safe_size.h: file_serve,
│                            http_cache_fill, http_serve_offload — WebDAV+S3 common
│                            HTTP ranged-serving pipeline)
│
├─ fs/                      ~169 files — storage plane (VFS = sole source of storage truth)
│   ├─ (top level)          vfs_*.c seam files, fd_cache.c, vfs_backend_registry — UNCHANGED
│   ├─ core/                ngx-free VFS verb kernel (vfs_core) — UNCHANGED (client-shared)
│   ├─ backend/             the SD drivers: posix rados s3 pblock block http remote
│   │                        xroot cache stage frm — UNCHANGED
│   ├─ tier/  xfer/         phase-64 composable tiers + transfer engine — UNCHANGED
│   ├─ path/                NEW (13 from src/path — §3.2): beneath, canonical, normalize,
│   │                        helpers, mkdir, resolve_confined_*, resolve_path_variants,
│   │                        unified, path.h, path_internal.h
│   ├─ cache/   (59)        read-through cache: cinfo/cstore/evict/fetch/origin/…
│   └─ scan/    (12)        namespace↔catalog fsck engine
│
├─ auth/                    ~120 files — identity, credentials, authz
│   ├─ gsi/(23) token/(35) sss/(8) krb5/(2) pwd/(3) unix/(1) host/(1) voms/(5)
│   ├─ crypto/  (10)        (pki_build, shared X509_STORE)
│   ├─ authz/               acc/(12: the xrdacc engine) + 10 ACL files from path/ (§3.2)
│   └─ impersonate/ (10)    (idmap + user-mapping broker)
│
├─ net/                     ~93 files — clustering, proxying, traffic shaping/shadowing
│   ├─ cms/(28) manager/(11) upstream/(11) ratelimit/(10)
│   ├─ proxy/   (19)        (terminating reverse proxy / tap_proxy, incl. gsi_upstream)
│   ├─ tap/     (5)         (ngx-free wire tap: decode + sinks + JSON audit)
│   └─ mirror/  (9)         (Phase-24 shadow-traffic replay — unit move, §0.2)
│
├─ observability/           ~59 files
│   ├─ metrics/(23) pmark/(8) dashboard/(27)
│   └─ accesslog/ (1)       path/access_log.c — stream access-log formatter (§3.2)
│
└─ tpc/                     (28) cross-plane (native SHM key registry + WebDAV curl COPY)
                            — kept top-level, not force-fit
```

### 3.1 Full 51-dir disposition

File counts are today's `.c`+`.h` census per top-level dir (Appendix A, cmd 2).

| Current dir | Files | Target | Move type | Note |
|---|---|---|---|---|
| compat | 107 | core/compat | unit | biggest single dir; 353 inbound `../compat/…` includes — most-referenced target |
| types | 7 | core/types | unit | |
| config | 18 | core/config | unit | +`path/merge.c` joins it |
| shm | 4 | core/shm | unit | |
| aio | 12 | core/aio | unit | |
| *(src root)* | 2 | core/ | file | `ngx_xrootd_module.h` (105 inbound includes), `feature_flags.h` |
| connection | 20 | protocols/root/connection | unit | root-only machinery (§0.1) |
| session | 10 | protocols/root/session | unit | " |
| protocol | 25 | protocols/root/protocol | unit | " — **client-shared** (§4.5): `shared/xrdproto` compiles `protocol/*.c` + `protocol/codec/*.c` in place |
| handshake | 9 | protocols/root/handshake | unit | |
| read | 22 | protocols/root/read | unit | |
| write | 25 | protocols/root/write | unit | |
| dirlist | 4 | protocols/root/dirlist | unit | |
| query | 14 | protocols/root/query | unit | |
| fattr | 7 | protocols/root/fattr | unit | |
| zip | 9 | protocols/root/zip | unit | client-shared: `zip_kernel.c` (§4.5) |
| stream | 4 | protocols/root/stream | unit | the STREAM module registration (`module.c` + enums/definition) |
| handoff | 2 | protocols/root/handoff | unit | single-port mux; serves the stream listener (§9 open item) |
| relay | 2 | protocols/root/relay | unit | transparent MITM relay; serves the stream listener (§9 open item) |
| response | 7 | protocols/root/response | unit | native kXR response builders; root-only today (§9) |
| webdav | 76 | protocols/webdav | unit | |
| s3 | 45 | protocols/s3 | unit | |
| ssi | 40 | protocols/ssi | unit | includes `svc_cta/` |
| srr | 4 | protocols/srr | unit | |
| dig | 2 | protocols/dig | unit | |
| **shared** | 7 | **split** → protocols/shared (6) + core/compat (`safe_size.h`) | file | §3.3 |
| fs | 85 | fs (unchanged) | none | internal layout already correct (core/backend/tier/xfer) |
| cache | 59 | fs/cache | unit | incl. `origin/` subdir |
| scan | 12 | fs/scan | unit | |
| **path** | 30 | **split 5-way** | file | §3.2 — the only multi-way split left in the plan |
| gsi | 23 | auth/gsi | unit | client-shared (§4.5) |
| token | 35 | auth/token | unit | client-shared (§4.5) |
| sss | 8 | auth/sss | unit | client-shared: `sss_keytab_kernel.c` (§4.5) |
| krb5 | 2 | auth/krb5 | unit | |
| pwd | 3 | auth/pwd | unit | |
| unix | 1 | auth/unix | unit | |
| host | 1 | auth/host | unit | |
| voms | 5 | auth/voms | unit | |
| crypto | 10 | auth/crypto | unit | PKI build + shared X509_STORE. (Not to be confused with `compat/crypto.*`, which is the client-shared one and moves with compat → core/compat.) |
| impersonate | 10 | auth/impersonate | unit | |
| acc | 12 | auth/authz/acc | unit | joins the 10 path/ ACL files under auth/authz |
| cms | 28 | net/cms | unit | contains its own module registration (`server_module.c`, §4.1) |
| manager | 11 | net/manager | unit | |
| upstream | 11 | net/upstream | unit | |
| proxy | 19 | net/proxy | unit | |
| ratelimit | 10 | net/ratelimit | unit | |
| tap | 5 | net/tap | unit | ngx-free by design |
| **mirror** | 9 | net/mirror | **unit** (v2 revision, §0.2) | shadow-traffic replay, one concept |
| metrics | 23 | observability/metrics | unit | |
| pmark | 8 | observability/pmark | unit | |
| dashboard | 27 | observability/dashboard | unit | |
| tpc | 28 | tpc (top-level) | none | cross-plane |

### 3.2 File-level split of `src/path/` (30 files — the enumeration v1 deferred)

Classified by reading each file's WHAT/WHY block on 2026-07-02.

| File(s) | Target | Rationale |
|---|---|---|
| `acl.c`, `authdb.c`, `find_rule.c`, `group_policy.c`, `auth_cache.{c,h}`, `auth_gate.{c,h}`, `auth_gate_l1.{c,h}` | **auth/authz/** (10) | ACL evaluation, authdb parsing, rule matching, per-path auth decision cache + gate. Pure authorization; joins `acc/`. |
| `beneath.{c,h}`, `canonical.c`, `normalize.c`, `helpers.c`, `mkdir.c`, `resolve_confined_helpers.c`, `resolve_confined_ops.c`, `resolve_path_variants.c`, `unified.{c,h}`, `path.h`, `path_internal.h` | **fs/path/** (13) | openat2 RESOLVE_BENEATH confinement, canonicalisation, the shared realpath resolver (`unified.c`), recursive-mkdir primitive. These are exactly the files the VFS namespace layer is built ON — the seam guard already allowlists `beneath`/`resolve_confined`/`mkdir` by name (§4.6), and all three land together here, keeping the guard's ALLOW regex a single prefix. |
| `extract.c`, `strip_cgi.c`, `stat_body.c`, `op_path.{c,h}` | **protocols/root/path/** (5) | Wire-protocol plumbing: payload→path extraction with embedded-NUL rejection, CGI-suffix strip, kXR_stat response-body formatting, and the per-opcode extract→depth-check→resolve pipeline shared by the root:// namespace handlers. Judgment call on `op_path` recorded in §9. |
| `merge.c` | **core/config/** (1) | Generic parent/child nginx-array merge used by all config merging (`acl.c`, `handshake/policy.c`, …). Nothing path-specific but the directory it sits in. |
| `access_log.c` | **observability/accesslog/** (1) | Formats/writes the per-request stream access-log line (security/ops/capacity streams). Sibling of `metrics/access_log.c`; consumed from `connection/disconnect.c` + `stream/module.c`. Judgment call recorded in §9. |

**Header caveat:** `path.h` is the umbrella header and declares symbols from more than
one of these targets. It moves *intact* to `fs/path/` (content-identical rule, §1);
callers in auth/ and protocols/root keep including it src-rooted. Splitting `path.h`
into per-bucket headers is a legitimate follow-up — as a *separate*, content-changing
phase.

### 3.3 File-level split of `src/shared/` (7 files)

| File(s) | Target | Rationale |
|---|---|---|
| `file_serve.{c,h}`, `http_cache_fill.{c,h}`, `http_serve_offload.{c,h}` | **protocols/shared/** (6) | The WebDAV+S3 common HTTP ranged-file-serving pipeline (200/206/416, byte accounting, offload). Protocol-plane by definition — shared *between protocols*, hence the bucket. `tests/test_cross_protocol_shared_helpers.py` enforces "one canonical implementation, many callers" and keys off these files — its paths get the map rewrite (§4.4). |
| `safe_size.h` | **core/compat/** (1) | Header-only overflow-safe size math used wherever a count comes off the wire (readv, uring, tape_rest, proxy, …). Concept-neutral primitive → core. |

---

## 4. What breaks, and the fix for each

### 4.0 The four include categories (know these before touching anything)

C resolves `#include "x"` **relative to the including file's directory first**, then
along `-I` paths (here: exactly one, `src/`). That yields four distinct behaviours:

| Category | Count | Example | Under a move |
|---|---|---|---|
| Bare same-dir | 899 | `#include "cinfo.h"` in `cache/` | **Survives** any unit move — never rewrite |
| Includer-relative subdir | part of the 175 | `#include "backend/sd.h"` from `src/fs/vfs.h`; `#include "origin/…"` from `cache/` | Survives when parent+child move together (all such pairs do in this plan) — but **normalize anyway** (step 0) so nobody has to reason about which of the 175 is which |
| Depth-relative | 1154 (1103 × `../`, 51 × `../../`+) | `#include "../compat/crc32c.h"` | **Breaks on every bucket move** (depth changes). Eliminated wholesale by step 0 |
| Src-rooted | rest of the 175 | `#include "protocol/frame_hdr.h"` (client tree) | Breaks when the *target* moves; rewritten by the old→new map |

### 4.1 `./config` — 594 `.c` + 192 `.h` refs, 820 path lines

Structure that MUST survive regeneration (do not hand-edit; write a generator):

- **7 module registrations**: STREAM `ngx_stream_xrootd_module` (config:552 — the
  ~460-line main source list), HTTP `metrics` (1026), HTTP `srr` (1054), HTTP
  `webdav` (1065), HTTP_AUX_FILTER `xrdhttp_filter` (1137), HTTP `s3` (1147), HTTP
  `dashboard` (1203), STREAM `cms_srv` (1242) — plus the **phase-47 combined-dynamic
  block** (1262–1283) that dedups `$xrd_dyn_srcs` into one `.so` (metrics/tracking.c
  is intentionally listed by two modules; the dedup loop handles it — the generator
  must preserve both the duplicate listing and the dedup).
- **Feature-gate conditionals** compiling to `-DXROOTD_HAVE_*` stubs:
  ZLIB / ZSTD / LZMA / BROTLI / BZIP2 / LZ4 / CEPH / RADOSSTRIPER / SQLITE / KRB5 /
  LIBURING / LIBXML2 / JANSSON. These gate via CFLAGS (stub-compile pattern), *not*
  by conditionally adding sources — so a purely **filename-keyed** generator works:
  walk the new tree, emit each `.c` under its module's list at its new path, keep
  every non-path line verbatim.
- Shared dep variables `ngx_xrootd_stream_deps` (config:337) and
  `ngx_xrootd_webdav_deps` (config:501) — header lists, same regen.
- `ngx_module_incs="$ngx_addon_dir/src"` (config:554, 1278) — **unchanged**; it is
  the whole enabler.

Test the generator against a no-optional-libs build (`XROOTD_WITHOUT_CEPH=1
XROOTD_WITHOUT_SQLITE=1`, no liburing/jansson/libxml2) as well as the full build.

### 4.2 In-tree includes — step-0 normalization

Rewrite every non-bare include in `src/` to **src-rooted form against today's
layout** (`#include "../gsi/parse.h"` → `#include "gsi/parse.h"`), as its own
commit *before any file moves*. Legal today (`-I src` exists), byte-diff limited to
`#include` lines, trivially reviewable, and it permanently removes depth-fragility:
after step 0, each bucket move only needs a **prefix rewrite** of src-rooted paths
(`"compat/` → `"core/compat/` etc.) plus the `./config` regen. **This single step
collapses most of the project's risk.**

### 4.3 Cross-tree C includes — 24 lines

`tests/*.c` (af_policy, gsi_pem_temp, tap unittests), `tests/c/`, `tests/unit/`,
`tests/fuzz/`, `client/tests/c/vfs_s3_smoke.c` include via `"../../src/…"` forms.
Same map-driven rewrite, same commit as the move that invalidates them.

### 4.4 Cross-tree path references — ≈244 files

Shell runners, python tests, Makefile fragments and docs under `tests/`, `client/`,
`tools/` mention `src/…` paths (e.g. `tests/test_cross_protocol_shared_helpers.py`
greps `src/shared/…`). Map-driven `grep -rl` sweep + rewrite; anything the sweep
can't auto-classify gets eyeballed.

### 4.5 The ngx-free build-in-place surface (NEW in v2 — silent-breakage risk)

Two Makefiles compile `src/` files **in place**, outside `./configure`:

| Consumer | Hard-coded `src/` roots | New value |
|---|---|---|
| `shared/xrdproto/Makefile` | `COMPAT=src/compat` (note: added `-iquote`, not `-I`, due to `time.h` shadowing), `PROTO=src/protocol`, `PROTO_CODEC=src/protocol/codec`, `GSI=src/gsi`, `TOKEN=src/token`, `SSS=src/sss`, `ZIP=src/zip`, `BACKEND=src/fs/backend`, `FSCORE=src/fs/core` — plus explicit per-object rules using those vars | `core/compat`, `protocols/root/protocol{,/codec}`, `auth/gsi`, `auth/token`, `auth/sss`, `protocols/root/zip`, `fs/backend` (unchanged), `fs/core` (unchanged) |
| `client/Makefile` | `SRC := $(REPO)/src`, `-I$(SRC)`; client sources include src-rooted: `"compat/crypto.h"`, `"compat/host_split.h"`, `"protocol/frame_hdr.h"`, `"protocol/codec/wire_codec.h"`, `"protocol/stat_line.h"`, `"fs/backend/sd.h"`, `"fs/backend/s3/sd_s3_transport.h"`, `"token/scopes.h"`, `"token/b64url.h"`, `"sss/sss_keytab_kernel.h"`, `"zip/zip_kernel.h"`, … | `-I$(SRC)` stays; the include *strings* get the same prefix rewrite as in-tree src-rooted includes |

Because `./configure && make` never touches these, a stale path fails only when the
client/libxrdproto is next built. **Therefore: `make -C shared/xrdproto && make -C
client` joins the per-bucket validation gate (§5.8).** Note the interaction with the
concept buckets: the ngx-free kernel set (protocol, token kernels, zip_kernel,
sss_keytab_kernel, sd_posix, vfs_core) is a *purity* dimension orthogonal to the
concept dimension — it deliberately spans `core/`, `protocols/root/`, `auth/`, and
`fs/`. That is fine (Makefile vars name each dir explicitly), but do not "fix" it by
inventing an eighth bucket.

### 4.6 Seam guard + backlogs

`tools/ci/check_vfs_seam.sh` anchors three regex sets on literal `^src/…` prefixes
(`ALLOW` line 73–76, `RAW_ALLOW` 121–130, `TIER3_ALLOW` 182–184) and reads
`tools/ci/vfs_seam_backlog{,_ns,_client}.txt`. Update the regexes with the map;
regen the backlog paths (`--regen` is sanctioned here — this *is* a deliberate
migration). While in there, delete the already-stale `^src/frm/reqfile` and
`^src/frm/` allows (frm no longer exists). The guard MUST stay green (tier-2 and
tier-3 backlogs = 0) after every bucket commit. Conveniently, the plan keeps each
allow-prefix coherent: the three `src/path/` names the guard allowlists
(`beneath`, `resolve_confined`, `mkdir`) all land in `fs/path/` (§3.2), and
`^src/fs/` widens to cover `fs/path/` + `fs/cache/` + `fs/scan/` naturally.

### 4.7 Docs, CLAUDE.md, clangd

- CLAUDE.md ROUTING + OP→FILE tables, HELPERS pointers, and BUILD GOVERNANCE get a
  real editorial pass (not just sed) — this is also the moment to fix the known
  `config.h`-vs-`./config` imprecision (§8).
- `docs/refactor/*` and `docs/09-developer-guide/*` path mentions: map-driven sweep.
- `tools/clangd/gen_compile_commands.py` derives entries from `objs/Makefile` — it
  self-heals after the post-move `./configure`; no edit needed.
- `.github/workflows/loc.yml` has no `src/` path dependence (checked).

---

## 5. Migration methodology

1. **Freeze point.** The phase-64 landing precondition is met (`a9da9b9`). Remaining:
   the current uncommitted working set (~50 modified tracked files + untracked
   AF-bridging/tap/proxy artifacts) must **land or park** — a mass `git mv` over a
   dirty tree destroys the ability to review either.
2. **Author one machine-readable map** `old_path → new_path` (checked in under
   `docs/refactor/phase-66-map.tsv`): file granularity for the two splits
   (`path/` §3.2, `shared/` §3.3) and the 2 src-root files; dir granularity for the
   47 unit moves. The map is the single input to the include-rewriter, the config
   generator check, the cross-tree sweep, and the guard update — one source of truth.
3. **Step 0 — include normalization (BEFORE any move).** §4.2. Own commit; build +
   fast test tier must pass on it alone.
4. **`git mv` only** (never delete+add) so blame/history follow every file. One
   commit per bucket (§6). Verify per commit: every file shows as pure rename
   (`git show --stat` = 100% rename similarity) with zero content hunks outside
   `#include` lines.
5. **Include-rewriter** (map-driven, idempotent, dry-run diff first) rewrites
   src-rooted include *targets* across `src/`, `tests/`, `client/`, `tools/`,
   `shared/xrdproto/`. After step 0 this is a pure prefix substitution.
6. **Regenerate `./config`** from the new tree (§4.1 generator); update the two
   build-in-place Makefiles (§4.5) in the same commit as the move that breaks them.
7. **`rm -rf objs && ./configure … && make -j$(nproc)`** — full rebuild mandatory
   after every `./configure` over a moved tree (configure-over-stale-objs produces
   mixed-ABI garbage: `thread_pool=0x1` SIGSEGV / EBADF — known repo gotcha).
8. **Validate per bucket commit:**
   - `objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf`
   - `tools/ci/check_vfs_seam.sh` green (tier-2/tier-3 = 0)
   - `tests/run_suite.sh --fast` (~4 min); full `--pr` gate before merge
   - C unit tests (`tests/c/`, `tests/unit/`)
   - **`make -C shared/xrdproto && make -C client`** (§4.5 — the surface `make` alone
     never exercises)
   - `TEST_CROSS_BACKEND=nginx` sample on one data-plane test
9. **Post-move sweeps:** CLAUDE.md editorial pass; `docs/` map sweep; regen seam
   backlogs; regen `compile_commands.json`.

---

## 6. Sequencing (each step independently buildable + testable)

Ordered so the smallest, least-coupled buckets prove the machinery before the big one.

| Step | Commit | Contents | ~Files moved |
|---|---|---|---|
| 0 | include normalization | no moves — §4.2 | 0 (≈1300 include-line edits) |
| 1 | `core/` | compat, types, config (+path/merge.c), shm, aio, src-root pair, safe_size.h | ~152 |
| 2 | `auth/` | gsi, token, sss, krb5, pwd, unix, host, voms, crypto, impersonate, acc, + 10 path/ ACL files | ~120 |
| 3 | `fs/` | cache, scan, + 13 path/ canon files → fs/path (fs internals untouched) | ~84 |
| 4 | `net/` | cms, manager, upstream, proxy, ratelimit, tap, mirror (unit) | ~93 |
| 5 | `observability/` | metrics, pmark, dashboard, path/access_log.c | ~59 |
| 6 | `protocols/` — non-root | webdav, s3, ssi, srr, dig, shared→protocols/shared | ~173 |
| 7 | `protocols/root/` — **last** | 14 root dirs + 5 path/ wire files | ~165 |

`tpc/` never moves. Steps 2–3 consume `src/path/` jointly; the directory disappears
at step 7 (its last 5 files leave). The `shared/xrdproto` + `client` Makefile updates
ride with steps 1 (compat), 2 (gsi/token/sss), and 7 (protocol/zip).

**root last, still** (v1 rationale holds, sharpened): root:// spans 14 dirs with the
densest coupling (`connection`/`session`/`protocol` alone draw 42+27+22 = 91 inbound
cross-dir includes, and `protocol/` is additionally client-shared). Step 0 has
already made every include depth-independent by the time this lands, so even the
biggest commit is a `git mv` + prefix rewrite + config regen.

---

## 7. Risks

- **The dirty tree.** Right now ~50 tracked files are modified and several features
  (AF-bridging P1–P4, tap/relay/proxy runtime work) live only in the working set.
  Executing phase-66 under that state guarantees unreviewable conflicts. Hard gate:
  clean `git status` (or an explicitly parked branch) before step 0.
- **`protocols/root/` is still the hard one** — largest commit, densest coupling,
  and the client-shared `protocol/` + `zip/` kernels ride in it. Mitigation: last
  position, step-0 depth-independence, client build in the gate.
- **Silent ngx-free breakage** (§4.5) — the only surface where `./configure && make
  && pytest` all pass while something is broken. Mitigation: client + xrdproto build
  added to the per-bucket gate; this is non-negotiable.
- **Config-generator fidelity.** The combined-dynamic dedup block, the intentional
  duplicate listing of `metrics/tracking.c`, and 13 feature gates must survive.
  Mitigation: generator diff-tested against the *current* config on the *current*
  tree first (regen-in-place must be a no-op modulo whitespace), then against the
  no-optional-libs build.
- **Merge conflicts with in-flight branches.** A 959-file move conflicts with
  everything. Needs an announced quiet window; anything unmergeable before it gets
  rebased after with `git log --follow` intact thanks to pure renames.
- **Reviewability.** Enforced invariant per commit: pure renames, zero content hunks
  outside `#include` lines (verify mechanically, not by eyeball: script over
  `git diff -M100% --stat` + a hunk grep).
- **Guard drift.** The seam guard is the codified storage invariant; a botched regex
  update could go green-by-accident. Mitigation: after each bucket, deliberately
  plant one raw `pread` in a handler in a scratch worktree and confirm the guard
  still catches it (guard-of-the-guard smoke test).

---

## 8. Build-fact correction (supersedes CLAUDE.md imprecision — still open)

New `.c` files register in the **top-level `./config`** (`$ngx_addon_dir/src/…c`
lists), **not** `src/config/config.h`. CLAUDE.md's BUILD GOVERNANCE section names
`config.h`; the live source list is `./config`. The §4.1 regen target here is
`./config`. Fix CLAUDE.md during the §4.7 editorial pass.

---

## 9. Open items (not blocking the draft)

- **`op_path.{c,h}` placement** — filed under `protocols/root/path/` (it drives the
  per-opcode handler pipeline) but it is the bridge into `fs/path/` resolution; if
  a second protocol ever adopts it, promote to `fs/path/`.
- **`access_log.c` placement** — filed under `observability/accesslog/`; the
  defensible alternative is `protocols/root/` (it formats root:// requests only).
  Decide at step 5; one-line map change either way.
- **`handoff/` and `relay/`** — filed under `protocols/root/` (they engage at the
  top of the stream handler); the alternative reading is `net/` (they are
  pass-through plumbing like `tap/`). Revisit at step 7 with `tap/` already in
  `net/` as the reference point.
- **`response/`** (native kXR response builders) — root-only today → `protocols/
  root/response`; if a second protocol ever emits kXR framing, promote to
  `protocols/` level.
- **`path.h` umbrella split** (§3.2 caveat) — follow-up content-changing phase.
- **Post-phase renames** deliberately out of scope but worth queueing: `src/stream/`
  → clearer name (`module/`?) once under `protocols/root/`; scrub remaining stale
  `frm` mentions in comments/docs.

---

## Appendix A — measurement commands (re-run before executing; v1→v2 drifted in a day)

```bash
# 1. top-level dirs
find src -maxdepth 1 -type d | tail -n +2 | wc -l
# 2. per-dir file census (drives §3 counts)
find src \( -name '*.c' -o -name '*.h' \) -printf '%h\n' | cut -d/ -f2 | sort | uniq -c | sort -rn
# 3. ./config surface
grep -oE 'src/[a-zA-Z_0-9/.]+\.c' config | sort -u | wc -l    # unique .c refs
grep -oE 'src/[a-zA-Z_0-9/.]+\.h' config | sort -u | wc -l    # unique .h refs
grep -cE 'ngx_addon_dir/src/' config                          # total path lines
grep -n 'ngx_module_incs' config                              # the single -I root
# 4. include categories
grep -rh 'include "\.\./' src --include=*.c --include=*.h | wc -l          # depth-relative
grep -rh 'include "\.\./\.\./' src --include=*.c --include=*.h | wc -l     # ≥2 levels
grep -rhE 'include "[a-z][a-z_0-9]*/' src --include=*.c --include=*.h | wc -l  # slash, non-../
grep -rhE 'include "[a-zA-Z_0-9]+\.h"' src --include=*.c --include=*.h | wc -l # bare
# 5. inbound-coupling tally (which dirs the ../ includes point at)
grep -rho 'include "\.\./[a-z_0-9./]*"' src --include=*.c --include=*.h \
  | awk -F'"' '{print $2}' | awk -F/ '{for(i=1;i<=NF;i++) if($i!=".."){print $i; break}}' \
  | sort | uniq -c | sort -rn
# 6. cross-tree surfaces
grep -rh 'include ".*src/' tests client tools --include=*.c --include=*.h | wc -l
grep -nE 'src/(compat|protocol|gsi|token|sss|zip|fs)' shared/xrdproto/Makefile client/Makefile
grep -n '\^src/' tools/ci/check_vfs_seam.sh
```
