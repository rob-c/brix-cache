# Phase 104 — VFS spec alignment: every backend and front end to 100% of the idealized interface

**Date:** 2026-08-10 · **Status:** PLAN (not started)
**Source of truth:** [`docs/11-architecture/vfs-interface-specification.md`](../11-architecture/vfs-interface-specification.md)
(the idealized contract — §3 axioms, §7.7 conformance tiers, §13 checklists,
§14 guards), with the gap history in
[`docs/11-architecture/vfs-evolution-and-rationale.md`](../11-architecture/vfs-evolution-and-rationale.md) §6
and the open rulings in `phase-90-plan-phase-remainder-register.md`.
**Baseline verification:** every per-driver fact in §0 was extracted from the
working tree on 2026-08-10 (`main` @ a3f1e500 + the uncommitted phase-88 W1–W4
edits) by dumping each driver's `const brix_sd_driver_t` designated-initializer
field list and `.caps`/`.cred_accept` expressions (protocol: Appendix A) — not
from docs. Several cited files are in the locally-modified set (`git status`);
**re-verify any §0 fact against `src/` immediately before implementing its
workstream** — this plan will age. Line numbers are anchors, not gospel.

---

## Contents

- [Goal & non-goals](#goal--non-goals)
- [How to read this plan / the package template](#how-to-read-this-plan--the-package-template)
- [Workstream summary](#workstream-summary)
- [§0 Baseline census](#0-baseline-census-2026-08-10--measured-not-aspirational)
- [W0 Harness + guards](#w0--conformance-harness--guards-build-the-gate-before-the-feature)
- [W1 Backend driver closure (B1–B9)](#w1--backend-driver-closure-per-driver-packages-b1b9)
- [W2 Decorator relay completeness](#w2--decorator-relay-completeness-m)
- [W3 Auth closure](#w3--auth-closure-across-all-schemas-l)
- [W4 Front-end conformance](#w4--front-end-conformance-xl-the-walls)
- [W5 gsiftp envelope](#w5--gsiftp-origin-driver-conformance-envelope-l-tracks-phase-91)
- [W6 Documentation truth](#w6--documentation-truth-s)
- [Sequence diagrams](#sequence-diagrams)
- [Migration order & per-package gating](#migration-order--per-package-gating)
- [Rollback & safety per workstream](#rollback--safety-per-workstream)
- [Risk register](#risk-register)
- [Open questions (resolve before the named package)](#open-questions-resolve-before-the-named-package)
- [Work-breakdown & sizing register](#work-breakdown--sizing-register)
- [Done criteria](#done-criteria)
- Appendices: [A extraction protocol](#appendix-a--extraction-protocol-reproduce-before-every-package) ·
  [B N/A ledger seed](#appendix-b--na-ledger-seed-rows) ·
  [C file/symbol index](#appendix-c--key-filesymbol-index-for-this-phase) ·
  [D test-name registry](#appendix-d--test-name-registry-prescriptive) ·
  [E skeleton conventions](#appendix-e--skeleton-conventions)

---

## Goal & non-goals

**Goal.** Close the distance between the tree and the spec to **100% of what
each storage model can express** — regardless of performance:

1. every backend driver implements its full **MUST + MUST-if-expressible +
   SHOULD** tiers (spec §7.7), with every remaining absence recorded as an
   honest, harness-asserted **N/A** (NULL slot + absent cap — axiom A3);
2. every decorator relays every slot it composes over, and a composed stack
   is indistinguishable from a native driver with the same effective caps
   (spec §8);
3. every front end passes the spec §13 eight-point checklist, and the three
   long-standing front-end walls (handle table, live dirlist loop,
   staged_file ratification) are ruled and executed;
4. every authentication schema reaches every backend that can consume it,
   with honest `cred_accept` gating, zero service-credential leaks on either
   the allow or the deny path, and a schema × driver × mode sweep as the
   permanent oracle;
5. a driver-conformance harness + two new CI guards make the achieved
   alignment **structurally permanent** — alignment cannot decay without CI
   turning red.

Genuine model impossibilities (an object store cannot `pwrite` a committed
object; a block device cannot rename; a remote origin has no local fd) are
**not** gaps — they are N/A rows in §0.1, asserted by the harness in both
directions (a driver *gaining* an undeclared slot also fails until the
profile is updated).

**Non-goals.** No wire-format changes; no new protocol front ends; no
io_uring redesign; no fd-cache build-out (W4.5 rules the placeholder, it
does not implement the design); no RADOS-native dedup (ledger row); no
Glacier restore (ledger MAY); the zero-copy fast paths beside the io core
(spec D8) are explicitly untouched. Performance work is bounded to "don't
regress the gates" — this phase buys *correctness completeness*, not speed.

**Standing rules for all workstreams** (unchanged from phase-101): no git
write commands without explicit OP approval in-conversation; 3 tests per
change-class (success + error + security-negative); no `goto`; HELPERS over
reimplementation; CCN ≤ 15 / 600-line file cap are live ratchets (extract
helpers rather than grandfather); new `src/` TUs → repo-root `./config` +
re-`./configure` (`check_config_coverage.py` enforces); client-shared files
must compile under `-DXRDPROTO_NO_NGX` (`check_client_build_coverage.py` +
`check-ngx-free.sh`); a VFS-side `if (backend == …)` is an automatic review
reject (`check_vfs_identity_branch.py`). **ABI trap** (memory:
`struct_field_abi_clean_rebuild`): W2 and W3.1 grow `brix_sd_driver_t` /
cred types consumed by every driver TU — treat every commit there as an
ABI-dirty rebuild (delete affected `.o` before rebuild; stale objects with
skewed offsets have previously produced phantom auth failures).

---

## How to read this plan / the package template

Every implementation unit below ("package": B1–B9, W2.1–W2.3, W3.1–W3.5,
W4.1–W4.7, W5 waves) is written to one template and MUST land as one
reviewable unit satisfying all six bullets:

1. **Facts** — the verified current state (files, anchors, caps). Re-run
   Appendix A on the touched driver before starting; if the facts moved,
   update this file's §0 in the same change.
2. **Change set** — slots/caps/twins to add, files touched (created vs
   modified), config/build-list edits.
3. **Recipe** — which existing HELPERS carry the body (never reimplement:
   the codec, the propfind pair, the coalescer, the conn cache, the ns
   verbs), plus a skeleton where the shape is non-obvious. Skeletons follow
   Appendix E conventions — they are *shape*, not copy-paste.
4. **Tests** — named test functions (Appendix D registry) covering
   success + error + security-negative per new op, plus the W0.2 profile
   row update (the harness row that turns green IS part of the package).
5. **Guards** — the W0.1 expectation rows deleted; any allow-list/`--regen`
   edits with rationale in the same commit.
6. **Docs** — the W6 rows (README driver table, feature matrix, ledger) in
   the same change.

---

## Workstream summary

| WS | Item | Verdict / gate | Size |
|----|------|----------------|------|
| **W0** | Conformance harness + 2 new guards (caps↔slots checker; spec-matrix drift script) — **built FIRST** | BUILD | M (rig itself M) |
| **W1** | Backend driver closure: B1 posix · B2 block · B3 pblock · B4 cephfsro · B5 ceph · B6 xroot · B7 http · B8 remote · B9 frm | BUILD | XL |
| **W2** | Decorator relay completeness (`sd_cache`/`sd_stage`); effective caps + cred_accept derived from the wrapped source; ns-twin relay-vs-unwrap ADR | BUILD + AUDIT + ADR | M |
| **W3** | Auth closure: CephX kind + ceph twins · remote read-side twins · http twins (rides B7) · xroot authenticated PRIMARY · schema×driver×mode sweep | BUILD; one **OP-DECIDE** (A4: AUTO default) | L |
| **W4** | Front-end conformance: W4.1 handle-table wall · W4.2 dirlist un-gate · W4.3 staged_file ratification · W4.4 worker-ns metering · W4.5 fd_cache · W4.6 per-protocol sweeps · W4.7 origin ns coverage | BUILD; three **OP-DECIDE** gates | XL |
| **W5** | `gsiftp` origin driver conformance envelope (phase-91 continuation) | BUILD (tracks phase-91) | L |
| **W6** | Documentation truth: fenced regenerated matrices; READMEs; N/A ledger | BUILD | S |

Dependency order: **W0 → {W1, W2} → W3 → W4**; W5 and W6 run alongside from
the first landed package. **Nothing in W1–W5 lands without its W0 harness
row turning green in the same change.**

---

## 0. Baseline census (2026-08-10) — measured, not aspirational

### 0.1 Vtable slot inventory per driver

Extracted from the driver initializers (Appendix A). Legend: ✔ = slot
present · — = absent (a candidate gap) · **n/a** = genuinely inexpressible
for this storage model (spec-sanctioned NULL, asserted by the harness).
`ceph`/`pblock` reflect the build-gated full builds (`BRIX_HAVE_CEPH` /
`BRIX_HAVE_SQLITE`).

| Slot | posix | block | pblock | ceph | cephfsro | xroot | http | remote | cache | stage | frm |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| init/cleanup | ✔ | ✔(init) | ✔ | ✔ | ✔ | — | — | — | — | — | — |
| open/close | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| pread | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| pwrite | ✔ | ✔ | ✔ | ✔ | n/a | ✔ | n/a | n/a | **—** | ✔ | **—** |
| preadv | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | **—** | ✔ | **—** | **—** | **—** |
| preadv2 | ✔ | ✔ | ✔ | ✔ | **—** | n/a | n/a | n/a | **—** | **—** | **—** |
| copy_range | ✔ | **—** | ✔ | n/a | n/a | n/a | n/a | n/a | **—** | **—** | — |
| read_sendfile_fd | ✔ | n/a¹ | ✔ | ✔² | n/a | n/a | n/a | n/a | ✔ | **—** | **—** |
| ftruncate | ✔ | n/a | ✔ | ✔ | n/a | ✔ | n/a | n/a | **—** | ✔ | n/a |
| fsync | ✔ | ✔ | ✔ | ✔ | n/a | ✔ | n/a | n/a | **—** | ✔ | **—** |
| fstat | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| read_advise | ✔ | **—** | **—** | **—** | **—** | n/a³ | n/a³ | n/a³ | ✔ | **—** | — |
| stat | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| unlink | ✔ | n/a | ✔ | ✔ | n/a | ✔ | ✔ | ✔ | ✔ | ✔ | — |
| mkdir | ✔ | n/a | ✔ | ✔ | n/a | ✔ | ✔ | ✔ | ✔ | ✔ | — |
| rename | ✔ | n/a | ✔ | ✔ | n/a | ✔ | ✔ | ✔ | ✔ | ✔ | — |
| server_copy | ✔ | n/a | ✔ | **—** | n/a | ✔ | **—** | ✔ | ✔ | ✔ | — |
| setattr | ✔ | n/a | ✔ | **—** | n/a | **—** | **—** | ✔ | ✔ | ✔ | — |
| truncate_path | **—** | n/a | **—** | **—** | n/a | ✔ | **—** | n/a | **—** | ✔ | — |
| opendir/readdir/closedir | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | — |
| getxattr/listxattr | ✔ | n/a | ✔ | ✔ | ✔ | ✔ | **—** | ✔ | ✔ | ✔ | — |
| setxattr/removexattr | ✔ | n/a | ✔ | ✔ | n/a | ✔ | **—** | ✔ | ✔ | ✔ | — |
| staged_open/write/commit/abort | ✔ | n/a | ✔ | ✔ | n/a | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| staged_path | ✔ | n/a | ✔ | n/a | n/a | n/a | **—**⁴ | n/a | **—** | **—** | — |
| dedup_publish / dedup_gc | ✔/✔ | n/a | ✔/n/a | **—** | n/a | n/a | n/a | n/a | **—** | **—** | — |
| recall / residency | n/a | n/a | ✔/✔ | n/a | n/a | n/a | n/a | **—**⁵ | **—** | **—** | ✔/✔ |
| space | **—** | **—** | ✔ | **—** | **—** | **—** | **—** | n/a | **—** | **—** | — |
| enumerate | n/a⁶ | **—** | ✔ | ✔ | **—** | n/a | n/a | **—**⁷ | **—** | **—** | — |

¹ block deliberately never sendfiles — the extent base must always be
honoured (`read_sendfile_fd` NULL is contract, `src/fs/backend/README.md`).
² present; returns no-fd for rados objects. ³ remote drivers have no local
read-ahead primitive; a request-shaping variant is a MAY, recorded in the
N/A ledger. ⁴ http stages via a local spool in some modes — B7 audits
whether `staged_path` should expose it for the cache-verify hook.
⁵ S3 Glacier restore = a MAY (stretch; operator cost decision).
⁶ POSIX: the namespace IS the catalog (spec-sanctioned `ENOTSUP` decline).
⁷ S3 HAS a native catalog (ListObjectsV2) — a real gap, B8.

Initializer anchors (re-grep before editing; line numbers drift):
`posix/sd_posix.c:255` (caps) · `block/sd_block.c:516` ·
`pblock/sd_pblock.c:245-246` (cred_accept, caps) · `rados/sd_ceph.c:448` ·
`rados/sd_cephfs_ro.c:367` · `xroot/sd_xroot.c:210-217` (caps+cred_accept)
· `http/sd_http.c:38-40` · `remote/sd_remote.c:375-382` ·
`cache/sd_cache.c:295` · `stage/sd_stage.c:271` · `frm/sd_frm.c:387`.

### 0.2 Credential-scoped (`*_cred`) twin inventory

| Driver | Present | Missing (vs. its own base slots) |
|---|---|---|
| pblock | full set: open, staged_open, stat, unlink, mkdir, rename, setattr, getxattr, listxattr, setxattr, removexattr, server_copy, opendir | — (the reference) |
| xroot | open, staged_open, stat, unlink, rename, mkdir, truncate_path, server_copy, getxattr, listxattr, setxattr, removexattr, opendir | `setattr_cred` (blocked on missing base `setattr` — B6) |
| http | open, staged_open, stat, unlink, mkdir, rename, opendir | xattr×4 + `setattr_cred` + `server_copy_cred` (blocked on B7 base slots) |
| remote | open, staged_open, stat, unlink, mkdir, rename, setxattr, removexattr, setattr | **`getxattr_cred`, `listxattr_cred`** (base slots EXIST — read-side xattr runs under the service cred today), `opendir_cred`, `server_copy_cred` — W3.2 |
| ceph | `open_cred` only | **every ns twin** + `staged_open_cred` — a deny-mode ceph export's probe/stat/rename runs under the service connection: the exact phase-2 invariant gap, re-opened for ceph — W3.1 |
| cache / stage | `open_cred`, `staged_open_cred` (relay) | ns twins deliberately absent: cred-scoped ns dispatch bypasses decorators via `brix_vfs_ns_leaf()` (`src/fs/vfs/vfs_cred_internal.h:51`; used at `vfs_cred.c:336/423/481`) — W2.3 ratifies or replaces this |
| posix / block / frm / cephfsro | n/a — local (impersonation), read-only, or adapter | harness N/A rows |

### 0.3 `cred_accept` masks (declared today)

`xroot` = `BEARER|PROXY_PEM|SSS|GSS_KRB5` · `http` = `BEARER|PROXY_PEM` ·
`remote` = `BEARER|PROXY_PEM|S3` · `pblock` = `IDENTITY` ·
posix / block / frm / ceph / cephfsro / cache / stage = **0**.

Two spec-honesty problems (axiom A3 / spec §9.6):
- **(a) ceph consumes CephX creds via `open_cred` but no CephX kind bit
  exists** in `brix_sd_cred_kind_t` (`src/fs/backend/sd_cred_types.h:19-49`)
  — the gate cannot pre-deny on kind for ceph, and ceph's `cred_accept=0`
  reads as "consumes nothing", which is false. → W3.1.
- **(b) the decorators declare 0 but forward creds** — their effective mask
  should mirror the wrapped leaf so `brix_vfs_backend_accepts_proxy()` and
  the kind gate need no composition special-case. → W2.2.

### 0.4 Caps-vs-slots inconsistencies (found during extraction)

| # | Finding | Evidence | Resolution owner |
|---|---|---|---|
| C1 | `frm` advertises `CAP_RANDOM_WRITE\|CAP_FD` but registers **no `pwrite`** and **no `fsync`** | `frm/sd_frm.c:387` caps vs §0.1 row | B9 (W0.1 forces the decision) |
| C2 | `cache` advertises `CAP_RANDOM_WRITE\|CAP_TRUNCATE` but registers no `pwrite`/`ftruncate`/`fsync`; its partial-hit objects carry the cache driver — `o->driver = inst->driver` (`cache/sd_cache_partial.c:319`) — so a worker-tier write/truncate against such an object dereferences a NULL slot | §0.1 + the partial-obj binding | W2.1 |
| C3 | `stage` write-back objects carry the stage driver (`stage/sd_stage_wb.c:164`) with no `preadv`/`preadv2`/`read_sendfile_fd` — a vectored or sendfile read against a write-back object hits NULL slots | §0.1 + the wb-obj binding | W2.1 |

These three are the seed rows of W0.1's expectation file.

### 0.5 Front-end residuals in scope (verified call sites)

- **Handle-table cluster:** `src/protocols/root/connection/fd_table.c`
  (524 lines) + the read/readv/pgread serve paths, `zip_member`,
  `tpc/launch` hold raw fds, not VFS handles. → W4.1.
- **Live dirlist loop:** `src/protocols/root/dirlist/handler.c` runs its
  own confined `fdopendir`/`readdir`; the io-core OPENDIR worker
  (`src/core/aio/dirlist.c`, 166 lines) exists but is gated off. → W4.2.
- **Correction to the evolution-doc §6 residual list** (verified by grep):
  the unified writer is ALREADY consumed by `s3/put_inner.c`,
  `s3/post_object.c`, `webdav/put_setup.c`,
  `root/read/open_resolved_file_dispatch.c`, and both gridftp ev paths
  (`ftp_ev_xfer.c`, `ftp_ev_mode_e_recv.c`). Remaining direct
  `staged_file` use: the `webdav/put.c` spool include + TPC temp/marker
  files. → W4.3 is a *ratification*, not a migration.
- **`src/fs/vfs/fd_cache.c` is 7 lines** (header include + design note).
  → W4.5.
- **`brix_vfs_file_fd` retirement** is the open phase-90 §6.1 ruling.
  → W4.1a.
- Gate internals for W3: `src/fs/vfs/vfs_cred.c` (593 lines —
  `brix_vfs_backend_cred()` data-plane gate + `brix_vfs_ns_cred()` sharing
  one policy body, per its header comment at lines 305-313) and
  `vfs_deleg.c` (518 lines). Async identity: `brix_stage_cred_t`
  (`src/fs/xfer/stage_engine.h:89`) — its `bearer[4096]` field is
  **inline-flush only**: journal writers persist only through `deny`
  (`BRIX_SREQ_IDENTITY_SIZE`), because a bearer is a secret and would be
  expired by async-replay time; journaled flushes re-resolve via key+dir.
  W3.4 must respect this split.
- Composition internals for W2/W5: the tier stack types
  (`src/fs/tier/tier.h` — `brix_tier_cfg_t`, `brix_tier_stack_t` with its
  lazy `composed` top) and the per-kind source-builder table
  (`src/fs/vfs/vfs_backend_registry_source.c:379` —
  `brix_vbr_source_table[]`, builders sharing `brix_vbr_source_fn`).
- Wire-query pattern for B6: `brix_sd_xroot_query_checksum(obj, …)`
  (`xroot/sd_xroot.h:98`) — the existing model for a one-shot origin query
  verb; `brix_sd_xroot_create_origin()` (`sd_xroot.h:86`) for
  instance-from-params construction.

---

## W0 — Conformance harness + guards (build the gate before the feature)

Everything else in this phase is *measured* by W0 (evolution-doc lesson 1:
every migration that went smoothly had its guard first). No W1–W5 package
lands without its harness row green in the same change.

### W0.1 — `tools/ci/check_sd_caps_slots.py` (new guard) — size S

**What.** Parses every `const brix_sd_driver_t` initializer under
`src/fs/backend/` (the Appendix A awk extraction, hardened: evaluate both
arms of `#ifndef XRDPROTO_NO_NGX` and take the server arm; follow
`#include`d slot fragments if any appear later) and asserts the
capability→slot implications from spec §7.3/§7.7:

| Rule | Implication |
|---|---|
| R1 | `CAP_RANDOM_WRITE ⇒ pwrite != NULL` |
| R2 | `CAP_TRUNCATE ⇒ ftruncate != NULL` |
| R3 | `CAP_SENDFILE ⇒ read_sendfile_fd != NULL ∧ CAP_FD` |
| R4 | `CAP_DIRS ⇒ opendir ∧ readdir ∧ closedir` |
| R5 | `CAP_DIRS_WRITE ⇒ mkdir ∧ rename ∧ unlink ∧ CAP_DIRS` |
| R6 | `CAP_XATTR ⇒ getxattr ∧ listxattr` |
| R7 | `CAP_XATTR_WRITE ⇒ setxattr ∧ removexattr ∧ CAP_XATTR` |
| R8 | `CAP_NEARLINE ⇒ recall ∧ residency` |
| R9 | `CAP_CATALOG ⇒ enumerate` |
| R10 | writable (`staged_open != NULL ∨ CAP_RANDOM_WRITE`) ∧ `!CAP_RANDOM_WRITE ⇒ full staged family (open+write+commit+abort)` |
| R11 | `cred_accept != 0 ⇒ open_cred != NULL` |
| R12 | any `<op>_cred != NULL ⇒ <op> != NULL` (a twin without its base is a wiring bug) |
| R13 | `staged_commit != NULL ⇒ staged_abort != NULL` (no commit without a crash path) |
| R14 | *(added by W2.3 if the unwrap ADR is ratified)* decorator drivers (`cache`,`stage`) MUST NOT register ns `_cred` twins |

**Skeleton** (shape only — Appendix E):

```python
#!/usr/bin/env python3
"""check_sd_caps_slots.py — capability↔slot honesty guard (phase-104 W0.1)."""
RULES = [  # (id, caps_required_mask_expr, slots_required, extra_caps_required)
    ("R1", {"CAP_RANDOM_WRITE"}, {"pwrite"}, set()),
    ("R3", {"CAP_SENDFILE"}, {"read_sendfile_fd"}, {"CAP_FD"}),
    # ... table mirrors the doc above; ids stable for expectation rows
]
def parse_driver(path):           # awk-equivalent: initializer block →
    ...                           # {name, caps:set, cred_accept:set, slots:set}
def violations(drv):
    for rid, caps, slots, xcaps in RULES:
        if caps <= drv.caps and (not slots <= drv.slots or not xcaps <= drv.caps):
            yield f"{drv.name}:{rid}"
# main: collect, subtract expectation file, fail on new; fail on stale rows
```

**Expectation file** `tools/ci/sd_caps_slots_expected.txt` — one line per
tolerated violation `driver:rule # note`, shipped pre-populated with
exactly §0.4:

```
frm:R1        # C1 — CAP_RANDOM_WRITE without pwrite; B9 rules drop-vs-implement
frm:R10       # C1 — staged family missing fsync hygiene; B9
cache:R1      # C2 — partial-hit objs carry cache driver, no pwrite; W2.1
cache:R2      # C2 — no ftruncate; W2.1
stage:VEC     # C3 — wb objs lack preadv/preadv2/read_sendfile_fd; W2.1 (note-rule)
```

Each W1/W2 fix **deletes its row in the same commit** (the phase-56 backlog
pattern applied to capability honesty). A row whose violation no longer
exists FAILS ("stale grandfather") — the file is honest in both directions.
`--regen` exists with the standing cultural rule: deliberate migrations
only, never CI appeasement. Failure output format:
`sd-caps-slots: NEW violation frm:R1 (CAP_RANDOM_WRITE but .pwrite is NULL) — see docs/refactor/phase-104-vfs-spec-alignment.md §0.4`.

**Runtime mode (W2.2 extension):** `--composed` queries a debug dump of
`brix_vfs_backend_export_info()` (extended with the effective caps/mask)
from a test-fleet instance and applies R1–R13 to composed stacks.

**Tests (3, in `tests/test_ci_guards.py` style):**
`test_sdcaps_detects_r1_violation` (fixture driver source with
RANDOM_WRITE and no pwrite → nonzero exit, names `fixture:R1`);
`test_sdcaps_current_tree_green` (shipped expectation file → exit 0);
`test_sdcaps_stale_row_fails` (expectation row for a non-violation → fail).

### W0.2 — the parametrized driver-conformance rig — size M (the phase's biggest test asset)

**Files.** NEW `tests/c/sd_conformance.c` (pure-C harness, one binary,
profiles as a table) + NEW `tests/test_sd_conformance.py` (pytest lane:
per-driver parametrization, fixture setup, fleet-backed origin profiles).
Registered in the C-unit lane: `tests/test_c_regression_units.py` gains
suite id `sdconf`. Build: standalone gcc target beside the existing
unittest harnesses (pblock/csi/ceph pattern — no nginx link).

**Profile shape** (the rig's single table):

```c
typedef enum { SDCONF_FIX_TMPDIR, SDCONF_FIX_BLOCK_IMAGE, SDCONF_FIX_PBLOCK,
               SDCONF_FIX_MOCK_WEBDAV, SDCONF_FIX_MOCK_S3, SDCONF_FIX_MOCK_XROOT,
               SDCONF_FIX_CEPH_LIVE, SDCONF_FIX_FRM_STUB } sdconf_fixture_t;

typedef struct {
    const char      *driver;       /* census name                           */
    sdconf_fixture_t fixture;
    uint32_t         expect_caps;  /* EXACT match vs instance effective caps */
    uint64_t         expect_slots; /* bitmask over the vtable fields         */
    uint64_t         na_slots;     /* asserted-NULL set (honest absences)    */
    unsigned         skip_live:1;  /* env lacks the fixture → SKIP not PASS  */
    unsigned         client_variant:1; /* also assert the NO_NGX narrowing   */
} sdconf_profile_t;

/* one row per census driver; W5 adds gsiftp on its first serving wave */
static const sdconf_profile_t profiles[] = {
    { "posix",  SDCONF_FIX_TMPDIR,      POSIX_CAPS,  POSIX_SLOTS,  POSIX_NA, 0, 1 },
    { "pblock", SDCONF_FIX_PBLOCK,      PBLOCK_CAPS, PBLOCK_SLOTS, PBLOCK_NA, 0, 0 },
    { "block",  SDCONF_FIX_BLOCK_IMAGE, BLOCK_CAPS,  BLOCK_SLOTS,  BLOCK_NA, 0, 1 },
    { "frm",    SDCONF_FIX_FRM_STUB,    FRM_CAPS,    FRM_SLOTS,    FRM_NA,   0, 0 },
    { "http",   SDCONF_FIX_MOCK_WEBDAV, HTTP_DAVS_CAPS, ..., 0, 0 },   /* davs   */
    { "http-plain", SDCONF_FIX_MOCK_WEBDAV, HTTP_PLAIN_CAPS, ..., 0, 0 },
    { "remote", SDCONF_FIX_MOCK_S3,     ... },
    { "xroot",  SDCONF_FIX_MOCK_XROOT,  ... },
    { "ceph",   SDCONF_FIX_CEPH_LIVE,   ..., .skip_live = 1 },
    { "cephfsro", SDCONF_FIX_CEPH_LIVE, ..., .skip_live = 1 },
    /* cache/stage run as COMPOSED profiles: decorator(posix) and
       decorator(mock-origin) — W2's acceptance rows                        */
};
```

**Assertion order per profile:**
1. **Shape:** actual slot set == `expect_slots` exactly. An *extra*
   implemented slot is ALSO a failure until the profile row is updated —
   the matrix stays truthful in both directions; every W1 package's diff
   includes its profile-row edit (that is the "harness row turns green in
   the same change" mechanic).
2. **Caps:** instance effective caps == `expect_caps` (catches init-time
   narrowing regressions and C1-style lies once fixed); `client_variant`
   profiles additionally assert the `XRDPROTO_NO_NGX` narrowing (posix
   drops SERVER_COPY/XATTR/HARD_RENAME/DIRS families).
3. **Semantics** (each leg success + error + security-negative):
   - open→pwrite→fsync→fstat→pread round-trip through the verb core
     (`xvfs_*`), byte-exact;
   - short-I/O + EINTR tolerance via a fault-injecting wrapper fd where
     the fixture allows (tmpdir legs: an interposing fd that returns
     short counts / EINTR on a schedule; origin legs: skip — the loop
     policy is single-sourced, tested once on the POSIX leg);
   - `rename(noreplace)` → `EEXIST`; `unlink(is_dir)` on non-empty →
     `ENOTEMPTY`; absent-path delete → `ENOENT` (the D17 origin rules);
   - `..`-escape / control-byte name → reject (`EXDEV`/`ENOENT`, never
     resolution outside the fixture root) — the standing
     security-negative;
   - staged open→write→**abort** leaves no final-path object; staged
     commit(excl=1) twice → second `EEXIST`;
   - errno-fact discipline: assert `errno` ∈ the POSIX set after every
     failing leg (no HTTP/kXR code leaks — a 404 that surfaces as `-404`
     is the historical failure mode this catches).
4. **N/A honesty:** every `na_slots` member is NULL AND its implied cap
   absent.

**Fixtures.** Pure-C legs: tmpdir (posix), loopback file image opened via
the block driver's unconfined open (block), tmpdir+sqlite (pblock),
`sd_frm_stub.c` adapter (frm). Pytest legs drive the same binary with
fixture endpoints injected via env: the fleet WebDAV/S3/xrootd mocks from
`fleet_specs` via `RegistryLauncher` (the same servers
`test_cmd_cache_http_source.py` / `test_cmd_cache_s3_origin.py` /
`test_cmd_cache_xroot_origin.py` already use; all ports within the
`TEST_PORT_START+2000` rule). Ceph mirrors the `test_sd_ceph.py` (pure) /
`test_ceph_live.py` (cluster-gated) split; `skip_live` reports SKIP, never
silent PASS.

### W0.3 — spec-matrix drift script — size S

NEW `tools/ci/gen_vfs_spec_matrix.py`: emits (a) the spec §7.3 per-driver
capability matrix and (b) this file's §0.1 slot matrix, from the same
parser as W0.1. Target docs get fence markers:

```markdown
<!-- sdmatrix:begin caps -->   … generated table … <!-- sdmatrix:end caps -->
<!-- sdmatrix:begin slots -->  … generated table … <!-- sdmatrix:end slots -->
```

CI regenerates and diffs the fenced regions — a hand edit inside a fence
or a driver change without a doc regen fails with a unified diff in the
log. Until W6 wires the fences the script runs report-only (a warning
annotation, not a failure), so W1 packages can land doc rows manually in
the interim. The generator's superscript-note column is sourced from an
annotations sidecar (`tools/ci/sd_matrix_notes.yaml`) so prose survives
regeneration.

---

## W1 — Backend driver closure (per-driver packages B1–B9)

Ordered cheapest-first so the rig accretes wins early. Every package
follows the template (Facts → Change set → Recipe/skeleton → Tests →
Guards → Docs); Appendix D holds the full test-name registry.

### B1 — posix (S)

**Facts.** Complete except `truncate_path`, `space` (§0.1). The reference
driver must not itself rely on VFS fallbacks the spec ranks SHOULD.
**Change set.** `posix/sd_posix.c`: two slots appended in vtable order;
no caps change (neither op has a cap). Callers audited:
`brix_vfs_truncate_path` (drops its open+ftruncate+close on the default
export), `brix_vfs_space` (stops `NGX_DECLINED` on default exports —
audit `kXR_statvfs` + SRR consumers and delete any now-dead duplicated
statvfs fallback).
**Recipe.**

```c
/* sd_posix_truncate_path — confined, impersonation-aware path truncate. */
static ngx_int_t
sd_posix_truncate_path(brix_sd_instance_t *inst, const char *path, off_t len)
{
    /* mirror the other posix ns slots: delegate to the confined helper
     * tier (brix_ns_* / *_confined_canon style body), absolute-path
     * contract, EISDIR fact for a directory, ENOENT for absent.        */
}

/* sd_posix_space — statvfs(3) of root_canon, below the seam. */
static ngx_int_t
sd_posix_space(brix_sd_instance_t *inst, brix_sd_space_t *out)
{
    struct statvfs v;
    /* statvfs(state->root_canon) — vfs-seam-N/A: this IS backend/ */
    out->total_bytes = (uint64_t) v.f_blocks * v.f_frsize;
    out->free_bytes  = (uint64_t) v.f_bavail * v.f_frsize;
    out->used_bytes  = out->total_bytes - out->free_bytes;
    return NGX_OK;
}
```

**Tests.** `sdconf`: `posix_truncate_path_{grow,shrink}` ·
`posix_truncate_path_absent_enoent` · `posix_truncate_path_escape_reject`
· `posix_space_sanity` (vs direct statvfs ± slack) ·
`posix_space_impersonation` (mapped-user export — same numbers).
**Guards/docs.** Profile row +2 slots; README posix row; spec matrix.

### B2 — block (S–M)

**Facts.** Caps `FD|RANDOM_WRITE|RANGE_READ(+DIRS server)`
(`block/sd_block.c:516`); byte ops + stat/dir only. Extent model: server
plane divides the device into `extent_size` extents `/0../N-1`; all byte
ops clamp+base-shift; boundary-crossing write refused `ENOSPC`.
**Change set.** `block/sd_block.c` (+ split a `sd_block_catalog.c` only if
the file-size ratchet trips): `space`, `read_advise`, `enumerate` +
`CAP_CATALOG`, `copy_range`.
**Recipe.** `space`: total = capacity from the existing `BLKGETSIZE64`
fstat body; used = occupied-extent count × extent_size (an extent is
"occupied" per the existing namespace logic); whole-device (extent_size 0)
reports total=used=capacity (one opaque extent). `read_advise`:
`posix_fadvise(state->devfd, base+off, len, …)` with the same clamp the
byte ops use — never advise past the extent tail. `enumerate`: iterate
extent indices, `key=path="/<i>"`, `have_stat` size = window length,
mtime = device mtime; honour cb-abort. `copy_range`: clamp both windows,
delegate to the shared POSIX raw op; any boundary crossing → `ENOSPC`
(consistent with the write clamp).
**Tests.** `block_space_capacity` · `block_enumerate_extents` (+ cb-abort
leg) · `block_read_advise_tail_clamp` · `block_copy_range_cross_extent_enospc`
· standing negatives: `block_extent_name_nonnumeric_enoent`,
`block_extent_out_of_range_enoent`.
**Guards/docs.** Profile +4 slots +CAP_CATALOG; README block row.

### B3 — pblock (S)

**Facts.** The completeness reference (only driver with
space+enumerate+recall+residency+full twins) — missing `read_advise`,
`truncate_path` (§0.1).
**Change set.** `pblock/sd_pblock.c` (+ catalog helper if needed).
**Recipe.** `read_advise`: offset-0 windows → fadvise the persistent
block-0 fd; higher windows → per-touched-block via the existing
transient-open helper; packed-arena records (`pack=1`) → advise the
containing `pack/seg-<n>.dat` range. Always best-effort `NGX_OK`.
`truncate_path`: catalog path→blob lookup, then the existing ftruncate
body (block drop + tail trim + catalog size update) without a handle
open — under the same flock/WAL discipline as handle truncate
(multi-worker safety).
**Tests.** `pblock_read_advise_{block0,highblock,packed}` ·
`pblock_truncate_path_{shrink_drops_blocks,grow}` ·
`pblock_truncate_path_concurrent_workers` (extends the
`test_pblock_group_multiuser.py` pattern) · escape negative.
**Guards/docs.** Profile +2; pblock deep-dive doc row.

### B4 — cephfsro (S)

**Facts.** Read-only MUST set complete; missing `preadv2`, `space`.
**Recipe.** `preadv2` delegates to `preadv`; `RWF_NOWAIT` returns
`-1/EAGAIN` honestly (the warm-cache probe then simply never fast-paths
here — correct degradation). `space` via the metadata-pool statfs on the
existing RADOS connection.
**Tests.** `cephfsro_preadv2_nowait_eagain` · `cephfsro_space_sanity`
(live-gated) · N/A assertions for every write slot.

### B5 — ceph (M)

**Facts.** Byte+ns+xattr+staged complete; missing `setattr`,
`server_copy`, `truncate_path`, `space` (§0.1); `read_advise`/`dedup` →
ledger. Cred twins → W3.1. TU layout: `sd_ceph.c` (shell+registry row),
`sd_ceph_io.c` (worker byte I/O), `sd_ceph_object.c` (lifecycle+metadata),
`sd_ceph_cred.c` (per-user conn cache), `sd_ceph_dir.c`, 
`sd_ceph_object_rename.c`.
**Change set.** `sd_ceph_object.c` gains setattr/truncate_path/space;
`sd_ceph_io.c` gains server_copy; registry row caps unchanged (none of
these carry caps except server_copy → add `CAP_SERVER_COPY`).
**Recipe — setattr via the shared advisory codec** (the
silent-chmod-no-op lesson says a mutable-metadata backend must NOT lean on
the NULL⇒no-op tolerance):

```c
/* sd_ceph_setattr — advisory-model metadata mutation (spec §5.6 table). */
static ngx_int_t
sd_ceph_setattr(brix_sd_instance_t *inst, const char *path,
                const brix_sd_setattr_t *attr)
{
    brix_meta_advisory_t adv;             /* meta_advisory.h codec         */
    /* 1. read current blob: rados xattr BRIX_META_ADVISORY_XATTR
     *    ("user.xrd.unixattr") on the resolved oid; absent → zeroed adv. */
    /* 2. merge per attr->set_mode/set_times/set_owner, honouring
     *    UTIME_OMIT/UTIME_NOW and (uid_t)-1/(gid_t)-1 sentinels.         */
    /* 3. encode + setxattr back (read-merge-write; the sd_remote_meta.c
     *    precedent).  ENOENT for an absent oid.                          */
}
/* + overlay: sd_ceph stat/fstat call sites decode the blob and overlay
 * mode/uid/gid/mtime onto brix_sd_stat_t — codec header documents this. */
```

`server_copy`: same-pool rados read→write through the oid layer in one
worker call, `bytes_out` = object size; cross-pool → `-1/EXDEV`-free
decline (`ENOTSUP`) so the VFS stream-through fallback applies (§7.4).
`truncate_path`: bare-oid probe (the rename slot's existence-probe
helper) then the ftruncate body. `space`: `rados_cluster_stat` + pool
quota → `brix_sd_space_t`.
**Tests.** Pure: advisory round-trip legs in `sd_ceph_unittest.c`
(`ceph_advisory_{encode_decode,merge_omit,merge_now}`), escape-named oid
unreachable. Live (`tests/ceph/sd_ceph_live_test.c` via
`test_ceph_live.py`): `ceph_setattr_roundtrip_crossmethod` (set over one
open, read over another), `ceph_server_copy_samepool`,
`ceph_server_copy_crosspool_declines`, `ceph_truncate_path`,
`ceph_space_sanity`.
**Guards/docs.** Profile +4 slots +CAP_SERVER_COPY; ledger rows for
read_advise/dedup; README ceph row.

### B6 — xroot (M)

**Facts.** Widest origin driver; missing `setattr`(+`_cred`), `space`
(§0.1). Wire-query pattern to copy: `brix_sd_xroot_query_checksum`
(`sd_xroot.h:98`) — a one-shot origin query on an open object;
ns-verb framing precedent in `sd_xroot_ns.c`; per-user session pattern in
`sd_xroot_ns_cred.c` (copy cred fields into the fill task).
**Change set.** `sd_xroot_ns.c`: `setattr` + `space`;
`sd_xroot_ns_cred.c`: `setattr_cred`; registry row: no cap change
(setattr/space carry none).
**Recipe.** `setattr`: `set_mode` → frame `kXR_chmod` (mode ↔ kXR mode
bits per the existing chmod handler's mapping, inverted); `set_times` →
the origin's fattr/advisory surface where the origin advertises it,
else *partial-apply honestly* (apply mode, report OK — the
`brix_sd_setattr_t` contract explicitly permits "apply what the namespace
can represent"; document the partial matrix in `sd_xroot.h`). `set_owner`
→ not representable over kXR → skipped (documented). `space`: frame
`kXR_statvfs` (path form) against the origin, parse into
`brix_sd_space_t`; where the origin lacks statvfs, fall back to
`kXR_Qconfig space` text parse; both absent → `-1/ENOTSUP` (VFS falls
back to local statvfs — which is *wrong* for a remote primary, so the
feature-matrix row flips only when this lands).
**Tests.** `test_cmd_remote_backend.py` gains:
`test_remote_backend_chmod_roundtrip` (gateway chmod visible via origin
stat) · `test_remote_backend_chmod_deny_never_reaches_origin`
(distinct-service-DN pattern + origin-log assertion) ·
`test_remote_backend_statvfs_matches_origin` ·
`test_remote_backend_setattr_times_partial` (times on a non-fattr origin
→ OK, mode applied). `sdconf` mock-xroot profile rows.
**Guards/docs.** Profile +2 (+twin); feature-matrix statvfs-on-gateway row.

### B7 — http (L; the biggest single-driver package)

**Facts.** Read + staged-write + ns skeleton + dir
(`sd_http.c:38` caps `RANGE_READ|MEMFILE|DIRS|DIRS_WRITE|HARD_RENAME`);
no xattr/setattr/server_copy/space/preadv (§0.1). TU layout:
`sd_http_read.c` (GETs) · `sd_http_write.c` (staged PUT) ·
`sd_http_mutate.c` (MKCOL/MOVE/DELETE) · `sd_http_dir.c` (PROPFIND, with
the shared `sd_http_propfind_issue()`/`sd_http_propfind_errno()` at
`sd_http_dir.c:347-381`) · `sd_http_introspect.c` · `sd_http_select.c`.
**Step 0 — capability split.** A **davs/WebDAV** origin can express
xattr/setattr/copy/space; **plain http** cannot. The instance `init`
knows the scheme (registry `tls` + config); it narrows the effective caps
per export (the phase-83 instance-caps mechanism — NO new config). The
rig carries TWO profiles (`http` davs-full, `http-plain` narrow); the
plain profile asserts every davs-only slot declines at runtime
(`ENOTSUP`) even though the slot pointer exists.
**Change set.** NEW `sd_http_xattr.c` (file-size ratchet — don't grow
`sd_http_mutate.c`); edits to `sd_http_mutate.c` (COPY), `sd_http_dir.c`
(quota PROPFIND), `sd_http_read.c` (preadv); NEW shared
`src/fs/backend/range_coalesce.{c,h}` (ngx-free; registered in `./config`
AND `shared/xrdproto/Makefile` if the client consumes it — decide in
review; default server-only). Register `sd_http_xattr.c` in `./config`.
**Recipe.**
- **xattr family** (+`CAP_XATTR|XATTR_WRITE` on the davs profile): map
  `user.<name>` ↔ a reserved dead-property
  `<brix:xattr-user-<name>>` under one namespace URI; `setxattr` /
  `removexattr` → `PROPPATCH` set/remove; `getxattr` / `listxattr` →
  `PROPFIND Depth: 0` via the existing propfind pair. Status mapping
  stays `sd_http_propfind_errno` (`207→ok, 404|409→ENOENT,
  401|403→EACCES, 405|501→ENOTSUP, else EIO` — the D17 table). Name
  validation BEFORE encoding: reject `/`, control bytes, oversize
  (`ERANGE` on get-into-small-buffer per the spec's xattr contract).
- **setattr**: PROPPATCH of ONE advisory property whose value is the
  `meta_advisory` codec string — the same string ceph/S3 store, so
  mode/uid/gid/mtime round-trip across access methods (R-8 mitigation:
  one codec, three backends).
- **server_copy** (+`CAP_SERVER_COPY` davs): WebDAV `COPY` with
  `Destination:` on the SAME origin (host:port match against the
  instance endpoint — a cross-origin Destination is refused before any
  request is sent); `Overwrite: F` → map 412 → `EEXIST`; `bytes_out`
  from post-copy PROPFIND size.
- **space**: RFC-4331 `quota-available-bytes`/`quota-used-bytes`
  PROPFIND on the base collection; absent props → `-1/ENOTSUP` (VFS
  statvfs fallback documented as *local* — feature-matrix note).
- **preadv**: extract the P80.1 coalescing body from
  `sd_remote_preadv` (`remote/sd_remote.c:271`) into
  `range_coalesce.{c,h}` — gap-merge policy and max-span knobs become
  parameters — consumed by BOTH drivers (HELPERS rule: one coalescer,
  two callers; `sd_remote.c` shrinks in the same commit).
- **staged_path audit** (⁴): if the davs staged write spools locally,
  expose the spool path (cache-verify digest hook); else assert n/a in
  the profile.
- **Every new base slot lands WITH its `_cred` twin in the same commit**
  (W3.3 — the bind-forgotten lesson: never ship an allow/deny split).
**Tests** (fleet WebDAV mock; extend the `test_cmd_cache_http_source.py`
fixture family): `http_xattr_{set_get_roundtrip,list,remove,erange}` ·
`http_xattr_name_injection_rejected` (control bytes, `/`, oversized) ·
`http_setattr_advisory_roundtrip_crossbackend` (same blob readable via
S3 profile — codec unification proof) · `http_copy_{ok,overwriteF_eexist}`
· `http_copy_cross_origin_refused` (no wire traffic — mock asserts zero
requests) · `http_space_quota_props` + absent-props decline ·
`http_preadv_coalesced` (mock asserts request COUNT, proving the merge) ·
plain-profile decline legs for all of the above · deny-mode twins legs
(W3.3).
**Guards/docs.** TWO profile rows; expectation deletions n/a (no C-row);
README http row; feature-matrix WebDAV-property rows.

### B8 — remote/S3 (M)

**Facts.** Read+staged+ns+xattr+setattr complete; missing `enumerate`
(§0.1⁷); read-side twins → W3.2; Glacier → ledger MAY.
**Change set.** NEW `sd_remote_catalog.c` (or extend `sd_remote_dir.c` if
under the ratchet); registry row + `CAP_CATALOG`.
**Recipe.** `enumerate` = ListObjectsV2 paging (continuation tokens) over
the bucket prefix; `want_stat` fills size/mtime FROM THE LISTING (no
per-object HEAD — one request per 1000 objects); `path` recovered from
the key (identity under the bucket prefix — the driver's documented
key↔path map); cb-abort honoured mid-page (finish decode, stop paging).
Uses the injected transport + `sd_s3_sign_ext` for the query-string
signing (list params are part of the canonical request — the
`host:port` SigV4 lesson applies).
**Tests.** `remote_enumerate_{single_page,multi_page,cb_abort}` (mock
returns 2 pages; assert continuation token flowed) ·
`remote_enumerate_want_stat_no_head` (mock asserts zero HEADs) · unit
legs beside `test_sd_s3_read_unit.py` for the list-XML decode.
**Guards/docs.** Profile +1 +CAP_CATALOG; inventory-tooling doc note
(walk fallback no longer used on S3 exports).

### B9 — frm (S)

**Facts.** C1 — caps `NEARLINE|RANGE_READ|RANDOM_WRITE|FD`
(`frm/sd_frm.c:387`) but no `pwrite`, no `fsync` (§0.4). Files:
`sd_frm.c` (driver) · `sd_frm_adapter.c`/`sd_frm_exec.c`/`sd_frm_stub.c`
(MSS adapters) · `sd_frm_lib.c`.
**Change set + recipe.** Resolve C1 per W0.1's forced decision.
**Recommendation: drop `CAP_RANDOM_WRITE`** — bytes never flow through
frm in place (writes land in the composed cache/stage tiers; frm's own
write surface is its staged family used by the recall landing path). Add
the missing `fsync` on the staged temp (R10 hygiene). IF the exec adapter
(`sd_frm_exec.c`) write path is found to need in-place `pwrite` during
implementation, implement it as a staged-adapter delegate and keep the
cap — either way the expectation rows die. Document the read contract in
`sd_frm.h`: **`pread` NEVER triggers a recall** — reads serve online
bytes only; recall is the explicit verb (`NGX_AGAIN` + parked open, spec
§6.6).
**Tests.** `frm_caps_honest` (rig shape check) ·
`frm_pread_offline_no_recall` (stub adapter: offline key → pread fails,
recall counter unmoved) · `frm_recall_parks_and_resumes` (stub:
`NGX_AGAIN` → land bytes → parked open resumes — the
`test_pblock_lab_nearline.py` pattern against `sd_frm_stub.c`).
**Guards/docs.** Delete `frm:R1`/`frm:R10` expectation rows; README frm
row documents the ruling.

---

## W2 — Decorator relay completeness (M)

Target: a composed stack is indistinguishable from a native driver with
the same effective caps (spec §8) — closing §0.4 C2/C3. Composition site:
the tier build (`src/fs/tier/tier.h` types; `brix_tier_stack_t.composed`
lazy top; source builders in
`vfs_backend_registry_source.c:379 brix_vbr_source_table[]`).

### W2.1 — relay audit + closure

For each of `sd_cache` / `sd_stage`, every slot the wrapped source
implements gets a relay or a deliberately-narrowed profile row:

| Slot | cache relay | stage relay |
|---|---|---|
| pwrite / ftruncate / fsync | **add** (C2): partial-hit objects are cache-driver-owned; write-intent opens already invalidate — relay to the underlying store object | present |
| preadv / preadv2 | **add**: segment-map over the partial-hit range logic; where a vector spans hit/miss ranges, decline to per-segment pread (measured, not assumed — see Open Question Q3) | **add** (C3): wb objects delegate to the spool fd |
| read_sendfile_fd | present | **add**: the wb spool is a real fd — expose when the requested range is fully spooled |
| truncate_path | **add**: invalidate + forward to source | present |
| staged_path | **add**: expose the fill temp (cache-verify already hooks it via the driver slot on the store — unify) | **add**: the wb spool path |
| space | **add**: report the SOURCE's space (the export's logical capacity), not the cache store's | same |
| enumerate | **add**: forward to source; mirror `CAP_CATALOG` | same |
| recall / residency | **add** explicit forwards — today only the VFS-layer walk (`brix_vfs_residency`) reaches through; moving the walk into the relay gives EVERY consumer the same answer | same |
| dedup_publish / dedup_gc | **add** pass-through to source (phase-88 arming already targets the leaf) | same |
| read_advise | present (cache) | **add** forward |
| copy_range | **add** forward when both objs share the leaf; else decline | same |

Relay skeleton (every forwarder is this shape — one screen, zero policy):

```c
static ngx_int_t
sd_cache_ftruncate(brix_sd_obj_t *obj, off_t len)
{
    sd_cache_obj_state *st = obj->state;
    if (st->src.driver == NULL || st->src.driver->ftruncate == NULL) {
        errno = ENOTSUP;  return NGX_ERROR;
    }
    return st->src.driver->ftruncate(&st->src, len);
    /* + the cache-specific side effect where one exists (invalidate),
     *   done BEFORE the forward, exactly as the open path does. */
}
```

Each relay deletes its W0.1 expectation row (`cache:R1`, `cache:R2`,
`stage:VEC`).

### W2.2 — effective caps + cred_accept derived, not static

At compose time the decorator instance's `caps` become
`own_serving_caps ∪ relay(source_caps)` — with W0.1's implication rules
applied to the composed result — and its effective `cred_accept` mirrors
the leaf's. Implementation point: the tier build where
`brix_tier_stack_t.composed` is constructed (the decorator `init` receives
the source instance; set `inst->caps`/an effective-mask field there).
`brix_vfs_backend_accepts_proxy()` and the kind gate then read the
composed top directly (they keep `ns_leaf` for *dispatch* until W2.3
rules). Extend `brix_vfs_backend_export_info()` with the effective
caps+mask so W0.1's `--composed` runtime mode can check real stacks.
**Tests.** `sdconf` composed profiles: `cache(posix)`, `stage(posix)`,
`cache(stage(mock_xroot))` — shape/caps assertions per W0.2; plus
`composed_accepts_proxy_mirrors_leaf` in the pytest lane.

### W2.3 — ns-twin relay vs leaf-unwrap: write the ADR

Today cred-scoped ns dispatch bypasses decorators via `brix_vfs_ns_leaf()`
(the decorator-dropped-the-credential fix, evolution §5). Two coherent end
states: **(a) ratify unwrap** — decorators never implement ns `_cred`
twins; checker rule R14 enforces their absence; `ns_leaf` is the
documented mechanism — or **(b)** full relay twins on decorators, retire
the unwrap. **Recommendation: (a)** — proven, simpler, decorators hold no
per-user state, one mechanism beats two. Deliverable: a one-page ADR
appended to this file after review (NOT an OP-DECIDE — no
externally-visible behaviour changes; only which internal mechanism is
load-bearing), + R14 in the checker, + regression test
`composed_denymode_zero_origin_traffic` (cache+stage composed export,
deny-mode stat → mock asserts zero origin requests).

---

## W3 — Auth closure across all schemas (L)

Review template for every package = the evolution-doc §5 checklist: bind
at every site · gate before offload · unwrap to the leaf · verify chains
cryptographically · re-resolve at use · dead-letter over retry.

### W3.1 — CephX becomes a first-class kind (M)

**Edit hunks** (append-only; enum values are stable wire-adjacent
identities):

```c
/* sd_cred_types.h — brix_sd_cred_kind_t, after BRIX_SD_CRED_GSS_KRB5 */
    /* CephX keyring credential (phase-104 W3.1): the SELECT-path per-user
     * {ceph_keyring, ceph_user} pair.  sd_ceph is the consumer; declaring
     * the kind lets the gate pre-deny a non-CephX bag on a ceph export
     * instead of silently falling through on mask 0. */
    BRIX_SD_CRED_CEPHX     = 1u << 6
```

```c
/* rados/sd_ceph.c — registry row */
-   /* (no cred_accept)  */
+   .cred_accept = BRIX_SD_CRED_CEPHX,
```

Gate: the SELECT resolver already produces keyring creds
(`ucred_parse.c` `.keyring` reader); tag the produced cred's kind so the
`cred_accept` checks at `vfs_cred.c:336`/`:481` apply uniformly (today
keyring creds slip past because the kind is unnamed and ceph's mask is 0).
**Twins** (`rados/sd_ceph_cred.c` — the per-user conn cache with the
pin/doom lifecycle from the two memory fixes lives here): implement
`stat_cred, unlink_cred, mkdir_cred, rename_cred, setattr_cred (after
B5), getxattr_cred, listxattr_cred, setxattr_cred, removexattr_cred,
opendir_cred, staged_open_cred` — each = the base body over a
checked-out per-user connection:

```c
static ngx_int_t
sd_ceph_stat_cred(brix_sd_instance_t *inst, const char *path,
                  brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    sd_ceph_conn_t *c = sd_ceph_conn_checkout(inst, cred, &err); /* pin */
    if (c == NULL) { errno = err; return NGX_ERROR; }            /* deny stays closed */
    rc = sd_ceph_stat_on(c, path, out);          /* the base body, conn-param'd */
    sd_ceph_conn_unpin(c);
    return rc;
}
```

(Refactor step first: parameterize the base bodies on a connection —
today they take the instance's service connection implicitly. Pure-move,
behaviour-preserving, its own commit.)
**Tests.** `ceph_denymode_stat_zero_service_conns` (deny-mode stat on a
ceph export: conn-cache counters — already exposed for the memory tests —
show zero service checkouts; distinct-service-key fixture so the
difference can't hide) · `ceph_allowpath_ns_as_user` (live: cluster log
names the per-user CephX id for rename/getxattr) ·
`ceph_kind_mismatch_preorigin_eacces` (bearer bag on a ceph export →
`EACCES`, zero cluster traffic) · pin/leak regressions re-run (the >8
eviction + flat-fd legs) since twins multiply checkout traffic.
**Guards/docs.** R11 satisfied; spec §9.6 kind list + mask table rows
(W6); ABI-dirty rebuild flag.

### W3.2 — remote/S3 read-side twins (S)

`getxattr_cred`/`listxattr_cred` (`sd_remote_xattr.c`), `opendir_cred`
(`sd_remote_dir.c`), `server_copy_cred` (`sd_remote.c`) — mechanically
trivial: the SigV4 signer is per-open re-initializable (phase-3 T3
precedent); the tests are the point:
`s3_denymode_{tagread,list,copy}_zero_service_sigs` — the mock records
the access-key id per request; deny-mode legs assert the service key
NEVER signs; allow legs assert the per-user key does.

### W3.3 — http twins ride B7 (same-commit rule; see B7).

### W3.4 — xroot authenticated PRIMARY (M–L)

**Facts.** The registry-selectable `root://` primary bootstraps anonymous
only; authenticated origins are proven on the *cache-fill* role of the
same driver (bearer/ztn AND GSI in-process — evolution era 5). The §14
service-credential block already reaches the registry
(`brix_vfs_backend_set_credential`: `bearer`, `x509_proxy`(+`key`),
`ca_dir`, `sss_keytab`).
**Change.** Wire those fields into the primary-role bootstrap
(`sd_xroot.c` instance/open path → `brix_cache_origin_bootstrap`, where
per-user creds already win over static ones by documented precedence) —
reusing the fill path's auth arms verbatim; no new credential storage.
Per-user delegation then composes exactly as on the fill path.
**Async caveat** (§0.5): the journaled write-back path persists only
key/dir/deny; a *bearer* rides memory on the inline flush only
(`stage_engine.h:80-89`). W3.4 must NOT "fix" this by journaling tokens —
the split is deliberate (secret + expiry). Add the primary-role variants
of the existing deny-mode + lapsed-key dead-letter legs.
**Tests.** `test_cmd_remote_backend.py` gains
`test_remote_backend_{bearer,gsi,sss}_primary` (origin log names the
right identity per arm) · `test_remote_backend_denymode_primary` ·
`test_remote_backend_expired_key_deadletters` (journaled flush,
key removed → dead-letter dir populated, zero origin auth attempts under
service identity).

### W3.5 — the schema × driver × mode sweep (M)

NEW `tests/test_auth_matrix_vfs.py`, one parametrized module; each live
cell asserts **who the origin saw** (fleet origins log DN/subject/
access-key) and **whether the origin was touched at all** on deny. Cell
IDs `AM-<schema>-<backend>-<mode>` (Appendix D):

| schema ↓ / backend → | xroot | http(davs) | remote(S3) | ceph | pblock | posix |
|---|---|---|---|---|---|---|
| GSI / X.509 proxy | SELECT·PASS·deny | SELECT·PASS·deny | kind-EACCES | keyring-SELECT·deny | identity | impersonation |
| WLCG bearer | SELECT·PASS·EXCH·deny | SELECT·PASS·deny | EXCH(STS)·deny | kind-EACCES | identity | impersonation |
| S3 SigV4 (inbound) | mint→PASS (opt-in) | mint→PASS (opt-in) | SELECT·STS·deny | kind-EACCES | identity | impersonation |
| krb5 | EXCH(ccache)·deny | n/a-doc | n/a-doc | n/a-doc | identity | impersonation |
| sss | SSS-inject | n/a-doc | n/a-doc | n/a-doc | identity | impersonation |
| anonymous | service-or-deny | service-or-deny | service-or-deny | service-or-deny | identity(anon) | worker |

(~40 live cells; `n/a-doc` cells become ledger rows; `kind-EACCES` cells
assert the pre-origin kind denial with zero origin traffic.)
**OP-DECIDE (A4):** whether `BRIX_CRED_AUTO` ships enabled-by-default per
export or stays explicit-only — the matrix tests both wirings; the
default is an operator posture call (AUTO maximizes identity fidelity;
explicit maximizes origin-audit predictability). Decision recorded here +
`docs/10-reference/per-user-backend-credentials.md`.

---

## W4 — Front-end conformance (XL; the walls)

### W4.1 — the handle-table wall (L–XL)

**Facts.** `src/protocols/root/connection/fd_table.c` (524 lines) stores
raw fds; `open_resolved_file*` populates; `read/readv/pgread` serve from
it; `zip_member` + `tpc/launch` borrow; today's `sd_obj.driver` gates are
the phase-1 bridge for no-fd backends. Blocks retiring
`brix_vfs_file_fd` (phase-90 §6.1).
**Design.** The table row becomes `{ brix_vfs_file_t *fh; …existing
per-handle state (POSC, checkpoint, cache-reopen)… }`; serve paths take
`brix_vfs_file_sd_obj()` / `sendfile_fd()` / `file_pread()` from the
handle; worker jobs get `brix_vfs_job_set_obj(&fh->obj)` uniformly,
dropping the parallel fd/obj threading. The marked `vfs-seam-allow` raw
calls inside `fd_table.c` (cache reopen, POSC/checkpoint cleanup) are
re-audited: calls that become handle ops lose their markers; genuine
separate-domain ones keep them.
**Landing plan** (the phase-54 playbook — slice, gate, repeat):

| Slice | Content | Files | Gate |
|---|---|---|---|
| S1 | dual-store: row carries fh AND fd; `assert(brix_vfs_file_fd(fh)==fd)` on every access | fd_table.c, open_resolved_file*.c | fleet green; assert never fires over one full suite cycle |
| S2 | `kXR_read` serve path reads via the handle (sendfile verdict + memory path) | read/read.c + file_serve seams | cleartext sendfile throughput + warm-read latency within the phase-54/56 tolerances on the measurement harness |
| S3 | `readv`/`pgread` jobs via `job_set_obj` from the handle | read/readv*, pgread paths | wire-conformance suites byte-identical |
| S4 | `zip_member` (scratch materialization already capability-gated) | zip_member.c | zip suite green |
| S5 | `tpc/launch` borrows the handle | tpc/launch.c | TPC suites green |
| S6 | drop the raw-fd column + the S1 assert | fd_table.c | full fleet |
| S7 | **OP-DECIDE W4.1a** — retire `brix_vfs_file_fd` (grep-verified: remaining callers == this cluster) or ratify a documented survivor rule; execute | vfs.h + callers | `grep -rn brix_vfs_file_fd src/` matches only the ruling |

**Tests.** Per slice: the existing raw-wire read/readv/pgread conformance
helpers re-run; NEW `test_stream_pblock_primary_e2e` (pblock-primary
stream export: open/read/readv/pgread/close over the wire — the no-fd
path end-to-end); S1's assert doubles as the migration's own regression
harness.

### W4.2 — dirlist worker un-gate (M)

**Steps.** (1) flip the gate (default-on for the AIO-pool and io_uring
tiers; event-loop inline fallback stays the synchronous body) behind one
directive so operators can revert without a rebuild; (2) A/B harness:
same directory, both paths, `kXR_dirlist` payload byte-compare across the
four arms (±stat × ±cksum — the job carries
`want_stat`/`want_cksum`/`cksum_algo`); (3) after one green fleet cycle +
the large-directory perf gate (50k-entry listing latency, worker vs
live), delete the live loop's scan body — the handler keeps framing only;
the TOCTOU-safe `dir_fd` per-entry opens move with the scan.
**Tests.** `test_dirlist_worker_ab_byte_identical` (4 arms) ·
`test_dirlist_50k_latency_gate` · `test_dirlist_symlink_out_not_followed`
(both paths, before deletion).

### W4.3 — staged_file ratification (S; OP-DECIDE)

**Baseline (verified §0.5):** writer fronts s3/webdav/gridftp/root
writes; direct `staged_file` use = `webdav/put.c` spool + TPC
temp/markers. **Decision:** (a) **ratify** `compat/staged_file` as an
ALLOW'd below-seam primitive — add its file set to
`tools/ci/check_vfs_seam.py` `_TIER3_ALLOW` (~l.113-121) with a rationale
block:

```python
_TIER3_ALLOW = (
    ...
    # phase-104 W4.3 ruling: compat/staged_file is a BELOW-SEAM primitive.
    # It is async-safe + self-contained (no ctx, no pool); the WebDAV/S3
    # PUT spool and TPC temp/marker files use it by design.  Re-plumbing
    # through ctx-holding vfs_staged would trade away async safety for no
    # accounting gain (evolution doc §6).  Ruled: <date>, OP <name>.
    r"^src/core/compat/staged_file",
)
```

…or (b) migrate the residual spool onto `brix_vfs_writer_staged()`.
**Recommendation: (a).** Either ruling closes the residual; the
`--regen` + rationale + phase-90 register entry land in the same commit.

### W4.4 — metered seam for worker-tier ns mutation (M)

**Design** (the job-executor split applied to observation):

```c
/* vfs_internal.h (or a small vfs_obs.h) */
typedef struct {                     /* filled on the worker, emitted on the loop */
    brix_metric_op_t op;             /* OP_DELETE / OP_RENAME / OP_MKDIR / OP_COPY */
    brix_proto_t     proto;
    size_t           bytes;
    uint64_t         start_ns, end_ns;
    ngx_int_t        rc;  int sys_errno;
    char             path[256];      /* truncated; access-log only          */
} brix_vfs_ns_obs_t;

void brix_vfs_observe_ns_record(const brix_vfs_ns_obs_t *o, ngx_log_t *log);
/* wraps the standard observer pair; loop-only; errno-restoring as ever */
```

Worker-tier callers *optionally* fill one per op (stack struct, zero
allocation); their existing completion callbacks on the event loop emit
it. The raw tier stays pool/metric-free (axiom A5 intact); the
observation rides the completion hop that already exists. Callers wired
this phase: TPC pull (`tpc/outbound/source.c`), S3 multipart assembly,
WebDAV collection COPY/MOVE engines.
**Tests.** `test_tpc_pull_emits_op_metrics` /
`test_multipart_assembly_metrics` (metric-delta around the op) ·
`test_no_double_count_collection_move` (enclosing protocol op + records
sum correctly — the W4.6 tables mark which sites emit).
**Docs.** Spec §12 gains the "worker-ns: observed-on-completion" row (W6).

### W4.5 — fd_cache: implement or delete (S; OP-DECIDE)

`src/fs/vfs/fd_cache.c` = 7 lines (include + design note). Rule it:
implement now (nothing in this phase depends on it) or **delete the TU**
(drop from `./config`; move the design note into the phase-90 register).
**Recommendation: delete** — a placeholder TU is standing drift.

### W4.6 — per-protocol §13 sweeps (M each; webdav · s3 · cvmfs · gridftp · dig/ssi/srr · root LAST)

Per protocol: enumerate EVERY ctx-build site —

```bash
grep -rn "brix_vfs_ctx_init\|brix_vfs_ctx_t " src/protocols/<p>/ | grep -v "\.h:"
```

— and fill the audit table (committed as
`docs/refactor/phase-104-sweeps/<p>.md` when executed):

| file:line | op family | binds cred? | binds mint? | binds deleg? | metered op | probe-vs-stat | sendfile gated? | verdict |
|---|---|---|---|---|---|---|---|---|

Fix failing rows against the spec §13 checklist (resolution via `path/`;
ctx fields complete; no raw export syscalls — tier-3 grep scoped to the
protocol dir; TLS/sendfile fork via `can_sendfile`; probe/quiet in
resolution; errno mapping spot-audit vs §10; no self-metering;
writer/staged for writes). **The completed table is pinned**: a
per-protocol counting test asserts the number and location of ctx sites
(a new site without a table row fails — the rig's both-directions honesty
applied to front ends).
Protocol notes: **webdav/s3** — port the multi-user doc's regression
greps for the five fixed bind sites into the counting test; **cvmfs** —
the phase-68 geo/manifest uncached passthroughs are *documented
exceptions* (protocol-side origin calls via
`brix_vfs_backend_http_endpoint`); record, don't "fix"; **root** — runs
LAST (after W4.1/W4.2 reshape its sites); **dig/ssi/srr** — expected
mostly-read; the sweep documents their ctx usage for the first time.

### W4.7 — origin ns coverage tests (S)

Close the named matrix gaps in `tests/test_ns_mutation_gateways.py`
(37 tests today, POSIX↔http↔xroot): add **gridftp×xroot STOR**
(`test_gw_gridftp_stor_xroot_backend`) and **S3×xroot PUT/DELETE**
(`test_gw_s3_{put,delete}_xroot_backend`) legs — same pattern: one op
through the gateway, POSIX as the oracle, D17 rules asserted
(type-blind delete refused; absent-path ENOENT; noreplace EEXIST).

---

## W5 — gsiftp origin driver conformance envelope (L; tracks phase-91)

Phase-91 owns the build-out; phase-104 owns *the definition of done per
wave*: the W0.2 profile is written FIRST from the phase-91 target (kind
ORIGIN; caps `RANGE_READ` + staged writes + `DIRS` via MLSD; n/a:
fd/sendfile/xattr/random-write/preadv2), and each wave turns profile rows
green instead of defining done ad hoc.

| Phase-91 wave | Profile rows it must turn green |
|---|---|
| serving wave 1 (open/pread/stat) | shape+caps; read round-trip; escape negative; errno facts |
| dir wave (MLSD) | opendir/readdir/closedir; D17 rules; MLSX traversal/control-byte rejects (already unit-tested in `gftp_mlsx` — promoted to standing rig negatives) |
| write wave (STOR staged) | staged family; abort-leaves-nothing; commit-excl EEXIST |
| auth wave | `cred_accept = PROXY_PEM`; `open_cred` + ns twins same-commit; deny-mode zero-traffic; the 227/229 SSRF screen (`net_target.h` re-check before dialling) as a permanent negative |

Registry: census row (`fs_list.h` kind ORIGIN) + scheme (`gsiftp`) land
with serving wave 1 — W0.3 then folds gsiftp into the matrices
automatically; W4.7's gridftp×xroot leg gains a gsiftp-origin variant
when the write wave lands.

---

## W6 — Documentation truth (S)

- Fence-mark (`<!-- sdmatrix:begin/end -->`) and flip W0.3 to enforcing:
  spec §7.3, this file's §0.1.
- Update `src/fs/backend/README.md` per-driver rows; the affected
  `docs/10-reference/xrootd-feature-matrix.md` rows (statvfs-on-gateway,
  chmod-on-remote, tape locality) as their features close;
  evolution-doc §6 — each closed residual becomes a dated "closed" ledger
  entry.
- Publish the **N/A ledger** (`docs/10-reference/vfs-na-ledger.md`) —
  Appendix B seeds it; the W0.3 notes sidecar keeps it in sync.
- Spec §12 gains the worker-ns observation row (W4.4); §9.6 gains the
  CephX kind (W3.1); §5.6's raw-twin warning gains a pointer to the W4.6
  counting tests.

---

## Sequence diagrams

**Rig execution (one profile):**

```
pytest test_sd_conformance.py::test[driver]
  │ fixture up (tmpdir | image | fleet mock | skip_live?)
  │ exec tests/c/sd_conformance --driver X --fixture-env …
  ▼
sd_conformance.c: lookup profile[X]
  1 shape:  extract inst->driver slots  ≟ expect_slots   (both directions)
  2 caps:   brix_sd_caps(inst)          ≟ expect_caps
  3 semantics: open→write→fsync→read (verb core) · noreplace/EEXIST ·
     ENOTEMPTY · ENOENT · escape-reject · staged abort/commit-excl ·
     errno-fact scan
  4 n/a:    every na_slots member NULL ∧ cap absent
  ▼ per-leg TAP lines → pytest asserts + suite `sdconf` aggregation
```

**Deny-mode ceph ns op (the W3.1 target state):**

```
davs stat on ceph export (deny-mode, no user keyring provisioned)
  handler ctx (identity U, bind cred_dir+deny) ─▶ brix_vfs_probe/stat
    gate (vfs_cred.c): SELECT resolves… miss → deny=1 → EACCES
    │            (kind check: bag kind ∉ cred_accept(CEPHX) → same EACCES)
    ▼
  EACCES returned BEFORE any sd_ceph call — conn-cache counters unmoved,
  cluster log silent.  (Today: falls through to the service connection.)
```

**W4.1 dual-store cutover (slice S1→S6):**

```
S1  row{fd, fh}  every access: use fd, assert fh->fd == fd   ← detector
S2+ row{fd, fh}  reads use fh (sd_obj / sendfile verdict); fd kept for
                  not-yet-migrated consumers; assert still armed
S6  row{fh}      fd column + assert deleted; brix_vfs_file_fd callers == 0
rollback at any slice = revert that slice's consumers to fd (column still
present until S6; S6 lands only after one full green fleet cycle on S5)
```

---

## Migration order & per-package gating

```
W0.1 checker (+expectation file) ─┐
W0.2 rig skeleton + posix/pblock/frm-stub profiles ─┤─ merge gate for all below
W0.3 matrix script (report-only) ─┘
  ├─ B1 posix → B3 pblock → B4 cephfsro → B2 block   (local; rig-proving)
  ├─ W2.1 relays + W2.2 derived caps  (kills C2/C3 NULL-slot hazards early)
  │     └─ W2.3 ADR (one page, then R14)
  ├─ B5 ceph ──→ W3.1 CephX kind + twins
  ├─ B6 xroot ─→ W3.4 authenticated primary
  ├─ B7 http (+W3.3 twins) → B8 remote (+W3.2 twins) → B9 frm
  ├─ W3.5 sweep  (after W3.1–W3.4; OP-DECIDE A4 before its config leg)
  ├─ W4.3 + W4.5 decisions early (cheap; unblock guard-list/`./config` edits)
  ├─ W4.6 sweeps: webdav+s3 first (regression-grep ports), then cvmfs,
  │     gridftp, dig/ssi/srr; root LAST (after W4.1/W4.2)
  ├─ W4.7 matrix legs (any time after W0)
  ├─ W4.2 dirlist → W4.4 worker-ns metering → W4.1 handle wall (last; biggest)
  └─ W5 profile-first alongside phase-91 · W6 continuously
```

**Per-package landing checklist** (every Bn/Wn.m): green tree +
`objs/nginx -t` · rig profile row(s) updated and green · W0.1 expectation
rows deleted · 3 tests per new op (success/error/security-neg) · touched
fleet suites green (`manage_test_servers` fleet, ports within the +2000
rule) · ABI-dirty rebuild where flagged · doc rows (W6) in the same
change · no new tier-1/2/3 seam findings · `check_vfs_identity_branch.py`
still zero.

---

## Rollback & safety per workstream

| WS | Rollback story |
|---|---|
| W0 | Guards are additive; expectation file can re-grow a row (with rationale) if a package must back out — the row IS the rollback record |
| W1 Bn | Each package is one commit-set touching one driver dir + its profile; revert = revert the set + restore the expectation/profile rows. New slots are additive (NULL before) — no consumer depends on them until the VFS fallback paths are deleted (B1's dead-fallback deletion is its own commit for this reason) |
| W2 | Relays are additive forwarders; W2.2's derived caps is one compose-site change behind the existing static seed — revert restores static masks. C2/C3 make the PRE-state the dangerous one; do not partially revert W2.1 (all-or-nothing per decorator) |
| W3.1 | Kind bit is append-only; reverting the ceph mask returns to mask-0 behaviour (documented worse, not broken). Twins revert to plain-slot fallback via the maybe_cred forwarders — the deny gate still holds at the VFS layer |
| W3.4 | Config-gated: an export without the credential block keeps anonymous bootstrap; revert = config removal, no code path change |
| W4.1 | Slice-wise; the dual-store column survives until S6; any slice reverts independently (see the cutover diagram) |
| W4.2 | Directive-gated; revert = flip the directive; the live loop body is deleted only after the gate holds one full cycle |
| W4.3/W4.5 | Guard-list / build-list one-liners with rationale; trivially revertible; the phase-90 register records either direction |
| W4.4 | Opt-in records; unwiring a caller removes its metrics only |
| W5 | Profile-first means a reverted phase-91 wave just re-reddens its rig rows (visible, not silent) |

---

## Risk register

| # | Risk | Mitigation |
|---|---|---|
| R-1 | Vtable/kind growth breaks ABI silently | append-only slots & enum values; designated initializers keep omissions NULL; ABI-dirty rebuild discipline on W2/W3.1; never reorder existing fields |
| R-2 | W4.1 regresses the hottest serve paths | phase-54 playbook: per-slice perf gates on the phase-56 §11 measurement harness; dual-store assert step before cutover; zero-copy fast paths out of scope |
| R-3 | W2.2 lets a decorator *widen* beyond its serving ability (e.g. SENDFILE over a MEMFILE source) | W0.1 implication rules run against the composed instance (`--composed`); the relay table is reviewed against §0.1, not caps alone |
| R-4 | W3.4 shifts primary-role trust posture (gateway holds origin service creds for the stream primary) | reuse the §14 credential block + its tests verbatim; no new storage mechanism; bearer-journal split preserved (never persist tokens) |
| R-5 | B7 PROPPATCH xattrs open a new remote write surface | mandatory security-negative tier per slot (name injection, control bytes, ERANGE, cross-origin COPY refusal); D17 probe rules extended to every new op |
| R-6 | Rig origin fixtures make the suite flaky/slow | fleet mocks only (no external endpoints); `skip_live` honoured (SKIP ≠ PASS); pure-C legs carry the MUST assertions so pytest legs are semantic-only; port discipline per the +2000 rule |
| R-7 | Expectation/profile files rot into a new backlog | both-directions failure semantics (stale rows fail; extra slots fail) make rot self-announcing |
| R-8 | B5/B7/B8 advisory-attr divergence between backends | ONE codec (`meta_advisory.{c,h}`) for ceph/S3/davs; cross-backend round-trip test (`http_setattr_advisory_roundtrip_crossbackend`) |
| R-9 | W4.4 double-counts ops (worker record + enclosing protocol op) | records are caller-opt-in; the W4.6 sweep tables mark which sites emit; `test_no_double_count_*` per wired caller |
| R-10 | Line/anchor drift between this plan and the tree | §0 anchors are grep patterns, not gospel; Appendix A re-extraction is step 0 of every package; W0.3 automates the drift for the matrices |
| R-11 | W3.1's base-body parameterization (conn-param'd ceph ops) introduces behaviour drift | pure-move commit first (service conn passed explicitly, byte-identical), twins commit second; live suite between them |
| R-12 | B7's dead-property namespace collides with real user properties on foreign servers | reserved namespace URI + prefix; `listxattr` filters to the reserved namespace only; foreign-prop passthrough explicitly out of scope (ledger) |

---

## Open questions (resolve before the named package)

| Q | Question | Owner package | Default if unresolved |
|---|---|---|---|
| Q1 | Should `range_coalesce.{c,h}` also compile into `libxrdproto` for the client S3 path? | B7 | server-only (client keeps `sd_s3` internal coalescing) |
| Q2 | `sd_xroot` `space`: does the target origin population support path-form `kXR_statvfs`, or is `Qconfig space` the reliable arm? | B6 | implement both, statvfs first, honest `ENOTSUP` if neither |
| Q3 | cache `preadv` across a hit/miss boundary: segment-map or decline-to-pread? | W2.1 | decline-to-pread (correctness first; measure before optimizing) |
| Q4 | B7 dead-prop namespace URI string (operator-visible in foreign-server PROPFINDs) | B7 | `urn:brix:xattr` + `brix:` prefix |
| Q5 | Does the exec MSS adapter need in-place `pwrite` (B9's cap decision)? | B9 | drop the cap (recommendation) |
| Q6 | W4.2 gate directive name + default-on timing (immediately vs one release later) | W4.2 | default-on immediately behind the directive |

---

## Work-breakdown & sizing register

| Package | Size | New TUs | Modified TUs (primary) | New tests (≈) |
|---|---|---|---|---|
| W0.1 | S | 1 script + expectation file | — | 3 |
| W0.2 | M | 2 (rig .c + pytest) | test_c_regression_units.py | rig frame + 11 profiles |
| W0.3 | S | 1 script + notes sidecar | 2 docs (fences) | 2 |
| B1 | S | — | sd_posix.c (+ fallback deletions) | 6 |
| B2 | S–M | 0–1 | sd_block.c | 6 |
| B3 | S | — | sd_pblock.c (+catalog) | 5 |
| B4 | S | — | sd_cephfs_ro.c | 3 |
| B5 | M | — | sd_ceph_object.c, sd_ceph_io.c, sd_ceph.c, unittest | 8 |
| B6 | M | — | sd_xroot_ns.c, sd_xroot_ns_cred.c | 5 |
| B7 | L | 2 (sd_http_xattr.c, range_coalesce.{c,h}) | sd_http_{mutate,dir,read,select}.c, sd_remote.c (shrink) | 14 |
| B8 | M | 0–1 (sd_remote_catalog.c) | sd_remote.c | 4 |
| B9 | S | — | sd_frm.c, sd_frm.h | 3 |
| W2.1 | M | — | sd_cache*.c, sd_stage*.c | composed profiles + 4 |
| W2.2 | S | — | tier build / registry_source.c, export_info | 2 |
| W2.3 | S | ADR section | checker R14 | 1 |
| W3.1 | M | — | sd_cred_types.h, sd_ceph.c, sd_ceph_cred.c, vfs_cred.c | 6 (+re-runs) |
| W3.2 | S | — | sd_remote_{xattr,dir}.c, sd_remote.c | 3 |
| W3.4 | M–L | — | sd_xroot.c (bootstrap), config plumb | 5 |
| W3.5 | M | 1 (test_auth_matrix_vfs.py) | — | ~40 cells |
| W4.1 | L–XL | — | fd_table.c, open_resolved_file*, read paths, zip_member, tpc/launch, vfs.h | per-slice re-runs + 1 e2e |
| W4.2 | M | — | dirlist handler, aio/dirlist.c, 1 directive | 3 |
| W4.3 | S | — | check_vfs_seam.py allow tuple | ruling test |
| W4.4 | M | 0–1 (vfs_obs) | vfs_internal.h + 3 caller sites | 3 |
| W4.5 | S | −1 (delete) | ./config | — |
| W4.6 | M×6 | 6 sweep tables | per-protocol fixes | 6 counting + fixes' tests |
| W4.7 | S | — | test_ns_mutation_gateways.py | 3 |
| W5 | L | profile rows | (phase-91's own) | standing negatives |
| W6 | S | 1 ledger doc | READMEs, spec, matrices | — |

---

## Done criteria

1. `check_sd_caps_slots.py` green with an **empty** expectation file
   (C1–C3 resolved; R1–R14 hold tree-wide, composed instances included
   via `--composed`).
2. The conformance rig covers all 11 census drivers (+ gsiftp on its
   first serving wave) — zero skipped MUST / MUST-if rows, every N/A row
   asserted, both-directions shape checks on, client-variant narrowing
   asserted where flagged.
3. `cred_accept` ≠ 0 on every driver that consumes any credential kind;
   the W3.5 matrix green across all live cells; zero
   service-credential-on-deny-path outcomes anywhere (ceph included);
   the pin/leak Ceph regressions still green under twin traffic.
4. All four decision gates ruled and executed with their guard/doc edits
   landed: W4.1a (fd retirement), W4.3 (staged_file), W4.5 (fd_cache),
   A4 (AUTO default) — plus the W2.3 ADR merged and R14 active.
5. Spec §7.3 / this §0.1 regenerated from source under **enforcing** CI
   drift-check; the N/A ledger published; evolution-doc §6 residuals each
   either closed (dated) or explicitly re-registered in phase-90 with a
   named owner.
6. Full python suite + C-unit lanes green; no new tier-1/2/3 seam
   findings; `check_vfs_identity_branch.py` still zero; the W4.6 ctx-site
   counting tests pinned and green; W4.1/W4.2 perf gates recorded in the
   phase log.

---

## Appendix A — extraction protocol (reproduce before every package)

Slot inventory (per driver; run from repo root):

```bash
for f in posix/sd_posix.c block/sd_block.c pblock/sd_pblock.c \
         rados/sd_ceph.c rados/sd_cephfs_ro.c xroot/sd_xroot.c \
         http/sd_http.c remote/sd_remote.c cache/sd_cache.c \
         stage/sd_stage.c frm/sd_frm.c; do
  echo "== $f =="
  awk '/const brix_sd_driver_t brix_sd_.*driver = \{/,/^\};/' \
      "src/fs/backend/$f" | grep -oE '^\s*\.[a-z_0-9]+' | tr -d ' .'
done
```

Caps/cred_accept: `grep -n '\.caps *=\|\.cred_accept *='
src/fs/backend/*/sd_*.c` then **read each initializer to its terminating
comma** — multi-line ORs bite: the §0.3 xroot/remote masks read as 2-kind
until the continuation lines were checked. `#ifndef XRDPROTO_NO_NGX`
arms: take the server arm for §0.1; record the client narrowing in the
profile's `client_variant`.
Writer consumers: `grep -rln brix_vfs_writer_open src/protocols/`.
Decorator object binding: `grep -n 'driver *=' src/fs/backend/{cache,stage}/*.c`.
Ctx sites per protocol (W4.6): the grep in that section.

## Appendix B — N/A ledger seed rows

| Driver | Absence | One-line reason |
|---|---|---|
| block | ns mutation / xattr / staged / truncate / sendfile | device extents: fixed namespace, opened in place, base offset must be honoured |
| cephfsro | all write slots | read-only by charter (serves a live CephFS it must not mutate) |
| xroot / http / remote | read_sendfile_fd, preadv2, local read_advise | no local fd; MEMFILE serving is the contract |
| ceph | read_advise; dedup | librados exposes no advise; RADOS-native dedup is its own design (phase-90 register) |
| remote | space; recall/residency | S3 exposes no df; Glacier restore = MAY (cost posture) |
| posix | enumerate | the namespace IS the catalog (`ENOTSUP` decline → walk) |
| frm | pread-triggers-recall | forbidden by contract: reads serve online bytes; recall is the explicit verb |
| http(plain) | xattr/setattr/copy/space | plain HTTP origin has no property/copy surface (davs profile carries them) |
| http(davs) | foreign dead-property passthrough | only the reserved `brix:` namespace maps to xattrs (R-12) |

## Appendix C — key file/symbol index for this phase

| Concern | Where |
|---|---|
| Vtable + caps + accessors | `src/fs/backend/sd.h` · `sd_cred_types.h` · `sd_cred_forward.h` · `sd_registry.{h,c}` |
| Gate + delegation | `src/fs/vfs/vfs_cred.c` (593) · `vfs_deleg*.c` · `vfs_cred_internal.h` (`brix_vfs_ns_leaf`) |
| Composition | `src/fs/tier/tier.h` (`brix_tier_cfg_t`/`brix_tier_stack_t`) · `src/fs/vfs/vfs_backend_registry_source.c:379` (`brix_vbr_source_table[]`) · `vfs_backend_registry.h` (`export_info`) |
| Advisory metadata codec | `src/fs/backend/meta_advisory.{c,h}` (`user.xrd.unixattr` / `x-amz-meta-xrd-unixattr`) |
| PROPFIND helpers | `src/fs/backend/http/sd_http_dir.c:347-381` (`sd_http_propfind_issue/_errno`) |
| Range coalescer to extract | `src/fs/backend/remote/sd_remote.c:271` (`sd_remote_preadv`, P80.1) |
| Wire-query pattern (B6) | `src/fs/backend/xroot/sd_xroot.h:98` (`brix_sd_xroot_query_checksum`) · `:86` (`create_origin`) |
| Stage identity record | `src/fs/xfer/stage_engine.h:89` (`brix_stage_cred_t`; bearer inline-only, journal ends at `deny`) |
| Handle table | `src/protocols/root/connection/fd_table.c` (524) |
| Dirlist worker | `src/core/aio/dirlist.c` (166) · `src/protocols/root/dirlist/handler.c` |
| Seam guard allow-lists | `tools/ci/check_vfs_seam.py` (`_RAW_ALLOW` ~l.90, `_TIER3_ALLOW` ~l.113) |
| Fleet | `tests/cmdscripts/manage_test_servers` · `fleet_specs` / `RegistryLauncher` · logs `/tmp/xrd-test/logs/` |
| Suites to extend | `test_ns_mutation_gateways.py` · `test_cmd_remote_backend.py` · `test_cmd_cache_{http_source,s3_origin,xroot_origin}.py` · `test_sd_ceph.py` / `test_ceph_live.py` · `test_pblock_lab_*.py` / `test_pblock_group_multiuser.py` · `test_sd_s3_read_unit.py` · `test_c_regression_units.py` (new suite `sdconf`) |
| New test modules | `tests/c/sd_conformance.c` · `tests/test_sd_conformance.py` · `tests/test_auth_matrix_vfs.py` · `tests/test_ci_guards.py` additions |

## Appendix D — test-name registry (prescriptive)

Naming: rig legs `sdconf:<driver>_<op>_<case>`; pytest
`test_<area>_<behaviour>`; auth matrix cells `AM-<schema>-<backend>-<mode>`
(e.g. `AM-bearer-xroot-passthrough`, `AM-gsi-ceph-deny`). Every package's
"Tests" list above is the registry; a package review checks the diff adds
exactly those names (renames allowed with a table update — the counting
tests keep totals honest). Security-negative legs are suffixed `_reject`,
`_refused`, `_zero_origin`, `_zero_service_*`, `_deadletters` — grep-able
as a class (`pytest -k "reject or refused or zero_"` is the phase's
security lane).

## Appendix E — skeleton conventions

The C/python skeletons in this plan are **shape, not source**: they fix
the signature, the delegation target, the errno facts, and the order of
side effects; they omit logging, arg validation, and style boilerplate.
When implementing: match the surrounding file's comment density and
WHAT/WHY/HOW header style (`coding-standards.md`); every new exported
symbol gets the standard header comment; no skeleton grants license to
reimplement a HELPER it names (the codec, the propfind pair, the
coalescer, the conn cache, the ns verbs, the verb core).
