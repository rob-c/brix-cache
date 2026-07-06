# Hardening-evidence web summary — /evidence page + repo doc (design)

**Date:** 2026-07-06
**Status:** approved (Rob, 2026-07-06)
**Scope:** one new page on the BriX-Cache Astro marketing site (`site/`) plus
one standalone markdown document in `docs/07-security/`.

## Goal

A web summary presenting **evidence** that BriX-Cache is designed to harden
services for a better user experience. Two deliverables (both chosen): a site
page and a shareable repo document that mirror each other. Structure is the
"evidence ledger" (approach A of three considered; B = UX-outcome-led,
C = case studies).

## Decisions (from brainstorming)

- **Format:** BOTH a site page and a standalone doc.
- **Candor:** FULL — internal postmortems and audits are cited by name as
  evidence of hardening discipline ("hunt, fix, document, regression-test").
- **Structure:** evidence ledger — four evidence classes, each opening with
  the user-visible outcome, every item citing a repo file/doc/test in mono.
- **Placement:** `site/src/pages/evidence.astro`; nav via `PRODUCT_PAGES`
  entry `{ label: 'Evidence', href: '/evidence' }` (order: brixMount, Tools,
  Evidence). Doc at `docs/07-security/hardening-evidence.md`; the site page
  links to the doc's GitHub blob URL.
- **Claims policy:** identical to prior pages — every citation verified to
  exist in the repo before shipping; no performance-comparison claims.

## Site page structure

**Hero (plain, first):** claim stated plainly — "Hardening is the design
brief, not a feature." Lede sets the ground rule: every item on the page
cites a file, document, or test in the repository; nothing is aspirational.
A small term block shows the receipt-style ethos (e.g. a `ls` of the
postmortem doc + test files) rather than a slogan.

**Band 1 — Designed-in defenses (sunken).** Panels, each with a mono
citation line:
- Fail-early config: missing certificates/JWKS/CRLs/directories fail
  `nginx -t` with an explicit `emerg` before traffic is accepted.
- Path confinement as a hard invariant: every wire path goes through the
  canonical resolve helper before `open()`; confined opens use `openat2`
  with `RESOLVE_IN_ROOT`, closing symlink-escape routes.
  (cite: CLAUDE.md INVARIANTS #4, `src/fs/` confined-open primitives)
- One storage seam: all raw file I/O lives in `src/fs/backend/` behind the
  VFS; a CI guard (`tools/ci/check_vfs_seam.sh`) fails the build if a
  handler bypasses it — confinement and identity checks cannot be skipped.
- Hardened builds: `-Werror` (with `format(printf)` attributes that caught a
  real bug), link defaults `-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack`
  (cite: `client/Makefile`, hardening-CFLAGS work).
- Operator-safe observability: wire strings sanitized before logging
  (`brix_sanitize_log_string`), metric labels fixed and low-cardinality.

**Band 2 — Failure-mode engineering (ink; the full-candor band).** Intro:
the strongest evidence is what happened when it broke. Three entries:
- **The semaphore stall postmortem.** Symptom: multi-worker connection
  stalls of 60–450 s on the hot `kXR_open` path. Root cause: lost
  POSIX-semaphore wakeup in shared-memory mutexes. Outcome: repo-wide
  spin+yield mutex rule enforced through a single allocation helper, plus a
  published postmortem
  (cite: `docs/09-developer-guide/postmortem-shmtx-semaphore-stall.md`,
  `src/core/compat/shm_slots.c`).
- **The reboot-lockup audit.** Four stranding classes found and fixed, each
  with a named regression test: dead-holder SHM mutex recovery
  (`test_shm_mutex_recovery.c`), cache-fill lock dead-owner reclaim
  (`test_cache_lock_reclaim.c`), missing origin stall timeout
  (`test_http_origin_stall_timeout.py`), rate-limit gauge leak reset
  (`test_ratelimit_gauge_reset.c`). (Test names verified against `tests/`
  during implementation; drop any that don't exist verbatim.)
- **Absorbing upstream flakiness.** Hardening aimed directly at UX: origin
  stall detection in seconds (connect + throughput floors), force-primary
  retry, stale-if-error serving, fill coalescing so a client storm becomes
  one upstream request (cite: `src/protocols/cvmfs/`,
  `tests/run_cvmfs_resilience.sh`).

**Band 3 — Proof by torture (plain).** The numbers: ~8,700-test suite;
~1,770-test slow lane devoted to resilience/chaos/fault-injection; TCP
fault-injection proxy (`tests/c/fault_proxy.c`) with byte-exact/no-EIO
assertions; netem lab; cross-backend conformance (identical tests against
BriX-Cache and reference XRootD); standing CI guards that keep the
architecture honest between releases (VFS seam, config coverage,
helper-reimplementation, file-size ratchet — `tools/ci/`).

**Band 4 — Integrity guarantees (sunken).** Per-page CRC32c on
`kXR_pgread`/`kXR_pgwrite`; checksum verification at rest (`xrdckverify`,
checksum-at-rest storage); CSI per-read integrity verification; CVMFS
content-addressed fetch with post-fetch hash verify; fault-suite byte-exact
assertions as the end-to-end check. Short band, panels or a compact list.

**CTA (plain):** links to docs + source, plus an inline link to the
standalone evidence doc on GitHub ("take the receipts with you").

## Standalone document

`docs/07-security/hardening-evidence.md` — mirrors the page
section-for-section in markdown: same four evidence classes, same items,
same citations as inline code spans, with relative repo links where they
resolve (e.g. `../09-developer-guide/postmortem-shmtx-semaphore-stall.md`).
Header notes it is the text form of the site's `/evidence` page. No content
appears in one deliverable but not the other (mirror rule).

## Implementation notes

- Nav: one-line `PRODUCT_PAGES` addition; Header/Footer pick it up.
- Page reuses `Layout`, `Band`, `Benefit`/`panel`, `Cta`, `term` classes;
  accent `root`; page-local styles only.
- The GitHub link to the doc uses `REPO_URL` +
  `/blob/main/docs/07-security/hardening-evidence.md`.

## Verification

- Every citation (file, doc, test name, CI guard) verified to exist in the
  repo during implementation; the plan carries the claim→evidence table.
- `astro build` green (8 pages); Evidence in nav on all pages; no stale
  `xrootd_*` branding; no performance-comparison claims.
- Doc and page reviewed side-by-side for the mirror rule.

## Out of scope

- Any new benchmark/performance content.
- Restructuring existing pages (the sysadmins page already links nothing
  here; cross-links can come later).
- Security-disclosure policy content (different document).
