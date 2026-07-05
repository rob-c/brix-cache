# brixMount marketing page — evil-networks narrative (design)

**Date:** 2026-07-05
**Status:** approved (Rob, 2026-07-05)
**Scope:** one new page on the BriX-Cache Astro marketing site (`site/`)

## Goal

A top-level product page for **brixMount** whose whole structure tells one story:
brixMount is hardened and torture-tested for bad networks. Features are
presented, but secondary to the resilience narrative (approach B of three
considered; A = standard product page, C = product page with torture-test
centerpiece band).

## Decisions (from brainstorming)

- **Audience:** both end users (physicists) and sysadmins/operators equally.
- **Placement:** new top-level page `site/src/pages/brixmount.astro`, added to
  the header nav and footer as **brixMount**. Not under `/for/` (brixMount is
  a product, not an audience).
- **Claims policy:** ONLY landed features. Every mechanism named on the page
  is grep-verified against code/tests on main during implementation; anything
  that exists only in a design spec (e.g. `cvmfs_talk`-style introspection) is
  dropped from the page.
- **Design system:** reuse `Layout`, `Band`, `Benefit`, `Cta`, and the
  existing `term` terminal-block styling. No new design system. Accent:
  `root`, or a dedicated 4th accent only if the existing palette mechanism
  (`AccentName` in `site/src/lib/site.ts`) extends cleanly.

## Page structure — five bands

1. **Hero — "Built for networks that want you to fail."**
   Lede: brixMount turns any CVMFS repository or XRootD/EOS endpoint into a
   local directory with one command — engineered on the assumption that the
   network between you and your data is hostile. Hero terminal shows
   `brixMount cvmfs atlas.cern.ch ~/atlas` followed by a read that survives a
   mid-transfer fault (comment lines: link reset mid-read → stall detected in
   seconds → resumed at offset → hash verified).

2. **The threat model.** Short band naming what bad networks actually do:
   connections reset mid-read; transfers that stall silently instead of
   failing; mirrors that go dark; links that drip bytes at 1 B/s; total
   outages. Sets up every band after it.

3. **The defenses.** One card per threat, each mapped to a landed mechanism:
   - stall detection in seconds, not minutes (connect ceiling + throughput
     floor);
   - bounded-backoff reconnect with full re-auth, handle reopen, and offset
     resume;
   - replica/proxy failover with timed blacklist and auto-reset;
   - content-hash verification on every fetched object, so a damaged or
     resumed transfer can never go undetected;
   - serve-from-cache when every upstream is down.

4. **The proof — torture-tested, not hoped-for.** Centerpiece band: the
   suites run through a TCP fault-injection proxy (`tests/c/fault_proxy.c`)
   that resets connections mid-read and injects stalls, latency, and loss;
   tests assert **byte-exact** recovery. Terminal mock of a fault-proxy
   session log. Numbers: dedicated resilience suites (FUSE mid-read faults —
   `tests/test_xrootdfs_resilience.py`; compressed-read faults —
   `tests/test_compression_fuse_resilience.py`; CVMFS failover/stall —
   `tests/run_cvmfs_resilience.sh`, `tests/run_cvmfs_failover.sh`), a netem
   lab (`tests/cvmfs/netem_lab.sh`), part of an ~8,700-test suite with a
   dedicated fault-injection lane.

5. **What you're mounting** (features, deliberately secondary) + CTA.
   Compact strip: the 5 mount types (`cvmfs`, `cvmfs-rw`, `eos`, `root`,
   `roots`) with one-liners; writable overlay (`cvmfs-rw`) with
   `--overlay-list` / `--overlay-reset`; autofs on-demand mounts; shared
   content-addressed cache; full manifest signature-chain verification
   (whitelist → cert fingerprint → manifest). Standard `Cta` closes the page.

## Implementation notes

- New file: `site/src/pages/brixmount.astro`. Nav change in
  `site/src/components/Header.astro` (and footer if it lists pages); if nav
  items come from `site/src/lib/site.ts`, extend there instead.
- Terminal mocks use the existing `term` / `k` / `c` / `mono` classes.
- Copy tone matches the existing pages (confident, concrete, no fluff).

## Verification

- Each claim on the page traced to a landed file/test before the page ships
  (the claim → file table lives in the implementation plan).
- `astro build` green; rebuilt `dist/` contains the page; nav renders on all
  pages.
- No stale branding: no `xrootd_*` directive/metric names, dashboard path is
  `/brix/`.

## Out of scope

- Home-page teaser band for brixMount (possible follow-up).
- Docs for brixMount itself; this is marketing copy only.
- Any spec-only/planned feature claims.
