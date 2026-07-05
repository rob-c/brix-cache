# Tools page "why better" expansion — comparison + vignettes (design)

**Date:** 2026-07-05
**Status:** approved (Rob, 2026-07-05)
**Scope:** expand the existing `/tools` page on the BriX-Cache Astro marketing
site (`site/src/pages/tools.astro`); no new pages, no nav changes.

## Goal

Give users concrete reasons the BriX tool suite is better for them, in two
forms (both chosen): a direct-but-factual head-to-head comparison with the
stock XRootD client stack, and user pain-story vignettes. Approach A of three
considered (A = two new bands on `/tools`, B = separate `/why` page,
C = replace the existing Why band).

## Decisions (from brainstorming)

- **Format:** both a comparison band AND scenario vignettes.
- **Tone:** direct but factual — the stock stack is named explicitly, rows
  are limited to verifiable facts, NO performance or reliability-percentage
  claims, no disparagement. One row deliberately concedes the stock stack's
  authority ("it is the reference") to keep the table credible.
- **Placement:** two new bands inside `/tools`; existing bands keep their
  content. Band order becomes: hero → Why these tools (sunken) →
  **The honest comparison** (plain, NEW) → The suite (variant flips to
  sunken) → Mounts & shim (variant flips to plain) → **A day with these
  tools** (sunken, NEW) → Bring your own tools (ink) → CTA. Only the two
  one-word `variant` flips touch existing markup.
- **Claims policy:** landed features only, same as the prior two pages.
  Terminal output in vignettes is illustrative, but every capability shown
  must be landed and traced in the plan's evidence table.

## New band 1 — "The honest comparison"

A two-column table (`the stock XRootD client stack` vs `the BriX suite`),
styled in the site's neo-brutalist system (bordered table, mono headers).
Rows, exactly these six:

| Row | Stock column | BriX column |
|---|---|---|
| Install | C++ client libraries plus their dependency tree | Plain-C binaries over one library — `make` and done |
| Protocol reach | `root://` natively; HTTP via plugin | `root://`, `roots://`, `davs://`, `http(s)://`, `s3://` in the same tools — no plugins |
| Tool sprawl | One binary per micro-tool | Multi-call personalities: five checksum tools and three monitors are symlinks onto two binaries |
| When it breaks | kXR error strings | `xrddiag` check / doctor turn failures into causes and fixes |
| Bad networks | Client-level retries | Reconnect, re-auth, handle reopen, offset resume — one `--max-stall` budget, in every tool |
| Compatibility | It *is* the reference | Validated against the reference — the cross-backend suite runs identical tests against both |

## New band 2 — "A day with these tools"

Three vignette panels (grid-3), each: a bold pain-line title, one sentence of
setup, a terminal mock (`term` classes), and a one-line takeaway.

1. **The transfer that died at 90%.** A 60 GB `xrdcp` over a flaky link;
   mid-transfer reset; the terminal shows reconnect → re-auth → resume at
   offset → done. Takeaway: a flaky link costs time, not the transfer.
2. **The error that explains itself.** `xrddiag check root://…` reports the
   GSI failure's cause (expired proxy) and the fix command
   (`xrdgsiproxy init`) instead of a bare auth error. Takeaway: the doctor
   is built in.
3. **Prove the bytes, end to end.** `xrdstorascan verify root://…//file`
   pulls the bytes, recomputes the checksum, compares against the server's
   answer, prints MATCH. Takeaway: trust is a command, not a hope.

## Implementation notes

- All changes inside `site/src/pages/tools.astro`: two new `<Band>` sections,
  two `variant` attribute flips, page-local styles for the comparison table
  and vignette panels. Table uses a semantic `<table>` for accessibility.
- Vignette capabilities trace to: `client/lib/net/resilient.c` (reconnect /
  re-auth / reopen / offset resume, `--max-stall`), `client/apps/diag/`
  (`diag_check.c`, `diag_doctor.c` — check/doctor subcommands, error
  explanation per `client/apps/README.md`), `client/apps/scan/`
  (`xrdstorascan` phase-1 `verify` per `client/apps/README.md`).
- Comparison rows trace to: `client/apps/README.md` (pure-C, libXrdCl-free;
  xrdcp URL schemes), `client/Makefile` (CKSUM_LINKS/DIAG_LINKS symlinks),
  `CLAUDE.md` (`TEST_CROSS_BACKEND` cross-backend suite). The two stock-side
  cells that describe stock behavior ("root:// natively; HTTP via plugin",
  "client-level retries") are common knowledge in the community and phrased
  minimally; they make no negative claim.

## Verification

- `astro build` green (7 pages, unchanged count); the two new bands present
  in `dist/tools/index.html`; existing bands intact; no stale `xrootd_*`
  branding; no performance claims in the new copy.

## Out of scope

- Home-page or audience-page changes.
- Any benchmark or performance comparison.
- New components or design-system additions.
