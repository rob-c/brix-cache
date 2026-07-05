# Tools marketing page — family catalog (design)

**Date:** 2026-07-05
**Status:** approved (Rob, 2026-07-05)
**Scope:** one new page on the BriX-Cache Astro marketing site (`site/`)

## Goal

A top-level **Tools** page covering both sides of the tooling story: the
project's own pure-C client tool suite (front and center, headlined by
drop-in stock compatibility) and the third-party clients the server supports.
Approach A of three considered (A = family catalog, B = advantage-led bands,
C = reference table).

## Decisions (from brainstorming)

- **Scope:** both BriX's own tools AND third-party compatibility, one page;
  our suite leads.
- **Headline advantage:** drop-in stock replacements — stock XRootD tool
  names keep working as multi-call personalities; pure C, no libXrdCl/XRootD
  client stack to install.
- **Placement:** `site/src/pages/tools.astro`, added to `PRODUCT_PAGES` in
  `site/src/lib/site.ts` as `{ label: 'Tools', href: '/tools' }` (renders in
  header nav + footer Project column next to brixMount).
- **Claims policy:** ONLY landed features, verified against
  `client/apps/README.md`, `client/Makefile`, and code. Notably:
  `xrdstorascan` claims are limited to the shipped phase-1 `verify` and
  `bench` modes (later server-engine phases are NOT claimed); the LD_PRELOAD
  shim is claimed as read-path only.
- **Design system:** reuse `Layout`, `Band`, `Benefit`, `Cta`, global
  `panel`/`chip`/`term`/`grid` classes. Accent `root`. No new components.

## Page structure — six bands

1. **Hero — "Your muscle memory still works."** Lede: BriX-Cache ships a
   complete pure-C client toolset and the stock XRootD tool names keep
   working — `xrdcp`, `xrdfs`, `xrdadler32`, `xrdgsiproxy` — with no XRootD
   client stack to install. Hero terminal: `xrdcp root://host//f .`,
   `xrdadler32 f`, plus a comment that stock names are multi-call
   personalities (symlinks, argv[0] dispatch) of a few small binaries.

2. **Why these tools — advantages strip.** Four panels:
   - **Drop-in**: stock tool names invocable as symlinks to multi-call
     binaries (`xrdcksum` absorbs `xrdcrc32c`/`xrdcrc64`/`xrdadler32`/
     `xrdckverify`/`xrdcinfo`; `xrddiag` absorbs `xrdqstats`/`wait41`/
     `mpxstats`) — zero migration cost.
   - **Small and self-contained**: pure C, libXrdCl-free, built on one
     client library, hardened link defaults (RELRO, now, noexecstack).
   - **Every protocol**: the same `xrdcp`/`xrdfs` speak `root://`/`roots://`
     plus `davs://`/`http(s)://`/`s3://`/`s3s://`, local paths, and `-`.
   - **Resilient by default**: tools ride the same reconnect + re-auth +
     offset-resume machinery (`--max-stall`) as brixMount; cross-link to
     `/brixmount`.

3. **The suite — family catalog.** Six panels in a grid, mirroring the
   `client/apps/` families:
   - *Data movement*: `xrdcp` (recursive, ZIP-member, web URLs), `xrdfs`
     (fs ops + interactive shell), `xrd` (swiss-army multi-call: ls/stat/
     cat/cp/du/df/tree/find/locate/query/prepare/stage/evict/explain +
     `battery`/`doctor`/`clockskew`/`mount` subcommands).
   - *Checksums & verification*: `xrdcrc32c`, `xrdcrc64`, `xrdadler32`,
     `xrdckverify`, `xrdcinfo` — one multi-call binary, local or `root://`.
   - *Diagnostics & monitoring*: `xrddiag` (check/bench/watch/topology/
     compare/doctor + human-readable error explanation), `xrdqstats`,
     `mpxstats`, `xrdmapc`, `wait41`.
   - *Storage admin*: `xrdstorascan` — `verify <url>` end-to-end integrity
     (pull bytes, recompute, compare against server checksum), `bench <url>`
     throughput/IOPS/latency sweep over block size × parallelism.
   - *Auth & security*: `xrdgsiproxy` (create/inspect/destroy X.509 proxy),
     `xrdgsitest` (GSI handshake self-test), `xrdsssadmin` (SSS keytab).
   - *Staging*: `xrdprep` (`kXR_prepare`: stage/cancel/evict).

4. **Mounts & the POSIX shim.** Short band: `brixMount` (umbrella FUSE
   front-end — link to `/brixmount`), `xrootdfs` (one binary, async/resilient
   default + `--legacy` synchronous fallback), `libbrixposix_preload.so`
   (LD_PRELOAD POSIX→XRootD read-path shim for unmodified binaries).

5. **Bring your own tools — compatibility strip.** The server side: stock
   `xrdcp`/`xrdfs`/pyxrootd over `root://`, `curl`/browsers/rucio over
   WebDAV, `aws-cli`/`boto3` over S3 — conformance-tested against reference
   XRootD by the cross-backend suite (`TEST_CROSS_BACKEND`).

6. **CTA.**

## Implementation notes

- New file: `site/src/pages/tools.astro`; one-line `PRODUCT_PAGES` addition
  in `site/src/lib/site.ts` (Header/Footer already map `PRODUCT_PAGES`).
- Terminal mocks use existing `term`/`p`/`k`/`c` classes; tool names in
  `mono` chips or plain mono text.
- Copy tone matches existing pages.

## Verification

- Claim → evidence table in the implementation plan; each tool name and
  capability traced to `client/apps/README.md` / `client/Makefile` / code.
- `astro build` green (7 pages after this lands); nav shows Tools on all
  pages; no stale `xrootd_*` metric/directive branding.

## Out of scope

- Per-tool documentation pages; this is one marketing page.
- `xrdstorascan` server-engine phases (inspect/inventory/drift/health) and
  any other unlanded capability.
- pymigrate / Ceph tooling (separate storage-migration story, not the client
  suite).
