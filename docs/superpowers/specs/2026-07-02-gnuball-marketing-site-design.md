# gnuBall marketing site — design

**Date:** 2026-07-02
**Status:** Approved (design), pending implementation plan
**Owner:** Rob Currie

## Goal

A flashy, standalone GitHub Pages marketing site that advertises **gnuBall** — the
modular WLCG storage interface (an nginx module) that speaks `root://` (XRootD),
WebDAV (`davs://`), and S3, with WLCG x509/GSI + token authentication and
Prometheus-based monitoring.

The site has **broad appeal on the main landing page** plus **four tailored
sub-pages**, one per audience, each arguing why gnuBall is good for that group.

This is a *marketing/advertising* site, distinct from the existing `docs/`
technical documentation tree. It links out to the docs and the GitHub repo; it
does not replace them.

## Audience

Everyone on the front page, then a dedicated sub-page per group:

1. **Grid sysadmins** — run WLCG storage endpoints. Care about drop-in
   deployment, modular parts, ops tooling, single-binary footprint.
2. **Physicists / grid users** — move data, don't run infra. Care that their
   existing tools (`xrdcp`, `xrdfs`, `rucio`, `aws-cli`, `boto3`) just work with
   no client changes.
3. **Infra / open-source engineers** — the architecture story: one nginx binary
   speaks three protocols over a shared core; VFS/backend seam; snap-together
   design.
4. **Funders / stakeholders** — impact and credibility: petabyte-scale HEP data,
   WLCG-native security, project maturity, Apache-2.0 licensing.

## Visual direction

**Neo-brutalist** (chosen from four explored directions: terminal/phosphor,
cosmic/particle-physics, engineering-blueprint, neo-brutalist).

Design system:
- Light background (`#fafaf9`), near-black ink (`#0a0a0a`).
- Hard borders (2–3px solid black) and hard offset shadows (`4px 4px 0 #0a0a0a`).
- Punchy accent blocks: yellow `#facc15`, lime `#a3e635`, cyan `#67e8f9`.
- Huge, tightly-tracked display type for headings; system sans for body;
  monospace (`ui-monospace`) for command snippets and protocol tags.
- One dark inverted section ("Why gnuBall for you") for contrast.
- High contrast, memorable, modern-OSS energy. No dark-mode toggle.

## Site map

| Path | Purpose |
|---|---|
| `/` | Main landing page (broad appeal) |
| `/for/sysadmins/` | Why gnuBall for grid sysadmins |
| `/for/physicists/` | Why gnuBall for physicists / grid users |
| `/for/engineers/` | Why gnuBall for infra / OSS engineers |
| `/for/stakeholders/` | Why gnuBall for funders / stakeholders |

Shared **header** (nav to the four sub-pages + Docs link + GitHub star link) and
shared **footer** (license, repo link) across all pages.

### Homepage section order (approved via mockup)

1. **Nav bar** — wordmark + nav (Docs · Protocols · Who it's for · GitHub).
2. **Hero** — headline "The whole HEP data stack in one binary.", subhead on the
   snap-together value prop, two CTAs (Get started → docs, View on GitHub), and a
   live command snippet (`xrdcp root://…` with a note that s3:// and davs:// hit
   the same server).
3. **Three protocols** — three cards: `root://` (native XRootD; xrdcp, xrdfs,
   pyxrootd, TPC), **WebDAV** (`davs://` for curl, rucio, browsers), **S3**
   (SigV4 REST for aws-cli, boto3).
4. **How it plugs in** — horizontal flow diagram: clients → nginx event loop +
   module → shared core (auth · cache · metrics) → POSIX / `root://` backend.
5. **Auth + Observability strip** — two columns: WLCG-native auth (x509/GSI,
   VOMS, bearer tokens + scopes, enforced before any byte moves) and
   observability (Prometheus `/metrics`, access logs, live dashboard —
   read & monitor by identity).
6. **Why gnuBall for you** — dark inverted section, four tiles linking to the
   audience sub-pages.
7. **Closing CTA + footer** — "Point your existing clients at it. Nothing to
   change." + Read the docs CTA + license/repo footer.

Each sub-page reuses the design system: a focused hero, 3–5 benefit blocks
framed for that audience, relevant command/config snippets or facts, and a CTA
back to the docs and repo.

## Content sourcing

All copy is condensed from existing, authoritative repo material — primarily
`README.md` and the `docs/` tree (value prop, architecture diagrams, protocol,
auth, and metrics facts). **No invented capabilities or benchmarks**; claims stay
grounded in what the repository already states. Where the README references
CERN/SLAC/Fermilab and petabyte scale as context, the site mirrors that framing
without adding unverifiable specifics.

## Tech stack

- **Astro 4**, static output (`output: 'static'`), zero client-side JS by
  default. Fast, no runtime framework, well-suited to GitHub Pages.
- **Components:** one shared `Layout.astro` (header/footer/`<head>`), small
  presentational `.astro` components for repeated blocks (protocol card, benefit
  block, CTA). Pages are `.astro` files under `src/pages/`.
- **Styling:** one global CSS file (`src/styles/global.css`) holding the
  neo-brutalist design tokens and component classes. Scoped `<style>` blocks only
  where genuinely local.
- **No** blog, search, analytics, CMS, or dark mode (YAGNI).

## Project layout

```
site/
  package.json
  astro.config.mjs
  src/
    layouts/Layout.astro
    components/{Header,Footer,ProtocolCard,Benefit,Cta}.astro
    pages/
      index.astro
      for/{sysadmins,physicists,engineers,stakeholders}.astro
    styles/global.css
  public/
    favicon.svg
    CNAME            # commented/placeholder — fill in for custom domain
```

Kept entirely separate from the existing `docs/` markdown tree.

## Deploy

- **Source** lives on `main` under `site/`.
- **GitHub Action** `.github/workflows/site.yml`: triggers on push to `main`
  affecting `site/**` (plus manual `workflow_dispatch`). Steps: checkout →
  setup Node → `npm ci` + `npm run build` in `site/` → publish `site/dist/` to
  the **`gh-pages`** branch via `peaceiris/actions-gh-pages`.
- GitHub Pages is configured (repo Settings → Pages) to serve from the
  `gh-pages` branch, root.

### Base path / URL (assumption to confirm)

GitHub project-pages URLs are `USER.github.io/<repo-name>`. This repo is
currently **`nginx-xrootd`**, so as-is the site serves at
`https://rob-c.github.io/nginx-xrootd/`.

The requested URL is `https://rob-c.github.io/gnuball/`. To get that, the repo
must be **renamed to `gnuball`** (or a custom domain used). The design proceeds
with:

```js
// astro.config.mjs
site: 'https://rob-c.github.io',
base:  '/gnuball',   // <-- matches requested URL; change to '/nginx-xrootd'
                     //     if the repo keeps its current name
```

`base` is referenced through Astro's `import.meta.env.BASE_URL` / `<base>` so all
internal links and asset URLs resolve correctly under the subpath. **This is the
single line to change** if the repo name differs or a custom domain is adopted.

### Custom domain (`gnuball.dev`) — optional, documented not built

GitHub Pages supports a custom apex domain but does **not** register it. To adopt
`gnuball.dev` later:

1. Register `gnuball.dev` at a registrar (`.dev` is HSTS-preloaded → HTTPS
   mandatory; Pages provisions a free Let's Encrypt cert).
2. DNS: four `A` records → `185.199.108–111.153` and four `AAAA` records →
   `2606:50c0:800{0..3}::153`, or ALIAS/CNAME-flatten the apex to
   `rob-c.github.io`.
3. Repo Settings → Pages → set custom domain (writes `CNAME`), enable "Enforce
   HTTPS".
4. Change `astro.config.mjs` to `site: 'https://gnuball.dev'`, `base: '/'`.

A commented `site/public/CNAME` placeholder ships ready to fill in.

## Testing / verification

- `npm run build` succeeds with zero errors/warnings.
- `astro check` / link audit: no broken internal links; every sub-page reachable
  from the homepage and vice-versa; every internal link honors `base`.
- Local preview (`npm run preview`) renders all five pages correctly under the
  configured `base`.
- Responsive sanity check: hero, protocol cards, and "who it's for" tiles
  reflow on narrow viewports (no horizontal scroll).
- Action dry-run: workflow builds on a push to `main` touching `site/**` and
  publishes to `gh-pages`.

## Out of scope (YAGNI)

Blog, full-text search, analytics/telemetry, dark-mode toggle, CMS, i18n,
interactive demos, and any server-side component. Static site only.

## Open assumptions

1. Repo rename to `gnuball` **or** acceptance of `/nginx-xrootd` base path (one
   line). Built as `/gnuball` per request.
2. Custom domain is documented and wired for easy enablement, but not activated
   in this work.
3. Deploy uses the `gh-pages` branch (per request) via `peaceiris/actions-gh-pages`,
   rather than the newer Pages-artifact deployment.
