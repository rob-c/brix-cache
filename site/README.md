# BriX-Cache marketing site

The public advertising site for **BriX-Cache** — a broad-appeal landing page plus
four audience pages (`/for/{sysadmins,physicists,engineers,stakeholders}`). Built
with [Astro](https://astro.build), static output, no client-side framework.

This is the *marketing* site. The technical documentation lives in
[`../docs/`](../docs/) and the source in [`../src/`](../src/).

## Develop

```bash
cd site
npm install
npm run dev        # local dev server with hot reload
npm run build      # static build → site/dist
npm run preview    # serve the built site locally
```

## Design

Neo-brutalist system defined once in `src/styles/global.css`. Color encodes
protocol identity everywhere it appears: `root://` = lime, `davs://` = cyan,
`s3://` = amber. Type: Archivo (display) · IBM Plex Sans (body) · IBM Plex Mono
(commands). Fonts are self-hosted via `@fontsource`, so the site makes no
external requests. Content is grounded in the repository's `README.md` and
`docs/` — no invented capabilities.

### Dark mode

The OS setting is the default, overridable from the header button, which cycles
**auto → light → dark**. Only the surface tokens move — the protocol accents are
byte-identical in both themes, because a lime chip has to mean `root://` either
way.

How the override is wired:

- `localStorage['brix-theme']` holds `light` or `dark`. **Auto stores nothing**,
  so the `prefers-color-scheme` media query stays in charge and later OS changes
  are followed live with no listener.
- An explicit choice writes `data-theme` onto `<html>`. `global.css` therefore
  carries the dark palette twice — once under `@media (prefers-color-scheme:
  dark) { :root:not([data-theme='light']) }`, once under
  `:root[data-theme='dark']`. CSS cannot share a declaration block across an
  `@media` boundary, so **the two copies must be kept in sync**. (`light-dark()`
  would collapse them, but it only takes colours and `--photo-filter` is a
  filter, so it can't carry the whole palette.)
- The theme is applied by an `is:inline` script in `Layout.astro`'s `<head>`, so
  a stored choice never flashes the other theme. The button's own script is
  `is:inline` directly after the element, so it runs during parse: the label is
  right on first paint, and the button ships `hidden` and is only revealed by
  that script — no dead control, and no layout shift.
- With JavaScript off the button never appears and the media query alone drives
  the theme, so the site still follows the OS.

Two traps, both of which produced invisible text before they were fixed:

- **Never pair `background: var(--ink)` with `color: var(--paper)`** on anything
  that contains muted text or internal rules. That pair inverts along with the
  theme, so a hard black block becomes a glaring white slab. Use the `--inv-*`
  tokens (`--inv-bg` / `--inv-fg` / `--inv-panel` / `--inv-muted` / `--inv-rule`),
  which encode *elevation* rather than a literal colour. A plain fg/bg pair with
  nothing inside it — `.btn--ink` — may safely flip. Anything sitting on a
  `.band--ink` surface must take `--inv-*`, never the page tokens.
- **`.band--ink foo` in a page's scoped `<style>` is dead code.** Astro appends
  the component's scope attribute to *every* compound, yielding
  `.band--ink[cid-page] .foo[cid-page]` — but `.band--ink` is rendered by
  `Band.astro`, so it carries Band's cid and never matches. Write
  `:global(.band--ink) .foo`, or style the element with `--inv-*` directly when
  it only ever appears on the inverted surface. Rules in `global.css` are
  unscoped and need neither.

Verify with a contrast audit against both emulated schemes, not by eye — a
`--paper`-coloured foreground on an inverted panel is invisible in a screenshot
and obvious in the numbers.

## Deploy

Pushing to `main` with changes under `site/**` triggers
[`.github/workflows/site.yml`](../.github/workflows/site.yml), which builds and
publishes `site/dist` to the **gh-pages** branch. Configure GitHub Pages to serve
from `gh-pages` / root.

### Base path / URL

`astro.config.mjs` sets `base: '/brix-cache'`, so the site expects to serve at
`https://rob-c.github.io/brix-cache/` — which requires the repository to be named
`brix-cache`. If the repo keeps another name, change `base` to match the repo name.

### Custom domain (optional)

To serve at `https://brix-cache.dev/`:

1. Register the domain and point DNS at GitHub Pages (apex `A`/`AAAA` records, or
   CNAME-flatten to `rob-c.github.io`).
2. Rename `public/CNAME.example` → `public/CNAME` (or set `cname:` in the
   workflow).
3. Set `site: 'https://brix-cache.dev'` and `base: '/'` in `astro.config.mjs`.
