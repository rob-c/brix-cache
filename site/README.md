# gnuBall marketing site

The public advertising site for **gnuBall** — a broad-appeal landing page plus
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

## Deploy

Pushing to `main` with changes under `site/**` triggers
[`.github/workflows/site.yml`](../.github/workflows/site.yml), which builds and
publishes `site/dist` to the **gh-pages** branch. Configure GitHub Pages to serve
from `gh-pages` / root.

### Base path / URL

`astro.config.mjs` sets `base: '/gnuball'`, so the site expects to serve at
`https://rob-c.github.io/gnuball/` — which requires the repository to be named
`gnuball`. If the repo keeps another name, change `base` to match the repo name.

### Custom domain (optional)

To serve at `https://gnuball.dev/`:

1. Register the domain and point DNS at GitHub Pages (apex `A`/`AAAA` records, or
   CNAME-flatten to `rob-c.github.io`).
2. Rename `public/CNAME.example` → `public/CNAME` (or set `cname:` in the
   workflow).
3. Set `site: 'https://gnuball.dev'` and `base: '/'` in `astro.config.mjs`.
