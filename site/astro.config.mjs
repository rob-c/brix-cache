// @ts-check
import { defineConfig } from 'astro/config';

// Deployed to GitHub Pages. Project pages live at USER.github.io/<repo>, so the
// base path is the repo name. This is the ONE line to change if the repo keeps a
// different name, or set `base: '/'` and update `site` when a custom domain
// (e.g. https://gnuball.dev) is adopted — see site/public/CNAME.example.
export default defineConfig({
  site: 'https://rob-c.github.io',
  base: '/gnuball',
  trailingSlash: 'ignore',
  build: {
    // Emit /for/engineers/index.html style paths so links work with or without
    // a trailing slash under the GitHub Pages base.
    format: 'directory',
  },
});
