# Tools Page "Why Better" Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the "honest comparison" band and the "day with these tools" vignette band to `/tools`, per `docs/superpowers/specs/2026-07-05-tools-why-better-design.md`.

**Architecture:** All changes live in `site/src/pages/tools.astro`: two new `<Band>` sections, two one-word `variant` flips on existing bands (to keep sunken/plain alternation), and page-local styles for the comparison table (`.cmp*`) and vignettes (`.vg*`). No new components, no nav changes.

**Tech Stack:** Astro 5 static site in `site/` (build with `npx --no-install astro build` from `site/`).

## Global Constraints

- **Tone: direct but factual.** The six comparison rows are fixed verbatim by the spec — do not add rows, and add NO performance or reliability-percentage claims anywhere.
- **Claims policy: landed features only.** Vignette capabilities trace to: `client/lib/net/resilient.c` (reconnect/re-auth/reopen/offset-resume, `--max-stall`), `client/apps/diag/diag_check.c` + `diag_doctor.c` (+ `client/apps/README.md` "human-readable error explanation"), `client/apps/README.md` (`xrdstorascan verify`). Comparison rows trace to `client/apps/README.md`, `client/Makefile` (CKSUM_LINKS/DIAG_LINKS), `CLAUDE.md` (`TEST_CROSS_BACKEND`). Terminal output is illustrative; capabilities are not.
- Branding: **BriX-Cache** / **brixMount** casing; no `xrootd_*` metric/directive names.
- Copy tone matches existing pages; table is a semantic `<table>` for accessibility.
- Commit directly to `main`. Commit trailer:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` + `Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6`

---

### Task 1: Comparison + vignette bands in tools.astro

**Files:**
- Modify: `site/src/pages/tools.astro` (band variants at the `<!-- THE SUITE -->` and `<!-- MOUNTS & SHIM -->` sections; two insertions; style block)

**Interfaces:**
- Consumes: existing `Band` component (props `variant?`, `id?`), global classes `eyebrow`, `display`, `band-head` (page-local), `grid grid-3`, `panel`, `term`/`p`/`k`/`c`, `mono`, `muted`; CSS vars `--ink`, `--paper`, `--band`, `--accent`, `--display`, `--mono`.
- Produces: band ids `compare` and `day` on `/tools`; classes `.cmp`, `.cmp-wrap`, `.vg`, `.vg-t`, `.vg-take` (page-local only).

- [ ] **Step 1: Flip the two band variants**

In `site/src/pages/tools.astro` change:

```astro
  <!-- THE SUITE -->
  <Band id="suite">
```
to
```astro
  <!-- THE SUITE -->
  <Band variant="sunken" id="suite">
```

and change:

```astro
  <!-- MOUNTS & SHIM -->
  <Band variant="sunken" id="mounts">
```
to
```astro
  <!-- MOUNTS & SHIM -->
  <Band id="mounts">
```

- [ ] **Step 2: Insert the comparison band**

Immediately before the `  <!-- THE SUITE -->` comment, insert:

```astro
  <!-- THE HONEST COMPARISON -->
  <Band id="compare">
    <span class="eyebrow">The honest comparison</span>
    <h2 class="display band-head">Same job, side by side.</h2>
    <div class="cmp-wrap">
      <table class="cmp">
        <thead>
          <tr>
            <th scope="col"><span class="visually-hidden">Dimension</span></th>
            <th scope="col" class="mono">the stock XRootD client stack</th>
            <th scope="col" class="mono">the BriX suite</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <th scope="row">Install</th>
            <td>C++ client libraries plus their dependency tree</td>
            <td>Plain-C binaries over one library — <span class="mono">make</span> and done</td>
          </tr>
          <tr>
            <th scope="row">Protocol reach</th>
            <td><span class="mono">root://</span> natively; HTTP via plugin</td>
            <td><span class="mono">root://</span>, <span class="mono">roots://</span>, <span class="mono">davs://</span>, <span class="mono">http(s)://</span>, <span class="mono">s3://</span> in the same tools — no plugins</td>
          </tr>
          <tr>
            <th scope="row">Tool sprawl</th>
            <td>One binary per micro-tool</td>
            <td>Multi-call personalities: five checksum tools and three monitors are symlinks onto two binaries</td>
          </tr>
          <tr>
            <th scope="row">When it breaks</th>
            <td>kXR error strings</td>
            <td><span class="mono">xrddiag</span> check / doctor turn failures into causes and fixes</td>
          </tr>
          <tr>
            <th scope="row">Bad networks</th>
            <td>Client-level retries</td>
            <td>Reconnect, re-auth, handle reopen, offset resume — one <span class="mono">--max-stall</span> budget, in every tool</td>
          </tr>
          <tr>
            <th scope="row">Compatibility</th>
            <td>It <em>is</em> the reference</td>
            <td>Validated against the reference — the cross-backend suite runs identical tests against both</td>
          </tr>
        </tbody>
      </table>
    </div>
  </Band>

```

- [ ] **Step 3: Insert the vignette band**

Immediately before the `  <!-- BRING YOUR OWN TOOLS -->` comment, insert:

```astro
  <!-- A DAY WITH THESE TOOLS -->
  <Band variant="sunken" id="day">
    <span class="eyebrow">A day with these tools</span>
    <h2 class="display band-head">Three moments where it pays off.</h2>
    <div class="grid grid-3">
      <article class="panel vg">
        <h3 class="vg-t">The transfer that died at 90%</h3>
        <p class="muted">A 60 GB pull over a link that drops every few minutes.</p>
        <div class="term" aria-label="Resumed transfer example">
          <div><span class="p">$</span> xrdcp root://dc//run7/big.root .</div>
          <div><span class="c"># 54.1 GB in — connection reset by peer</span></div>
          <div><span class="c"># reconnect → re-auth → reopen → resume at 54.1 GB</span></div>
          <div>[60.0/60.0 GB] <span class="k">done</span> — checksum ok</div>
        </div>
        <p class="vg-take">A flaky link costs you time, not the transfer.</p>
      </article>
      <article class="panel vg">
        <h3 class="vg-t">The error that explains itself</h3>
        <p class="muted">Auth fails five minutes before your slot on the batch farm.</p>
        <div class="term" aria-label="Diagnostic example">
          <div><span class="p">$</span> xrddiag check root://dc.example.org</div>
          <div>auth: GSI handshake <span class="k">failed</span></div>
          <div>cause: proxy certificate expired 3h ago</div>
          <div>fix:   <span class="k">xrdgsiproxy init</span></div>
        </div>
        <p class="vg-take">The doctor is built in — causes and fixes, not error codes.</p>
      </article>
      <article class="panel vg">
        <h3 class="vg-t">Prove the bytes, end to end</h3>
        <p class="muted">After a migration, “it copied” is not the same as “it’s intact”.</p>
        <div class="term" aria-label="End-to-end verify example">
          <div><span class="p">$</span> xrdstorascan verify root://dc//run7/big.root</div>
          <div>local  crc32c <span class="k">8f3d21aa</span></div>
          <div>server crc32c <span class="k">8f3d21aa</span>  MATCH</div>
        </div>
        <p class="vg-take">Trust is a command, not a hope.</p>
      </article>
    </div>
  </Band>

```

- [ ] **Step 4: Add the page-local styles**

In the `<style>` block at the bottom of `tools.astro`, insert before the closing `</style>`:

```css
  .cmp-wrap { overflow-x: auto; }
  .cmp { width: 100%; border-collapse: collapse; border: 3px solid var(--ink); background: var(--paper); }
  .cmp th, .cmp td { border: 2px solid var(--ink); padding: 0.7rem 0.9rem; text-align: left; vertical-align: top; font-size: 0.95rem; }
  .cmp thead th { font-size: 0.72rem; letter-spacing: 0.1em; text-transform: uppercase; background: var(--band); }
  .cmp thead th:last-child { background: var(--accent); }
  .cmp tbody th { font-family: var(--mono); font-size: 0.78rem; letter-spacing: 0.06em; text-transform: uppercase; white-space: nowrap; }
  .cmp td:last-child { font-weight: 600; }
  .visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
  .vg { display: flex; flex-direction: column; gap: 0.6rem; }
  .vg-t {
    font-family: var(--display); font-stretch: 112%; font-weight: 700;
    font-size: 1.2rem; line-height: 1.1;
  }
  .vg .term { font-size: 0.78rem; }
  .vg-take { font-weight: 600; }
```

- [ ] **Step 5: Build and verify**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd/site && npx --no-install astro build`
Expected: `[build] 7 page(s) built` … `Complete!`.

Run: `grep -o 'id="compare"\|id="day"' dist/tools/index.html | sort | uniq -c`
Expected: one `id="compare"` and one `id="day"`.

Run: `grep -o 'The honest comparison\|A day with these tools' dist/tools/index.html | sort -u`
Expected: both strings.

Run: `grep -in 'faster\|% \|percent\|MiB/s\|MB/s\|throughput.*than' dist/tools/index.html`
Expected: no performance-claim hits in the new copy (the word "throughput" alone from the existing xrdstorascan bench description is acceptable; anything comparative is not).

Run: `grep -n 'xrootd_\|/xrootd/' dist/tools/index.html`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
git add site/src/pages/tools.astro
git commit -m "feat(site): honest-comparison and vignette bands on Tools page

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6"
```

---

### Task 2: Final sweep

**Files:**
- Modify: none expected (fixes only if the sweep finds issues)

**Interfaces:**
- Consumes: built `site/dist/` from Task 1.
- Produces: nothing — release gate.

- [ ] **Step 1: Clean rebuild**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd/site && rm -rf dist && npx --no-install astro build`
Expected: `[build] 7 page(s) built`, `Complete!`.

- [ ] **Step 2: Spec conformance check**

Confirm against `docs/superpowers/specs/2026-07-05-tools-why-better-design.md`: band order on `/tools` is hero → why (sunken) → compare (plain) → suite (sunken) → mounts (plain) → day (sunken) → byot (ink) → CTA; exactly six comparison rows with the spec's wording; three vignettes; existing band content untouched. Fix inline if anything is off.

Run: `grep -rn 'xrootd_proxy\|/xrootd/\|xrootd_requests\|xrootd_bytes\|xrootd_auth_total' dist/`
Expected: no output.

- [ ] **Step 3: Commit (only if fixes were needed)**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
git add -u site/
git commit -m "fix(site): Tools why-better final-sweep fixes

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6"
```
