# brixMount Marketing Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a top-level `/brixmount` page to the BriX-Cache marketing site (`site/`) that tells the evil-networks narrative from `docs/superpowers/specs/2026-07-05-brixmount-page-design.md`.

**Architecture:** One new Astro page reusing the existing neo-brutalist design system (`Layout`, `Band`, `Benefit`, `Cta`, global `term`/`panel`/`grid` classes). Nav plumbing goes through a new `PRODUCT_PAGES` list in `site/src/lib/site.ts` consumed by `Header.astro` and `Footer.astro`. No new design system, accent `root`.

**Tech Stack:** Astro 5 static site in `site/` (build with `npx --no-install astro build` from `site/`). No JS runtime on the page.

## Global Constraints

- **Claims policy: ONLY landed features.** Every mechanism named on the page must appear in the claim→evidence table below. Do not add capabilities from design specs (no `cvmfs_talk` introspection, no client-side geo-sort, no throughput-floor claim for the *client* — `LOW_SPEED` stall floors are server-side only).
- Branding: product is **BriX-Cache**, the mount client is **brixMount** (exact casing). No `xrootd_*` directive or metric names; dashboard path is `/brix/`.
- All internal links via `url()` from `site/src/lib/site.ts` (GitHub Pages base-path safety).
- Copy tone matches existing pages: confident, concrete, no fluff, no exclamation marks.
- Commit directly to `main` (no branches — standing repo rule). Commit trailer:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` + `Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6`

## Claim → evidence table (verified 2026-07-05)

| Page claim | Landed evidence |
|---|---|
| `brixMount <type> <endpoint> <mountdir>`; types `cvmfs`, `cvmfs-rw`, `eos`, `root`, `roots`; `--overlay-list` / `--overlay-reset` | `client/apps/fs/brixmount.c:37-40,122-126` |
| Connect ceiling caps TCP+handshake+TLS+login; per-op I/O cap; backoff with jitter ("a stalled handshake should fail in seconds") | `client/lib/net/nettmo.c` header comment |
| Reconnect + full re-auth + handle reopen + offset resume + bounded backoff, one patience budget (`--max-stall`) | `client/lib/net/resilient.c:5,110-122` |
| Replica+proxy failover; timed blacklist with first-failure probation, capped backoff, auto-reset; all-blacklisted → offline mode | `shared/cvmfs/failover/failover.h:4-15,29-48,81` |
| Content-addressed fetch, hash-verified retry, offline cache mode | `client/apps/fs/brixcvmfs.c:6-7`, `shared/cvmfs/object/`, `shared/cvmfs/fetch/fetch.h:52` |
| Failed catalog refresh keeps current catalog serving (offline-tolerant) | `shared/cvmfs/client/client.h:81` |
| Manifest trust chain: whitelist → cert fingerprint → manifest signature | `shared/cvmfs/signature/{whitelist,verify,manifest}.c` |
| Writable overlay: copy-up, whiteouts, local changes in `.brixwrites/`, list/reset CLI | `client/apps/fs/brixcvmfs_rw.c`, `client/lib/fs/overlay.c` |
| autofs on-demand mounts under `/cvmfs/<repo>` | `deploy/cvmfs/mount.cvmfs`, `deploy/cvmfs/auto.cvmfs`, `tests/run_mount_cvmfs_live.sh` |
| TCP fault-injection proxy: resets mid-read, stalls, latency | `tests/c/fault_proxy.c` |
| FUSE suites assert byte-exact recovery, no EIO surfaced | `tests/test_xrootdfs_resilience.py:7,168-207`, `tests/test_compression_fuse_resilience.py` |
| CVMFS failover/stall suites + netem lab | `tests/run_cvmfs_resilience.sh`, `tests/run_cvmfs_failover.sh`, `tests/cvmfs/netem_lab.sh` |
| ~8,700-test suite; ~1,770-test slow lane incl. resilience/chaos/fault-injection | `tests/README.md:3,12` |

---

### Task 1: Nav plumbing — `PRODUCT_PAGES` in site.ts, Header, Footer

**Files:**
- Modify: `site/src/lib/site.ts` (after the `AUDIENCES` export, line 74)
- Modify: `site/src/components/Header.astro:2,14-16`
- Modify: `site/src/components/Footer.astro:2,20-25`

**Interfaces:**
- Consumes: existing `NavItem` interface and `url()` helper in `site/src/lib/site.ts`.
- Produces: `export const PRODUCT_PAGES: NavItem[]` with one entry `{ label: 'brixMount', href: '/brixmount' }` — Task 2's page must live at that route.

- [ ] **Step 1: Add `PRODUCT_PAGES` to site.ts**

Append after the `AUDIENCES` array in `site/src/lib/site.ts`:

```ts

/** Product pages shown in the primary nav after the audience links. */
export const PRODUCT_PAGES: NavItem[] = [
  { label: 'brixMount', href: '/brixmount' },
];
```

- [ ] **Step 2: Render it in Header.astro**

Change line 2 to:

```astro
import { url, REPO_URL, DOCS_URL, AUDIENCES, PRODUCT_PAGES } from '../lib/site';
```

Insert between the `AUDIENCES.map` block and the Docs link (after line 16):

```astro
      {PRODUCT_PAGES.map((p) => (
        <a href={url(p.href)} class:list={['nav-link', { on: isActive(p.href) }]}>{p.label}</a>
      ))}
```

- [ ] **Step 3: Render it in Footer.astro**

Change line 2 to:

```astro
import { url, REPO_URL, DOCS_URL, LICENSE, AUDIENCES, PRODUCT_PAGES } from '../lib/site';
```

In the "Project" footer column, insert as the first links (before the Documentation link on line 22):

```astro
      {PRODUCT_PAGES.map((p) => <a href={url(p.href)}>{p.label}</a>)}
```

- [ ] **Step 4: Build and verify the nav renders on every page**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd/site && npx --no-install astro build`
Expected: `[build] 5 page(s) built` … `Complete!` (page count becomes 6 after Task 2).

Run: `grep -c 'brixMount' dist/index.html dist/for/sysadmins/index.html`
Expected: ≥2 per file (header + footer). The nav link targets a page that doesn't exist until Task 2 — fine: nothing is pushed or deployed by this plan, and Task 2 follows immediately.

- [ ] **Step 5: Commit**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
git add site/src/lib/site.ts site/src/components/Header.astro site/src/components/Footer.astro
git commit -m "feat(site): brixMount entry in primary nav and footer

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6"
```

---

### Task 2: The `/brixmount` page

**Files:**
- Create: `site/src/pages/brixmount.astro`

**Interfaces:**
- Consumes: `Layout` (props `title`, `description`, `accent`), `Band` (props `variant?`, `id?`, `first?`), `Benefit` (props `marker`, `title`, slot body), `Cta` (props `title`, `note?`); global classes `eyebrow`, `display`, `lede`, `muted`, `mono`, `stack`, `grid grid-2/grid-3`, `panel panel--hover`, `chip chip--root/--dav/--s3`, `term`, `term-title`, `term .p/.k/.c`, `btn btn--accent`.
- Produces: the route `/brixmount` that Task 1's `PRODUCT_PAGES` entry points at.

- [ ] **Step 1: Write the page**

Create `site/src/pages/brixmount.astro` with exactly this content:

```astro
---
import Layout from '../layouts/Layout.astro';
import Band from '../components/Band.astro';
import Benefit from '../components/Benefit.astro';
import Cta from '../components/Cta.astro';
import { REPO_URL, DOCS_URL } from '../lib/site';

// What a bad network actually does — each threat is answered by exactly one
// defense card in the band below, in the same order.
const threats = [
  { t: 'Resets connections mid-read', d: 'A firewall RST-injects 40 GB into your 60 GB file.' },
  { t: 'Stalls without failing', d: 'The TCP handshake completes, then the link black-holes bytes. No error, ever.' },
  { t: 'Mirrors go dark', d: 'The nearest replica stops answering ten minutes into your job.' },
  { t: 'Corrupts what arrives', d: 'Bytes land, but they are not the bytes the repository published.' },
  { t: 'Tampers in transit', d: 'A hostile middlebox serves you a catalog the project never signed.' },
  { t: 'Disappears entirely', d: 'The uplink dies. Your batch farm does not stop asking for files.' },
];
---

<Layout
  title="brixMount"
  description="brixMount turns any CVMFS repository or XRootD/EOS endpoint into a local directory with one command — a hardened FUSE client engineered and torture-tested for bad networks."
  accent="root"
>
  <!-- HERO -->
  <Band first={true}>
    <div class="bm-hero">
      <div class="stack">
        <span class="eyebrow">brixMount — hardened FUSE client</span>
        <h1 class="display">Built for networks<br />that want you to fail.</h1>
        <p class="lede">
          brixMount turns any CVMFS repository or XRootD/EOS endpoint into a local directory
          with one command — engineered on the assumption that the network between you and
          your data is hostile.
        </p>
        <div class="bm-actions">
          <a class="btn btn--accent" href={DOCS_URL}>Get started →</a>
          <a class="btn" href={REPO_URL}>View source ↗</a>
        </div>
      </div>
      <div class="term" aria-label="brixMount surviving a mid-read fault">
        <div class="term-title">one command, hostile network</div>
        <div><span class="p">$</span> brixMount cvmfs atlas.cern.ch ~/atlas</div>
        <div><span class="p">$</span> sha1sum ~/atlas/sw/setup.sh</div>
        <div class="mt"><span class="c"># link reset mid-read → reconnect, re-auth, resume at offset</span></div>
        <div><span class="c"># object hash re-verified on arrival — byte-exact, no EIO</span></div>
        <div><span class="k">3f2a…d41c</span>  /home/you/atlas/sw/setup.sh</div>
      </div>
    </div>
  </Band>

  <!-- THREAT MODEL -->
  <Band variant="ink" id="threats">
    <span class="eyebrow">The threat model</span>
    <h2 class="display band-head">What a bad network actually does.</h2>
    <p class="lede muted bm-intro">
      Hotel wifi, an overloaded site uplink, a misbehaving inline firewall, a mirror
      mid-meltdown — from a mount's point of view they are all the same adversary.
      brixMount assumes all of it, all the time.
    </p>
    <div class="grid grid-3">
      {threats.map((th, i) => (
        <article class="panel bm-threat">
          <span class="bm-threat-n mono">{String(i + 1).padStart(2, '0')}</span>
          <h3 class="bm-threat-t">{th.t}</h3>
          <p class="muted">{th.d}</p>
        </article>
      ))}
    </div>
  </Band>

  <!-- DEFENSES -->
  <Band variant="sunken" id="defenses">
    <span class="eyebrow">The defenses</span>
    <h2 class="display band-head">One answer per threat. All of them landed code.</h2>
    <div class="grid grid-2">
      <Benefit marker="01 · resets" title="Reads that outlive the connection">
        <p>
          A dropped or reset link triggers reconnect, full re-authentication, handle reopen,
          and offset resume — inside one patience budget (<span class="mono">--max-stall</span>),
          with bounded exponential backoff and jitter so a thousand clients don't re-hammer a
          flapping link in lockstep. The read completes; the application never sees it.
        </p>
      </Benefit>
      <Benefit marker="02 · stalls" title="Fail in seconds, not minutes">
        <p>
          A connect ceiling caps the whole bring-up — TCP, protocol handshake, TLS, login — so
          a black-holed connection becomes a prompt, retryable failure instead of a hung mount.
          A separate per-operation I/O cap patrols steady state, because a stalled handshake and
          a legitimate large read deserve very different patience.
        </p>
      </Benefit>
      <Benefit marker="03 · dead mirrors" title="Failover with a memory">
        <p>
          Replica and proxy failover with a timed blacklist: first failure earns a short
          probation, repeat offenders back off to a capped interval, recovered endpoints snap
          back on success. When a mirror dies mid-job, the next fetch has already routed around it.
        </p>
      </Benefit>
      <Benefit marker="04 · corruption" title="Every object hash-verified">
        <p>
          Content comes from a content-addressed store, and every fetched object is verified
          against its hash on arrival. A damaged transfer, a truncated resume, a byte-flipping
          middlebox — none of it can go undetected, which is also what makes retrying against a
          <em>different</em> mirror mid-file safe.
        </p>
      </Benefit>
      <Benefit marker="05 · tampering" title="Trust is verified, not assumed">
        <p>
          CVMFS manifests are accepted only through the full trust chain — repository whitelist,
          certificate fingerprint, manifest signature. A middlebox can drop your packets, but it
          can't hand you a catalog the repository never signed.
        </p>
      </Benefit>
      <Benefit marker="06 · outages" title="Offline is a mode, not an error">
        <p>
          When every replica and proxy is blacklisted, brixMount drops to cache-only serving
          from its local content-addressed cache, and a failed catalog refresh keeps the current
          catalog serving. Total outage upstream; the mount keeps answering.
        </p>
      </Benefit>
    </div>
  </Band>

  <!-- PROOF -->
  <Band variant="ink" id="proof">
    <div class="grid grid-2 bm-proof">
      <div class="stack">
        <span class="eyebrow">The proof</span>
        <h2 class="display band-head">Torture-tested, not hoped-for.</h2>
        <p class="muted">
          Every claim above is enforced by tests, not marketing. The FUSE suites run through a
          TCP fault-injection proxy (<span class="mono">fault_proxy.c</span>) that resets
          connections mid-read and injects stalls and latency on command — and the tests assert
          <strong>byte-exact</strong> recovery with no <span class="mono">EIO</span> ever
          surfaced to the application.
        </p>
        <p class="muted">
          Around it: dedicated CVMFS failover and upstream-stall suites, a
          <span class="mono">netem</span> network-emulation lab, and compressed-read fault
          coverage — inside a ~8,700-test suite whose slow lane (~1,770 tests) is devoted to
          resilience, chaos, and fault injection.
        </p>
      </div>
      <div class="term" aria-label="Fault-injection test session">
        <div class="term-title">tests/test_xrootdfs_resilience.py · via fault_proxy</div>
        <div><span class="c"># inject: connection RESET mid-transfer</span></div>
        <div>recovered transparently, byte-exact <span class="k">PASS</span></div>
        <div class="mt"><span class="c"># inject: stall, then short outage window</span></div>
        <div>detected in seconds, resumed at offset <span class="k">PASS</span></div>
        <div class="mt"><span class="c"># inject: high-latency link</span></div>
        <div>transfer byte-exact <span class="k">PASS</span></div>
        <div class="mt"><span class="c"># applications saw zero EIO across all faults</span></div>
      </div>
    </div>
  </Band>

  <!-- WHAT YOU'RE MOUNTING -->
  <Band id="mounts">
    <span class="eyebrow">What you're mounting</span>
    <h2 class="display band-head">One command. Five mount types.</h2>
    <div class="grid grid-3">
      <article class="panel panel--hover">
        <span class="chip chip--root mono">cvmfs</span>
        <h3 class="bm-mount-t">CVMFS-brix</h3>
        <p class="muted">
          Native CVMFS repositories as a read-only mount: SQLite catalogs, content-addressed
          fetch, the full signature trust chain, and a shared local cache. autofs on-demand
          mounting under <span class="mono">/cvmfs/&lt;repo&gt;</span> works stock-style.
        </p>
      </article>
      <article class="panel panel--hover">
        <span class="chip chip--dav mono">cvmfs-rw</span>
        <h3 class="bm-mount-t">CVMFS-brix, writable</h3>
        <p class="muted">
          The same repository plus a local writable overlay: create, edit, and delete on top of
          read-only software stacks. Your changes live in a plain, inspectable directory —
          list them with <span class="mono">--overlay-list</span>, discard with
          <span class="mono">--overlay-reset</span>.
        </p>
      </article>
      <article class="panel panel--hover">
        <span class="chip chip--s3 mono">eos · root · roots</span>
        <h3 class="bm-mount-t">XRootDFS-brix</h3>
        <p class="muted">
          Any XRootD or EOS endpoint as a POSIX directory, over
          <span class="mono">root://</span> or TLS <span class="mono">roots://</span> — with the
          same reconnect-and-resume machinery underneath every read.
        </p>
      </article>
    </div>
    <div class="term bm-types" aria-label="Mount type examples">
      <div><span class="p">$</span> brixMount cvmfs    atlas.cern.ch           ~/atlas <span class="c"># read-only repo</span></div>
      <div><span class="p">$</span> brixMount cvmfs-rw atlas.cern.ch           ~/atlas <span class="c"># + writable overlay</span></div>
      <div><span class="p">$</span> brixMount eos      root://eoslhcb.cern.ch  ~/eos   <span class="c"># XRootD/EOS backend</span></div>
      <div><span class="p">$</span> brixMount --overlay-list ~/atlas                   <span class="c"># what have I changed?</span></div>
    </div>
  </Band>

  <Band variant="sunken">
    <Cta
      title="Mount it once. Stop thinking about the network."
      note="brixMount ships with BriX-Cache — the resilience suites above run on every release."
    />
  </Band>
</Layout>

<style>
  .bm-hero { display: grid; gap: 2.5rem; align-items: center; }
  @media (min-width: 900px) { .bm-hero { grid-template-columns: 1.05fr 0.95fr; gap: 3rem; } }
  .bm-actions { display: flex; gap: 0.8rem; flex-wrap: wrap; }
  .bm-intro { margin: 0.4rem 0 1.6rem; }
  .band-head { margin: 0.5rem 0 1.4rem; max-width: 24ch; }
  .bm-threat-n { font-size: 0.72rem; letter-spacing: 0.12em; color: var(--accent); }
  .bm-threat-t {
    font-family: var(--display); font-stretch: 112%; font-weight: 700;
    font-size: 1.15rem; line-height: 1.1; margin: 0.35rem 0 0.5rem;
  }
  .bm-proof { align-items: start; }
  .bm-mount-t {
    font-family: var(--display); font-stretch: 112%; font-weight: 700;
    font-size: 1.3rem; margin: 0.6rem 0 0.5rem;
  }
  .bm-types { margin-top: 1.4rem; }
  .term .mt { margin-top: 0.6rem; }
</style>
```

- [ ] **Step 2: Build and verify the page exists**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd/site && npx --no-install astro build`
Expected: `[build] 6 page(s) built` … `Complete!` and a `src/pages/brixmount.astro → /brixmount/index.html` line.

- [ ] **Step 3: Verify claims and branding in the built page**

Run: `grep -c 'brixMount' dist/brixmount/index.html`
Expected: ≥10.

Run: `grep -o '<title>[^<]*</title>' dist/brixmount/index.html`
Expected: `<title>brixMount · BriX-Cache</title>`

Run: `grep -n 'xrootd_\|/xrootd/' dist/brixmount/index.html`
Expected: no output (exit 1) — no stale branding.

Cross-check the page's mechanisms against the claim→evidence table in this plan's header: every named mechanism (offset resume, connect ceiling, timed blacklist, hash verify, trust chain, cache-only mode, overlay list/reset, autofs, fault proxy, byte-exact/no-EIO, test counts) must have its table row. If you added any claim not in the table, verify it against the repo the same way or remove it.

- [ ] **Step 4: Commit**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
git add site/src/pages/brixmount.astro
git commit -m "feat(site): brixMount evil-networks product page

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6"
```

---

### Task 3: Final sweep — full-site build check + spec verification

**Files:**
- Modify: none expected (fixes only if the sweep finds issues)

**Interfaces:**
- Consumes: the built `site/dist/` from Tasks 1–2.
- Produces: nothing — this is the release gate for the page.

- [ ] **Step 1: Full rebuild from clean**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd/site && rm -rf dist && npx --no-install astro build`
Expected: `[build] 6 page(s) built`, `Complete!`.

- [ ] **Step 2: Site-wide consistency greps**

Run: `grep -rl 'brixMount' dist/ | sort`
Expected: all six `index.html` files (nav+footer on every page).

Run: `grep -rn 'xrootd_proxy\|/xrootd/\|xrootd_requests\|xrootd_bytes\|xrootd_auth_total' dist/`
Expected: no output.

Run: `grep -c 'nav-link' dist/brixmount/index.html`
Expected: ≥7 (4 audiences + brixMount + Docs + GitHub).

- [ ] **Step 3: Spec coverage check**

Re-read `docs/superpowers/specs/2026-07-05-brixmount-page-design.md` § "Page structure" and confirm each of the five bands exists on the page (hero, threat model, defenses, proof, mount types + CTA), the placement is a top-level nav item, and no spec-only feature slipped in. Fix inline if anything is missing.

- [ ] **Step 4: Commit (only if fixes were needed)**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
git add -u site/
git commit -m "fix(site): brixMount page final-sweep fixes

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6"
```
