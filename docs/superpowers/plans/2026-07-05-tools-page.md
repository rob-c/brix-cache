# Tools Marketing Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a top-level `/tools` page to the BriX-Cache marketing site (`site/`) — the family-catalog design from `docs/superpowers/specs/2026-07-05-tools-page-design.md`.

**Architecture:** One new Astro page reusing the existing design system (`Layout`, `Band`, `Benefit`, `Cta`, global `panel`/`chip`/`term`/`grid` classes) plus a one-line `PRODUCT_PAGES` addition in `site/src/lib/site.ts` (Header and Footer already render `PRODUCT_PAGES`, so no component edits). Accent `root`.

**Tech Stack:** Astro 5 static site in `site/` (build with `npx --no-install astro build` from `site/`). No JS runtime on the page.

## Global Constraints

- **Claims policy: ONLY landed features** — every tool name/capability traced to the claim→evidence table below. `xrdstorascan` claims limited to phase-1 `verify`/`bench`; LD_PRELOAD shim claimed as read-path only. No `xrdstorascan` server-engine phases, no pymigrate/Ceph tooling.
- Branding: **BriX-Cache** / **brixMount** exact casing. No `xrootd_*` directive/metric names; dashboard path `/brix/`.
- Internal links via `url()` from `site/src/lib/site.ts`.
- Copy tone matches existing pages: confident, concrete, no fluff, no exclamation marks.
- Commit directly to `main`. Commit trailer:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` + `Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6`

## Claim → evidence table (verified 2026-07-05)

| Page claim | Landed evidence |
|---|---|
| Pure-C, libXrdCl-free tool suite on one client library | `client/apps/README.md` intro |
| Stock names as multi-call symlink personalities: `xrdcksum` → crc32c/crc64/adler32/ckverify/cinfo; `xrddiag` → qstats/wait41/mpxstats | `client/Makefile:153-160` (`CKSUM_LINKS`, `DIAG_LINKS`), `:220-224` |
| Hardened link defaults (RELRO, now, noexecstack) | `client/Makefile` `LDFLAGS ?= -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack` |
| `xrdcp`: root://, web URLs (davs/http(s)/dav/s3/s3s), local, `-`, recursive, ZIP-member | `client/apps/README.md` Data movement |
| `xrdfs`: fs ops + interactive shell, web backends too | `client/apps/README.md` Data movement |
| `xrd`: multi-call verb set + battery/doctor/clockskew/mount | `client/apps/README.md`, `client/Makefile` `xrd_OBJS` |
| `xrddiag`: check/bench/watch/topology/compare/doctor + error explanation | `client/apps/README.md` Diagnostics |
| `xrdqstats`, `mpxstats`, `xrdmapc`, `wait41` | `client/apps/README.md` Diagnostics |
| `xrdstorascan verify` (end-to-end integrity vs server `kXR_Qcksum`), `bench` (throughput/IOPS/latency over block size × parallelism) | `client/apps/README.md` (phase 1 shipped+tested) |
| `xrdgsiproxy`, `xrdgsitest`, `xrdsssadmin` | `client/apps/README.md` Auth & security |
| `xrdprep` (`kXR_prepare` stage/cancel/evict) | `client/apps/README.md` Namespace/staging |
| Reconnect + re-auth + handle reopen + offset resume, `--max-stall` budget | `client/lib/net/resilient.c:5,110-122` |
| `brixMount` types + overlay; `xrootdfs` async default + `--legacy` sync fallback | `client/apps/fs/brixmount.c:37-40,122-126`, `client/apps/README.md` Optional |
| `libbrixposix_preload.so` LD_PRELOAD read-path shim | `client/apps/README.md` Optional, `client/preload/` |
| Cross-backend conformance suite (same tests vs nginx AND reference XRootD) | `CLAUDE.md` BUILD & TEST (`TEST_CROSS_BACKEND=nginx`) |

---

### Task 1: The `/tools` page + nav entry

**Files:**
- Modify: `site/src/lib/site.ts` (the `PRODUCT_PAGES` array, ~line 78)
- Create: `site/src/pages/tools.astro`

**Interfaces:**
- Consumes: `NavItem`/`url()` from `site/src/lib/site.ts`; `Layout` (props `title`, `description`, `accent`), `Band` (props `variant?`, `id?`, `first?`), `Benefit` (props `marker`, `title`, slot), `Cta` (props `title`, `note?`); global classes `eyebrow`, `display`, `lede`, `muted`, `mono`, `stack`, `grid grid-2/grid-3`, `panel panel--hover`, `chip chip--root/--dav/--s3/--ghost`, `term`, `term-title`, `term .p/.k/.c`, `btn`.
- Produces: route `/tools`; nav label **Tools** (Header/Footer pick it up from `PRODUCT_PAGES` automatically).

- [ ] **Step 1: Add Tools to `PRODUCT_PAGES` in site.ts**

Change the `PRODUCT_PAGES` array to:

```ts
/** Product pages shown in the primary nav after the audience links. */
export const PRODUCT_PAGES: NavItem[] = [
  { label: 'brixMount', href: '/brixmount' },
  { label: 'Tools', href: '/tools' },
];
```

- [ ] **Step 2: Create the page**

Create `site/src/pages/tools.astro` with exactly this content:

```astro
---
import Layout from '../layouts/Layout.astro';
import Band from '../components/Band.astro';
import Benefit from '../components/Benefit.astro';
import Cta from '../components/Cta.astro';
import { url } from '../lib/site';

// The tool families, mirroring client/apps/ one-to-one. Tool lists and
// capabilities come from client/apps/README.md — landed features only.
const families = [
  {
    name: 'Data movement',
    tools: 'xrdcp · xrdfs · xrd',
    d: 'xrdcp copies between root://, web URLs (davs, http(s), s3), local paths, and stdin/stdout — recursive, ZIP-member aware. xrdfs covers the filesystem verbs and doubles as an interactive shell. xrd is the swiss-army front-end: ls, stat, cat, cp, du, df, tree, find, locate, query, prepare — plus doctor, battery, and clockskew self-checks.',
  },
  {
    name: 'Checksums & verification',
    tools: 'xrdcrc32c · xrdcrc64 · xrdadler32 · xrdckverify · xrdcinfo',
    d: 'One multi-call binary, five personalities. Hash a local or root:// file, verify a file on disk against its recorded checksum, or dump a cache file’s present-bitmap as JSON.',
  },
  {
    name: 'Diagnostics & monitoring',
    tools: 'xrddiag · xrdqstats · mpxstats · xrdmapc · wait41',
    d: 'xrddiag turns raw failures into explanations — check, bench, watch, topology, compare, doctor. Query server stats and config, map a redirector’s live cluster, or block until a server accepts connections in your orchestration scripts.',
  },
  {
    name: 'Storage admin',
    tools: 'xrdstorascan',
    d: 'verify pulls the bytes, recomputes the checksum, and compares against the server’s answer — end-to-end integrity, any backend. bench sweeps block size × parallelism and reports throughput, IOPS, and latency.',
  },
  {
    name: 'Auth & security',
    tools: 'xrdgsiproxy · xrdgsitest · xrdsssadmin',
    d: 'Create, inspect, and destroy X.509 GSI proxies; self-test a GSI handshake against a live server; manage SSS shared-secret keytabs.',
  },
  {
    name: 'Staging',
    tools: 'xrdprep',
    d: 'Issue kXR_prepare requests — stage, cancel, evict — for one or many paths on tape-backed or tiered storage.',
  },
];
---

<Layout
  title="Tools"
  description="BriX-Cache ships a complete pure-C client toolset — the stock XRootD tool names keep working with no XRootD client stack installed, and your existing clients keep working against the server."
  accent="root"
>
  <!-- HERO -->
  <Band first={true}>
    <div class="tl-hero">
      <div class="stack">
        <span class="eyebrow">The BriX tool suite</span>
        <h1 class="display">Your muscle memory<br />still works.</h1>
        <p class="lede">
          BriX-Cache ships a complete client toolset in plain C — and the stock XRootD tool
          names keep working: <span class="mono">xrdcp</span>, <span class="mono">xrdfs</span>,
          <span class="mono">xrdadler32</span>, <span class="mono">xrdgsiproxy</span>. No
          XRootD client stack to install, nothing to relearn.
        </p>
      </div>
      <div class="term" aria-label="Stock tool names working">
        <div class="term-title">stock names, no stock install</div>
        <div><span class="p">$</span> xrdcp root://host//data/higgs.root .</div>
        <div><span class="p">$</span> xrdadler32 higgs.root</div>
        <div><span class="k">2f0a37b1</span>  higgs.root</div>
        <div class="mt"><span class="c"># each stock name is a personality of one small</span></div>
        <div><span class="c"># pure-C multi-call binary — symlinks, not a 400 MB stack</span></div>
      </div>
    </div>
  </Band>

  <!-- WHY THESE TOOLS -->
  <Band variant="sunken" id="why">
    <span class="eyebrow">Why these tools</span>
    <h2 class="display band-head">Four reasons to stop installing the big stack.</h2>
    <div class="grid grid-2">
      <Benefit marker="drop-in" title="The names you already type">
        <p>
          Stock tool names stay invocable — <span class="mono">xrdcksum</span> answers as
          <span class="mono">xrdcrc32c</span>, <span class="mono">xrdcrc64</span>,
          <span class="mono">xrdadler32</span>, <span class="mono">xrdckverify</span>, and
          <span class="mono">xrdcinfo</span>; <span class="mono">xrddiag</span> absorbed
          <span class="mono">xrdqstats</span>, <span class="mono">wait41</span>, and
          <span class="mono">mpxstats</span>. Your scripts don't change.
        </p>
      </Benefit>
      <Benefit marker="self-contained" title="Small, plain C, hardened">
        <p>
          Every tool is a thin front-end over one client library — pure C, no libXrdCl, no
          dependency tree. Binaries link with full RELRO, immediate binding, and
          non-executable stacks by default.
        </p>
      </Benefit>
      <Benefit marker="protocols" title="One toolset, every protocol">
        <p>
          The same <span class="mono">xrdcp</span> that speaks <span class="mono">root://</span>
          and <span class="mono">roots://</span> also copies from and to
          <span class="mono">davs://</span>, <span class="mono">http(s)://</span>, and
          <span class="mono">s3://</span> URLs, local paths, and <span class="mono">-</span>.
          One tool, one syntax, the whole storage estate.
        </p>
      </Benefit>
      <Benefit marker="resilient" title="Hardened for bad networks">
        <p>
          Every tool rides the same machinery as <a href={url('/brixmount')}>brixMount</a>:
          reconnect, full re-authentication, handle reopen, and offset resume inside one
          <span class="mono">--max-stall</span> patience budget. A flaky link costs you time,
          not a transfer.
        </p>
      </Benefit>
    </div>
  </Band>

  <!-- THE SUITE -->
  <Band id="suite">
    <span class="eyebrow">The suite</span>
    <h2 class="display band-head">Six families, one library underneath.</h2>
    <div class="grid grid-3">
      {families.map((f) => (
        <article class="panel panel--hover tl-fam">
          <h3 class="tl-fam-t">{f.name}</h3>
          <p class="mono tl-fam-tools">{f.tools}</p>
          <p class="muted">{f.d}</p>
        </article>
      ))}
    </div>
  </Band>

  <!-- MOUNTS & SHIM -->
  <Band variant="sunken" id="mounts">
    <span class="eyebrow">Mounts & the POSIX shim</span>
    <h2 class="display band-head">When the tool is “just a directory”.</h2>
    <div class="grid grid-3">
      <article class="panel panel--hover tl-fam">
        <h3 class="tl-fam-t">brixMount</h3>
        <p class="mono tl-fam-tools">cvmfs · cvmfs-rw · eos · root · roots</p>
        <p class="muted">
          The umbrella FUSE front-end: any CVMFS repository or XRootD/EOS endpoint as a local
          directory, torture-tested for bad networks.
          <a href={url('/brixmount')}>Read the brixMount page →</a>
        </p>
      </article>
      <article class="panel panel--hover tl-fam">
        <h3 class="tl-fam-t">xrootdfs</h3>
        <p class="mono tl-fam-tools">one binary, two drivers</p>
        <p class="muted">
          The XRootD FUSE mount itself: the async, resilient driver by default, and a simple
          synchronous fallback behind <span class="mono">--legacy</span> when you want the
          dumbest possible thing.
        </p>
      </article>
      <article class="panel panel--hover tl-fam">
        <h3 class="tl-fam-t">LD_PRELOAD shim</h3>
        <p class="mono tl-fam-tools">libbrixposix_preload.so</p>
        <p class="muted">
          A POSIX→XRootD read-path shim for binaries you can't change: preload it and existing
          applications read <span class="mono">root://</span> paths as if they were local files
          — no mount, no recompile.
        </p>
      </article>
    </div>
  </Band>

  <!-- BRING YOUR OWN TOOLS -->
  <Band variant="ink" id="byot">
    <span class="eyebrow">Bring your own tools</span>
    <h2 class="display band-head">Already have a toolchain? Keep it.</h2>
    <p class="lede muted tl-intro">
      The server side of the same promise: BriX-Cache speaks the wire protocols your existing
      clients expect, and the test suite runs the same conformance tests against BriX-Cache
      and the reference XRootD implementation.
    </p>
    <div class="grid grid-3">
      <article class="panel tl-fam">
        <span class="chip chip--root mono">root://</span>
        <p class="mono tl-fam-tools">stock xrdcp · xrdfs · pyxrootd</p>
        <p class="muted">The reference XRootD clients work unmodified — same opcodes, same semantics.</p>
      </article>
      <article class="panel tl-fam">
        <span class="chip chip--dav mono">davs://</span>
        <p class="mono tl-fam-tools">curl · rucio · browser</p>
        <p class="muted">Standard WebDAV over HTTPS with x509 or WLCG tokens — anything that speaks HTTP works.</p>
      </article>
      <article class="panel tl-fam">
        <span class="chip chip--s3 mono">s3://</span>
        <p class="mono tl-fam-tools">aws-cli · boto3</p>
        <p class="muted">SigV4 REST against the same tree — point your existing S3 tooling at it.</p>
      </article>
    </div>
  </Band>

  <Band>
    <Cta
      title="One library. Every tool you need."
      note="All of it ships with BriX-Cache — build the client suite with a plain make."
    />
  </Band>
</Layout>

<style>
  .tl-hero { display: grid; gap: 2.5rem; align-items: center; }
  @media (min-width: 900px) { .tl-hero { grid-template-columns: 1.05fr 0.95fr; gap: 3rem; } }
  .band-head { margin: 0.5rem 0 1.4rem; max-width: 26ch; }
  .tl-intro { margin: 0.4rem 0 1.6rem; }
  .tl-fam { display: flex; flex-direction: column; gap: 0.5rem; }
  .tl-fam-t {
    font-family: var(--display); font-stretch: 112%; font-weight: 700;
    font-size: 1.25rem; line-height: 1.1;
  }
  .tl-fam-tools { font-size: 0.82rem; font-weight: 600; }
  .tl-fam .muted a { color: inherit; }
  .term .mt { margin-top: 0.6rem; }
</style>
```

- [ ] **Step 3: Build and verify**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd/site && npx --no-install astro build`
Expected: `[build] 7 page(s) built` … `Complete!` with a `src/pages/tools.astro → /tools/index.html` line.

Run: `grep -o '<title>[^<]*</title>' dist/tools/index.html`
Expected: `<title>Tools · BriX-Cache</title>`

Run: `grep -o 'Tools' dist/index.html | wc -l`
Expected: ≥2 (header + footer nav on the home page).

Run: `grep -n 'xrootd_\|/xrootd/' dist/tools/index.html`
Expected: no output (exit 1).

Cross-check every tool name and capability on the page against the claim→evidence table in this plan's header; anything not covered gets verified against the repo or removed.

- [ ] **Step 4: Commit**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
git add site/src/lib/site.ts site/src/pages/tools.astro
git commit -m "feat(site): Tools family-catalog product page

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6"
```

---

### Task 2: Final sweep — clean rebuild + site-wide checks

**Files:**
- Modify: none expected (fixes only if the sweep finds issues)

**Interfaces:**
- Consumes: the built `site/dist/` from Task 1.
- Produces: nothing — release gate.

- [ ] **Step 1: Clean rebuild**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd/site && rm -rf dist && npx --no-install astro build`
Expected: `[build] 7 page(s) built`, `Complete!`.

- [ ] **Step 2: Site-wide consistency greps**

Run: `grep -rl '/tools' dist/ | wc -l`
Expected: 7 (nav on every page).

Run: `grep -rn 'xrootd_proxy\|/xrootd/\|xrootd_requests\|xrootd_bytes\|xrootd_auth_total' dist/`
Expected: no output.

- [ ] **Step 3: Spec coverage check**

Re-read `docs/superpowers/specs/2026-07-05-tools-page-design.md` § "Page structure" and confirm all six bands exist (hero, advantages strip, family catalog, mounts & shim, compatibility strip, CTA), the nav label is Tools, and no unlanded capability is claimed (`xrdstorascan` beyond verify/bench, shim write path, server-engine modes). Fix inline if anything is missing.

- [ ] **Step 4: Commit (only if fixes were needed)**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
git add -u site/
git commit -m "fix(site): Tools page final-sweep fixes

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6"
```
