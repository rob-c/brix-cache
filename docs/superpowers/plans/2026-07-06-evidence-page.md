# Hardening-Evidence Page + Doc Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `/evidence` page to the marketing site and the mirrored `docs/07-security/hardening-evidence.md` document, per `docs/superpowers/specs/2026-07-06-evidence-page-design.md`.

**Architecture:** One new Astro page (`evidence.astro`) using the existing design system, one `PRODUCT_PAGES` nav line, and one markdown doc that mirrors the page section-for-section. The site page links to the doc's GitHub blob URL.

**Tech Stack:** Astro 5 static site in `site/`; plain markdown for the doc.

## Global Constraints

- **Claims policy:** every citation on page and doc must exist in the repo — all were verified 2026-07-06 (table below). No performance-comparison claims.
- **Full candor:** postmortems/audits cited by name; symptom → root cause → outcome phrasing.
- **Mirror rule:** no content appears in one deliverable but not the other (same four evidence classes, same items, same citations).
- Branding: **BriX-Cache** / **brixMount** casing; no `xrootd_*` directive/metric names.
- Internal links via `url()`; the doc link uses `REPO_URL + '/blob/main/docs/07-security/hardening-evidence.md'`.
- Commit directly to `main`. Commit trailer:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` + `Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6`

## Claim → evidence table (verified 2026-07-06)

| Claim | Evidence |
|---|---|
| Semaphore-stall postmortem (60–450 s multi-worker stalls, lost wakeup, spin+yield rule) | `docs/09-developer-guide/postmortem-shmtx-semaphore-stall.md`, `src/core/compat/shm_slots.c`, CLAUDE.md invariant #10 |
| Reboot-lockup audit: 4 fixes each with a regression test | `tests/test_shm_mutex_recovery.py` + `tests/c/test_shm_mutex_recovery.c`, `tests/test_cache_lock_reclaim.py` + `tests/c/test_cache_lock_reclaim.c`, `tests/test_http_origin_stall_timeout.py`, `tests/test_ratelimit_gauge_reset.py` + `tests/c/test_ratelimit_gauge_reset.c` |
| Upstream-flakiness absorb: stall detect (connect 2s / stall 4s defaults), force-primary, stale-if-error, fill coalescing | `src/protocols/cvmfs/module.c:448-449` (4s default), `tests/run_cvmfs_resilience.sh`, `src/protocols/shared/http_cache_fill.c` |
| Path confinement: resolve before open (invariant), openat2 RESOLVE_IN_ROOT | CLAUDE.md INVARIANTS #4, `src/fs/path/beneath.h`, `src/fs/path/resolve_confined_helpers.c` |
| One storage seam + CI guard | `src/fs/backend/` (tier-1 rule), `tools/ci/check_vfs_seam.sh` |
| Hardened builds: -Werror + format attrs (caught a real bug), RELRO/now/noexecstack | hardening-CFLAGS work (format attr caught webdav LOCK `%ui` bug), `client/Makefile` LDFLAGS |
| Sanitized log strings, low-cardinality labels | `src/observability/accesslog/access_log.c` (`brix_sanitize_log_string`), CLAUDE.md invariant #8 |
| Fail-early config (`nginx -t` emerg) | existing verified site copy (sysadmins page), CLAUDE.md reload-semantics doc |
| ~8,700 tests; ~1,770 fault/chaos lane; fault proxy; netem; cross-backend | `tests/README.md:3,12`, `tests/c/fault_proxy.c`, `tests/cvmfs/netem_lab.sh`, `CLAUDE.md` `TEST_CROSS_BACKEND` |
| Five standing CI guards | `tools/ci/check_vfs_seam.sh`, `check_config_coverage.sh`, `check_http_helper_reimpl.sh`, `check_file_size.sh`, `check_sd_driver_conformance.sh` |
| Per-page CRC32c on pgread/pgwrite | `src/protocols/root/read/pgread.c:11`, CLAUDE.md invariant #1 |
| Checksum at rest / verify tooling | `client/apps/README.md` (`xrdckverify`) |
| CSI per-read integrity verification | `src/fs/backend/csi_verify.c` |
| CVMFS hash-verified fetch, offline cache mode | `client/apps/fs/brixcvmfs.c:6-7` |
| Byte-exact / no-EIO fault assertions | `tests/test_xrootdfs_resilience.py:7,168-207` |

---

### Task 1: The `/evidence` page + nav entry

**Files:**
- Modify: `site/src/lib/site.ts` (the `PRODUCT_PAGES` array)
- Create: `site/src/pages/evidence.astro`

**Interfaces:**
- Consumes: `Layout`/`Band`/`Cta` components, global classes (`eyebrow`, `display`, `lede`, `muted`, `mono`, `stack`, `grid grid-2/grid-3`, `panel`, `term`/`p`/`k`/`c`), `REPO_URL` + `url()` from `site/src/lib/site.ts`.
- Produces: route `/evidence`; nav label **Evidence**; page-local classes `.ev-*`.

- [ ] **Step 1: Add Evidence to `PRODUCT_PAGES`**

```ts
/** Product pages shown in the primary nav after the audience links. */
export const PRODUCT_PAGES: NavItem[] = [
  { label: 'brixMount', href: '/brixmount' },
  { label: 'Tools', href: '/tools' },
  { label: 'Evidence', href: '/evidence' },
];
```

- [ ] **Step 2: Create `site/src/pages/evidence.astro`**

```astro
---
import Layout from '../layouts/Layout.astro';
import Band from '../components/Band.astro';
import Cta from '../components/Cta.astro';
import { REPO_URL } from '../lib/site';

const DOC_URL = `${REPO_URL}/blob/main/docs/07-security/hardening-evidence.md`;

// Evidence class 1: designed-in defenses. Every cite is a real repo path.
const defenses = [
  {
    t: 'Bad config never takes traffic',
    d: 'Missing certificates, JWKS files, CRLs, or required directories fail nginx -t with an explicit emerg line before a single byte is accepted. Reloads drain gracefully — in-flight transfers finish on old workers.',
    cite: 'nginx -t · docs/09-developer-guide/reload-semantics.md',
  },
  {
    t: 'Path confinement is an invariant, not a habit',
    d: 'Every path that arrives over the wire goes through the canonical resolve helper before any open — no exceptions. Confined opens use openat2 with RESOLVE_IN_ROOT, so a hostile symlink cannot walk out of the export.',
    cite: 'src/fs/path/beneath.h · src/fs/path/resolve_confined_helpers.c',
  },
  {
    t: 'One storage seam, mechanically enforced',
    d: 'All raw file I/O lives in one place — the storage backend under the VFS. A CI guard fails the build if a protocol handler reaches around it, so confinement and identity checks cannot be bypassed by new code.',
    cite: 'src/fs/backend/ · tools/ci/check_vfs_seam.sh',
  },
  {
    t: 'Hardened builds by default',
    d: 'The tree compiles -Werror with printf-format attributes — which caught a real header-formatting bug — and binaries link with full RELRO, immediate binding, and non-executable stacks.',
    cite: 'client/Makefile · -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack',
  },
  {
    t: 'Observability that cannot leak or explode',
    d: 'Strings from the wire are sanitized before they reach a log line, and metric labels are fixed and low-cardinality — no per-path or per-user label explosion to fall over during an incident.',
    cite: 'src/observability/accesslog/access_log.c · brix_sanitize_log_string',
  },
];

// Evidence class 4: integrity guarantees.
const integrity = [
  { t: 'Per-page CRC32c on the wire', d: 'kXR_pgread / kXR_pgwrite carry a CRC32c per 4K page — corruption is caught per page, not per file.', cite: 'src/protocols/root/read/pgread.c' },
  { t: 'Checksums at rest', d: 'Recorded checksums travel with the file and are verifiable on demand from the client side.', cite: 'xrdckverify · client/apps/README.md' },
  { t: 'Verified reads from storage', d: 'CSI integrity verification checks what storage returns against the record made at write time.', cite: 'src/fs/backend/csi_verify.c' },
  { t: 'Content-addressed trust for CVMFS', d: 'Every fetched object is verified against its content hash on arrival; a damaged or resumed transfer cannot go undetected.', cite: 'client/apps/fs/brixcvmfs.c' },
  { t: 'Byte-exact under fault injection', d: 'The FUSE resilience suites assert byte-exact results with zero EIO surfaced — while a proxy resets and stalls the link.', cite: 'tests/test_xrootdfs_resilience.py' },
];
---

<Layout
  title="Evidence"
  description="Evidence that BriX-Cache is designed to harden services for a better user experience: designed-in defenses, named postmortems with fixes and regression tests, a fault-injection test lane, and end-to-end integrity guarantees — every claim cited to the repository."
  accent="root"
>
  <!-- HERO -->
  <Band first={true}>
    <div class="ev-hero">
      <div class="stack">
        <span class="eyebrow">The evidence</span>
        <h1 class="display">Hardening is the design brief,<br />not a feature.</h1>
        <p class="lede">
          The claim: BriX-Cache is engineered so that failures — bad networks, bad configs, bad
          actors, crashed workers — cost users as little as possible. The rule for this page:
          every item cites a file, document, or test in the repository. Nothing here is
          aspirational.
        </p>
      </div>
      <div class="term" aria-label="The receipts in the source tree">
        <div class="term-title">the receipts are in the tree</div>
        <div><span class="p">$</span> ls docs/09-developer-guide/postmortem-*.md</div>
        <div>postmortem-shmtx-semaphore-stall.md</div>
        <div class="mt"><span class="p">$</span> ls tools/ci/check_*.sh | wc -l</div>
        <div><span class="k">5</span>  <span class="c"># standing architecture guards, run in CI</span></div>
        <div class="mt"><span class="p">$</span> tests/run_suite.sh --nightly</div>
        <div><span class="c"># ~1,770 resilience / chaos / fault-injection tests</span></div>
      </div>
    </div>
  </Band>

  <!-- CLASS 1: DESIGNED-IN DEFENSES -->
  <Band variant="sunken" id="defenses">
    <span class="eyebrow">Evidence class 1</span>
    <h2 class="display band-head">Designed-in defenses.</h2>
    <p class="lede muted ev-intro">
      What the user feels: the service refuses to start broken, cannot be walked out of its
      export, and does not grow new bypasses as the code evolves.
    </p>
    <div class="grid grid-2">
      {defenses.map((x) => (
        <article class="panel ev-item">
          <h3 class="ev-t">{x.t}</h3>
          <p class="muted">{x.d}</p>
          <p class="mono ev-cite">{x.cite}</p>
        </article>
      ))}
    </div>
  </Band>

  <!-- CLASS 2: FAILURE-MODE ENGINEERING -->
  <Band variant="ink" id="postmortems">
    <span class="eyebrow">Evidence class 2</span>
    <h2 class="display band-head">Failure-mode engineering, in public.</h2>
    <p class="lede muted ev-intro">
      The strongest evidence is what happened when something broke: hunt the failure mode, fix
      it, write it down, and pin it with a regression test.
    </p>
    <div class="grid grid-3">
      <article class="panel ev-item">
        <h3 class="ev-t">The semaphore stall</h3>
        <p class="muted">
          <strong>Symptom:</strong> multi-worker connection stalls of 60–450 seconds on the hot
          open path. <strong>Root cause:</strong> a lost POSIX-semaphore wakeup inside
          shared-memory mutexes — a worker slept on a lock that was already free.
          <strong>Outcome:</strong> a repo-wide spin-and-yield mutex rule enforced through one
          allocation helper, and a published postmortem.
        </p>
        <p class="mono ev-cite">docs/09-developer-guide/postmortem-shmtx-semaphore-stall.md · src/core/compat/shm_slots.c</p>
      </article>
      <article class="panel ev-item">
        <h3 class="ev-t">The reboot-lockup audit</h3>
        <p class="muted">
          A "stuck after many reboots" report triggered a full audit of every lock a dying
          worker could strand. Four classes found and fixed — dead-holder mutex recovery,
          cache-lock dead-owner reclaim, missing origin stall timeout, leaked in-use gauges —
          each pinned by its own regression test.
        </p>
        <p class="mono ev-cite">tests/test_shm_mutex_recovery.py · test_cache_lock_reclaim.py · test_http_origin_stall_timeout.py · test_ratelimit_gauge_reset.py</p>
      </article>
      <article class="panel ev-item">
        <h3 class="ev-t">Absorbing upstream flakiness</h3>
        <p class="muted">
          Hardening aimed straight at user experience: a stuck origin is detected in seconds
          (2 s connect / 4 s stall defaults), retried against fresh connections, and — when
          everything upstream fails — answered from cache with stale-if-error. A client storm
          coalesces into a single upstream fill.
        </p>
        <p class="mono ev-cite">src/protocols/cvmfs/ · tests/run_cvmfs_resilience.sh</p>
      </article>
    </div>
  </Band>

  <!-- CLASS 3: PROOF BY TORTURE -->
  <Band id="torture">
    <span class="eyebrow">Evidence class 3</span>
    <h2 class="display band-head">Proof by torture.</h2>
    <div class="grid grid-2 ev-proof">
      <div class="stack">
        <p class="muted">
          The suite is ~8,700 tests, and its slow lane — ~1,770 tests — exists specifically to
          hurt the software: resilience, chaos, and fault injection. A TCP fault proxy resets
          connections mid-read and injects stalls and latency while the tests assert byte-exact
          results and zero errors surfaced to applications; a <span class="mono">netem</span>
          lab degrades whole links.
        </p>
        <p class="muted">
          Conformance is cross-checked, not assumed: the same tests run against BriX-Cache and
          the reference XRootD implementation. And five standing CI guards — VFS seam, config
          coverage, helper reimplementation, file-size ratchet, storage-driver conformance —
          keep the architectural rules from eroding between releases.
        </p>
      </div>
      <div class="term" aria-label="Torture-lane summary">
        <div class="term-title">the numbers</div>
        <div>tests, full suite            <span class="k">~8,700</span></div>
        <div>fault / chaos / resilience   <span class="k">~1,770</span></div>
        <div>fault-injection proxy        <span class="k">tests/c/fault_proxy.c</span></div>
        <div>network-emulation lab        <span class="k">tests/cvmfs/netem_lab.sh</span></div>
        <div>cross-backend conformance    <span class="k">nginx ⇄ reference XRootD</span></div>
        <div>standing CI guards           <span class="k">5</span></div>
      </div>
    </div>
  </Band>

  <!-- CLASS 4: INTEGRITY -->
  <Band variant="sunken" id="integrity">
    <span class="eyebrow">Evidence class 4</span>
    <h2 class="display band-head">Integrity, end to end.</h2>
    <p class="lede muted ev-intro">
      What the user feels: the bytes that arrive are the bytes that were published — provable
      at every hop.
    </p>
    <div class="grid grid-3">
      {integrity.map((x) => (
        <article class="panel ev-item">
          <h3 class="ev-t">{x.t}</h3>
          <p class="muted">{x.d}</p>
          <p class="mono ev-cite">{x.cite}</p>
        </article>
      ))}
    </div>
  </Band>

  <Band>
    <p class="ev-doclink mono">
      Take the receipts with you: <a href={DOC_URL}>docs/07-security/hardening-evidence.md ↗</a>
    </p>
    <Cta
      title="Verify it yourself."
      note="Every citation on this page resolves in the repository — the docs, the guards, and the tests are all in the tree."
    />
  </Band>
</Layout>

<style>
  .ev-hero { display: grid; gap: 2.5rem; align-items: center; }
  @media (min-width: 900px) { .ev-hero { grid-template-columns: 1.05fr 0.95fr; gap: 3rem; } }
  .band-head { margin: 0.5rem 0 1.4rem; max-width: 24ch; }
  .ev-intro { margin: 0.4rem 0 1.6rem; }
  .ev-item { display: flex; flex-direction: column; gap: 0.55rem; }
  .ev-t {
    font-family: var(--display); font-stretch: 112%; font-weight: 700;
    font-size: 1.2rem; line-height: 1.1;
  }
  .ev-cite { margin-top: auto; font-size: 0.72rem; color: var(--ink-2); word-break: break-word; }
  .band--ink .ev-cite { color: #a8a29e; }
  .ev-proof { align-items: start; }
  .ev-doclink { text-align: center; margin-bottom: 1.6rem; font-size: 0.85rem; }
  .term .mt { margin-top: 0.6rem; }
</style>
```

- [ ] **Step 3: Build and verify**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd/site && npx --no-install astro build`
Expected: `[build] 8 page(s) built` … `Complete!` with a `/evidence/index.html` line.

Run: `grep -o '<title>[^<]*</title>' dist/evidence/index.html`
Expected: `<title>Evidence · BriX-Cache</title>`

Run: `grep -o 'id="defenses"\|id="postmortems"\|id="torture"\|id="integrity"' dist/evidence/index.html | sort | uniq -c`
Expected: each id once.

Run: `grep -n 'xrootd_\|/xrootd/' dist/evidence/index.html`
Expected: no output.

Run: `grep -o 'postmortem-shmtx-semaphore-stall' dist/evidence/index.html | head -1`
Expected: the string (candor content present).

- [ ] **Step 4: Commit**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
git add site/src/lib/site.ts site/src/pages/evidence.astro
git commit -m "feat(site): hardening-evidence ledger page

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6"
```

---

### Task 2: The mirrored document

**Files:**
- Create: `docs/07-security/hardening-evidence.md`

**Interfaces:**
- Consumes: nothing from Task 1 (content mirrors the page by construction).
- Produces: the doc the page's `DOC_URL` points at — path must be exactly `docs/07-security/hardening-evidence.md`.

- [ ] **Step 1: Write the doc**

Create `docs/07-security/hardening-evidence.md` with exactly this content:

```markdown
# Hardening evidence — designed for a better user experience

> Text form of the site's `/evidence` page. The claim: BriX-Cache is
> engineered so that failures — bad networks, bad configs, bad actors,
> crashed workers — cost users as little as possible. The rule: every item
> below cites a file, document, or test in this repository. Nothing here is
> aspirational.

## 1. Designed-in defenses

*What the user feels: the service refuses to start broken, cannot be walked
out of its export, and does not grow new bypasses as the code evolves.*

- **Bad config never takes traffic.** Missing certificates, JWKS files,
  CRLs, or required directories fail `nginx -t` with an explicit `emerg`
  line before a single byte is accepted; reloads drain gracefully.
  ([reload semantics](../09-developer-guide/reload-semantics.md))
- **Path confinement is an invariant, not a habit.** Every wire path goes
  through the canonical resolve helper before any open — no exceptions —
  and confined opens use `openat2` with `RESOLVE_IN_ROOT`, closing
  symlink-escape routes. (`src/fs/path/beneath.h`,
  `src/fs/path/resolve_confined_helpers.c`)
- **One storage seam, mechanically enforced.** All raw file I/O lives in
  `src/fs/backend/` behind the VFS; `tools/ci/check_vfs_seam.sh` fails the
  build if a handler reaches around it, so confinement and identity checks
  cannot be bypassed by new code.
- **Hardened builds by default.** `-Werror` with `printf`-format attributes
  (which caught a real header-formatting bug); binaries link with full
  RELRO, immediate binding, and non-executable stacks (`client/Makefile`).
- **Observability that cannot leak or explode.** Wire strings are sanitized
  before logging (`brix_sanitize_log_string`,
  `src/observability/accesslog/access_log.c`); metric labels are fixed and
  low-cardinality.

## 2. Failure-mode engineering, in public

*The strongest evidence is what happened when something broke: hunt the
failure mode, fix it, write it down, pin it with a regression test.*

- **The semaphore stall.** Symptom: multi-worker connection stalls of
  60–450 s on the hot open path. Root cause: a lost POSIX-semaphore wakeup
  inside shared-memory mutexes — a worker slept on a lock that was already
  free. Outcome: a repo-wide spin+yield mutex rule enforced through one
  allocation helper (`src/core/compat/shm_slots.c`) and a published
  postmortem
  ([postmortem](../09-developer-guide/postmortem-shmtx-semaphore-stall.md)).
- **The reboot-lockup audit.** A "stuck after many reboots" report triggered
  a full audit of every lock a dying worker could strand. Four classes
  found and fixed, each pinned by a regression test: dead-holder SHM mutex
  recovery (`tests/test_shm_mutex_recovery.py`), cache-fill lock dead-owner
  reclaim (`tests/test_cache_lock_reclaim.py`), missing origin stall timeout
  (`tests/test_http_origin_stall_timeout.py`), leaked in-use gauges
  (`tests/test_ratelimit_gauge_reset.py`).
- **Absorbing upstream flakiness.** Hardening aimed straight at user
  experience: a stuck origin is detected in seconds (2 s connect / 4 s
  stall defaults, `src/protocols/cvmfs/module.c`), retried against fresh
  connections (force-primary policy), and — when everything upstream fails —
  answered from cache with stale-if-error. A client storm coalesces into a
  single upstream fill. (`tests/run_cvmfs_resilience.sh`)

## 3. Proof by torture

- Full suite **~8,700 tests**; the slow lane — **~1,770 tests** — exists
  specifically to hurt the software: resilience, chaos, fault injection
  (`tests/README.md`).
- A TCP fault-injection proxy (`tests/c/fault_proxy.c`) resets connections
  mid-read and injects stalls and latency while suites assert **byte-exact**
  results and **zero EIO** surfaced to applications
  (`tests/test_xrootdfs_resilience.py`).
- A `netem` network-emulation lab degrades whole links
  (`tests/cvmfs/netem_lab.sh`).
- Conformance is cross-checked, not assumed: the same tests run against
  BriX-Cache and the reference XRootD implementation
  (`TEST_CROSS_BACKEND`).
- Five standing CI guards keep the architecture from eroding between
  releases: `tools/ci/check_vfs_seam.sh`, `check_config_coverage.sh`,
  `check_http_helper_reimpl.sh`, `check_file_size.sh`,
  `check_sd_driver_conformance.sh`.

## 4. Integrity, end to end

*What the user feels: the bytes that arrive are the bytes that were
published — provable at every hop.*

- **Per-page CRC32c on the wire** — `kXR_pgread`/`kXR_pgwrite` carry a CRC
  per 4K page (`src/protocols/root/read/pgread.c`).
- **Checksums at rest** — recorded checksums are verifiable on demand
  (`xrdckverify`, `client/apps/README.md`).
- **Verified reads from storage** — CSI integrity verification checks what
  storage returns against the record made at write time
  (`src/fs/backend/csi_verify.c`).
- **Content-addressed trust for CVMFS** — every fetched object is verified
  against its content hash on arrival (`client/apps/fs/brixcvmfs.c`).
- **Byte-exact under fault injection** — the end-to-end check that ties it
  together (`tests/test_xrootdfs_resilience.py`).
```

- [ ] **Step 2: Verify the relative links resolve**

Run: `ls docs/09-developer-guide/reload-semantics.md docs/09-developer-guide/postmortem-shmtx-semaphore-stall.md`
Expected: both listed.

- [ ] **Step 3: Mirror check**

Read the doc against the page content in Task 1: same four classes, same items, same citations. Fix either side if anything diverges.

- [ ] **Step 4: Commit**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
git add docs/07-security/hardening-evidence.md
git commit -m "docs(security): hardening-evidence summary (mirrors /evidence page)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6"
```

---

### Task 3: Final sweep

**Files:**
- Modify: none expected (fixes only if the sweep finds issues)

**Interfaces:**
- Consumes: built `site/dist/` and the committed doc.
- Produces: nothing — release gate.

- [ ] **Step 1: Clean rebuild**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd/site && rm -rf dist && npx --no-install astro build`
Expected: `[build] 8 page(s) built`, `Complete!`.

- [ ] **Step 2: Site-wide greps**

Run: `grep -rl '/evidence' dist/ | wc -l`
Expected: 8 (nav on every page).

Run: `grep -rn 'xrootd_proxy\|/xrootd/\|xrootd_requests\|xrootd_bytes\|xrootd_auth_total' dist/`
Expected: no output.

Run: `grep -o 'hardening-evidence.md' dist/evidence/index.html | head -1`
Expected: the string (doc link present).

- [ ] **Step 3: Spec conformance check**

Confirm against `docs/superpowers/specs/2026-07-06-evidence-page-design.md`: hero + four ledger bands + CTA with doc link; nav order brixMount, Tools, Evidence; full-candor entries present; mirror rule holds. Fix inline if anything is off.

- [ ] **Step 4: Commit (only if fixes were needed)**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
git add -u site/ docs/
git commit -m "fix(site): evidence page final-sweep fixes

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6"
```
