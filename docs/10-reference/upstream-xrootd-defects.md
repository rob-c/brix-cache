# Genuine upstream XRootD defects and quirks exposed during BriX-Cache development

## Purpose

This document consolidates the small set of findings that are attributable to
**upstream XRootD itself** — the reference C++ server (`xrootd`/`cmsd`), the
`XrdCl` client library, the command-line tools, or the wire protocol / its
specification — as opposed to defects in *this* module. It exists because that
distinction is easy to lose: the large majority of "conformance findings"
accumulated during development were **our** bugs, fixed to match the reference.
The items below are the exceptions that point the other way.

### Methodology and honesty framing

The working rule throughout development was deliberately conservative: *a
divergence between this module and stock XRootD is a bug in **this** module
unless there is positive evidence otherwise.* Consequently every upstream
attribution here is comparatively well-evidenced — most were observed live, and
the X.509 finding was additionally confirmed by reading the pinned XRootD v6.1.0
source, not just black-box behaviour.

A fair framing also matters in the other direction: the reference `xrootd`
server and `XrdCl` client are mature, widely deployed, production-grade
software. Several observations below were sharpened by a deliberately hostile
environment — a constrained WSL2 host, a ~26-minute serial marathon that
accumulates kernel/memory pressure, and tests that intentionally race teardowns
and forge requests. These are specific, load-induced or spec-edge findings, not
a verdict on XRootD's overall robustness.

Findings fall into three tiers:

- **(A) Confirmed defects observed live** — a wrong or fatal behaviour,
  reproduced.
- **(B) Spec ambiguities and upstream quirks** — real oddities that are not
  clean defects (the reference is self-consistent; the spec text or a tool is
  the awkward part).
- **(C) Explicitly *not* upstream bugs** — recorded to prevent misattribution.

---

## (A) Confirmed upstream defects observed live

### A1 — `XrdCl` synchronous-call deadlock (un-interruptible)

A synchronous `XrdCl` call can block the calling thread forever inside a C++
condition variable — `XrdCl::Stream::OnReadTimeout → XrdSysCondVar::Wait` — with
**no externally observable timeout**. In the Python binding the GIL is released
during the wait, so the call never returns to the interpreter and even a
SIGALRM-based watchdog cannot fire. An application embedding `XrdCl` inherits an
un-interruptible hang.

- **Upstream locus:** `XrdCl` client library (read-timeout path on the
  synchronous call surface).
- **Evidence — live:** a GDB backtrace of a frozen test process showed exactly
  this stack; a single hung op froze an entire ~4,000-test session and had to be
  killed. This is why the harness now runs *all* official bindings out-of-process
  — a deadlock kills a subprocess, not the host.
- **Cite:** `docs/11-architecture/reliability-under-load.md` §"Problems observed
  with the official stack under load" → item 1.

### A2 — `XrdCl` response-framing corruption under concurrent `dirlist`

Under concurrent `kXR_dirlist` traffic the official client/server pair
intermittently returns `[ERROR] Invalid response`: a second large response on a
reused pooled connection desyncs the client's response parser.

- **Upstream locus:** `XrdCl` client (pooled-connection response framing).
- **Evidence — live:** in the same dirlist comparison, **this module returned
  `[SUCCESS]` while the reference `xrootd` returned `[ERROR] Invalid response`**,
  repeatedly, across multiple marathon runs, and only under load. The condition
  is real enough that the conformance suite ships a dedicated retry helper whose
  comment names it *"an xrootd-client quirk, not an nginx behaviour."*
- **Cite:** `docs/11-architecture/reliability-under-load.md` §item 2.

### A3 — Reference `xrootd`/`cmsd` daemons dying under a sustained marathon

After a sustained multi-process marathon, the reference data-node daemons were
found **dead** (process count had dropped to zero) while the nginx instances
survived the same run. This is the practical face of the thread-per-connection
model meeting accumulated fd/memory pressure.

- **Upstream locus:** `xrootd`/`cmsd` server process model under resource
  pressure.
- **Evidence — live:** observed at the end of the marathon (reference daemon
  process count → 0; nginx workers still up).
- **Caveat:** reproduced under a deliberately hostile constrained host; not every
  marathon failure is the server's fault (some are client-side connection churn
  while the nginx worker sits idle — see the doc's "Honest caveats").
- **Cite:** `docs/11-architecture/reliability-under-load.md` §item 3.

### A4 — CMS heartbeat drop → false `kXR_NotFound` for a file that exists

In a redirector/cluster, a data server's `cmsd` management connection can
transiently drop under load **even though its data plane is still serving
bytes**. Stock treats the server as gone, so a client asking for a file that
lives *only* on that server gets "not found" — a correctness failure caused
purely by control-plane load.

- **Upstream locus:** `cmsd`/manager control plane (availability decision).
- **Evidence — live, deterministic:** killing a data node's `cmsd` while its
  `xrootd` data server kept serving made the manager answer
  `[3011] file not found` for a file demonstrably on disk. The module's
  availability-biased selection (stale + blacklist fallback, `locate` kept
  strict) instead succeeds `xrdcp` 5/5 with correct checksums in the same
  scenario.
- **Cite:** `docs/11-architecture/reliability-under-load.md` §item 4 and §C.

### A5 — Stock `XrdHttp` accepts X.509 the WLCG/IGTF profile says to reject

Stock `XrdHttp`'s TLS layer performs no GSI chain / signing-policy verification;
it accepts certificates the WLCG CA/token profile requires be rejected:
out-of-namespace certs, wrong-CA-policy certs, and **CRL-revoked** end-entity
certs.

- **Upstream locus:** `XrdHttp` server TLS/GSI verification path.
- **Evidence — live + source-verified:** differential runs (`TEST_X509_DIFF=1`)
  recorded `xrootd = accept ⚠` vs `spec = reject` for `sp_out_of_namespace`,
  `sp_wrong_ca_block`, and `crl_revoked_eec (revoked)`. A second pass verified
  this against pinned XRootD **v6.1.0** source (`/tmp/xrootd-src`, tag v6.1.0):
  stock does **not** enforce Globus `signing_policy` at all, does **not** enforce
  RFC 3820 limited-proxy monotonicity, and only *warns* on CRL expiry rather than
  rejecting.
- **Fairness caveat (stated in-repo):** the stock server was in a baseline CA-dir
  config without extra CRL/`signing_policy` directives, so a ⚠ means "not
  enforced in this baseline." The v6.1.0 source read is what elevates this above
  a mere config artifact — `signing_policy` is not enforced *at all*, and CRL
  expiry only warns.
- **Cite:** `docs/10-reference/wlcg-x509-differential-findings.md` (results
  table); `docs/09-developer-guide/history-testing-and-incidents.md` §2.3;
  `docs/10-reference/xrootd-interoperability-conformance.md` §5.

---

## (B) Spec ambiguities and upstream quirks

### B1 — Undocumented `root://` wire behaviours ("none of this is in the spec")

Reverse-engineering the reference client/source surfaced wire behaviours the
official specification simply does not describe. The reference is self-consistent
here; the spec text is the gap.

- `kXR_mv` payload uses an **ASCII space (0x20) separator, not a NUL byte** —
  reading it as a NUL-terminated C string at `src[arg1len-1]` fails for every
  path (`protocol-notes.md` §13).
- Real clients may include **exactly one trailing NUL inside the path `dlen`**
  (`protocol-notes.md` §19).
- v5 clients send the 20-byte handshake **and** `kXR_protocol` as a **single
  44-byte TCP segment** (`protocol-notes.md` §"handshake").
- Further "spec purity had to yield to real `xrdcp`" items: v5 handshake reply
  format, `SecurityInfo` in `kXR_protocol`, plain-text GSI login params,
  `kXR_pgwrite` needing a 32-byte `kXR_status` response, and
  `kXR_new | kXR_delete` meaning overwrite (`quirks.md` §10).
- **Evidence:** reverse-engineered from the C++ source and confirmed by running
  real clients (behavioural, not a formal upstream ticket).
- **Cite:** `docs/10-reference/protocol-notes.md` (banner + §13, §19);
  `docs/10-reference/quirks.md` §10.

### B2 — `xrdcp` misleading "key values mismatch" on an EEC-vs-proxy

`xrdcp` prints `TLS: ossl_x509_check_private_key: key values mismatch` even when
the cert and key moduli match — the true cause is that an end-entity cert was
supplied where a proxy was expected. A pure red herring that cost real debugging
time.

- **Evidence — live:** MD5s of all three cert/key files matched (`ddc46a…`); the
  error was reproduced and traced to the EEC-vs-proxy client-side quirk.
- **Cite:** `docs/09-developer-guide/postmortem-origin-credential-shadowing.md`
  §5 ("dead-ends").

### B3 — Stock `mkdir` "idempotency" is an `XrdOss` namespace-cache artifact

Stock returns `mkdir` rc=0 for a directory it *itself* created earlier in the
same process, but correctly returns `kXR_ItExists` (3018) for a pre-existing
on-disk directory. It is a stable but quirky cache behaviour, not a wire
contract — judged a non-bug not to copy.

- **Cite:** `docs/10-reference/comparison/conformance-findings.md`
  ("non-bugs" note); `docs/09-developer-guide/history-testing-and-incidents.md`
  (2026-06-24 triage).

### B4 — `xrdgsiproxy info` ignores `X509_USER_PROXY`

The stock tool ignores the `X509_USER_PROXY` environment variable; this project's
`info` honours it (the more useful behaviour). Recorded as a stock quirk, a
deliberate divergence, not something to copy.

- **Cite:** `docs/09-developer-guide/history-client-tooling.md` (2026-06-26
  divergence list, item 3).

### B5 — Stock POSC disconnect handling (defensible difference)

On a client disconnect with an un-closed partial, stock's Persist-On-Successful-
Close path keeps the partial pending a reconnect window; this module removes it
immediately. Explicitly called "a defensible semantic difference, not a bug" —
listed only because it is an upstream behavioural quirk, left as a documented
xfail.

- **Cite:** `docs/10-reference/comparison/conformance-findings.md` (POSC note).

---

## (C) Explicitly *not* upstream bugs (recorded to prevent misattribution)

- **pgwrite CSE-retransmit vs hard-fail** — stock replies `kXR_ok` +
  `ServerResponseBody_pgWrCSE` retransmit list on a corrupt page; this module
  hard-fails with `kXR_ChkSumErr`. Both detect the corruption; only the recovery
  shape differs. (`conformance-findings.md`)
- **Stock `xrdcrc32c` can't checksum a `root://` URL** — it is a strictly-local
  tool with no `libXrdCl` linkage. "Not a bug on either side."
  (`history-client-tooling.md`)
- **Per-tool missing-file exit codes** (`xrdadler32`=1, `xrdcrc32c`=3,
  `xrdcrc64`=1) — a stock idiosyncrasy this repo matched rather than "fixed."
  (`history-client-tooling.md`)
- **Opaque parsing splits on `&` only, keeping `;` as value content** — this is
  correct, spec-conformant upstream behaviour (`XrdOucEnv.cc`/`XrdClURL.cc`); the
  parameter-smuggling bug was in *our* splitter, and the fix aligned us to stock.
- **gfal `davix`/neon TLS flakiness** and the **go-hep "GSI provider not found"**
  failures — client/environment limitations, not upstream `xrootd` defects. The
  go-hep- and gfal-found protocol bugs (sigver ack, stat/dirlist redirect,
  root-prefix match, RFC 4331 per-file quota) were all **this module's** defects.

---

## Summary

| # | Finding | Upstream locus | Tier | Evidence |
|---|---|---|---|---|
| A1 | `XrdCl` sync-call deadlock (un-interruptible) | `XrdCl` client | Defect | Live (GDB backtrace) |
| A2 | `XrdCl` "Invalid response" framing under concurrent dirlist | `XrdCl` client | Defect | Live, load-only |
| A3 | Reference daemons die under marathon pressure | `xrootd`/`cmsd` server | Defect | Live |
| A4 | CMS heartbeat drop → false `kXR_NotFound` | `cmsd`/manager | Defect | Live, deterministic |
| A5 | `XrdHttp` accepts out-of-ns / wrong-CA / CRL-revoked X.509 | `XrdHttp` TLS/GSI | Defect | Live + v6.1.0 source |
| B1 | Undocumented `root://` wire behaviours (mv separator, path NUL, 44-byte segment, …) | Wire protocol / spec | Quirk | Reverse-engineered + live clients |
| B2 | `xrdcp` "key values mismatch" on EEC-vs-proxy | `xrdcp` client | Quirk | Live |
| B3 | `mkdir` "idempotency" = `XrdOss` cache artifact | `xrootd` server | Quirk | Live, two probes |
| B4 | `xrdgsiproxy info` ignores `X509_USER_PROXY` | stock tool | Quirk | Live |
| B5 | POSC disconnect keeps partial pending reconnect | `xrootd` server | Quirk (defensible) | Live, xfail |

**Bottom line:** five confirmed upstream defects observed live — two in the
`XrdCl` client, two in the server / CMS control plane, and one security-relevant
X.509 non-enforcement in `XrdHttp` — plus a set of genuine spec ambiguities and
tool quirks. The reliability defects are consolidated in
`docs/11-architecture/reliability-under-load.md`; the security one is captured in
the WLCG X.509 differential goldens.

## Source index

- `docs/11-architecture/reliability-under-load.md` — A1–A4 (live load-observed
  server/client failure modes) + mitigations.
- `docs/10-reference/wlcg-x509-differential-findings.md` — A5 differential table
  (`{ours, xrootd, spec}` goldens).
- `docs/09-developer-guide/history-testing-and-incidents.md` §2.3 — A5
  source-level verification narrative (XRootD v6.1.0).
- `docs/10-reference/xrootd-interoperability-conformance.md` §5 — "more
  conformant than stock" summary.
- `docs/10-reference/protocol-notes.md`, `docs/10-reference/quirks.md` — B1
  undocumented wire behaviours / spec gaps.
- `docs/09-developer-guide/postmortem-origin-credential-shadowing.md` §5 — B2.
- `docs/10-reference/comparison/conformance-findings.md` — B3, B5, (C) non-bugs.
- `docs/09-developer-guide/history-client-tooling.md` — B4, (C) tool non-bugs.
