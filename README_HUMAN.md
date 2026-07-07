# BriX-Cache, explained like a human

> **One nginx server that speaks every language physics data speaks.**

This is the friendly front door to the project. No jargon walls, no assumed
physics degree — just what this thing is, why it exists, how it works, and the
parts we're genuinely proud of. Every section links to the real documentation
when you want to go deeper. (The [README](README.md) is the technical
front page; [docs/index.md](docs/index.md) is the full guided map.)

---

## The 30-second version

Physicists at CERN, SLAC, and Fermilab move **petabytes** of particle-collision
data around the world every day. They do it with two protocols that ordinary
web servers have never spoken: **XRootD** (`root://`) and **WebDAV**
(`davs://`).

Traditionally, serving that data means running a zoo: an `xrootd` daemon for
`root://`, a web server for WebDAV, an object store like MinIO if anyone wants
S3. Three services, three config languages, three things to monitor, three
things that page you at 3 a.m.

**BriX-Cache** (this repository — `nginx-xrootd`) collapses the zoo into one
process. It teaches nginx — the same battle-tested server behind GitHub and
Netflix — to speak XRootD natively, plus WebDAV and an S3-compatible API, all
serving the **same files off the same disk**:

```
        /data/atlas/run3/results.root        ← one file on disk
                       │
        ┌──────────────┼──────────────┐
   root://host//   davs://host//   s3://host/
     xrdcp, xrdfs    curl, rucio,    aws-cli,
     python client   your browser    boto3
```

One binary. One config file (a working server is ~20 lines). One
`/metrics` endpoint. Same bytes, same permissions, whichever door a client
walks in through.

**Want to try it?** You can go from zero to a working, verified server in
about 50 minutes following the
[beginner path](docs/index.md#-i-want-a-working-server---start-here) — no
XRootD or physics background required.

---

## Wait — what's XRootD? (plain English)

Think **FTP, but purpose-built for 50-gigabyte physics files**. It's the
standard file-moving protocol of High Energy Physics: persistent sessions,
file handles, parallel streams, per-page checksums baked into the wire format.

| If you know… | …then this is |
|---|---|
| `http://` | `root://` — a URL scheme for XRootD servers |
| `scp` / `rsync` | `xrdcp` — copies files to/from an XRootD server |
| `ssh` + `ls` | `xrdfs` — browse a remote server interactively |

One naming trap worth knowing:
**ROOT** (the C++ analysis framework and `.root` file format) and **XRootD**
(the network protocol) are different things. This server moves raw bytes; it
never parses `.root` files. More context:
[XRootD Basics](docs/02-concepts/xrootd-basics.md) and the
[Glossary](docs/10-reference/glossary.md).

**And why nginx?** Because nginx has a `stream` module that can speak *any*
TCP protocol, not just HTTP — so the XRootD wire protocol is implemented
directly on nginx's famously efficient event loop, with no translation layer.
Thousands of idle or slow clients cost almost nothing; blocking disk work is
handed to a thread pool so no connection can ever stall the others. The full
argument for this design lives in
[Design Rationale](docs/10-reference/design-rationale.md).

---

## What it does

**Protocols.** All from one nginx instance, mix-and-match per port:

| You configure | Clients use | What it's for |
|---|---|---|
| `root://` / `roots://` | `xrdcp`, `xrdfs`, PyXRootD | Native XRootD, plain or TLS-from-first-byte |
| `davs://` (WebDAV/HTTPS) | curl, rucio, browsers | HTTP file access, full method set incl. LOCK & COPY |
| S3-compatible REST | aws-cli, boto3 | Cloud tooling against physics data, SigV4 auth, multipart |
| `cvmfs://` | CVMFS clients | A drop-in site cache for software distribution (replaces Squid) |
| `cms://` | cluster managers | XRootD clustering: registration, redirects, hierarchy |
| `/metrics` + `/brix/` | Prometheus, humans | Counters and a live HTTPS operator dashboard |

**All 32 active XRootD 5.2 opcodes** are implemented — reads, writes,
scatter-gather, paged I/O with CRC32c, directory listing, extended attributes,
third-party copy, staging. Per-opcode status:
[Operation Status](docs/05-operations/operation-status.md).

**Authentication** — the whole grid menu, checked before a single byte moves:
anonymous, GSI/x509 proxy certificates (with VOMS and request signing), WLCG
and SciTokens bearer tokens (with per-path scope enforcement), shared-secret
(SSS), Kerberos 5, password, host allowlists, S3 SigV4. Two authorization
engines, including a faithful re-implementation of stock XRootD's authdb
format — so an existing site policy file drops in unchanged. Start at
[Authentication Overview](docs/06-authentication/auth-overview.md).

**Three deployment shapes** (details: [Deployment Modes](docs/02-concepts/deployment-modes.md)):

1. **Standalone server** — nginx *is* your storage server, serving local disk.
2. **Transparent proxy** — slide it in front of an existing `xrootd` daemon and
   instantly gain TLS, auth, and metrics *without touching the backend or any
   client config*. The backend becomes invisible.
3. **WebDAV perimeter** — terminate HTTPS and token auth at the edge, forward
   plain HTTP to an internal server.

---

## The special bits

These are the parts that make this project more than "nginx with extra
protocols."

### One data path, enforced by machine

Every protocol handler funnels through a single virtual filesystem layer
(the VFS) before touching storage. Raw file syscalls are *only allowed* in one
directory of the tree — and a CI guard fails the build if anyone tries to
sneak one in elsewhere. That means path confinement (kernel-level
`openat2(RESOLVE_BENEATH)` — directory-escape attacks stop in the kernel, not
in a regex), metrics, caching, and checksums are byte-identical across
`root://`, WebDAV, and S3. One implementation per security concern, so a fix
lands everywhere at once. Storage backends are pluggable behind the same seam
(POSIX today; Ceph/RADOS and object experiments in-tree). See
[Cross-Protocol Unification](docs/11-architecture/cross-protocol-unification.md)
and [src/fs/README.md](src/fs/README.md).

### Spec-first security, receipts included

Grid authentication is hard: federated identities, short-lived proxy
certificates, token scopes where `storage.read:/cms` must mean *only* `/cms`
even after path tricks. This project's answer is to implement the RFCs and
WLCG profiles directly and then prove it: a **510-case WLCG token conformance
suite**, an x509/CA conformance suite, and differential testing against the
official XRootD server (which has found real divergences — in *their*
implementation). Add a published
[threat model](docs/07-security/threat-model.md), a
[four-layer hardening guide](docs/07-security/hardening-guide.md), fuzz
targets, ASan/UBSan test lanes, and hardened builds (PIE, full RELRO, zero
`strcpy`-family calls in the tree).

### Byte-exact when the network is terrible

On a clean network, throughput matches the reference XRootD daemon. On a bad
one — the "hotel WiFi abroad" scenario — the in-tree fault-injection harness
shows transfers **finish, byte-exact**, where the stock stack stalls or fails:
at 1% simulated loss the native client resumes at the byte offset over both
`root://` and HTTP Range requests (roughly a 1000× jump in HTTP loss
tolerance). Slow, never corrupt. Methodology and honest caveats:
[README § Performance & resilience](README.md#performance--resilience).

### A CVMFS site cache that never drops a client

The `cvmfs://` handler turns the same binary into a Tier-2 software cache:
coalesced fills (a 1000-core farm asking for the same file triggers exactly
one upstream fetch), SHA-1 content verification before anything is admitted
(zero corrupt bytes served, ever — corrupt objects are quarantined), automatic
failover between Stratum-1 origins ranked by measured round-trip time, and
"never-drop" semantics: clients always get a well-formed HTTP answer, even
when the WAN is on fire.

### A complete clean-room client suite

The `client/` tree is a from-scratch, pure-C client stack with **zero
dependency on the official XRootD libraries**: `xrdcp` (with sync/mirror,
journals and resume, filters), `xrdfs` (JSON output, `tail -f`, recursive
ops), diagnostics (`xrddiag` with capture/replay), checksum and manifest
tools, GSI/SSS helpers, two FUSE mounts (`xrootdfs` and the multi-backend
`brixMount`, including a writable CVMFS overlay), a POSIX `LD_PRELOAD` shim,
and the embeddable `libxrdc` C library. Tour:
[Native Client Tools](docs/04-protocols/native-client-tools.md).

### Engineering culture you can audit

- **Zero `goto`** in the entire module and client source — enforced, not aspirational.
- Every function carries a WHAT/WHY/HOW doc block; every directory has a README.
- **Every change needs three tests**: success, error, and a security-negative.
- **5,400+ test functions** (≈8,700 collected cases) run against *real* nginx
  processes with real PKI — no mocks — including an adversarial "evil-actor"
  suite that hunts worker crashes and data races with hostile wire frames.
- Development happens through numbered, written-first refactor phases
  (60+ so far), each specified before code is typed. Postmortems for the
  gnarly bugs are published in the
  [developer guide](docs/09-developer-guide/) — read the
  [shared-memory mutex stall](docs/09-developer-guide/postmortem-shmtx-semaphore-stall.md)
  one if you enjoy a good detective story.

### Boring on purpose, where it counts

Operations is deliberately just… nginx. `nginx -s reload` rotates
certificates without dropping connections; JWKS, CRLs, and authdb hot-reload
on change; `nginx -t` refuses to start with missing certs or directories
instead of failing at 3 a.m.; RPM packages exist for RHEL/Alma 8–11. Every
request lands in a Prometheus counter (fixed, low-cardinality labels — your
dashboards stay fast) and a structured access log, with a live transfer
monitor at `/brix/`. See the
[Monitoring Guide](docs/08-metrics-monitoring/monitoring-guide.md) and
[Operations Guide](docs/05-operations/operations-guide.md).

---

## What it deliberately is not

Honesty section. The official XRootD project is a 20-year, ~380k-line
general-purpose framework; this module is intentionally narrower — a lean,
auditable data plane for POSIX-backed sites that already trust nginx. Not
covered: tape/mass-storage residency management (FRM/MSS), arbitrary
third-party storage plugins, and some cluster-admin corners. The full, honest
ledger lives in [Gaps vs Official XRootD](docs/10-reference/gaps-vs-xrootd.md)
and the [comparison](docs/10-reference/design-rationale.md). If you need
those, run upstream XRootD — possibly with BriX-Cache in front of it as a
transparent proxy, which is rather the point.

---

## By the numbers

| | |
|---|---|
| Protocols served from one binary | root://, roots://, WebDAV, S3, cvmfs://, cms:// |
| XRootD opcodes implemented | all 32 active (v5.2 protocol) |
| Module source | ~200k lines of C across ~1,000 focused files |
| Clean-room client suite | ~53k lines, no upstream XRootD libraries |
| Tests | 5,400+ test functions, ≈8,700 collected cases, no mocks |
| WLCG token conformance | 510 cases |
| Documentation | 440+ markdown docs, beginner path included |
| `goto` statements | 0 |
| Minimal working config | ~16 lines |
| Zero → verified server | ~50 minutes ([start here](docs/index.md#-i-want-a-working-server---start-here)) |
| License | [AGPL-3.0-only](LICENSE) |

---

## Where to go next

- **"I've never touched XRootD or built from source."** →
  [Before You Start](docs/01-getting-started/before-you-start.md), then
  [What Is This Project?](docs/01-getting-started/what-is-this.md)
- **"Give me a running server."** →
  [Getting Started (Full)](docs/01-getting-started/getting-started-full.md)
- **"I run a site and want this in production."** →
  [Production Deployment](docs/03-configuration/production-deployment.md) and the
  [Security Hardening Guide](docs/07-security/hardening-guide.md)
- **"I think in diagrams."** →
  [Architecture Overview](docs/11-architecture/overview.md)
- **"I want to contribute."** →
  [Development Workflow](docs/09-developer-guide/dev-workflow.md),
  [Coding Standards](docs/09-developer-guide/coding-standards.md), and
  [AGENTS.md](AGENTS.md)
- **Everything else** → [docs/index.md](docs/index.md), the guided map.
