# Security Policy

brix-cache (`nginx-xrootd`) is a data-transfer server: it terminates untrusted
network connections, authenticates them (GSI/X.509 proxies, WLCG bearer tokens,
Kerberos 5, SSS, S3 SigV4), and hands out file data on behalf of other people's
identities. Almost every bug in the request path is a security bug in some
deployment. Please treat it that way, and so will we.

## Reporting a vulnerability

**Do not open a public issue for a security report.** Use either:

1. **GitHub private vulnerability reporting** — the *Report a vulnerability*
   button under this repository's **Security** tab. Preferred: it gives us a
   private fork to develop and review the fix in.
2. **Email** — `rob.currie@ed.ac.uk`, subject prefixed `[brix-cache security]`.
   Use this if you cannot access GitHub, or want to send an encrypted archive.

Please include, as far as you have it:

- affected version or commit (`nginx -V`, or the `BRIX_SERVER_VERSION` banner),
- the configuration that exposes it — the relevant `brix_*` directives, the
  auth mechanism in play, and the backend (POSIX, S3, Ceph, CVMFS, remote),
- a reproducer: a request sequence, a `xrdcp`/`curl` invocation, or a packet
  capture. `tests/` is full of harnesses you can build one on top of,
- what you believe the impact is, and whether you have told anyone else.

You do **not** need a working exploit. A crash under a fuzzer, an assertion that
fires on attacker-controlled input, or a convincing read of the code is enough.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement that a human has read it | 3 working days |
| Initial assessment — severity, affected versions, whether we can reproduce | 10 working days |
| Fix or documented mitigation for high/critical | 30 days from assessment |
| Public disclosure | coordinated; by default when a fix ships |

This is a small project without a paid on-call rotation, so those are honest
targets rather than a contractual SLA. If a deadline slips you will hear why,
not silence. We will credit you in the changelog and the advisory unless you
ask us not to. There is no bug bounty.

If you have not heard anything in 10 working days, send a follow-up — mail gets
lost. If you still hear nothing after a further 10, treat the report as
unacknowledged and disclose as you see fit.

## Supported versions

Fixes land on `main` first and ship in the next release. Only the most recent
minor series receives backports.

| Version | Supported |
|---|---|
| 1.4.x | ✅ security fixes |
| 1.3.x and earlier | ❌ upgrade |
| `main` | ✅ fixed at HEAD |

Distribution packages (`nginx-mod-brix-cache`) inherit the support status of
the upstream version they are built from.

## Scope

**In scope** — anything reachable by a client of a correctly configured server:

- the `root://` wire-protocol parsers and every opcode handler,
- HTTP/WebDAV, TPC (native and WebDAV `COPY`), and the GridFTP gateway,
- authentication and authorization: proxy-certificate and CA-path validation,
  token signature/claim checking, SSS keys, gridmap and VO mapping, delegation
  and credential forwarding,
- path resolution and the VFS seam — any traversal, symlink, or
  identity-confusion bug that reaches data another user owns,
- the cache: cross-identity leakage of cached objects or metadata,
- shared-memory tables, and anything a hostile *peer server* can do to a
  redirector or a data server in the mesh,
- privilege handling in the client tools and the FUSE driver.

**Out of scope:**

- an operator configuring the server to do exactly what they asked for
  (`brix_allow_write` on an unauthenticated location, disabled TLS
  verification, a world-readable keytab) — see the
  [hardening guide](docs/07-security/hardening-guide.md),
- resource exhaustion that any client could equally cause with legitimate
  traffic, absent a specific amplification factor,
- vulnerabilities in nginx itself, or in XRootD, OpenSSL, Ceph, or other
  dependencies — report those upstream; tell us too if we ship an affected
  default,
- results from an automated scanner with no analysis of whether the code path
  is reachable,
- findings in `docs/`, `tests/`, or the CI tooling that do not affect a
  deployed server.

Testing must be against **your own** deployment. Do not probe production grid
endpoints belonging to anyone else.

## Hardening and design context

- [Threat model](docs/07-security/threat-model.md) — trust boundaries and the
  attacker classes we design against.
- [Hardening guide](docs/07-security/hardening-guide.md) — how to deploy this
  safely.
- [Hostile-network lessons](docs/07-security/hostile-network-lessons.md) — the
  failure modes found by the fault-injection sweeps, and what they taught us.
- [Protocol fuzz conformance](docs/07-security/protocol-fuzz-conformance.md) —
  the malformed-packet corpus and how to extend it.

## Security-relevant contribution rules

If you are fixing or touching this surface, [`CONTRIBUTING.md`](CONTRIBUTING.md)
and the invariants in [`CLAUDE.md`](CLAUDE.md) are binding. In particular: every
change ships with three tests — success, error, and a **security negative** that
proves the rejection actually happens. Dependencies are two-sidedly bounded and
checked by `tools/ci/check_python_deps.py`; do not widen a bound to make a build
pass.
