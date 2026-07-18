# Development History, Decisions & Lessons Learnt

**Date:** 2026-07-15
**Status:** Living master index. This is the entry point for "why does this
subsystem look the way it does" and "has someone hit this before" questions —
read the linked document for your area before spending time rediscovering
something already known.
**Origin:** synthesized from ~234 session-memory records accumulated across
the project's development (2026-04 through 2026-07-15), grouped by subsystem
and rewritten as narrative history. Individual per-topic memory files still
exist as a secondary, more granular record (see "Relationship to the memory
system" below), but this set of documents is now the canonical, in-repo
record of *why* — decisions, incidents, and lessons — as opposed to the
`docs/refactor/phase-NN-*.md` docs and code, which are the canonical record
of *what* (specs and current-state implementation detail).

None of these documents repeat implementation detail already covered by a
`docs/refactor/phase-NN-*.md` spec or a `docs/09-developer-guide/*.md`
reference doc — they link out to those instead and focus on the parts that
don't otherwise survive: the reasoning behind a design choice, the incident
that produced a guardrail, the bug that cost a day to find, the thing that's
still open.

---

## The six topic documents

| Document | Covers | Size |
|---|---|---|
| [History — Protocols & Feature Phases](history-protocols-and-feature-phases.md) | Native XRootD/pgread-pgwrite wire fidelity, S3, WebDAV extras, CMS mesh, proxy mode, pipelining, mirroring, dashboard, monitoring/AF-bridging, SciTags, federation (Pelican) | 59 KB |
| [History — Storage & Caching](history-storage-and-caching.md) | VFS seam closure, composable cache tiers, pluggable backends (pblock, Ceph/RADOS, S3, CVMFS), FRM/tape staging dissolution, unified cache state | 54 KB |
| [History — Client Tooling](history-client-tooling.md) | Native xrdcp/xrdfs, FUSE (xrootdfs), CVMFS native client (brixMount), GSI client interop, the "swiss army client" vision, robustness/UX/firewall/mount-speed work | 41 KB |
| [History — Testing & Incidents](history-testing-and-incidents.md) | Test harness evolution, conformance suites (WLCG x509/token, multiuser perms), chaos/reload testing, load testing, production postmortems (incl. the "host overloaded" banned-diagnosis incident) | 45 KB |
| [History — Security & Credentials](history-security-and-credentials.md) | Auth gate ordering, credential forwarding, TPC delegation (native + WebDAV), impersonation, GSI/TLS negotiation, ARC-CE httpg front proxy + `$brix_delegated_cred` / hashed-CA-dir directives, vulnerabilities found & fixed, XrdAcc | 62 KB |
| [History — Build, Infra & Decisions](history-build-infra-and-decisions.md) | Build system mechanics, packaging, codebase-wide refactors (rebrand, src realignment, hardening waves), **and the standing working agreements for AI agents in this repo** | 30 KB |

These sit alongside the five earlier `lessons-*.md` documents, which remain
the deep-dive references for their specific eras and are cross-linked from
the topic docs above rather than duplicated:

| Document | Covers |
|---|---|
| [lessons-migration-era-2026.md](lessons-migration-era-2026.md) | Structural migrations phases 55–66: storage-driver abstraction, VFS seam closure, composable-tier/FRM dissolution, `src/` conceptual realignment |
| [lessons-tpc-vfs.md](lessons-tpc-vfs.md) | Native TPC (GSI/async/TLS/delegation) and VFS storage-driver field guide |
| [lessons-codebase-hardening-2026-06.md](lessons-codebase-hardening-2026-06.md) | Whole-tree hardening pass: link-time hardening, `safe_size.h`, libFuzzer, ASan/UBSan, sandboxing |
| [lessons-security-reaudit-and-cleanup.md](lessons-security-reaudit-and-cleanup.md) | Security re-audit findings and cleanup |
| [lessons-brix-rebrand-and-suite-stabilization-2026-07.md](lessons-brix-rebrand-and-suite-stabilization-2026-07.md) | The BriX symbol rebrand and post-merge fast-suite stabilization |

---

## Open items across all six documents

The single most important thing to check before starting work in an
unfamiliar area: each history document ends with an open-items table. As of
2026-07-15 the notable standing ones are:

- **Native TPC-over-GSI delegation is broken** — flagged prominently near the
  top of [History — Security & Credentials](history-security-and-credentials.md#open-item)
  with repro steps and root-cause diagnosis. Do not assume this is fixed
  without re-running the `--tpc only` gate.
- See each document's closing table for the rest (hybrid-mesh WebDAV/XrdHttp
  gaps, S3 metadata-parity scoping decisions left undone, etc.)

## Relationship to the memory system

Claude's per-session memory system (`~/.claude/projects/.../memory/`) still
holds ~234 individual records, most now compacted to short pointers. Going
forward:

- **For subsystem history, design rationale, and lessons learnt, consult this
  document tree first** — it is the synthesized, durable record and is
  checked into the repo (survives memory resets, is reviewable in PRs, and is
  visible to every contributor, not just an AI agent's private memory).
- The memory system's `MEMORY.md` index now points here at the top of the
  file. Individual memory files remain as a secondary, more granular log
  (exact dates, session IDs, raw incident detail) and are still useful for
  archaeology, but should not be treated as more authoritative than this
  document tree when the two overlap — this tree was written *from* the
  memory files and is the reconciled, deduplicated version.
- New project/feedback memories saved in future sessions should still go
  through the normal per-file memory flow (they're cheap and low-latency to
  write), but anything that rises to the level of a durable
  decision/lesson/incident worth a future contributor reading should also be
  folded into the relevant document above when convenient.
