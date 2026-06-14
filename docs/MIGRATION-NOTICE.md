# Documentation Reorganization — Complete (December 2025 → May 2026)

The documentation has been reorganized into a numbered structure optimized for beginners. Old flat paths are deprecated but still exist as compatibility stubs.

## Current Structure

```
docs/
├── index.md                    ← Main navigation hub (START HERE)
├── MIGRATION-NOTICE.md         ← This file — mapping old → new paths
├── _archive/                   ← Archived planning documents
│   └── refactoring-proposal.md ← Original proposal for this reorganization
├── 01-getting-started/         ← Installation and setup
├── 02-concepts/                ← Domain knowledge for newcomers
├── 03-configuration/           ← Build, config reference, TLS
├── 04-protocols/               ← Protocol-specific guides
├── 05-operations/              ← Production operations
├── 06-authentication/          ← Auth and PKI setup
├── 07-security/                ← Security hardening
├── 08-metrics-monitoring/      ← Observability
├── 09-developer-guide/         ← Contributing and development
├── 10-architecture/            ← Visual architecture overview (new)
└── 10-reference/               ← Deep technical reference
```

## Legacy Path → New Path Mapping

| Old Location | New Location | Notes |
|---|---|---|
| `docs/getting-started.md` | [01-getting-started/getting-started-full.md](01-getting-started/getting-started-full.md) | Consolidated into full guide; quick-install.md now redirects here |
| `docs/background.md` | [02-concepts/xrootd-basics.md](02-concepts/xrootd-basics.md) | xrootd-background.md deleted as duplicate |
| `docs/architecture/` | [10-architecture/overview.md](10-architecture/overview.md) + [09-developer-guide/architecture-overview.md](09-developer-guide/architecture-overview.md) | Visual overview now consolidated into single page with Mermaid diagrams |
| `docs/comparison/` | [10-reference/design-rationale.md](10-reference/design-rationale.md) | |
| `docs/configuration/` | [03-configuration/](03-configuration/) + [rpm-package-build.md](03-configuration/rpm-package-build.md) | directives moved to config-reference.md |
| `docs/contributing/` | [09-developer-guide/contributing.md](09-developer-guide/contributing.md) | |
| `docs/metrics/` | [08-metrics-monitoring/](08-metrics-monitoring/) | |
| `docs/operations/` | [05-operations/](05-operations/) | |
| `docs/optimizations/*` | [09-developer-guide/optimizations.md](09-developer-guide/optimizations.md) | All optimization docs consolidated into single file |
| `docs/pki/` | [06-authentication/](06-authentication/) | |
| `docs/reference/` | [10-reference/](10-reference/) | |
| `docs/testing/` | [09-developer-guide/testing-runbook.md](09-developer-guide/testing-runbook.md) | infrastructure.md consolidated into runbook |
| `docs/webdav/` | [04-protocols/webdav-overview.md](04-protocols/webdav-overview.md) | |

## Cleanup Notes (May 2026)

The following stub redirect files have been removed — content was already consolidated:
- `docs/optimizations/*.md` → all merged into `09-developer-guide/optimizations.md`
- `docs/testing/infrastructure.md` → merged into `09-developer-guide/testing-runbook.md`
- `docs/01-getting-started/quick-install.md` → redirected to `getting-started-full.md` (the comprehensive guide)
- `docs/02-concepts/xrootd-background.md` → deleted; content duplicated in `xrootd-basics.md`

## May 2026 — New Additions and Enhancements

### Architecture Overview (New Section)
- **[10-architecture/overview.md](10-architecture/overview.md)** — Single-page visual guide with Mermaid diagrams showing:
  - High-level client → nginx layers → filesystem architecture
  - Protocol comparison table (XRootD vs WebDAV vs S3)
  - Three deployment mode diagrams
  - Native XRootD request flow sequence diagram

### Glossary Enhancement
- **[10-reference/glossary.md](10-reference/glossary.md)** — Enhanced with:
  - **A-Z quick lookup table** at top for fast term lookup
  - **Missing terms added:** Manager Mode, Cluster Mode, S3-Compatible Endpoint, JWKS (separate entry), Bearer Token (separate from WLCG token), Proxy Certificate (separate from x509 certificate)
  - **Expanded kXR_opcode table** — now shows all 12 commonly used opcodes (was 5)
  - **All cross-references fixed** — previously pointed to non-existent proposed paths

## June 2026 — Archival pass + loose-file consolidation (2026-06-13)

A second tidy-up moved everything that is *not* current, living documentation out
of the active tree:

- **Loose top-level docs relocated** into the numbered sections — e.g.
  `docs/quick-start-guide.md` → [01-getting-started/](01-getting-started/),
  `docs/Tier{1,2}-Stream-Data-Paths.md` → [10-architecture/](10-architecture/),
  `docs/comparison-nginx-xrootd-vs-canonical.md` and `docs/FEATURE_GAPS.md` →
  [10-reference/](10-reference/), `docs/TEST_PROTOCOL_MAPPING.md` →
  [09-developer-guide/](09-developer-guide/).
- **Completed plans, point-in-time status reports, and superseded proposals
  archived** to [`_archive/`](_archive/) (and `_archive/refactor/`,
  `_archive/unification/`) — the `PHASE1–6` unification family, the
  `shared-code-plan*` series, completed `docs/refactor/phase-*` implementation
  plans, the root `CHANGES_VS_GITHUB`/`CODE_REDUCTION_ANALYSIS`/`MIGRATION-NOTICE`
  duplicates, etc. See [`_archive/README.md`](_archive/README.md) for the full
  catalogue and the reason each was archived.
- **Living docs fact-checked against `src/`** and corrected in place (broken
  relative links, stale counts/opcodes/directive lists, "now implemented" status).

Ground rule going forward: `src/` is authoritative; `docs/_archive/` is history.

---

See [docs/index.md](index.md) for the full interactive index with learning paths.
