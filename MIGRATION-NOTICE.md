# Documentation Migration Notice

**Date:** May 2026  
**Status:** Complete — see [docs/index.md](docs/index.md) for the new structure

---

## What Changed

The documentation has been reorganized from a flat directory of ~60 files into a **numbered, progressive learning path**. This makes it easier to find what you need without reading through everything.

### Before: Flat Directory (Confusing)

```
docs/
├── getting-started.md          ← where do I start?
├── background.md               ← same as above?
├── architecture.md             ← is this beginner or advanced?
├── configuration.md            ← which one, there are three...
├── pki.md                      ← same problem
├── ...                         ← 57 more files to sort through
└── (and another dozen subdirs)
```

A new developer sees **60+ files** with no clear order or priority. Which ones matter? Which are duplicates?

### After: Numbered Learning Paths (Clear)

```
docs/
├── index.md                    ← START HERE — your entry point
├── MIGRATION-NOTICE.md         ← you're reading this
│
├── 01-getting-started/         ← "I want to install and run" (30 min)
├── 02-concepts/                ← "I need domain knowledge" (15 min)
├── 03-configuration/           ← "I need to configure something"
├── 04-protocols/               ← "I want to use a specific protocol"
├── 05-operations/              ← "I need to operate in production"
├── 06-authentication/          ← "I need to set up access control"
├── 07-security/                ← "I need to harden my deployment"
├── 08-metrics-monitoring/      ← "I want observability"
├── 09-developer-guide/         ← "I want to contribute code"
└── 10-reference/               ← "I need deep technical details"
```

---

## File Migration Map

| Old Path | New Location | Status |
|---|---|---|
| `docs/getting-started.md` | [01-getting-started/quick-install.md](01-getting-started/quick-install.md) | Migrated |
| `docs/background.md` | [02-concepts/xrootd-basics.md](02-concepts/xrootd-basics.md) | Migrated |
| `docs/architecture/index.md` + subfiles | [09-developer-guide/architecture-overview.md](09-developer-guide/architecture-overview.md) + [10-reference/](10-reference/) | Migrated |
| `docs/building.md` | [03-configuration/build-guide.md](03-configuration/build-guide.md) | Migrated |
| `docs/configuration/directives.md` | [03-configuration/config-reference.md](03-configuration/config-reference.md) | Migrated |
| `docs/authentication.md` | [06-authentication/auth-overview.md](06-authentication/auth-overview.md) | Migrated |
| `docs/pki.md` + `pki/` | [06-authentication/](06-authentication/) | Migrated |
| `docs/tls.md` | [03-configuration/tls-config.md](03-configuration/tls-config.md) | Migrated |
| `docs/proxy-mode.md` | [05-operations/proxy-mode-guide.md](05-operations/proxy-mode-guide.md) | Migrated |
| `docs/webdav.md` + `webdav/` | [04-protocols/webdav-overview.md](04-protocols/webdav-overview.md) | Migrated |
| `docs/cluster-mode.md` | [05-operations/cluster-management.md](05-operations/cluster-management.md) | Migrated |
| `docs/hierarchical-cms-cluster.md` | [05-operations/hierarchical-cluster.md](05-operations/hierarchical-cluster.md) | Migrated |
| `docs/manager-mode.md` | [05-operations/manager-mode.md](05-operations/manager-mode.md) | Migrated |
| `docs/operations.md` + `operations/` | [05-operations/](05-operations/) | Migrated |
| `docs/status.md` | [05-operations/operation-status.md](05-operations/operation-status.md) | Migrated |
| `docs/metrics-and-logging.md` | [08-metrics-monitoring/monitoring-guide.md](08-metrics-monitoring/monitoring-guide.md) | Migrated |
| `docs/benchmarks.md` | [05-operations/performance-benchmarks.md](05-operations/performance-benchmarks.md) | Migrated |
| `docs/testing.md` + `testing/` | [09-developer-guide/testing-runbook.md](09-developer-guide/testing-runbook.md) | Migrated |
| `docs/contributing.md` + `contributing/` | [09-developer-guide/contributing.md](09-developer-guide/contributing.md) | Migrated |
| `docs/development.md` | [09-developer-guide/dev-workflow.md](09-developer-guide/dev-workflow.md) | Migrated |
| `docs/xrootd-concepts.md` | [10-reference/xrootd-concepts-deep.md](10-reference/xrootd-concepts-deep.md) | Migrated |
| `docs/protocol-notes.md` | [10-reference/protocol-notes.md](10-reference/protocol-notes.md) | Migrated |
| `docs/quirks.md` | [10-reference/quirks.md](10-reference/quirks.md) | Migrated |
| `docs/handler-reference.md` | [10-reference/handler-reference.md](10-reference/handler-reference.md) | Migrated |
| `docs/types.md` | [10-reference/types.md](10-reference/types.md) | Migrated |
| `docs/feature-roadmap.md` | [09-developer-guide/feature-roadmap.md](09-developer-guide/feature-roadmap.md) | Migrated |
| `docs/xrdcp-interactions.md` | [04-protocols/xrootd-client-interaction.md](04-protocols/xrootd-client-interaction.md) | Migrated |
| `docs/xrdhttp-parity-roadmap.md` | [10-reference/xrdhttp-parity-roadmap.md](10-reference/xrdhttp-parity-roadmap.md) | Migrated |
| `docs/comparison-with-xrootd.md` | [10-reference/design-rationale.md](10-reference/design-rationale.md) | Migrated |
| `docs/deployment-guide.md` | [10-reference/deployment-guide.md](10-reference/deployment-guide.md) | Migrated |
| `docs/optimizations.md` + `optimizations/` | [09-developer-guide/optimizations.md](09-developer-guide/optimizations.md) | Migrated |
| `docs/test-pki.md` | [06-authentication/test-pki-setup.md](06-authentication/test-pki-setup.md) | Migrated |
| `docs/test-tokens.md` | [06-authentication/test-token-generation.md](06-authentication/test-token-generation.md) | Migrated |

---

## What This Means For You

1. **Start at [`docs/index.md`](docs/index.md)** — it has learning paths organized by your experience level
2. **Follow the numbered sections in order** if you're new to XRootD or nginx
3. **Skip ahead** if you already know the domain concepts and just need configuration help
4. **Bookmark the new paths** — old links may still work temporarily but are deprecated

---

## Why This Matters

Before: *"I'm new here, there are 60 files, which do I read first?"*  
After: *"Open index.md → follow 'New to XRootD' path → done in 30 minutes."*

The content is the same. The organization helps you find it faster.
