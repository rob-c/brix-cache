# Documentation Refactoring Proposal

> Created: 2026-05-12 | Status: Proposed | Audience: Contributors deciding whether to adopt this project

---

## Problem Statement

A developer who has **never used XRootD or nginx** encounters three barriers:

1. **Terminology wall**: GSI, WLCG, VOMS, xrdcp, xrdfs, ROOT, kXR_opcodes — all assumed known
2. **Structural fragmentation**: 43+ files scattered across root level and 8+ subdirectories with significant duplication
3. **No visual "big picture"**: Architecture is described in text but not visualized for quick understanding

The current documentation assumes the reader either already knows XRootD or wants to read everything from scratch. There is no middle ground — a guided path that explains *what each thing means* as you encounter it.

---

## Current State Analysis

### Structural Issues

| Problem | Examples |
|---|---|
| **Duplicate files** | `metrics-and-logging.md` (root) + `metrics/` directory (6 files); `testing.md` (root) + `testing/` (3 files); `comparison-with-xrootd.md` (root) + `comparison/` (3 files) |
| **Flat root-level sprawl** | 28 top-level `.md` files in `docs/` — too many to navigate without an index |
| **Cross-references scattered across 4 locations** | README.md, docs/index.md, AGENTS.md, individual doc headers all maintain separate (out-of-sync) navigation tables |

### Content Gaps for Newcomers

1. **No glossary** — terms like "GSI proxy certificate", "WLCG token", "kXR_opcodes" appear throughout but are only defined inline in scattered places
2. **No visual architecture diagram** — ASCII text diagrams exist but there's no single-page visual overview showing how components relate at a glance
3. **Getting-started is 471 lines** — covers everything including S3 multipart, HTTP-TPC credential delegation, and advanced PKI setup in one document that should be focused on "first working server"
4. **No prerequisites section** — assumes familiarity with concepts like "what is a TCP port", "how does HTTPS work", or at minimum "what is GSI authentication"

---

## Proposed New Structure

```
docs/
├── index.md                      ← Navigation hub (unchanged role, simplified content)
│
├── 01-getting-started/           ← NEW: Organized by learning phase
│   ├── 01-overview.md            ← What is this project? Why does it exist?
│   ├── 02-prerequisites.md       ← What you need to know *before* starting (no physics background required)
│   ├── 03-build-and-run.md       ← Minimal: one protocol, anonymous access, working in 15 minutes
│   ├── 04-add-protocols.md       ← Adding WebDAV, S3 (optional extensions)
│   └── 05-troubleshooting.md     ← Common errors with solutions
│
├── glossary.md                   ← NEW: All terminology explained, cross-referenced from other docs
│
├── 10-architecture/              ← Consolidated architecture docs
│   ├── overview.md               ← Visual diagram + high-level mental model (NEW)
│   ├── stream-layer.md           ← Native XRootD protocol handling
│   ├── webdav-layer.md           ← WebDAV/HTTPS layer
│   └── s3-layer.md               ← S3-compatible HTTP layer
│
├── 20-operations/                ← Consolidated operations docs
│   ├── read.md                   ← (from operations/read.md)
│   ├── write.md                  ← (from operations/write.md)
│   ├── management.md             ← (from operations/management.md)
│   └── index.md                  ← Navigation between above
│
├── 30-configuration/             ← Consolidated configuration docs
│   ├── directives.md             ← (from configuration/directives.md)
│   ├── examples.md               ← (from configuration/examples.md)
│   ├── quick-reference.md        ← (from configuration/quick-reference.md)
│   └── index.md                  ← Navigation between above
│
├── 40-security/                  ← NEW: Consolidated auth/PKI docs
│   ├── authentication.md         ← Unified auth guide (from authentication.md + pki/index.md)
│   ├── pki-setup.md              ← PKI concepts and trust model
│   ├── gsi-certificates.md       ← GSI/x509 proxy certificates (from pki/gsi-auth.md)
│   ├── token-auth.md             ← JWT/WLCG bearer tokens
│   └── authorization.md          ← VO/FQAN ACLs, scopes (from pki/authorization.md)
│
├── 50-deployment/                ← Deployment-specific docs
│   ├── standalone.md             ← Standalone server patterns
│   ├── proxy-mode.md             ← Transparent XRootD proxy (moved from root)
│   ├── webdav-proxy.md           ← WebDAV perimeter proxy
│   ├── cluster-mode.md           ← Manager/cluster mode (moved from root)
│   └── hierarchical-cluster.md   ← Hierarchical CMS cluster (moved from root)
│
├── 60-reference/                 ← Developer reference (unchanged purpose, cleaner structure)
│   ├── xrootd-concepts.md        ← Protocol concepts (from reference/xrootd-concepts.md)
│   ├── protocol-notes.md         ← Wire protocol details
│   ├── quirks.md                 ← Design mismatches and trade-offs
│   ├── handler-reference.md      ← Function signatures
│   ├── types.md                  ← Struct definitions
│   └── nginx-concepts.md         ← nginx internals reference (from reference/nginx-concepts.md)
│
├── 70-contributing/              ← Contributing docs (consolidated from contributing/)
│   ├── index.md                  ← Navigation hub
│   ├── workflow.md               ← Development workflow
│   ├── code-style.md             ← Code style expectations
│   └── extending.md              ← How to add new features (recipes moved here)
│
├── 80-testing/                   ← Testing docs (consolidated from testing/)
│   ├── runbook.md                ← Running tests (from testing.md + testing/index.md)
│   ├── infrastructure.md         ← Test server setup
│   └── writing-tests.md          ← How to write new tests
│
    misc/                         ← Deprecation candidates — redirect or archive
    ├── benchmarks.md             ← Performance data (keep, but smaller)
    ├── feature-roadmap.md        ← Future plans
    ├── missing_optional.md       ← Feature gaps vs official xrootd
    └── comparison-with-xrootd.md ← Design rationale (keep, shorten for newcomers)

```

---

## What Changes, What Stays

### CREATE NEW

| File | Purpose | Rationale |
|---|---|---|
| `docs/01-getting-started/*.md` | Split getting-started into phased learning | 471-line doc is overwhelming; split by "must know" vs "nice to know" |
| `docs/glossary.md` | Terminology reference | Newcomers encounter physics terms without explanation — this becomes the single source of truth |
| `docs/10-architecture/overview.md` | Visual architecture diagram | ASCII diagrams are scattered; newcomers need one page with a clean visual overview |

### CONSOLIDATE INTO

| Action | Files Involved | Result |
|---|---|---|
| Merge auth/PKI docs | authentication.md + pki/*.md (5 files) → 40-security/ | Security is one concern, not three scattered layers |
| Consolidate root-level metrics | metrics-and-logging.md + metrics/*.md (6 files) → keep only essential metrics pages in their logical section | Reduce noise; move detailed Prometheus examples to reference |
| Move proxy/cluster docs | proxy-mode.md, cluster-mode.md, hierarchical-cms-cluster.md → 50-deployment/ | These are deployment patterns, not operations or architecture |

### DEPRECATE / REDIRECT

| File | Reason | Action |
|---|---|---|
| `docs/test-pki.md` | Setup guide belongs in getting-started extensions | Move relevant content to 01-getting-started/04-add-protocols.md |
| `docs/test-tokens.md` | Same as above | Move relevant content to 01-getting-started/04-add-protocols.md |
| Root-level duplicate index files | README, docs/index.md, AGENTS.md all maintain separate navigation tables | Standardize on one primary navigation hub (index.md), add redirect comments elsewhere |
| `docs/xrdhttp-parity-roadmap.md` | Niche content for ongoing development tracking | Move to `.github/` or keep in root with deprecation note |

---

## Specific Changes for Newcomer Experience

### 1. Add a Glossary (`docs/glossary.md`)

A newcomers' glossary should answer: "What does this term mean *in the context of this project*?"

Example entry structure:
```markdown
### GSI (Grid Security Infrastructure)

**Category:** Authentication

The security framework used in High Energy Physics for identity verification. In nginx-xrootd, 
GSI authentication uses x509 proxy certificates presented during TLS handshake to identify 
the connecting user and their permissions.

**Related terms:** [x509 certificate](#x509-certificate), [proxy certificate](#proxy-certificate), 
[WLCG token](#wlcg-token)

**Where you'll encounter it:** Authentication setup, `ssl_verify_client` configuration, 
GSI-specific XRootD opcodes (`kXR_auth` with GSI method).
```

### 2. Visual Architecture Overview (`docs/10-architecture/overview.md`)

Replace scattered ASCII diagrams with a single-page visual summary using Mermaid.js (supported by GitHub and most Markdown renderers):

```markdown
## High-Level Architecture

```mermaid
graph TB
    subgraph Clients["Clients"]
        xrdcp[xrdcp]
        curl[curl / HTTP tools]
        aws[aws s3 CLI]
        python[XRootD Python client]
    end
    
    subgraph nginx["nginx process"]
        stream[stream {} block<br/>XRootD protocol]
        http[http {} block]
        
        subgraph httpLayers["HTTP layer"]
            webdav[WebDAV handler]
            s3[S3 handler]
            metrics[Prometheus /metrics]
        end
        
        subgraph xrootdLayer["Stream layer"]
            native[Native XRootD handler]
            proxy[XRootD proxy mode]
        end
    end
    
    subgraph Storage["Local POSIX filesystem"]
        files[Files on disk]
    end
    
    xrdcp --> stream
    curl -.-> http
    aws -.-> http
    python --> stream
    
    stream --> native
    stream --> proxy
    
    http --> webdav
    http --> s3
    http --> metrics
    
    native --> files
    proxy --> files
    webdav --> files
    s3 --> files
```

**Key insight:** The same POSIX files are served through three independent protocol handlers. 
Each handler is a separate nginx module path — the `stream {}` block for XRootD, the `http {}` block for WebDAV and S3.
```

### 3. Simplified Getting Started Path

Split the current monolithic getting-started.md into phases:

| Phase | Content | Time | Prerequisites |
|---|---|---|---|
| **Phase 1: Hello World** | Build one protocol, anonymous access, verify with xrdcp | 15 min | gcc, curl, internet connection |
| **Phase 2: Add HTTPS/WebDAV** | TLS cert setup, davs:// access | +10 min | openssl (for self-signed cert) |
| **Phase 3: Security** | GSI certs or JWT tokens, restricted paths | +30 min | Understanding of Phase 1-2 |
| **Phase 4: Advanced** | Proxy mode, cluster mode, S3, metrics | +1 hour | Understanding of all above |

Each phase is a separate file. Users can skip ahead if they already know concepts from earlier phases.

### 4. Prerequisites Page (`docs/01-getting-started/02-prerequisites.md`)

A new page that explicitly states what knowledge is and isn't required:

```markdown
## What You Need to Know (and What You Don't)

**Required:**
- Basic Linux command-line skills (copy, paste, run a terminal)
- Understanding of file permissions (`chmod`, `ls -l`)
- Ability to follow a step-by-step guide

**Not Required:**
- XRootD experience — this project teaches you as it goes
- nginx experience — the getting-started guide explains everything inline
- Physics background — none needed to use or contribute to this project
- GSI/PKI knowledge — explained in security sections when relevant

## What You Should Understand (Recommended Reading)

If you're new to any of these topics, spend 10 minutes reading before continuing:

| Topic | Quick Reference | Time |
|---|---|---|
| What is a TCP port? | [Wikipedia](https://en.wikipedia.org/wiki/Port_(computer_networking)) | 3 min |
| How HTTPS/TLS works | [Let's Encrypt explanation](https://letsencrypt.org/how-it-works/) | 5 min |
| What is a proxy? | [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Glossary/Proxy_server) | 3 min |
```

---

## Migration Steps (Phased Rollout)

### Phase 1: Add New Content (Non-Destructive)
1. Create `docs/glossary.md` with terms encountered across existing documentation
2. Create `docs/01-getting-started/` directory structure, move first 3 sections of current getting-started.md
3. Create `docs/10-architecture/overview.md` with visual diagram

### Phase 2: Consolidate (No Content Loss)
4. Move proxy-mode.md, cluster-mode.md to deployment section
5. Merge authentication.md + pki/index.md into security section
6. Update all cross-references to new paths

### Phase 3: Deprecate and Clean Up
7. Add redirect comments at old file locations pointing to new paths
8. Remove duplicate root-level files that are now fully superseded
9. Update README.md "New here?" section with simplified navigation

---

## Expected Impact

| Metric | Before | After |
|---|---|---|
| Top-level docs in `docs/` | 28+ files | ~15 files (organized into sections) |
| Duplicate content locations | 3-4 per topic | 1 canonical location |
| First-time setup time estimate | "10 minutes" (ambiguous — which protocol?) | Clear phased timeline with milestones |
| Newcomer terminology barrier | Must find definitions scattered across 8+ docs | Single glossary page + inline context |

---

## Appendix: Term Frequency Analysis

Terms that appear frequently but lack centralized definition:

| Term | Occurrences in `docs/` | Defined In |
|---|---|---|
| XRootD | 400+ | background.md, getting-started.md |
| ROOT (framework) | 50+ | background.md (briefly) |
| GSI / x509 | 200+ | pki/gsi-auth.md, authentication.md |
| WLCG | 150+ | authentication.md, background.md |
| VOMS | 80+ | pki/authorization.md |
| kXR_opcodes | 300+ | AGENTS.md, reference/xrootd-concepts.md |
| xrdcp | 250+ | getting-started.md, README.md |
| xrdfs | 40+ | getting-started.md |

**Recommendation:** All terms above should have glossary entries with cross-references to where they're primarily used in the project.
