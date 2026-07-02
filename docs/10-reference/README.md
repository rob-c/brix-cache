# Reference (Deep Dive)

Technical reference material for contributors and advanced operators. Assumes familiarity with XRootD, nginx, and HEP infrastructure.

> **Navigation:** [← Back to docs/index](../index.md) | [Getting Started →](../01-getting-started/README.md)

These documents are detailed and intended for experienced developers who need protocol-level details or want to understand design trade-offs.

---

## Core Protocol Reference

| Document | Description |
|---|---|
| [XRootD Concepts (Deep)](xrootd-concepts-deep.md) | Protocol framing, session model, cluster topology *(17 sections)* |
| [Protocol Notes](protocol-notes.md) | Wire-protocol details for developers |
| [Quirks & Compromises](quirks.md) | Design mismatches and trade-offs with official xrootd |

---

## Architecture Reference

| Document | Description |
|---|---|
| [Handler Reference](handler-reference.md) | Function signatures and call patterns |
| [Core Types](types.md) | Struct definitions used throughout the codebase |
| [Architecture Overview](../09-developer-guide/architecture-overview.md) | Request lifecycle, mental models for nginx/XRootD devs |

---

## Design & Planning

| Document | Description |
|---|---|
| **[XRootD vs gnuBall — comparison set](comparison/xrootd-vs-nginx/README.md)** | **Authoritative hyper-detailed set**: 11 source-grounded docs comparing official XRootD against this module across architecture, protocol, auth, data plane, HTTP/WebDAV/S3, clustering/TPC, storage/cache/tape, operations, clients, security, and gaps — with codebase-internals *and* admin/end-user views. Consolidates the docs below. |
| [Design Rationale](design-rationale.md) | Why gnuBall exists, comparison with official xrootd |
| [Deployment Configuration Reference](comparison/deployment-reference.md) | Side-by-side gnuBall and vanilla XRootD configs for root, HTTP, token, GSI, packet marking, user mapping, HTTPS, cache, TPC, monitoring, mirroring, staging, and traffic-control roles |
| [Source-Verified XRootD Comparison](source-verified-xrootd-comparison.md) | Current feature/gap comparison checked against this source tree and `/tmp/xrootd-src` |
| [XRootD Feature Matrix](xrootd-feature-matrix.md) | High-level current matrix derived from the source-verified comparison |
| [Gaps vs Official XRootD](gaps-vs-xrootd.md) | Remaining narrower or missing upstream features |
| [XrdHttp Parity Roadmap](xrdhttp-parity-roadmap.md) | Planned features and priorities |

---

## Note for Beginners

The content here is deep-dive material that assumes familiarity with XRootD and nginx — **start with sections 01-02** first.

However, the **[Glossary](glossary.md)** is beginner-friendly and explains terminology used throughout this project. Feel free to reference it whenever you encounter unfamiliar terms.
