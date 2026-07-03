# BriX-Cache vs the official XRootD server

A direct comparison for operators and developers deciding whether BriX-Cache fits their site — as of **2026-05-08**.
project is a better fit for a modern HEP storage endpoint.

The short version: upstream XRootD is a mature, extremely broad storage
framework. `nginx-xrootd` is intentionally narrower and more opinionated: it
uses nginx as the high-performance event engine, serves local POSIX storage, and
integrates native XRootD, WebDAV/HTTPS, S3-style HTTP, TLS, metrics, and common
grid auth in one operational surface.

That focus is the design advantage. XRootD is a toolkit for many storage
architectures. `nginx-xrootd` is a lean data plane for sites that already trust
nginx and want fewer moving parts on the hot path.

---

## Executive comparison

| Area | official `xrootd` daemon | `nginx-xrootd` design position |
|---|---|---|
| Project scope | General-purpose data access framework with plugins, cluster roles, proxying, cache, storage backends, monitoring, HTTP, and native XRootD | Focused nginx module for POSIX-backed HEP data serving with native XRootD, WebDAV, S3-compatible HTTP, and Prometheus |
| Best fit | Large heterogeneous XRootD deployments, sites needing mature CMS/FRM/PSS/OSS ecosystems, custom storage plugins, legacy WLCG monitoring | nginx-operated storage gateways, local filesystems, simple data servers, HTTP/WebDAV-heavy sites, high-concurrency edge services |
| Process model | Dedicated xrd/brix/cmsd daemons with their own scheduling, config, logging, plugins, and operational habits | One nginx master with event-driven workers; the module plugs into nginx stream and HTTP lifecycles |
| Concurrency model | Thread-oriented XRootD server scheduler; highly tunable and mature | nginx event loop for sockets plus nginx thread pools only where blocking I/O is needed |
| Operational surface | XRootD config language, multiple component namespaces, xrootd/cmsd/frm/oss/ofs/http/sec/etc. directives | nginx config, nginx TLS policy, nginx logging, nginx worker model, nginx reloads, nginx metrics endpoint |
| Protocol coverage | Deep native XRootD ecosystem plus HTTP, TPC, SciTokens, Macaroons, plugins, proxy/cache/storage-service modes | Implements the practical data-server XRootD opcode set, WebDAV/HTTPS, S3-style HTTP subset, HTTP-TPC pull and push, cache/manager modes |
| Observability | XRootD logs and XrdMon ecosystem, plus whatever site-specific exporters are deployed | Prometheus `/metrics` built into the module, plus nginx-style access logs |
| Security model | Mature pluggable auth/security ecosystem with many historical modes | Focused current paths: anonymous, GSI/x509 proxies, SSS, WLCG/JWT tokens, VO ACLs, nginx TLS, WebDAV x509/token auth |
| Design bias | Maximum flexibility and compatibility with decades of XRootD deployments | Modern nginx-native simplicity, predictable hot paths, fewer services, clearer code-path separation |

---

## Sub-pages

- [By the numbers](comparison/by-the-numbers.md) — source stats, test suite, developer investment estimates
- [Design rationale](comparison/design-rationale.md) — current XRootD state, six reasons nginx wins, performance data
- [Deployment guide](comparison/deployment-guide.md) — detailed design comparison tables, production replacement checklist, conclusions
