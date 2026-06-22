[← Comparison overview](../design-rationale.md)

## Detailed design comparison

Side-by-side on the decisions that matter most to operators: deployment model, dependency surface, auth, observability, and operational overhead.

### Deployment and operations

| Question | official `xrootd` | `nginx-xrootd` |
|---|---|---|
| How many server models does the operator need to understand? | XRootD daemon model plus nginx if HTTP/TLS/reverse-proxy infrastructure is also used | nginx model for native stream, WebDAV HTTP, S3 HTTP, and metrics |
| Config style | XRootD component directives, plugins, conditionals, component namespaces | nginx directives in `stream {}` and `http {}` |
| Reload/restart pattern | XRootD service management | nginx reload/workers/master process |
| TLS policy | XRootD TLS directives and plugins; HTTP plugin TLS for XrdHttp | nginx stream SSL, nginx HTTP SSL, or native XRootD TLS upgrade in the module |
| Logs | XRootD logs plus any HTTP/plugin logs | nginx-style access/error logs plus module access logs |
| Metrics | XrdMon and site tooling | built-in Prometheus endpoint for native XRootD, WebDAV, and S3-compatible traffic |

Favourable angle: `nginx-xrootd` lets an nginx shop run XRootD as a capability
of the edge server rather than as a parallel operational universe.

### Protocol and client compatibility

| Capability | official `xrootd` | `nginx-xrootd` |
|---|---|---|
| native `root://` | reference implementation | supported, with conformance tests against reference xrootd |
| `roots://` | supported by XRootD TLS modes | supported through nginx stream SSL |
| native `root://` TLS upgrade | supported in modern XRootD | supported via `xrootd_tls on` |
| WebDAV/HTTPS | supported through XrdHttp | supported through nginx HTTP module |
| HTTP-TPC | mature upstream support | opt-in pull and push support for HTTPS sources/destinations |
| S3 client ecosystem | upstream has XrdClS3 client work | module exposes S3-compatible path-style endpoint subset |
| remote storage backends | broad plugin ecosystem | intentionally not a goal; local POSIX storage |

Favourable angle: this module covers the practical edge protocols for many
sites while avoiding the maintenance cost of backend types it does not intend to
serve.

### Security and authorization

| Area | official `xrootd` | `nginx-xrootd` |
|---|---|---|
| GSI/x509 | mature native support | native GSI plus WebDAV proxy-cert verification |
| WLCG/JWT tokens | SciTokens/macaroons ecosystem upstream | local JWKS validation, token scopes, `wlcg.groups`, WebDAV bearer support |
| VO authorization | mature site patterns | VOMS extraction and `xrootd_require_vo` path ACLs |
| TLS | XRootD-native TLS and XrdHttp TLS | nginx HTTP/stream TLS plus native upgrade |
| HTTP client certs | XrdHttp path | nginx SSL plus module proxy-cert verification and caching |
| S3 auth | XrdClS3 client-side ecosystem upstream | optional SigV4 endpoint auth |

Favourable angle: the module focuses on current grid security models and keeps
token verification local. Avoiding an IdP lookup during transfer startup is good
for latency and for failure containment.

### Code and maintenance shape

| Concern | official `xrootd` | `nginx-xrootd` |
|---|---|---|
| Extension model | broad plugin architecture | nginx module boundaries and local helper APIs |
| Request routing | xrd framework plus protocol/plugin dispatch | explicit stream dispatch and HTTP location handlers |
| Memory lifetime | XRootD internals | nginx pools tied to connection/request lifetimes |
| Socket readiness | XRootD scheduler | nginx event loop |
| Blocking I/O | XRootD scheduler/threading | nginx thread pools where needed |
| HTTP semantics | implemented by XrdHttp plugin | delegated to nginx HTTP layer |

Favourable angle: for this narrower scope, the code is easier to reason about
because the module can follow nginx's established lifecycle instead of carrying
a full independent server framework.

---

## Production replacement checklist

This section is for operators evaluating whether `nginx-xrootd` can replace
their existing `xrootd` daemon without loss of service. The questions are
ordered from most to least likely to be site-specific blockers.

### Step 1 — Does your site have tape storage?

If `kXR_prepare` with `kXR_stage` is used to stage files from tape (CASTOR,
EOS tape, dCache tape, Enstore, etc.) before reading them, treat replacement as
a site-validation project rather than an automatic yes/no. With `xrootd_frm on`,
the module has a durable FRM queue, real request IDs, `kXR_cancel` handling, and
WLCG Tape REST gateway integration. It still is not the complete upstream
XrdFrm/MSS ecosystem with every migration, purge, space, and tape-driver
behavior.

> **Verdict:** Tape-backed sites must run real prepare/qprep/cancel/evict tests
> against their storage manager. Disk-cache nodes in front of tape remain the
> lowest-risk replacement target.

---

### Step 2 — How does FTS transfer to your site?

FTS3/FTS4 supports WebDAV HTTP-TPC in two modes:

| FTS mode | nginx-xrootd support |
|---|---|
| Pull — destination server fetches from source (`Source:` header) | **Yes** — pull COPY with `curl` subprocess |
| Push — source server pushes to destination (`Destination:` header) | **Yes** — push COPY with `curl --upload-file` |

Both pull and push forward `Authorization:` / `TransferHeader*` headers from
the original COPY request. The outbound TLS identity (cert/key/CA) is
configured per-server block with `xrootd_webdav_tpc_cert`,
`xrootd_webdav_tpc_key`, `xrootd_webdav_tpc_cafile` / `xrootd_webdav_tpc_cadir`.

For native `root://` TPC: the module implements destination pull with
`tpc.src=` / `tpc.key=`, source-side rendezvous (`tpc.dst` + `tpc.key` register,
`tpc.org` + `tpc.key` consume), manager redirect with `?tpc.key=`, and a
shared-memory key registry (`xrootd_tpc_key_ttl`). The embedded pull client can
complete ztn or GSI after `kXR_authmore` when configured, but TLS-upgraded
origins and multihop delegation still need deployment validation; see
[`operation-status.md`](../../05-operations/operation-status.md).

> **Verdict:** Both FTS WebDAV pull and push modes are supported.

---

### Step 3 — Does xrdcp use parallel streams (`-S N`)?

`xrdcp -S N` establishes N secondary TCP connections via `kXR_bind` and
distributes read I/O across them. The module fully supports this: secondary
connections inherit auth from the primary session registry and can read
primary-published file handles.

**Implementation detail**: secondary connections reopen the primary's
canonical path in their own worker and validate `st_dev/st_ino` against the
published shared-handle table. If the primary closes or reuses the handle,
the bound stream closes any stale local fd and returns `kXR_FileNotOpen`.
Raw file descriptors are not shared across worker processes; paths are.

> **Verdict:** Fully supported. `xrdcp -S N` achieves parallel-stream
> throughput on single large files.

---

### Step 4 — What authentication mechanisms does your site use?

| Mechanism | Status |
|---|---|
| Anonymous | Supported |
| GSI / x509 proxy with VOMS | Supported |
| WLCG JWT / SciTokens | Supported |
| SSS (shared-secret) | Supported |
| Macaroon tokens | Supported — HMAC-SHA256 signature chaining and caveat validation |
| krb5 | Supported when optional Kerberos support is built and configured |
| `host` / `pwd` | **Not supported** |

> **Verdict:** Sites using GSI + WLCG JWT + Macaroon tokens are all supported.
> krb5 sites must confirm that their build includes the optional krb5 module.

---

### Step 5 — What does your cluster topology look like?

| Topology | Status |
|---|---|
| Standalone data server (no redirector) | Supported |
| Two-tier: one redirector + leaf data servers | Supported — module acts as leaf CMS client and as redirector |
| Sub-manager / three-tier hierarchy | Supported for native XRootD redirects — the module can run as a sub-manager, escalate registry misses to a parent CMS, handle `kYR_select` / `kYR_try`, and redirect clients to the selected leaf |

Most WLCG Tier-1 and Tier-2 sites run simple two-tier (one-level) redirector
topologies. Three-tier deployments are less common.

> **Verdict:** Two-tier and native XRootD three-tier redirect topologies work.
> Select-then-proxy gateway topologies still need upstream coordination.

---

### Step 6 — Will any WebDAV clients other than xrdcp be used?

| Client / use case | Status |
|---|---|
| `xrdcp davs://` | Supported |
| FTS WebDAV pull | Supported |
| Rucio WebDAV | Supported |
| GFAL2 WebDAV | Supported |
| Windows WebDAV (requires LOCK) | Supported — LOCK/UNLOCK with xattr-based lock state |
| Desktop sync clients (Cyberduck, Nautilus, etc.) | Supported — LOCK-dependent clients work |
| WebDAV server-side COPY (RFC 4918 §9.8) — copy within same server | Supported — `copy_file_range(2)` + pread/write fallback, atomic rename |

> **Verdict:** All WLCG-standard clients work. Windows WebDAV clients using
> LOCK, server-side COPY (RFC 4918 §9.8), and standard PROPFIND all work.

---

### Step 7 — Are you using the S3 endpoint for large file uploads?

The S3-compatible endpoint supports the full multipart upload lifecycle:
`CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, and
`AbortMultipartUpload`.  Parts are staged in a hidden directory and assembled
atomically on completion.  AWS SDK clients will automatically use multipart
upload for files larger than the configurable threshold (default 8 MiB in
most SDKs).

> **Verdict:** The S3 endpoint is now a viable replacement for sites using S3
> ecosystem clients for large file upload, including XrdClS3-backed `xrdcp`
> and FTS transfers.

---

### Summary decision matrix

```text
Site profile                                    Can replace xrootd?
──────────────────────────────────────────────────────────────────
Disk-only POSIX, GSI+JWT, FTS pull-mode         Yes — full replacement
Disk-only POSIX, GSI+JWT, FTS push-mode         Yes — full replacement
Tape-backed data server                         Partial — validate FRM/Tape REST behavior site-by-site
Tape-adjacent disk cache                        Yes — cache tier replacement
Uses xrdcp -S N for throughput on single file   Yes — kXR_bind parallel streams fully implemented
Uses Macaroon tokens                            Yes — Macaroon HMAC-SHA256 validation supported
Needs LOCK/UNLOCK (Windows or desktop WebDAV)   Yes — LOCK/UNLOCK fully implemented
Multi-tier sub-manager cluster topology         Partial — redirects work; select-then-proxy gateways need review
```

---

## Where official XRootD still wins

A favourable comparison is strongest when it is honest. Operators should still
choose official XRootD when they need:

- the full, battle-tested XRootD federation and plugin ecosystem
- non-POSIX backend integrations such as site-specific storage plugins
- mature PSS/PFC/full XrdFrm patterns exactly as deployed at existing sites
- tape-backed data servers where exact upstream MSS migration/purge/recall behavior is required
- every historical authentication mechanism or site-specific security plugin
- an operational team already standardized on XRootD rather than nginx
- exact upstream behavior for obscure protocol corners not used by this module's
  target deployments

In other words: upstream XRootD is the general tool. `nginx-xrootd` is the
sharper tool for nginx-native POSIX data serving.

---

## Where nginx-xrootd should look better

This project should be positioned aggressively in these situations:

1. **The site already runs nginx well.**
   Reusing nginx for TLS, HTTP, logging, reloads, worker management, and metrics
   reduces operational novelty.

2. **The data is local POSIX storage.**
   The module's hot path is optimized for local files rather than abstract
   storage backends.

3. **WebDAV/HTTPS matters as much as native `root://`.**
   nginx is a first-class HTTP server; WebDAV fits naturally into the HTTP
   layer.

4. **Prometheus is the observability standard.**
   The module exports scrapeable metrics directly.

5. **High concurrency matters.**
   The nginx event model is a strong match for many concurrent clients,
   especially when some are idle, slow, TLS-heavy, or backpressured.

6. **The team values small, visible hot paths.**
   Request routing is explicit. Native, WebDAV, S3, and metrics handlers are
   separated. Optimization work can be localized and tested.

```text
best-fit decision tree

Need broad XRootD storage framework, plugins, legacy monitoring, remote backends?
    |
    +-- yes -> official xrootd is probably the safer default
    |
    +-- no
        |
        v
Already operate nginx and serve POSIX files over root:// and/or davs://?
        |
        +-- yes -> nginx-xrootd is the cleaner design fit
        |
        +-- no
            |
            v
Need a compact edge gateway with Prometheus and nginx TLS/logging?
        |
        +-- yes -> nginx-xrootd is attractive
        +-- no  -> compare operational team experience first
```

---

## Design thesis

The official XRootD server optimizes for universality. `nginx-xrootd` optimizes
for a narrower and increasingly common deployment shape:

```text
modern storage edge
    |
    +-- local POSIX data
    +-- native root:// clients
    +-- WebDAV/HTTPS clients
    +-- occasional S3-style clients
    +-- GSI and WLCG tokens
    +-- Prometheus/Grafana operations
    +-- nginx TLS/logging/reload discipline
```

For that shape, an nginx module can be cleaner than a separate storage daemon:
fewer moving parts, better HTTP fit, a proven event loop, a familiar operational
surface, and a hot path designed around the actual filesystem being served.

That is the favourable case for this project. It does not need to be a complete
replacement for XRootD everywhere. It needs to be the better engineered choice
for sites whose real requirements match its design center.

---

## Sources checked

External upstream references:

- XRootD home page, including project description and release announcements:
  <https://xrootd.org/>
- XRootD documentation index, including 6.0 configuration/proxy/CMS/monitoring
  references and protocol docs: <https://xrootd.org/docs>
- XRootD GitHub releases, including v6.0.1 and v5.9.3 notes:
  <https://github.com/xrootd/xrootd/releases>
- XRootD 6.0 configuration reference:
  <https://xrootd.web.cern.ch/doc/dev6/xrd_config.html>

Project-local references:

- `README.md`
- `docs/10-architecture/overview.md`
- `docs/05-operations/operations-guide.md`
- `docs/05-operations/operation-status.md`
- `docs/09-developer-guide/optimizations.md`
- `docs/10-reference/source-verified-xrootd-comparison.md`
