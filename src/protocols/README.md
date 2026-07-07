# protocols — one subdirectory per wire protocol

Each protocol terminates its own wire format and auth handshake, then
reaches storage exclusively through the VFS seam (`src/fs/`) and identity
through `src/auth/`. Shared HTTP semantics (headers, conditionals, ETags,
cache fill) come from `src/core/http/` and [shared/](shared/) — protocols
must not grow private copies (CI-enforced).

| Dir | Protocol | Layer |
|---|---|---|
| [root/](root/) | `root://` / `roots://` — the XRootD wire protocol | stream |
| [webdav/](webdav/) | WebDAV over HTTP(S) (`davs://`), incl. HTTP-TPC | http |
| [s3/](s3/) | S3 REST (SigV4, presigned, multipart) | http |
| [cvmfs/](cvmfs/) | `cvmfs://` site cache (+ experimental `scvmfs://`) | http |
| [ssi/](ssi/) | XrdSsi framework (request/response multiplex, CTA-style services) | stream |
| [srr/](srr/) | storage resource reporting (WLCG SRR JSON) | http |
| [dig/](dig/) | `dig://` diagnostics namespace | stream |
| [shared/](shared/) | cross-protocol helpers: cache fill (coalescing+hold), proto-exclusivity guard | — |

**Adding a protocol:** ONE row in `src/core/types/proto_list.h`
(append-only) generates the unified enum, labels, dashboard ids, and JSON
buckets — then follow the checklist in that header.
