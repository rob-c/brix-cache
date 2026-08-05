# BriX server conformance — multi-client testing findings

**Rig:** `brixbench` (`run_matrix.sh` + `compare.py`), 5 client implementations driven against
BriX and, for reference, against a stock XRootD origin of the same version:

| driver | client | language | notes |
|---|---|---|---|
| `bench_py.py`      | PyXRootD (`python3-xrootd`) | Python | official XRootD Python API |
| `bench_go/`        | go-hep `xrootd`            | Go     | pure-Go client, default `WithSubStreams(8)` |
| `bench_rust/`      | XrdRust                   | Rust   | pure-Rust client |
| `bench_cli.sh`     | stock `xrdcp`/`xrdfs`     | C++    | reference CLI, v5.9.6 |
| `bench_brixcli.sh` | `brix-xrdcp`/`brix-xrdfs` | C      | BriX-native client |

Each op is verified for byte-correctness against a deterministic source `det(n) = n % 251`,
not merely for a non-error return. "BriX" here is the nginx stream module
(`ngx_stream_brix_module.so`) speaking the XRootD wire protocol, typically fronting a
remote `root://` origin with a write-stage tier.

This document consolidates every finding from Phase-1 (no-auth) and Phase-2 (X.509/GSI)
testing. Individual deep-dives live in their own docs; this is the index + verdict.

---

## Verdict progression

| phase | verdict | meaning |
|---|---|---|
| Phase-1 no-auth, pre-fix  | PASS 34 · FAIL 33 · N/A 2 | 33 FAILs = go-hep + XrdRust hitting two real BriX bugs |
| Phase-1 no-auth, post-fix | full parity | all three bugs fixed |
| Phase-2 GSI               | PASS 68 · FAIL 0 · N/A 1 | full authenticated parity |
| Phase-2 GSI + vector-read | PASS 85 · FAIL 0 · N/A 1 | readv covered on every capable client |

The single remaining `N/A` is `vector_read` on the **stock** CLI, which ships no readv
primitive — not a BriX gap.

---

## Findings that were BriX bugs (found by cross-client testing, since fixed)

These surfaced only because non-XrdCl clients (go-hep, XrdRust) exercise the wire protocol
differently than the reference C++/Python clients, which tolerated the deviations.

### 1. `kXR_protocol` security-block layout (wire-conformance)
`src/protocols/root/session/protocol.c` prepended a non-standard "SecurityInfo header" +
binary auth-protocol entries, shifting the mandatory `ServerResponseReqs_Protocol` ('S')
signing block downfield. Under `brix_auth none`, XrdRust rejected with "security block has
tag 0x00, expected 'S'" and go-hep with "requires request 3010 to be signed, but the session
established no signing key". XrdCl/PyXRootD tolerated it, so it was invisible until go-hep and
XrdRust were added. **Fixed:** emit only the 6-byte `ServerResponseReqs_Protocol` after the
body. Details: [kxr-protocol sec-block layout](kxr-protocol-secblock-layout-bug — memory).

### 2. go-hep large-write framing desync (two stacked gaps)
go-hep (default `WithSubStreams=8`) opens parallel data connections via `kXR_bind` and streams
the raw write payload there with a non-zero pathID on the primary. BriX had **(a)** no
cross-connection write data-path to consume the bound-connection bytes (it misread them as a
request header → "payload too large, closing"), and **(b)** a 16 MiB `kXR_write` cap while
go-hep sent 64 MiB in one request. **Fixed** without the cross-connection path:
- a **streaming write engine** (`src/protocols/root/write/write_stream.c`) that delivers a
  large `kXR_write` to the fd/staged writer in bounded chunks with one final ack (cap raised
  to 1 GiB for plain writes);
- the **`brix_data_substreams`** knob and a **safe pathid guard** that refuses a non-zero-pathID
  write at the header phase without desyncing, so clients fall back to inline pathid-0.

See the data-substream section below and
[vector-read + streaming write](vector-read-cli-conformance.md).

### 3. `mkdir -p` idempotency
BriX returned `[3018] Directory not empty` (ENOTEMPTY) for a `mkdir` on an existing directory,
where stock is idempotent. Root cause: `src/fs/cache/origin_ns.c` mapped the origin's overloaded
`kXR_ItExists` (3018) to ENOTEMPTY for all ops; for `mkdir` it means EEXIST. go-hep `MkdirAll`
(walks ancestors with plain mkdir) tolerates EEXIST-flavoured 3018 but not ENOTEMPTY-flavoured,
so it failed only against the cache gateway. **Fixed:** decode the kXR code from the reply body
and map `kXR_ItExists → EEXIST` on the mkdir path only; rmdir/mv keep ENOTEMPTY.

---

## Findings where BriX is MORE correct than stock (candidate stock defects)

### 4. CRL revocation through a delegated proxy — CONFIRMED, mechanism-pinned
Given a CRL revoking a user's EEC, stock XRootD v5.9.6 loads the CRL, records the revocation,
then authenticates a proxy delegated from that revoked EEC anyway (`EEC not found in chain`).
BriX — matching openssl, the reference verifier — rejects it. Verified across **2 independent
EECs × 4 proxy formats** (RFC 3820, legacy GT2, limited, proxy-of-proxy) with a valid positive
control. Full writeup + repro: [gsi-crl-revocation-conformance](gsi-crl-revocation-conformance.md).

### 5. Vector-read CLI primitive
`brix-xrdfs readv` (kXR_readv) is a scatter/gather CLI primitive that **stock `xrdcp`/`xrdfs`
lack entirely**. Verified byte-correct against both a stock origin and a BriX gateway, and under
GSI. Details: [vector-read-cli-conformance](vector-read-cli-conformance.md).

---

## Non-defects (recorded so the report is not inflated)

- **XrdRust `checksum` "brix-only":** the stock origin computes checksums asynchronously and
  returns `kXR_wait`; XrdRust accumulates the waits past its 300 s cap. BriX answers
  synchronously. A timing/behavioural difference, not a stock bug.
- **`vector_read` N/A on the stock CLI:** the stock CLI has no readv subcommand — a tooling
  limitation, not a protocol conformance gap.

---

## Data sub-streams (kXR_bind) — feature status

`brix_data_substreams` (default **ON**) accepts `kXR_bind`, assigns pathids, and **serves reads
*and writes* on bound secondary connections** cross-worker via an SHM handle table. A bound
`kXR_write` carries the whole request (pathid 0) on the secondary; the server reopens the
writable handle in that connection's worker (dev/inode-validated) and pwrites at the request's
self-addressing offset (Phase 94). This covers **fd-backed exports** *and* a **gateway to a remote
`root://` origin** (Phase 2): a writable gateway stages the upload to a local export-rooted
`.part` (a real fd), which is fanned out exactly like an fd-export and flushed whole to the origin
at close — proven byte-exact on the origin by `test_data_substreams_gateway.py`. Only a
whole-object PUT backend (S3/WebDAV, sequential `file->writer`, fd < 0) still degrades to the
primary (byte-exact fallback; parallel throughput into it is a deferred throughput-only item). The BriX client now defaults to `streams=4` and **fans both upload chunks and download reads
round-robin across the secondaries**, with a per-op safe-fallback to the primary — so a new
client against an old/gateway server that refuses bound writes/reads still completes byte-exact
(verified). The default fan-out is serial (one in-flight op, full resilient ride-out); an opt-in
`--parallel` flag runs a **true concurrent striped download** (thread-per-connection, disjoint
`pwrite` ranges) for real multi-stream throughput on high-latency links. A cross-connection non-zero-pathID write (go-hep style, header on primary) is still
refused cleanly. Full audit, defaults, per-client behaviour, and test inventory:
[data-substreams-conformance](data-substreams-conformance.md).
