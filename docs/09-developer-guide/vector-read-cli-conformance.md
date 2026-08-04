# Vector-read (kXR_readv) CLI primitive & cross-client conformance

**Status:** verified 2026-08-04 (xrd1). **Context:** closes the lone `vector_read` gap in the
BriX-vs-stock client parity matrix (see [gsi-benchmark-rig](gsi-benchmark-rig-2026-08-04) and
`brixbench/`).

## Summary

Scatter/gather read (`kXR_readv`, request 3025) is exercised by the Python, go-hep, and
XrdRust API drivers, but the **stock XRootD CLI** (`xrdcp`/`xrdfs`, v5.9.6) ships **no
vector-read subcommand** — so the CLI row of the matrix was `N/A`. The **BriX client suite
already provides the primitive**: `brix-xrdfs readv <path> <off len> [<off len> ...]` issues
all segments in one round-trip (implemented in `client/apps/fs/xrdfs_data_xfer_vec.c` via
`brix_file_readv`) and writes them concatenated to stdout. The benchmark now uses it, so
vector-read is covered by every client implementation that has any readv capability.

## What changed (benchmark harness only — no server/client code)

- `brixbench/drivers/bench_brixcli.sh`: the `vector_read` op is now a real `brix-xrdfs readv`
  of three disjoint segments (head / interior / tail-flush) of the 1 MiB `small.bin`, with
  byte-level verification against the deterministic source `det(off+j) = (off+j) % 251`.
- `brixbench/drivers/bench_cli.sh`: message updated — the stock CLI genuinely has no readv
  primitive; the BriX CLI provides one. (Row stays `N/A` for the stock CLI, honestly.)
- `brixbench/compare.py`: `brixcli` added to the compared `CLIENTS` so the BriX-native CLI
  (and its readv coverage) appears in the parity matrix.

## Results

No-auth rig (stock origin `:21095`, BriX gateway `:21094`), `compare.py` verdict
**PASS 85 · FAIL 0 · N/A 1** — the `vector_read` row across every client implementation, where
the two columns are the two server types the client was pointed at:

| client         | stock origin | BriX gateway | verdict |
|----------------|:------------:|:------------:|:-------:|
| PyXRootD (API) | ok           | ok           | PASS |
| go-hep (API)   | ok           | ok           | PASS |
| XrdRust (API)  | ok           | ok           | PASS |
| **brix-xrdfs `readv` (CLI)** | ok | ok       | PASS |
| stock xrdcp/xrdfs (CLI) | FAIL | FAIL        | N/A (no readv primitive) |

The remaining `N/A` is not a BriX gap — it is the stock CLI lacking the primitive entirely.
Every byte returned by `brix-xrdfs readv` matches the `det()` source on both server types.

## GSI spot-check

Under X.509/GSI auth (`XrdSecPROTOCOL=gsi`, valid user proxy), `brix-xrdfs readv` returns
byte-identical correct segments from **both** the stock GSI origin (`:21195`) and the BriX GSI
gateway (`:21196`) — auth is transparent to the readv path.

## Reproduce

```
# no-auth, both server types, all clients:
cd brixbench && bash run_matrix.sh readv-verify 5 \
    root://127.0.0.1:21095/ root://127.0.0.1:21094/
python3 compare.py results/readv-verify | grep -E 'client:|vector_read'

# direct CLI primitive against any server:
brix-xrdfs <host:port> readv <path> 0 4096 500000 8192 1044480 4096 | wc -c   # -> 16384
```
