# Wire-parser fuzz harness (Phase 27 W7)

The module's real attack surface is the set of parsers that consume
attacker-controlled bytes off the wire (`root://`, `davs://`, S3, CMS, TPC).
This directory holds libFuzzer targets compiled **standalone** against the
parser translation units (not the full nginx binary) and run under ASAN, so a
few CPU-minutes per target routinely surfaces the overflow / leak / UAF cases
manual review misses.

## Building & running

Requires clang with libFuzzer + ASAN (`clang -fsanitize=fuzzer,address`):

```bash
cd tests/fuzz
clang -O1 -g -fsanitize=fuzzer,address,undefined \
    -I ../../src -I ../../src/shared \
    fuzz_safe_size.c -o fuzz_safe_size
mkdir -p corpus_safe_size
./fuzz_safe_size -runs=200000 -max_total_time=120 corpus_safe_size/
```

A clean run prints `Done … exit 0` with no crash artifacts.

## Targets

| Target | Parser under test | Status |
|---|---|---|
| `fuzz_safe_size.c` | W1 overflow-checked size math + array alloc | ✅ runnable |
| `fuzz_b64url.c`  | token base64url decode (pre-auth)       | ✅ runnable |
| `fuzz_zip_dir.c` | server ZIP central-directory walk (Task-7; Phase-B hardened allocs) | ✅ runnable |

## Adding a parser target (template)

The high-value targets are the genuinely attacker-driven parsers.  Each needs
the parser refactored to a pure `(const uint8_t *data, size_t len)` entry point
with no nginx runtime/socket dependency, then:

```c
#include <stddef.h>
#include <stdint.h>
/* declare the pure parser entry point from the module TU */
extern int parse_under_test(const uint8_t *data, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_under_test(data, size);   /* must not crash / leak / overflow */
    return 0;
}
```

Recommended next targets (see Phase 27 W7 / Appendix B):

- **Framing + per-opcode dispatch** — `src/connection/recv.c`, `src/handshake`
  (the `ClientRequestHdr` `dlen` / per-opcode cap table; F1 readv segment math).
- **GSI/TPC bucket + PEM/cipher parsing** — `src/tpc/gsi_outbound_*`, `src/auth/gsi`
  (F2 — the densest external-handle error paths).
- **Token / JWT / JWKS** — `src/auth/token` (base64url, JSON header/claims).
- **S3 SigV4 + multipart** — `src/s3`.
- **WebDAV XML / dead-props** — `src/webdav/dead_props.c`.

Seed each `corpus_*/` from the existing test fixtures (captured requests, sample
PEM/JWT/XML blobs) for faster coverage.
