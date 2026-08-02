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
| `fuzz_jwt_json.c` | JWT/JWKS JSON claim/key extraction (pre-auth; hyper-hardening C-1) | ✅ runnable |
| `fuzz_urlcodec.c` | shared HTTP percent-codec `brix_http_urldecode`/`urlencode` — the byte core under S3 SigV4 canonicalisation, WebDAV query, XrdHttp paths (pre-auth; C-1) | ✅ runnable |
| `fuzz_gsi_bucket.c` | GSI `XrdSecBuffer` bucket walk `brix_gsi_find_bucket` — first structural decode of the GSI handshake (pre-auth; C-1 target 1) | ✅ runnable |
| `fuzz_sss_frame.c` | SSS datagram outer-header framing `brix_sss_header_framing_ok` (pre-auth; C-1 target 3) | ✅ runnable |
| `fuzz_macaroon_frame.c` | macaroon length-prefixed packet walk `brix_macaroon_scan_frames` (pre-auth; C-1 target 4) | ✅ runnable |
| `fuzz_sigv4_canonical.c` | S3 SigV4 canonical query-string builder `build_canonical_qs` (pre-auth; C-1 target 5) | ✅ runnable |
| `fuzz_root_frame.c` | `root://` `ClientRequestHdr` `dlen` vs per-opcode cap `brix_root_frame_dlen_ok` — the "reject before allocation" invariant (C-2) | ✅ runnable |

All targets are built and smoke-run in CI by `.github/workflows/fuzz.yml` (blocking
PR/push, `FUZZ_TIME=60`; nightly cron `600s`) via the `cmdscripts.fuzz_all` runner —
add a new target to that runner's `BUILD_ARGS` and it joins the lane automatically.
`fuzz_jwt_json` links `src/auth/token/json.c` and needs `-ljansson`; `fuzz_urlcodec`
links `src/core/compat/uri.c` + `hex.c` (libc only); `fuzz_gsi_bucket` links
`src/auth/gsi/gsi_buf.c` and needs `-lcrypto` (CI installs `libssl-dev`);
`fuzz_sigv4_canonical` unity-`#include`s `auth_sigv4_canonical.c` with
`BRIX_SIGV4_STANDALONE` set (libc-only). The C-1/C-2 targets exercise pure
`(data,len)` functions **carved** out of their nginx-coupled TUs (`sss_framing.c`,
`macaroon_frame.c`, `recv_frame_bounds.c`, and the guarded SigV4 include); the
production callers now delegate to those functions, so the carve is single-source.

The **behavioural** counterpart to these harnesses is `kat_carved_parsers.c` — a
deterministic known-answer test (success / error / security-negative per function)
run under ASan+UBSan by `tests/test_fuzz_carved_parsers.py`. The fuzzers prove no
input crashes; the KAT pins the actual accept/reject verdicts.

**Corpus write-back (B-3).** The nightly `corpus-writeback` job in `fuzz.yml` runs
`tools/ci/fuzz_corpus_writeback.py --commit`, which minimizes every corpus with
libFuzzer `-merge=1` and commits the coverage-minimal `corpus_*` dirs back to
`main` so coverage compounds. It never runs on `pull_request` and stages nothing
outside `tests/fuzz/corpus_*`.

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

- **Framing + per-opcode dispatch** — `src/protocols/root/connection/recv.c`, `src/protocols/root/handshake`
  (the `ClientRequestHdr` `dlen` / per-opcode cap table; F1 readv segment math).
- **GSI/TPC bucket + PEM/cipher parsing** — `src/tpc/gsi/gsi_outbound_*`, `src/auth/gsi`
  (F2 — the densest external-handle error paths).
- **Token / JWT / JWKS** — `src/auth/token` (base64url, JSON header/claims).
- **S3 SigV4 + multipart** — `src/protocols/s3`.
- **WebDAV XML / dead-props** — `src/protocols/webdav/dead_props.c`.

Seed each `corpus_*/` from the existing test fixtures (captured requests, sample
PEM/JWT/XML blobs) for faster coverage.
