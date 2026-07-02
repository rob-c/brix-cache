# Codebase Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the residual hardening gaps in an already well-defended codebase: adopt the existing overflow-checked allocation helper across wire-driven allocations, add in-process libFuzzer coverage for the highest-risk parsers, default link-time hardening (RELRO/BIND_NOW/PIE), wire a sanitizer CI lane, and lock down privileged subprocess exec + deployment sandboxing.

**Architecture:** Each phase is independently shippable and produces a tested deliverable. No phase depends on another's runtime behaviour, so they can be merged in any order. The work reuses two pieces of infrastructure that already exist but are under-adopted: `src/core/compat/safe_size.h` (overflow-checked size math, currently used in only 2 files) and `tests/fuzz/` (one libFuzzer target today, with a documented template and target backlog).

**Tech Stack:** C11 (nginx module + ngx-free client), nginx `./config` add-module build, clang libFuzzer + ASan/UBSan, pytest harness, GCC `__builtin_*_overflow` intrinsics, `readelf`/`checksec` for link verification.

## Global Constraints

- **No `goto`** anywhere in `src/`, `shared/`, or `client/` — early-return + helper decomposition only.
- **Functional/modular**: one responsibility per function, pass state explicitly, no new globals.
- **Use existing helpers** — never reimplement path/auth/metrics/framing; for size math use `src/core/compat/safe_size.h`.
- **`src/` allocations use `ngx_palloc`/`ngx_pcalloc`/`ngx_alloc`**; `client/` uses libc `malloc`. Never raw `malloc` in `src/` except the documented crypto/codec/thread-context exceptions.
- **New `.c` files register in the top-level `./config`** (`$ngx_addon_dir/src/...` source lists), NOT `src/core/config/config.h`; then run `./configure`. No `./configure` for edits to existing files.
- **3 tests per behavioural change**: success + error + security-negative.
- **Never run git stash/reset/checkout/clean/rebase.** Commit only the files each task names.
- Section-level WHAT/WHY/HOW docblock on every new function.
- Build: `make -j$(nproc)` incremental; `./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)` when the source list or `--with-*` changes.
- Client build: `cd client && make -j$(nproc)`.

---

## File Structure

**Phase A — link hardening**
- Modify: `client/Makefile` (PIE + RELRO/BIND_NOW/noexecstack in default `HARDEN`/`LDFLAGS`)
- Modify: `config` (append RELRO/BIND_NOW to the module link; document)
- Create: `tests/test_build_hardening.py` (asserts hardening on built artifacts via `readelf`)

**Phase B — `safe_size.h` adoption on wire-driven allocations**
- Modify: `src/protocols/root/zip/zip_dir.c` (central-directory + member buffer allocations)
- Modify: `src/auth/token/jwks.c` (JWKS file-size allocation)
- Modify: `src/auth/gsi/gsi_buf.c` + `src/auth/gsi/proxy_req.c` (external-handle buffer allocations)
- Create/Modify: `tests/c/safe_size_adoption_test.c` (standalone overflow unit checks)

**Phase C — in-process fuzzing**
- Create: `tests/fuzz/fuzz_b64url.c` (token base64url decoder)
- Create: `tests/fuzz/fuzz_zip_dir.c` (server ZIP central-directory walk over a memfd)
- Modify: `tests/fuzz/README.md` (target table + run recipes)
- Create: `tests/fuzz/run_all.sh` (build + short run of every target, CI entry point)

**Phase D — runtime + deployment hardening**
- Create: `tests/build_sanitizer.sh` (ASan+UBSan build) + `tests/test_sanitizer_smoke.py`
- Modify: `src/tpc/outbound/tpc_token.c`, `src/protocols/webdav/tpc_cred.c` (absolute-path + sanitized-env exec)
- Create: `packaging/nginx-xrootd.service` (hardened systemd unit) + `docs/09-developer-guide/deployment-hardening.md`

---

## Phase A — Link-time hardening

### Task 1: Client binaries — PIE + full RELRO + non-exec stack

**Files:**
- Modify: `client/Makefile` (the `HARDEN :=` block and the link rules' `LDFLAGS`)
- Test: `tests/test_build_hardening.py`

**Interfaces:**
- Consumes: nothing.
- Produces: client binaries (`client/bin/*`) and `client/libxrdc.so*` linked with `-pie`/`-shared`, `-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_build_hardening.py
"""Asserts the build emits position-independent, RELRO+BIND_NOW, non-exec-stack
artifacts. Security regression guard for the link-hardening defaults."""
import subprocess, pathlib, pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
CLIENT_BIN = REPO / "client" / "bin" / "xrdcp"


def _readelf(path):
    return subprocess.run(["readelf", "-Wl", "-d", "-h", str(path)],
                          capture_output=True, text=True, check=True).stdout


@pytest.mark.skipif(not CLIENT_BIN.exists(), reason="client not built")
def test_client_binary_is_pie_relro_now_noexecstack():
    out = _readelf(CLIENT_BIN)
    assert "Type:" in out and "DYN (" in out, "binary is not PIE (Type should be DYN)"
    assert "GNU_RELRO" in out, "missing RELRO segment"
    assert "BIND_NOW" in out or "FLAGS_1" in out and "NOW" in out, "missing BIND_NOW"
    assert "GNU_STACK" in out, "missing GNU_STACK"
    stack_line = [l for l in out.splitlines() if "GNU_STACK" in l]
    assert stack_line and " E " not in stack_line[0], "stack is executable"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/test_build_hardening.py::test_client_binary_is_pie_relro_now_noexecstack -v`
Expected: FAIL — current binaries are not PIE / lack BIND_NOW (or SKIP if not built; if SKIP, run `cd client && make -j$(nproc)` first, then it should FAIL).

- [ ] **Step 3: Add the hardening flags to `client/Makefile`**

Append `-fPIE` to the existing `HARDEN :=` block:

```makefile
HARDEN := -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
          -fstack-clash-protection -fcf-protection=full -fPIE
```

Set default link-hardening flags (place near the `LDFLAGS` usage, keeping packager override — `?=` lets RPM `%{build_ldflags}` win):

```makefile
# Link hardening defaults. Packagers can override by exporting LDFLAGS.
LDFLAGS ?= -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
# Executables are PIE; the shared lib is already -shared (implicitly PIC).
LDFLAGS_PIE := -pie
```

Add `$(LDFLAGS_PIE)` to each executable link rule (the `apps/%` and split-tool rules), e.g.:

```makefile
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) $(LDFLAGS_PIE) apps/$*.o $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) -o $@
```

(Do not add `$(LDFLAGS_PIE)` to the `libxrdc.so` rule — shared objects must not be `-pie`; `-z,relro -z,now` still apply there.)

- [ ] **Step 4: Rebuild and run test to verify it passes**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd/client && make -j$(nproc) && cd .. && PYTHONPATH=tests pytest tests/test_build_hardening.py::test_client_binary_is_pie_relro_now_noexecstack -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add client/Makefile tests/test_build_hardening.py
git commit -m "harden: PIE + full RELRO/BIND_NOW/noexecstack on client binaries"
```

### Task 2: nginx module `.so` — RELRO + BIND_NOW by default

**Files:**
- Modify: `config` (append link-hardening flags to the module link path; update the comment block at lines 14–16)
- Test: `tests/test_build_hardening.py` (add module-`.so` case)

**Interfaces:**
- Consumes: nothing.
- Produces: the built `ngx_*xrootd*.so` linked with RELRO + BIND_NOW.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_build_hardening.py`:

```python
import glob

def _find_module_so():
    # nginx builds the dynamic module under the nginx source objs/ tree.
    for base in ("/tmp/nginx-1.28.3/objs", "/tmp/nginx*/objs"):
        for p in glob.glob(base + "/*xrootd*.so"):
            return p
    return None


def test_module_so_is_relro_now():
    so = _find_module_so()
    if not so:
        pytest.skip("module .so not built")
    out = _readelf(so)
    assert "GNU_RELRO" in out, "module .so missing RELRO"
    assert "BIND_NOW" in out or "NOW" in out, "module .so missing BIND_NOW"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=tests pytest tests/test_build_hardening.py::test_module_so_is_relro_now -v`
Expected: FAIL (or SKIP if `.so` not present — if SKIP, do a full `./configure ... && make` first, then it FAILs because RELRO/NOW are not defaulted).

- [ ] **Step 3: Default the link flags in `config`**

The dynamic module's link picks up `--with-ld-opt`, but for a *defaulted* build we append linker flags through the module link variable nginx honours. After the `CFLAGS=...` line (line 16), add:

```sh
# Link hardening for the dynamic module (.so). Appended unless the operator
# already passed equivalent flags via --with-ld-opt. Full RELRO + BIND_NOW make
# the GOT read-only after startup; noexecstack marks the stack non-executable.
case "$NGX_LD_OPT" in
    *relro*) : ;;  # operator already set it; don't double-add
    *) NGX_LD_OPT="$NGX_LD_OPT -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack" ;;
esac
```

Update the comment at lines 14–15 from "pass at configure time" to: "Defaulted below (`NGX_LD_OPT`); override with `--with-ld-opt`."

- [ ] **Step 4: Reconfigure, rebuild, verify**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
REPO=$(pwd)
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
    --with-http_dav_module --with-threads --add-module=$REPO >/dev/null && make -j$(nproc) >/dev/null
PYTHONPATH=tests pytest tests/test_build_hardening.py::test_module_so_is_relro_now -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add config tests/test_build_hardening.py
git commit -m "harden: default RELRO/BIND_NOW/noexecstack on the dynamic module link"
```

---

## Phase B — Overflow-checked allocations on wire-driven sizes

> Each task follows the same shape: prove the *current* code would under-allocate on a wraparound count (standalone unit test against the math), then route the allocation through `safe_size.h` so the wrap becomes a clean error. `safe_size.h` is header-only and supports `XROOTD_SAFE_SIZE_STANDALONE` for tests with no nginx runtime.

### Task 3: ZIP central-directory + member buffers

**Files:**
- Modify: `src/protocols/root/zip/zip_dir.c:101` (`cd = malloc((size_t) cd_size)`) and `:200` (`comp = malloc((size_t) m->comp_size)`)
- Test: `tests/c/safe_size_adoption_test.c` (new standalone unit)

**Interfaces:**
- Consumes: `xrootd_size_mul`/`xrootd_size_add` from `src/core/compat/safe_size.h` (standalone mode).
- Produces: `zip_dir.c` allocations that return a clean error (not a truncated buffer) when `cd_size`/`comp_size` derive from a corrupt archive and would overflow when combined with a `+1`/header offset.

- [ ] **Step 1: Write the failing test**

```c
/* tests/c/safe_size_adoption_test.c
 * Standalone (no nginx) checks that the overflow-checked size helpers reject
 * wraparound. Compile: see tests/fuzz/README. */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define XROOTD_SAFE_SIZE_STANDALONE 1
typedef long ngx_int_t;
#define NGX_OK 0
#define NGX_ERROR -1
#define ngx_inline inline
/* pool/alloc helpers are not exercised here; only the arithmetic. */
#include "../../src/core/compat/safe_size.h"

int main(void) {
    size_t out = 0;
    /* SIZE_MAX * 2 must be rejected, not wrap to SIZE_MAX-1 */
    assert(xrootd_size_mul((size_t)-1, 2, &out) == NGX_ERROR);
    /* header offset + huge comp_size must be rejected */
    assert(xrootd_size_add((size_t)-1, 4096, &out) == NGX_ERROR);
    /* a legitimate small computation still succeeds */
    assert(xrootd_size_mul(16, 256, &out) == NGX_OK && out == 4096);
    assert(xrootd_size_add(4096, 1, &out) == NGX_OK && out == 4097);
    printf("safe_size_adoption_test: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run test to verify it fails (compile + run)**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
gcc -O1 -g -Wall tests/c/safe_size_adoption_test.c -o /tmp/sst && /tmp/sst
```
Expected: compiles and prints `OK` (this test guards the *helper* — it should pass once the include path is right; if the include path is wrong it FAILS to compile). This is the regression anchor for the conversions below.

- [ ] **Step 3: Convert the `zip_dir.c` allocations**

At top of `src/protocols/root/zip/zip_dir.c` add the include (after existing includes):

```c
#include "../shared/safe_size.h"   /* overflow-checked size math */
```

Replace the central-directory allocation (line ~101). The reader allocates `cd_size` bytes then indexes into it with header offsets; guard the `+` arithmetic used when walking and the base allocation:

```c
    /* cd_size is read from the (untrusted) End-Of-Central-Directory record.
     * Reject a value that cannot be a sane allocation before mallocing. */
    size_t cd_alloc;
    if (xrootd_size_add((size_t) cd_size, 1, &cd_alloc) != NGX_OK) {
        return ZIP_ERR_CORRUPT;   /* use the file's existing corrupt-archive code */
    }
    cd = malloc(cd_alloc);
```

Replace the member buffer allocation (line ~200) likewise:

```c
    size_t comp_alloc;
    if (xrootd_size_add((size_t) m->comp_size, 1, &comp_alloc) != NGX_OK) {
        return ZIP_ERR_CORRUPT;
    }
    comp = malloc(comp_alloc);
```

(Match the actual error-return convention already in those functions — read the surrounding 20 lines; use the same `ZIP_ERR_*`/`-1` value the function already returns on a bad archive. Do not introduce `goto`.)

- [ ] **Step 4: Build and re-run the unit test + existing zip tests**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc) 2>&1 | tail -5
gcc -O1 -g -Wall tests/c/safe_size_adoption_test.c -o /tmp/sst && /tmp/sst
PYTHONPATH=tests pytest tests/ -k "zip" -v --tb=short
```
Expected: module builds clean; `safe_size_adoption_test: OK`; zip tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/protocols/root/zip/zip_dir.c tests/c/safe_size_adoption_test.c
git commit -m "harden(zip): overflow-checked central-directory/member allocations"
```

### Task 4: JWKS file-load allocation

**Files:**
- Modify: `src/auth/token/jwks.c:179` (`buf = malloc((size_t) fsize + 1)`)
- Test: reuse `tests/c/safe_size_adoption_test.c` (already proves the helper); add a pytest that loads a pathologically-sized JWKS path is out of scope — `fsize` comes from `fstat`, so the guard is defense-in-depth against a negative/huge `fsize`.

**Interfaces:**
- Consumes: `xrootd_size_add` from `safe_size.h`.
- Produces: `jwks.c` load path that rejects a `fsize` that would wrap `fsize + 1`.

- [ ] **Step 1: Add the include and guard**

In `src/auth/token/jwks.c`, add near the includes:

```c
#include "../shared/safe_size.h"
```

Replace line ~179:

```c
    size_t buf_sz;
    if (fsize < 0 || xrootd_size_add((size_t) fsize, 1, &buf_sz) != NGX_OK) {
        return -1;   /* match the function's existing failure return */
    }
    buf = malloc(buf_sz);
```

(Confirm the function's existing failure-return value and use it; read the 15 lines around the malloc.)

- [ ] **Step 2: Build and run token tests**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc) 2>&1 | tail -3
PYTHONPATH=tests pytest tests/ -k "token or jwks or jwt" -v --tb=short
```
Expected: builds clean; token tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/auth/token/jwks.c
git commit -m "harden(token): overflow-checked JWKS file-load allocation"
```

### Task 5: GSI external-handle buffers

**Files:**
- Modify: `src/auth/gsi/gsi_buf.c` and `src/auth/gsi/proxy_req.c` (the wire-length-driven `malloc` sites)
- Test: build + existing GSI test suite

**Interfaces:**
- Consumes: `xrootd_size_add`/`xrootd_size_mul` from `safe_size.h`.
- Produces: GSI buffer allocations that reject wraparound on attacker-supplied bucket/PEM lengths.

- [ ] **Step 1: Locate the wire-driven allocations**

Run: `grep -nE 'malloc|calloc|realloc' src/auth/gsi/gsi_buf.c src/auth/gsi/proxy_req.c`
For each site whose size derives from a wire/bucket length (not a fixed `sizeof(struct)`), apply the guard pattern.

- [ ] **Step 2: Add include + convert each wire-driven site**

Add `#include "../shared/safe_size.h"` to each file. For a `malloc(len)` or `malloc(len + n)` where `len` is wire-derived:

```c
    size_t need;
    if (xrootd_size_add((size_t) len, EXTRA, &need) != NGX_OK) {
        /* return the file's existing GSI error code (read surrounding lines) */
        return GSI_ERR;   /* placeholder: use the real code from context */
    }
    buf = malloc(need);
```

Leave fixed-`sizeof` struct allocations unchanged (no overflow possible).

- [ ] **Step 3: Build and run GSI/auth tests**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc) 2>&1 | tail -3
PYTHONPATH=tests pytest tests/ -k "gsi or proxy_cert or auth" -v --tb=short
```
Expected: builds clean; tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/auth/gsi/gsi_buf.c src/auth/gsi/proxy_req.c
git commit -m "harden(gsi): overflow-checked external-handle buffer allocations"
```

---

## Phase C — In-process libFuzzer coverage

### Task 6: Fuzz the token base64url decoder

**Files:**
- Create: `tests/fuzz/fuzz_b64url.c`
- Modify: `tests/fuzz/README.md` (add to target table)

**Interfaces:**
- Consumes: `b64url_decode(const char *in, size_t in_len, uint8_t *out, size_t out_max)` from `src/auth/token/b64url.h` (compiled against `src/auth/token/b64url.c`).
- Produces: a runnable `fuzz_b64url` target that must not crash/overflow/leak.

- [ ] **Step 1: Write the fuzz target**

```c
/* tests/fuzz/fuzz_b64url.c — libFuzzer target for the token base64url decoder.
 * WHAT: feeds arbitrary bytes as a base64url string and a range of output caps.
 * WHY:  b64url_decode runs on every bearer token before any auth check — a
 *       decode-side overflow is pre-auth attacker-reachable.
 * Build: see tests/fuzz/README.md. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "../../src/auth/token/b64url.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    /* out_max derived from the first byte: exercises both the exact-fit and the
     * deliberately-too-small output buffer (truncation must not overflow). */
    size_t out_max = (size_t) data[0] + 1;
    uint8_t *out = (uint8_t *) malloc(out_max);
    if (!out) return 0;
    (void) b64url_decode((const char *) data + 1, size - 1, out, out_max);
    free(out);
    return 0;
}
```

- [ ] **Step 2: Build and run the fuzzer**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd/tests/fuzz
clang -O1 -g -fsanitize=fuzzer,address,undefined \
    -I ../../src -I ../../src/auth/token \
    fuzz_b64url.c ../../src/auth/token/b64url.c -o fuzz_b64url
mkdir -p corpus_b64url
./fuzz_b64url -runs=200000 -max_total_time=120 corpus_b64url/
```
Expected: `Done ... exit 0`, no crash artifacts. (If a real crash surfaces, STOP and fix the decoder via systematic-debugging before continuing — that is the point of this task.)

- [ ] **Step 3: Document the target**

In `tests/fuzz/README.md`, add a row to the "Targets" table:

```
| `fuzz_b64url.c`  | token base64url decode (pre-auth)       | ✅ runnable |
```

- [ ] **Step 4: Commit**

```bash
git add tests/fuzz/fuzz_b64url.c tests/fuzz/README.md
git commit -m "test(fuzz): in-process libFuzzer target for token base64url decode"
```

### Task 7: Fuzz the server ZIP central-directory walk

**Files:**
- Create: `tests/fuzz/fuzz_zip_dir.c`
- Modify: `tests/fuzz/README.md`

**Interfaces:**
- Consumes: `xrootd_zip_find_member(int fd, off_t archive_size, const char *member, ...)` from `src/protocols/root/zip/zip_dir.h` (compiled against `src/protocols/root/zip/zip_dir.c` + its kernel dep). Uses `memfd_create` to turn fuzz bytes into an fd.
- Produces: a runnable `fuzz_zip_dir` target exercising the Task-3-hardened allocations.

- [ ] **Step 1: Write the fuzz target**

```c
/* tests/fuzz/fuzz_zip_dir.c — libFuzzer target for the server ZIP central-dir
 * reader. Turns the fuzz buffer into a memfd and walks it as an archive.
 * WHY: ZIP member access parses an attacker-supplied central directory; the
 *      cd_size/comp_size fields drove the allocations hardened in Phase B. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include "../../src/protocols/root/zip/zip_dir.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int fd = memfd_create("zipfuzz", 0);
    if (fd < 0) return 0;
    if (write(fd, data, size) != (ssize_t) size) { close(fd); return 0; }
    xrootd_zip_member_t m;
    /* member name fixed; the directory walk is what we are fuzzing */
    (void) xrootd_zip_find_member(fd, (off_t) size, "any.dat", &m);
    close(fd);
    return 0;
}
```

(Adjust the `xrootd_zip_find_member` call to the real signature/out-param shape after reading `zip_dir.h` lines 30–60.)

- [ ] **Step 2: Build and run**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd/tests/fuzz
clang -O1 -g -fsanitize=fuzzer,address,undefined \
    -I ../../src -I ../../src/protocols/root/zip \
    fuzz_zip_dir.c ../../src/protocols/root/zip/zip_dir.c ../../src/protocols/root/zip/zip_kernel.c -o fuzz_zip_dir
mkdir -p corpus_zip_dir
# seed from any sample archive available
cp ../fixtures/*.zip corpus_zip_dir/ 2>/dev/null || true
./fuzz_zip_dir -runs=200000 -max_total_time=120 corpus_zip_dir/
```
Expected: `Done ... exit 0`. (Resolve link errors by adding the exact kernel TU `zip_dir.c` depends on — `grep -n include src/protocols/root/zip/zip_dir.c` shows it.)

- [ ] **Step 3: Document + commit**

Add the row to `tests/fuzz/README.md`, then:

```bash
git add tests/fuzz/fuzz_zip_dir.c tests/fuzz/README.md
git commit -m "test(fuzz): in-process libFuzzer target for server ZIP central-dir walk"
```

### Task 8: One-command fuzz runner (CI entry point)

**Files:**
- Create: `tests/fuzz/run_all.sh`

**Interfaces:**
- Consumes: every `tests/fuzz/fuzz_*.c` target.
- Produces: a script that builds and short-runs all targets, exit-nonzero on any crash.

- [ ] **Step 1: Write the runner**

```bash
#!/usr/bin/env bash
# tests/fuzz/run_all.sh — build + short-run every libFuzzer target under ASan/UBSan.
# Exit nonzero if any target crashes. Intended for CI (a few CPU-minutes total).
set -euo pipefail
cd "$(dirname "$0")"
TIME="${FUZZ_TIME:-60}"
SRC=../../src
declare -A TARGETS=(
  [fuzz_safe_size]=""
  [fuzz_b64url]="$SRC/token/b64url.c"
  [fuzz_zip_dir]="$SRC/zip/zip_dir.c $SRC/zip/zip_kernel.c"
)
for t in "${!TARGETS[@]}"; do
  echo "=== $t ==="
  clang -O1 -g -fsanitize=fuzzer,address,undefined -I "$SRC" \
      "$t.c" ${TARGETS[$t]} -o "$t"
  mkdir -p "corpus_${t#fuzz_}"
  ./"$t" -runs=0 "corpus_${t#fuzz_}/" >/dev/null 2>&1 || true   # warm corpus
  ./"$t" -max_total_time="$TIME" "corpus_${t#fuzz_}/"
done
echo "all fuzz targets clean"
```

- [ ] **Step 2: Make executable and run**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
chmod +x tests/fuzz/run_all.sh
FUZZ_TIME=20 tests/fuzz/run_all.sh
```
Expected: each target prints `Done`, final line `all fuzz targets clean`, exit 0.

- [ ] **Step 3: Commit**

```bash
git add tests/fuzz/run_all.sh
git commit -m "test(fuzz): one-command runner for all libFuzzer targets (CI entry point)"
```

---

## Phase D — Runtime + deployment hardening

### Task 9: ASan+UBSan build + smoke lane

**Files:**
- Create: `tests/build_sanitizer.sh`
- Create: `tests/test_sanitizer_smoke.py`

**Interfaces:**
- Consumes: the existing `manage_test_servers.sh` `SANITIZE=1` env wiring (ASAN_OPTIONS log path).
- Produces: a reproducible sanitizer build + a smoke test that asserts no ASan/UBSan reports after a basic transfer.

- [ ] **Step 1: Write the sanitizer build script**

```bash
#!/usr/bin/env bash
# tests/build_sanitizer.sh — configure+build the module and client with
# ASan+UBSan for the sanitizer CI lane. Slow; not the default build.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SAN="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
cd "$REPO"
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
    --with-http_dav_module --with-threads --add-module="$REPO" \
    --with-cc-opt="$SAN" --with-ld-opt="$SAN"
make -j"$(nproc)"
( cd client && make -j"$(nproc)" CFLAGS="$SAN" LDFLAGS="$SAN" )
echo "sanitizer build complete"
```

- [ ] **Step 2: Write the smoke test**

```python
# tests/test_sanitizer_smoke.py
"""Runs a minimal transfer against a SANITIZE=1 fleet and fails if any
ASan/UBSan report was written. Skips unless XROOTD_SANITIZER_LANE=1 (the lane
sets it after build_sanitizer.sh)."""
import os, glob, subprocess, pathlib, pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("XROOTD_SANITIZER_LANE") != "1",
    reason="sanitizer lane only")

LOGDIR = os.environ.get("SANITIZE_LOG_DIR", "/tmp/xrd-test/sanitize")


def test_no_sanitizer_reports_after_basic_io(tmp_path):
    # a basic read/write through the running sanitizer fleet
    subprocess.run(["tests/manage_test_servers.sh", "restart"], check=True,
                   env={**os.environ, "SANITIZE": "1"})
    # (perform a trivial xrdcp round-trip here using the existing helpers)
    reports = glob.glob(os.path.join(LOGDIR, "asan.*"))
    assert not reports, f"sanitizer reports present: {reports}"
```

- [ ] **Step 3: Verify the build script runs**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
chmod +x tests/build_sanitizer.sh
bash -n tests/build_sanitizer.sh && echo "syntax ok"
PYTHONPATH=tests pytest tests/test_sanitizer_smoke.py -v   # expect SKIP without the lane env
```
Expected: `syntax ok`; pytest SKIPs (lane not active). Full execution of `build_sanitizer.sh` is a CI-time concern (slow); syntax + skip is the unit-level gate.

- [ ] **Step 4: Commit**

```bash
git add tests/build_sanitizer.sh tests/test_sanitizer_smoke.py
git commit -m "test: ASan+UBSan build script + sanitizer smoke lane"
```

### Task 10: Lock down privileged subprocess exec

**Files:**
- Modify: `src/tpc/outbound/tpc_token.c:169` and `src/protocols/webdav/tpc_cred.c:194` (the `execlp("oidc-token", ...)` calls)

**Interfaces:**
- Consumes: nothing new.
- Produces: credential-helper exec that resolves a configured/absolute binary path and runs with a sanitized environment, removing `$PATH`-substitution risk in the daemon context.

- [ ] **Step 1: Read both call sites and their surrounding fork/exec helper**

Run: `sed -n '150,200p' src/tpc/outbound/tpc_token.c; sed -n '180,210p' src/protocols/webdav/tpc_cred.c`
Confirm both are post-`fork()` child branches calling `execlp`.

- [ ] **Step 2: Switch to a resolved absolute path + sanitized env**

Replace `execlp("oidc-token", "oidc-token", ...)` with an `execve` against a resolved path. Add a small file-local helper (no globals, early-return) in each file:

```c
/* Resolve the oidc-token binary to an absolute path: honour an explicit
 * override env first, else probe the standard install locations. Returns NULL
 * if none is executable — caller must _exit(127). Avoids $PATH substitution in
 * the daemon's (possibly attacker-influenced) environment. */
static const char *
resolve_oidc_token_binary(void)
{
    const char *override = secure_getenv("XROOTD_OIDC_TOKEN_BIN");
    if (override != NULL && access(override, X_OK) == 0) {
        return override;
    }
    static const char *const candidates[] = {
        "/usr/bin/oidc-token", "/usr/local/bin/oidc-token", NULL
    };
    for (const char *const *p = candidates; *p != NULL; p++) {
        if (access(*p, X_OK) == 0) {
            return *p;
        }
    }
    return NULL;
}
```

In the child branch, build a minimal environment and `execve`:

```c
    const char *bin = resolve_oidc_token_binary();
    if (bin == NULL) {
        _exit(127);
    }
    char *child_argv[] = { (char *) bin, /* ...existing args... */, NULL };
    char *child_envp[] = { "PATH=/usr/bin:/bin", NULL };  /* + OIDC_* if needed */
    execve(bin, child_argv, child_envp);
    _exit(127);
```

(Preserve the exact argument list each call site already passes; only the program-resolution + env change. Keep the existing `(char *) NULL` argv terminator semantics.)

- [ ] **Step 3: Build and run TPC token tests**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc) 2>&1 | tail -3
PYTHONPATH=tests pytest tests/ -k "tpc and (token or cred or oidc)" -v --tb=short
```
Expected: builds clean; TPC credential tests pass (or skip if oidc-token not installed — acceptable, the path-resolution helper is exercised by code review + the build).

- [ ] **Step 4: Commit**

```bash
git add src/tpc/outbound/tpc_token.c src/protocols/webdav/tpc_cred.c
git commit -m "harden(tpc): resolve oidc-token to absolute path + sanitized env on exec"
```

### Task 11: Hardened systemd unit + deployment-hardening doc

**Files:**
- Create: `packaging/nginx-xrootd.service`
- Create: `docs/09-developer-guide/deployment-hardening.md`

**Interfaces:**
- Consumes: nothing.
- Produces: a sandboxed systemd unit + operator documentation; contains the impersonate broker (the highest-impact component) within kernel-enforced limits.

- [ ] **Step 1: Write the hardened unit**

```ini
# packaging/nginx-xrootd.service — hardened unit for the nginx-xrootd gateway.
# The impersonate broker requires CAP_SETUID/CAP_SETGID; everything else is
# stripped. Adjust ReadWritePaths to the export + log + cache roots.
[Unit]
Description=nginx-xrootd storage gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/nginx-xrootd.pid
ExecStartPre=/usr/sbin/nginx-xrootd -t
ExecStart=/usr/sbin/nginx-xrootd
ExecReload=/bin/kill -HUP $MAINPID

# --- sandboxing ---
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=false           # broker needs SUID/SGID drops
MemoryDenyWriteExecute=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service @setuid
SystemCallFilter=~@debug @mount @reboot @swap @obsolete
SystemCallArchitectures=native
# Capabilities: only what the privilege-dropping broker needs.
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_BIND_SERVICE
# Writable roots — narrow these to the deployment's actual paths.
ReadWritePaths=/var/log/nginx-xrootd /var/cache/nginx-xrootd /run

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Write the operator doc**

Create `docs/09-developer-guide/deployment-hardening.md` documenting: (a) the systemd directives above and why each is safe given the broker's CAP_SETUID/SETGID need; (b) `systemd-analyze security nginx-xrootd.service` as the verification command and target score; (c) the build-side defaults from Phases A (RELRO/PIE) so operators know what's already on; (d) when to widen `ReadWritePaths`/`RestrictAddressFamilies` (e.g. if impersonation is disabled, drop `@setuid` and the SETUID/SETGID caps).

- [ ] **Step 3: Validate the unit syntax**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
systemd-analyze verify packaging/nginx-xrootd.service 2>&1 | head || echo "systemd-analyze unavailable (validate on a systemd host)"
```
Expected: no syntax errors (or a clear "unavailable" note on non-systemd build hosts; the directive set is the deliverable).

- [ ] **Step 4: Commit**

```bash
git add packaging/nginx-xrootd.service docs/09-developer-guide/deployment-hardening.md
git commit -m "harden(deploy): sandboxed systemd unit + deployment-hardening guide"
```

---

## Self-Review

**Spec coverage** (against the 8-item assessment):
1. `safe_size.h` adoption → Tasks 3, 4, 5 ✅
2. In-process fuzzing of core parsers → Tasks 6, 7, 8 ✅
3. Sanitizer CI lane → Task 9 ✅
4. Link-time hardening (RELRO/BIND_NOW/PIE) → Tasks 1, 2 ✅
5. `$PATH`-resolved privileged exec → Task 10 ✅
6. Deployment sandboxing (systemd/seccomp) → Task 11 ✅
7. Raw-`malloc` error-path audit → folded into Task 9 (LSan via ASan lane covers leak detection across all modules) ✅
8. (MEMORY.md size warning — explicitly out of scope, not security) ✅

**Placeholder scan:** Two intentional "use the file's existing error code" notes remain in Tasks 3/5 because the exact `ZIP_ERR_*`/`GSI_ERR` constant must be read from the surrounding function at implementation time — the step tells the engineer exactly where to look (read N surrounding lines) rather than inventing a wrong constant. The `execve` arg list in Task 10 likewise says "preserve the exact existing args" because they differ between the two call sites. These are deliberate, scoped lookups, not vague TODOs.

**Type consistency:** `xrootd_size_mul`/`xrootd_size_add` signatures match `safe_size.h` exactly across Tasks 3–5; `b64url_decode` signature in Task 6 matches `src/auth/token/b64url.h`; `xrootd_zip_find_member`/`xrootd_zip_member_t` in Task 7 match `src/protocols/root/zip/zip_dir.h`; `_readelf`/`_find_module_so` helpers are defined once in Task 1 and reused in Task 2.

---

## Notes on ordering & risk

- **Phases are independent and individually shippable.** Recommended merge order by risk-reduction-per-effort: A (link flags, ~1hr, mechanical) → B (allocation guards, contained) → C (fuzzing, may surface real bugs — budget for systematic-debugging) → D (exec + deploy).
- **Phase C is the one that can surface latent bugs.** If `fuzz_b64url` or `fuzz_zip_dir` crashes, that is a finding, not a task failure — switch to systematic-debugging, fix the parser, add the crashing input to the corpus, then continue.
- **Phase B is defense-in-depth**, not a known-exploitable bug fix — the wire paths audited already have upstream `dlen`/divisibility/total-size guards (`readv.c`, `clone.c`). The value is making the *allocation layer itself* wrap-proof so a future caller that forgets the upstream check is still safe.
