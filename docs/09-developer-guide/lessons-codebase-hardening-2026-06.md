# Codebase Hardening Exercise — Findings & Summary (June–July 2026)

**Status:** Complete — 11 tasks, all reviewed clean, final whole-branch review READY-TO-MERGE.
**Scope:** `src/`, `shared/`, `client/`, build system, test/fuzz infrastructure, deployment packaging.
**Related:** [deployment-hardening.md](deployment-hardening.md) · [coding-standards.md](coding-standards.md) · [lessons-security-reaudit-and-cleanup.md](lessons-security-reaudit-and-cleanup.md) · plan: `docs/superpowers/plans/2026-06-28-codebase-hardening.md`

---

## 1. Why this exercise

A structured pass over the whole tree to answer one question: *what can be done to harden this codebase?* The finding up front matters as much as the work that followed:

> **The codebase was already well-defended — far above typical.** The exercise closed *residual* gaps rather than building defenses from scratch.

The value was therefore in (a) confirming and documenting the existing posture, and (b) systematically closing the specific gaps that remained, each with a test and a review.

---

## 2. Pre-existing security posture (what was already strong)

These were verified during the assessment and required **no change**:

| Area | State found |
|---|---|
| Compiler hardening | `-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fcf-protection=full -Wformat -Werror=format-security` on both the module and the client |
| Dangerous string funcs | **Zero** `strcpy`/`strcat`/`sprintf`/`gets`/`vsprintf` across `src/`, `shared/`, `client/` |
| Shell / command injection | No `system()`/`popen()`; all `exec*` use argv arrays (no shell) |
| Stack allocation | No `alloca`, no attacker-sized VLAs |
| Control flow | `goto`-free (a project hard rule) |
| Wire-length validation | Request parsers validate `dlen`, use divisibility checks (`clone.c`, `readv.c`) and running-total caps (`readv.c` → `BRIX_MAX_READV_TOTAL`) |
| Overflow-checked size math | Helper `src/core/compat/safe_size.h` already existed (`brix_size_mul`/`_add`, `brix_*_array`) |
| Sanitizer support | Test harness (`manage_test_servers.sh`) already wired `SANITIZE=1` (ASan/UBSan/LSan log capture) |
| Confinement | Path resolution via `RESOLVE_BENEATH`/`openat2`; impersonate broker uses `openat2` + confined fds, not string paths |

---

## 3. The residual-gap assessment (8 items)

The initial audit produced a prioritized list. All were addressed except #8 (explicitly out of scope):

1. `safe_size.h` existed but was used in only **2 files** — many wire-driven allocations still did raw size math.
2. In-process fuzzing was thin — only `fuzz_safe_size` + a client ZIP fuzzer; the core parsers had only a black-box (out-of-process) Python fuzzer.
3. Sanitizer builds were supported but **opt-in / ad-hoc**, not a CI lane.
4. Link-time hardening (full RELRO / `BIND_NOW` / PIE) was **documented but not defaulted** — left to the packager.
5. Credential-helper `exec` resolved `oidc-token` via `$PATH` (PATH-substitution risk in a privileged context).
6. No shipped deployment sandboxing (systemd/seccomp) for the root-capable impersonate broker.
7. Raw-`malloc` error-path leak audit (folded into the sanitizer lane).
8. `MEMORY.md` size warning — **not security, out of scope.**

---

## 4. What was implemented — 4 phases, 11 tasks

Executed edit-only (subagents edited + tested; the human reviews and commits), one implementer + one reviewer subagent per task, plus a final whole-branch review.

### Phase A — Link-time hardening (Tasks 1–2)
- **Client binaries** (`client/Makefile`): `-fPIE` + default `LDFLAGS ?= -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack` + `-pie` on every executable link rule (shared objects correctly excluded). Packager override preserved via `?=`.
- **Dynamic module `.so`** (`config`): appended RELRO/BIND_NOW/noexecstack to `NGX_LD_OPT` with an idempotency guard (`*relro*` case) so `--with-ld-opt` isn't double-applied.
- **Regression test** (`tests/test_build_hardening.py`): asserts `Type: DYN` (PIE), `GNU_RELRO`, `BIND_NOW`/`NOW`, and a non-executable stack via `readelf`.
- **Verified on the real artifacts:** `xrdcp` → `Type: DYN` + `FLAGS_1: NOW PIE` + `GNU_RELRO` + `GNU_STACK RW`; `libxrdc.so` gets `NOW` and is correctly *not* `-pie`.

### Phase B — Overflow-checked allocations (Tasks 3–5)
Routed **genuinely wire/archive-driven** allocations through `safe_size.h`; deliberately left fixed-size and internally-serialized allocations alone (converting those would be dead code).
- `src/protocols/root/zip/zip_dir.c` — central-directory (`cd_size`) and member (`comp_size`) buffers from an untrusted archive; `+1` sentinel doubles as a walk-past-end guard. Returns the function's existing `BRIX_ZIP_ECORRUPT` / `-1`.
- `src/auth/token/jwks.c` — JWKS file-load `fsize + 1` (defense-in-depth; see finding 6.4).
- `src/auth/gsi/proxy_req.c` — the single wire-driven site in `brix_gsi_assemble_proxy` (`proxy_pem_len` from the client-sent `kXGC_sigpxy` PEM). Enumerated all 5 GSI allocations; the other 4 are OpenSSL `i2d_*`/`BIO_get_mem_data` egress lengths and were correctly left unconverted.
- **Unit test** (`tests/c/safe_size_adoption_test.c`): rejects `SIZE_MAX*2` and `SIZE_MAX+n`, accepts legitimate small sizes.

### Phase C — In-process libFuzzer coverage (Tasks 6–8)
- `tests/fuzz/fuzz_b64url.c` — the token base64url decoder (**pre-auth** attacker-reachable). 200k+ runs, ASan/UBSan clean. Needs `-lcrypto` (OpenSSL EVP).
- `tests/fuzz/fuzz_zip_dir.c` — the **server** ZIP central-directory walk (exercises the Phase-B guards). Solved standalone compilation via the existing `XRDPROTO_NO_NGX` guard + a **unity build** (`#include`-ing the source TUs with shim macros) — no source surgery, no `-I`, just `-lz`. 200k runs clean, real OK/extract paths hit.
- `tests/fuzz/run_all.sh` — CI entry point; per-target build functions encode each target's real recipe; `FUZZ_TIME` override; **crash → nonzero exit** via `set -euo pipefail` on the unguarded fuzz run (verified).

### Phase D — Runtime + deployment hardening (Tasks 9–11)
- `tests/build_sanitizer.sh` + `tests/test_sanitizer_smoke.py` — ASan+UBSan build (module **and** client) and a **genuine** MD5-verified `xrdcp` round-trip through a `SANITIZE=1` fleet, asserting zero `asan.*` reports. Skip-gated behind `BRIX_SANITIZER_LANE=1`.
- `src/tpc/tpc_token.c`, `src/protocols/webdav/tpc_cred.c` — the `execlp("oidc-token", …)` **fallbacks** replaced with absolute-path resolution (`resolve_oidc_token_binary()`: `secure_getenv` override → `/usr/bin` → `/usr/local/bin`) + `execve` using a controlled envp allowlist (`PATH=/usr/bin:/bin` + pass-through `HOME`/`OIDC_SOCK`/`XDG_RUNTIME_DIR`), stripping `LD_PRELOAD` and arbitrary env. The already-hardened primary `execve(…, NULL)` helper branches were left untouched.
- `packaging/nginx-xrootd.service` + `docs/09-developer-guide/deployment-hardening.md` — sandboxed unit (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies`, `SystemCallFilter=@system-service @setuid` minus dangerous groups, `CapabilityBoundingSet` = `CAP_SETUID`/`CAP_SETGID`/`CAP_NET_BIND_SERVICE`) matched to the real dynamic-module deployment (`/usr/sbin/nginx -c …`). `systemd-analyze verify` → exit 0.

---

## 5. Process finding — the plan itself had bugs, and the review loop caught them

The most important *process* lesson: writing a detailed plan is not enough; a per-task implement→review loop caught **four errors in the plan's own draft code**, each verified by an independent reviewer before acceptance:

1. **`build_sanitizer.sh` ran `./configure` from the repo root** — but nginx's `configure` lives in the nginx source tree. Fixed to `cd "$NGINX_SRC"`.
2. **`build_sanitizer.sh` set client `LDFLAGS="$SAN"`** — which would have *silently dropped* the Phase-A link hardening. Fixed to preserve RELRO/NOW/noexecstack alongside the sanitizer flags.
3. **The systemd unit's `RestrictSUIDSGID=false`** — the plan conflated process-identity transitions (`setresuid`, governed by the `@setuid` syscall filter + `CAP_SETUID`/`CAP_SETGID`) with **file** setuid/setgid *bits* (what `RestrictSUIDSGID` actually controls). Corrected to `true` — strictly tighter, and the broker never creates setuid files.
4. **The systemd unit included `CAP_DAC_OVERRIDE`** — but the broker (`broker_creds.c`) drops it in its `PR_CAPBSET_DROP` loop and never needs it, and nginx doesn't either. Removed from the bounding set (defense-in-depth).

Findings 3 and 4 *contradicted the plan text* but were verified technically correct (tighter) against systemd semantics and the broker source, and accepted as improvements.

---

## 6. Technical findings worth remembering

1. **`safe_size.h` was under-adopted, not missing.** The right work was adoption discipline (convert *wire-driven* sites, skip fixed/egress ones), not new infrastructure.
2. **Distinguish ingress from egress when hardening allocations.** In `proxy_req.c` and `gsi_buf.c`, only client-supplied (`kXGC_sigpxy`) lengths are attacker-controlled; OpenSSL `i2d_*`/`BIO` serialization lengths are locally generated and guarding them is dead code.
3. **Standalone fuzzing of nginx-coupled code is tractable via the existing `XRDPROTO_NO_NGX` guard + a unity build** — no need to refactor the parser or touch module source.
4. **A dead-code guard is a legitimate review finding.** `jwks.c`'s `fsize < 0` / add-overflow arms are unreachable given the existing `0 < fsize ≤ 65536` bound; kept as plan-mandated defense-in-depth and for idiom consistency, but flagged so a future maintainer isn't misled.
5. **`RestrictSUIDSGID` ≠ setuid syscalls.** It governs the S_ISUID/S_ISGID *file mode bits*; `setresuid()`-family transitions are governed by `@setuid` + `CAP_SETUID`/`CAP_SETGID`. A privilege-dropping daemon should set it `true`.
6. **`execlp` fallbacks are the real PATH-substitution surface.** The primary helper exec was already absolute-path + `NULL` env; only the `oidc-token` PATH fallbacks needed hardening.
7. **`-lcrypto` / `-lz` are per-target build facts** — the fuzz runner must encode each target's real recipe, not a single shared template.

---

## 7. Verification evidence

- **Phase A:** `readelf` on `client/bin/xrdcp` and `.../ngx_stream_brix_module.so` (PIE/RELRO/NOW/noexec-stack confirmed on the real binaries by the final reviewer).
- **Phase B:** `safe_size_adoption_test` prints `OK` (overflow rejected, valid accepted); module builds clean; 23 zip tests pass.
- **Phase C:** all three fuzz targets rebuilt and run clean under clang 21 using `run_all.sh`'s exact recipes (`fuzz_b64url` 1.7M runs, `fuzz_zip_dir` 533k runs, rc=0).
- **Phase D:** 63 TPC tests pass after the exec change; `systemd-analyze verify` exit 0; smoke test skips cleanly without the lane env.
- **Final whole-branch review (Opus):** no Critical/Important findings; merge-ready.

---

## 8. Residual follow-ups (none block merge)

| ID | Item | Disposition |
|---|---|---|
| **N2** | `deployment-hardening.md` §2 understates client PIE — the Makefile now applies `-pie` unconditionally, so a plain `make` *is* PIE | Quick doc fix |
| **N3** | systemd `RestrictAddressFamilies` omits `AF_NETLINK` — glibc `getaddrinfo` may use it; nginx has its own resolver | Verify on target host |
| N1 | `gsi_buf.c` (named in the plan) left unconverted — it's egress-only; `find_bucket` does no allocation | Acceptable |
| N4 | Post-fork child uses `getenv`/`snprintf` before `execve` (not strictly async-signal-safe) — matches pre-existing pattern, stack-only | Acceptable |
| T1 | Dev-only test-helper binaries not link-hardened | Out of scope |
| T2 | Module `.so` test omits noexecstack assert; `_find_module_so` returns first glob match | Acceptable |
| T4 | `jwks.c` guard arms are dead code (see finding 6.4) | Plan-mandated defense-in-depth |
| T6 | Fuzz README lacks a per-target build example; comment the intentional unsigned-wrap in `b64url.c` | Follow-up |
| T8 | `\|\| true` on corpus-warm could mask a manually-planted crash seed; consider `-rss_limit_mb=512` for long CI | Follow-up |
| T11 | logrotate references `/run/nginx.pid` not `/run/nginx-xrootd.pid` | Documented in the unit header |

---

## 9. How to run the new tooling

```bash
# Link-hardening regression test
PYTHONPATH=tests TEST_SKIP_SERVER_SETUP=1 pytest tests/test_build_hardening.py -v

# safe_size overflow unit test (standalone)
gcc -O1 -g -Wall tests/c/safe_size_adoption_test.c -o /tmp/sst && /tmp/sst

# All fuzz targets (CI entry point; FUZZ_TIME seconds per target)
FUZZ_TIME=60 tests/fuzz/run_all.sh

# Sanitizer lane (slow; CI-time)
tests/build_sanitizer.sh
SANITIZE=1 tests/manage_test_servers.sh restart
BRIX_SANITIZER_LANE=1 PYTHONPATH=tests pytest tests/test_sanitizer_smoke.py -v
SANITIZE=1 tests/manage_test_servers.sh stop   # then inspect $TEST_ROOT/sanitize/asan.*

# Deployment sandbox
systemd-analyze verify packaging/nginx-xrootd.service
systemd-analyze security nginx-xrootd.service   # on the deployed host
```

---

*Adding a new fuzz target: write `tests/fuzz/fuzz_<x>.c`, add a `build_fuzz_<x>()` function + a `TARGETS` entry in `run_all.sh`. Adopting `safe_size.h` at a new site: `#include "../shared/safe_size.h"`, guard the wire-driven size with `brix_size_add`/`brix_size_mul`, return the enclosing function's existing error code. Convert ingress sites only.*
