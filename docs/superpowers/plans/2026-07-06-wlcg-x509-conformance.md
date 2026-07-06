# WLCG X.509 / CA-Directory Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the module's X.509 handling conform to the WLCG/IGTF CA-directory trust model (signing_policy enforcement, limited-proxy monotonicity, explicit CRL strictness) and ship a ~120-case, three-layer conformance suite that hunts corner-case defects.

**Architecture:** A new ngx-free `signing_policy` engine parses Globus EACL files into a per-CA policy table. `brix_build_ca_store()` builds that table from the CA directory and attaches it (plus the operator's `signing_policy`/`crl` modes) to the `X509_STORE` via `ex_data`, so the single shared verifier (`brix_gsi_verify_chain`) and every store-rebuild path — stream startup, stream CRL-reload timer, WebDAV config merge — inherit enforcement uniformly. A Python fixture forge manufactures hostile PKI trees driven by a manifest that all three test layers consume.

**Tech Stack:** C (OpenSSL 1.1/3.x X509 API, nginx module conventions), Python 3 (`cryptography` 48.x + raw-DER escape hatch, pytest), bash test runners.

## Global Constraints

- **NO `goto`** anywhere in `src/` (`.c`/`.h`) — early-return + helper decomposition only.
- **Functional/modular:** one responsibility per function, explicit data flow, no new globals, pure helpers with side effects at the edges. Section-level WHAT/WHY/HOW doc block on every function.
- **Use HELPERS, never reimplement** path/auth/metrics/framing.
- **3 tests per code change minimum:** success + error + security-negative.
- Every new `.c` file MUST be added to the repo-root `./config` `ngx_module_srcs` list; `./configure` rerun only when a new source file or top-level block is added, otherwise `make -j$(nproc)`.
- New config directive recipe: field on conf struct (`NGX_CONF_UNSET`) → `ngx_command_t` row → merge in `merge_*_conf()`. No `./configure` unless new top-level block.
- ngx-free core files (like `src/net/guard/`) take a caller-supplied `void *log` + logging callback and caller malloc/free — no `ngx_*` symbols, so they link into a standalone unit-test binary.
- DN canonical form for all matching is OpenSSL `X509_NAME_oneline` slash form; exactly one shared helper produces it on both the policy side and the cert side.
- Fail closed: malformed / unreadable / wrong-CA policy file ⇒ reject that CA's certs at verify time, WARN once at load.
- Test-fleet interaction: attach-don't-wipe (conftest default); scenarios needing their own CA dir set `TEST_OWN_FLEET=1` and run serially.
- Build/validate commands:
  - New source file: `./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)` (with `REPO=/home/rcurrie/HEP-x/nginx-xrootd`).
  - Incremental: `make -j$(nproc)` in `/tmp/nginx-1.28.3`.
  - Config check: `/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf`.

---

## File Structure

**New source (implementation):**
- `src/auth/crypto/signing_policy.h` — ngx-free EACL parser + matcher + policy-table API.
- `src/auth/crypto/signing_policy.c` — implementation.
- `src/auth/crypto/store_policy.h` — `X509_STORE` ex_data attach/fetch for the policy table + modes (bridges ngx-free core to the OpenSSL store).
- `src/auth/crypto/store_policy.c` — implementation.

**Modified source:**
- `src/auth/crypto/pki_build.h` / `pki_build.c` — extend `brix_build_ca_store()` signature with `signing_policy_mode` + `crl_mode`; build+attach policy table; install CRL-downgrade verify callback.
- `src/auth/crypto/gsi_verify.c` — post-verify signing_policy chain walk + limited-proxy monotonicity, reading modes from store ex_data.
- `src/core/types/config.h` — add `signing_policy_mode`, `crl_mode` fields to `ngx_stream_brix_srv_conf_t`.
- `src/protocols/root/stream/directives_auth.inc` — `brix_signing_policy`, `brix_crl_mode` directive rows.
- `src/protocols/root/stream/module.c` (or wherever `merge_srv_conf` lives) — merge defaults.
- `src/auth/gsi/config.c` — pass modes into `brix_build_ca_store` via `brix_rebuild_gsi_store`; `require`+bundle config error.
- `src/protocols/webdav/webdav.h` — add mode fields to loc conf.
- `src/protocols/webdav/module.c` — directive rows.
- `src/protocols/webdav/config.c` — merge defaults; pass modes to `webdav_build_ca_store`.
- `src/protocols/webdav/auth_store.c` — thread modes into `brix_build_ca_store`.
- `config` — add `signing_policy.c`, `store_policy.c` to `ngx_module_srcs`.

**New tests + fixtures:**
- `tests/x509forge.py` — fixture forge (scenario trees + manifest).
- `tests/c/signing_policy_unittest.c` — ngx-free grammar/matcher unit tests (SP-*).
- `tests/c/run_signing_policy_tests.sh` — compile+run runner.
- `tests/c/x509_conformance_test.c` — chain/proxy/CRL C-level tests (CHN-*, C-half PX/CRL).
- `tests/c/run_x509_conformance_tests.sh` — runner.
- `tests/test_wlcg_conformance_signing_policy.py` — SP e2e.
- `tests/test_wlcg_conformance_proxy.py` — PX e2e.
- `tests/test_wlcg_conformance_crl.py` — CRL e2e.
- `tests/test_wlcg_conformance_cadir.py` — CAD e2e.
- `tests/test_wlcg_conformance_voms.py` — VMS e2e.
- `tests/test_wlcg_conformance_runtime.py` — RT e2e.
- `tests/wlcg_fleet.py` — shared helper: start an nginx instance with a custom CA dir on both surfaces (thin wrapper over the `test_reload.py` Instance pattern).
- `tests/run_x509_differential.sh` — differential runner vs stock XRootD.

**New docs:**
- `docs/09-developer-guide/wlcg-ca-conformance.md`
- `docs/10-reference/wlcg-x509-differential-findings.md` (generated)
- `docs/03-configuration/quick-reference.md` (append directive rows)

---

## Task 1: signing_policy engine — parser + matcher (ngx-free core)

**Files:**
- Create: `src/auth/crypto/signing_policy.h`
- Create: `src/auth/crypto/signing_policy.c`
- Create: `tests/c/signing_policy_unittest.c`
- Create: `tests/c/run_signing_policy_tests.sh`
- Modify: `config` (add `signing_policy.c` to `ngx_module_srcs`)

**Interfaces:**
- Produces:
  - `typedef enum { BRIX_SP_MODE_OFF, BRIX_SP_MODE_ON, BRIX_SP_MODE_REQUIRE } brix_sp_mode_t;`
  - `typedef struct brix_sp_policy_s brix_sp_policy_t;` (opaque compiled single-file policy: matched CA DN blocks + glob lists)
  - `brix_sp_policy_t *brix_sp_parse(const char *buf, size_t len, char *errbuf, size_t errlen);` — parse an EACL file image; returns NULL on malformed input with a message in `errbuf`. Caller owns result.
  - `void brix_sp_free(brix_sp_policy_t *p);`
  - `int brix_sp_ca_dn_present(const brix_sp_policy_t *p, const char *ca_dn);` — 1 if any `access_id_CA` block matches this CA DN.
  - `int brix_sp_subject_allowed(const brix_sp_policy_t *p, const char *ca_dn, const char *subject_dn);` — 1 if `subject_dn` matches the `cond_subjects` globs of the block(s) for `ca_dn`; 0 otherwise. If no block matches `ca_dn`, returns 0 (fail closed).
  - `int brix_sp_glob_match(const char *pat, const char *str);` — Globus glob: `*` matches any run incl `/`, `?` one char, case-insensitive. Exposed for direct unit testing.

- [ ] **Step 1: Write the failing test file `tests/c/signing_policy_unittest.c`**

```c
/*
 * signing_policy_unittest.c — SP-* grammar and matcher conformance (ngx-free).
 *
 * Build/run: tests/c/run_signing_policy_tests.sh
 * Exit 0 = all checks pass.
 */
#include "auth/crypto/signing_policy.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;
#define CHECK(cond, msg) do {                                   \
    checks++;                                                   \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", (msg)); } \
    else { printf("  ok: %s\n", (msg)); }                       \
} while (0)

static const char *CA_DN = "/DC=test/DC=xrootd/CN=Test XRootD CA";

static brix_sp_policy_t *parse_ok(const char *s) {
    char err[256];
    brix_sp_policy_t *p = brix_sp_parse(s, strlen(s), err, sizeof(err));
    if (p == NULL) { printf("  parse unexpectedly failed: %s\n", err); }
    return p;
}

static void test_glob(void) {
    printf("SP glob:\n");
    CHECK(brix_sp_glob_match("/DC=test/DC=xrootd/*", "/DC=test/DC=xrootd/CN=Bob"),
          "SP-01 star matches trailing incl slash");
    CHECK(brix_sp_glob_match("/DC=test/*/CN=Bob", "/DC=test/DC=x/DC=y/CN=Bob"),
          "SP-02 star crosses embedded slashes");
    CHECK(!brix_sp_glob_match("/DC=test/DC=xrootd/*", "/DC=other/CN=Bob"),
          "SP-03 non-matching prefix rejected");
    CHECK(brix_sp_glob_match("/dc=TEST/*", "/DC=test/CN=Bob"),
          "SP-04 case-insensitive");
    CHECK(brix_sp_glob_match("/DC=test/CN=?ob", "/DC=test/CN=Bob"),
          "SP-05 question mark one char");
}

static void test_enforce(void) {
    printf("SP enforce:\n");
    const char *ok =
        "access_id_CA  X509  '/DC=test/DC=xrootd/CN=Test XRootD CA'\n"
        "pos_rights    globus  CA:sign\n"
        "cond_subjects globus  '\"/DC=test/DC=xrootd/*\"'\n";
    brix_sp_policy_t *p = parse_ok(ok);
    CHECK(p != NULL, "SP-06 canonical file parses");
    CHECK(brix_sp_ca_dn_present(p, CA_DN), "SP-07 CA DN block found");
    CHECK(brix_sp_subject_allowed(p, CA_DN, "/DC=test/DC=xrootd/CN=Bob"),
          "SP-08 in-namespace subject allowed");
    CHECK(!brix_sp_subject_allowed(p, CA_DN, "/DC=evil/CN=Mallory"),
          "SP-09 out-of-namespace subject rejected");
    CHECK(!brix_sp_subject_allowed(p, "/DC=wrong/CN=Other CA",
                                   "/DC=test/DC=xrootd/CN=Bob"),
          "SP-10 unknown CA fails closed");
    brix_sp_free(p);
}

static void test_variants(void) {
    printf("SP grammar variants:\n");
    /* comments, blank lines, CRLF, single unquoted glob */
    const char *v =
        "# comment\r\n"
        "\r\n"
        "access_id_CA X509 '/DC=test/DC=xrootd/CN=Test XRootD CA'\r\n"
        "pos_rights globus CA:sign\r\n"
        "cond_subjects globus \"/DC=test/DC=xrootd/*\"\r\n";
    brix_sp_policy_t *p = parse_ok(v);
    CHECK(p != NULL, "SP-11 CRLF+comments+single-glob parses");
    CHECK(p && brix_sp_subject_allowed(p, CA_DN, "/DC=test/DC=xrootd/CN=Bob"),
          "SP-12 single unquoted glob enforced");
    brix_sp_free(p);

    /* multi-block file, one block per CA */
    const char *multi =
        "access_id_CA X509 '/DC=a/CN=CA A'\n"
        "cond_subjects globus '\"/DC=a/*\"'\n"
        "access_id_CA X509 '/DC=test/DC=xrootd/CN=Test XRootD CA'\n"
        "cond_subjects globus '\"/DC=test/DC=xrootd/*\"'\n";
    brix_sp_policy_t *m = parse_ok(multi);
    CHECK(m && brix_sp_subject_allowed(m, CA_DN, "/DC=test/DC=xrootd/CN=Bob"),
          "SP-13 second block matches its own CA");
    CHECK(m && !brix_sp_subject_allowed(m, CA_DN, "/DC=a/CN=X"),
          "SP-14 block A namespace not granted to CA B");
    brix_sp_free(m);
}

static void test_malformed(void) {
    printf("SP malformed → fail closed:\n");
    char err[256];
    CHECK(brix_sp_parse("access_id_CA X509\n", 18, err, sizeof(err)) == NULL,
          "SP-15 truncated access_id_CA line rejected");
    CHECK(brix_sp_parse("garbage tokens here\n", 20, err, sizeof(err)) == NULL,
          "SP-16 unknown directive rejected");
    /* neg_rights block grants nothing */
    const char *neg =
        "access_id_CA X509 '/DC=test/DC=xrootd/CN=Test XRootD CA'\n"
        "neg_rights globus CA:sign\n"
        "cond_subjects globus '\"/DC=test/DC=xrootd/*\"'\n";
    brix_sp_policy_t *p = brix_sp_parse(neg, strlen(neg), err, sizeof(err));
    CHECK(p != NULL && !brix_sp_subject_allowed(p, CA_DN,
              "/DC=test/DC=xrootd/CN=Bob"),
          "SP-17 neg_rights grants nothing");
    if (p) brix_sp_free(p);
}

int main(void) {
    test_glob();
    test_enforce();
    test_variants();
    test_malformed();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
```

- [ ] **Step 2: Write the runner `tests/c/run_signing_policy_tests.sh`**

```bash
#!/usr/bin/env bash
# run_signing_policy_tests.sh — build+run the ngx-free signing_policy unit tests.
set -euo pipefail
cd "$(dirname "$0")/../.."

gcc -Wall -Wextra -Werror -I src -o /tmp/brix_sp_ut \
    tests/c/signing_policy_unittest.c \
    src/auth/crypto/signing_policy.c

/tmp/brix_sp_ut
```

Then `chmod +x tests/c/run_signing_policy_tests.sh`.

- [ ] **Step 3: Run it to confirm it fails to build (no implementation yet)**

Run: `bash tests/c/run_signing_policy_tests.sh`
Expected: FAIL — `signing_policy.h: No such file` / undefined references.

- [ ] **Step 4: Write `src/auth/crypto/signing_policy.h`**

```c
/*
 * signing_policy.h — Globus EACL signing_policy parser + subject matcher.
 *
 * WHAT: Parses a single <hash>.signing_policy file image into a compiled
 *       policy (per-CA cond_subjects glob lists) and answers "may this CA
 *       sign this subject DN?".
 * WHY:  WLCG/IGTF trust requires a CA sign only within its namespace; plain
 *       PKIX chain validation does not enforce this.
 * HOW:  ngx-free, caller-owned allocation, no globals. Fail closed on any
 *       malformed input (caller rejects the CA).
 */
#ifndef BRIX_CRYPTO_SIGNING_POLICY_H
#define BRIX_CRYPTO_SIGNING_POLICY_H

#include <stddef.h>

typedef enum {
    BRIX_SP_MODE_OFF     = 0,
    BRIX_SP_MODE_ON      = 1,
    BRIX_SP_MODE_REQUIRE = 2
} brix_sp_mode_t;

typedef struct brix_sp_policy_s brix_sp_policy_t;

/* Parse an EACL file image. Returns NULL on malformed input, writing a
 * human-readable reason (incl. line number) into errbuf. Caller owns result. */
brix_sp_policy_t *brix_sp_parse(const char *buf, size_t len,
                                char *errbuf, size_t errlen);

void brix_sp_free(brix_sp_policy_t *p);

/* 1 if some access_id_CA block names this CA DN (oneline slash form). */
int brix_sp_ca_dn_present(const brix_sp_policy_t *p, const char *ca_dn);

/* 1 if subject_dn matches the cond_subjects globs of the block for ca_dn.
 * Returns 0 (fail closed) when no block matches ca_dn or none granted. */
int brix_sp_subject_allowed(const brix_sp_policy_t *p,
                            const char *ca_dn, const char *subject_dn);

/* Globus glob: '*' any run incl '/', '?' one char, case-insensitive. */
int brix_sp_glob_match(const char *pat, const char *str);

#endif /* BRIX_CRYPTO_SIGNING_POLICY_H */
```

- [ ] **Step 5: Write `src/auth/crypto/signing_policy.c`**

Implement with these focused functions (no `goto`, early-return):
- `brix_sp_glob_match(pat, str)` — recursive/iterative glob with `*` backtracking, `tolower` compare.
- Internal tokenizer `sp_next_token(line, &cursor)` — returns next whitespace- or quote-delimited token; handles `'...'` and `"..."`.
- Internal `sp_parse_line(line, block_ctx, errbuf)` — dispatch on first token (`#`/blank → skip; `access_id_CA` → open block, require `X509` + quoted DN; `pos_rights`/`neg_rights` → set grant flag; `cond_subjects` → parse `'..."g1" "g2"...'` OR single `"g"`/bare glob into the current block's glob array; anything else → error).
- `brix_sp_parse` — split image into lines (handle `\r\n`), iterate `sp_parse_line`, on any error free partial + return NULL.
- `brix_sp_ca_dn_present` / `brix_sp_subject_allowed` — linear scan of blocks; DN compare is case-insensitive exact (`strcasecmp`); a block only grants if it saw `pos_rights ... CA:sign` and no `neg_rights`.

Representative core (glob) — full function:

```c
int
brix_sp_glob_match(const char *pat, const char *str)
{
    const char *star = NULL;
    const char *ss = NULL;

    while (*str) {
        if (*pat == '?' || tolower((unsigned char) *pat)
                            == tolower((unsigned char) *str)) {
            pat++; str++;
        } else if (*pat == '*') {
            star = pat++; ss = str;
        } else if (star) {
            pat = star + 1; str = ++ss;
        } else {
            return 0;
        }
    }
    while (*pat == '*') { pat++; }
    return *pat == '\0';
}
```

- [ ] **Step 6: Add `signing_policy.c` to `config`**

In `/home/rcurrie/HEP-x/nginx-xrootd/config`, in the `ngx_module_srcs` list next to the other `src/auth/crypto/*.c` entries (near line 898), add:

```bash
    $ngx_addon_dir/src/auth/crypto/signing_policy.c \
```

- [ ] **Step 7: Run the unit tests to green**

Run: `bash tests/c/run_signing_policy_tests.sh`
Expected: PASS — `NN checks, 0 failures`, exit 0.

- [ ] **Step 8: Commit**

```bash
git add src/auth/crypto/signing_policy.h src/auth/crypto/signing_policy.c \
        tests/c/signing_policy_unittest.c tests/c/run_signing_policy_tests.sh config
git commit -m "feat(auth): ngx-free Globus signing_policy parser + matcher (SP-* unit tests)"
```

---

## Task 2: Attach policy table + modes to the X509_STORE (store_policy)

**Files:**
- Create: `src/auth/crypto/store_policy.h`
- Create: `src/auth/crypto/store_policy.c`
- Modify: `config` (add `store_policy.c`)
- Test: extend `tests/c/signing_policy_unittest.c` with a table-build case, OR add cases to Task 8's `x509_conformance_test.c`. Use Task 8 (needs real certs + a real store). Here the deliverable is verified by compilation + Task 3/8.

**Interfaces:**
- Produces:
  - `typedef struct brix_sp_table_s brix_sp_table_t;` — set of `{ca_hash, ca_dn, brix_sp_policy_t*}` entries.
  - `brix_sp_table_t *brix_sp_table_build(const char *cadir, void *log, brix_sp_log_fn log_fn);` — scan `cadir` for `<hash>.signing_policy` files, parse each, key by CA subject hash (both SHA-1 and old MD5 names). NULL cadir → empty table. Malformed file → recorded as a poisoned entry (any subject for that CA rejected) + WARN via `log_fn`.
  - `void brix_sp_table_free(brix_sp_table_t *t);`
  - `int brix_sp_table_check(const brix_sp_table_t *t, brix_sp_mode_t mode, X509 *ca, X509 *subject);` — resolve policy for `ca` (by subject hash + DN); apply `mode`: OFF→always 1; ON→1 if no file present, else enforce; REQUIRE→must have a granting block. Returns 1 allow, 0 deny.
  - ex_data glue:
    - `int brix_store_policy_attach(X509_STORE *store, brix_sp_table_t *table, brix_sp_mode_t sp_mode, int crl_mode);` — store table+modes on the store; store takes ownership of `table` (freed by an ex_data free callback when the store is freed).
    - `brix_sp_table_t *brix_store_policy_table(X509_STORE_CTX *ctx);`
    - `brix_sp_mode_t brix_store_policy_mode(X509_STORE_CTX *ctx);`
    - `int brix_store_crl_mode(X509_STORE_CTX *ctx);`
  - `typedef void (*brix_sp_log_fn)(void *log, int level, const char *fmt, ...);`
  - `crl_mode` values: `#define BRIX_CRL_MODE_OFF 0`, `BRIX_CRL_MODE_TRY 1`, `BRIX_CRL_MODE_REQUIRE 2`.

- Consumes: `signing_policy.h` from Task 1.

- [ ] **Step 1: Write `store_policy.h`** with the interface above (WHAT/WHY/HOW blocks; include `<openssl/x509.h>`, `<openssl/x509_vfy.h>`, `signing_policy.h`).

- [ ] **Step 2: Write `store_policy.c`**

- Register one ex_data index at first attach via `X509_STORE_get_ex_new_index()` with a `free_func` that calls `brix_sp_table_free` (mirror the store-owns-table lifetime). Guard the index with a one-time init (function-local `static int idx = -1;` + `if (idx < 0) idx = ...`). This is initialization, not mutable shared state — acceptable per the "no new globals" rule (same pattern OpenSSL apps use).
- `brix_sp_table_build`: `opendir(cadir)`; for each entry ending `.signing_policy`, read the file (cap size, e.g. 256 KiB), `brix_sp_parse`; derive the CA DN it names; store entry. Key lookup at check time is by matching the CA's oneline DN (case-insensitive) — the hash is a fast prefilter only. On parse failure store a poisoned entry keyed by filename stem.
- `brix_sp_table_check`: compute `subject_dn` and `ca_dn` via one shared `X509_NAME_oneline` helper (declare `brix_x509_oneline(X509_NAME*, char*, size_t)` here; reused by gsi_verify). Apply mode semantics exactly per §3.1 of the spec.

- [ ] **Step 3: Add `store_policy.c` to `config`** (next to `signing_policy.c`).

- [ ] **Step 4: Confirm it compiles standalone-clean**

Run: `gcc -fsyntax-only -Wall -Wextra -Werror -I src src/auth/crypto/store_policy.c`
Expected: exit 0 (may need `-I` for OpenSSL headers if not default; add `$(pkg-config --cflags openssl)` if so).

- [ ] **Step 5: Commit**

```bash
git add src/auth/crypto/store_policy.h src/auth/crypto/store_policy.c config
git commit -m "feat(auth): signing_policy table + X509_STORE ex_data attach (crl_mode carrier)"
```

---

## Task 3: Extend brix_build_ca_store + enforce in the shared verifier

**Files:**
- Modify: `src/auth/crypto/pki_build.h` (signature), `src/auth/crypto/pki_build.c`
- Modify: `src/auth/crypto/gsi_verify.c`
- Test: `tests/c/x509_conformance_test.c` (Task 8 authoritative); a smoke assertion added here.

**Interfaces:**
- Changed: `brix_build_ca_store(log, cadir, cafile, crl_path, extra_flags, crl_count_out)` → add trailing params `brix_sp_mode_t sp_mode, int crl_mode`. All existing callers (`gsi/config.c`, `webdav/auth_store.c`) updated in Tasks 4/6.
- Produces (behavioral): after `X509_verify_cert` succeeds in `brix_gsi_verify_chain`, every non-proxy cert in the verified chain whose issuer is a trust-anchor CA is checked via `brix_sp_table_check`; failure → return NGX_ERROR with a distinct log line ("signing_policy: CA X may not sign subject Y").

- [ ] **Step 1: Write the failing C test (in `tests/c/x509_conformance_test.c`, Task 8 scaffolds the file).** Add case CHN/SP bridging: build a store with a policy table that forbids the leaf's namespace, verify a valid chain, assert `brix_gsi_verify_chain` now returns NGX_ERROR. (Full harness lands in Task 8; if executing strictly in order, defer this step's *run* to Task 8 and keep the assertion here.)

- [ ] **Step 2: Extend `brix_build_ca_store` signature in `pki_build.h`** — add the two params with a doc note; update the WHAT/WHY/HOW block.

- [ ] **Step 3: Implement in `pki_build.c`:**
  - After store + CA load, when `cadir != NULL`: `table = brix_sp_table_build(cadir, log, brix_pki_log_shim)`; `brix_store_policy_attach(store, table, sp_mode, crl_mode)`. When `cadir == NULL` (bundle file): if `sp_mode == BRIX_SP_MODE_REQUIRE`, log EMERG and return NULL (config error surfaced by caller); else attach an empty table with the mode.
  - CRL flag block: gate on `crl_mode`. `OFF` → never set CRL flags. `TRY`/`REQUIRE` → set `CRL_CHECK|CRL_CHECK_ALL|USE_DELTAS` when crl_count>0; in `TRY` also install a verify callback (`X509_STORE_set_verify_cb`) that downgrades `X509_V_ERR_UNABLE_TO_GET_CRL` to OK (return 1) while leaving `X509_V_ERR_CRL_HAS_EXPIRED` fatal. `REQUIRE` sets flags even at crl_count==0 (so a missing CRL for any CA fails).
  - Add `brix_pki_log_shim(void *log, int level, const char *fmt, ...)` that forwards to `ngx_log_error` — this is the ngx↔core bridge.

- [ ] **Step 4: Implement enforcement in `gsi_verify.c`:**
  - Before `X509_STORE_CTX_free(vctx)`, when `X509_verify_cert` succeeded, fetch chain via `X509_STORE_CTX_get0_chain(vctx)` (borrowed; do not free), and the table+mode via `brix_store_policy_table/brix_store_policy_mode`.
  - Walk chain leaf→root; for each cert that is NOT a proxy (`!(X509_get_extension_flags(cert) & EXFLAG_PROXY)`), find its issuer (next in chain), and if the issuer is self-issued or a trust anchor call `brix_sp_table_check(table, mode, issuer, cert)`; on 0 → log + set an error flag → after loop, free ctx and return NGX_ERROR.
  - Keep the existing DN extraction on success. No `goto`: use a `verdict` local + early returns.

- [ ] **Step 5: Build the module**

Run (new files already in config from Tasks 1–2, so reconfigure once):
`REPO=/home/rcurrie/HEP-x/nginx-xrootd; cd /tmp/nginx-1.28.3 && $REPO/../nginx-1.28.3/configure ... ` — actually run the canonical configure from the repo instructions, then `make -j$(nproc)`.
Expected: clean build, exit 0. Fix any -Werror issues inline.

- [ ] **Step 6: Commit**

```bash
git add src/auth/crypto/pki_build.h src/auth/crypto/pki_build.c src/auth/crypto/gsi_verify.c
git commit -m "feat(auth): enforce signing_policy in shared verifier; crl_mode-gated CRL flags"
```

---

## Task 4: Config directives — stream side (brix_signing_policy, brix_crl_mode)

**Files:**
- Modify: `src/core/types/config.h` (fields)
- Modify: `src/protocols/root/stream/directives_auth.inc` (rows)
- Modify: stream `merge_srv_conf` (locate via `grep -n "merge_srv_conf\|crl_reload" src/protocols/root/stream/*.c`)
- Modify: `src/auth/gsi/config.c` (`brix_rebuild_gsi_store` passes modes; `require`+bundle error)

**Interfaces:**
- Produces: `xcf->signing_policy_mode` (`brix_sp_mode_t`, default `BRIX_SP_MODE_ON`), `xcf->crl_mode` (int, default `BRIX_CRL_MODE_TRY`).
- Directive values parsed by a small enum setter (`on|off|require`, `off|try|require`).

- [ ] **Step 1: Write the failing test — a config-parse pytest.** In `tests/test_wlcg_conformance_cadir.py` (Task 12 scaffolds), add `test_require_mode_with_bundle_file_is_config_error` asserting `nginx -t` fails when `brix_signing_policy require` is set with a bundle *file* trusted CA. For now, add a standalone check runnable via `nginx -t`. (Deferred run to Task 12; keep the config fragment here.)

- [ ] **Step 2: Add fields to `ngx_stream_brix_srv_conf_t`** in `src/core/types/config.h` after `crl_mtime`:

```c
    ngx_uint_t  signing_policy_mode;  /* [brix_signing_policy on|off|require]
                                         BRIX_SP_MODE_*; default ON (enforce
                                         when <hash>.signing_policy present) */
    ngx_uint_t  crl_mode;             /* [brix_crl_mode off|try|require]
                                         BRIX_CRL_MODE_*; default TRY */
```

- [ ] **Step 3: Add directive rows** in `directives_auth.inc` (mirror the `brix_crl` row shape) using custom setter functions `brix_conf_set_sp_mode` / `brix_conf_set_crl_mode` (define them in the same `.inc`'s companion `.c`, or inline as static in the module .c). Each maps the keyword to the enum via `ngx_str_t` compare, `NGX_CONF_TAKE1`.

- [ ] **Step 4: Merge defaults** in stream `merge_srv_conf`:

```c
ngx_conf_merge_uint_value(conf->signing_policy_mode,
                          prev->signing_policy_mode, BRIX_SP_MODE_ON);
ngx_conf_merge_uint_value(conf->crl_mode, prev->crl_mode, BRIX_CRL_MODE_TRY);
```

- [ ] **Step 5: Thread modes through `brix_rebuild_gsi_store`** (`src/auth/gsi/config.c`): pass `xcf->signing_policy_mode`, `xcf->crl_mode` into `brix_build_ca_store`. If the store build returns NULL because of `require`+bundle, surface `ngx_conf_log_error(NGX_LOG_EMERG, ...)` in `brix_configure_gsi`.

- [ ] **Step 6: Reconfigure + build + `nginx -t`**

Run: `make -j$(nproc)` then `/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf`
Expected: build exit 0; config test OK with defaults.

- [ ] **Step 7: Commit**

```bash
git add src/core/types/config.h src/protocols/root/stream/directives_auth.inc \
        src/protocols/root/stream/module.c src/auth/gsi/config.c
git commit -m "feat(config): brix_signing_policy + brix_crl_mode directives (stream)"
```

---

## Task 5: Config directives — WebDAV side + limited-proxy monotonicity

**Files:**
- Modify: `src/protocols/webdav/webdav.h`, `src/protocols/webdav/module.c`, `src/protocols/webdav/config.c`, `src/protocols/webdav/auth_store.c`
- Modify: `src/auth/crypto/gsi_verify.c` (proxy classification + monotonicity)
- Test: `tests/c/x509_conformance_test.c` (PX cases, Task 8)

**Interfaces:**
- Produces: webdav loc conf `signing_policy_mode` + `crl_mode` fields, directives `brix_webdav_signing_policy` / `brix_webdav_crl_mode`, threaded into `webdav_build_ca_store` → `brix_build_ca_store`.
- Produces (behavioral): `brix_gsi_verify_chain` classifies each proxy (RFC3820 impersonation `1.3.6.1.5.5.7.21.1` / independent `.21.2` / Globus limited `1.3.6.1.4.1.3536.1.1.1.9`; legacy `CN=proxy`/`CN=limited proxy`); enforces: once a limited proxy appears at depth d, every proxy at depth <d (closer to leaf) must be limited too → else NGX_ERROR; legacy proxy below an RFC3820 proxy → NGX_ERROR.

- [ ] **Step 1: Add webdav conf fields** (`webdav.h`) + directive rows (`module.c`) + merge (`config.c`), mirroring Task 4. WebDAV builds its store once at merge; that's fine — the table travels on the store.

- [ ] **Step 2: Thread modes into `webdav_build_ca_store`** (`auth_store.c`): add the two params to its signature (or read from `conf`), pass to `brix_build_ca_store`. Update the caller at `config.c:573`.

- [ ] **Step 3: Add proxy-classification helper in `gsi_verify.c`:**

```c
typedef enum { BRIX_PX_NONE, BRIX_PX_FULL, BRIX_PX_LIMITED } brix_px_kind_t;
static brix_px_kind_t brix_px_classify(X509 *cert);  /* inspects PCI OID / legacy CN */
```

Then in the chain walk, track `seen_limited` and reject a FULL proxy that appears after (closer to leaf than) a LIMITED one, and reject a legacy proxy beneath an RFC3820 proxy. No `goto`.

- [ ] **Step 4: Build + `nginx -t`.** Expected exit 0.

- [ ] **Step 5: Commit**

```bash
git add src/protocols/webdav/webdav.h src/protocols/webdav/module.c \
        src/protocols/webdav/config.c src/protocols/webdav/auth_store.c \
        src/auth/crypto/gsi_verify.c
git commit -m "feat(auth): webdav signing_policy/crl_mode directives + limited-proxy monotonicity"
```

---

## Task 6: Fixture forge — tests/x509forge.py

**Files:**
- Create: `tests/x509forge.py`
- Test: `tests/test_x509forge_selftest.py` (forge produces parseable artifacts + valid manifest)

**Interfaces:**
- Produces:
  - `class Scenario` with `dir` (Path to a hashed CA dir), `ca_dir`, `credentials` (dict name→PEM path), `manifest` (list of dicts).
  - `forge_scenario(root: Path, name: str, spec: dict) -> Scenario` — materialize a CA dir (CA cert, both hash links, `.signing_policy`, `.r0`/`.r1` CRLs), EEC + proxy chains, and write `manifest.json`.
  - Manifest entry: `{"scenario","credential","surface":"root|davs|both","expected":"accept|reject","reason","spec_ref"}`.
  - Builder helpers: `make_ca()`, `make_eec(ca, subject, key_usage=...)`, `make_proxy(parent, kind="rfc3820|limited|legacy", pathlen=None, pci_critical=True, policy_oid=...)`, `make_crl(ca, revoked=[], next_update_days=..., signer=None)`, `raw_der_ext(oid, der, critical)` (escape hatch via `UnrecognizedExtension`), `write_hashed_ca_dir(ca, policy_text, crls)`.

- [ ] **Step 1: Write `tests/test_x509forge_selftest.py` (failing)**

```python
import json
from pathlib import Path
import x509forge

def test_forge_baseline_scenario(tmp_path):
    sc = x509forge.forge_scenario(tmp_path, "baseline", x509forge.BASELINE_SPEC)
    # hashed CA dir has a .0 link and a .signing_policy
    names = [p.name for p in sc.ca_dir.iterdir()]
    assert any(n.endswith(".0") for n in names)
    assert any(n.endswith(".signing_policy") for n in names)
    # manifest round-trips and has both accept and reject cases
    manifest = json.loads((sc.dir / "manifest.json").read_text())
    verdicts = {m["expected"] for m in manifest}
    assert {"accept", "reject"} <= verdicts
```

- [ ] **Step 2: Run to confirm failure** (`no module named x509forge`).
Run: `PYTHONPATH=tests pytest tests/test_x509forge_selftest.py -v` → FAIL.

- [ ] **Step 3: Implement `tests/x509forge.py`** on the `cryptography` package, reusing patterns from `utils/make_proxy.py`, `utils/make_crl.py`, `utils/voms_proxy_fake.py`. Include `BASELINE_SPEC` and the hostile-artifact builders listed in spec §4. Compute subject hashes by shelling `openssl x509 -subject_hash`/`-subject_hash_old` (matches `pki_helpers.py`). Write both hash links + `.signing_policy` + CRLs.

- [ ] **Step 4: Run selftest to green.**
Run: `PYTHONPATH=tests pytest tests/test_x509forge_selftest.py -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/x509forge.py tests/test_x509forge_selftest.py
git commit -m "test(x509): fixture forge — hostile PKI scenario trees + manifest"
```

---

## Task 7: Shared fleet helper — tests/wlcg_fleet.py

**Files:**
- Create: `tests/wlcg_fleet.py`
- Test: exercised by Tasks 9–14 (no standalone test; a smoke import + one start/stop in Task 9).

**Interfaces:**
- Produces: `class WlcgInstance` (thin wrapper over the `test_reload.py` Instance pattern) with:
  - `__init__(self, prefix, ca_dir, *, signing_policy="on", crl="", crl_mode="try")`
  - `render()` → nginx.conf string with a stream `server` (root:// GSI on an ephemeral port) and an http `server` (davs:// on an ephemeral port), both pointing `brix_trusted_ca`/`brix_webdav_cadir` at `ca_dir` and setting the two mode directives.
  - `start()`, `reload(**opts)` (SIGHUP), `stop()`.
  - `root_port`, `davs_port` attributes.
  - `attempt_root(cred_pem) -> (ok: bool, detail: str)` — run `xrdcp`/`xrdfs` with the credential, return accept/reject.
  - `attempt_davs(cred_pem) -> (ok, detail)` — `curl --cert/--key` against the davs port.

- [ ] **Step 1:** Read `tests/test_reload.py` lines 80–207 for the Instance pattern; copy the render/write/start/stop/reload mechanics.
- [ ] **Step 2:** Implement `WlcgInstance` reusing `settings.py` for `NGINX`, cert/key paths (server cert from `blitz_test_pki`), ephemeral port allocation (bind-0 pattern used elsewhere in tests).
- [ ] **Step 3:** Smoke: import in a scratch pytest, start with the baseline forge CA dir, assert the process is up and `nginx -t` passed, stop. Run and confirm green.
- [ ] **Step 4: Commit**

```bash
git add tests/wlcg_fleet.py
git commit -m "test(x509): WlcgInstance helper — custom-CA-dir fleet on root:// + davs://"
```

---

## Task 8: C conformance tests — chain/proxy/CRL (CHN-*, PX-*, CRL-*)

**Files:**
- Create: `tests/c/x509_conformance_test.c`
- Create: `tests/c/run_x509_conformance_tests.sh`

**Interfaces:**
- Consumes: `brix_build_ca_store` (new signature), `brix_gsi_verify_chain`, `store_policy.h`, forge-written fixture trees (runner invokes `x509forge` once to materialize a `/tmp/x509conf` fixture root).

- [ ] **Step 1: Write the runner `tests/c/run_x509_conformance_tests.sh`**

```bash
#!/usr/bin/env bash
# run_x509_conformance_tests.sh — build+run C-level x509 conformance tests.
set -euo pipefail
cd "$(dirname "$0")/../.."

FIX=/tmp/x509conf
PYTHONPATH=tests python3 -c "import x509forge,pathlib; x509forge.forge_all(pathlib.Path('$FIX'))"

gcc -Wall -Wextra -Werror -I src $(pkg-config --cflags openssl 2>/dev/null) \
    -o /tmp/brix_x509conf \
    tests/c/x509_conformance_test.c \
    src/auth/crypto/signing_policy.c \
    src/auth/crypto/store_policy.c \
    -lssl -lcrypto

BRIX_X509_FIXTURES="$FIX" /tmp/brix_x509conf
```

Note: `pki_build.c`/`gsi_verify.c` depend on `ngx_log_error`; the C test cannot link them without nginx. Therefore this binary tests the **ngx-free** layer directly: `signing_policy.c` + `store_policy.c` + a local mini-verifier that replicates the `brix_gsi_verify_chain` chain-walk logic against a real `X509_STORE` built with plain OpenSSL calls (`X509_STORE_new` + `X509_STORE_add_cert` + `brix_store_policy_attach`). The wire-level proof that `brix_gsi_verify_chain` itself enforces policy lives in the pytest layer (Tasks 9–11). Add a comment in the test file stating this split.

- [ ] **Step 2: Write `x509_conformance_test.c`** using the `CHECK` macro pattern. Load fixtures from `getenv("BRIX_X509_FIXTURES")`. Cover:
  - CHN-01..15: build store from forge trees, `X509_verify_cert` a leaf; assert accept/reject for AKID/SKID-mismatch proxy (accept), CA:FALSE intermediate (reject), missing keyCertSign CA (reject), depth exceeded (reject), MD5-signed cert (reject under modern OpenSSL), self-signed leaf (reject), expired intermediate (reject), cross-signed dual path (accept).
  - SP bridge: attach a policy table forbidding the leaf namespace; assert the mini-verifier's `brix_store_policy_check`-equivalent rejects.
  - PX C-half: `brix_px_classify` unit assertions on forged proxies.
  - CRL C-half: expired-CRL vs missing-CRL under each `crl_mode` on the store.

- [ ] **Step 3: `chmod +x` runner; run to confirm failures for any not-yet-implemented behavior, then green after Tasks 2/3/5 are in.**
Run: `bash tests/c/run_x509_conformance_tests.sh`
Expected: `NN checks, 0 failures`, exit 0.

- [ ] **Step 4: Commit**

```bash
git add tests/c/x509_conformance_test.c tests/c/run_x509_conformance_tests.sh
git commit -m "test(x509): C conformance — chain building, proxy classify, crl_mode (CHN/PX/CRL)"
```

---

## Task 9: pytest e2e — signing_policy enforcement (SP-*)

**Files:**
- Create: `tests/test_wlcg_conformance_signing_policy.py`

**Interfaces:**
- Consumes: `x509forge`, `WlcgInstance`, forge manifest.

- [ ] **Step 1: Write the manifest-driven test** — this is the real content, not a placeholder:

```python
"""SP-* — signing_policy enforcement on the wire (root:// GSI + davs://)."""
import json, pathlib, pytest
import x509forge
from wlcg_fleet import WlcgInstance

pytestmark = pytest.mark.x509conf

SCENARIOS = ["sp_in_namespace", "sp_out_of_namespace", "sp_wrong_ca_block",
             "sp_subca_out_of_parent_ns", "sp_proxy_cn_exempt"]

@pytest.fixture(scope="module")
def sp_fixtures(tmp_path_factory):
    root = tmp_path_factory.mktemp("sp")
    return {name: x509forge.forge_scenario(root, name, x509forge.SP_SPECS[name])
            for name in SCENARIOS}

@pytest.mark.parametrize("mode", ["on", "require"])
@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("surface", ["root", "davs"])
def test_signing_policy_verdict(tmp_path, sp_fixtures, scenario, mode, surface):
    sc = sp_fixtures[scenario]
    inst = WlcgInstance(tmp_path / f"{scenario}-{mode}-{surface}",
                        ca_dir=sc.ca_dir, signing_policy=mode)
    inst.start()
    try:
        for m in sc.manifest:
            if m["surface"] not in (surface, "both"):
                continue
            cred = sc.credentials[m["credential"]]
            ok, detail = (inst.attempt_root(cred) if surface == "root"
                          else inst.attempt_davs(cred))
            expect = m["expected"]
            # 'on' passes CAs without a policy file; 'require' rejects them
            assert ok == (expect == "accept"), \
                f"{scenario}/{m['credential']} {surface} {mode}: {expect} vs {detail}"
    finally:
        inst.stop()

def test_signing_policy_hot_reload(tmp_path, sp_fixtures):
    """Editing the policy to forbid a subject takes effect after reload."""
    sc = sp_fixtures["sp_in_namespace"]
    inst = WlcgInstance(tmp_path / "reload", ca_dir=sc.ca_dir, signing_policy="on")
    inst.start()
    try:
        cred = sc.credentials["eec_in_ns"]
        assert inst.attempt_root(cred)[0] is True
        # tighten policy to a disjoint namespace, reload
        x509forge.rewrite_signing_policy(sc, "'\"/DC=nobody/*\"'")
        inst.reload()
        assert inst.attempt_root(cred)[0] is False
    finally:
        inst.stop()
```

- [ ] **Step 2: Add the `SP_SPECS` scenario dicts + `rewrite_signing_policy` to `x509forge.py`** (each spec produces the certs + policy text the test names). Commit lands with this task.

- [ ] **Step 3: Run** (own-fleet, serial):
`TEST_OWN_FLEET=1 PYTHONPATH=tests pytest tests/test_wlcg_conformance_signing_policy.py -v -p no:xdist`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/test_wlcg_conformance_signing_policy.py tests/x509forge.py
git commit -m "test(x509): SP-* e2e — signing_policy enforcement on root:// and davs://"
```

---

## Task 10: pytest e2e — proxy certificates (PX-*)

**Files:**
- Create: `tests/test_wlcg_conformance_proxy.py`

- [ ] **Step 1: Write the manifest-driven proxy test** covering PX-01..25 via `x509forge.PX_SPECS` (RFC3820 accept matrix, limited-proxy authn, limited→full escalation reject, legacy Globus proxy, legacy-below-RFC3820 reject, pathlen-0 delegation reject, proxy with CA:TRUE / SAN / bogus PCI OID reject, non-critical PCI reject, expired proxy on valid EEC reject, proxy outliving EEC reject). Same parametrized `assert ok == (expected=="accept")` structure as Task 9, both surfaces where applicable (limited/escalation are root:// GSI-primary; davs:// rejects all proxies by design — assert reject there).
- [ ] **Step 2: Add `PX_SPECS` to `x509forge.py`.**
- [ ] **Step 3: Run** serial own-fleet → PASS.
- [ ] **Step 4: Commit** (`test(x509): PX-* e2e — RFC3820 proxies + limited-proxy monotonicity`).

---

## Task 11: pytest e2e — CRL / revocation (CRL-*)

**Files:**
- Create: `tests/test_wlcg_conformance_crl.py`

- [ ] **Step 1: Write CRL-01..20** via `x509forge.CRL_SPECS`: revoked EEC rejected, revoked intermediate rejected, un-revocation via reload accepted, per-`crl_mode` matrix (`off` ignores CRLs; `try` accepts missing-CRL but rejects expired-CRL and revoked; `require` rejects missing/expired/revoked), wrong-issuer CRL, bad-signature CRL, delta CRL honored, `.r1` second CRL loaded, malformed CRL file non-fatal at startup but revocation still enforced from the good CRL. Parametrize over `crl_mode`.
- [ ] **Step 2: Add `CRL_SPECS` + `x509forge.make_crl` variants** (expired `next_update`, wrong signer, delta indicator).
- [ ] **Step 3: Run** serial own-fleet → PASS.
- [ ] **Step 4: Commit** (`test(x509): CRL-* e2e — revocation + brix_crl_mode matrix`).

---

## Task 12: pytest e2e — CA-directory mechanics (CAD-*)

**Files:**
- Create: `tests/test_wlcg_conformance_cadir.py`

- [ ] **Step 1: Write CAD-01..15:** MD5-only hash links accepted, SHA1-only accepted, `.0`+`.1` duplicate-hash CAs both usable, dangling symlink ignored, junk files ignored, expired CA rejected, CA added via reload then accepted, CA removed via reload then rejected, bundle-file mode parity with dir mode, and `test_require_mode_with_bundle_file_is_config_error` (from Task 4 Step 1 — assert `nginx -t` EMERGs). Uses `x509forge.CAD_SPECS`.
- [ ] **Step 2: Add `CAD_SPECS` + link-layout helpers to `x509forge.py`.**
- [ ] **Step 3: Run** serial own-fleet → PASS.
- [ ] **Step 4: Commit** (`test(x509): CAD-* e2e — CA-dir hash links, reload add/remove, bundle parity`).

---

## Task 13: pytest e2e — VOMS edge cases (VMS-*)

**Files:**
- Create: `tests/test_wlcg_conformance_voms.py`

- [ ] **Step 1: Write VMS-01..08** reusing `utils/voms_proxy_fake.py`: valid AC FQANs extracted, expired AC not honored, tampered AC signature rejected, AC on wrong chain level ignored, hostile VO names (control chars, `,/\`) rejected by `brix_vo_token_safe`, libvomsapi-absent graceful degradation (skip if lib present; else assert decline path). Mark `@pytest.mark.skipif` when `libvomsapi.so.1` is unavailable for the AC-honored cases; keep the sanitizer cases library-independent (they can hit the sanitizer via a unit shim if needed).
- [ ] **Step 2: Run** → PASS (or skips where lib absent).
- [ ] **Step 3: Commit** (`test(x509): VMS-* e2e — VOMS AC + VO-name sanitization`).

---

## Task 14: pytest e2e — runtime / reload races (RT-*)

**Files:**
- Create: `tests/test_wlcg_conformance_runtime.py`

- [ ] **Step 1: Write RT-01..07:** store rebuild under live load drops no in-flight request (spawn N concurrent root:// reads, trigger `brix_crl` change + SIGHUP mid-stream, assert all complete); corrupt CRL appearing mid-reload keeps the old store serving (assert no verify regression + WARN logged); reload-interval revocation latency bound (revoke, wait < `brix_crl_reload`, assert still accepted; wait past, assert rejected). Uses `WlcgInstance.reload()` and the log file under the instance prefix.
- [ ] **Step 2: Run** serial own-fleet → PASS.
- [ ] **Step 3: Commit** (`test(x509): RT-* e2e — store rebuild under load, reload safety`).

---

## Task 15: Differential runner vs stock XRootD + generated findings

**Files:**
- Create: `tests/run_x509_differential.sh`
- Create: `docs/10-reference/wlcg-x509-differential-findings.md` (generated stub committed)

**Interfaces:**
- Consumes: forge manifest, `WlcgInstance` (our verdict), a stock `xrootd` server started with gsi auth over the same CA dir.

- [ ] **Step 1: Write `run_x509_differential.sh`** — gated on `TEST_X509_DIFF=1` and an `xrootd` binary (honor `BRIX_BIN`/`REF_BIN` like `run_load_test.sh`); skip-clean (exit 0 with a notice) when absent. For each manifest scenario: get `ours` (via a small pytest-invoked helper or direct `xrdcp`/`curl` against `WlcgInstance`), get `xrootd` (start stock `xrootd` with a generated `.cfg` pointing `-crl`/`sec.protocol gsi` at the scenario CA dir, attempt the same credential), read `spec` from the manifest. Assert `ours == spec` (non-zero exit on mismatch). Collect `xrootd != spec` rows.
- [ ] **Step 2: Emit the findings doc** — the script regenerates `docs/10-reference/wlcg-x509-differential-findings.md` with a table `| scenario | credential | spec | ours | xrootd | note |` and a repro command per divergence. Commit an initial stub with the header + "run `TEST_X509_DIFF=1 tests/run_x509_differential.sh` to populate".
- [ ] **Step 3: Run** if an `xrootd` binary is available in the environment; otherwise confirm skip-clean.
Run: `TEST_X509_DIFF=1 bash tests/run_x509_differential.sh`
Expected: `ours == spec` for all; findings table written; exit 0.
- [ ] **Step 4: Commit** (`test(x509): differential runner vs stock XRootD + findings report`).

---

## Task 16: Docs + suite integration

**Files:**
- Create: `docs/09-developer-guide/wlcg-ca-conformance.md`
- Modify: `docs/03-configuration/quick-reference.md`
- Modify: `tests/conftest.py` (register `x509conf` marker if not auto) and the slow/pr tier hints if needed
- Modify: `CLAUDE.md` (add the new directives to the config-directive recipe row and the routing/keyword tables if warranted — minimal)

- [ ] **Step 1: Write `wlcg-ca-conformance.md`:** the trust model as implemented, the two directive tables (signing_policy modes, crl_mode semantics), supported EACL grammar subset, limited-proxy rules, the **CRL default-change migration note** (`try` vs old implicit require-when-present; set `require` to restore), how to run each suite layer (`run_signing_policy_tests.sh`, `run_x509_conformance_tests.sh`, the `x509conf`-marked pytest family, `run_x509_differential.sh`), and how to regenerate the findings file.
- [ ] **Step 2: Append directive rows to `quick-reference.md`.**
- [ ] **Step 3: Register the pytest marker** — add `x509conf` to `conftest.py` markers; add the family to the fast/slow tiering per the existing `_SLOW_MODULE_HINTS` convention (mark the heavy own-fleet modules `slow`).
- [ ] **Step 4: Run the whole new suite + a regression pass:**

```bash
bash tests/c/run_signing_policy_tests.sh
bash tests/c/run_x509_conformance_tests.sh
TEST_OWN_FLEET=1 PYTHONPATH=tests pytest tests/test_wlcg_conformance_*.py -v -p no:xdist
PYTHONPATH=tests pytest tests/ -m "not slow" -q   # regression: existing --pr tier stays green
```

Expected: new suite green (≥120 cases, zero xfails on our side); existing tier unaffected.

- [ ] **Step 5: Commit**

```bash
git add docs/09-developer-guide/wlcg-ca-conformance.md docs/03-configuration/quick-reference.md \
        tests/conftest.py CLAUDE.md
git commit -m "docs(x509): WLCG CA conformance guide + directive reference + suite tiering"
```

---

## Self-Review

**Spec coverage:**
- §3.1 signing_policy engine → Tasks 1, 2, 3, 4/5 (directives). ✓
- §3.2 proxy monotonicity → Task 5. ✓
- §3.3 crl_mode → Tasks 3 (flags/callback), 4/5 (directives), 11 (tests). ✓
- §3.4 config surface → Tasks 4, 5. ✓
- §4 forge → Task 6. ✓
- §5 three layers: C unit → Tasks 1, 8; pytest e2e → Tasks 9–14; differential → Task 15. ✓
- §6 docs → Task 16. ✓
- §7 acceptance (≥120 cases, both surfaces, zero xfail, no regression) → Task 16 Step 4. ✓
- §8 risks: shared DN helper (Task 2 `brix_x509_oneline`), fleet-restart cost (module-scoped fixtures + reload over restart in Tasks 9/14), CRL default migration note (Task 16), differential skip-clean (Task 15). ✓

**Placeholder scan:** No "TBD"/"handle edge cases"; each code step shows real code or a precise function list with signatures. Data-driven test tasks (10–14) reference concrete `*_SPECS` dicts added in the same task and reuse the fully-shown harness from Task 9.

**Type consistency:** `brix_sp_mode_t` (Task 1) used in Tasks 2–5; `brix_sp_table_t`/`brix_store_policy_attach` (Task 2) used in Task 3; `brix_build_ca_store` new signature (Task 3) consumed by Tasks 4 (gsi/config.c) and 5 (auth_store.c); `brix_px_kind_t`/`brix_px_classify` (Task 5) tested in Task 8; `WlcgInstance` (Task 7) used in Tasks 9–15; forge `*_SPECS` names consistent across Tasks 6/9–14.

**Known adjustment captured:** the C conformance binary (Task 8) cannot link `pki_build.c`/`gsi_verify.c` (they depend on `ngx_log_error`), so it tests the ngx-free layer + a mini-verifier; the wire-level proof that `brix_gsi_verify_chain` enforces policy lives in the pytest layer. Documented in Task 8 Step 1.
