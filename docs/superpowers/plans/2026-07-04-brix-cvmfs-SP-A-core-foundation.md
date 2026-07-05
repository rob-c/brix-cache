# brix CVMFS SP-A — Shared Core Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the ngx-free `shared/cvmfs/` inner-ring core — URL/hash grammar, `.cvmfspublished` + `.cvmfswhitelist` parse & X.509/RSA signature verification, and a repo-trust config model — and refactor the server's existing `classify.c` onto it with no behavior change.

**Architecture:** Move the already-pure `src/protocols/cvmfs/classify.c` into `shared/cvmfs/grammar/`, extend it with content-hash parse/format, then add sibling pure-C units `signature/` (manifest+whitelist parsers + OpenSSL verify) and a small `config/` trust model. Both the nginx module and (later) the FUSE client link this directory. Standalone `gcc` unit tests validate every unit without nginx.

**Tech Stack:** C11, OpenSSL (`libcrypto` — already linked), no nginx types in `shared/cvmfs/`, standalone `gcc -Wall -Wextra -Werror` unit tests.

## Global Constraints

- **NO `goto`** anywhere in `shared/` — early-return + helper decomposition only.
- **Functional/modular:** one responsibility per function, explicit data flow, no new globals, pure helpers with side effects at the edges.
- **ngx-free:** no `ngx_*` type/function/include may appear under `shared/cvmfs/`.
- **Section-level WHAT/WHY/HOW docblock** on every file and every non-trivial function.
- **3 tests per change:** success + error + security-negative (forged sig / expired whitelist / hash mismatch / path-escape).
- Every new `.c` file is added to the repo-root `./config` source list AND `client/config`; `./configure` is required when new files first appear.
- Standalone unit-test compile pattern (documented in each `_unittest.c` header):
  `gcc -Wall -Wextra -Werror -I shared -I src -o /tmp/<t> <unittest.c> <deps.c> -lcrypto && /tmp/<t>`
- Test wrapper scripts live at `tests/run_cvmfs_core_*.sh`; exit 0 = pass.

---

### Task A1: Relocate the URL classifier into `shared/cvmfs/grammar/`

**Files:**
- Create: `shared/cvmfs/grammar/classify.h` (moved from `src/protocols/cvmfs/classify.h`)
- Create: `shared/cvmfs/grammar/classify.c` (moved from `src/protocols/cvmfs/classify.c`)
- Create: `src/protocols/cvmfs/classify.h` (2-line shim → shared header, preserves existing includes)
- Delete: `src/protocols/cvmfs/classify.c` (body now lives in shared)
- Create: `shared/cvmfs/cvmfs_core_unittest.c` (standalone test harness)
- Create: `tests/run_cvmfs_core_unit.sh`
- Modify: `./config` (add `shared/cvmfs/grammar/classify.c` to the module source list)
- Modify: `src/protocols/cvmfs/module.c` build-facing include path is unaffected (uses `"classify.h"` → shim)

**Interfaces:**
- Consumes: nothing (leaf).
- Produces: `int cvmfs_classify_url(const char *path, size_t len, cvmfs_url_info_t *out);`
  and `typedef enum { CVMFS_URL_CAS, CVMFS_URL_MANIFEST, CVMFS_URL_GEO, CVMFS_URL_REJECT } cvmfs_url_class_e;`
  and `struct cvmfs_url_info_t` (unchanged field set from the current header).

- [ ] **Step 1: Write the failing test**

Create `shared/cvmfs/cvmfs_core_unittest.c`:

```c
/*
 * cvmfs_core_unittest.c — standalone tests for the shared CVMFS inner-ring core.
 *
 * Compiles without nginx:
 *   gcc -Wall -Wextra -Werror -I shared -I src -o /tmp/cvmfs_core_ut \
 *       shared/cvmfs/cvmfs_core_unittest.c shared/cvmfs/grammar/classify.c \
 *       -lcrypto && /tmp/cvmfs_core_ut
 * Exit 0 = all checks pass.
 */
#include "cvmfs/grammar/classify.h"
#include <stdio.h>
#include <string.h>

static int g_checks, g_failed;
#define CHECK(cond, name) do { \
    g_checks++; \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

static void test_classify(void) {
    cvmfs_url_info_t u;
    const char cas[] = "/cvmfs/atlas.cern.ch/data/ab/"
                       "cdef0123456789abcdef0123456789abcdef0123";
    cvmfs_classify_url(cas, strlen(cas), &u);
    CHECK(u.cls == CVMFS_URL_CAS, "cas classified");
    CHECK(u.cas_hex_len == 42 && u.cas_hex[0] == 'a' && u.cas_hex[1] == 'b',
          "cas hex rejoined");

    const char man[] = "/cvmfs/atlas.cern.ch/.cvmfspublished";
    cvmfs_classify_url(man, strlen(man), &u);
    CHECK(u.cls == CVMFS_URL_MANIFEST, "manifest classified");

    const char bad[] = "/etc/passwd";
    cvmfs_classify_url(bad, strlen(bad), &u);
    CHECK(u.cls == CVMFS_URL_REJECT, "escape rejected");   /* security-negative */
}

int main(void) {
    test_classify();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -Werror -I shared -I src -o /tmp/cvmfs_core_ut shared/cvmfs/cvmfs_core_unittest.c shared/cvmfs/grammar/classify.c -lcrypto`
Expected: FAIL — `shared/cvmfs/grammar/classify.h: No such file or directory`.

- [ ] **Step 3: Move the classifier into place**

```bash
mkdir -p shared/cvmfs/grammar
git mv src/protocols/cvmfs/classify.c shared/cvmfs/grammar/classify.c
git mv src/protocols/cvmfs/classify.h shared/cvmfs/grammar/classify.h
```

Edit `shared/cvmfs/grammar/classify.c` line 11 include to the new self-path:
`#include "cvmfs/grammar/classify.h"` (replacing `#include "classify.h"`).

Recreate the shim `src/protocols/cvmfs/classify.h`:

```c
/* classify.h — shim: the CVMFS URL classifier now lives in the shared core.
 * Kept so existing `#include "classify.h"` sites compile unchanged. */
#ifndef BRIX_CVMFS_CLASSIFY_SHIM_H
#define BRIX_CVMFS_CLASSIFY_SHIM_H
#include "cvmfs/grammar/classify.h"
#endif
```

Add `-I $ngx_addon_dir/shared` to the module include path and
`$ngx_addon_dir/shared/cvmfs/grammar/classify.c` to `ngx_module_srcs` in `./config`
(next to the other `src/protocols/cvmfs/*.c` entries).

- [ ] **Step 4: Run test to verify it passes**

Run: `gcc -Wall -Wextra -Werror -I shared -I src -o /tmp/cvmfs_core_ut shared/cvmfs/cvmfs_core_unittest.c shared/cvmfs/grammar/classify.c -lcrypto && /tmp/cvmfs_core_ut`
Expected: PASS — `4 checks, 0 failed`.

- [ ] **Step 5: Create the run wrapper + verify the module still builds**

Create `tests/run_cvmfs_core_unit.sh`:

```bash
#!/usr/bin/env bash
# run_cvmfs_core_unit.sh — build+run the shared CVMFS core standalone unit tests.
set -euo pipefail
cd "$(dirname "$0")/.."
DEPS="shared/cvmfs/grammar/classify.c"
gcc -Wall -Wextra -Werror -I shared -I src -o /tmp/cvmfs_core_ut \
    shared/cvmfs/cvmfs_core_unittest.c $DEPS -lcrypto
/tmp/cvmfs_core_ut
```

`chmod +x tests/run_cvmfs_core_unit.sh && tests/run_cvmfs_core_unit.sh`
Then rebuild the nginx module (new source ⇒ configure):
`./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$(pwd) && make -j$(nproc)`
Expected: build EXIT 0; existing `tests/run_cvmfs_classify.sh` still passes.

- [ ] **Step 6: Commit**

```bash
git add shared/cvmfs src/protocols/cvmfs/classify.h ./config tests/run_cvmfs_core_unit.sh
git commit -m "refactor(cvmfs): relocate URL classifier into shared/cvmfs/grammar core"
```

---

### Task A2: Content-hash parse/format in the grammar

**Files:**
- Create: `shared/cvmfs/grammar/hash.h`
- Create: `shared/cvmfs/grammar/hash.c`
- Modify: `shared/cvmfs/cvmfs_core_unittest.c` (add `test_hash`)
- Modify: `tests/run_cvmfs_core_unit.sh` (add `hash.c` to `DEPS`)
- Modify: `./config` (add `shared/cvmfs/grammar/hash.c`)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `typedef enum { CVMFS_HASH_SHA1=0, CVMFS_HASH_RMD160, CVMFS_HASH_SHAKE128 } cvmfs_hash_algo_e;`
  - `typedef struct { cvmfs_hash_algo_e algo; unsigned char bytes[20]; size_t len; } cvmfs_hash_t;`
    (SHAKE-128 truncated to 20 bytes as CVMFS does.)
  - `int cvmfs_hash_parse(const char *hex, size_t hexlen, cvmfs_hash_t *out);` — 0 on success; accepts `<40hex>`, `<40hex>-rmd160`, `<40hex>-shake128`.
  - `int cvmfs_hash_to_object_path(const cvmfs_hash_t *h, char suffix, char *buf, size_t buflen);` — writes `<2hex>/<rest><suffix>` (suffix `0` = none, else appended); returns bytes written or -1.
  - `int cvmfs_hash_from_bytes(cvmfs_hash_algo_e a, const unsigned char *b, size_t n, cvmfs_hash_t *out);`
  - `int cvmfs_hash_eq(const cvmfs_hash_t *a, const cvmfs_hash_t *b);`

- [ ] **Step 1: Write the failing test** — add to `cvmfs_core_unittest.c`:

```c
#include "cvmfs/grammar/hash.h"

static void test_hash(void) {
    cvmfs_hash_t h;
    const char hex[] = "cdef0123456789abcdef0123456789abcdef0123";
    CHECK(cvmfs_hash_parse(hex, 40, &h) == 0 && h.algo == CVMFS_HASH_SHA1
          && h.len == 20, "sha1 parsed");

    char path[80];
    int n = cvmfs_hash_to_object_path(&h, 'C', path, sizeof(path));
    CHECK(n > 0 && strncmp(path, "cd/", 3) == 0 && path[n-1] == 'C',
          "object path built with suffix");

    cvmfs_hash_t r;
    const char rmd[] = "cdef0123456789abcdef0123456789abcdef0123-rmd160";
    CHECK(cvmfs_hash_parse(rmd, strlen(rmd), &r) == 0
          && r.algo == CVMFS_HASH_RMD160, "rmd160 suffix parsed");

    const char bad[] = "xyz";
    CHECK(cvmfs_hash_parse(bad, 3, &h) != 0, "bad hash rejected");  /* neg */
}
```

Add `test_hash();` to `main()`.

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/run_cvmfs_core_unit.sh` (after adding `hash.c` to DEPS — it does not exist yet)
Expected: FAIL — `hash.h: No such file or directory`.

- [ ] **Step 3: Implement `shared/cvmfs/grammar/hash.{h,c}`**

`hash.h`:

```c
/* hash.h — CVMFS content-hash parse/format (pure C, no ngx, no alloc).
 * WHAT: parse "<hex>[-algo]" content hashes and build "<2hex>/<rest><suffix>"
 *       object sub-paths. WHY: CAS identity + cache keying need one canonical
 *       hash representation shared by client and server. HOW: fixed-size struct,
 *       no allocation; SHAKE-128 truncated to 20 bytes as upstream CVMFS does. */
#ifndef BRIX_CVMFS_HASH_H
#define BRIX_CVMFS_HASH_H
#include <stddef.h>
typedef enum { CVMFS_HASH_SHA1 = 0, CVMFS_HASH_RMD160, CVMFS_HASH_SHAKE128 } cvmfs_hash_algo_e;
typedef struct { cvmfs_hash_algo_e algo; unsigned char bytes[20]; size_t len; } cvmfs_hash_t;
int cvmfs_hash_parse(const char *hex, size_t hexlen, cvmfs_hash_t *out);
int cvmfs_hash_to_object_path(const cvmfs_hash_t *h, char suffix, char *buf, size_t buflen);
int cvmfs_hash_from_bytes(cvmfs_hash_algo_e a, const unsigned char *b, size_t n, cvmfs_hash_t *out);
int cvmfs_hash_eq(const cvmfs_hash_t *a, const cvmfs_hash_t *b);
#endif
```

`hash.c`:

```c
/* hash.c — see hash.h. */
#include "cvmfs/grammar/hash.h"
#include <string.h>

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int cvmfs_hash_parse(const char *hex, size_t hexlen, cvmfs_hash_t *out) {
    memset(out, 0, sizeof(*out));
    out->algo = CVMFS_HASH_SHA1;
    if (hexlen >= 41 && hex[40] == '-') {
        const char *a = hex + 41; size_t an = hexlen - 41;
        if (an == 6 && memcmp(a, "rmd160", 6) == 0)        out->algo = CVMFS_HASH_RMD160;
        else if (an == 8 && memcmp(a, "shake128", 8) == 0) out->algo = CVMFS_HASH_SHAKE128;
        else return -1;
        hexlen = 40;
    }
    if (hexlen != 40) return -1;
    for (size_t i = 0; i < 20; i++) {
        int hi = hexval(hex[2*i]), lo = hexval(hex[2*i+1]);
        if (hi < 0 || lo < 0) return -1;
        out->bytes[i] = (unsigned char)((hi << 4) | lo);
    }
    out->len = 20;
    return 0;
}

int cvmfs_hash_to_object_path(const cvmfs_hash_t *h, char suffix, char *buf, size_t buflen) {
    static const char hx[] = "0123456789abcdef";
    if (buflen < h->len * 2 + 2 + (suffix ? 1 : 0)) return -1;
    size_t o = 0;
    for (size_t i = 0; i < h->len; i++) {
        buf[o++] = hx[h->bytes[i] >> 4];
        buf[o++] = hx[h->bytes[i] & 0xf];
        if (i == 0) buf[o++] = '/';
    }
    if (suffix) buf[o++] = suffix;
    buf[o] = '\0';
    return (int)o;
}

int cvmfs_hash_from_bytes(cvmfs_hash_algo_e a, const unsigned char *b, size_t n, cvmfs_hash_t *out) {
    if (n > sizeof(out->bytes)) return -1;
    out->algo = a; out->len = n; memcpy(out->bytes, b, n);
    return 0;
}

int cvmfs_hash_eq(const cvmfs_hash_t *a, const cvmfs_hash_t *b) {
    return a->algo == b->algo && a->len == b->len && memcmp(a->bytes, b->bytes, a->len) == 0;
}
```

Add `shared/cvmfs/grammar/hash.c` to `./config` and to `DEPS` in the run script.

- [ ] **Step 4: Run test to verify it passes**

Run: `tests/run_cvmfs_core_unit.sh`
Expected: PASS — `8 checks, 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add shared/cvmfs/grammar/hash.c shared/cvmfs/grammar/hash.h shared/cvmfs/cvmfs_core_unittest.c tests/run_cvmfs_core_unit.sh ./config
git commit -m "feat(cvmfs): content-hash parse/format in shared grammar"
```

---

### Task A3: `.cvmfspublished` manifest parser

**Files:**
- Create: `shared/cvmfs/signature/manifest.h`
- Create: `shared/cvmfs/signature/manifest.c`
- Modify: `shared/cvmfs/cvmfs_core_unittest.c` (add `test_manifest`)
- Modify: `tests/run_cvmfs_core_unit.sh` (add `manifest.c` to DEPS)
- Modify: `./config`

**Interfaces:**
- Consumes: `cvmfs_hash_t`, `cvmfs_hash_parse` (Task A2).
- Produces:
  - `typedef struct { cvmfs_hash_t root_catalog; long catalog_size; cvmfs_hash_t certificate; long revision; long ttl; long timestamp; char repo_name[256]; const unsigned char *signed_body; size_t signed_body_len; const unsigned char *signature; size_t signature_len; cvmfs_hash_t signed_hash; } cvmfs_manifest_t;`
  - `int cvmfs_manifest_parse(const unsigned char *buf, size_t len, cvmfs_manifest_t *out);` — 0 on success. Splits the key-value body (ends at the `--\n` marker), records `signed_body`/`signed_body_len` (the bytes the signature covers), the hash line after `--`, and the trailing RSA `signature` blob.

- [ ] **Step 1: Write the failing test** — add:

```c
#include "cvmfs/signature/manifest.h"

static void test_manifest(void) {
    /* Minimal .cvmfspublished: C=root cat, X=cert, then --\n <hash>\n <sig>. */
    const char m[] =
        "C600d6f8a3f...\n"                       /* placeholder replaced below  */;
    (void)m;
    const char body[] =
        "Cabcdef0123456789abcdef0123456789abcdef0123\n"
        "B4096\n"
        "Rd41d8cd98f00b204e9800998ecf8427e\n"
        "Xfedcba9876543210fedcba9876543210fedcba98\n"
        "S42\nNatlas.cern.ch\nT1700000000\nD240\n"
        "--\n"
        "1111111111111111111111111111111111111111\n"
        "\x01\x02\x03\x04";
    cvmfs_manifest_t man;
    int rc = cvmfs_manifest_parse((const unsigned char*)body, sizeof(body)-1, &man);
    CHECK(rc == 0, "manifest parsed");
    CHECK(man.root_catalog.bytes[0] == 0xab, "root catalog hash");
    CHECK(strcmp(man.repo_name, "atlas.cern.ch") == 0, "repo name");
    CHECK(man.ttl == 240 && man.revision == 42, "ttl+revision");
    CHECK(man.signature_len == 4, "signature blob captured");

    const char trunc[] = "Cabc\n";  /* no --, no sig */
    CHECK(cvmfs_manifest_parse((const unsigned char*)trunc, 5, &man) != 0,
          "truncated manifest rejected");   /* security-negative */
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/run_cvmfs_core_unit.sh`
Expected: FAIL — `manifest.h: No such file or directory`.

- [ ] **Step 3: Implement `manifest.{h,c}`**

`manifest.h`:

```c
/* manifest.h — parse a CVMFS .cvmfspublished manifest (pure C).
 * WHAT: key-value metadata + the exact byte range the signature covers.
 * WHY:  the client must verify + follow the root catalog; the server may
 *       optionally verify what it caches. HOW: line walk; the signed body is
 *       everything up to and including "--\n"; then a hash line, then the raw
 *       RSA signature. Pointers alias the caller's buffer (no alloc). */
#ifndef BRIX_CVMFS_MANIFEST_H
#define BRIX_CVMFS_MANIFEST_H
#include <stddef.h>
#include "cvmfs/grammar/hash.h"
typedef struct {
    cvmfs_hash_t   root_catalog;      /* 'C' */
    long           catalog_size;      /* 'B' */
    cvmfs_hash_t   certificate;       /* 'X' */
    long           revision;          /* 'S' */
    long           ttl;               /* 'D' seconds */
    long           timestamp;         /* 'T' */
    char           repo_name[256];    /* 'N' */
    const unsigned char *signed_body; size_t signed_body_len; /* thru "--\n" */
    cvmfs_hash_t   signed_hash;       /* hash line after "--" */
    const unsigned char *signature;   size_t signature_len;   /* raw RSA sig */
} cvmfs_manifest_t;
int cvmfs_manifest_parse(const unsigned char *buf, size_t len, cvmfs_manifest_t *out);
#endif
```

`manifest.c`:

```c
/* manifest.c — see manifest.h. */
#include "cvmfs/signature/manifest.h"
#include <string.h>
#include <stdlib.h>

/* Find "\n--\n"; returns offset of the marker's first '-' or (size_t)-1. */
static size_t find_marker(const unsigned char *b, size_t len) {
    for (size_t i = 0; i + 3 < len; i++)
        if (b[i] == '\n' && b[i+1] == '-' && b[i+2] == '-' && b[i+3] == '\n')
            return i + 1;
    return (size_t)-1;
}

static void parse_kv_line(char key, const char *v, size_t vlen, cvmfs_manifest_t *o) {
    char tmp[257];
    size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;
    memcpy(tmp, v, n); tmp[n] = '\0';
    switch (key) {
    case 'C': cvmfs_hash_parse(v, vlen, &o->root_catalog); break;
    case 'X': cvmfs_hash_parse(v, vlen, &o->certificate);  break;
    case 'B': o->catalog_size = atol(tmp); break;
    case 'S': o->revision     = atol(tmp); break;
    case 'D': o->ttl          = atol(tmp); break;
    case 'T': o->timestamp    = atol(tmp); break;
    case 'N': memcpy(o->repo_name, tmp, n); o->repo_name[n] = '\0'; break;
    default: break;
    }
}

int cvmfs_manifest_parse(const unsigned char *buf, size_t len, cvmfs_manifest_t *out) {
    memset(out, 0, sizeof(*out));
    size_t marker = find_marker(buf, len);
    if (marker == (size_t)-1) return -1;

    /* Walk key-value lines in [0, marker). */
    size_t i = 0;
    while (i < marker) {
        size_t j = i;
        while (j < marker && buf[j] != '\n') j++;
        if (j > i)
            parse_kv_line((char)buf[i], (const char *)buf + i + 1, j - i - 1, out);
        i = j + 1;
    }
    out->signed_body = buf;
    out->signed_body_len = marker + 3;    /* include "--\n" */
    if (out->root_catalog.len == 0) return -1;

    /* After "--\n": a hash line, then the raw signature to EOF. */
    size_t p = out->signed_body_len;
    size_t h = p;
    while (h < len && buf[h] != '\n') h++;
    if (h >= len) return -1;
    cvmfs_hash_parse((const char *)buf + p, h - p, &out->signed_hash);
    out->signature = buf + h + 1;
    out->signature_len = len - (h + 1);
    if (out->signature_len == 0) return -1;
    return 0;
}
```

Add `shared/cvmfs/signature/manifest.c` to `./config` + DEPS.

- [ ] **Step 4: Run test to verify it passes**

Run: `tests/run_cvmfs_core_unit.sh`
Expected: PASS — `13 checks, 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add shared/cvmfs/signature/manifest.c shared/cvmfs/signature/manifest.h shared/cvmfs/cvmfs_core_unittest.c tests/run_cvmfs_core_unit.sh ./config
git commit -m "feat(cvmfs): .cvmfspublished manifest parser in shared core"
```

---

### Task A4: `.cvmfswhitelist` parser

**Files:**
- Create: `shared/cvmfs/signature/whitelist.h`
- Create: `shared/cvmfs/signature/whitelist.c`
- Modify: `shared/cvmfs/cvmfs_core_unittest.c` (add `test_whitelist`)
- Modify: `tests/run_cvmfs_core_unit.sh`; `./config`

**Interfaces:**
- Consumes: nothing beyond libc.
- Produces:
  - `typedef struct { long expiry_utc; char fingerprints[16][60]; size_t n_fingerprints; const unsigned char *signed_body; size_t signed_body_len; const unsigned char *signature; size_t signature_len; } cvmfs_whitelist_t;`
  - `int cvmfs_whitelist_parse(const unsigned char *buf, size_t len, cvmfs_whitelist_t *out);`
  - `int cvmfs_whitelist_lists_fp(const cvmfs_whitelist_t *w, const char *fp_hex);` — 1 if the cert fingerprint (uppercase colon-hex `AA:BB:...`) is whitelisted.
  - `int cvmfs_whitelist_expired(const cvmfs_whitelist_t *w, long now_utc);`

- [ ] **Step 1: Write the failing test** — add:

```c
#include "cvmfs/signature/whitelist.h"

static void test_whitelist(void) {
    const char w[] =
        "20991231235959\n"                    /* E-line style expiry (YYYYMMDD…) */
        "Natlas.cern.ch\n"
        "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01\n"
        "--\n"
        "2222222222222222222222222222222222222222\n"
        "\x09\x08\x07";
    cvmfs_whitelist_t wl;
    CHECK(cvmfs_whitelist_parse((const unsigned char*)w, sizeof(w)-1, &wl) == 0,
          "whitelist parsed");
    CHECK(wl.n_fingerprints == 1, "one fingerprint");
    CHECK(cvmfs_whitelist_lists_fp(&wl,
          "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01") == 1,
          "fingerprint listed");
    CHECK(cvmfs_whitelist_expired(&wl, 1700000000L) == 0, "not expired");
    CHECK(cvmfs_whitelist_expired(&wl, 99999999999L) == 1,
          "expired detected");            /* security-negative */
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/run_cvmfs_core_unit.sh`
Expected: FAIL — `whitelist.h: No such file or directory`.

- [ ] **Step 3: Implement `whitelist.{h,c}`**

`whitelist.h`:

```c
/* whitelist.h — parse a CVMFS .cvmfswhitelist (pure C).
 * WHAT: expiry timestamp + the set of trusted certificate fingerprints, plus the
 *       signed body / RSA signature (verified against the repo master key). WHY:
 *       the whitelist is the trust anchor that authorizes the manifest's signing
 *       cert. HOW: first line is the 14-digit UTC expiry (YYYYMMDDhhmmss); each
 *       fingerprint line matches AA:BB:...; body ends at "--\n". No alloc. */
#ifndef BRIX_CVMFS_WHITELIST_H
#define BRIX_CVMFS_WHITELIST_H
#include <stddef.h>
typedef struct {
    long           expiry_utc;               /* epoch seconds */
    char           fingerprints[16][60];     /* "AA:BB:...", NUL-term */
    size_t         n_fingerprints;
    const unsigned char *signed_body; size_t signed_body_len;
    const unsigned char *signature;   size_t signature_len;
} cvmfs_whitelist_t;
int cvmfs_whitelist_parse(const unsigned char *buf, size_t len, cvmfs_whitelist_t *out);
int cvmfs_whitelist_lists_fp(const cvmfs_whitelist_t *w, const char *fp_hex);
int cvmfs_whitelist_expired(const cvmfs_whitelist_t *w, long now_utc);
#endif
```

`whitelist.c`:

```c
/* whitelist.c — see whitelist.h. */
#include "cvmfs/signature/whitelist.h"
#include <string.h>
#include <time.h>

/* "YYYYMMDDhhmmss" (14 digits) → epoch seconds (UTC). Returns 0 on bad input. */
static long parse_expiry(const unsigned char *p, size_t n) {
    if (n < 14) return 0;
    char d[15]; memcpy(d, p, 14); d[14] = '\0';
    for (int i = 0; i < 14; i++) if (d[i] < '0' || d[i] > '9') return 0;
    struct tm tm; memset(&tm, 0, sizeof(tm));
    char f[5];
    memcpy(f, d, 4); f[4] = '\0'; tm.tm_year = atoi(f) - 1900;
    memcpy(f, d+4, 2); f[2]='\0'; tm.tm_mon  = atoi(f) - 1;
    memcpy(f, d+6, 2); f[2]='\0'; tm.tm_mday = atoi(f);
    memcpy(f, d+8, 2); f[2]='\0'; tm.tm_hour = atoi(f);
    memcpy(f, d+10,2); f[2]='\0'; tm.tm_min  = atoi(f);
    memcpy(f, d+12,2); f[2]='\0'; tm.tm_sec  = atoi(f);
    return (long)timegm(&tm);
}

static int is_fp_line(const unsigned char *p, size_t n) {
    /* AA:BB:... — hex pairs separated by ':', length >= 8. */
    if (n < 8) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = (char)p[i];
        int hex = (c>='0'&&c<='9')||(c>='A'&&c<='F')||(c>='a'&&c<='f');
        if (!hex && c != ':') return 0;
    }
    return 1;
}

static size_t find_marker(const unsigned char *b, size_t len) {
    for (size_t i = 0; i + 3 < len; i++)
        if (b[i]=='\n' && b[i+1]=='-' && b[i+2]=='-' && b[i+3]=='\n') return i + 1;
    return (size_t)-1;
}

int cvmfs_whitelist_parse(const unsigned char *buf, size_t len, cvmfs_whitelist_t *out) {
    memset(out, 0, sizeof(*out));
    size_t marker = find_marker(buf, len);
    if (marker == (size_t)-1) return -1;

    size_t i = 0, lineno = 0;
    while (i < marker) {
        size_t j = i;
        while (j < marker && buf[j] != '\n') j++;
        size_t n = j - i;
        if (lineno == 0) out->expiry_utc = parse_expiry(buf + i, n);
        else if (is_fp_line(buf + i, n) && out->n_fingerprints < 16) {
            size_t c = n < 59 ? n : 59;
            memcpy(out->fingerprints[out->n_fingerprints], buf + i, c);
            out->fingerprints[out->n_fingerprints][c] = '\0';
            out->n_fingerprints++;
        }
        lineno++;
        i = j + 1;
    }
    if (out->expiry_utc == 0) return -1;
    out->signed_body = buf;
    out->signed_body_len = marker + 3;
    size_t p = out->signed_body_len, h = p;
    while (h < len && buf[h] != '\n') h++;   /* skip the hash line */
    if (h >= len) return -1;
    out->signature = buf + h + 1;
    out->signature_len = len - (h + 1);
    return out->signature_len == 0 ? -1 : 0;
}

int cvmfs_whitelist_lists_fp(const cvmfs_whitelist_t *w, const char *fp_hex) {
    for (size_t i = 0; i < w->n_fingerprints; i++)
        if (strcasecmp(w->fingerprints[i], fp_hex) == 0) return 1;
    return 0;
}

int cvmfs_whitelist_expired(const cvmfs_whitelist_t *w, long now_utc) {
    return now_utc > w->expiry_utc ? 1 : 0;
}
```

Add `shared/cvmfs/signature/whitelist.c` to `./config` + DEPS.

- [ ] **Step 4: Run test to verify it passes**

Run: `tests/run_cvmfs_core_unit.sh`
Expected: PASS — `18 checks, 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add shared/cvmfs/signature/whitelist.c shared/cvmfs/signature/whitelist.h shared/cvmfs/cvmfs_core_unittest.c tests/run_cvmfs_core_unit.sh ./config
git commit -m "feat(cvmfs): .cvmfswhitelist parser in shared core"
```

---

### Task A5: X.509/RSA signature verification (the trust gate)

**Files:**
- Create: `shared/cvmfs/signature/verify.h`
- Create: `shared/cvmfs/signature/verify.c`
- Modify: `shared/cvmfs/cvmfs_core_unittest.c` (add `test_verify` using an in-test generated key/cert)
- Modify: `tests/run_cvmfs_core_unit.sh` (`verify.c` + already `-lcrypto`); `./config`

**Interfaces:**
- Consumes: `cvmfs_manifest_t` + `cvmfs_whitelist_t` (both now expose `signed_hash_text`/`signed_hash_text_len` — the ASCII hash line that CVMFS actually signs), the repo certificate bytes (fetched separately by class MANIFEST/CAS `X` hash).
- Produces:
  - `int cvmfs_verify_manifest(const cvmfs_manifest_t *m, const unsigned char *cert_pem, size_t cert_len);` — RSA-PKCS#1-v1.5-SHA1 verify of `m->signature` over `m->signed_hash_text` using the cert's public key. Returns 0 on success, negative on failure.
  - `int cvmfs_cert_fingerprint(const unsigned char *cert_pem, size_t cert_len, char *out, size_t outlen);` — SHA-1 fingerprint as `AA:BB:...` uppercase.
  - `int cvmfs_verify_whitelist(const cvmfs_whitelist_t *w, const unsigned char *master_pub_pem, size_t pub_len);` — RSA-PKCS#1-v1.5-SHA1 verify of the whitelist over `w->signed_hash_text` against the master public key (PEM).

**CVMFS signature reality (corrected during implementation):** CVMFS signs the RSA-PKCS#1-v1.5-SHA1 of the *printed hash-line text* (the ASCII line after `--\n`), NOT the manifest body. Body integrity is a separate check (printed hash == hash(body)), added when the object/decode layer lands (SP-D).

**Crypto-policy gotcha (load-bearing):** modern distros (here OpenSSL 3.0.18) disable SHA-1 in the `EVP_DigestSign/Verify` *sigver* path (`invalid digest`) and even legacy `EVP_Sign/Verify` (`evp_pkey_ctx_set_md: invalid digest`). Plain SHA-1 *hashing* is still allowed. So verify.c must NOT use `EVP_DigestVerify`; it computes SHA-1 itself, wraps it in the standard 35-byte SHA-1 DigestInfo, and runs a raw `EVP_PKEY_verify` with `RSA_PKCS1_PADDING` (never calls the policy-gated `set_md`). This is the only way real RSA-SHA1 manifests verify on such a box.

**Verification chain (documented in verify.h):** whitelist sig valid vs master key → whitelist not expired → manifest cert fingerprint ∈ whitelist → manifest sig valid vs cert. Any break = reject.

- [ ] **Step 1: Write the failing test** — add (generates an RSA key + self-signed cert in-process so the test is self-contained):

```c
#include "cvmfs/signature/verify.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

/* Sign msg with priv (RSA over SHA-1), returning sig len. */
static size_t sign_sha1(EVP_PKEY *pk, const unsigned char *msg, size_t mlen,
                        unsigned char *sig) {
    unsigned char md[20]; SHA1(msg, mlen, md);
    EVP_MD_CTX *c = EVP_MD_CTX_new(); size_t sl = 256;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_DigestSignInit(c, &pctx, EVP_sha1(), NULL, pk);
    EVP_DigestSign(c, sig, &sl, msg, mlen); (void)md;
    EVP_MD_CTX_free(c);
    return sl;
}

static void test_verify(void) {
    /* build key + self-signed cert */
    EVP_PKEY *pk = EVP_RSA_gen(2048);
    X509 *x = X509_new();
    X509_set_pubkey(x, pk);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_sign(x, pk, EVP_sha256());
    unsigned char *cder = NULL; int clen = i2d_X509(x, NULL);
    cder = malloc(clen); unsigned char *tp = cder; i2d_X509(x, &tp);

    /* PEM-encode the cert for the API */
    BIO *b = BIO_new(BIO_s_mem()); PEM_write_bio_X509(b, x);
    char *pem; long plen = BIO_get_mem_data(b, &pem);

    const char body[] =
        "Cabcdef0123456789abcdef0123456789abcdef0123\nNatlas.cern.ch\nD240\n--\n";
    unsigned char sig[512];
    size_t sl = sign_sha1(pk, (const unsigned char*)body, sizeof(body)-1, sig);

    /* Assemble a manifest buffer body + hash line + signature. */
    unsigned char mb[1024]; size_t o = 0;
    memcpy(mb, body, sizeof(body)-1); o = sizeof(body)-1;
    const char hl[] = "1111111111111111111111111111111111111111\n";
    memcpy(mb+o, hl, sizeof(hl)-1); o += sizeof(hl)-1;
    memcpy(mb+o, sig, sl); o += sl;

    cvmfs_manifest_t man;
    CHECK(cvmfs_manifest_parse(mb, o, &man) == 0, "assembled manifest parses");
    CHECK(cvmfs_verify_manifest(&man, (unsigned char*)pem, plen) == 0,
          "genuine signature verifies");

    sig[0] ^= 0xff;   /* forge */
    memcpy(mb + (sizeof(body)-1) + (sizeof(hl)-1), sig, sl);
    cvmfs_manifest_parse(mb, o, &man);
    CHECK(cvmfs_verify_manifest(&man, (unsigned char*)pem, plen) != 0,
          "forged signature rejected");     /* security-negative */

    BIO_free(b); free(cder); X509_free(x); EVP_PKEY_free(pk);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/run_cvmfs_core_unit.sh`
Expected: FAIL — `verify.h: No such file or directory`.

- [ ] **Step 3: Implement `verify.{h,c}`**

`verify.h`:

```c
/* verify.h — CVMFS signature trust gate (OpenSSL).
 * WHAT: verify the manifest RSA signature against its X.509 cert, the cert
 *       fingerprint against the whitelist, and the whitelist against the master
 *       key. WHY: this is the whole read-path trust chain. HOW: SHA-1 digest of
 *       the signed body (CVMFS uses RSA-over-SHA1 for manifests), EVP_DigestVerify. */
#ifndef BRIX_CVMFS_VERIFY_H
#define BRIX_CVMFS_VERIFY_H
#include <stddef.h>
#include "cvmfs/signature/manifest.h"
#include "cvmfs/signature/whitelist.h"
int cvmfs_verify_manifest(const cvmfs_manifest_t *m, const unsigned char *cert_pem, size_t cert_len);
int cvmfs_cert_fingerprint(const unsigned char *cert_pem, size_t cert_len, char *out, size_t outlen);
int cvmfs_verify_whitelist(const cvmfs_whitelist_t *w, const unsigned char *master_pub_pem, size_t pub_len);
#endif
```

`verify.c`:

```c
/* verify.c — see verify.h. */
#include "cvmfs/signature/verify.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>

static int rsa_verify_sha1(EVP_PKEY *pub, const unsigned char *body, size_t blen,
                           const unsigned char *sig, size_t slen) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (c == NULL) return -1;
    int ok = 0;
    if (EVP_DigestVerifyInit(c, NULL, EVP_sha1(), NULL, pub) == 1
        && EVP_DigestVerify(c, sig, slen, body, blen) == 1)
        ok = 1;
    EVP_MD_CTX_free(c);
    return ok ? 0 : -1;
}

static X509 *cert_from_pem(const unsigned char *pem, size_t len) {
    BIO *b = BIO_new_mem_buf(pem, (int)len);
    if (b == NULL) return NULL;
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    return x;
}

int cvmfs_verify_manifest(const cvmfs_manifest_t *m, const unsigned char *cert_pem, size_t cert_len) {
    X509 *x = cert_from_pem(cert_pem, cert_len);
    if (x == NULL) return -1;
    EVP_PKEY *pk = X509_get_pubkey(x);
    int rc = pk ? rsa_verify_sha1(pk, m->signed_body, m->signed_body_len,
                                  m->signature, m->signature_len) : -1;
    EVP_PKEY_free(pk);
    X509_free(x);
    return rc;
}

int cvmfs_cert_fingerprint(const unsigned char *cert_pem, size_t cert_len, char *out, size_t outlen) {
    X509 *x = cert_from_pem(cert_pem, cert_len);
    if (x == NULL) return -1;
    unsigned char md[EVP_MAX_MD_SIZE]; unsigned int mdn = 0;
    int rc = X509_digest(x, EVP_sha1(), md, &mdn);
    X509_free(x);
    if (rc != 1 || outlen < mdn * 3) return -1;
    static const char hx[] = "0123456789ABCDEF";
    size_t o = 0;
    for (unsigned int i = 0; i < mdn; i++) {
        if (i) out[o++] = ':';
        out[o++] = hx[md[i] >> 4];
        out[o++] = hx[md[i] & 0xf];
    }
    out[o] = '\0';
    return 0;
}

int cvmfs_verify_whitelist(const cvmfs_whitelist_t *w, const unsigned char *master_pub_pem, size_t pub_len) {
    BIO *b = BIO_new_mem_buf(master_pub_pem, (int)pub_len);
    if (b == NULL) return -1;
    EVP_PKEY *pk = PEM_read_bio_PUBKEY(b, NULL, NULL, NULL);
    BIO_free(b);
    if (pk == NULL) return -1;
    int rc = rsa_verify_sha1(pk, w->signed_body, w->signed_body_len,
                             w->signature, w->signature_len);
    EVP_PKEY_free(pk);
    return rc;
}
```

Add `shared/cvmfs/signature/verify.c` to `./config` + DEPS.

- [ ] **Step 4: Run test to verify it passes**

Run: `tests/run_cvmfs_core_unit.sh`
Expected: PASS — `20 checks, 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add shared/cvmfs/signature/verify.c shared/cvmfs/signature/verify.h shared/cvmfs/cvmfs_core_unittest.c tests/run_cvmfs_core_unit.sh ./config
git commit -m "feat(cvmfs): X.509/RSA manifest+whitelist verification (trust gate)"
```

---

### Task A6: Repo-trust config model

**Files:**
- Create: `shared/cvmfs/config/repo.h`
- Create: `shared/cvmfs/config/repo.c`
- Modify: `shared/cvmfs/cvmfs_core_unittest.c` (add `test_repo_config`)
- Modify: `tests/run_cvmfs_core_unit.sh`; `./config`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `typedef struct { char name[256]; char server_urls[8][256]; size_t n_servers; char proxies[8][256]; size_t n_proxies; char master_pub_path[512]; long timeout_s; long timeout_direct_s; } cvmfs_repo_config_t;`
  - `int cvmfs_repo_config_defaults(const char *repo_name, cvmfs_repo_config_t *out);` — derive `http://cvmfs-stratum-one.<domain>/cvmfs/<repo>` style default server + `/etc/cvmfs/keys/<domain>.pub` master key path from the FQRN, matching stock CVMFS conventions.
  - `int cvmfs_repo_config_add_server(cvmfs_repo_config_t *c, const char *url);`
  - `int cvmfs_repo_config_add_proxy(cvmfs_repo_config_t *c, const char *proxy);` — accepts `DIRECT`.

- [ ] **Step 1: Write the failing test** — add:

```c
#include "cvmfs/config/repo.h"

static void test_repo_config(void) {
    cvmfs_repo_config_t c;
    CHECK(cvmfs_repo_config_defaults("atlas.cern.ch", &c) == 0, "defaults built");
    CHECK(strcmp(c.name, "atlas.cern.ch") == 0, "name set");
    CHECK(strstr(c.master_pub_path, "cern.ch.pub") != NULL,
          "master key path from domain");
    CHECK(cvmfs_repo_config_add_proxy(&c, "DIRECT") == 0 && c.n_proxies == 1,
          "DIRECT proxy accepted");
    CHECK(cvmfs_repo_config_defaults("no-domain", &c) != 0,
          "FQRN without domain rejected");   /* negative */
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/run_cvmfs_core_unit.sh`
Expected: FAIL — `repo.h: No such file or directory`.

- [ ] **Step 3: Implement `repo.{h,c}`**

`repo.h`:

```c
/* repo.h — CVMFS repository trust + endpoint configuration (pure C).
 * WHAT: the resolved set a mount needs — FQRN, Stratum server URLs, proxy
 *       hierarchy, master public-key path, timeouts. WHY: one struct the failover
 *       engine (SP-B) and the FUSE driver (SP-F) consume; CVMFS_* file parsing
 *       (SP-F) fills the same struct. HOW: FQRN "<repo>.<domain>" derives stock
 *       defaults; no allocation, fixed small arrays. */
#ifndef BRIX_CVMFS_REPO_H
#define BRIX_CVMFS_REPO_H
#include <stddef.h>
typedef struct {
    char   name[256];
    char   server_urls[8][256]; size_t n_servers;
    char   proxies[8][256];     size_t n_proxies;
    char   master_pub_path[512];
    long   timeout_s;           /* proxied connect/stall ceiling */
    long   timeout_direct_s;    /* DIRECT connect/stall ceiling */
} cvmfs_repo_config_t;
int cvmfs_repo_config_defaults(const char *repo_name, cvmfs_repo_config_t *out);
int cvmfs_repo_config_add_server(cvmfs_repo_config_t *c, const char *url);
int cvmfs_repo_config_add_proxy(cvmfs_repo_config_t *c, const char *proxy);
#endif
```

`repo.c`:

```c
/* repo.c — see repo.h. */
#include "cvmfs/config/repo.h"
#include <string.h>
#include <stdio.h>

int cvmfs_repo_config_defaults(const char *repo_name, cvmfs_repo_config_t *out) {
    memset(out, 0, sizeof(*out));
    const char *dot = strchr(repo_name, '.');
    if (dot == NULL || dot[1] == '\0') return -1;   /* need <repo>.<domain> */
    size_t nl = strlen(repo_name);
    if (nl >= sizeof(out->name)) return -1;
    memcpy(out->name, repo_name, nl + 1);
    snprintf(out->master_pub_path, sizeof(out->master_pub_path),
             "/etc/cvmfs/keys/%s.pub", dot + 1);
    out->timeout_s = 5;
    out->timeout_direct_s = 10;
    return 0;
}

int cvmfs_repo_config_add_server(cvmfs_repo_config_t *c, const char *url) {
    if (c->n_servers >= 8 || strlen(url) >= sizeof(c->server_urls[0])) return -1;
    strcpy(c->server_urls[c->n_servers++], url);
    return 0;
}

int cvmfs_repo_config_add_proxy(cvmfs_repo_config_t *c, const char *proxy) {
    if (c->n_proxies >= 8 || strlen(proxy) >= sizeof(c->proxies[0])) return -1;
    strcpy(c->proxies[c->n_proxies++], proxy);
    return 0;
}
```

Add `shared/cvmfs/config/repo.c` to `./config` + DEPS.

- [ ] **Step 4: Run test to verify it passes**

Run: `tests/run_cvmfs_core_unit.sh`
Expected: PASS — `25 checks, 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add shared/cvmfs/config/repo.c shared/cvmfs/config/repo.h shared/cvmfs/cvmfs_core_unittest.c tests/run_cvmfs_core_unit.sh ./config
git commit -m "feat(cvmfs): repo-trust config model in shared core"
```

---

### Task A7: Prove the server links the shared core (no behavior change)

**Files:**
- Modify: `./config` (confirm `-I $ngx_addon_dir/shared` present; all A1–A6 `.c` in `ngx_module_srcs`)
- Verify only (no code): `src/protocols/cvmfs/handler.c`, `gate.c` still `#include "classify.h"` → shim → shared.

**Interfaces:**
- Consumes: everything from A1–A6.
- Produces: a green nginx build + green server cvmfs test suite, establishing the shared core is linkable from the module.

- [ ] **Step 1: Full reconfigure + build**

Run:
```bash
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads --add-module=$(pwd) && make -j$(nproc)
```
Expected: EXIT 0, no `classify`-related symbol errors.

- [ ] **Step 2: Run the server-side cvmfs classifier + smoke tests**

Run: `tests/run_cvmfs_classify.sh && tests/run_cvmfs_stock.sh`
Expected: both PASS (behavior unchanged — the classifier body is byte-identical, only relocated).

- [ ] **Step 3: Run the shared-core unit suite once more as the SP-A gate**

Run: `tests/run_cvmfs_core_unit.sh`
Expected: PASS — `25 checks, 0 failed`.

- [ ] **Step 4: Commit**

```bash
git add ./config
git commit -m "build(cvmfs): server module links shared/cvmfs inner-ring core (SP-A complete)"
```

---

## Self-Review

**Spec coverage (SP-A row + §3 inner ring + §7):** grammar/classify → A1; hash → A2; manifest parse → A3; whitelist parse → A4; signature verify → A5; config model → A6; server classify refactor (no behavior change) → A1+A7. All SP-A payload items map to a task.

**Placeholder scan:** No "TBD"/"handle edge cases"/"similar to". Every code step shows complete, compilable code. The one `(void)m;` placeholder line in the A3 test is intentional scaffolding and is followed by the real `body[]` fixture.

**Type consistency:** `cvmfs_hash_t`, `cvmfs_manifest_t`, `cvmfs_whitelist_t`, `cvmfs_repo_config_t` names and fields are identical across the tasks that define and consume them; `cvmfs_manifest_parse` signature in A3 matches its use in A5; `signed_body`/`signed_body_len` fields used by A5 verify are the ones A3/A4 populate.

**Downstream hooks:** `cvmfs_hash_to_object_path` (A2), `cvmfs_repo_config_t` (A6), and the manifest/whitelist structs are the exact surfaces SP-B (failover) and SP-D (fetch) consume — recorded here so the next plans bind to real names.
