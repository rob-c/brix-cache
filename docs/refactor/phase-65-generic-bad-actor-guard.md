# Phase-65: Generic bad-actor MITM guard (ARC + XRootD) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Design spec:** [`docs/superpowers/specs/2026-07-01-generic-bad-actor-guard-arc-xrootd-design.md`](../superpowers/specs/2026-07-01-generic-bad-actor-guard-arc-xrootd-design.md)

**Goal:** Put nginx in front of ARC and a real XRootD instance as a credential-preserving MITM that classifies each request, bounces obvious junk, and emits one structured log line per bad-actor signal for fail2ban to ban on.

**Architecture:** A protocol-agnostic, allocation-free guard core (`src/guard/`, no nginx — same discipline as `src/net/tap/`) exposes `guard_classify_pre/post` + `guard_audit_format` over a normalized `guard_request_t`. Three thin adapters feed it: one nginx HTTP module (`ngx_http_xrootd_guard_module`) serving ARC and XrdHttp/WebDAV via a `profile` directive (ACCESS phase = pre-backend bounce, LOG phase = audit), and the existing `src/relay/` stream relay (guard sink on the tap → drop the connection). Stock `ngx_http_proxy_module` moves the bytes.

**Tech Stack:** C (C99), nginx module API (stream + http), stock `ngx_http_proxy_module`, pytest test harness, fail2ban (nftables banaction), standalone `gcc` for pure-C unit tests.

## Global Constraints

Copied verbatim from CLAUDE.md / spec — every task's requirements implicitly include these:

- **NO `goto`** anywhere in `src/`. Early-return + helper decomposition only.
- **Functional/modular**: one job per function, explicit data flow, no new globals, pure helpers with side effects at the edges.
- **Use HELPERS — never reimplement** path/auth/metrics/framing. In particular: `xrootd_sanitize_log_string()` on every wire-derived string; stock `ngx_http_proxy_module` for proxying (never a bespoke proxy).
- **Guard core is pure C**: no nginx headers, no allocation, no OpenSSL — so it unit-tests standalone (mirror `src/net/tap/`).
- nginx allocation only in adapters: HTTP `ngx_palloc(r->pool,…)`, stream `ngx_pcalloc(c->pool,…)` — never raw `malloc`.
- **Metric labels low-cardinality only** (INVARIANT 8): no paths/IPs in metrics. High-cardinality detail lives in the audit log; any metric counts by `signal` class only.
- **New `.c`/`.h` files register in the top-level `./config`** (`$ngx_addon_dir/src/...` lists), then run `./configure`. Incremental builds are `make -j$(nproc)` alone.
- **3 tests per change**: success + error + security-negative.
- **Never run any git command without explicit OP instruction** beyond the per-task `git add`/`git commit` steps this plan authorizes.
- errno→kXR→HTTP table (spec §quick-ref): ENOENT→kXR_NotFound→404; EACCES/EPERM→kXR_NotAuthorized→403.

---

## File Structure

**Guard core — `src/guard/` (pure C):**
- `guard.h` — types (`guard_request_t`, enums, `guard_ruleset_t`) + full public API.
- `guard_classify.c` — `guard_classify_pre`, `guard_classify_post`, `guard_signature_match`, `guard_grammar_ok`.
- `guard_audit.c` — `guard_audit_format` (key=value line; optional JSON).
- `guard_ruleset.c` — ruleset construction + built-in signature defaults + per-profile grammar defaults.
- `guard_test.c` — standalone unit test (compiled with plain `gcc`, no nginx).

**HTTP adapter — `src/httpguard/` (nginx http module):**
- `guard_http.h` — module decl, loc-conf struct, request-ctx struct.
- `module.c` — module definition, directive table, conf create/merge, phase-handler registration.
- `classify_handler.c` — ACCESS-phase handler (build `guard_request_t`, `classify_pre`, bounce).
- `audit_handler.c` — LOG-phase handler (outcome mapping, `classify_post`, append audit line).
- `guard_http_req.c` — `guard_request_t` builder from `ngx_http_request_t` (op mapping, cred_present, sanitized path) + audit-log file writer.

**Stream adapter — extend `src/relay/`:**
- `relay_guard.c` (new) — opcode→op-class table, `xrootd_tap_frame_t`→`guard_request_t`, guard sink, drop-flag.
- `relay.c` (modify) — register guard sink, check drop-flag in `relay_pump`.
- `relay.h` (modify) — new fields / decl.

**fail2ban — `deploy/fail2ban/`:**
- `xrootd-guard.filter` — `failregex` per signal.
- `jail.d/xrootd-guard.conf` — per-signal jails.
- `samples/xrootd-guard-audit.sample.log` — fixture for `fail2ban-regex`.

**Tests — `tests/`:**
- `tests/guard/run_guard_core.sh` — build+run `guard_test.c`.
- `tests/test_arc_guard.py`, `tests/test_xrdhttp_guard.py`, `tests/test_stream_guard.py`.
- `tests/test_fail2ban_regex.py` — runs `fail2ban-regex` over the sample log.

**Build/docs:**
- `./config` (modify) — register all new `.c`.
- `src/guard/README.md`, `src/httpguard/README.md`.

---

## Task 1: Guard core header + types + standalone test harness

**Files:**
- Create: `src/guard/guard.h`
- Create: `src/guard/guard_test.c`
- Create: `tests/guard/run_guard_core.sh`

**Interfaces:**
- Produces: `guard_request_t`, `guard_op_class_t`, `guard_outcome_t`, `guard_verdict_t`, `guard_reason_t`, `guard_ruleset_t` (opaque-ish struct), and the function prototypes used by every later task.

- [ ] **Step 1: Write `src/guard/guard.h`**

```c
#ifndef XROOTD_GUARD_GUARD_H
#define XROOTD_GUARD_GUARD_H

/*
 * guard.h — protocol-agnostic bad-actor classifier (pure C, no nginx).
 *
 * WHAT: normalizes any protocol request into guard_request_t, then classifies it
 *   for bad-actor signals (junk signatures, namespace-grammar violations,
 *   backend not-found storms, auth failures) and formats one audit line per
 *   flagged request for fail2ban to ban on.
 * WHY:  the bad-actor logic and the fail2ban contract are identical across ARC,
 *   XrdHttp/WebDAV, and root:// — write them once, feed from thin adapters.
 * HOW:  pure C — no nginx, no allocation, no OpenSSL — so it embeds in an nginx
 *   http module, in the stream relay, and unit-tests standalone. Mirrors src/net/tap/.
 */

#include <stddef.h>

typedef enum {
    GUARD_OP_READ, GUARD_OP_WRITE, GUARD_OP_LIST, GUARD_OP_DELETE,
    GUARD_OP_JOBCTL, GUARD_OP_STAGE, GUARD_OP_INFO, GUARD_OP_DELEG,
    GUARD_OP_HANDSHAKE, GUARD_OP_UNKNOWN
} guard_op_class_t;

typedef enum {
    OUTCOME_PENDING, OUTCOME_OK, OUTCOME_NOTFOUND,
    OUTCOME_AUTHFAIL, OUTCOME_ERROR
} guard_outcome_t;

typedef enum { GUARD_ALLOW, GUARD_BOUNCE } guard_verdict_t;

typedef enum {
    GUARD_R_NONE, GUARD_R_SIGNATURE, GUARD_R_GRAMMAR,
    GUARD_R_NOTFOUND, GUARD_R_AUTHFAIL
} guard_reason_t;

typedef struct {
    const char       *ip;          /* remote addr, adapter-supplied, NUL-term */
    const char       *proto;       /* "arc" | "xrdhttp" | "root" */
    guard_op_class_t  op;
    const char       *path;        /* already sanitized at the adapter edge */
    size_t            path_len;
    int               cred_present; /* 1 = client cert verified OR bearer present */
    guard_outcome_t   outcome;      /* PENDING pre-backend; set post-response */
    int               status_code;  /* HTTP status or kXR_* status */
} guard_request_t;

/* Signature pattern kinds. */
typedef enum {
    GUARD_SIG_SUFFIX,   /* path ends with pat  (".php") */
    GUARD_SIG_PREFIX,   /* path starts with pat ("/wp-") */
    GUARD_SIG_SUBSTR    /* path contains pat   ("/../") */
} guard_sig_kind_t;

#define GUARD_MAX_SIGS      64
#define GUARD_MAX_PREFIXES  32
#define GUARD_MAX_METHODS   16

typedef struct { guard_sig_kind_t kind; const char *pat; size_t pat_len; }
    guard_sig_t;

typedef struct {
    /* signature blocklist */
    guard_sig_t sigs[GUARD_MAX_SIGS];
    int         n_sigs;
    /* namespace grammar */
    const char *prefixes[GUARD_MAX_PREFIXES];
    size_t      prefix_len[GUARD_MAX_PREFIXES];
    int         n_prefixes;
    int         op_allowed[GUARD_OP_UNKNOWN + 1]; /* 1 = op permitted */
    int         enforce_grammar;                  /* 0 = prefixes/ops advisory */
    /* outcome flag toggles */
    int         flag_notfound;
    int         flag_authfail;
} guard_ruleset_t;

/* ---- classification (guard_classify.c) ---- */

/* Pre-backend verdict: signatures + grammar only. Sets *why on BOUNCE. */
guard_verdict_t guard_classify_pre(const guard_ruleset_t *rs,
    const guard_request_t *req, guard_reason_t *why);

/* Post-response signal: maps req->outcome to a loggable reason, else NONE.
 * Never bounces (the response already went out). */
guard_reason_t guard_classify_post(const guard_ruleset_t *rs,
    const guard_request_t *req);

/* Return 1 if path matches any signature. */
int guard_signature_match(const guard_ruleset_t *rs,
    const char *path, size_t len);

/* Return 1 if (op,path) is within the configured grammar. */
int guard_grammar_ok(const guard_ruleset_t *rs, guard_op_class_t op,
    const char *path, size_t len);

/* ---- audit formatting (guard_audit.c) ---- */

/* Format one flagged request as a single key=value line (fail2ban-friendly)
 * into out[0..outsz). `ts` is a caller-supplied timestamp string (adapters own
 * the clock). Returns bytes written (excl. NUL), or 0 if it would not fit. */
size_t guard_audit_format(const guard_request_t *req, guard_reason_t reason,
    const char *ts, char *out, size_t outsz);

/* Reason -> stable lowercase token used in the audit line + fail2ban filter. */
const char *guard_reason_str(guard_reason_t r);

/* Op-class -> stable lowercase token. */
const char *guard_op_str(guard_op_class_t op);

/* ---- ruleset construction (guard_ruleset.c) ---- */

/* Zero a ruleset. */
void guard_ruleset_init(guard_ruleset_t *rs);

/* Append the built-in junk-scanner signature set (php/wp/.env/.git/…). */
void guard_ruleset_add_default_signatures(guard_ruleset_t *rs);

/* Add one signature (pat must outlive the ruleset). Returns 0 on overflow. */
int guard_ruleset_add_signature(guard_ruleset_t *rs, guard_sig_kind_t kind,
    const char *pat, size_t pat_len);

/* Add one valid namespace prefix. Returns 0 on overflow. */
int guard_ruleset_add_prefix(guard_ruleset_t *rs, const char *pfx, size_t len);

/* Load the built-in grammar defaults for a profile ("arc"|"xrdhttp"|"root").
 * Sets prefixes + op_allowed[]. Unknown profile leaves grammar permissive. */
void guard_ruleset_load_profile(guard_ruleset_t *rs, const char *profile);

#endif /* XROOTD_GUARD_GUARD_H */
```

- [ ] **Step 2: Write the standalone test harness `src/guard/guard_test.c` (bootstrap: one trivially-true assertion)**

```c
/* guard_test.c — standalone unit tests for the pure-C guard core.
 * Build: gcc -Wall -Wextra -I src/guard src/guard/*.c -o /tmp/guard_test */
#include "guard.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

int main(void)
{
    /* Task 1 bootstrap: the header + enums compile and link. */
    guard_ruleset_t rs;
    guard_ruleset_init(&rs);
    CHECK(rs.n_sigs == 0);
    CHECK(rs.n_prefixes == 0);

    printf(fails ? "GUARD CORE: %d FAIL\n" : "GUARD CORE: all pass\n", fails);
    return fails ? 1 : 0;
}
```

- [ ] **Step 3: Write `tests/guard/run_guard_core.sh`**

```bash
#!/usr/bin/env bash
# Build + run the standalone guard-core unit test (no nginx).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
gcc -Wall -Wextra -std=c99 -Isrc/guard src/guard/guard_*.c -o /tmp/guard_test
exec /tmp/guard_test
```

- [ ] **Step 4: Create a minimal `guard_ruleset.c` so the bootstrap links**

```c
#include "guard.h"
#include <string.h>

void guard_ruleset_init(guard_ruleset_t *rs) { memset(rs, 0, sizeof(*rs)); }
```

- [ ] **Step 5: Run the harness — expect it to build and pass the bootstrap**

Run: `chmod +x tests/guard/run_guard_core.sh && tests/guard/run_guard_core.sh`
Expected: `GUARD CORE: all pass`

- [ ] **Step 6: Commit**

```bash
git add src/guard/guard.h src/guard/guard_test.c src/guard/guard_ruleset.c tests/guard/run_guard_core.sh
git commit -m "feat(guard): pure-C guard core header + standalone test harness"
```

---

## Task 2: Signature matching

**Files:**
- Create: `src/guard/guard_classify.c`
- Modify: `src/guard/guard_ruleset.c`
- Modify: `src/guard/guard_test.c`

**Interfaces:**
- Consumes: `guard_ruleset_t`, `guard_sig_t`, `guard_sig_kind_t` (Task 1).
- Produces: `int guard_signature_match(const guard_ruleset_t*, const char *path, size_t)`; `guard_ruleset_add_signature(...)`; `guard_ruleset_add_default_signatures(...)`.

- [ ] **Step 1: Add failing tests to `guard_test.c` (append before the final print)**

```c
    /* --- signatures --- */
    guard_ruleset_t sg; guard_ruleset_init(&sg);
    guard_ruleset_add_default_signatures(&sg);
    CHECK(guard_signature_match(&sg, "/wp-login.php", 13));   /* suffix .php */
    CHECK(guard_signature_match(&sg, "/wp-admin/", 10));       /* prefix /wp- */
    CHECK(guard_signature_match(&sg, "/x/.env", 7));           /* substr .env */
    CHECK(guard_signature_match(&sg, "/a/../b", 7));           /* substr /../ */
    CHECK(!guard_signature_match(&sg, "/rest/1.0/jobs", 14));  /* clean */
    CHECK(!guard_signature_match(&sg, "/data/file.root", 15)); /* clean */
    /* custom substring */
    guard_ruleset_t cs; guard_ruleset_init(&cs);
    CHECK(guard_ruleset_add_signature(&cs, GUARD_SIG_SUBSTR, "phpMyAdmin", 10));
    CHECK(guard_signature_match(&cs, "/phpMyAdmin/index", 17));
    CHECK(!guard_signature_match(&cs, "/data/ok", 8));
```

- [ ] **Step 2: Run — expect link failure (functions undefined)**

Run: `tests/guard/run_guard_core.sh`
Expected: FAIL — undefined reference to `guard_signature_match` / `guard_ruleset_add_default_signatures`.

- [ ] **Step 3: Implement `guard_signature_match` in `guard_classify.c`**

```c
#include "guard.h"
#include <string.h>

/* Case-sensitive suffix/prefix/substring test of one pattern against path. */
static int
sig_hit(const guard_sig_t *s, const char *path, size_t len)
{
    if (s->pat_len == 0 || s->pat_len > len) {
        return 0;
    }
    switch (s->kind) {
    case GUARD_SIG_SUFFIX:
        return memcmp(path + len - s->pat_len, s->pat, s->pat_len) == 0;
    case GUARD_SIG_PREFIX:
        return memcmp(path, s->pat, s->pat_len) == 0;
    case GUARD_SIG_SUBSTR:
    default: {
        size_t i;
        for (i = 0; i + s->pat_len <= len; i++) {
            if (memcmp(path + i, s->pat, s->pat_len) == 0) {
                return 1;
            }
        }
        return 0;
    }
    }
}

int
guard_signature_match(const guard_ruleset_t *rs, const char *path, size_t len)
{
    int i;
    for (i = 0; i < rs->n_sigs; i++) {
        if (sig_hit(&rs->sigs[i], path, len)) {
            return 1;
        }
    }
    return 0;
}
```

- [ ] **Step 4: Implement the signature builders in `guard_ruleset.c`**

```c
int
guard_ruleset_add_signature(guard_ruleset_t *rs, guard_sig_kind_t kind,
    const char *pat, size_t pat_len)
{
    if (rs->n_sigs >= GUARD_MAX_SIGS) {
        return 0;
    }
    rs->sigs[rs->n_sigs].kind    = kind;
    rs->sigs[rs->n_sigs].pat     = pat;
    rs->sigs[rs->n_sigs].pat_len = pat_len;
    rs->n_sigs++;
    return 1;
}

/* Built-in junk-scanner set. Static storage: literals outlive the ruleset. */
void
guard_ruleset_add_default_signatures(guard_ruleset_t *rs)
{
    static const struct { guard_sig_kind_t k; const char *p; } d[] = {
        { GUARD_SIG_SUFFIX, ".php" },   { GUARD_SIG_SUFFIX, ".asp" },
        { GUARD_SIG_SUFFIX, ".aspx" },  { GUARD_SIG_SUFFIX, ".cgi" },
        { GUARD_SIG_PREFIX, "/wp-" },   { GUARD_SIG_PREFIX, "/cgi-bin" },
        { GUARD_SIG_PREFIX, "/vendor" },{ GUARD_SIG_PREFIX, "/.git" },
        { GUARD_SIG_SUBSTR, "/.env" },  { GUARD_SIG_SUBSTR, "phpMyAdmin" },
        { GUARD_SIG_SUBSTR, "/../" },   { GUARD_SIG_SUBSTR, "/.aws" },
        { GUARD_SIG_SUBSTR, "/wp-config" },
    };
    size_t i;
    for (i = 0; i < sizeof(d) / sizeof(d[0]); i++) {
        guard_ruleset_add_signature(rs, d[i].k, d[i].p, strlen(d[i].p));
    }
}
```
(Add `#include <string.h>` at the top of `guard_ruleset.c` if not present.)

- [ ] **Step 5: Run — expect all pass**

Run: `tests/guard/run_guard_core.sh`
Expected: `GUARD CORE: all pass`

- [ ] **Step 6: Commit**

```bash
git add src/guard/guard_classify.c src/guard/guard_ruleset.c src/guard/guard_test.c
git commit -m "feat(guard): signature blocklist matching + built-in scanner set"
```

---

## Task 3: Namespace grammar + `guard_classify_pre`

**Files:**
- Modify: `src/guard/guard_classify.c`
- Modify: `src/guard/guard_ruleset.c`
- Modify: `src/guard/guard_test.c`

**Interfaces:**
- Consumes: `guard_signature_match` (Task 2), `guard_request_t`, `guard_ruleset_t`.
- Produces: `guard_grammar_ok(...)`, `guard_classify_pre(...)`, `guard_ruleset_add_prefix(...)`, `guard_ruleset_load_profile(...)`.

- [ ] **Step 1: Add failing tests to `guard_test.c`**

```c
    /* --- grammar + classify_pre --- */
    guard_ruleset_t ar; guard_ruleset_init(&ar);
    guard_ruleset_add_default_signatures(&ar);
    guard_ruleset_load_profile(&ar, "arc");   /* sets prefixes + op_allowed */

    guard_reason_t why = GUARD_R_NONE;
    guard_request_t ok = { "1.2.3.4", "arc", GUARD_OP_READ,
                           "/arex/rest/1.0/jobs", 19, 1, OUTCOME_PENDING, 0 };
    CHECK(guard_classify_pre(&ar, &ok, &why) == GUARD_ALLOW);
    CHECK(why == GUARD_R_NONE);

    guard_request_t junk = { "1.2.3.4", "arc", GUARD_OP_READ,
                             "/wp-login.php", 13, 0, OUTCOME_PENDING, 0 };
    CHECK(guard_classify_pre(&ar, &junk, &why) == GUARD_BOUNCE);
    CHECK(why == GUARD_R_SIGNATURE);

    guard_request_t offns = { "1.2.3.4", "arc", GUARD_OP_READ,
                              "/random/path", 12, 0, OUTCOME_PENDING, 0 };
    CHECK(guard_classify_pre(&ar, &offns, &why) == GUARD_BOUNCE);
    CHECK(why == GUARD_R_GRAMMAR);

    /* signatures take precedence over grammar (both would fire) */
    guard_request_t both = { "1.2.3.4", "arc", GUARD_OP_READ,
                             "/evil/.env", 10, 0, OUTCOME_PENDING, 0 };
    CHECK(guard_classify_pre(&ar, &both, &why) == GUARD_BOUNCE);
    CHECK(why == GUARD_R_SIGNATURE);

    /* advisory grammar: off-namespace ALLOWED when enforce_grammar==0 */
    guard_ruleset_t adv; guard_ruleset_init(&adv);
    guard_ruleset_add_prefix(&adv, "/arex", 5);
    adv.enforce_grammar = 0;
    CHECK(guard_classify_pre(&adv, &offns, &why) == GUARD_ALLOW);
```

- [ ] **Step 2: Run — expect link failure (`guard_grammar_ok`, `guard_classify_pre`, `guard_ruleset_load_profile` undefined)**

Run: `tests/guard/run_guard_core.sh`
Expected: FAIL — undefined references.

- [ ] **Step 3: Implement grammar + classify_pre in `guard_classify.c`**

```c
int
guard_grammar_ok(const guard_ruleset_t *rs, guard_op_class_t op,
    const char *path, size_t len)
{
    int i;
    if (!rs->op_allowed[op]) {
        return 0;
    }
    if (rs->n_prefixes == 0) {
        return 1;                       /* no prefixes configured = any path */
    }
    for (i = 0; i < rs->n_prefixes; i++) {
        if (len >= rs->prefix_len[i]
            && memcmp(path, rs->prefixes[i], rs->prefix_len[i]) == 0)
        {
            return 1;
        }
    }
    return 0;
}

guard_verdict_t
guard_classify_pre(const guard_ruleset_t *rs, const guard_request_t *req,
    guard_reason_t *why)
{
    if (guard_signature_match(rs, req->path, req->path_len)) {
        *why = GUARD_R_SIGNATURE;       /* signatures win over grammar */
        return GUARD_BOUNCE;
    }
    if (rs->enforce_grammar
        && !guard_grammar_ok(rs, req->op, req->path, req->path_len))
    {
        *why = GUARD_R_GRAMMAR;
        return GUARD_BOUNCE;
    }
    *why = GUARD_R_NONE;
    return GUARD_ALLOW;
}
```

- [ ] **Step 4: Implement `guard_ruleset_add_prefix` + `guard_ruleset_load_profile` in `guard_ruleset.c`**

```c
int
guard_ruleset_add_prefix(guard_ruleset_t *rs, const char *pfx, size_t len)
{
    if (rs->n_prefixes >= GUARD_MAX_PREFIXES) {
        return 0;
    }
    rs->prefixes[rs->n_prefixes]   = pfx;
    rs->prefix_len[rs->n_prefixes] = len;
    rs->n_prefixes++;
    return 1;
}

static void allow_ops(guard_ruleset_t *rs, const guard_op_class_t *ops, int n)
{ int i; for (i = 0; i < n; i++) rs->op_allowed[ops[i]] = 1; }

void
guard_ruleset_load_profile(guard_ruleset_t *rs, const char *profile)
{
    rs->enforce_grammar = 1;
    rs->flag_notfound   = 1;
    rs->flag_authfail   = 1;

    if (strcmp(profile, "arc") == 0) {
        static const guard_op_class_t ops[] = {
            GUARD_OP_READ, GUARD_OP_WRITE, GUARD_OP_LIST, GUARD_OP_DELETE,
            GUARD_OP_JOBCTL, GUARD_OP_STAGE, GUARD_OP_INFO, GUARD_OP_DELEG };
        guard_ruleset_add_prefix(rs, "/arex", 5);
        guard_ruleset_add_prefix(rs, "/rest", 5);
        guard_ruleset_add_prefix(rs, "/datadelivery", 13);
        allow_ops(rs, ops, (int)(sizeof(ops)/sizeof(ops[0])));
    } else if (strcmp(profile, "xrdhttp") == 0) {
        static const guard_op_class_t ops[] = {
            GUARD_OP_READ, GUARD_OP_WRITE, GUARD_OP_LIST, GUARD_OP_DELETE,
            GUARD_OP_INFO };
        /* XrdHttp/WebDAV serves the export root; operator narrows via
         * xrootd_guard_valid_prefix. Default: root-open but grammar on ops. */
        allow_ops(rs, ops, (int)(sizeof(ops)/sizeof(ops[0])));
    } else if (strcmp(profile, "root") == 0) {
        static const guard_op_class_t ops[] = {
            GUARD_OP_READ, GUARD_OP_WRITE, GUARD_OP_LIST, GUARD_OP_DELETE,
            GUARD_OP_INFO, GUARD_OP_HANDSHAKE };
        allow_ops(rs, ops, (int)(sizeof(ops)/sizeof(ops[0])));
    } else {
        /* unknown profile: permissive grammar, signatures still apply */
        int i;
        for (i = 0; i <= GUARD_OP_UNKNOWN; i++) rs->op_allowed[i] = 1;
        rs->enforce_grammar = 0;
    }
}
```
(Ensure `#include <string.h>` is present.)

- [ ] **Step 5: Run — expect all pass**

Run: `tests/guard/run_guard_core.sh`
Expected: `GUARD CORE: all pass`

- [ ] **Step 6: Commit**

```bash
git add src/guard/guard_classify.c src/guard/guard_ruleset.c src/guard/guard_test.c
git commit -m "feat(guard): namespace grammar + pre-backend classify (signature>grammar)"
```

---

## Task 4: Post-response outcome classification

**Files:**
- Modify: `src/guard/guard_classify.c`
- Modify: `src/guard/guard_test.c`

**Interfaces:**
- Consumes: `guard_request_t.outcome`, `guard_ruleset_t.flag_notfound/flag_authfail`.
- Produces: `guard_reason_t guard_classify_post(const guard_ruleset_t*, const guard_request_t*)`.

- [ ] **Step 1: Add failing tests to `guard_test.c`**

```c
    /* --- classify_post --- */
    guard_ruleset_t pr; guard_ruleset_init(&pr);
    pr.flag_notfound = 1; pr.flag_authfail = 1;
    guard_request_t nf = { "1.2.3.4","arc",GUARD_OP_READ,"/arex/x",7,1,
                           OUTCOME_NOTFOUND, 404 };
    CHECK(guard_classify_post(&pr, &nf) == GUARD_R_NOTFOUND);
    guard_request_t af = { "1.2.3.4","arc",GUARD_OP_READ,"/arex/x",7,0,
                           OUTCOME_AUTHFAIL, 401 };
    CHECK(guard_classify_post(&pr, &af) == GUARD_R_AUTHFAIL);
    guard_request_t okr = { "1.2.3.4","arc",GUARD_OP_READ,"/arex/x",7,1,
                            OUTCOME_OK, 200 };
    CHECK(guard_classify_post(&pr, &okr) == GUARD_R_NONE);
    /* toggled off => not flagged */
    guard_ruleset_t off; guard_ruleset_init(&off);
    off.flag_notfound = 0; off.flag_authfail = 0;
    CHECK(guard_classify_post(&off, &nf) == GUARD_R_NONE);
    CHECK(guard_classify_post(&off, &af) == GUARD_R_NONE);
```

- [ ] **Step 2: Run — expect link failure (`guard_classify_post` undefined)**

Run: `tests/guard/run_guard_core.sh`
Expected: FAIL.

- [ ] **Step 3: Implement in `guard_classify.c`**

```c
guard_reason_t
guard_classify_post(const guard_ruleset_t *rs, const guard_request_t *req)
{
    if (req->outcome == OUTCOME_NOTFOUND && rs->flag_notfound) {
        return GUARD_R_NOTFOUND;
    }
    if (req->outcome == OUTCOME_AUTHFAIL && rs->flag_authfail) {
        return GUARD_R_AUTHFAIL;
    }
    return GUARD_R_NONE;
}
```

- [ ] **Step 4: Run — expect all pass**

Run: `tests/guard/run_guard_core.sh`
Expected: `GUARD CORE: all pass`

- [ ] **Step 5: Commit**

```bash
git add src/guard/guard_classify.c src/guard/guard_test.c
git commit -m "feat(guard): post-response outcome classification (notfound/authfail)"
```

---

## Task 5: Audit line formatting

**Files:**
- Create: `src/guard/guard_audit.c`
- Modify: `src/guard/guard_test.c`

**Interfaces:**
- Consumes: `guard_request_t`, `guard_reason_t`, `guard_op_class_t`.
- Produces: `guard_audit_format(...)`, `guard_reason_str(...)`, `guard_op_str(...)`.

**Decision (spec §6):** the fail2ban line is **key=value**, single line, stable field order:
`<ts> ip=<ip> proto=<proto> signal=<reason> op=<op> path="<path>" status=<code>`.
The adapter passes a pre-sanitized `path` (no quotes/control bytes) — the formatter
still wraps it in quotes but assumes the edge already escaped it.

- [ ] **Step 1: Add failing tests to `guard_test.c`**

```c
    /* --- audit format --- */
    char line[512];
    guard_request_t sigreq = { "203.0.113.9","arc",GUARD_OP_READ,
                               "/wp-login.php",13,0,OUTCOME_PENDING,403 };
    size_t n = guard_audit_format(&sigreq, GUARD_R_SIGNATURE,
                                  "2026-07-01T12:00:00Z", line, sizeof(line));
    CHECK(n > 0);
    CHECK(strcmp(line,
        "2026-07-01T12:00:00Z ip=203.0.113.9 proto=arc signal=signature "
        "op=read path=\"/wp-login.php\" status=403") == 0);
    /* token maps */
    CHECK(strcmp(guard_reason_str(GUARD_R_AUTHFAIL), "authfail") == 0);
    CHECK(strcmp(guard_reason_str(GUARD_R_NOTFOUND), "notfound") == 0);
    CHECK(strcmp(guard_op_str(GUARD_OP_STAGE), "stage") == 0);
    /* too-small buffer => 0, no overflow */
    char tiny[8];
    CHECK(guard_audit_format(&sigreq, GUARD_R_SIGNATURE,
                             "2026-07-01T12:00:00Z", tiny, sizeof(tiny)) == 0);
```

- [ ] **Step 2: Run — expect link failure**

Run: `tests/guard/run_guard_core.sh`
Expected: FAIL — undefined references.

- [ ] **Step 3: Implement `src/guard/guard_audit.c`**

```c
#include "guard.h"
#include <stdio.h>

const char *
guard_reason_str(guard_reason_t r)
{
    switch (r) {
    case GUARD_R_SIGNATURE: return "signature";
    case GUARD_R_GRAMMAR:   return "grammar";
    case GUARD_R_NOTFOUND:  return "notfound";
    case GUARD_R_AUTHFAIL:  return "authfail";
    case GUARD_R_NONE:      default: return "none";
    }
}

const char *
guard_op_str(guard_op_class_t op)
{
    switch (op) {
    case GUARD_OP_READ:      return "read";
    case GUARD_OP_WRITE:     return "write";
    case GUARD_OP_LIST:      return "list";
    case GUARD_OP_DELETE:    return "delete";
    case GUARD_OP_JOBCTL:    return "jobctl";
    case GUARD_OP_STAGE:     return "stage";
    case GUARD_OP_INFO:      return "info";
    case GUARD_OP_DELEG:     return "deleg";
    case GUARD_OP_HANDSHAKE: return "handshake";
    case GUARD_OP_UNKNOWN:   default: return "unknown";
    }
}

size_t
guard_audit_format(const guard_request_t *req, guard_reason_t reason,
    const char *ts, char *out, size_t outsz)
{
    int n = snprintf(out, outsz,
        "%s ip=%s proto=%s signal=%s op=%s path=\"%.*s\" status=%d",
        ts, req->ip, req->proto, guard_reason_str(reason),
        guard_op_str(req->op), (int) req->path_len, req->path,
        req->status_code);
    if (n < 0 || (size_t) n >= outsz) {
        return 0;                       /* truncated -> emit nothing */
    }
    return (size_t) n;
}
```

- [ ] **Step 4: Run — expect all pass**

Run: `tests/guard/run_guard_core.sh`
Expected: `GUARD CORE: all pass`

- [ ] **Step 5: Commit**

```bash
git add src/guard/guard_audit.c src/guard/guard_test.c
git commit -m "feat(guard): key=value audit line formatter + reason/op tokens"
```

---

## Task 6: Register guard core in the build + `src/guard/README.md`

**Files:**
- Modify: `./config`
- Create: `src/guard/README.md`

**Interfaces:**
- Produces: guard-core `.o` files compiled into the module so adapters can link them.

- [ ] **Step 1: Add the guard sources to `./config`**

Find the `NGX_ADDON_SRCS` block that lists `src/net/tap/...` and add, in the same style:

```
    $ngx_addon_dir/src/guard/guard_classify.c \
    $ngx_addon_dir/src/guard/guard_audit.c \
    $ngx_addon_dir/src/guard/guard_ruleset.c \
```
(Do **not** add `guard_test.c` — it is standalone, never compiled into nginx.)

- [ ] **Step 2: Write `src/guard/README.md`** (short: purpose, the pure-C rule, the `guard_request_t` contract, that adapters own the clock + path sanitization, and the standalone test command).

- [ ] **Step 3: Reconfigure + build (new source files => full configure)**

Run:
```bash
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads --add-module=$PWD && make -j$(nproc)
```
Expected: clean build, exit 0. (Per the build-mixed-ABI gotcha, a fresh `./configure` after adding sources is mandatory.)

- [ ] **Step 4: Re-run the standalone guard test to confirm nothing regressed**

Run: `tests/guard/run_guard_core.sh`
Expected: `GUARD CORE: all pass`

- [ ] **Step 5: Commit**

```bash
git add config src/guard/README.md
git commit -m "build(guard): register guard core in ./config + README"
```

---

## Task 7: HTTP guard module skeleton (conf, directives, phase registration)

**Files:**
- Create: `src/httpguard/guard_http.h`
- Create: `src/httpguard/module.c`
- Modify: `./config`

**Interfaces:**
- Produces: `ngx_http_xrootd_guard_module`; `ngx_http_xrootd_guard_loc_conf_t` (holds a built `guard_ruleset_t`, `enable`, `profile`, `audit_log` `ngx_open_file_t*`, `bounce_status`); the directives from spec §5.
- Consumes: guard-core ruleset builders (Task 3/2).

Follow the pattern in `src/webdav/module.c` (module struct, `ngx_command_t` table, create/merge loc-conf, `postconfiguration` registering phase handlers). Key points below.

- [ ] **Step 1: Write `src/httpguard/guard_http.h`**

```c
#ifndef XROOTD_HTTPGUARD_GUARD_HTTP_H
#define XROOTD_HTTPGUARD_GUARD_HTTP_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "../guard/guard.h"

typedef struct {
    ngx_flag_t        enable;          /* xrootd_guard on|off */
    ngx_str_t         profile;         /* "arc" | "xrdhttp" */
    ngx_flag_t        default_sigs;    /* xrootd_guard_default_signatures */
    ngx_uint_t        bounce_status;   /* 403 | 444 */
    ngx_open_file_t  *audit_log;       /* xrootd_guard_audit_log */
    guard_ruleset_t   ruleset;         /* built at merge time */
    ngx_array_t      *extra_sigs;      /* ngx_str_t, operator additions */
    ngx_array_t      *prefixes;        /* ngx_str_t, operator prefixes */
    ngx_array_t      *methods;         /* ngx_str_t, operator methods */
} ngx_http_xrootd_guard_loc_conf_t;

/* Per-request state carried from ACCESS phase to LOG phase. */
typedef struct {
    guard_reason_t    pre_reason;      /* NONE unless pre-bounced */
    unsigned          bounced:1;
} ngx_http_xrootd_guard_ctx_t;

extern ngx_module_t ngx_http_xrootd_guard_module;

/* classify_handler.c */
ngx_int_t ngx_http_xrootd_guard_access_handler(ngx_http_request_t *r);
/* audit_handler.c */
ngx_int_t ngx_http_xrootd_guard_log_handler(ngx_http_request_t *r);
/* guard_http_req.c */
void ngx_http_xrootd_guard_build_request(ngx_http_request_t *r,
    ngx_http_xrootd_guard_loc_conf_t *lcf, guard_request_t *out,
    char *pathbuf, size_t pathbuf_sz);
void ngx_http_xrootd_guard_write_audit(ngx_http_request_t *r,
    ngx_http_xrootd_guard_loc_conf_t *lcf, const guard_request_t *req,
    guard_reason_t reason);

#endif
```

- [ ] **Step 2: Write `src/httpguard/module.c`** — the directive table, conf create/merge (building `ruleset` from `profile` + `default_sigs` + operator arrays), and `postconfiguration` that pushes the access + log handlers.

```c
#include "guard_http.h"

static void *ngx_http_xrootd_guard_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_xrootd_guard_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_xrootd_guard_postconf(ngx_conf_t *cf);

static ngx_command_t ngx_http_xrootd_guard_commands[] = {
    { ngx_string("xrootd_guard"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_guard_loc_conf_t, enable), NULL },

    { ngx_string("xrootd_guard_profile"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_guard_loc_conf_t, profile), NULL },

    { ngx_string("xrootd_guard_default_signatures"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_guard_loc_conf_t, default_sigs), NULL },

    { ngx_string("xrootd_guard_bounce_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_guard_loc_conf_t, bounce_status), NULL },

    { ngx_string("xrootd_guard_audit_log"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_xrootd_guard_audit_log_slot, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },

    { ngx_string("xrootd_guard_signature"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_xrootd_guard_array_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_guard_loc_conf_t, extra_sigs), NULL },

    { ngx_string("xrootd_guard_valid_prefix"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_xrootd_guard_array_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_guard_loc_conf_t, prefixes), NULL },

    { ngx_string("xrootd_guard_valid_method"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_xrootd_guard_methods_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_guard_loc_conf_t, methods), NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_xrootd_guard_module_ctx = {
    NULL, ngx_http_xrootd_guard_postconf,
    NULL, NULL, NULL, NULL,
    ngx_http_xrootd_guard_create_loc_conf,
    ngx_http_xrootd_guard_merge_loc_conf
};

ngx_module_t ngx_http_xrootd_guard_module = {
    NGX_MODULE_V1,
    &ngx_http_xrootd_guard_module_ctx,
    ngx_http_xrootd_guard_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_xrootd_guard_postconf(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt       *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = ngx_http_xrootd_guard_access_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = ngx_http_xrootd_guard_log_handler;

    return NGX_OK;
}
```

Also in `module.c`: `create_loc_conf` (`ngx_pcalloc`, set `enable/default_sigs/bounce_status = NGX_CONF_UNSET`, arrays `NGX_CONF_UNSET_PTR`); `merge_loc_conf` (apply defaults — `bounce_status` default `444`, `default_sigs` default `1` — then build `ruleset`: `guard_ruleset_init` → if `default_sigs` `guard_ruleset_add_default_signatures` → `guard_ruleset_load_profile(&ruleset, profile)` → append operator `extra_sigs` as `GUARD_SIG_SUBSTR`, `prefixes` via `guard_ruleset_add_prefix`, map `methods` to `op_allowed`); and the three custom slot helpers (`_audit_log_slot` via `ngx_conf_open_file(cf->cycle, &value[1])`, `_array_slot`, `_methods_slot`). Mirror `src/webdav/config.c` for the `ngx_conf_open_file` idiom.

- [ ] **Step 3: Register in `./config`**

Add to `NGX_ADDON_SRCS` (alongside the other http modules) — and to `NGX_ADDON_DEPS` the header:
```
    $ngx_addon_dir/src/httpguard/module.c \
    $ngx_addon_dir/src/httpguard/classify_handler.c \
    $ngx_addon_dir/src/httpguard/audit_handler.c \
    $ngx_addon_dir/src/httpguard/guard_http_req.c \
```
If this module needs its own `HTTP_MODULES` entry, mirror how `ngx_http_xrootd_webdav_module` is added in `./config` (`ngx_module_name`/`HTTP_MODULES` list). Create empty stubs for `classify_handler.c`, `audit_handler.c`, `guard_http_req.c` returning `NGX_DECLINED` / no-op so the build links this task.

- [ ] **Step 4: Reconfigure + build**

Run: `./configure … --add-module=$PWD && make -j$(nproc)`
Expected: exit 0. Then `objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf` parses with a `xrootd_guard on;` line added to a test location.
Expected: `configuration file … test is successful`.

- [ ] **Step 5: Commit**

```bash
git add src/httpguard/guard_http.h src/httpguard/module.c src/httpguard/classify_handler.c src/httpguard/audit_handler.c src/httpguard/guard_http_req.c config
git commit -m "feat(httpguard): module skeleton — directives, conf, phase registration"
```

---

## Task 8: HTTP `guard_request_t` builder (op mapping, cred_present, sanitized path)

**Files:**
- Modify: `src/httpguard/guard_http_req.c`
- Test: `tests/test_arc_guard.py` (create; ACCESS-phase behaviour asserted here via live server)

**Interfaces:**
- Consumes: `ngx_http_request_t`, `ngx_http_xrootd_guard_loc_conf_t`, `guard_request_t`.
- Produces: `ngx_http_xrootd_guard_build_request(r, lcf, out, pathbuf, sz)` filling `out` with `ip/proto/op/path/path_len/cred_present`; `ngx_http_xrootd_guard_write_audit(...)`.

- [ ] **Step 1: Implement `ngx_http_xrootd_guard_build_request` in `guard_http_req.c`**

```c
#include "guard_http.h"

/* HTTP method -> guard op-class (profile-independent baseline). */
static guard_op_class_t
method_to_op(ngx_uint_t m)
{
    switch (m) {
    case NGX_HTTP_GET:
    case NGX_HTTP_HEAD:      return GUARD_OP_READ;
    case NGX_HTTP_PUT:
    case NGX_HTTP_POST:      return GUARD_OP_WRITE;
    case NGX_HTTP_DELETE:    return GUARD_OP_DELETE;
    case NGX_HTTP_PROPFIND:  return GUARD_OP_LIST;
    case NGX_HTTP_OPTIONS:   return GUARD_OP_INFO;
    default:                 return GUARD_OP_UNKNOWN;
    }
}

/* 1 if the client presented a verified cert OR a non-empty Authorization. */
static int
cred_present(ngx_http_request_t *r)
{
#if (NGX_HTTP_SSL)
    if (r->connection->ssl) {
        ngx_str_t vs;
        if (ngx_ssl_get_client_verify(r->connection, r->pool == NULL ? NULL
                : r->pool, &vs) == NGX_OK && vs.len == 2
            && ngx_strncmp(vs.data, "OK", 2) == 0)
        {
            return 1;   /* mTLS proxy cert verified by our optional_no_ca */
        }
    }
#endif
    return r->headers_in.authorization != NULL
        && r->headers_in.authorization->value.len > 0;
}

void
ngx_http_xrootd_guard_build_request(ngx_http_request_t *r,
    ngx_http_xrootd_guard_loc_conf_t *lcf, guard_request_t *out,
    char *pathbuf, size_t pathbuf_sz)
{
    ngx_str_t san;

    /* Sanitize the wire-derived path (INVARIANT: escape control/quote bytes). */
    san = xrootd_sanitize_log_string(r->pool, &r->uri);

    if (san.len >= pathbuf_sz) {
        san.len = pathbuf_sz - 1;
    }
    ngx_memcpy(pathbuf, san.data, san.len);
    pathbuf[san.len] = '\0';

    out->ip           = (const char *) r->connection->addr_text.data;
    out->proto        = (const char *) lcf->profile.data;   /* "arc"/"xrdhttp" */
    out->op           = method_to_op(r->method);
    out->path         = pathbuf;
    out->path_len     = san.len;
    out->cred_present = cred_present(r);
    out->outcome      = OUTCOME_PENDING;
    out->status_code  = 0;
}
```
Note: `r->connection->addr_text` is NUL-terminated by nginx; `lcf->profile.data` is a config `ngx_str_t` — NUL-terminated by the conf parser. Confirm both, else copy into `pathbuf`-adjacent scratch. Use `xrootd_sanitize_log_string()` — do NOT reimplement (HELPERS).

- [ ] **Step 2: Write the ACCESS-phase pytest `tests/test_arc_guard.py`** using the existing test-server fixtures (mirror `tests/test_dashboard_files.py` for a live nginx location). Point a guard location at a stub upstream. Assert:

```python
def test_signature_bounced_pre_backend(guard_server, stub_backend):
    r = guard_server.get("/wp-login.php")
    assert r.status_code == 444
    assert stub_backend.hits == 0          # backend never touched

def test_valid_arc_request_proxied(guard_server, stub_backend):
    r = guard_server.get("/arex/rest/1.0/info")
    assert r.status_code == 200
    assert stub_backend.hits == 1

def test_grammar_violation_bounced(guard_server, stub_backend):
    r = guard_server.get("/random/scan")
    assert r.status_code == 444
    assert stub_backend.hits == 0
```

(These pass only after Task 9 wires the access handler; this step writes them to fail first.)

- [ ] **Step 3: Run — expect FAIL (handler still a stub)**

Run: `PYTHONPATH=tests pytest tests/test_arc_guard.py -v`
Expected: FAIL (stub returns NGX_DECLINED → 200/404, backend hit).

- [ ] **Step 4: Commit (builder only; handler wired next task)**

```bash
git add src/httpguard/guard_http_req.c tests/test_arc_guard.py
git commit -m "feat(httpguard): guard_request_t builder (op/cred/sanitized path) + access tests"
```

---

## Task 9: HTTP ACCESS-phase classify handler (pre-backend bounce)

**Files:**
- Modify: `src/httpguard/classify_handler.c`

**Interfaces:**
- Consumes: `ngx_http_xrootd_guard_build_request` (Task 8), `guard_classify_pre` (Task 3), `ngx_http_xrootd_guard_ctx_t`.
- Produces: `ngx_http_xrootd_guard_access_handler`.

- [ ] **Step 1: Implement `classify_handler.c`**

```c
#include "guard_http.h"

ngx_int_t
ngx_http_xrootd_guard_access_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_guard_loc_conf_t *lcf;
    ngx_http_xrootd_guard_ctx_t      *ctx;
    guard_request_t                   req;
    guard_reason_t                    why = GUARD_R_NONE;
    char                              pathbuf[1024];

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_guard_module);
    if (!lcf->enable || r->internal) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_guard_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_xrootd_guard_module);
    }

    ngx_http_xrootd_guard_build_request(r, lcf, &req, pathbuf, sizeof(pathbuf));

    if (guard_classify_pre(&lcf->ruleset, &req, &why) == GUARD_BOUNCE) {
        ctx->pre_reason  = why;
        ctx->bounced     = 1;
        req.status_code  = (int) lcf->bounce_status;
        /* audit now: the LOG phase also runs, but recording here guarantees a
         * line even if the request is discarded before logging. */
        ngx_http_xrootd_guard_write_audit(r, lcf, &req, why);
        return (ngx_int_t) lcf->bounce_status;    /* 403 or 444 */
    }

    return NGX_DECLINED;    /* clean -> proxy_pass runs */
}
```

Note: returning `444` yields nginx's `NGX_HTTP_CLOSE` (connection dropped, no response) — ideal for scanners; `403` returns a normal error page. Both are valid `ngx_int_t` returns from an access handler.

To avoid double-logging, the LOG handler (Task 10) must skip when `ctx->bounced` is already set for a pre-reason (it records post-signals only).

- [ ] **Step 2: Build**

Run: `make -j$(nproc)`
Expected: exit 0.

- [ ] **Step 3: Run the ACCESS tests — expect PASS**

Run: `PYTHONPATH=tests pytest tests/test_arc_guard.py -v`
Expected: PASS (signature/grammar → 444 pre-backend; valid → proxied).

- [ ] **Step 4: Commit**

```bash
git add src/httpguard/classify_handler.c
git commit -m "feat(httpguard): ACCESS-phase pre-backend bounce (signature/grammar)"
```

---

## Task 10: HTTP LOG-phase audit handler (outcome mapping + fail2ban line)

**Files:**
- Modify: `src/httpguard/audit_handler.c`
- Modify: `src/httpguard/guard_http_req.c` (add `ngx_http_xrootd_guard_write_audit`)
- Modify: `tests/test_arc_guard.py` (add post-response cases)

**Interfaces:**
- Consumes: `guard_classify_post` (Task 4), `guard_audit_format` (Task 5), `ngx_http_xrootd_guard_ctx_t`.
- Produces: `ngx_http_xrootd_guard_log_handler`, `ngx_http_xrootd_guard_write_audit`.

- [ ] **Step 1: Implement `ngx_http_xrootd_guard_write_audit` in `guard_http_req.c`**

```c
/* Append one guard_audit_format line to the configured audit log. */
void
ngx_http_xrootd_guard_write_audit(ngx_http_request_t *r,
    ngx_http_xrootd_guard_loc_conf_t *lcf, const guard_request_t *req,
    guard_reason_t reason)
{
    char       line[1280];
    u_char     ts[sizeof("YYYY-MM-DDTHH:MM:SSZ")];
    size_t     n;
    ngx_str_t  out;

    if (lcf->audit_log == NULL || lcf->audit_log->fd == NGX_INVALID_FILE) {
        return;
    }
    /* ISO-8601 UTC timestamp from cached time (no syscall). */
    ngx_gmtime(ngx_time(), NULL);   /* replace with ngx_http_time / snprintf */
    ngx_sprintf(ts, "%4d-%02d-%02dT%02d:%02d:%02dZ", 0,0,0,0,0,0); /* fill */

    n = guard_audit_format(req, reason, (char *) ts, line, sizeof(line));
    if (n == 0) {
        return;
    }
    line[n++] = '\n';
    out.data = (u_char *) line;
    out.len  = n;
    (void) ngx_write_fd(lcf->audit_log->fd, out.data, out.len);
}
```
Implementation note: build the timestamp with `ngx_libc_localtime`/`ngx_gmtime` on `ngx_time()` (cached, no syscall) — the pseudo-lines above are placeholders for the engineer to fill with the real `ngx_gmtime(ngx_time(), &tm)` + `ngx_sprintf`. Writing under a single `ngx_write_fd` keeps the line atomic for concurrent workers (one `write()` ≤ PIPE_BUF for a short line is atomic on a regular fd append opened `O_APPEND`; `ngx_conf_open_file` opens append-mode).

- [ ] **Step 2: Implement `audit_handler.c`**

```c
#include "guard_http.h"

static guard_outcome_t
status_to_outcome(ngx_uint_t status)
{
    if (status == NGX_HTTP_NOT_FOUND)      return OUTCOME_NOTFOUND;   /* 404 */
    if (status == NGX_HTTP_UNAUTHORIZED
        || status == NGX_HTTP_FORBIDDEN)   return OUTCOME_AUTHFAIL;   /* 401/403 */
    if (status >= NGX_HTTP_BAD_REQUEST)    return OUTCOME_ERROR;
    return OUTCOME_OK;
}

ngx_int_t
ngx_http_xrootd_guard_log_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_guard_loc_conf_t *lcf;
    ngx_http_xrootd_guard_ctx_t      *ctx;
    guard_request_t                   req;
    guard_reason_t                    reason;
    char                              pathbuf[1024];

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_guard_module);
    if (!lcf->enable) {
        return NGX_OK;
    }
    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_guard_module);
    if (ctx != NULL && ctx->bounced) {
        return NGX_OK;   /* already logged at ACCESS phase (pre-reason) */
    }

    ngx_http_xrootd_guard_build_request(r, lcf, &req, pathbuf, sizeof(pathbuf));
    req.status_code = (int) r->headers_out.status;
    req.outcome     = status_to_outcome(r->headers_out.status);

    reason = guard_classify_post(&lcf->ruleset, &req);
    if (reason != GUARD_R_NONE) {
        ngx_http_xrootd_guard_write_audit(r, lcf, &req, reason);
    }
    return NGX_OK;
}
```

- [ ] **Step 3: Add post-response tests to `tests/test_arc_guard.py`**

```python
def test_backend_404_logged_notfound(guard_server, stub_backend, audit_log):
    stub_backend.reply_status = 404
    guard_server.get("/arex/rest/1.0/jobs/does-not-exist")
    assert audit_log.last_line_has(signal="notfound", status="404")

def test_missing_cred_401_logged_authfail(guard_server, stub_backend, audit_log):
    stub_backend.reply_status = 401
    guard_server.get("/arex/rest/1.0/jobs")           # no cert, no bearer
    assert audit_log.last_line_has(signal="authfail", status="401")

def test_clean_request_not_logged(guard_server, stub_backend, audit_log):
    stub_backend.reply_status = 200
    n0 = audit_log.line_count()
    guard_server.get("/arex/rest/1.0/info")
    assert audit_log.line_count() == n0                # no signal line
```

- [ ] **Step 4: Build + run**

Run: `make -j$(nproc) && PYTHONPATH=tests pytest tests/test_arc_guard.py -v`
Expected: PASS (all ACCESS + LOG cases).

- [ ] **Step 5: Commit**

```bash
git add src/httpguard/audit_handler.c src/httpguard/guard_http_req.c tests/test_arc_guard.py
git commit -m "feat(httpguard): LOG-phase outcome classify + fail2ban audit line"
```

---

## Task 11: XrdHttp profile parity

**Files:**
- Create: `tests/test_xrdhttp_guard.py`

**Interfaces:**
- Consumes: everything from Tasks 7–10; the only change is `xrootd_guard_profile xrdhttp` + XrdHttp grammar prefixes.

- [ ] **Step 1: Add an `xrootd_guard on; xrootd_guard_profile xrdhttp;` location** to the test nginx conf (mirror the ARC location, different `proxy_pass` + `xrootd_guard_valid_prefix /` per your export). Point at the same stub backend.

- [ ] **Step 2: Write `tests/test_xrdhttp_guard.py`** — the same matrix as ARC but under the xrdhttp profile:

```python
def test_xrdhttp_signature_bounced(xrdhttp_guard_server, stub_backend):
    r = xrdhttp_guard_server.get("/.git/config")
    assert r.status_code == 444
    assert stub_backend.hits == 0

def test_xrdhttp_valid_get_proxied(xrdhttp_guard_server, stub_backend):
    r = xrdhttp_guard_server.get("/store/data/file.root")
    assert r.status_code == 200
    assert stub_backend.hits == 1

def test_xrdhttp_403_logged_authfail(xrdhttp_guard_server, stub_backend, audit_log):
    stub_backend.reply_status = 403
    xrdhttp_guard_server.get("/store/protected/file.root")
    assert audit_log.last_line_has(signal="authfail", proto="xrdhttp")
```

- [ ] **Step 3: Run — expect PASS (no new C code; profile switch only)**

Run: `PYTHONPATH=tests pytest tests/test_xrdhttp_guard.py -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/test_xrdhttp_guard.py
git commit -m "test(httpguard): XrdHttp/WebDAV profile parity matrix"
```

---

## Task 12: Stream adapter — opcode→op-class + guard sink + drop enforcement

**Files:**
- Create: `src/relay/relay_guard.c`
- Modify: `src/relay/relay.h`, `src/relay/relay.c`
- Modify: `src/core/config/*` stream srv-conf (add `guard_enable`, reuse existing audit/ruleset config) + `./config`
- Test: `tests/test_stream_guard.py`

**Interfaces:**
- Consumes: `xrootd_tap_frame_t` (`src/net/tap/tap.h`), `guard_classify_pre/post`, `guard_audit_format`.
- Produces: `xrootd_relay_guard_t` state; `xrootd_relay_guard_init(...)`; a tap sink `xrootd_relay_guard_sink(...)`; `int xrootd_relay_guard_should_drop(const xrootd_relay_guard_t*)`.

- [ ] **Step 1: Add guard state to `relay.h` / `xrootd_relay_t`**

Add to the `xrootd_relay_t` struct in `relay.c` (and any needed decl in `relay.h`):
```c
    guard_ruleset_t          guard_rules;   /* built once at relay start */
    int                      guard_enable;
    int                      guard_drop;    /* set by the sink -> pump closes */
```
Include `"../guard/guard.h"` at the top of `relay.c`.

- [ ] **Step 2: Write `src/relay/relay_guard.c`**

```c
#include "../ngx_xrootd_module.h"
#include "relay.h"
#include "../tap/tap.h"
#include "../guard/guard.h"
#include "../protocol/opcodes.h"

/* kXR_* request opcode -> guard op-class. */
static guard_op_class_t
opcode_to_op(uint16_t op)
{
    switch (op) {
    case kXR_open:     return GUARD_OP_READ;   /* refined by mode elsewhere */
    case kXR_read:
    case kXR_readv:
    case kXR_pgread:   return GUARD_OP_READ;
    case kXR_write:
    case kXR_pgwrite:  return GUARD_OP_WRITE;
    case kXR_dirlist:  return GUARD_OP_LIST;
    case kXR_rm:
    case kXR_rmdir:    return GUARD_OP_DELETE;
    case kXR_stat:
    case kXR_query:    return GUARD_OP_INFO;
    case kXR_login:
    case kXR_auth:
    case kXR_protocol: return GUARD_OP_HANDSHAKE;
    default:           return GUARD_OP_UNKNOWN;
    }
}

/* kXR_* response status -> outcome (only the two we act on). */
static guard_outcome_t
status_to_outcome(uint16_t st)
{
    if (st == kXR_NotFound)      return OUTCOME_NOTFOUND;
    if (st == kXR_NotAuthorized) return OUTCOME_AUTHFAIL;
    return OUTCOME_OK;
}

/* The tap sink: called once per decoded frame. ctx is the xrootd_relay_t. */
void
xrootd_relay_guard_sink(void *ctx, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const uint8_t *payload, size_t payload_len)
{
    xrootd_relay_t *r = ctx;
    guard_request_t req;
    guard_reason_t  why = GUARD_R_NONE;
    char            path[XROOTD_TAP_PATH_CAP + 1];
    char            ts[sizeof("YYYY-MM-DDThh:mm:ssZ")];
    char            line[1280];
    size_t          n, plen = 0;

    (void) payload; (void) payload_len;
    if (!r->guard_enable) {
        return;
    }

    if (f->path != NULL && f->path_len > 0) {
        plen = f->path_len < XROOTD_TAP_PATH_CAP ? f->path_len
                                                 : XROOTD_TAP_PATH_CAP;
        ngx_memcpy(path, f->path, plen);
    }
    path[plen] = '\0';

    req.ip           = (const char *) r->client->addr_text.data;
    req.proto        = "root";
    req.path         = path;
    req.path_len     = plen;
    req.cred_present = 0;   /* refine from tapped login state if desired */
    req.status_code  = 0;

    if (dir == XROOTD_TAP_C2U && f->is_request) {
        req.op      = opcode_to_op(f->opcode);
        req.outcome = OUTCOME_PENDING;
        if (guard_classify_pre(&r->guard_rules, &req, &why) == GUARD_BOUNCE) {
            r->guard_drop = 1;          /* pump tears the relay down */
        }
    } else if (dir == XROOTD_TAP_U2C && !f->is_request) {
        req.op          = GUARD_OP_UNKNOWN;
        req.status_code = (int) f->status;
        req.outcome     = status_to_outcome(f->status);
        why             = guard_classify_post(&r->guard_rules, &req);
    }

    if (why == GUARD_R_NONE) {
        return;
    }
    xrootd_relay_guard_timestamp(ts, sizeof(ts));     /* small helper below */
    n = guard_audit_format(&req, why, ts, line, sizeof(line));
    if (n > 0) {
        ngx_log_error(NGX_LOG_INFO, &r->log, 0, "%s", line);
    }
}
```
Add a tiny `xrootd_relay_guard_timestamp()` using `ngx_gmtime(ngx_time(), &tm)` + `ngx_sprintf`. Confirm the exact `kXR_*` enum names against `/tmp/xrootd-src/src/XProtocol/XProtocol.hh` and `src/protocol/opcodes.h` (INVARIANT: wire spec is authoritative).

- [ ] **Step 3: Wire the sink + drop check into `relay.c`**

In `xrootd_relay_start`, after `xrootd_tap_stream_init` for both decoders, build the ruleset and register the guard sink **in addition to** `relay_audit_sink`:
```c
    if (conf->guard_enable) {
        guard_ruleset_init(&r->guard_rules);
        guard_ruleset_add_default_signatures(&r->guard_rules);
        guard_ruleset_load_profile(&r->guard_rules, "root");
        r->guard_enable = 1;
        xrootd_tap_register_sink(&r->tap, xrootd_relay_guard_sink, r);
    }
```
In `relay_pump`, immediately after `xrootd_tap_stream_feed(dec, buf, (size_t) n);`, add:
```c
            {
                xrootd_relay_t *rr = /* recover hub */;
                if (rr->guard_drop) {
                    return NGX_ERROR;   /* BOUNCE: tear the relay down */
                }
            }
```
Because `relay_pump` doesn't currently receive the hub, add an `xrootd_relay_t *r` parameter to `relay_pump` (it already receives the per-direction decoder — thread the hub through the four call sites in `relay_cu`/`relay_uc`/`relay_begin`). This is a mechanical signature change; keep it functional (pass state explicitly, no globals).

- [ ] **Step 4: Add the `guard_enable` stream directive** — `xrootd_guard_stream on|off` on the transparent-proxy server block. Add the field to `ngx_stream_xrootd_srv_conf_t` and a `ngx_command_t` (mirror the `xrootd_transparent_proxy` registration in `src/stream/module.c` per the note that live stream tables live there). Register `relay_guard.c` in `./config`.

- [ ] **Step 5: Reconfigure + build**

Run: `./configure … --add-module=$PWD && make -j$(nproc)`
Expected: exit 0.

- [ ] **Step 6: Write `tests/test_stream_guard.py`** (self-start a relay in front of a real/stub XRootD on a high port, mirror `tests/hybrid_mesh_lib.py`/resilience dedicated-instance pattern):

```python
def test_valid_root_op_relayed(stream_guard):
    # xrdcp a known file through the relay -> succeeds, audit clean
    assert stream_guard.copy_ok("/store/data/file.root")

def test_garbage_handshake_dropped(stream_guard):
    # send non-XRootD bytes -> connection dropped, signal=signature logged
    conn = stream_guard.raw_connect()
    conn.send(b"GET /wp-login.php HTTP/1.0\r\n\r\n")
    assert conn.recv_eof(timeout=2)                 # relay RST/closed
    assert stream_guard.audit_has(signal="signature", proto="root")

def test_notfound_logged(stream_guard):
    stream_guard.stat("/store/data/missing.root")   # kXR_NotFound response
    assert stream_guard.audit_has(signal="notfound", proto="root")
```

- [ ] **Step 7: Run — expect PASS**

Run: `PYTHONPATH=tests pytest tests/test_stream_guard.py -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/relay/relay_guard.c src/relay/relay.c src/relay/relay.h src/stream/module.c config tests/test_stream_guard.py
git commit -m "feat(relay): stream guard sink — frame classify + connection drop"
```

---

## Task 13: fail2ban deliverables (filter, jails, regex test)

**Files:**
- Create: `deploy/fail2ban/xrootd-guard.filter`
- Create: `deploy/fail2ban/jail.d/xrootd-guard.conf`
- Create: `deploy/fail2ban/samples/xrootd-guard-audit.sample.log`
- Create: `tests/test_fail2ban_regex.py`

**Interfaces:**
- Consumes: the audit-line format from Task 5 (`… ip=<HOST> … signal=<reason> …`).

- [ ] **Step 1: Write `xrootd-guard.filter`**

```ini
# fail2ban filter for the nginx xrootd/ARC guard audit log.
# One [Definition]; jails select a signal via the `signal=` token.
[Definition]
# Bind <HOST> to the ip= field; the signal is parameterized per jail.
_signal = %(signal)s
failregex = ^\S+ ip=<HOST> proto=\S+ signal=%(_signal)s\b
ignoreregex =
datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%S
```

Because fail2ban filters can't take a runtime parameter directly, ship **four** thin filter files that each set the signal — or use one filter with `failregex` matching any actionable signal and split thresholds by jail. Simpler and robust: one filter per signal:

`filter.d/xrootd-guard-signature.conf`:
```ini
[Definition]
failregex = ^\S+ ip=<HOST> proto=\S+ signal=signature\b
datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%S
```
Repeat for `grammar`, `notfound`, `authfail` (one file each). Put them under `deploy/fail2ban/filter.d/`.

- [ ] **Step 2: Write `jail.d/xrootd-guard.conf`**

```ini
[xrootd-guard-signature]
enabled  = true
filter   = xrootd-guard-signature
logpath  = /var/log/xrootd-guard-audit.log
maxretry = 1
findtime = 600
bantime  = 86400
banaction = nftables-multiport

[xrootd-guard-grammar]
enabled  = true
filter   = xrootd-guard-grammar
logpath  = /var/log/xrootd-guard-audit.log
maxretry = 2
findtime = 600
bantime  = 43200
banaction = nftables-multiport

[xrootd-guard-notfound]
enabled  = true
filter   = xrootd-guard-notfound
logpath  = /var/log/xrootd-guard-audit.log
maxretry = 20
findtime = 60
bantime  = 3600
banaction = nftables-multiport

[xrootd-guard-authfail]
enabled  = true
filter   = xrootd-guard-authfail
logpath  = /var/log/xrootd-guard-audit.log
maxretry = 5
findtime = 120
bantime  = 7200
banaction = nftables-multiport
```

- [ ] **Step 3: Write the sample log** `samples/xrootd-guard-audit.sample.log` — one line per signal, real format from Task 5:

```
2026-07-01T12:00:00Z ip=203.0.113.9 proto=arc signal=signature op=read path="/wp-login.php" status=444
2026-07-01T12:00:01Z ip=198.51.100.7 proto=arc signal=grammar op=read path="/random/scan" status=444
2026-07-01T12:00:02Z ip=203.0.113.9 proto=xrdhttp signal=notfound op=read path="/store/x" status=404
2026-07-01T12:00:03Z ip=192.0.2.5 proto=root signal=authfail op=unknown path="/store/p" status=0
```

- [ ] **Step 4: Write `tests/test_fail2ban_regex.py`**

```python
import shutil, subprocess, pytest, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "deploy/fail2ban/samples/xrootd-guard-audit.sample.log"

@pytest.mark.skipif(not shutil.which("fail2ban-regex"),
                    reason="fail2ban-regex not installed")
@pytest.mark.parametrize("signal,host", [
    ("signature", "203.0.113.9"), ("grammar", "198.51.100.7"),
    ("notfound", "203.0.113.9"), ("authfail", "192.0.2.5")])
def test_filter_extracts_host(signal, host):
    flt = ROOT / f"deploy/fail2ban/filter.d/xrootd-guard-{signal}.conf"
    out = subprocess.run(["fail2ban-regex", str(SAMPLE), str(flt)],
                         capture_output=True, text=True).stdout
    assert "Missed" not in out.split("Lines:")[-1] or host in out
    assert host in out            # the matched IP was extracted
```

- [ ] **Step 5: Run**

Run: `PYTHONPATH=tests pytest tests/test_fail2ban_regex.py -v`
Expected: PASS (or SKIP where `fail2ban-regex` absent — install `fail2ban` in CI to exercise).

- [ ] **Step 6: Commit**

```bash
git add deploy/fail2ban tests/test_fail2ban_regex.py
git commit -m "feat(fail2ban): per-signal filters + jails + regex fixture test"
```

---

## Task 14: End-to-end integration, docs, and final verification

**Files:**
- Create: `src/httpguard/README.md`
- Modify: `CLAUDE.md` (OP→FILE HTTP table: add guard keyword→files row; ROUTING note)
- Create: `tests/test_guard_e2e.py` (optional smoke across all three surfaces)

- [ ] **Step 1: Write `src/httpguard/README.md`** — deployment recipe: host cert on `ssl_certificate`, `ssl_verify_client optional_no_ca`, `proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert`, `proxy_pass https://arc_backend`, `xrootd_guard on; xrootd_guard_profile arc; xrootd_guard_audit_log /var/log/xrootd-guard-audit.log;` — plus the fail2ban wiring pointer.

- [ ] **Step 2: Add an OP→FILE row to `CLAUDE.md`**

Under the HTTP table: `| guard / bad-actor / fail2ban | src/httpguard/*, src/guard/*, src/relay/relay_guard.c |`.

- [ ] **Step 3: Full guard-core + adapter test sweep**

Run:
```bash
tests/guard/run_guard_core.sh
PYTHONPATH=tests pytest tests/test_arc_guard.py tests/test_xrdhttp_guard.py tests/test_stream_guard.py tests/test_fail2ban_regex.py -v --tb=short
```
Expected: all PASS (fail2ban SKIP acceptable if the tool is absent).

- [ ] **Step 4: Config validation with a full guarded server block**

Run: `objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf`
Expected: `test is successful`.

- [ ] **Step 5: Confirm the no-goto / build invariants**

Run: `! grep -rn '\bgoto\b' src/guard src/httpguard src/relay/relay_guard.c`
Expected: no matches (exit 0 from the negation).

- [ ] **Step 6: Commit**

```bash
git add src/httpguard/README.md CLAUDE.md tests/test_guard_e2e.py
git commit -m "docs(guard): deployment README + OP->FILE row + e2e sweep"
```

---

## Self-review notes (author)

- **Spec coverage:** D1 (Task 8 cred_present + Task 14 cert-forwarding recipe), D2 (Tasks 9/10/13), D3 all four signals (T2 signature, T3 grammar, T4 notfound/authfail post), D4 stock proxy_pass (T9 returns DECLINED), D5 pure-C core (T1–T6), D6 three surfaces (HTTP T7–T11, stream T12). fail2ban contract (T13). Testing §7 (core T1–T5, http T8–T11, stream T12, fail2ban T13).
- **Open implementation details flagged for the engineer, not left vague:** the exact `ngx_gmtime`+`ngx_sprintf` timestamp fill (T10/T12), confirming `kXR_*` enum names against the wire spec (T12), the `relay_pump` hub-threading signature change (T12), and whether the guard module needs its own `HTTP_MODULES` entry in `./config` (T7) — each names the reference file to copy from.
- **Type consistency:** `guard_request_t`, `guard_classify_pre(rs,req,&why)`, `guard_classify_post(rs,req)`, `guard_audit_format(req,reason,ts,out,sz)` used identically in every task and both adapters.
