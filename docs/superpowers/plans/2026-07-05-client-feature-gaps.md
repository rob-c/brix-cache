# Client Feature-Gap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the user-facing feature gaps in the brix client tool suite: copy/sync policy (dry-run, filters, sync modes, mirror-delete, remove-source, resume journal), xrdfs power features (rm -r, --json, cat compression, tail -f), a recursive checksum audit, xrddiag --json, .xrdrc defaults, io_uring in xrdfs, man pages, and bash completion.

**Architecture:** Pure/policy logic goes in `client/lib/` (unit-testable via `make -C client test`); CLI wiring goes in `client/apps/`. New shared enablers (JSON emit, copy filter, journal, remote tree-walk/rmtree, manifest parser) land first, then features consume them. End-to-end behavior is verified by a new `tests/run_client_features.sh` that uses local↔local copies where possible and the test fleet (`root://localhost:11094`) where a server is required.

**Tech Stack:** C (C99, client is nginx-free standalone), POSIX (fnmatch, pthread), existing libbrix APIs (`brix_ops.h`, `brix_net.h`), GNU make, troff man pages, bash completion.

## Global Constraints

- **NO `goto`** anywhere in `client/` — early-return + helper decomposition (CLAUDE.md HARD BLOCK).
- Every function gets a WHAT/WHY/HOW doc block; follow `docs/09-developer-guide/coding-standards.md` (mandatory read before editing).
- 3 tests per change: success + error + security-negative (CLAUDE.md core rule 2).
- Build: `make -C /home/rcurrie/HEP-x/nginx-xrootd/client` (incremental). Unit tests: `make -C client test`. New lib `.c` files MUST be added to `LIB_SRCS` (client/Makefile ~lines 99–120); new app objects to `<tool>_OBJS`; new unit tests to `CLIENT_UNIT_TESTS` (~line 429).
- Commit directly to `main` after each task (Rob's standing rule: no feature branches). `git add` ONLY the files you touched — NEVER `git add -A` (the tree has unrelated WIP: `site/` pages and possible Makefile WIP).
- NEVER run destructive git commands (stash/reset/checkout/clean) — CLAUDE.md HARD BLOCK.
- Client code is ngx-free: no nginx headers/allocators; plain malloc/free with cleanup on all paths.
- `client/lib/brix_ops.h` etc. are installed public headers — additions only, no field reordering; new struct fields append at the end so zero-init keeps legacy behavior.
- Commit message trailer (every commit):
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_015B4HXDzc1zRLSsrBw8EGG6`

## Interface Reference (established by explorations; verbatim from source)

- `int brix_rm(brix_conn *c, const char *path, brix_status *st);` / `brix_rmdir` — brix_ops.h:325-328
- `int brix_dirlist(brix_conn *c, const char *path, int want_stat, brix_dirent **ents, size_t *count, brix_status *st);`
- `brix_dirent { char name[XRDC_NAME_MAX]; int have_stat; brix_statinfo st; }` (`st.flags & kXR_isDir`, `st.size`, `st.mtime`)
- `int brix_stat(brix_conn *c, const char *path, brix_statinfo *out, brix_status *st);`
- `int brix_cksum_algo_parse(const char *name, brix_cksum_algo *out);`
- `int brix_cksum_fd(int fd, brix_cksum_algo algo, char *hex, size_t hexsz, brix_status *st);`
- `int brix_query_cksum(brix_conn *c, const char *path, const char *algo_name, char *hex, size_t hexsz, brix_status *st);`
- `int brix_rfile_open_read(brix_conn *c, const char *path, const char *opaque, int pgrw, int max_stall_ms, brix_rfile *rf, brix_status *st);`
- `ssize_t brix_rfile_pread(brix_rfile *rf, int64_t off, void *buf, size_t len, brix_status *st);`
- xrdfs handler signature: `int handler(brix_conn *c, const char *cwd, int argc, char **argv)`; dispatch table `COMMANDS[]` in `apps/fs/xrdfs.c:9-47`; `build_path(cwd, arg, path, sizeof(path))` resolves relative paths.
- xrdcp batch: `transfer_one()` / `batch_copy_one()` / `batch_worker()` in `apps/copy/xrdcp_transfer.c`; `batch_ctx` in `apps/copy/xrdcp_internal.h:22-35`.
- lib recursive copy: `copy_tree_download()` / `copy_tree_upload()` / `copy_recursive()` in `lib/xfer/copy_recursive.c`; decls in `lib/xfer/copy_internal.h`.
- Compression opaque: `snprintf(opq, sizeof(opq), "xrootd.compress=%s", o->compress)` at `lib/xfer/copy_local.c:126` — read lines 115–140 there to see exactly how `opq` is passed into the open, and mirror it.
- VFS io_uring: `vopts.io_uring = o->io_uring;` at `lib/xfer/copy_local.c:242`; the field is `int io_uring;` in `lib/fs/vfs.h:59`.
- `.xrdcap`: writer+replay already complete (`lib/observability/capture.c`; `brix_capture_replay(path, verbose, out, st)` in brix_net.h:475). `xrddiag replay` exists (`apps/diag/diag_misc.c:177-194`).
- xrddiag JSON: `diag_args.json` already parsed (`--json`, xrddiag.c:610); `fjson_str(FILE*, const char*)` at xrddiag.c:404-424.
- `.xrdrc` parser: `lib/core/config/xrdrc.c` (sections `[alias NAME]`, `key = value`; lazy load via `$XRDRC` or `~/.xrdrc`).
- Timeouts: `lib/net/nettmo.c:44-85` — `brix_tmo_connect_ms()` (env `XRDC_CONNECT_TIMEOUT_MS`, default 15000), `brix_tmo_io_ms()` (env `XRDC_IO_TIMEOUT_MS`, default 30000), backoff env `XRDC_BACKOFF_BASE_MS` (nettmo.c:119-131), stall env `XRDC_MAX_STALL_MS` (lib/net/resilient.c:54).

---

### Task 1: Shared JSON emit helpers (`lib/cli/jsonout`)

**Files:**
- Create: `client/lib/cli/jsonout.h`, `client/lib/cli/jsonout.c`
- Modify: `client/Makefile` (LIB_SRCS + CLIENT_UNIT_TESTS), `client/apps/diag/xrddiag.c:404-424` (fjson_str delegates)
- Test: `client/tests/c/jsonout_unit.c`

**Interfaces:**
- Produces: `void brix_json_escape(FILE *out, const char *s)` (escaped, NO quotes), `void brix_json_fputs(FILE *out, const char *s)` (escaped, WITH surrounding quotes), `void brix_json_kv_str(FILE *out, const char *k, const char *v, int comma)`, `void brix_json_kv_ll(FILE *out, const char *k, long long v, int comma)`, `void brix_json_kv_bool(FILE *out, const char *k, int v, int comma)`. Used by Tasks 11, 15.

- [ ] **Step 1: Write the failing test** `client/tests/c/jsonout_unit.c`:

```c
/* jsonout_unit.c — unit tests for lib/cli/jsonout.c
 * WHAT: verifies JSON string escaping and kv emit helpers.
 * WHY:  one escaper shared by xrdfs --json and xrddiag --json; a broken
 *       escaper is an output-injection bug.
 * HOW:  render into a memstream, compare byte-exact. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cli/jsonout.h"

static char *render(void (*fn)(FILE *, const char *), const char *in)
{
    char  *buf = NULL;
    size_t sz = 0;
    FILE  *f = open_memstream(&buf, &sz);
    fn(f, in);
    fclose(f);
    return buf;
}

static void test_plain_roundtrip(void)          /* success */
{
    char *s = render(brix_json_fputs, "hello.txt");
    assert(strcmp(s, "\"hello.txt\"") == 0);
    free(s);
}

static void test_escapes(void)                   /* error-shaped input */
{
    char *s = render(brix_json_fputs, "a\"b\\c\nd\te");
    assert(strcmp(s, "\"a\\\"b\\\\c\\nd\\te\"") == 0);
    free(s);
}

static void test_injection_blocked(void)         /* security-negative */
{
    /* An embedded quote+brace must NOT be able to close the JSON string. */
    char *s = render(brix_json_fputs, "x\",\"evil\":1,\"y");
    assert(strstr(s, "\\\"") != NULL);
    assert(strstr(s, "\"evil\"") == NULL);   /* the quotes around evil are escaped */
    free(s);
    /* Control + high bytes become \u00XX (ASCII-safe output). */
    s = render(brix_json_fputs, "\x01\x9f");
    assert(strcmp(s, "\"\\u0001\\u009f\"") == 0);
    free(s);
}

static void test_kv_helpers(void)
{
    char  *buf = NULL; size_t sz = 0;
    FILE  *f = open_memstream(&buf, &sz);
    brix_json_kv_str(f, "name", "a b", 1);
    brix_json_kv_ll(f, "size", 42, 1);
    brix_json_kv_bool(f, "dir", 0, 0);
    fclose(f);
    assert(strcmp(buf, "\"name\":\"a b\",\"size\":42,\"dir\":false") == 0);
    free(buf);
}

int main(void)
{
    test_plain_roundtrip();
    test_escapes();
    test_injection_blocked();
    test_kv_helpers();
    printf("jsonout_unit: ALL PASS\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails.** Add `jsonout_unit` to `CLIENT_UNIT_TESTS` (client/Makefile ~line 429), then: `make -C client test`. Expected: compile FAILURE (`cli/jsonout.h: No such file`).

- [ ] **Step 3: Implement** `client/lib/cli/jsonout.h`:

```c
#ifndef BRIX_CLI_JSONOUT_H
#define BRIX_CLI_JSONOUT_H
#include <stdio.h>

/* WHAT: minimal shared JSON emit helpers for the CLI tools' --json modes.
 * WHY:  one escaping implementation across xrdfs/xrddiag — divergent
 *       hand-rolled escapers are a classic output-injection bug.
 * HOW:  RFC 8259 string escaping; bytes <0x20 and >=0x80 emit \u00XX so the
 *       output is pure ASCII regardless of on-wire filename bytes. */
void brix_json_escape(FILE *out, const char *s);   /* escaped, no quotes  */
void brix_json_fputs(FILE *out, const char *s);    /* "escaped"           */
void brix_json_kv_str(FILE *out, const char *k, const char *v, int comma);
void brix_json_kv_ll(FILE *out, const char *k, long long v, int comma);
void brix_json_kv_bool(FILE *out, const char *k, int v, int comma);

#endif
```

and `client/lib/cli/jsonout.c`:

```c
/* jsonout.c — shared JSON string/kv emitters (see jsonout.h). */
#include "cli/jsonout.h"

void
brix_json_escape(FILE *out, const char *s)
{
    const unsigned char *p = (const unsigned char *) s;
    for (; *p != '\0'; p++) {
        switch (*p) {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out);  break;
        case '\r': fputs("\\r", out);  break;
        case '\t': fputs("\\t", out);  break;
        default:
            if (*p < 0x20 || *p >= 0x80) {
                fprintf(out, "\\u%04x", (unsigned) *p);
            } else {
                fputc(*p, out);
            }
        }
    }
}

void
brix_json_fputs(FILE *out, const char *s)
{
    fputc('"', out);
    brix_json_escape(out, s);
    fputc('"', out);
}

void
brix_json_kv_str(FILE *out, const char *k, const char *v, int comma)
{
    brix_json_fputs(out, k);
    fputc(':', out);
    brix_json_fputs(out, v);
    if (comma) { fputc(',', out); }
}

void
brix_json_kv_ll(FILE *out, const char *k, long long v, int comma)
{
    brix_json_fputs(out, k);
    fprintf(out, ":%lld%s", v, comma ? "," : "");
}

void
brix_json_kv_bool(FILE *out, const char *k, int v, int comma)
{
    brix_json_fputs(out, k);
    fprintf(out, ":%s%s", v ? "true" : "false", comma ? "," : "");
}
```

Add `lib/cli/jsonout.c` to `LIB_SRCS` in client/Makefile. Then read `apps/diag/xrddiag.c:404-424`: if `fjson_str` writes surrounding quotes, replace its body with `brix_json_fputs(out, s);`; if not, replace with `brix_json_escape(out, s);` — keep the `fjson_str` name and all call sites unchanged. Add `#include "cli/jsonout.h"` (apps compile with `-I lib`).

- [ ] **Step 4: Run tests + build:** `make -C client && make -C client test`. Expected: `jsonout_unit: ALL PASS`, all pre-existing tests still pass.

- [ ] **Step 5: Commit:**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
git add client/lib/cli/jsonout.h client/lib/cli/jsonout.c client/tests/c/jsonout_unit.c client/Makefile client/apps/diag/xrddiag.c
git commit -m "feat(client): shared JSON emit helpers in lib/cli, xrddiag fjson_str delegates"
```

---

### Task 2: Copy filter + sync comparison policy (`lib/xfer/copy_filter.c`)

**Files:**
- Create: `client/lib/xfer/copy_filter.c`
- Modify: `client/lib/brix_ops.h` (append fields to `brix_copy_opts` at brix_ops.h:408-448; new constants + decls), `client/Makefile`
- Test: `client/tests/c/copy_filter_unit.c`

**Interfaces:**
- Produces: `int brix_copy_filter_match(const brix_copy_opts *o, const char *rel)` (1 = transfer, 0 = filtered out), `int brix_sync_should_skip(int cmp, long long ssz, long long smt, long long dsz, long long dmt)` (1 = up-to-date/skip), constants `XRDC_SYNC_SIZE 0`, `XRDC_SYNC_MTIME 1`, `XRDC_SYNC_CKSUM 2`. New `brix_copy_opts` fields (all zero = legacy behavior): `excludes/n_excludes`, `includes/n_includes`, `dry_run`, `remove_source`, `sync`, `sync_cmp`, `sync_cksum_algo`, `sync_delete`. Consumed by Tasks 5–9.

- [ ] **Step 1: Append to `brix_copy_opts`** (end of the struct, brix_ops.h:~447, before the closing brace):

```c
    /* --- 2026-07-05 transfer-policy extensions (zero-init = legacy) --- */
    const char *const *excludes;   /* fnmatch(3) patterns; a match skips the file */
    size_t             n_excludes;
    const char *const *includes;   /* when non-empty, a file must match one       */
    size_t             n_includes;
    int  dry_run;                  /* print decisions, transfer nothing            */
    int  remove_source;            /* delete source after verified success         */
    int  sync;                     /* --sync honored inside recursive walkers      */
    int  sync_cmp;                 /* XRDC_SYNC_SIZE | _MTIME | _CKSUM             */
    const char *sync_cksum_algo;   /* algo for XRDC_SYNC_CKSUM (default adler32)   */
    int  sync_delete;              /* recursive sync: delete dst entries not in src */
```

and after the struct:

```c
#define XRDC_SYNC_SIZE  0   /* skip when sizes match (legacy --sync)            */
#define XRDC_SYNC_MTIME 1   /* sizes match AND dst mtime >= src mtime           */
#define XRDC_SYNC_CKSUM 2   /* sizes match AND checksums match (caller does I/O) */

int brix_copy_filter_match(const brix_copy_opts *o, const char *rel);
int brix_sync_should_skip(int cmp, long long ssz, long long smt,
                          long long dsz, long long dmt);
```

- [ ] **Step 2: Write the failing test** `client/tests/c/copy_filter_unit.c`:

```c
/* copy_filter_unit.c — unit tests for --exclude/--include matching and the
 * --sync-check size/mtime comparison policy. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "brix.h"
#include "brix_ops.h"

static void test_no_filters_passes(void)        /* success */
{
    brix_copy_opts o;
    memset(&o, 0, sizeof(o));
    assert(brix_copy_filter_match(&o, "sub/dir/file.txt") == 1);
}

static void test_exclude_and_include(void)
{
    static const char *ex[] = { "*.log" };
    static const char *in[] = { "*.root" };
    brix_copy_opts o;
    memset(&o, 0, sizeof(o));
    o.excludes = ex; o.n_excludes = 1;
    assert(brix_copy_filter_match(&o, "run/job.log") == 0);   /* basename match  */
    assert(brix_copy_filter_match(&o, "run/data.root") == 1);
    o.includes = in; o.n_includes = 1;
    assert(brix_copy_filter_match(&o, "run/data.root") == 1);
    assert(brix_copy_filter_match(&o, "run/notes.txt") == 0); /* include gate    */
}

static void test_exclude_beats_include(void)     /* error/conflict case */
{
    static const char *ex[] = { "secret*" };
    static const char *in[] = { "*" };
    brix_copy_opts o;
    memset(&o, 0, sizeof(o));
    o.excludes = ex; o.n_excludes = 1;
    o.includes = in; o.n_includes = 1;
    assert(brix_copy_filter_match(&o, "secret.txt") == 0);
}

static void test_hostile_rel(void)               /* security-negative */
{
    /* A pathologically long rel must not crash or overflow (no fixed buffers). */
    static const char *ex[] = { "*.log" };
    char big[8192];
    brix_copy_opts o;
    memset(&o, 0, sizeof(o));
    o.excludes = ex; o.n_excludes = 1;
    memset(big, 'a', sizeof(big) - 5);
    memcpy(big + sizeof(big) - 5, ".log", 5);
    assert(brix_copy_filter_match(&o, big) == 0);
    assert(brix_copy_filter_match(&o, "") == 1);
    assert(brix_copy_filter_match(NULL, "x") == 1);
}

static void test_sync_should_skip(void)
{
    assert(brix_sync_should_skip(XRDC_SYNC_SIZE, 10, 0, 10, 0) == 1);
    assert(brix_sync_should_skip(XRDC_SYNC_SIZE, 10, 0, 11, 0) == 0);
    assert(brix_sync_should_skip(XRDC_SYNC_MTIME, 10, 100, 10, 100) == 1);
    assert(brix_sync_should_skip(XRDC_SYNC_MTIME, 10, 200, 10, 100) == 0); /* src newer */
    assert(brix_sync_should_skip(XRDC_SYNC_MTIME, 10, 100, 11, 200) == 0); /* size differs */
}

int main(void)
{
    test_no_filters_passes();
    test_exclude_and_include();
    test_exclude_beats_include();
    test_hostile_rel();
    test_sync_should_skip();
    printf("copy_filter_unit: ALL PASS\n");
    return 0;
}
```

- [ ] **Step 3: Run to verify it fails** (`make -C client test` after adding `copy_filter_unit` to `CLIENT_UNIT_TESTS`). Expected: link failure `undefined reference to brix_copy_filter_match`.

- [ ] **Step 4: Implement** `client/lib/xfer/copy_filter.c` (add to LIB_SRCS):

```c
/* copy_filter.c — pure transfer-policy predicates for xrdcp.
 * WHAT: --exclude/--include pattern matching + --sync-check up-to-date test.
 * WHY:  the same policy must apply identically in the single, batch, and
 *       recursive copy paths (lib + app), so it lives here once, pure and
 *       unit-testable.
 * HOW:  fnmatch(3) with flags 0 against the copy-root-relative path AND its
 *       basename (so `--exclude '*.log'` works at any depth). Exclude wins
 *       over include; a non-empty include list is a whitelist for files. */
#include "copy_internal.h"
#include <fnmatch.h>

static const char *
rel_basename(const char *rel)
{
    const char *b = strrchr(rel, '/');
    return (b != NULL) ? b + 1 : rel;
}

int
brix_copy_filter_match(const brix_copy_opts *o, const char *rel)
{
    size_t i;

    if (o == NULL || rel == NULL) {
        return 1;
    }
    for (i = 0; i < o->n_excludes; i++) {
        if (fnmatch(o->excludes[i], rel, 0) == 0
            || fnmatch(o->excludes[i], rel_basename(rel), 0) == 0) {
            return 0;
        }
    }
    if (o->n_includes > 0) {
        for (i = 0; i < o->n_includes; i++) {
            if (fnmatch(o->includes[i], rel, 0) == 0
                || fnmatch(o->includes[i], rel_basename(rel), 0) == 0) {
                return 1;
            }
        }
        return 0;
    }
    return 1;
}

int
brix_sync_should_skip(int cmp, long long ssz, long long smt,
                      long long dsz, long long dmt)
{
    if (ssz != dsz) {
        return 0;
    }
    if (cmp == XRDC_SYNC_MTIME && smt > dmt) {
        return 0;   /* source is newer than the destination — copy */
    }
    return 1;       /* SIZE (and the size half of CKSUM) — up to date */
}
```

- [ ] **Step 5: Run tests + build:** `make -C client && make -C client test` → `copy_filter_unit: ALL PASS`.

- [ ] **Step 6: Commit** (`git add client/lib/xfer/copy_filter.c client/lib/brix_ops.h client/tests/c/copy_filter_unit.c client/Makefile`, message `feat(client): copy filter + sync comparison policy in lib/xfer`).

---

### Task 3: Transfer journal (`lib/cli/xferjournal`)

**Files:**
- Create: `client/lib/cli/xferjournal.h`, `client/lib/cli/xferjournal.c`
- Modify: `client/Makefile`
- Test: `client/tests/c/xferjournal_unit.c`

**Interfaces:**
- Produces (opaque struct): `brix_journal *brix_journal_open(const char *path, brix_status *st)` (creates the file if missing; loads existing `ok <src>` lines), `int brix_journal_has(const brix_journal *j, const char *src)` (1 = already completed), `int brix_journal_mark(brix_journal *j, const char *src)` (thread-safe append + fflush; 0/-1; refuses src containing `\n` or `\r`), `void brix_journal_close(brix_journal *j)`. Consumed by Task 9.

- [ ] **Step 1: Write the failing test** `client/tests/c/xferjournal_unit.c`:

```c
/* xferjournal_unit.c — batch resume journal: load, lookup, append, hostile input. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "brix.h"
#include "cli/xferjournal.h"

static const char *PATH = "/tmp/xferjournal_unit.journal";

static void test_roundtrip(void)                 /* success */
{
    brix_status   st;
    brix_journal *j;
    unlink(PATH);
    brix_status_clear(&st);
    j = brix_journal_open(PATH, &st);
    assert(j != NULL);
    assert(brix_journal_has(j, "root://h//a") == 0);
    assert(brix_journal_mark(j, "root://h//a") == 0);
    brix_journal_close(j);
    j = brix_journal_open(PATH, &st);            /* reload: entry persisted */
    assert(j != NULL);
    assert(brix_journal_has(j, "root://h//a") == 1);
    assert(brix_journal_has(j, "root://h//b") == 0);
    brix_journal_close(j);
}

static void test_open_error(void)                /* error */
{
    brix_status st;
    brix_status_clear(&st);
    assert(brix_journal_open("/nonexistent-dir/x.journal", &st) == NULL);
    assert(st.msg[0] != '\0');
}

static void test_hostile_entries(void)           /* security-negative */
{
    brix_status   st;
    brix_journal *j;
    FILE         *f;
    unlink(PATH);
    /* Hand-craft a journal with a malformed + an oversized line: both must be
     * skipped without crashing, and valid lines around them still load. */
    f = fopen(PATH, "w");
    fprintf(f, "ok good1\n");
    fprintf(f, "garbage-no-prefix\n");
    fprintf(f, "ok ");
    for (int i = 0; i < 9000; i++) { fputc('x', f); }
    fprintf(f, "\nok good2\n");
    fclose(f);
    brix_status_clear(&st);
    j = brix_journal_open(PATH, &st);
    assert(j != NULL);
    assert(brix_journal_has(j, "good1") == 1);
    assert(brix_journal_has(j, "good2") == 1);
    assert(brix_journal_has(j, "garbage-no-prefix") == 0);
    /* Newline injection must be refused (would forge a second entry). */
    assert(brix_journal_mark(j, "evil\nok forged") == -1);
    brix_journal_close(j);
    j = brix_journal_open(PATH, &st);
    assert(brix_journal_has(j, "forged") == 0);
    brix_journal_close(j);
    unlink(PATH);
}

int main(void)
{
    test_roundtrip();
    test_open_error();
    test_hostile_entries();
    printf("xferjournal_unit: ALL PASS\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails** (add `xferjournal_unit` to CLIENT_UNIT_TESTS; expect missing header).

- [ ] **Step 3: Implement.** `client/lib/cli/xferjournal.h`:

```c
#ifndef BRIX_CLI_XFERJOURNAL_H
#define BRIX_CLI_XFERJOURNAL_H
#include "brix.h"

/* WHAT: persistent completion journal for batch copies (xrdcp --from/--resume).
 * WHY:  a 10k-file manifest killed at file 8k must resume without recopying;
 *       the journal records each completed source, one line: "ok <src>\n".
 * HOW:  loaded once into a qsort'ed array (bsearch lookups), appended+flushed
 *       under a mutex so -j worker threads can share one handle. */
typedef struct brix_journal brix_journal;

brix_journal *brix_journal_open(const char *path, brix_status *st);
int           brix_journal_has(const brix_journal *j, const char *src);
int           brix_journal_mark(brix_journal *j, const char *src);
void          brix_journal_close(brix_journal *j);

#endif
```

`client/lib/cli/xferjournal.c`:

```c
/* xferjournal.c — batch-copy resume journal (see xferjournal.h). */
#include "cli/xferjournal.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JOURNAL_LINE_MAX 4096   /* longer lines are hostile/corrupt: skipped */

struct brix_journal {
    FILE            *fp;      /* append stream */
    pthread_mutex_t  lock;
    char           **done;    /* sorted array of completed sources */
    size_t           n, cap;
};

static int
cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *) a, *(const char *const *) b);
}

/* Append one strdup'd entry to j->done (unsorted; caller sorts). 0/-1. */
static int
done_append(brix_journal *j, const char *s)
{
    if (j->n == j->cap) {
        size_t nc = j->cap ? j->cap * 2 : 64;
        char **na = (char **) realloc(j->done, nc * sizeof(char *));
        if (na == NULL) { return -1; }
        j->done = na;
        j->cap = nc;
    }
    j->done[j->n] = strdup(s);
    if (j->done[j->n] == NULL) { return -1; }
    j->n++;
    return 0;
}

/* Load existing "ok <src>" lines; malformed/oversized lines are skipped
 * (a corrupt journal must degrade to "recopy", never to a crash). 0/-1. */
static int
journal_load(brix_journal *j, const char *path)
{
    FILE *f = fopen(path, "r");
    char  line[JOURNAL_LINE_MAX];

    if (f == NULL) {
        return 0;   /* no journal yet — nothing completed */
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] != '\n' && !feof(f)) {
            int ch;                                   /* oversized: drain + skip */
            while ((ch = fgetc(f)) != EOF && ch != '\n') { }
            continue;
        }
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (strncmp(line, "ok ", 3) != 0 || line[3] == '\0') {
            continue;
        }
        if (done_append(j, line + 3) != 0) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    if (j->n > 1) {
        qsort(j->done, j->n, sizeof(char *), cmp_str);
    }
    return 0;
}

brix_journal *
brix_journal_open(const char *path, brix_status *st)
{
    brix_journal *j = (brix_journal *) calloc(1, sizeof(*j));

    if (j == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "journal: out of memory");
        return NULL;
    }
    if (journal_load(j, path) != 0) {
        brix_status_set(st, XRDC_EPROTO, 0, "journal: out of memory loading %s", path);
        brix_journal_close(j);
        return NULL;
    }
    j->fp = fopen(path, "a");
    if (j->fp == NULL) {
        brix_status_set(st, XRDC_ESOCK, errno, "journal: cannot open %s: %s",
                        path, strerror(errno));
        brix_journal_close(j);
        return NULL;
    }
    pthread_mutex_init(&j->lock, NULL);
    return j;
}

int
brix_journal_has(const brix_journal *j, const char *src)
{
    if (j == NULL || j->n == 0) {
        return 0;
    }
    return bsearch(&src, j->done, j->n, sizeof(char *), cmp_str) != NULL;
}

int
brix_journal_mark(brix_journal *j, const char *src)
{
    int rc;

    if (j == NULL || j->fp == NULL || src == NULL || src[0] == '\0'
        || strpbrk(src, "\n\r") != NULL || strlen(src) + 4 > JOURNAL_LINE_MAX) {
        return -1;   /* newline injection would forge entries — refuse */
    }
    pthread_mutex_lock(&j->lock);
    rc = (fprintf(j->fp, "ok %s\n", src) > 0 && fflush(j->fp) == 0) ? 0 : -1;
    pthread_mutex_unlock(&j->lock);
    return rc;
}

void
brix_journal_close(brix_journal *j)
{
    size_t i;

    if (j == NULL) {
        return;
    }
    if (j->fp != NULL) {
        fclose(j->fp);
        pthread_mutex_destroy(&j->lock);
    }
    for (i = 0; i < j->n; i++) { free(j->done[i]); }
    free(j->done);
    free(j);
}
```

Note: `brix_journal_open` initializes the mutex only after fopen succeeds, and `brix_journal_close` destroys it only when `fp != NULL` — keep that pairing.

- [ ] **Step 4: Run tests:** `make -C client test` → `xferjournal_unit: ALL PASS`.
- [ ] **Step 5: Commit** (message `feat(client): batch-copy resume journal in lib/cli`).

---

### Task 4: Remote tree walk + rmtree + safe-rel promotion (`lib/fs`)

**Files:**
- Create: `client/lib/fs/walk.c`, `client/lib/fs/rmtree.c`
- Modify: `client/lib/brix_ops.h` (decls), `client/lib/fs/path.c` (add `brix_rel_is_unsafe`), `client/apps/copy/xrdcp.c:281-287` (`rel_is_unsafe` delegates to lib), `client/Makefile`
- Test: `client/tests/c/relsafe_unit.c`

**Interfaces:**
- Produces:
  - `typedef int (*brix_walk_fn)(const char *path, const brix_dirent *e, int depth, void *u);`
  - `int brix_tree_walk(brix_conn *c, const char *path, brix_walk_fn fn, void *u, brix_status *st);` — pre-order, depth cap 64, skips `.`/`..`; visitor return non-zero aborts (walk returns 1); -1 on error.
  - `#define BRIX_RMTREE_DRYRUN 0x1`
  - `typedef int (*brix_rmtree_report)(const char *path, int is_dir, void *u);`
  - `int brix_rmtree(brix_conn *c, const char *path, unsigned flags, brix_rmtree_report report, void *u, brix_status *st);` — post-order recursive delete; refuses `""` and `"/"`; report (may be NULL) fires per deleted entry; DRYRUN reports without deleting. 0/-1.
  - `int brix_rel_is_unsafe(const char *rel);` — 1 when rel is absolute or contains a `..` component.
  - Consumed by Tasks 7, 10, 14.

- [ ] **Step 1: Write the failing test** `client/tests/c/relsafe_unit.c`:

```c
/* relsafe_unit.c — brix_rel_is_unsafe: the guard that keeps server-supplied or
 * manifest-supplied relative paths inside the destination root. */
#include <assert.h>
#include <stdio.h>
#include "brix.h"
#include "brix_ops.h"

int main(void)
{
    /* success: benign paths pass */
    assert(brix_rel_is_unsafe("a/b/c.txt") == 0);
    assert(brix_rel_is_unsafe("a..b/c..d") == 0);     /* dots inside names OK */
    assert(brix_rel_is_unsafe("...") == 0);
    /* error/edge: empty is safe to join (degenerate but not escaping) */
    assert(brix_rel_is_unsafe("") == 0);
    /* security-negative: every escape shape is caught */
    assert(brix_rel_is_unsafe("/etc/passwd") == 1);
    assert(brix_rel_is_unsafe("..") == 1);
    assert(brix_rel_is_unsafe("../x") == 1);
    assert(brix_rel_is_unsafe("x/../y") == 1);
    assert(brix_rel_is_unsafe("x/..") == 1);
    printf("relsafe_unit: ALL PASS\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails** (add `relsafe_unit` to CLIENT_UNIT_TESTS).

- [ ] **Step 3: Implement.** In `client/lib/fs/path.c` append (and declare in brix_ops.h):

```c
/* WHAT: 1 if a relative path would escape the directory it is joined under.
 * WHY:  server dirlists, manifests, and archives are untrusted inputs; a
 *       "../" component or absolute path must never place files outside the
 *       destination root (moved here from apps/copy so every consumer shares
 *       one guard).
 * HOW:  flag absolute paths and any exact ".." path component. */
int
brix_rel_is_unsafe(const char *rel)
{
    size_t len;

    if (rel == NULL || rel[0] == '/') {
        return rel != NULL;
    }
    len = strlen(rel);
    if (strcmp(rel, "..") == 0
        || strncmp(rel, "../", 3) == 0
        || strstr(rel, "/../") != NULL
        || (len >= 3 && strcmp(rel + len - 3, "/..") == 0)) {
        return 1;
    }
    return 0;
}
```

Replace the body of `rel_is_unsafe` in `apps/copy/xrdcp.c:281-287` with `return brix_rel_is_unsafe(rel);` (keep the wrapper so app callers are untouched).

`client/lib/fs/walk.c` (model: `apps/fs/xrdfs_walk.c:12-42`; this is the lib twin so non-xrdfs tools can walk):

```c
/* walk.c — generic pre-order remote tree walk over brix_dirlist.
 * WHAT: visit every entry under `path` (files and directories), parent first.
 * WHY:  xrdcksum tree, sync --delete and future tools all need one bounded,
 *       overflow-checked walker instead of four ad-hoc recursions.
 * HOW:  brix_dirlist(want_stat=1) per directory; recursion capped at
 *       BRIX_WALK_MAXDEPTH; path joins are length-checked. */
#include "brix.h"
#include "brix_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BRIX_WALK_MAXDEPTH 64

static int
walk_is_dot(const char *n)
{
    return n[0] == '.' && (n[1] == '\0' || (n[1] == '.' && n[2] == '\0'));
}

static int
walk_join(const char *dir, const char *name, char *out, size_t outsz)
{
    size_t dl = strlen(dir);
    const char *sep = (dl > 0 && dir[dl - 1] == '/') ? "" : "/";
    return ((size_t) snprintf(out, outsz, "%s%s%s", dir, sep, name) >= outsz)
           ? -1 : 0;
}

static int
tree_walk_depth(brix_conn *c, const char *path, int depth,
                brix_walk_fn fn, void *u, brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, i;
    int          rc = 0;

    if (brix_dirlist(c, path, 1, &ents, &n, st) != 0) {
        return -1;
    }
    for (i = 0; i < n && rc == 0; i++) {
        char full[XRDC_PATH_MAX];
        if (walk_is_dot(ents[i].name)) {
            continue;
        }
        if (walk_join(path, ents[i].name, full, sizeof(full)) != 0) {
            brix_status_set(st, XRDC_EUSAGE, 0, "walk: path too long under %s", path);
            rc = -1;
            break;
        }
        rc = fn(full, &ents[i], depth, u);
        if (rc == 0 && ents[i].have_stat && (ents[i].st.flags & kXR_isDir)) {
            if (depth + 1 >= BRIX_WALK_MAXDEPTH) {
                brix_status_set(st, XRDC_EUSAGE, 0, "walk: depth cap at %s", full);
                rc = -1;
            } else {
                rc = tree_walk_depth(c, full, depth + 1, fn, u, st);
            }
        }
    }
    free(ents);
    return rc;
}

int
brix_tree_walk(brix_conn *c, const char *path, brix_walk_fn fn, void *u,
               brix_status *st)
{
    return tree_walk_depth(c, path, 0, fn, u, st);
}
```

`client/lib/fs/rmtree.c`:

```c
/* rmtree.c — post-order recursive remote delete (rm -r for root://).
 * WHAT: delete every file, then every directory bottom-up, under `path`,
 *       then `path` itself.
 * WHY:  the wire has no bulk delete; xrdfs rm -r and xrdcp --delete both
 *       need one careful implementation (depth-capped, overflow-checked,
 *       refuses the export root).
 * HOW:  brix_dirlist(want_stat=1); recurse into dirs first, brix_rm files,
 *       brix_rmdir self last. BRIX_RMTREE_DRYRUN reports without deleting. */
#include "brix.h"
#include "brix_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BRIX_RMTREE_MAXDEPTH 64

static int
rmtree_depth(brix_conn *c, const char *path, int depth, unsigned flags,
             brix_rmtree_report report, void *u, brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, i;
    int          rc = 0;

    if (depth >= BRIX_RMTREE_MAXDEPTH) {
        brix_status_set(st, XRDC_EUSAGE, 0, "rmtree: depth cap at %s", path);
        return -1;
    }
    if (brix_dirlist(c, path, 1, &ents, &n, st) != 0) {
        return -1;
    }
    for (i = 0; i < n && rc == 0; i++) {
        char full[XRDC_PATH_MAX];
        size_t dl = strlen(path);
        const char *sep = (dl > 0 && path[dl - 1] == '/') ? "" : "/";
        if (ents[i].name[0] == '.'
            && (ents[i].name[1] == '\0'
                || (ents[i].name[1] == '.' && ents[i].name[2] == '\0'))) {
            continue;
        }
        if ((size_t) snprintf(full, sizeof(full), "%s%s%s", path, sep,
                              ents[i].name) >= sizeof(full)) {
            brix_status_set(st, XRDC_EUSAGE, 0, "rmtree: path too long under %s", path);
            rc = -1;
            break;
        }
        if (ents[i].have_stat && (ents[i].st.flags & kXR_isDir)) {
            rc = rmtree_depth(c, full, depth + 1, flags, report, u, st);
        } else {
            if (report != NULL && report(full, 0, u) != 0) { rc = -1; break; }
            if (!(flags & BRIX_RMTREE_DRYRUN) && brix_rm(c, full, st) != 0) {
                rc = -1;
            }
        }
    }
    free(ents);
    if (rc != 0) {
        return rc;
    }
    if (report != NULL && report(path, 1, u) != 0) {
        return -1;
    }
    if (!(flags & BRIX_RMTREE_DRYRUN) && brix_rmdir(c, path, st) != 0) {
        return -1;
    }
    return 0;
}

int
brix_rmtree(brix_conn *c, const char *path, unsigned flags,
            brix_rmtree_report report, void *u, brix_status *st)
{
    if (path == NULL || path[0] == '\0' || strcmp(path, "/") == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "rmtree: refusing to delete the export root");
        return -1;
    }
    return rmtree_depth(c, path, 0, flags, report, u, st);
}
```

Declare all of the above in `brix_ops.h` next to `brix_rm`/`brix_rmdir` (brix_ops.h:325-328). Add both files to LIB_SRCS.

- [ ] **Step 4: Run tests + build:** `make -C client && make -C client test` → `relsafe_unit: ALL PASS` (walk/rmtree get e2e coverage in Tasks 7/10's fleet sections).
- [ ] **Step 5: Commit** (message `feat(client): lib tree walk, post-order rmtree, shared rel-safety guard`).

---

### Task 5: xrdcp `--dry-run` / `--exclude` / `--include` wiring + e2e harness

**Files:**
- Modify: `client/apps/copy/xrdcp.c` (usage + arg loop + opts fields), `client/apps/copy/xrdcp_transfer.c` (`transfer_one`), `client/lib/xfer/copy_recursive.c` + `client/lib/xfer/copy_internal.h` (rel threading), `client/apps/copy/xrdcp_recursive.c` (web walkers)
- Create: `tests/run_client_features.sh` (repo-root tests/, the e2e harness all later tasks extend)

**Interfaces:**
- Consumes: `brix_copy_filter_match`, opts fields from Task 2.
- Produces: CLI flags `--dry-run`/`-n`, `--exclude PAT` (repeatable), `--include PAT` (repeatable); `copy_tree_download(c, rpath, lpath, rel, o, st)` and `copy_tree_upload(c, lpath, rpath, rel, o, st)` — the new `const char *rel` param ("" at the root) that Tasks 6–8 also use.

- [ ] **Step 1: e2e harness skeleton** `tests/run_client_features.sh` (executable):

```bash
#!/usr/bin/env bash
# run_client_features.sh — e2e checks for the 2026-07-05 client feature set.
# Local-only sections always run; fleet sections auto-skip when no server on
# ${XRD_TEST_URL:-root://localhost:11094} answers.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/client/bin"
URL="${XRD_TEST_URL:-root://localhost:11094}"
WORK="$(mktemp -d /tmp/client-features.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
have_fleet() { "$BIN/wait41" "$URL" 2>/dev/null >/dev/null; }

section_dryrun_filters() {
  echo "== dry-run + filters (local) =="
  mkdir -p "$WORK/src/sub" "$WORK/dst"
  echo A >"$WORK/src/a.root"; echo B >"$WORK/src/b.log"; echo C >"$WORK/src/sub/c.root"
  # dry-run copies nothing
  "$BIN/xrdcp" --dry-run "$WORK/src/a.root" "$WORK/dst/a.root" >/dev/null
  check "dry-run leaves dst absent" '[ ! -e "$WORK/dst/a.root" ]'
  # exclude filters the .log
  "$BIN/xrdcp" -r --exclude '*.log' "$WORK/src/" "$WORK/dst" 2>/dev/null
  check "exclude: .root copied"    '[ -e "$WORK/dst/a.root" ] && [ -e "$WORK/dst/sub/c.root" ]'
  check "exclude: .log filtered"   '[ ! -e "$WORK/dst/b.log" ]'
  # include whitelist
  rm -rf "$WORK/dst"; mkdir -p "$WORK/dst"
  "$BIN/xrdcp" -r --include '*.log' "$WORK/src/" "$WORK/dst" 2>/dev/null
  check "include: only .log copied" '[ -e "$WORK/dst/b.log" ] && [ ! -e "$WORK/dst/a.root" ]'
  # security: exclude beats include
  rm -rf "$WORK/dst"; mkdir -p "$WORK/dst"
  "$BIN/xrdcp" -r --include '*' --exclude 'a.*' "$WORK/src/" "$WORK/dst" 2>/dev/null
  check "exclude beats include" '[ ! -e "$WORK/dst/a.root" ] && [ -e "$WORK/dst/b.log" ]'
}

main() {
  section_dryrun_filters
  # (later tasks append sections + calls here)
  echo "client-features: $PASS pass, $FAIL fail"
  [ "$FAIL" -eq 0 ]
}
main "$@"
```

NOTE: if `xrdcp -r local/ localdst` turns out unsupported (`brix_copy` handles root↔local trees only — check `lib/xfer/copy.c:237-300`), route the local sections through the fleet instead: guard them with `have_fleet` and use `$URL//tmp/...` as one side. Determine this empirically in Step 5 and adjust the script — the assertions stay the same.

- [ ] **Step 2: Parse flags in `apps/copy/xrdcp.c`.** In `main` add locals near the other lists (line ~331): `char **excl = NULL, **incl = NULL; size_t nexcl = 0, exclcap = 0, nincl = 0, inclcap = 0;`. In the option loop (after `--sync`, line ~377):

```c
else if (strcmp(a, "--dry-run") == 0 || strcmp(a, "-n") == 0) { opts.dry_run = 1; }
else if (strcmp(a, "--exclude") == 0 && i + 1 < (size_t) argc) {
    if (str_append(&excl, &nexcl, &exclcap, argv[++i]) != 0) { oom = 1; }
}
else if (strcmp(a, "--include") == 0 && i + 1 < (size_t) argc) {
    if (str_append(&incl, &nincl, &inclcap, argv[++i]) != 0) { oom = 1; }
}
```

After the loop (next to the `sync_mode` force block, line ~433):

```c
opts.excludes   = (const char *const *) excl;
opts.n_excludes = nexcl;
opts.includes   = (const char *const *) incl;
opts.n_includes = nincl;
```

Add `str_free(excl, nexcl); str_free(incl, nincl);` beside every existing `str_free(pos, npos)` cleanup (7 return paths in main — grep `str_free(pos`). Add the three flags to `usage()`:

```
"  -n, --dry-run  print what would be transferred/deleted; move no bytes\n"
"  --exclude <pat> skip files matching this fnmatch pattern (repeatable)\n"
"  --include <pat> only transfer files matching a pattern (repeatable)\n"
```

- [ ] **Step 3: `transfer_one` policy** (`apps/copy/xrdcp_transfer.c:90-102`) — replace with:

```c
/* Transfer src -> dst honoring filters, --sync and --dry-run.
 * Returns 0 (copied), 1 (skipped), or -1 (failed, st set). */
int
transfer_one(const char *src, const char *dst, const brix_copy_opts *o,
             const brix_opts *co, int retries, int sync_mode, brix_status *st)
{
    char base[XRDC_NAME_MAX];

    path_basename(src, base, sizeof(base));
    if (!brix_copy_filter_match(o, base)) {
        return 1;                                   /* filtered — like a skip */
    }
    if (sync_mode || o->sync) {
        long long ssz = 0, dsz = 0;
        if (entry_size(src, co, &ssz) == 0 && entry_size(dst, co, &dsz) == 0
            && ssz == dsz) {
            return 1;   /* up-to-date — skip (Task 6 upgrades this test) */
        }
    }
    if (o->dry_run) {
        printf("[dry-run] copy %s -> %s\n", src, dst);
        return 0;
    }
    return (copy_one_with_retry(src, dst, o, co, retries, st) == 0) ? 0 : -1;
}
```

- [ ] **Step 4: Thread `rel` through the lib tree walkers.** In `lib/xfer/copy_internal.h` change the two decls to
`int copy_tree_download(brix_conn *c, const char *rpath, const char *lpath, const char *rel, const brix_copy_opts *o, brix_status *st);` (same for `copy_tree_upload` with `lpath, rpath, rel`). In `lib/xfer/copy_recursive.c`:
  - `copy_recursive()` (lines 213–218): pass `""` as `rel` in both calls.
  - `copy_tree_download` (lines 48–98): add the param; guard the mkdir with `if (!o->dry_run && local_mkdirs(...) != 0)`; inside the loop after the dot-skip build the child rel:

```c
        char relc[XRDC_PATH_MAX];
        if ((size_t) snprintf(relc, sizeof(relc), "%s%s%s",
                              rel, rel[0] ? "/" : "", ents[i].name) >= sizeof(relc)) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "recursive copy: rel path too long under %s", rpath);
            free(ents);
            return -1;
        }
```

    recurse with `copy_tree_download(c, rc, lc, relc, o, st)`. In the file branch, before `copy_one_r2l`:

```c
            if (!brix_copy_filter_match(o, relc)) {
                continue;
            }
            if (o->dry_run) {
                printf("[dry-run] copy %s -> %s\n", rc, lc);
                continue;
            }
```

  - `copy_tree_upload` (lines 102–150): same pattern — guard `brix_mkdir` with `!o->dry_run`, build `relc` from `de->d_name`, filter + dry-run print before `copy_one_l2r`, recurse with `relc`.
- [ ] **Step 5: Web recursive paths.** In `apps/copy/xrdcp_recursive.c`: at the top of `recursive_place()` (lines 142–181, it receives `rel`) add the same filter + dry-run guard (`return 0` counts as handled for dry-run; `return 1`-equivalent skip for filtered — read its return convention first and match it). In `web_upload_walk()` (lines 410–488) add the guard in the file branch using its rel path variable. Build: `make -C client`.
- [ ] **Step 6: Run e2e:** `tests/run_client_features.sh` → all dry-run/filter checks pass (adjust the local-vs-fleet routing per the Step 1 NOTE if needed). Run `make -C client test` (no regressions).
- [ ] **Step 7: Commit** (add the five modified files + the new script; message `feat(xrdcp): --dry-run, --exclude/--include across single/batch/recursive paths`).

---

### Task 6: xrdcp `--sync-check size|mtime|cksum` + recursive sync

**Files:**
- Modify: `client/apps/copy/xrdcp.c` (flag), `client/apps/copy/xrdcp_transfer.c` (`entry_size`→`entry_meta`, cksum compare, `transfer_one`), `client/apps/copy/xrdcp_internal.h` (decls), `client/lib/xfer/copy_recursive.c` (sync skip inside walkers), `tests/run_client_features.sh`

**Interfaces:**
- Consumes: `brix_sync_should_skip`, `XRDC_SYNC_*`, `brix_query_cksum`, `brix_cksum_fd`, `brix_cksum_algo_parse`.
- Produces: `int entry_meta(const char *url, const brix_opts *co, long long *size, long long *mtime)` (replaces `entry_size`; update xrdcp_internal.h decl and the sole caller), `static int sync_cksum_equal(const char *src, const char *dst, const char *algo, const brix_opts *co)`.

- [ ] **Step 1: Flag parsing** (xrdcp.c, after `--sync`):

```c
else if (strcmp(a, "--sync-check") == 0 && i + 1 < (size_t) argc) {
    const char *m = argv[++i];
    sync_mode = 1;
    if (strcmp(m, "size") == 0)       { opts.sync_cmp = XRDC_SYNC_SIZE; }
    else if (strcmp(m, "mtime") == 0) { opts.sync_cmp = XRDC_SYNC_MTIME; }
    else if (strncmp(m, "cksum", 5) == 0) {
        opts.sync_cmp = XRDC_SYNC_CKSUM;
        opts.sync_cksum_algo = (m[5] == ':' && m[6] != '\0') ? m + 6 : "adler32";
    } else {
        fprintf(stderr, "xrdcp: --sync-check needs size|mtime|cksum[:algo]\n");
        usage();
        return 50;
    }
}
```

After the loop, next to the existing `if (sync_mode) { opts.force = 1; }` add `opts.sync = sync_mode;`. usage() line: `"  --sync-check <m>  --sync comparison: size (default) | mtime | cksum[:algo]\n"`.

- [ ] **Step 2: `entry_meta`** — rename `entry_size` (xrdcp_transfer.c:56-85) and extend: local branch also sets `*mtime = (long long) sb.st_mtime;`; root branch `*mtime = (long long) si.mtime;`. Keep the -1-on-web behavior.
- [ ] **Step 3: `sync_cksum_equal`** in xrdcp_transfer.c (static, above transfer_one):

```c
/* 1 = both ends have the same <algo> digest; 0 = differ or undeterminable
 * (undeterminable must copy — a sync that silently skips on error is data loss). */
static int
sync_cksum_equal(const char *src, const char *dst, const char *algo,
                 const brix_opts *co)
{
    char shex[132], dhex[132];

    if (entry_cksum(src, co, algo, shex, sizeof(shex)) != 0
        || entry_cksum(dst, co, algo, dhex, sizeof(dhex)) != 0) {
        return 0;
    }
    return strcasecmp(shex, dhex) == 0;
}
```

with the per-endpoint helper:

```c
/* Digest of a file at `url` (local: computed; root://: server kXR_Qcksum). 0/-1. */
static int
entry_cksum(const char *url, const brix_opts *co, const char *algo,
            char *hex, size_t hexsz)
{
    brix_url    u;
    brix_status st;

    brix_status_clear(&st);
    if (brix_is_web_url(url) || brix_url_parse(url, &u, &st) != 0) {
        return -1;
    }
    if (u.scheme == XRDC_SCHEME_LOCAL) {
        brix_cksum_algo a;
        int fd, rc;
        if (brix_cksum_algo_parse(algo, &a) != 0) { return -1; }
        fd = open(u.path, O_RDONLY);
        if (fd < 0) { return -1; }
        rc = brix_cksum_fd(fd, a, hex, hexsz, &st);
        close(fd);
        return rc;
    }
    if (u.scheme == XRDC_SCHEME_ROOT || u.scheme == XRDC_SCHEME_ROOTS) {
        brix_conn c;
        int rc;
        if (brix_connect(&c, &u, co, &st) != 0) { return -1; }
        rc = brix_query_cksum(&c, u.path, algo, hex, hexsz, &st);
        brix_close(&c);
        return rc;
    }
    return -1;
}
```

- [ ] **Step 4: Upgrade `transfer_one`'s sync block** (replaces the Task 5 interim):

```c
    if (sync_mode || o->sync) {
        long long ssz = 0, smt = 0, dsz = 0, dmt = 0;
        if (entry_meta(src, co, &ssz, &smt) == 0
            && entry_meta(dst, co, &dsz, &dmt) == 0
            && brix_sync_should_skip(o->sync_cmp, ssz, smt, dsz, dmt)) {
            if (o->sync_cmp != XRDC_SYNC_CKSUM
                || sync_cksum_equal(src, dst,
                       o->sync_cksum_algo ? o->sync_cksum_algo : "adler32", co)) {
                return 1;   /* up-to-date — skip */
            }
        }
    }
```

- [ ] **Step 5: Recursive sync skip.** In `copy_tree_download`'s file branch (after the filter/dry-run guards from Task 5), when `o->sync`: `stat(lc, &sb)` — if it exists as a regular file and `brix_sync_should_skip(o->sync_cmp, ents[i].st.size, ents[i].st.mtime, sb.st_size, sb.st_mtime)` (CKSUM mode: additionally `brix_query_cksum(c, rc, ...)` vs local `brix_cksum_fd` — same pattern as entry_cksum but reusing the open conn `c`), `continue`. Mirror in `copy_tree_upload` using `brix_stat(c, rc, &si, &mst)` vs local `sb`.
- [ ] **Step 6: e2e section** appended to run_client_features.sh: build src/dst where dst file has same size but is stale/different content; assert `--sync` (size) skips it, `--sync-check cksum` recopies it (fleet-gated if cksum needs a server on one side; local↔local both-sides-local works with `brix_cksum_fd` only — use local); `--sync-check bogus` exits 50 (error case); a src newer-mtime same-size file recopies under `--sync-check mtime`.
- [ ] **Step 7: Build + full test run; commit** (message `feat(xrdcp): --sync-check size|mtime|cksum with recursive sync support`).

---

### Task 7: xrdcp `--delete` (mirror-delete for recursive sync)

**Files:**
- Modify: `client/apps/copy/xrdcp.c` (flag + validation), `client/lib/xfer/copy_recursive.c` (mirror pass + `local_rmtree`), `tests/run_client_features.sh`

**Interfaces:**
- Consumes: `brix_rmtree` (Task 4), `brix_copy_filter_match`, `o->sync_delete`, `o->dry_run`.

- [ ] **Step 1: Flag + guard** (xrdcp.c): parse `else if (strcmp(a, "--delete") == 0) { opts.sync_delete = 1; }`; after arg parsing validate:

```c
    if (opts.sync_delete && !(opts.recursive && sync_mode)) {
        fprintf(stderr, "xrdcp: --delete requires -r and --sync\n");
        return 50;
    }
```

usage(): `"  --delete       with -r --sync: delete dest entries missing from the source\n"`.

- [ ] **Step 2: `local_rmtree`** (static in copy_recursive.c — lstat-based, never follows symlinks):

```c
/* Recursively remove a LOCAL tree (mirror-delete). lstat + no symlink follow so
 * a link inside the dest can never delete data outside it. 0/-1 (errno). */
static int
local_rmtree(const char *path)
{
    struct stat sb;

    if (lstat(path, &sb) != 0) {
        return -1;
    }
    if (S_ISDIR(sb.st_mode)) {
        DIR           *d = opendir(path);
        struct dirent *de;
        if (d == NULL) { return -1; }
        while ((de = readdir(d)) != NULL) {
            char child[XRDC_PATH_MAX];
            if (de->d_name[0] == '.'
                && (de->d_name[1] == '\0'
                    || (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
                continue;
            }
            if ((size_t) snprintf(child, sizeof(child), "%s/%s", path,
                                  de->d_name) >= sizeof(child)) {
                closedir(d);
                errno = ENAMETOOLONG;
                return -1;
            }
            if (local_rmtree(child) != 0) { closedir(d); return -1; }
        }
        closedir(d);
        return rmdir(path);
    }
    return unlink(path);
}
```

- [ ] **Step 3: Mirror pass in `copy_tree_download`** — after the entry loop (before `free(ents)` is too early; do it after the loop while `ents` is still live): when `o->sync_delete`, `opendir(lpath)`, for each local name not present in `ents[]` (linear scan by `strcmp` on names) and whose relc passes `brix_copy_filter_match(o, relc)` (excluded paths are OUTSIDE the sync set — never delete them):

```c
                if (o->dry_run) {
                    printf("[dry-run] delete %s\n", lchild);
                } else if (local_rmtree(lchild) != 0) {
                    fprintf(stderr, "xrdcp: --delete: cannot remove %s: %s\n",
                            lchild, strerror(errno));
                }
```

  Mirror in `copy_tree_upload`: `brix_dirlist(c, rpath, 1, ...)` after the upload loop; extras → `brix_rmtree(c, full, o->dry_run ? BRIX_RMTREE_DRYRUN : 0, NULL, NULL, &dst_st)` for dirs / `brix_rm` for files, same dry-run print. Extract each mirror pass into its own static helper (`mirror_delete_local(...)`, `mirror_delete_remote(...)`) to keep the walkers readable (no-goto/small-functions rule).
- [ ] **Step 4: e2e section** (fleet-gated): upload tree with extra file pre-seeded on dst; `xrdcp -r --sync --delete` removes the extra; with `--exclude` covering the extra it survives (security case); `--delete` without `--sync` exits 50 (error case); `--dry-run --delete` prints but deletes nothing.
- [ ] **Step 5: Build, run `tests/run_client_features.sh` + `make -C client test`; commit** (`feat(xrdcp): --delete mirror semantics for recursive sync`).

---

### Task 8: xrdcp `--remove-source` (move semantics)

**Files:**
- Modify: `client/apps/copy/xrdcp.c` (flag + web-source guard), `client/apps/copy/xrdcp_transfer.c` (`remove_source_entry` + hook in `transfer_one`), `client/lib/xfer/copy_recursive.c` (per-file + post-order dir removal), `tests/run_client_features.sh`

- [ ] **Step 1: Flag + guard** (xrdcp.c): parse `--remove-source` → `opts.remove_source = 1`. After source expansion (line ~490) validate:

```c
    if (opts.remove_source) {
        for (i = 0; i < nexp; i++) {
            if (brix_is_web_url(exp[i])) {
                fprintf(stderr, "xrdcp: --remove-source supports local and "
                                "root:// sources only\n");
                /* free lists as the surrounding error paths do */
                return 50;
            }
        }
    }
```

usage(): `"  --remove-source  delete each source after its transfer succeeds (local/root://)\n"`.

- [ ] **Step 2: `remove_source_entry`** (static in xrdcp_transfer.c):

```c
/* Delete the source of a successfully-transferred file. Local => unlink;
 * root:// => connect + brix_rm. Called only after the copy (including any
 * --cksum/--verify check inside brix_copy) reported success. 0/-1. */
static int
remove_source_entry(const char *url, const brix_opts *co)
{
    brix_url    u;
    brix_status st;

    brix_status_clear(&st);
    if (brix_url_parse(url, &u, &st) != 0) {
        return -1;
    }
    if (u.scheme == XRDC_SCHEME_LOCAL) {
        return unlink(u.path);
    }
    if (u.scheme == XRDC_SCHEME_ROOT || u.scheme == XRDC_SCHEME_ROOTS) {
        brix_conn c;
        int       rc;
        if (brix_connect(&c, &u, co, &st) != 0) { return -1; }
        rc = brix_rm(&c, u.path, &st);
        brix_close(&c);
        return rc;
    }
    return -1;
}
```

Hook at the end of `transfer_one` (replace the final return):

```c
    if (copy_one_with_retry(src, dst, o, co, retries, st) != 0) {
        return -1;
    }
    if (o->remove_source && remove_source_entry(src, co) != 0) {
        fprintf(stderr, "xrdcp: warning: transferred but could not remove "
                        "source %s\n", src);
    }
    return 0;
```

and in the dry-run branch print `"[dry-run] copy %s -> %s%s\n", src, dst, o->remove_source ? " (then remove source)" : ""`.

- [ ] **Step 3: Recursive removal.** `copy_tree_download` file branch: after successful `copy_one_r2l`, `if (o->remove_source && !o->dry_run) { brix_status rst; brix_status_clear(&rst); (void) brix_rm(c, rc, &rst); }`; after a fully-successful directory recursion, best-effort `brix_rmdir(c, rc, &rst)`. `copy_tree_upload`: `unlink(lc)` per file, best-effort `rmdir(lc)` per dir. The source ROOT dir is removed best-effort in `copy_recursive()` after a rc==0 walk. Failures warn once to stderr; they never fail the copy.
- [ ] **Step 4: e2e section:** local→local file move (src gone, dst byte-exact); `--remove-source` with an s3:// source exits 50 (error/security); `--dry-run --remove-source` leaves the source intact.
- [ ] **Step 5: Build + tests + commit** (`feat(xrdcp): --remove-source move semantics`).

---

### Task 9: xrdcp `--journal` / `--resume`

**Files:**
- Modify: `client/apps/copy/xrdcp.c` (flags + journal lifecycle), `client/apps/copy/xrdcp_transfer.c` (batch integration), `client/apps/copy/xrdcp_internal.h` (`batch_ctx` field + decls), `tests/run_client_features.sh`

**Interfaces:**
- Consumes: `brix_journal_*` (Task 3).
- Produces: `batch_ctx` gains `brix_journal *jrn;` (NULL = disabled); `batch_copy_one` is untouched — journal checks live in the two call sites (sequential loop + `batch_worker`).

- [ ] **Step 1: Flags** (xrdcp.c): `--journal <path>` → `const char *journal_path = NULL;`; `--resume` → `int resume = 0;`. After manifest handling (line ~458):

```c
    if (resume && journal_path == NULL) {
        if (from == NULL || strcmp(from, "-") == 0) {
            fprintf(stderr, "xrdcp: --resume needs --from <file> (not stdin) "
                            "or an explicit --journal <path>\n");
            return 50;
        }
        static char jbuf[XRDC_PATH_MAX];
        if ((size_t) snprintf(jbuf, sizeof(jbuf), "%s.journal", from)
                >= sizeof(jbuf)) {
            fprintf(stderr, "xrdcp: journal path too long\n");
            return 50;
        }
        journal_path = jbuf;
    }
```

Open it just before the batch branch (`brix_journal *jrn = NULL;` at top of main): `if (journal_path != NULL) { jrn = brix_journal_open(journal_path, &st); if (jrn == NULL) { fprintf(stderr, "xrdcp: %s\n", st.msg); ...free+return 51; } }`. `brix_journal_close(jrn)` beside `brix_cred_store_free` on every exit after that point. usage(): `"  --journal <p>  record completed transfers; skip them on the next run\n"` and `"  --resume       shorthand: --journal <manifest>.journal (needs --from)\n"`.

- [ ] **Step 2: Batch integration.** Sequential loop (xrdcp.c:623-645): before `batch_copy_one`:

```c
                if (jrn != NULL && brix_journal_has(jrn, exp[i])) {
                    skip++;
                    continue;
                }
```

after `one == 0`: `if (jrn != NULL) { (void) brix_journal_mark(jrn, exp[i]); }`. `batch_parallel` gains a `brix_journal *jrn` parameter stored in `batch_ctx`; `batch_worker` applies the same has/mark around its `batch_copy_one` call (mark under no extra lock — the journal is internally locked). Journal marking is skipped when `o->dry_run` (a dry run completes nothing).

- [ ] **Step 3: e2e section** (local, no fleet): manifest of 3 files → run with `--journal j` (3 copied, journal has 3 `ok` lines); touch a 4th file + append to manifest → rerun (output shows exactly 1 copied, 3 skipped); corrupt journal line prepended → rerun still works (security); `--resume` without `--from` exits 50 (error).
- [ ] **Step 4: Build + tests + commit** (`feat(xrdcp): resumable batch transfers via completion journal`).

---

### Task 10: xrdfs `rm -r`

**Files:**
- Modify: `client/apps/fs/xrdfs_meta.c` (`do_rm`, lines 140-154), `client/apps/fs/xrdfs.c:9-47` (help row → `"rm [-r] [-v] <path>"`), `tests/run_client_features.sh`

**Interfaces:**
- Consumes: `brix_rmtree`, `brix_stat` (kXR_isDir), `build_path`, `brix_shellcode`, `brix_cred_hint_for_status`.

- [ ] **Step 1: Rewrite `do_rm`:**

```c
/* rm_report — per-entry printer for rm -r -v. Never aborts the delete. */
static int
rm_report(const char *path, int is_dir, void *u)
{
    (void) u;
    printf("removed %s%s\n", is_dir ? "dir  " : "file ", path);
    return 0;
}

/* WHAT: rm [-r] [-v] <path> — delete a file, or a whole tree with -r.
 * WHY:  rmdir only takes empty dirs; users cleaning a tree need one command.
 * HOW:  -r stats the target; directories go through brix_rmtree (post-order,
 *       depth-capped). The resolved export root "/" is always refused. */
int
do_rm(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    int         recursive = 0, verbose = 0, i;
    const char *arg = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "-R") == 0) {
            recursive = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else {
            arg = argv[i];
        }
    }
    if (arg == NULL) {
        fprintf(stderr, "usage: rm [-r] [-v] <path>\n");
        return 50;
    }
    build_path(cwd, arg, path, sizeof(path));
    brix_status_clear(&st);
    if (recursive) {
        brix_statinfo si;
        if (strcmp(path, "/") == 0) {
            fprintf(stderr, "xrdfs: rm -r: refusing to delete the export root\n");
            return 50;
        }
        if (brix_stat(c, path, &si, &st) != 0) {
            fprintf(stderr, "xrdfs: rm %s: %s\n", path, st.msg);
            return brix_shellcode(&st);
        }
        if (si.flags & kXR_isDir) {
            if (brix_rmtree(c, path, 0, verbose ? rm_report : NULL, NULL,
                            &st) != 0) {
                fprintf(stderr, "xrdfs: rm -r %s: %s\n", path, st.msg);
                brix_cred_hint_for_status(&st, 1, stderr);
                return brix_shellcode(&st);
            }
            return 0;
        }
        /* -r on a plain file falls through to the single unlink */
    }
    if (brix_rm(c, path, &st) != 0) {
        fprintf(stderr, "xrdfs: rm %s: %s\n", path, st.msg);
        brix_cred_hint_for_status(&st, 1, stderr);
        return brix_shellcode(&st);
    }
    return 0;
}
```

- [ ] **Step 2: e2e section** (fleet-gated): build `d/a d/sub/b` via `xrdfs mkdir -p` + `upload`; `rm -r d` → `stat d` fails (success); `rm -r /` → exit 50, root intact (security); `rm -r missing` → nonzero (error); `rm -r <file>` deletes the file.
- [ ] **Step 3: Build + tests + commit** (`feat(xrdfs): rm -r recursive delete with export-root guard`).

---

### Task 11: xrdfs `--json` for stat / ls / du

**Files:**
- Modify: `client/apps/fs/xrdfs_fmt.c` (+`json_statinfo`), `client/apps/fs/xrdfs_internal.h` (decl), `client/apps/fs/xrdfs_meta.c` (`do_stat`), `client/apps/fs/xrdfs_walk.c` (`do_ls`, `do_du`), `client/apps/fs/xrdfs.c` (help rows), `tests/run_client_features.sh`

**Interfaces:**
- Consumes: `brix_json_fputs`/`brix_json_kv_*` (Task 1), `print_statinfo` fields (`brix_statinfo`: id/size/mtime/ctime/atime/flags/mode/owner/group/have_ext — xrdfs_fmt.c:80-100).

- [ ] **Step 1:** `json_statinfo` in xrdfs_fmt.c:

```c
/* One stat result as a single-line JSON object (xrdfs --json). */
void
json_statinfo(const char *path, const brix_statinfo *si)
{
    fputc('{', stdout);
    brix_json_kv_str(stdout, "path", path, 1);
    brix_json_kv_ll(stdout, "size", (long long) si->size, 1);
    brix_json_kv_ll(stdout, "mtime", (long long) si->mtime, 1);
    brix_json_kv_ll(stdout, "flags", (long long) si->flags, 1);
    brix_json_kv_bool(stdout, "is_dir", (si->flags & kXR_isDir) != 0,
                      si->have_ext);
    if (si->have_ext) {
        brix_json_kv_ll(stdout, "mode", (long long) (si->mode & 07777), 1);
        brix_json_kv_str(stdout, "owner", si->owner, 1);
        brix_json_kv_str(stdout, "group", si->group, 0);
    }
    fputs("}\n", stdout);
}
```

- [ ] **Step 2:** Each of `do_stat`/`do_ls`/`do_du` parses `-j`/`--json` in its existing flag loop (pattern: `do_head`, xrdfs_data.c:132-168). `do_stat -j` calls `json_statinfo` instead of `print_statinfo`. `do_ls -j` forces `want_stat=1` and prints a JSON array — `[` then per entry `{"name":…,"size":…,"mtime":…,"is_dir":…}` comma-separated, `]\n` (emit into stdout directly; commas via a `first` flag). `do_du -j` prints `{"path":…,"bytes":…,"files":…,"dirs":…}` from its `du_acc`. Update the three help rows in `COMMANDS[]` (e.g. `"ls [-l] [-R] [-h] [-j] [path]"`).
- [ ] **Step 3: e2e section** (fleet-gated): `xrdfs $HOSTPORT stat -j /path | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["is_dir"] in (True,False)'`; same `json.loads` gate for `ls -j` and `du -j`; a filename containing `"` quote uploaded then listed — `json.loads` must still parse (security); `stat -j missing` → nonzero exit, NO partial JSON on stdout (error).
- [ ] **Step 4: Build + tests + commit** (`feat(xrdfs): --json output for stat/ls/du`).

---

### Task 12: xrdfs `cat -z <codec>` (inline decompression)

**Files:**
- Modify: `client/apps/fs/xrdfs_data.c` (`stream_file` + `do_cat`; other `stream_file` callers pass NULL), `client/apps/fs/xrdfs_internal.h` (decl), `client/apps/fs/xrdfs.c` (help row), `tests/run_client_features.sh`

- [ ] **Step 1:** Read `lib/xfer/copy_local.c:115-140` to confirm exactly how the `"xrootd.compress=%s"` opaque string is passed into the read-open (with or without a leading `?`). Mirror that form.
- [ ] **Step 2:** `stream_file` (xrdfs_data.c:13-58) gains `const char *opaque` after `path`, forwarded as `brix_rfile_open_read(c, path, opaque, 0, -1, &rf, st)`. Update ALL callers (`grep -n stream_file client/apps/fs/*.c`) to pass `NULL`, except `do_cat`.
- [ ] **Step 3:** `do_cat` parses `-z <codec>`:

```c
    /* -z <codec>: ask the server for inline read compression (gzip|deflate|
     * zstd|br|xz|bzip2). Transparent: brix_file_read inflates each frame; a
     * server without support ignores the request and streams plaintext. */
```

builds `char opq[80]; snprintf(opq, sizeof(opq), "<form from Step 1>", codec);` and passes it. Reject codec strings longer than 16 chars or containing `&`/`?`/`=` (opaque injection — security guard) with usage exit 50. Help row: `"cat [-z codec] <path>"`.
- [ ] **Step 4: e2e section** (fleet-gated): `xrdfs ... cat -z gzip /f > out` byte-identical to `cat /f` (works whether or not the server negotiates the codec — that IS the transparency contract); `cat -z 'gz&evil=1'` exits 50 (security); `cat -z gzip missing` nonzero (error).
- [ ] **Step 5: Build + tests + commit** (`feat(xrdfs): cat -z requests inline read compression`).

---

### Task 13: xrdfs `tail -f` (resilient follow)

**Files:**
- Modify: `client/apps/fs/xrdfs_data.c` (`tail_follow` + `do_tail`), `client/apps/fs/xrdfs.c` (help row), `tests/run_client_features.sh`

- [ ] **Step 1:** Read the existing `do_tail` in xrdfs_data.c (grep `do_tail`) to find where it finishes printing the last N lines and what offset it ends at. Add:

```c
/* WHAT: follow mode for tail (-f): poll the file size and stream appended
 * bytes until interrupted.
 * WHY:  log-following over WAN is the resilient-handle showcase — the rfile
 *       rides out connection severs (reconnect+reopen+resume) transparently.
 * HOW:  brix_stat once per second; new bytes pread through one long-lived
 *       brix_rfile; a shrink (truncate/rotate) resets to the new EOF. */
static int
tail_follow(brix_conn *c, const char *path, int64_t start_off, brix_status *st)
{
    brix_rfile rf;
    uint8_t   *buf;
    int64_t    off = start_off;

    if (brix_rfile_open_read(c, path, NULL, 0, -1, &rf, st) != 0) {
        return -1;
    }
    buf = (uint8_t *) malloc(1 << 20);
    if (buf == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        brix_rfile_close(&rf, st);
        return -1;
    }
    for (;;) {
        brix_statinfo   si;
        struct timespec ts = { 1, 0 };
        if (brix_stat(c, path, &si, st) != 0) {
            break;                       /* file gone / conn dead beyond window */
        }
        if ((int64_t) si.size < off) {
            fprintf(stderr, "xrdfs: tail: %s truncated, following new end\n", path);
            off = (int64_t) si.size;
        }
        while (off < (int64_t) si.size) {
            size_t  want = (size_t) ((si.size - off) < (1 << 20)
                                     ? (si.size - off) : (1 << 20));
            ssize_t n = brix_rfile_pread(&rf, off, buf, want, st);
            if (n <= 0) { break; }
            fwrite(buf, 1, (size_t) n, stdout);
            off += n;
        }
        fflush(stdout);
        nanosleep(&ts, NULL);
    }
    free(buf);
    {
        brix_status tw;
        brix_status_clear(&tw);
        brix_rfile_close(&rf, &tw);
    }
    return -1;   /* only reachable on error; SIGINT kills the process */
}
```

`do_tail` parses `-f`; after printing the initial lines it calls `tail_follow(c, path, <size at start>, &st)`. Help row: `"tail [-c BYTES] [-n LINES] [-f] <path>"`.
- [ ] **Step 2: e2e section** (fleet-gated): create file; `timeout 5 xrdfs $HOSTPORT tail -f /f > cap &`; append via `xrdcp -f`; wait; assert cap contains appended text (success); `tail -f missing` exits nonzero fast (error); truncate the file mid-follow → process keeps running and reports "truncated" on stderr (resilience case).
- [ ] **Step 3: Build + tests + commit** (`feat(xrdfs): tail -f resilient follow mode`).

---

### Task 14: xrdcksum `tree` + `check` (recursive checksum audit)

**Files:**
- Create: `client/lib/protocols/shared/cksum_manifest.c` (+ decls in brix_ops.h), `client/apps/cksum/xrdcktree.c`
- Modify: `client/apps/cksum/xrdcksum.c:32-94` (register `tree`/`check` subcommands + usage), `client/Makefile` (LIB_SRCS, `xrdcksum_OBJS`, CLIENT_UNIT_TESTS)
- Test: `client/tests/c/ckmanifest_unit.c`, e2e section

**Interfaces:**
- Produces: `int brix_ckmf_parse_line(const char *line, char *hex, size_t hexsz, char *rel, size_t relsz)` — parses `"<hex>  <rel>\n"` (two spaces, sha256sum-style); returns 0, or -1 for malformed/oversized/`brix_rel_is_unsafe(rel)`. App entry points `int brix_xrdcktree_main(int argc, char **argv)` / `int brix_xrdckcheck_main(int argc, char **argv)` (declared in a small `apps/cksum/xrdcksum_internal.h` if one exists, else prototyped in xrdcksum.c — match how `brix_xrdckverify_main` is declared today, see xrdcksum.c:51-70).

- [ ] **Step 1: Failing unit test** `client/tests/c/ckmanifest_unit.c`:

```c
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "brix.h"
#include "brix_ops.h"

int main(void)
{
    char hex[132], rel[4096];
    /* success */
    assert(brix_ckmf_parse_line("03e51f2a  sub/dir/f.root\n",
                                hex, sizeof(hex), rel, sizeof(rel)) == 0);
    assert(strcmp(hex, "03e51f2a") == 0 && strcmp(rel, "sub/dir/f.root") == 0);
    /* error: malformed lines */
    assert(brix_ckmf_parse_line("", hex, sizeof(hex), rel, sizeof(rel)) == -1);
    assert(brix_ckmf_parse_line("deadbeef-no-separator", hex, sizeof(hex),
                                rel, sizeof(rel)) == -1);
    assert(brix_ckmf_parse_line("nothex!!  f\n", hex, sizeof(hex),
                                rel, sizeof(rel)) == -1);
    /* security-negative: escaping rel paths are rejected */
    assert(brix_ckmf_parse_line("03e51f2a  ../../etc/passwd\n", hex,
                                sizeof(hex), rel, sizeof(rel)) == -1);
    assert(brix_ckmf_parse_line("03e51f2a  /abs/path\n", hex, sizeof(hex),
                                rel, sizeof(rel)) == -1);
    printf("ckmanifest_unit: ALL PASS\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify failure**, then implement `cksum_manifest.c`:

```c
/* cksum_manifest.c — parse/format the tree-audit manifest line format:
 * "<hex>  <rel>\n" (two spaces — sha256sum -c compatible). rel is validated
 * with brix_rel_is_unsafe: a hostile manifest must never direct reads or
 * comparisons outside the audit root. */
#include "brix.h"
#include "brix_ops.h"
#include <ctype.h>
#include <string.h>

int
brix_ckmf_parse_line(const char *line, char *hex, size_t hexsz,
                     char *rel, size_t relsz)
{
    const char *sep, *r;
    size_t      hl, rl;

    if (line == NULL) { return -1; }
    sep = strstr(line, "  ");
    if (sep == NULL || sep == line) { return -1; }
    hl = (size_t) (sep - line);
    if (hl >= hexsz) { return -1; }
    for (r = line; r < sep; r++) {
        if (!isxdigit((unsigned char) *r)) { return -1; }
    }
    memcpy(hex, line, hl);
    hex[hl] = '\0';
    r = sep + 2;
    rl = strlen(r);
    while (rl > 0 && (r[rl - 1] == '\n' || r[rl - 1] == '\r')) { rl--; }
    if (rl == 0 || rl >= relsz) { return -1; }
    memcpy(rel, r, rl);
    rel[rl] = '\0';
    return brix_rel_is_unsafe(rel) ? -1 : 0;
}
```

- [ ] **Step 3: Implement `apps/cksum/xrdcktree.c`.** `brix_xrdcktree_main`: args `<root> [--algo NAME] [-o FILE]` (default algo `adler32`, output stdout).
  - Local root (no `://` and `stat` says dir): recursive `opendir`/`readdir` walk (lstat, skip symlinks, same dot-skip and overflow checks as `copy_tree_upload`), per regular file `open`+`brix_cksum_fd`, print `"%s  %s\n"` (hex, rel).
  - root:// root: `brix_url_parse` + `brix_connect` + `brix_tree_walk` with a visitor that skips dirs and calls `brix_query_cksum(c, path, algo, hex, sizeof(hex), &st)`; rel = `path + strlen(rooturl_path) (+1 for the slash)`. Per-file failures print to stderr, set an `errors` counter, and continue.
  - Exit 0 clean, 2 if any per-file errors.
  `brix_xrdckcheck_main`: args `<manifest> <root>`; per line `brix_ckmf_parse_line` (malformed → stderr + errors++), compute the same-side digest (local: `brix_cksum_fd`; remote: one connection reused, `brix_query_cksum`), compare case-insensitively; print `OK <rel>` / `FAILED <rel>`; exit 0 all-OK, 1 any mismatch, 2 errors.
  Register both in the xrdcksum dispatcher (read xrdcksum.c:32-94 and add `tree`/`check` exactly the way `verify`/`info` route to `brix_xrdckverify_main`/`brix_xrdcinfo_main`); add `apps/cksum/xrdcktree.o` to `xrdcksum_OBJS`.
- [ ] **Step 4: e2e section** (local, no fleet): build a 3-file tree; `xrdcksum tree dir -o m` → 3 lines; `xrdcksum check m dir` exit 0; tamper one file → exit 1 and `FAILED` names it; inject `03e5..  ../../etc/passwd` line → rejected as malformed, exit 2, nothing outside dir touched (security). Fleet-gated: `tree root://.../dir` matches the local manifest of the same content.
- [ ] **Step 5: Build + unit + e2e + commit** (`feat(xrdcksum): recursive tree manifests and check verification`).

---

### Task 15: xrddiag `--json` for check/topology; verify replay + doctor

**Files:**
- Modify: `client/apps/diag/xrddiag.c` (or the file holding `do_check`) and `client/apps/diag/diag_topology.c`, `tests/run_client_features.sh`

- [ ] **Step 1: Verify what exists** (no code yet): run `client/bin/xrddiag replay /nonexistent` (expect a clean error, proving the subcommand is wired); grep `a->json`/`args.json` usage in `do_check` and `do_topology` — the explorer found `--json` honored only by remote-doctor/watch/srr/tape. Confirm `do_doctor` emits JSON via `doctor_emit_json` when `a->json` is set; if it already does, doctor needs nothing.
- [ ] **Step 2: `do_check --json`:** read `do_check` (declared diag_internal.h, implemented in `apps/diag/diag_check.c`); it runs connect/auth phases and prints human lines. Collect the per-phase outcomes it already computes into locals, and when `a->json` emit ONE object to stdout instead of the prose, e.g.:

```c
        printf("{");
        brix_json_kv_str(stdout, "url", a->url, 1);
        brix_json_kv_bool(stdout, "connect_ok", connect_ok, 1);
        brix_json_kv_str(stdout, "auth_proto", proto_name, 1);
        brix_json_kv_bool(stdout, "auth_ok", auth_ok, 1);
        brix_json_kv_ll(stdout, "rtt_ms", rtt_ms, 0);
        printf("}\n");
```

(field list = whatever do_check actually measures — mirror its human output 1:1; use `#include "cli/jsonout.h"`). `do_topology --json`: emit a JSON array of the nodes it prints (host, port, role fields it already has).
- [ ] **Step 3: e2e section:** fleet-gated `xrddiag check --json $URL | python3 -c 'import sys,json; json.load(sys.stdin)'`; unreachable URL with --json → nonzero exit and NO partial JSON on stdout (error case). Replay fixture (no fleet needed — the format is `XRDCAP1\n` + records, capture.c:25-27):

```bash
python3 - "$WORK/fix.xrdcap" <<'EOF'
import struct, sys
with open(sys.argv[1], 'wb') as f:
    f.write(b"XRDCAP1\n")
    k, v = b"tool", b"fixture"
    f.write(b"M" + bytes([len(k)]) + k + struct.pack(">H", len(v)) + v)
    hdr = bytes(24)                      # one zeroed 24B request header
    f.write(b"F" + b">" + b"\x01" + struct.pack(">HHI", 1, 3000, len(hdr)) + hdr)
EOF
"$BIN/xrddiag" replay "$WORK/fix.xrdcap" >/dev/null
check "xrdcap replay decodes fixture" '[ $? -eq 0 ]'
```

(check the `'F'` record byte order against capture.c:13 — `dir:1 isreq:1 sid:2BE code:2BE wirelen:4BE` — and fix the fixture writer to match exactly; a truncated file must produce a clean error, not a crash — add that as the security case.)
- [ ] **Step 4: Build + tests + commit** (`feat(xrddiag): --json for check/topology; replay fixture coverage`).

---

### Task 16: `~/.xrdrc [defaults]` section (timeouts/stall/backoff)

**Files:**
- Modify: `client/lib/core/config/xrdrc.c` (parse `[defaults]`), `client/lib/brix_net.h` (decl), `client/lib/net/nettmo.c:44-131` (layering), `client/lib/net/resilient.c:54` area (stall), `client/Makefile` (CLIENT_UNIT_TESTS)
- Test: `client/tests/c/xrdrc_defaults_unit.c`

**Interfaces:**
- Produces: `int brix_xrdrc_default_ms(const char *key, int *out_ms);` — 1 and sets `*out_ms` when `[defaults]` carries the key with a valid positive integer; keys: `connect_timeout_ms`, `io_timeout_ms`, `max_stall_ms`, `backoff_base_ms`. Resolution order everywhere becomes: **CLI setter > env var > .xrdrc [defaults] > compiled default**.

- [ ] **Step 1: Failing test** `client/tests/c/xrdrc_defaults_unit.c`:

```c
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "brix.h"
#include "brix_net.h"

int main(void)
{
    const char *path = "/tmp/xrdrc_defaults_unit.rc";
    FILE *f = fopen(path, "w");
    int   v = 0;
    fprintf(f, "[defaults]\n");
    fprintf(f, "connect_timeout_ms = 7000\n");
    fprintf(f, "io_timeout_ms = notanumber\n");        /* ignored */
    fprintf(f, "max_stall_ms = -5\n");                 /* ignored (negative) */
    fprintf(f, "[alias foo]\nurl = root://h:1094//x\n");
    fclose(f);
    setenv("XRDRC", path, 1);

    assert(brix_xrdrc_default_ms("connect_timeout_ms", &v) == 1 && v == 7000);
    assert(brix_xrdrc_default_ms("io_timeout_ms", &v) == 0);      /* error   */
    assert(brix_xrdrc_default_ms("max_stall_ms", &v) == 0);       /* security:
        negative values must not become giant unsigned timeouts */
    assert(brix_xrdrc_default_ms("nosuchkey", &v) == 0);
    /* layering: env var beats the xrdrc default */
    setenv("XRDC_CONNECT_TIMEOUT_MS", "9000", 1);
    assert(brix_tmo_connect_ms() == 9000);
    unlink(path);
    printf("xrdrc_defaults_unit: ALL PASS\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify failure**, then implement: in `xrdrc.c`'s line parser (read xrdrc.c:56-129 first), track `in_defaults` when the section header is exactly `[defaults]`; store matched keys into a `static int g_def_connect_ms, g_def_io_ms, g_def_stall_ms, g_def_backoff_ms;` (0 = unset) using `strtol` with full-string + `> 0` validation. Export:

```c
/* 1 and *out_ms set when ~/.xrdrc [defaults] carries `key` with a positive
 * integer. Layer: CLI setter > env > this > compiled default. */
int
brix_xrdrc_default_ms(const char *key, int *out_ms)
{
    /* ensure_loaded() = the same lazy-load gate the alias lookups use */
    ...
    if (strcmp(key, "connect_timeout_ms") == 0 && g_def_connect_ms > 0) {
        *out_ms = g_def_connect_ms;  return 1;
    }
    /* … io_timeout_ms / max_stall_ms / backoff_base_ms … */
    return 0;
}
```

- [ ] **Step 3: Layering.** Read `nettmo.c:44-85`: each resolver is `setter > env > default`. Insert the xrdrc consult between env and default, e.g. in `brix_tmo_connect_ms()`:

```c
    { int v; if (brix_xrdrc_default_ms("connect_timeout_ms", &v)) { return cache_and_return(v); } }
```

(match the file's actual caching idiom). Same for `brix_tmo_io_ms` and the backoff resolver (nettmo.c:119-131, key `backoff_base_ms`). For stall: grep `XRDC_MAX_STALL_MS` in `lib/net/` and insert the same fallback beneath the env check at each resolution point (explorer flagged resilient.c:54; verify with grep whether it is parsed in more than one file and patch every parse).
- [ ] **Step 4: Run:** `make -C client && make -C client test` → `xrdrc_defaults_unit: ALL PASS`, no regressions.
- [ ] **Step 5: Commit** (`feat(client): ~/.xrdrc [defaults] for timeouts, stall window, backoff`).

---

### Task 17: xrdfs `download`/`upload` `--io-uring`

**Files:**
- Modify: `client/apps/fs/xrdfs_data.c` (`do_download` ~line 843, `do_upload`), `client/apps/fs/xrdfs.c` (help rows), `tests/run_client_features.sh`

- [ ] **Step 1:** Read `do_download`'s local-destination setup (xrdfs_data.c:877-903) to find the `brix_vfs` open-options struct it fills (the same struct copy_local.c:242 fills). Parse `--io-uring <on|off|auto>` (and `--io-uring=<m>`) in both commands using the exact idiom from xrdcp.c:394-405, then set the opts field: `vopts.io_uring = mode;` before the vfs open. If `do_upload` reads via plain fd (no vfs opts), apply it only where a vfs open exists and say so in the help text.
- [ ] **Step 2:** Help rows gain `[--io-uring on|off|auto]`.
- [ ] **Step 3: e2e section** (fleet-gated): download the same remote file with `--io-uring off` and `--io-uring auto` → `cmp` byte-identical (success); `--io-uring bogus` → treated as auto or usage error, must not crash (error); `--io-uring on` on a kernel without uring → clean error message per vfs_posix.c:99 contract, not a partial file (security/robustness — accept either success or clean failure in the script).
- [ ] **Step 4: Build + tests + commit** (`feat(xrdfs): --io-uring control for download/upload`).

---

### Task 18: Man pages for all tools

**Files:**
- Create: `client/man/xrdcp.1`, `xrdfs.1`, `xrddiag.1`, `xrdcksum.1`, `xrdgsiproxy.1`, `xrdsssadmin.1`, `xrdprep.1`, `xrdstorascan.1`, `brixMount.1`
- Modify: `client/Makefile:416-425` (install loop)

- [ ] **Step 1:** Write `client/man/xrdcp.1` in classic man(7) troff. Full skeleton (the OPTIONS entries are transcribed 1:1 from `usage()` in apps/copy/xrdcp.c:10-54 INCLUDING the flags added by Tasks 5–9):

```troff
.TH XRDCP 1 "2026-07-05" "brix client" "User Commands"
.SH NAME
xrdcp \- copy files between local, root://, WebDAV/HTTP and S3 endpoints
.SH SYNOPSIS
.B xrdcp
[\fIOPTIONS\fR] \fISRC\fR... \fIDST\fR
.SH DESCRIPTION
.B xrdcp
copies files and directory trees between local paths, \fBroot://\fR /
\fBroots://\fR servers, WebDAV/HTTP(S) endpoints and S3 buckets, with
resilient transfers (reconnect + resume), checksum verification,
third-party copy, parallel jobs and streams, sync/mirror semantics and
resumable batch manifests.
.SH OPTIONS
.TP
.B \-f
Overwrite an existing destination.
.TP
.B \-r
Recursively copy a tree.
.TP
.BR \-n ", " \-\-dry\-run
Print what would be transferred or deleted; move no bytes.
.TP
.BI \-\-exclude " PAT"
Skip files matching this fnmatch pattern (repeatable).
.TP
.BI \-\-sync\-check " MODE"
Comparison for \-\-sync: size (default), mtime, or cksum[:algo].
.\" …one .TP entry per remaining usage() line — transcribe them all…
.SH EXAMPLES
.nf
xrdcp -r --sync --delete root://se//data/run42/ /scratch/run42/
xrdcp --from list.txt --resume -j 8 root://se//dest/
.fi
.SH ENVIRONMENT
XRDC_CONNECT_TIMEOUT_MS, XRDC_IO_TIMEOUT_MS, XRDC_MAX_STALL_MS,
BEARER_TOKEN, X509_USER_PROXY, AWS_ACCESS_KEY_ID, XRDRC.
.SH SEE ALSO
.BR xrdfs (1),
.BR xrdcksum (1),
.BR xrddiag (1)
```

- [ ] **Step 2:** Write the other eight pages with the same section set (NAME/SYNOPSIS/DESCRIPTION/OPTIONS or COMMANDS/EXAMPLES/SEE ALSO). Source of truth for each: the tool's own usage()/help output — run each binary with `-h` (or no args) and transcribe: `xrdfs` (COMMANDS section = the `COMMANDS[]` help strings incl. new `rm -r`, `-j`, `cat -z`, `tail -f`), `xrddiag` (subcommands check/bench/metabench/watch/topology/status/compare/remote-doctor/probe-robustness/replay/srr/tape), `xrdcksum` (crc32c/crc64/adler32/verify/info/tree/check), `xrdgsiproxy` (init/info/destroy), `xrdsssadmin` (add/install/read/write), `xrdprep` (-s/-c/-w/-f/-e/-p), `xrdstorascan` (verify/bench/dump/fill/compare), `brixMount` (cvmfs/cvmfs-rw/eos/root/roots, --overlay-list/--overlay-reset).
- [ ] **Step 3:** Makefile `install-bin` (lines 416-425): replace the two hard-coded man installs with:

```makefile
	for m in man/*.1; do install -m644 $$m $(DESTDIR)$(PREFIX)/share/man/man1/; done
```

- [ ] **Step 4: Verify:** `for m in client/man/*.1; do MANWIDTH=80 man -l "$m" >/dev/null || echo "BAD $m"; done` prints nothing.
- [ ] **Step 5: Commit** (`docs(client): man pages for all CLI tools`).

---

### Task 19: Bash completion

**Files:**
- Create: `client/completions/brix-tools.bash`
- Modify: `client/Makefile` (install-bin target)

- [ ] **Step 1:** Write `client/completions/brix-tools.bash`:

```bash
# brix-tools.bash — bash completion for the brix client CLI suite.
# zsh: `autoload -U +X bashcompinit && bashcompinit`, then source this file.

_brix_opts_filter() {  # complete only when the current word starts with '-'
  local cur="${COMP_WORDS[COMP_CWORD]}"
  [[ "$cur" == -* ]] || return 1
  COMPREPLY=($(compgen -W "$1" -- "$cur"))
  return 0
}

_xrdcp() {
  local opts="-f -r -P -s -v -d -n -j -S -T -V -h --from --retry --no-retry
    --max-stall --auto-refresh --oidc-account --jobs --sync --sync-check
    --delete --dry-run --exclude --include --remove-source --journal --resume
    --progress --verify --tls --notlsok --noverifyhost --auth --pgrw --cksum
    --compress --zip --zip-append --streams --tpc --tpc-token-mode --token
    --s3-access --s3-secret --s3-region --wire-trace --timing --io-uring
    --proxy"
  _brix_opts_filter "$opts" && return
  local prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
    --sync-check) COMPREPLY=($(compgen -W "size mtime cksum" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --tpc)        COMPREPLY=($(compgen -W "first only delegate" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --io-uring)   COMPREPLY=($(compgen -W "on off auto" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --auth)       COMPREPLY=($(compgen -W "gsi ztn krb5 sss unix" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --from|--journal) COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
  esac
  COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}"))
}

_xrdfs() {
  if [[ $COMP_CWORD -eq 2 ]]; then
    COMPREPLY=($(compgen -W "stat ls du df tree find mkdir rm rmdir mv chmod
      touch ln readlink truncate cat head tail wc grep hexdump dd upload
      download cmp cksum xattr readv writev locate query statvfs prepare
      stage evict explain" -- "${COMP_WORDS[COMP_CWORD]}"))
  fi
}

_xrddiag() {
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "check bench metabench watch topology status
      compare remote-doctor probe-robustness replay srr tape" \
      -- "${COMP_WORDS[COMP_CWORD]}"))
    return
  fi
  _brix_opts_filter "--json --interval --count --prometheus --sweep --davs
    --cluster-url --probe-timeout --playback -S"
}

_xrdcksum() {
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "crc32c crc64 adler32 verify info tree check" \
      -- "${COMP_WORDS[COMP_CWORD]}"))
    return
  fi
  COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}"))
}

_xrd() {
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "cp copy get put sync upload download ls stat
      mkdir rm diag ping certinfo clockskew whoami caps doctor login mount
      mounts unmount inventory verify drift inspect replicas version help" \
      -- "${COMP_WORDS[COMP_CWORD]}"))
  fi
}

complete -F _xrdcp xrdcp
complete -F _xrdfs xrdfs
complete -F _xrddiag xrddiag
complete -F _xrdcksum xrdcksum
complete -F _xrd xrd
```

- [ ] **Step 2:** Makefile install-bin gains:

```makefile
	install -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions
	install -m644 completions/brix-tools.bash $(DESTDIR)$(PREFIX)/share/bash-completion/completions/xrdcp
```

- [ ] **Step 3: Verify:** `bash -c 'source client/completions/brix-tools.bash && complete -p xrdcp xrdfs xrddiag xrdcksum xrd'` lists all five.
- [ ] **Step 4: Commit** (`feat(client): bash completion for the CLI suite`).

---

### Task 20: Final sweep — docs, full verification

**Files:**
- Modify: `client/apps/README.md`, `client/README.md` (document every new flag/subcommand), `tests/run_client_features.sh` (final assembly check)

- [ ] **Step 1:** Update both READMEs: new xrdcp flags (`--dry-run --exclude --include --sync-check --delete --remove-source --journal --resume`), xrdfs (`rm -r`, `-j/--json`, `cat -z`, `tail -f`, `--io-uring`), `xrdcksum tree/check`, `xrddiag check/topology --json`, `.xrdrc [defaults]`, man pages + completions install.
- [ ] **Step 2: Full verification** (superpowers:verification-before-completion — run, read output, then claim):

```bash
make -C /home/rcurrie/HEP-x/nginx-xrootd/client
make -C /home/rcurrie/HEP-x/nginx-xrootd/client test
tests/manage_test_servers.sh start   # if not already up
tests/run_client_features.sh
```

Expected: clean build, `ALL PASS` from every unit test, `client-features: N pass, 0 fail`.
- [ ] **Step 3: Commit** (`docs(client): document the 2026-07-05 feature set`).

---

## Self-Review Notes

- **Spec coverage:** 15 requested features → Tasks 5 (dry-run, filters), 6 (sync modes), 7 (--delete), 8 (remove-source), 9 (journal), 10 (rm -r), 11 (xrdfs --json), 12 (cat compression), 13 (resilient tail), 14 (tree audit), 15 (diag --json; `.xrdcap` replay verified pre-existing), 16 (.xrdrc defaults), 17 (io_uring beyond xrdcp), 18 (man pages), 19 (completion). Tasks 1–4 are shared enablers.
- **Known unknowns, called out in-task:** local↔local `-r` support (Task 5 Step 1 NOTE), opaque `?` prefix (Task 12 Step 1), `do_check` internals (Task 15 Step 2), nettmo caching idiom + stall parse sites (Task 16 Step 3), `do_upload` vfs usage (Task 17 Step 1). Each has an explicit read/grep instruction and a decision rule — not placeholders.
- **Type consistency:** `brix_copy_filter_match(const brix_copy_opts *, const char *)`, `brix_sync_should_skip(int, ll, ll, ll, ll)`, `brix_journal_*`, `brix_rmtree(conn, path, flags, report, u, st)`, `brix_tree_walk(conn, path, fn, u, st)`, `brix_rel_is_unsafe(const char *)`, `brix_ckmf_parse_line(line, hex, hexsz, rel, relsz)`, `brix_xrdrc_default_ms(key, out)` — used with identical signatures in every consuming task.
