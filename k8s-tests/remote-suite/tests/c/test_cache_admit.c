/*
 * test_cache_admit.c — standalone unit tests for the shared admission filter
 * (src/fs/cache/cache_admit.c). Links against the compiled cache_admit.o.
 *
 * cache_admit.o reads ngx_array_t (elts/nelts) of brix_wt_prefix_entry_t
 * (ngx_str_t prefix). We mirror those layouts byte-compatibly and build the
 * prefix arrays by hand — no nginx runtime, no pool.
 *
 * Build/run via tests/c/run_cache_admit_tests.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <regex.h>
#include <sys/types.h>

typedef uintptr_t ngx_uint_t;
typedef unsigned char u_char;

/* Mirror of ngx_str_t. */
typedef struct { size_t len; u_char *data; } ngx_str_t;

/* Mirror of ngx_array_t (only elts/nelts are read by cache_admit.o, but keep the
 * full layout so the field offsets match). */
typedef struct {
    void      *elts;
    ngx_uint_t nelts;
    size_t     size;
    ngx_uint_t nalloc;
    void      *pool;
} ngx_array_t;

/* Mirror of brix_wt_prefix_entry_t. */
typedef struct { ngx_str_t prefix; } brix_wt_prefix_entry_t;

typedef enum { BRIX_CACHE_ADMIT = 0, BRIX_CACHE_DECLINE = 1 } brix_cache_admit_e;

typedef struct {
    ngx_array_t *deny_prefixes;
    ngx_array_t *allow_prefixes;
    off_t        size_limit;
    regex_t     *include_regex;
} brix_cache_admit_cfg_t;

brix_cache_admit_e brix_cache_admit(const brix_cache_admit_cfg_t *cfg,
    const char *path, off_t size, int is_new);

/* ---- harness ---- */
static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do {                                              \
        if (cond) { g_pass++; }                                            \
        else { g_fail++; printf("FAIL: %s\n", msg); }                      \
    } while (0)

/* Build a 1-element prefix array (leaked; fine for a short test). */
static ngx_array_t *
prefix_array(const char *p)
{
    ngx_array_t              *a = calloc(1, sizeof(*a));
    brix_wt_prefix_entry_t *e = calloc(1, sizeof(*e));
    e->prefix.len  = strlen(p);
    e->prefix.data = (u_char *) strdup(p);
    a->elts = e; a->nelts = 1; a->size = sizeof(*e); a->nalloc = 1;
    return a;
}

static void
test_deny_beats_allow(void)
{
    brix_cache_admit_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.deny_prefixes  = prefix_array("/a/");
    c.allow_prefixes = prefix_array("/a/b/");
    CHECK(brix_cache_admit(&c, "/a/b/x", 10, 0) == BRIX_CACHE_DECLINE,
          "deny precedence over allow");
}

static void
test_whitelist(void)
{
    brix_cache_admit_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.allow_prefixes = prefix_array("/keep/");
    CHECK(brix_cache_admit(&c, "/keep/f", 10, 0) == BRIX_CACHE_ADMIT,
          "whitelisted path admitted");
    CHECK(brix_cache_admit(&c, "/other/f", 10, 0) == BRIX_CACHE_DECLINE,
          "non-whitelisted path declined");
}

static void
test_size_and_new(void)
{
    brix_cache_admit_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.size_limit = 100;
    CHECK(brix_cache_admit(&c, "/f", 200, 0) == BRIX_CACHE_DECLINE,
          "over-limit existing file declined");
    CHECK(brix_cache_admit(&c, "/f", 200, 1) == BRIX_CACHE_ADMIT,
          "new file (size unknown) admitted");
    CHECK(brix_cache_admit(&c, "/f", 50, 0) == BRIX_CACHE_ADMIT,
          "under-limit file admitted");
}

static void
test_regex_bypasses_size(void)
{
    brix_cache_admit_cfg_t c;
    regex_t                  re;
    memset(&c, 0, sizeof(c));
    c.size_limit = 100;
    regcomp(&re, "\\.root$", REG_EXTENDED);
    c.include_regex = &re;
    CHECK(brix_cache_admit(&c, "/big.root", 9999, 0) == BRIX_CACHE_ADMIT,
          "regex match bypasses size cap");
    CHECK(brix_cache_admit(&c, "/big.txt", 9999, 0) == BRIX_CACHE_DECLINE,
          "regex non-match still size-capped");
    regfree(&re);
}

static void
test_null_failclosed(void)
{
    brix_cache_admit_cfg_t c;
    memset(&c, 0, sizeof(c));
    CHECK(brix_cache_admit(NULL, "/f", 10, 0) == BRIX_CACHE_DECLINE, "NULL cfg declines");
    CHECK(brix_cache_admit(&c, NULL, 10, 0) == BRIX_CACHE_DECLINE, "NULL path declines");
    CHECK(brix_cache_admit(&c, "/f", 10, 0) == BRIX_CACHE_ADMIT, "empty cfg admits");
}

int
main(void)
{
    test_deny_beats_allow();
    test_whitelist();
    test_size_and_new();
    test_regex_bypasses_size();
    test_null_failclosed();
    printf("cache_admit unit tests: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
