/*
 * scan_unittest.c — standalone suite for the ngx-free scan cores.
 *
 *   gcc -Wall -Wextra -Werror -I src/scan -o /tmp/scan_ut \
 *       src/scan/scan_unittest.c src/scan/scan_record.c src/scan/scan_throttle.c \
 *       src/scan/scan_emit.c src/scan/scan_drift.c -lm \
 *       && /tmp/scan_ut
 *
 * Exit 0 = all checks pass. Driven by tests/test_scan.py.
 */
#include "scan_record.h"
#include "scan_throttle.h"
#include "scan_emit.h"
#include "scan_drift.h"

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int g_fail;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__);  \
            g_fail++;                                                          \
        }                                                                      \
    } while (0)

#define STREQ(a, b) (strcmp((a), (b)) == 0)
#define CLOSE(a, b, eps) (fabs((double)(a) - (double)(b)) < (eps))

/* ---- scan_record ---------------------------------------------------------- */

static void
test_json_escape(void)
{
    char out[64];

    CHECK(brix_scan_json_escape("a/b", 3, out, sizeof(out)) == 3, "plain len");
    CHECK(STREQ(out, "a/b"), "plain passthrough");

    CHECK(brix_scan_json_escape("a\"b", 3, out, sizeof(out)) == 4, "quote len");
    CHECK(STREQ(out, "a\\\"b"), "quote escaped");

    CHECK(brix_scan_json_escape("a\\b", 3, out, sizeof(out)) == 4, "bslash len");
    CHECK(STREQ(out, "a\\\\b"), "backslash escaped");

    CHECK(brix_scan_json_escape("a\nb", 3, out, sizeof(out)) == 4, "nl len");
    CHECK(STREQ(out, "a\\nb"), "newline short form");

    {
        char in[3] = { 'a', 0x01, 'b' };
        CHECK(brix_scan_json_escape(in, 3, out, sizeof(out)) == 8, "ctrl len");
        CHECK(STREQ(out, "a\\u0001b"), "control \\u escaped");
    }

    /* overflow → -1, never truncate */
    CHECK(brix_scan_json_escape("abcdef", 6, out, 4) == -1, "overflow rejects");
}

static void
test_record_file(void)
{
    char buf[512];

    /* verify-shape: stored + computed present */
    CHECK(brix_scan_record_file(buf, sizeof(buf), "/x", 12, 34, "adler32",
                                  "abcd", "abcd", "ok") > 0, "file rc");
    CHECK(STREQ(buf,
        "{\"t\":\"file\",\"path\":\"/x\",\"size\":12,\"mtime\":34,"
        "\"alg\":\"adler32\",\"stored\":\"abcd\",\"computed\":\"abcd\","
        "\"status\":\"ok\"}"), "verify-shape file record");

    /* dump-shape: no stored, no computed */
    CHECK(brix_scan_record_file(buf, sizeof(buf), "/x", 12, 34, "adler32",
                                  NULL, NULL, "ok") > 0, "dump rc");
    CHECK(STREQ(buf,
        "{\"t\":\"file\",\"path\":\"/x\",\"size\":12,\"mtime\":34,"
        "\"alg\":\"adler32\",\"stored\":null,\"status\":\"ok\"}"),
        "dump-shape file record");

    /* path gets escaped */
    CHECK(brix_scan_record_file(buf, sizeof(buf), "/a\"b", 0, 0, "crc32c",
                                  NULL, NULL, "missing") > 0, "esc rc");
    CHECK(strstr(buf, "\"path\":\"/a\\\"b\"") != NULL, "path escaped in record");
}

static void
test_record_cursor_summary(void)
{
    char buf[256];
    brix_scan_summary_t s;

    CHECK(brix_scan_record_cursor(buf, sizeof(buf), "/a/b") > 0, "cursor rc");
    CHECK(STREQ(buf, "{\"t\":\"cursor\",\"after\":\"/a/b\"}"), "cursor record");

    memset(&s, 0, sizeof(s));
    s.files = 120345; s.bytes = 98765432; s.ok = 120300; s.mismatch = 2;
    s.missing = 40; s.unreadable = 3; s.filled = 0; s.already = 0;
    s.elapsed_s = 812.4;
    CHECK(brix_scan_record_summary(buf, sizeof(buf), &s) > 0, "summary rc");
    CHECK(STREQ(buf,
        "{\"t\":\"summary\",\"files\":120345,\"bytes\":98765432,\"ok\":120300,"
        "\"mismatch\":2,\"missing\":40,\"unreadable\":3,\"filled\":0,"
        "\"already\":0,\"elapsed_s\":812.40}"), "summary record");
}

static void
test_record_inspect_health(void)
{
    char buf[256];

    CHECK(brix_scan_record_inspect(buf, sizeof(buf), "/x", "posix", 12, 34,
                                     "xattr", 1) > 0, "inspect rc");
    CHECK(STREQ(buf,
        "{\"t\":\"inspect\",\"path\":\"/x\",\"backend\":\"posix\",\"size\":12,"
        "\"mtime\":34,\"stored_src\":\"xattr\",\"namespace_consistent\":true}"),
        "inspect record");

    CHECK(brix_scan_record_inspect(buf, sizeof(buf), "/y", "posix", 0, 0,
                                     "none", 0) > 0, "inspect rc2");
    CHECK(strstr(buf, "\"namespace_consistent\":false") != NULL,
          "inspect ns false");

    CHECK(brix_scan_record_health(buf, sizeof(buf), "posix",
                                    1000, 400, 600) > 0, "health rc");
    CHECK(STREQ(buf,
        "{\"t\":\"health\",\"backend\":\"posix\",\"total_bytes\":1000,"
        "\"free_bytes\":400,\"used_bytes\":600}"), "health record");
}

static void
test_record_object_drift(void)
{
    char buf[256];

    /* inventory object: backend key + recovered logical path, not an orphan */
    CHECK(brix_scan_record_object(buf, sizeof(buf), "atlas.x.root",
                                    "/atlas/x.root", 12345, 1719600000, 0) > 0,
          "object rc");
    CHECK(STREQ(buf,
        "{\"t\":\"object\",\"key\":\"atlas.x.root\",\"path\":\"/atlas/x.root\","
        "\"size\":12345,\"mtime\":1719600000,\"orphan\":false}"),
        "object record");

    /* orphan object: no recoverable namespace path → path null, orphan true */
    CHECK(brix_scan_record_object(buf, sizeof(buf), "atlas.orphan.0", NULL,
                                    4096, 0, 1) > 0, "object orphan rc");
    CHECK(strstr(buf, "\"path\":null") != NULL, "orphan path null");
    CHECK(strstr(buf, "\"orphan\":true") != NULL, "orphan flag true");

    /* drift orphan_object: catalog key present, no namespace entry */
    CHECK(brix_scan_record_drift(buf, sizeof(buf), "atlas.orphan.0", NULL,
                                   "orphan_object", 4096) > 0, "drift rc");
    CHECK(STREQ(buf,
        "{\"t\":\"drift\",\"key\":\"atlas.orphan.0\",\"path\":null,"
        "\"class\":\"orphan_object\",\"size\":4096}"), "drift orphan record");

    /* drift namespace_only: namespace path present, no backing object → key null */
    CHECK(brix_scan_record_drift(buf, sizeof(buf), NULL, "/atlas/ghost",
                                   "namespace_only", 0) > 0, "drift ns rc");
    CHECK(strstr(buf, "\"key\":null") != NULL, "ns_only key null");
    CHECK(strstr(buf, "\"path\":\"/atlas/ghost\"") != NULL, "ns_only path");
}

/* ---- scan_throttle -------------------------------------------------------- */

static void
test_token_bucket(void)
{
    brix_scan_tb_t tb;

    /* 1 MB/s, 1 MB burst, starts full at t=0 */
    brix_scan_tb_init(&tb, 1.0e6, 1.0e6, 0);
    CHECK(brix_scan_tb_wait_ns(&tb, 5.0e5, 0) == 0, "full bucket: no wait");

    brix_scan_tb_consume(&tb, 1.0e6);   /* drain */
    /* need 1 MB, empty, 1 MB/s -> 1.0 s */
    CHECK(CLOSE(brix_scan_tb_wait_ns(&tb, 1.0e6, 0), 1.0e9, 1.0e6),
          "empty bucket: wait 1 s for 1 MB");

    /* after 0.5 s, 0.5 MB accrued -> need 1 MB still 0.5 s away */
    CHECK(CLOSE(brix_scan_tb_wait_ns(&tb, 1.0e6, 500000000ull), 5.0e8, 1.0e6),
          "half-refilled bucket: 0.5 s wait");

    /* unlimited rate -> never wait */
    brix_scan_tb_init(&tb, 0.0, 0.0, 0);
    CHECK(brix_scan_tb_wait_ns(&tb, 1.0e9, 12345) == 0, "rate 0 = unlimited");
}

static void
test_budget(void)
{
    brix_scan_budget_t b;

    b.max_bytes = 1000; b.max_seconds = 0;
    CHECK(!brix_scan_budget_hit(&b, 999, 1e9), "under byte budget");
    CHECK(brix_scan_budget_hit(&b, 1000, 0), "at byte budget");
    CHECK(brix_scan_budget_hit(&b, 1001, 0), "over byte budget");

    b.max_bytes = 0; b.max_seconds = 10.0;
    CHECK(!brix_scan_budget_hit(&b, 1ull << 40, 9.9), "under time budget");
    CHECK(brix_scan_budget_hit(&b, 0, 10.0), "at time budget");

    b.max_bytes = 0; b.max_seconds = 0;
    CHECK(!brix_scan_budget_hit(&b, 1ull << 40, 1e9), "no budget = never hit");
}

static void
test_adapt(void)
{
    /* idle + nominal latency -> full speed */
    CHECK(CLOSE(brix_scan_adapt(0, 10.0, 10.0), 1.0, 1e-9), "idle/nominal = 1.0");
    /* 4x latency shrinks */
    CHECK(brix_scan_adapt(0, 40.0, 10.0) < 1.0, "high latency shrinks");
    CHECK(CLOSE(brix_scan_adapt(0, 40.0, 10.0), 0.25, 1e-9), "4x latency = 0.25");
    /* foreground pressure shrinks, monotonic */
    CHECK(brix_scan_adapt(10, 10.0, 10.0) < brix_scan_adapt(2, 10.0, 10.0),
          "more pressure = smaller multiplier");
    CHECK(brix_scan_adapt(2, 10.0, 10.0) < brix_scan_adapt(0, 10.0, 10.0),
          "any pressure < idle");
    /* floor clamp */
    CHECK(CLOSE(brix_scan_adapt(100000, 1e9, 10.0), 0.1, 1e-9), "clamped to 0.1");
    CHECK(brix_scan_adapt(100000, 1e9, 10.0) >= 0.1, "never below floor");
}

/* ---- scan_emit (ordered reorder buffer) ----------------------------------- */

static uint64_t g_emit_order[16];
static int      g_emit_n;

static void
emit_collect(void *ctx, uint64_t seq, void *payload)
{
    (void) ctx;
    /* payload encodes seq too, so we can assert they agree */
    CHECK((uint64_t) (uintptr_t) payload == seq, "emit payload matches seq");
    if (g_emit_n < (int) (sizeof(g_emit_order) / sizeof(g_emit_order[0]))) {
        g_emit_order[g_emit_n++] = seq;
    }
}

#define PAY(seq) ((void *) (uintptr_t) (seq))

static void
test_emitq_ordering(void)
{
    brix_scan_emitq_t q;
    void          *slots[4];
    unsigned char  used[4];
    int            r;

    g_emit_n = 0;
    brix_scan_emitq_init(&q, slots, used, 4);

    /* out-of-order arrivals: 2 then 0 then 1 -> emitted strictly 0,1,2 */
    r = brix_scan_emitq_submit(&q, 2, PAY(2), emit_collect, NULL);
    CHECK(r == 0, "seq 2 buffered, nothing emitted yet");
    r = brix_scan_emitq_submit(&q, 0, PAY(0), emit_collect, NULL);
    CHECK(r == 1, "seq 0 releases just 0");
    r = brix_scan_emitq_submit(&q, 1, PAY(1), emit_collect, NULL);
    CHECK(r == 2, "seq 1 releases 1 and 2");

    CHECK(g_emit_n == 3, "three records emitted");
    CHECK(g_emit_order[0] == 0 && g_emit_order[1] == 1 && g_emit_order[2] == 2,
          "emitted in walk order");
}

static void
test_emitq_errors(void)
{
    brix_scan_emitq_t q;
    void          *slots[2];
    unsigned char  used[2];

    g_emit_n = 0;
    brix_scan_emitq_init(&q, slots, used, 2);

    /* beyond the window (next=0, window=2 -> max seq 1) */
    CHECK(brix_scan_emitq_submit(&q, 2, PAY(2), emit_collect, NULL) == -1,
          "seq beyond window rejected");

    /* emit 0, then a late duplicate 0 is rejected */
    CHECK(brix_scan_emitq_submit(&q, 0, PAY(0), emit_collect, NULL) == 1,
          "seq 0 emits");
    CHECK(brix_scan_emitq_submit(&q, 0, PAY(0), emit_collect, NULL) == -1,
          "already-emitted seq rejected");
}

/* ---- scan_drift (namespace↔catalog reconciliation) ------------------------ */

static int   g_orphan_n;
static char  g_orphan_keys[8][64];
static int64_t g_orphan_sizes[8];

static void
orphan_collect(void *ctx, const char *key, int64_t size)
{
    (void) ctx;
    if (g_orphan_n < 8) {
        snprintf(g_orphan_keys[g_orphan_n], sizeof(g_orphan_keys[0]), "%s", key);
        g_orphan_sizes[g_orphan_n] = size;
        g_orphan_n++;
    }
}

static void
test_drift(void)
{
    brix_scan_driftset_t *s = brix_scan_driftset_create(4);
    int64_t cs = -1;

    CHECK(s != NULL, "driftset created");
    CHECK(brix_scan_driftset_add(s, "a", 10) == 0, "add a");
    CHECK(brix_scan_driftset_add(s, "b", 20) == 0, "add b");
    CHECK(brix_scan_driftset_add(s, "orphan", 5) == 0, "add orphan");

    /* namespace stream vs catalog */
    CHECK(brix_scan_driftset_match(s, "a", 10, &cs) == BRIX_DRIFT_IN_BOTH,
          "a in both"); CHECK(cs == 10, "a cat size");
    CHECK(brix_scan_driftset_match(s, "b", 99, &cs) == BRIX_DRIFT_SIZE_MISMATCH,
          "b size mismatch"); CHECK(cs == 20, "b cat size");
    CHECK(brix_scan_driftset_match(s, "c", 1, NULL) == BRIX_DRIFT_NAMESPACE_ONLY,
          "c namespace-only");

    /* growth past initial capacity must preserve entries */
    CHECK(brix_scan_driftset_add(s, "d", 40) == 0, "add d (grow)");
    CHECK(brix_scan_driftset_add(s, "e", 50) == 0, "add e (grow)");
    CHECK(brix_scan_driftset_match(s, "d", 40, NULL) == BRIX_DRIFT_IN_BOTH,
          "d survives grow");

    /* unmatched catalog keys are orphans: "orphan" and "e" */
    g_orphan_n = 0;
    brix_scan_driftset_orphans(s, orphan_collect, NULL);
    CHECK(g_orphan_n == 2, "two orphans");
    {
        int seen_orphan = 0, seen_e = 0, i;
        for (i = 0; i < g_orphan_n; i++) {
            if (strcmp(g_orphan_keys[i], "orphan") == 0
                && g_orphan_sizes[i] == 5) {
                seen_orphan = 1;
            }
            if (strcmp(g_orphan_keys[i], "e") == 0) {
                seen_e = 1;
            }
        }
        CHECK(seen_orphan && seen_e, "orphans are exactly the unmatched keys");
    }

    /* duplicate add updates size, not a second entry */
    brix_scan_driftset_add(s, "a", 11);
    CHECK(brix_scan_driftset_match(s, "a", 11, &cs) == BRIX_DRIFT_IN_BOTH
          && cs == 11, "duplicate add updates size");

    brix_scan_driftset_free(s);
}

int
main(void)
{
    test_json_escape();
    test_record_file();
    test_record_inspect_health();
    test_record_object_drift();
    test_record_cursor_summary();
    test_token_bucket();
    test_budget();
    test_adapt();
    test_emitq_ordering();
    test_emitq_errors();
    test_drift();

    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("scan cores: all checks passed\n");
    return 0;
}
