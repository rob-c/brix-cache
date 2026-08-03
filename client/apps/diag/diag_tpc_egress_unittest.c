/*
 * diag_tpc_egress_unittest.c — standalone unit test for the TPC egress
 * self-test's pure classifiers: the trigger-outcome verdict mapper and the
 * egress-denial message discriminator.
 *
 *   cc -std=c11 -Wall -Wextra -Werror -Ilib -I../src -I../shared \
 *      -DXRDPROTO_NO_NGX apps/diag/diag_tpc_egress_unittest.c -o /tmp/ut \
 *   && /tmp/ut          (run from client/)
 *
 * Exit 0 = all checks pass. Pure C — no server, no connection: the TU under test
 * is #included and the wire/render externs it references (brix_connect,
 * brix_url_parse, brix_file_open_opaque, brix_file_sync, brix_close,
 * brix_status_clear, gen_tpc_key, fjson_str) are satisfied by trivial stubs.
 * The live path (tpce_run) is covered online by test_xrddiag_tpc_egress.py.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag_internal.h"

/* ---- extern stubs (never reached by the pure classifiers under test) ---- */
void brix_status_clear(brix_status *st) { (void) st; }
int  brix_url_parse(const char *s, brix_url *o, brix_status *st)
{ (void) s; (void) o; (void) st; return -1; }
int  brix_connect(brix_conn *c, const brix_url *u, const brix_opts *o,
                  brix_status *st)
{ (void) c; (void) u; (void) o; (void) st; return -1; }
int  brix_file_open_opaque(brix_conn *c, const char *p, const char *op, int w,
                           int f, int po, brix_file *fl, brix_status *st)
{ (void) c; (void) p; (void) op; (void) w; (void) f; (void) po; (void) fl;
  (void) st; return -1; }
int  brix_file_sync(brix_conn *c, brix_file *f, brix_status *st)
{ (void) c; (void) f; (void) st; return -1; }
void brix_close(brix_conn *c) { (void) c; }
int  gen_tpc_key(char *out, size_t n) { (void) out; (void) n; return -1; }
void fjson_str(FILE *o, const char *s) { (void) o; (void) s; }

#include "diag_tpc_egress.c"

/* ---- harness ---- */
static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static tpce_verdict
classify(int kxr, int errno_, const char *msg, double el, double budget)
{
    brix_status st;
    char        detail[256];
    memset(&st, 0, sizeof(st));
    st.kxr = kxr;
    st.sys_errno = errno_;
    if (msg != NULL) {
        snprintf(st.msg, sizeof(st.msg), "%s", msg);
    }
    return tpce_classify_trigger(&st, el, budget, detail, sizeof(detail));
}


/* SUCCESS: kxr==0 (the pull completed) is the worst-case ACCEPTED verdict. */
static void
test_accepted(void)
{
    CHECK(classify(0, 0, NULL, 12.0, 4000.0) == TPCE_ACCEPTED);
    /* a success status never mis-reads a stale errno/msg. */
    CHECK(classify(0, ECONNREFUSED, "connection refused", 5.0, 4000.0)
          == TPCE_ACCEPTED);
}


/* PERMITTED variants: the gateway originated and we can tell how far it got. */
static void
test_permitted_variants(void)
{
    /* conn-refused wins on errno OR on message text. */
    CHECK(classify(kXR_FSError, ECONNREFUSED, "", 3.0, 4000.0)
          == TPCE_CONN_REFUSED);
    CHECK(classify(kXR_FSError, 0, "connection refused by source", 3.0, 4000.0)
          == TPCE_CONN_REFUSED);
    /* filtered: explicit timeout errno, timeout text, or budget elapsed. */
    CHECK(classify(-1, ETIMEDOUT, "", 100.0, 4000.0) == TPCE_FILTERED);
    CHECK(classify(kXR_FSError, 0, "operation timed out", 50.0, 4000.0)
          == TPCE_FILTERED);
    CHECK(classify(kXR_FSError, 0, "", 3700.0, 4000.0) == TPCE_FILTERED);
    /* the gateway's generic "TPC connect to <h> failed" (no errno): a FAST reply
     * is an active refusal, a SLOW one is its own connect timeout (filtered). */
    CHECK(classify(kXR_ServerError, 0, "TPC connect to h failed", 6.0, 4000.0)
          == TPCE_CONN_REFUSED);
    CHECK(classify(kXR_ServerError, 0, "TPC connect to h failed", 2500.0, 4000.0)
          == TPCE_FILTERED);
    /* reached, lfn absent: NotFound code or "no such"/"not found" text. */
    CHECK(classify(kXR_NotFound, 0, "", 40.0, 4000.0) == TPCE_REACHED_NOENT);
    CHECK(classify(kXR_FSError, 0, "no such file or directory", 40.0, 4000.0)
          == TPCE_REACHED_NOENT);
    /* reached, some other error the source answered with. */
    CHECK(classify(kXR_ServerError, 0, "internal source error", 40.0, 4000.0)
          == TPCE_REACHED_ERROR);
}


/* PRECEDENCE: conn-refused must beat the budget-elapsed timeout heuristic when
 * BOTH could match (a fast RST whose measured time also crossed the threshold
 * on a tiny budget). refused is the more specific fact. */
static void
test_precedence(void)
{
    /* errno=ECONNREFUSED but elapsed also >= 0.9*budget → still CONN_REFUSED. */
    CHECK(classify(kXR_FSError, ECONNREFUSED, "", 3800.0, 4000.0)
          == TPCE_CONN_REFUSED);
    /* success beats everything. */
    CHECK(classify(0, ETIMEDOUT, "timed out", 3900.0, 4000.0) == TPCE_ACCEPTED);
}


/* EGRESS-DENIAL discriminator: only source/egress-policy text counts as a
 * working guard; an unrelated NotAuthorized (read-only, token scope) does not. */
static void
test_egress_denial(void)
{
    CHECK(tpce_msg_is_egress_denial("TPC source host not permitted: 10.0.0.1"));
    CHECK(tpce_msg_is_egress_denial("prohibited private address"));
    CHECK(tpce_msg_is_egress_denial("loopback source refused"));
    CHECK(tpce_msg_is_egress_denial("SSRF policy: egress blocked"));
    /* unrelated denials must NOT read as an egress guard. */
    CHECK(!tpce_msg_is_egress_denial("export is read-only"));
    CHECK(!tpce_msg_is_egress_denial("token scope does not cover this path"));
    CHECK(!tpce_msg_is_egress_denial(""));
    CHECK(!tpce_msg_is_egress_denial(NULL));
}


/* AFTER-ARM: the arm result drives egress_permitted + verdict correctly. */
static void
test_after_arm(void)
{
    brix_status st;
    tpce_result r;
    brix_conn   c;
    brix_file   f;

    memset(&c, 0, sizeof(c));
    memset(&f, 0, sizeof(f));

    /* arm refused with an egress-policy NotAuthorized → REFUSED_POLICY, no egress. */
    memset(&r, 0, sizeof(r));
    memset(&st, 0, sizeof(st));
    st.kxr = kXR_NotAuthorized;
    snprintf(st.msg, sizeof(st.msg), "TPC source host not permitted");
    tpce_after_arm(&c, &f, -1, &st, 4000.0, &r);
    CHECK(r.verdict == TPCE_REFUSED_POLICY && r.egress_permitted == 0);
    CHECK(r.arm_kxr == kXR_NotAuthorized);

    /* arm refused with an UNRELATED NotAuthorized → ARM_ERROR, not policy. */
    memset(&r, 0, sizeof(r));
    memset(&st, 0, sizeof(st));
    st.kxr = kXR_NotAuthorized;
    snprintf(st.msg, sizeof(st.msg), "export is read-only");
    tpce_after_arm(&c, &f, -1, &st, 4000.0, &r);
    CHECK(r.verdict == TPCE_ARM_ERROR && r.egress_permitted == 0);
}


int
main(void)
{
    test_accepted();
    test_permitted_variants();
    test_precedence();
    test_egress_denial();
    test_after_arm();

    if (g_fail == 0) {
        printf("all checks passed\n");
        return 0;
    }
    printf("%d check(s) FAILED\n", g_fail);
    return 1;
}
