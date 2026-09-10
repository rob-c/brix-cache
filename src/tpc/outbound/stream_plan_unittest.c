/*
 * stream_plan_unittest.c — standalone unit test for the multi-stream TPC planner.
 *
 *   gcc -Wall -Wextra -Werror -I src/tpc/outbound -o /tmp/tpc_plan_ut \
 *       src/tpc/outbound/stream_plan_unittest.c src/tpc/outbound/stream_plan.c \
 *       && /tmp/tpc_plan_ut
 *
 * Exit 0 = all checks pass. The load-bearing cases are the negatives: a round
 * verdict that accepts data after a short window commits a file with a hole,
 * and a clamp that trusts the client's tpc.str lets one transfer fan out past
 * the server's brix_tpc_streams ceiling.
 */

#include "stream_plan.h"

#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

#define WIN 1024

/* --- success: the clamp honours a sane hint under the cap -------------------- */
static void
test_clamp_success(void)
{
    CHECK(tpc_stream_plan_clamp("4", 8) == 4);
    CHECK(tpc_stream_plan_clamp("1", 8) == 1);
    CHECK(tpc_stream_plan_clamp("8", 8) == 8);
    CHECK(tpc_stream_plan_clamp(NULL, 8) == 1);      /* no hint = single stream */
    CHECK(tpc_stream_plan_clamp("", 8) == 1);
}

/* --- error: garbage hints fall back to one stream, never to zero or negative -- */
static void
test_clamp_error(void)
{
    CHECK(tpc_stream_plan_clamp("abc", 8) == 1);
    CHECK(tpc_stream_plan_clamp("4x", 8) == 1);
    CHECK(tpc_stream_plan_clamp("0", 8) == 1);
    CHECK(tpc_stream_plan_clamp("-3", 8) == 1);
    CHECK(tpc_stream_plan_clamp("99999999999999999999", 8) == 1);
    CHECK(tpc_stream_plan_clamp("4", 0) == 1);       /* a broken cap = one stream */
    CHECK(tpc_stream_plan_clamp("4", -1) == 1);
}

/* --- security-negative: the client can lower the ceiling, never raise it ------ */
static void
test_clamp_security(void)
{
    CHECK(tpc_stream_plan_clamp("8", 2) == 2);
    CHECK(tpc_stream_plan_clamp("1000", 4) == 4);
    CHECK(tpc_stream_plan_clamp("1000", 1000) == TPC_STREAMS_MAX);
    CHECK(tpc_stream_plan_clamp("15", TPC_STREAMS_MAX) == TPC_STREAMS_MAX);
    CHECK(tpc_stream_plan_clamp("16", TPC_STREAMS_MAX) == TPC_STREAMS_MAX);
    CHECK(TPC_SUBSTREAMS_MAX == TPC_STREAMS_MAX - 1);
}

/* --- success: full rounds advance by the whole fan, a short tail ends it ------ */
static void
test_round_success(void)
{
    size_t full[4]  = { WIN, WIN, WIN, WIN };
    size_t tail[4]  = { WIN, WIN, 100, 0 };
    size_t one[1]   = { 300 };
    size_t adv = 0;
    int    eof = -1;

    CHECK(tpc_stream_plan_round(full, 4, WIN, &adv, &eof) == 0);
    CHECK(adv == 4 * WIN && eof == 0);

    CHECK(tpc_stream_plan_round(tail, 4, WIN, &adv, &eof) == 0);
    CHECK(adv == 2 * WIN + 100 && eof == 0);

    CHECK(tpc_stream_plan_round(one, 1, WIN, &adv, &eof) == 0);
    CHECK(adv == 300 && eof == 0);
}

/* --- success: EOF is slot 0 delivering nothing --------------------------------- */
static void
test_round_eof(void)
{
    size_t empty[3] = { 0, 0, 0 };
    size_t adv = 99;
    int    eof = 0;

    CHECK(tpc_stream_plan_round(empty, 3, WIN, &adv, &eof) == 0);
    CHECK(adv == 0 && eof == 1);
}

/* --- error: bad arguments are refused ------------------------------------------ */
static void
test_round_error(void)
{
    size_t got[2] = { WIN, WIN };
    size_t adv = 0;
    int    eof = 0;

    CHECK(tpc_stream_plan_round(NULL, 2, WIN, &adv, &eof) == -1);
    CHECK(tpc_stream_plan_round(got, 0, WIN, &adv, &eof) == -1);
    CHECK(tpc_stream_plan_round(got, -1, WIN, &adv, &eof) == -1);
    CHECK(tpc_stream_plan_round(got, 2, WIN, NULL, &eof) == -1);
    CHECK(tpc_stream_plan_round(got, 2, WIN, &adv, NULL) == -1);
}

/* --- security-negative: a hole (data after a short slot) is never committed ---- */
static void
test_round_hole(void)
{
    size_t hole[4]   = { WIN, 100, WIN, 0 };
    size_t hole2[3]  = { 0, WIN, 0 };          /* EOF on 0 but slot 1 has data */
    size_t over[2]   = { WIN + 1, 0 };         /* over-delivered window */
    size_t adv = 0;
    int    eof = 0;

    CHECK(tpc_stream_plan_round(hole, 4, WIN, &adv, &eof) == -1);
    CHECK(tpc_stream_plan_round(hole2, 3, WIN, &adv, &eof) == -1);
    CHECK(tpc_stream_plan_round(over, 2, WIN, &adv, &eof) == -1);
}

/* --- read_args: pathid in byte 0, the seven reserved bytes zero ---------------- */
static void
test_read_args(void)
{
    unsigned char args[TPC_READ_ARGS_LEN];
    unsigned char zero[TPC_READ_ARGS_LEN - 1] = { 0 };

    memset(args, 0xff, sizeof(args));
    tpc_stream_plan_read_args(args, 7);
    CHECK(args[0] == 7);
    CHECK(memcmp(args + 1, zero, sizeof(zero)) == 0);

    tpc_stream_plan_read_args(args, 0);
    CHECK(args[0] == 0);
    CHECK(TPC_READ_ARGS_LEN == 8);
}

int
main(void)
{
    test_clamp_success();
    test_clamp_error();
    test_clamp_security();
    test_round_success();
    test_round_eof();
    test_round_error();
    test_round_hole();
    test_read_args();

    if (g_fail != 0) {
        printf("%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
