/*
 * io_xfer_unittest.c — standalone unit test for the TPC full-transfer loop.
 *
 *   gcc -Wall -Wextra -Werror -I src/tpc/outbound -o /tmp/tpc_xfer_ut \
 *       src/tpc/outbound/io_xfer_unittest.c src/tpc/outbound/io_xfer.c \
 *       -lssl -lcrypto && /tmp/tpc_xfer_ut
 *
 * Exit 0 = all checks pass. No nginx, no TPC context, no TLS handshake: the
 * loop is driven over a socketpair with ssl == NULL, which is the cleartext
 * path every TPC pull uses before (and unless) it upgrades on kXR_gotoTLS.
 *
 * What matters here is that a PARTIAL transfer never reports success. TPC wire
 * framing reads a fixed-size ServerResponseHdr and then a length-prefixed body,
 * so a loop that returns 0 having moved fewer bytes than asked leaves the
 * stream desynchronised — the next header is parsed out of body bytes, and an
 * attacker-controlled source could steer that. Hence the truncation cases.
 */

#include "io_xfer.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* A connected pair standing in for the origin socket. */
static void
mk_pair(int sv[2])
{
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
}

/* --- success: every byte moves, in both directions ------------------------ */

static void
test_send_then_receive_is_byte_exact(void)
{
    int  sv[2];
    char payload[4096];
    char got[4096];

    mk_pair(sv);
    memset(payload, 'A', sizeof(payload));
    memset(got, 0, sizeof(got));

    CHECK(brix_tpc_xfer_all(NULL, sv[0], payload, sizeof(payload),
                            BRIX_TPC_XFER_SEND) == 0);
    CHECK(brix_tpc_xfer_all(NULL, sv[1], got, sizeof(got),
                            BRIX_TPC_XFER_RECV) == 0);
    CHECK(memcmp(payload, got, sizeof(payload)) == 0);

    close(sv[0]);
    close(sv[1]);
}

static void
test_receive_reassembles_a_dribbled_stream(void)
{
    int  sv[2];
    char got[64];

    mk_pair(sv);
    memset(got, 0, sizeof(got));

    /* Three separate writes: the receive loop must return only once all 64
     * bytes have arrived, not after the first recv() returns 10. */
    CHECK(write(sv[0], "0123456789", 10) == 10);
    CHECK(write(sv[0], "abcdefghijklmnopqrstuvwxyz0123", 30) == 30);
    CHECK(write(sv[0], "ABCDEFGHIJKLMNOPQRSTUVWX", 24) == 24);

    CHECK(brix_tpc_xfer_all(NULL, sv[1], got, sizeof(got),
                            BRIX_TPC_XFER_RECV) == 0);
    CHECK(memcmp(got, "0123456789", 10) == 0);
    CHECK(got[63] == 'X');

    close(sv[0]);
    close(sv[1]);
}

static void
test_zero_length_is_a_noop_success(void)
{
    char sentinel = '\x7f';

    /* -1 is not a usable fd: a zero-length transfer must not touch it. */
    CHECK(brix_tpc_xfer_all(NULL, -1, &sentinel, 0, BRIX_TPC_XFER_SEND) == 0);
    CHECK(brix_tpc_xfer_all(NULL, -1, &sentinel, 0, BRIX_TPC_XFER_RECV) == 0);
    CHECK(sentinel == '\x7f');
}

/* --- error: a dead peer fails, it does not hang or half-succeed ------------ */

static void
test_receive_on_a_closed_peer_fails(void)
{
    int  sv[2];
    char got[16];

    mk_pair(sv);
    close(sv[0]);                       /* orderly close, nothing written */

    CHECK(brix_tpc_xfer_all(NULL, sv[1], got, sizeof(got),
                            BRIX_TPC_XFER_RECV) == -1);
    close(sv[1]);
}

static void
test_send_on_a_closed_peer_fails(void)
{
    int  sv[2];
    char payload[8];

    mk_pair(sv);
    memset(payload, 'z', sizeof(payload));
    close(sv[1]);

    /* SIGPIPE is ignored for the whole process in main(): it would kill the
     * test instead of letting send() return -1, and the nginx worker that
     * hosts a real pull runs with it ignored too. */
    CHECK(brix_tpc_xfer_all(NULL, sv[0], payload, sizeof(payload),
                            BRIX_TPC_XFER_SEND) == -1);
    close(sv[0]);
}

static void
test_invalid_fd_fails(void)
{
    char got[4];

    CHECK(brix_tpc_xfer_all(NULL, -1, got, sizeof(got),
                            BRIX_TPC_XFER_RECV) == -1);
}

/* --- security-negative: a truncated stream must never report success ------- */

static void
test_truncated_receive_is_not_a_success(void)
{
    int  sv[2];
    char got[32];

    mk_pair(sv);
    memset(got, 0, sizeof(got));

    /* 8 of the 32 requested bytes, then EOF: returning 0 here would hand the
     * caller 24 bytes of uninitialised buffer as though they were wire data. */
    CHECK(write(sv[0], "12345678", 8) == 8);
    close(sv[0]);

    CHECK(brix_tpc_xfer_all(NULL, sv[1], got, sizeof(got),
                            BRIX_TPC_XFER_RECV) == -1);
    close(sv[1]);
}

static void
test_a_short_frame_cannot_be_replayed_as_a_full_one(void)
{
    int  sv[2];
    char got[16];

    mk_pair(sv);
    memset(got, 0xEE, sizeof(got));

    CHECK(write(sv[0], "hdr", 3) == 3);
    close(sv[0]);

    /* The loop consumed the 3 real bytes and then failed. The tail must still
     * be the caller's fill, never something the loop invented to reach len. */
    CHECK(brix_tpc_xfer_all(NULL, sv[1], got, sizeof(got),
                            BRIX_TPC_XFER_RECV) == -1);
    CHECK(memcmp(got, "hdr", 3) == 0);
    CHECK((unsigned char) got[15] == 0xEE);

    close(sv[1]);
}

int
main(void)
{
    signal(SIGPIPE, SIG_IGN);

    test_send_then_receive_is_byte_exact();
    test_receive_reassembles_a_dribbled_stream();
    test_zero_length_is_a_noop_success();
    test_receive_on_a_closed_peer_fails();
    test_send_on_a_closed_peer_fails();
    test_invalid_fd_fails();
    test_truncated_receive_is_not_a_success();
    test_a_short_frame_cannot_be_replayed_as_a_full_one();

    if (g_fail != 0) {
        printf("%d check(s) FAILED\n", g_fail);
        return 1;
    }
    printf("io_xfer: all checks passed\n");
    return 0;
}
