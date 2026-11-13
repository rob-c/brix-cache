/* Real synchronous handle-stat framing over a bounded socketpair peer. */
#include "brix.h"
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    int fd;
    const char *body;
    size_t length;
    int wrong_stream;
} stat_peer;

/* WHAT: Answer one handle-stat request with a selected wire body.
 * WHY: Malformed remote metadata must never be adopted as a local stat.
 * HOW: Validate the exact request and use the real I/O helpers for the reply. */
static void *
answer_stat(void *opaque)
{
    stat_peer *peer = opaque;
    uint8_t request[24], reply[8];
    uint16_t code;
    uint32_t length;
    xrdw_stat_req_t fields;
    brix_io io = {0};
    brix_status status;

    io.fd = peer->fd;
    io.timeout_ms = 1000;
    brix_status_clear(&status);
    assert(brix_read_full(&io, request, sizeof(request), &status) == 0);
    memcpy(&code, request + 2, sizeof(code));
    assert(ntohs(code) == kXR_stat);
    assert(xrdw_stat_req_unpack(request + 4, &fields) == XRDW_OK);
    assert(memcmp(fields.fhandle, "abcd", 4) == 0);
    assert(memcmp(request + 20, "\0\0\0\0", 4) == 0);
    memcpy(reply, request, 2);
    if (peer->wrong_stream) { reply[1] ^= 1; }
    code = htons(kXR_ok);
    memcpy(reply + 2, &code, sizeof(code));
    length = htonl((uint32_t) peer->length);
    memcpy(reply + 4, &length, sizeof(length));
    assert(brix_write_full(&io, reply, sizeof(reply), &status) == 0);
    assert(brix_write_full(&io, peer->body, peer->length, &status) == 0);
    close(peer->fd);
    return NULL;
}

/* WHAT: Execute one finite parser contract against real transport framing.
 * WHY: Success, malformed bodies and cross-stream replies need distinct checks.
 * HOW: Own the peer thread, connection and socket pair until both sides finish. */
static void
check_reply(const char *body, size_t length, int wrong_stream, int succeeds)
{
    int pair[2];
    pthread_t thread;
    brix_conn connection = {0};
    brix_file file = {0};
    brix_statinfo info = {0};
    brix_status status;
    stat_peer peer = {0};
    int result;

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    connection.io.fd = pair[0];
    connection.io.timeout_ms = 1000;
    memcpy(file.fhandle, "abcd", 4);
    peer.fd = pair[1]; peer.body = body; peer.length = length;
    peer.wrong_stream = wrong_stream;
    assert(pthread_create(&thread, NULL, answer_stat, &peer) == 0);
    brix_status_clear(&status);
    result = brix_file_stat(&connection, &file, &info, &status);
    assert((result == 0) == succeeds);
    if (succeeds) {
        assert(info.id == 123 && info.size == 456 && info.mtime == 789);
    } else {
        assert(status.kxr == XRDC_EPROTO);
    }
    assert(pthread_join(thread, NULL) == 0);
    close(pair[0]);
}

int
main(void)
{
    const char valid[] = "123 456 0 789";
    char oversized[1024];
    memset(oversized, 'x', sizeof(oversized));
    check_reply(valid, strlen(valid), 0, 1);
    check_reply(valid, sizeof(valid), 0, 1);
    check_reply("", 0, 0, 0);
    check_reply("untrusted metadata", 18, 0, 0);
    check_reply(oversized, sizeof(oversized), 0, 0);
    check_reply(valid, strlen(valid), 1, 0);
    puts("ALL PASS: handle stat framing and metadata");
    return 0;
}
