/* Observe the real streaming decoder and sink fan-out at arbitrary boundaries. */
#include "net/tap/tap.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

/* WHAT: Record decoded frames without borrowing their transient path buffer.
 * WHY: One input frame must yield exactly one sink event despite fragmentation.
 * HOW: Print bounded numeric fields and the captured path as hexadecimal. */
static void observe(void *context, const brix_tap_frame_t *frame,
    brix_tap_dir_t direction, const uint8_t *payload, size_t length)
{
    unsigned *count = context; (*count)++;
    assert(payload == NULL && length == 0 && frame->path_len <= BRIX_TAP_PATH_CAP);
    assert(frame->is_request == (direction == BRIX_TAP_C2U));
    printf("%u %u %u %u %u ", frame->streamid, frame->opcode, frame->status, frame->dlen, frame->errnum);
    if (!frame->path_len) { putchar('-'); }
    for (size_t i = 0; i < frame->path_len; i++) { printf("%02x", frame->path[i]); }
    putchar('\n');
}

int main(int argc, char **argv)
{
    assert(argc == 6); FILE *input = fopen(argv[1], "rb"); assert(input);
    size_t chunk = (size_t) strtoul(argv[3], NULL, 10); assert(chunk > 0 && chunk <= 4096);
    unsigned count = 0; brix_tap_ctx_t tap = {0}; brix_tap_stream_t stream;
    brix_tap_register_sink(&tap, observe, &count);
    brix_tap_stream_init(&stream, &tap, atoi(argv[2]) ? BRIX_TAP_U2C : BRIX_TAP_C2U);
    uint8_t bytes[4096]; size_t n;
    brix_tap_stream_feed(&stream, NULL, 0);
    while ((n = fread(bytes, 1, chunk, input)) != 0) { brix_tap_stream_feed(&stream, bytes, n); }
    assert(!ferror(input) && !fclose(input));
    assert(count == (unsigned) atoi(argv[4]));
    assert(stream.payload_left == strtoull(argv[5], NULL, 10));
    assert(!stream.preamble_skip && !stream.hdr_got == !stream.in_payload);
    return 0;
}
