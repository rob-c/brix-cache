/* Native paged-status parser: success, error, and hostile structural cases. */
#include "protocols/root/ops_internal.h"

#include <assert.h>
#include <sys/socket.h>
#include <unistd.h>

enum {
    MUTATE_NONE,
    MUTATE_CRC,
    MUTATE_BODY_SID,
    MUTATE_REQUEST,
    MUTATE_RESERVED,
    MUTATE_RESPTYPE
};

static void
put_u16(uint8_t *dst, uint16_t value)
{
    value = htons(value);
    memcpy(dst, &value, sizeof(value));
}

static void
put_u32(uint8_t *dst, uint32_t value)
{
    value = htonl(value);
    memcpy(dst, &value, sizeof(value));
}

static void
make_frame(uint8_t frame[32], int mutation)
{
    uint8_t *body = frame + XRD_RESPONSE_HDR_LEN;
    uint64_t offset = htobe64(UINT64_C(4095));

    memset(frame, 0, 32);
    put_u16(frame, 7);
    put_u16(frame + 2, kXR_status);
    put_u32(frame + 4, XRDC_PG_STATUSBODY);
    put_u16(body + 4, mutation == MUTATE_BODY_SID ? 8 : 7);
    body[6] = mutation == MUTATE_REQUEST ? 29
        : (uint8_t) (kXR_pgread - kXR_1stRequest);
    body[7] = mutation == MUTATE_RESPTYPE ? 9 : kXR_FinalResult;
    if (mutation == MUTATE_RESERVED) body[8] = 1;
    put_u32(body + 12, 4100);
    memcpy(body + 16, &offset, sizeof(offset));
    put_u32(body, brix_crc32c_value(body + 4, XRDC_PG_STATUSBODY - 4));
    if (mutation == MUTATE_CRC) body[0] ^= 0x80U;
}

static int
parse_frame(int mutation, brix_status *status)
{
    uint8_t frame[32];
    uint8_t resptype = 0xff;
    uint32_t pgdlen = 0;
    int64_t offset = 0;
    int pair[2];
    brix_conn connection;
    int result;

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    make_frame(frame, mutation);
    assert(send(pair[0], frame, sizeof(frame), 0) == (ssize_t) sizeof(frame));
    memset(&connection, 0, sizeof(connection));
    connection.io.fd = pair[1];
    connection.io.timeout_ms = 1000;
    brix_status_clear(status);
    result = read_status_frame(&connection, 7,
        kXR_pgread - kXR_1stRequest, &resptype, &pgdlen, &offset, status);
    close(pair[0]);
    close(pair[1]);
    if (mutation == MUTATE_NONE) {
        assert(result == 0);
        assert(resptype == kXR_FinalResult);
        assert(pgdlen == 4100);
        assert(offset == 4095);
    }
    return result;
}

int
main(void)
{
    brix_status status;

    assert(parse_frame(MUTATE_NONE, &status) == 0);
    assert(parse_frame(MUTATE_CRC, &status) == -1);
    assert(status.kxr == XRDC_EINTEGRITY);
    assert(parse_frame(MUTATE_BODY_SID, &status) == -1);
    assert(status.kxr == XRDC_EPROTO);
    assert(parse_frame(MUTATE_REQUEST, &status) == -1);
    assert(parse_frame(MUTATE_RESERVED, &status) == -1);
    assert(parse_frame(MUTATE_RESPTYPE, &status) == -1);
    puts("pg status unit: PASS");
    return 0;
}
