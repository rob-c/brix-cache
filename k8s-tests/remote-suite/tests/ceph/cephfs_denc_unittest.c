/*
 * cephfs_denc_unittest.c — standalone unit tests for the Ceph decode primitives.
 *
 * Pure C, no cluster, no nginx. Builds Ceph-encoded byte buffers by hand (the
 * encoding is fixed: little-endian ints, u32-length-prefixed strings, and the
 * struct_v/compat/u32-len ENCODE_START frame) and asserts cephfs_denc decodes
 * them, including overrun safety and forward-compatible field skipping.
 *
 *   cc -I src/fs/backend/rados tests/ceph/cephfs_denc_unittest.c \
 *      src/fs/backend/rados/cephfs_denc.c -o /tmp/denc_test && /tmp/denc_test
 */
#include "cephfs_denc.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);           \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* ---- fixed-width little-endian integers ---------------------------------- */
static void
test_integers(void)
{
    /* u8=0x01, u16=0x0302, u32=0x07060504, u64=0x0f0e0d0c0b0a0908 */
    const uint8_t buf[] = {
        0x01,
        0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    cephfs_denc_t d;

    cephfs_denc_init(&d, buf, sizeof(buf));
    CHECK(cephfs_denc_u8(&d)  == 0x01);
    CHECK(cephfs_denc_u16(&d) == 0x0302);
    CHECK(cephfs_denc_u32(&d) == 0x07060504u);
    CHECK(cephfs_denc_u64(&d) == 0x0f0e0d0c0b0a0908ull);
    CHECK(cephfs_denc_ok(&d));
    CHECK(cephfs_denc_remaining(&d) == 0);
}

/* a negative s64 must round-trip (two's complement, little-endian) */
static void
test_signed(void)
{
    const uint8_t buf[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; /* -1 */
    cephfs_denc_t d;

    cephfs_denc_init(&d, buf, sizeof(buf));
    CHECK(cephfs_denc_s64(&d) == (int64_t) -1);
    CHECK(cephfs_denc_ok(&d));
}

/* ---- length-prefixed string ---------------------------------------------- */
static void
test_string(void)
{
    const uint8_t buf[] = { 0x03, 0x00, 0x00, 0x00, 'a', 'b', 'c', 0x42 };
    cephfs_denc_t d;
    const char   *s = NULL;
    uint32_t      len = 0;

    cephfs_denc_init(&d, buf, sizeof(buf));
    CHECK(cephfs_denc_str(&d, &s, &len) == 0);
    CHECK(len == 3);
    CHECK(s != NULL && memcmp(s, "abc", 3) == 0);
    /* the trailing 0x42 is still readable after the string */
    CHECK(cephfs_denc_u8(&d) == 0x42);
    CHECK(cephfs_denc_ok(&d));
}

/* ---- ENCODE_START frame + forward-compatible skip ------------------------ */
static void
test_frame_forward_skip(void)
{
    /* frame: struct_v=2, compat=1, struct_len=8; payload = u32(0x11223344) then
     * 4 trailing bytes a newer encoder added. A v1-aware decoder reads only the
     * u32 and finish()es past the rest. After the frame: a u16(0x00ff). */
    const uint8_t buf[] = {
        0x02, 0x01, 0x08, 0x00, 0x00, 0x00,             /* v, compat, len=8     */
        0x44, 0x33, 0x22, 0x11,                         /* u32 we understand    */
        0xde, 0xad, 0xbe, 0xef,                         /* trailing, to skip    */
        0xff, 0x00,                                     /* after the frame      */
    };
    cephfs_denc_t       d;
    cephfs_denc_frame_t f;

    cephfs_denc_init(&d, buf, sizeof(buf));
    CHECK(cephfs_denc_start(&d, &f) == 2);
    CHECK(f.struct_v == 2 && f.struct_compat == 1);
    CHECK(cephfs_denc_u32(&d) == 0x11223344u);
    cephfs_denc_finish(&d, &f);                         /* skip trailing 4 bytes */
    CHECK(cephfs_denc_u16(&d) == 0x00ffu);
    CHECK(cephfs_denc_ok(&d));
}

/* ---- overrun safety ------------------------------------------------------ */
static void
test_overrun(void)
{
    const uint8_t buf[] = { 0x01, 0x02 };
    cephfs_denc_t d;

    cephfs_denc_init(&d, buf, sizeof(buf));
    CHECK(cephfs_denc_u32(&d) == 0);   /* only 2 bytes — overrun */
    CHECK(!cephfs_denc_ok(&d));
    /* once errored, further reads stay safe no-ops */
    CHECK(cephfs_denc_u8(&d) == 0);
    CHECK(!cephfs_denc_ok(&d));
}

/* a frame whose declared length runs past the buffer is rejected */
static void
test_frame_bad_len(void)
{
    const uint8_t buf[] = { 0x01, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00 }; /* len=255 */
    cephfs_denc_t       d;
    cephfs_denc_frame_t f;

    cephfs_denc_init(&d, buf, sizeof(buf));
    CHECK(cephfs_denc_start(&d, &f) == 0);
    CHECK(!cephfs_denc_ok(&d));
}

/* raw byte run + skip */
static void
test_bytes_skip(void)
{
    const uint8_t  buf[] = { 0x10, 0x11, 0x12, 0x13, 0x14 };
    cephfs_denc_t  d;
    const uint8_t *p;

    cephfs_denc_init(&d, buf, sizeof(buf));
    p = cephfs_denc_bytes(&d, 2);
    CHECK(p != NULL && p[0] == 0x10 && p[1] == 0x11);
    cephfs_denc_skip(&d, 1);                            /* skip 0x12 */
    CHECK(cephfs_denc_u8(&d) == 0x13);
    CHECK(cephfs_denc_ok(&d));
    CHECK(cephfs_denc_bytes(&d, 5) == NULL);            /* overrun */
    CHECK(!cephfs_denc_ok(&d));
}

int
main(void)
{
    test_integers();
    test_signed();
    test_string();
    test_frame_forward_skip();
    test_overrun();
    test_frame_bad_len();
    test_bytes_skip();

    if (failures == 0) {
        printf("cephfs_denc_unittest: ALL PASS\n");
        return 0;
    }
    printf("cephfs_denc_unittest: %d FAILURE(S)\n", failures);
    return 1;
}
