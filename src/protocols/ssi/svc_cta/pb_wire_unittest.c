/*
 * pb_wire_unittest.c — standalone unit test for the protobuf wire primitives.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/pb_wire_ut \
 *       src/ssi/svc_cta/pb_wire_unittest.c src/ssi/svc_cta/pb_wire.c \
 *       && /tmp/pb_wire_ut
 */
#include "pb_wire.h"
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static int bytes_eq(const pb_writer *w, const char *hex)
{
    size_t n = strlen(hex) / 2, i;
    if (w->len != n) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        if (w->p[i] != (unsigned char) v) {
            return 0;
        }
    }
    return 1;
}

static void test_varint_roundtrip(void)
{
    static const uint64_t vals[] = {0, 1, 127, 128, 300, 0xFFFFFFFFu,
                                    (uint64_t) 1 << 63};
    unsigned char buf[32];
    size_t i;

    for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        pb_writer w = { buf, 0, sizeof(buf) };
        pb_reader r;
        uint64_t got = 0;
        CHECK(pb_write_varint(&w, vals[i]) == 0);
        r.p = buf; r.end = buf + w.len;
        CHECK(pb_read_varint(&r, &got) == 0);
        CHECK(got == vals[i]);
        CHECK(r.p == r.end);
    }
}

static void test_varint_encoding_golden(void)
{
    unsigned char buf[16];
    pb_writer w = { buf, 0, sizeof(buf) };
    CHECK(pb_write_varint(&w, 300) == 0);
    CHECK(bytes_eq(&w, "ac02"));          /* 300 = 0xAC 0x02 */
}

static void test_varint_truncated_rejected(void)
{
    /* high-bit set on the final byte → incomplete varint */
    const unsigned char bad[] = { 0xAC };
    pb_reader r = { bad, bad + sizeof(bad) };
    uint64_t out;
    CHECK(pb_read_varint(&r, &out) == -1);
}

static void test_tag_roundtrip(void)
{
    unsigned char buf[8];
    pb_writer w = { buf, 0, sizeof(buf) };
    pb_reader r;
    uint32_t field = 0;
    int wt = -1;
    CHECK(pb_write_tag(&w, 11, PB_WT_LEN) == 0);
    CHECK(w.len == 1 && w.p[0] == 0x5A);   /* (11<<3)|2 = 0x5A */
    r.p = buf; r.end = buf + w.len;
    CHECK(pb_read_tag(&r, &field, &wt) == 0);
    CHECK(field == 11 && wt == PB_WT_LEN);
}

static void test_len_delim_roundtrip(void)
{
    unsigned char buf[16];
    pb_writer w = { buf, 0, sizeof(buf) };
    pb_reader r;
    uint32_t field; int wt;
    const unsigned char *data; size_t len;
    CHECK(pb_write_string(&w, 3, "hi") == 0);
    r.p = buf; r.end = buf + w.len;
    CHECK(pb_read_tag(&r, &field, &wt) == 0);
    CHECK(field == 3 && wt == PB_WT_LEN);
    CHECK(pb_read_len_delim(&r, &data, &len) == 0);
    CHECK(len == 2 && memcmp(data, "hi", 2) == 0);
}

static void test_len_delim_overrun_rejected(void)
{
    /* tag len=5 but only 2 bytes follow */
    const unsigned char bad[] = { 0x1A, 0x05, 'a', 'b' };
    pb_reader r = { bad, bad + sizeof(bad) };
    uint32_t field; int wt;
    const unsigned char *data; size_t len;
    CHECK(pb_read_tag(&r, &field, &wt) == 0);
    CHECK(pb_read_len_delim(&r, &data, &len) == -1);
}

static void test_skip_field(void)
{
    /* varint field 1 = 5, then string field 3 = "ok" */
    unsigned char buf[16];
    pb_writer w = { buf, 0, sizeof(buf) };
    pb_reader r;
    uint32_t field; int wt;
    const unsigned char *data; size_t len;
    CHECK(pb_write_varint_field(&w, 1, 5) == 0);
    CHECK(pb_write_string(&w, 3, "ok") == 0);
    r.p = buf; r.end = buf + w.len;
    /* skip field 1 (varint) */
    CHECK(pb_read_tag(&r, &field, &wt) == 0 && field == 1);
    CHECK(pb_skip_field(&r, wt) == 0);
    /* read field 3 */
    CHECK(pb_read_tag(&r, &field, &wt) == 0 && field == 3);
    CHECK(pb_read_len_delim(&r, &data, &len) == 0);
    CHECK(len == 2 && memcmp(data, "ok", 2) == 0);
}

static void test_writer_overflow_rejected(void)
{
    unsigned char buf[1];
    pb_writer w = { buf, 0, sizeof(buf) };
    CHECK(pb_write_varint(&w, 300) == -1);   /* needs 2 bytes, cap 1 */
}

int main(void)
{
    test_varint_roundtrip();
    test_varint_encoding_golden();
    test_varint_truncated_rejected();
    test_tag_roundtrip();
    test_len_delim_roundtrip();
    test_len_delim_overrun_rejected();
    test_skip_field();
    test_writer_overflow_rejected();
    printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail);
    return g_fail ? 1 : 0;
}
