/*
 * cta_pb_unittest.c — standalone unit test for the CTA message codec.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/cta_pb_ut \
 *       src/ssi/svc_cta/cta_pb_unittest.c src/ssi/svc_cta/cta_pb.c \
 *       src/ssi/svc_cta/pb_wire.c && /tmp/cta_pb_ut
 *
 * Golden Request messages are built bottom-up with the (independently golden-
 * tested) pb_wire writers using the REAL CTA field numbers, so a build→decode
 * round-trip proves the decoder against byte-compatible CTA wire bytes.
 */
#include "cta_pb.h"
#include "pb_wire.h"
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* Build a cta.xrd.Request{ notification{ wf{event,instance{name}}, cli{user{u,g}},
 * file{lpath,archive_file_id} } } into out; returns total length. */
static size_t
build_request(uint64_t event, const char *inst, const char *user,
              const char *grp, const char *lpath, uint64_t afid,
              unsigned char *out, size_t cap)
{
    unsigned char svc[64], wf[128], rid[64], cli[128], file[1100], notif[1400];
    pb_writer ws = { svc,  0, sizeof(svc) };
    pb_writer ww = { wf,   0, sizeof(wf) };
    pb_writer wr = { rid,  0, sizeof(rid) };
    pb_writer wc = { cli,  0, sizeof(cli) };
    pb_writer wf2= { file, 0, sizeof(file) };
    pb_writer wn = { notif,0, sizeof(notif) };
    pb_writer wo = { out,  0, cap };

    /* Service{ name=1 } */
    pb_write_string(&ws, 1, inst);
    /* Workflow{ event=1 (varint), instance=5 (Service) } */
    pb_write_varint_field(&ww, 1, event);
    pb_write_len_delim(&ww, 5, svc, ws.len);
    /* RequesterId{ username=1, groupname=2 } */
    pb_write_string(&wr, 1, user);
    pb_write_string(&wr, 2, grp);
    /* Client{ user=1 (RequesterId) } */
    pb_write_len_delim(&wc, 1, rid, wr.len);
    /* Metadata{ lpath=11, archive_file_id=15 (varint) } */
    pb_write_string(&wf2, 11, lpath);
    pb_write_varint_field(&wf2, 15, afid);
    /* Notification{ wf=1, cli=2, file=4 } */
    pb_write_len_delim(&wn, 1, wf,   ww.len);
    pb_write_len_delim(&wn, 2, cli,  wc.len);
    pb_write_len_delim(&wn, 4, file, wf2.len);
    /* Request{ notification=1 } */
    pb_write_len_delim(&wo, 1, notif, wn.len);
    return wo.len;
}

static void test_decode_archive(void)
{
    unsigned char buf[2048];
    cta_request_t req;
    size_t n = build_request(4 /*CLOSEW*/, "eosdev", "alice", "eosusers",
                             "/eos/dev/file1", 42, buf, sizeof(buf));
    CHECK(cta_pb_decode_request(buf, n, &req) == 0);
    CHECK(req.op == CTA_OP_ARCHIVE);
    CHECK(strcmp(req.instance, "eosdev") == 0);
    CHECK(strcmp(req.owner_user, "alice") == 0);
    CHECK(strcmp(req.owner_group, "eosusers") == 0);
    CHECK(strcmp(req.path, "/eos/dev/file1") == 0);
    CHECK(req.archive_id == 42);
}

static void test_decode_retrieve(void)
{
    unsigned char buf[2048];
    cta_request_t req;
    size_t n = build_request(6 /*PREPARE*/, "eosp", "bob", "grp",
                             "/eos/p/f", 7, buf, sizeof(buf));
    CHECK(cta_pb_decode_request(buf, n, &req) == 0);
    CHECK(req.op == CTA_OP_RETRIEVE);
    CHECK(strcmp(req.path, "/eos/p/f") == 0);
}

static void test_decode_cancel(void)
{
    unsigned char buf[2048];
    cta_request_t req;
    size_t n = build_request(8 /*ABORT_PREPARE*/, "e", "u", "g", "/f", 0,
                             buf, sizeof(buf));
    CHECK(cta_pb_decode_request(buf, n, &req) == 0);
    CHECK(req.op == CTA_OP_CANCEL);
}

static void test_unknown_field_skipped(void)
{
    /* a top-level varint field 99 (unknown) before the notification → skipped */
    unsigned char buf[2048], full[2100];
    cta_request_t req;
    size_t n = build_request(4, "e", "u", "g", "/f", 1, buf, sizeof(buf));
    pb_writer w = { full, 0, sizeof(full) };
    pb_write_varint_field(&w, 99, 12345);          /* unknown field */
    memcpy(full + w.len, buf, n);                  /* then the real request */
    CHECK(cta_pb_decode_request(full, w.len + n, &req) == 0);
    CHECK(req.op == CTA_OP_ARCHIVE);
    CHECK(strcmp(req.path, "/f") == 0);
}

static void test_truncated_rejected(void)
{
    unsigned char buf[2048];
    cta_request_t req;
    size_t n = build_request(4, "e", "u", "g", "/f", 1, buf, sizeof(buf));
    /* chop the last few bytes → a length-delimited field overruns */
    CHECK(cta_pb_decode_request(buf, n - 3, &req) == -1);
}

static void test_encode_response(void)
{
    unsigned char out[256];
    size_t n = 0;
    pb_reader r;
    uint32_t f; int wt;
    int saw_type = 0, saw_msg = 0;

    CHECK(cta_pb_encode_response(CTA_RSP_SUCCESS, "ok", 0, out, sizeof(out), &n) == 0);
    CHECK(n > 0);
    /* decode back: type field 1 (varint) == 1, message_txt field 3 == "ok" */
    r.p = out; r.end = out + n;
    while (r.p < r.end) {
        CHECK(pb_read_tag(&r, &f, &wt) == 0);
        if (f == 1 && wt == PB_WT_VARINT) {
            uint64_t v; CHECK(pb_read_varint(&r, &v) == 0);
            CHECK(v == CTA_RSP_SUCCESS); saw_type = 1;
        } else if (f == 3 && wt == PB_WT_LEN) {
            const unsigned char *d; size_t L;
            CHECK(pb_read_len_delim(&r, &d, &L) == 0);
            CHECK(L == 2 && memcmp(d, "ok", 2) == 0); saw_msg = 1;
        } else {
            CHECK(pb_skip_field(&r, wt) == 0);
        }
    }
    CHECK(saw_type && saw_msg);
}

static void test_encode_error_response(void)
{
    unsigned char out[256];
    size_t n = 0;
    pb_reader r;
    uint32_t f; int wt;
    uint64_t type = 0;

    CHECK(cta_pb_encode_response(CTA_RSP_ERR_USER, "bad path", 0,
                                 out, sizeof(out), &n) == 0);
    r.p = out; r.end = out + n;
    CHECK(pb_read_tag(&r, &f, &wt) == 0 && f == 1 && wt == PB_WT_VARINT);
    CHECK(pb_read_varint(&r, &type) == 0);
    CHECK(type == CTA_RSP_ERR_USER);
}

static void test_encode_stream_header(void)
{
    unsigned char resp[128], stream[256];
    size_t rn = 0, sn = 0;
    pb_reader r;
    uint32_t f; int wt;
    const unsigned char *d; size_t L;

    CHECK(cta_pb_encode_response(CTA_RSP_SUCCESS, "list", 0, resp, sizeof(resp), &rn) == 0);
    CHECK(cta_pb_encode_stream_header(resp, rn, stream, sizeof(stream), &sn) == 0);
    /* StreamResponse.header is field 1 (len-delim), wrapping the Response */
    r.p = stream; r.end = stream + sn;
    CHECK(pb_read_tag(&r, &f, &wt) == 0 && f == 1 && wt == PB_WT_LEN);
    CHECK(pb_read_len_delim(&r, &d, &L) == 0);
    CHECK(L == rn && memcmp(d, resp, rn) == 0);
}

int main(void)
{
    test_decode_archive();
    test_decode_retrieve();
    test_decode_cancel();
    test_unknown_field_skipped();
    test_truncated_rejected();
    test_encode_response();
    test_encode_error_response();
    test_encode_stream_header();
    printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail);
    return g_fail ? 1 : 0;
}
