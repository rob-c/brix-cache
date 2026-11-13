/* Native read/write and vector framing with finite response fragments.
 * Compression, wire codecs, bounds checks and buffer scatter remain real. */
#include "protocols/root/ops_internal.h"
#include <assert.h>
#include <stdio.h>

typedef struct {
    brix_conn connection;
    const char *operation, *mode;
    uint8_t plain[100000], response[160000];
    size_t length, response_length, position;
    unsigned sends, receives, reallocations, arms, disarms, steps;
    int codec, armed, sync, multi;
} fixture;
static fixture *state(void)
{
    const char *p = getenv("BRIX_RW_STATE");
    return p ? (fixture *)(uintptr_t) strtoull(p, NULL, 16) : NULL;
}
static int mode(const char *name) { return state() && !strcmp(state()->mode, name); }

void *__real_malloc(size_t);
void *__real_realloc(void *, size_t);
void *__wrap_malloc(size_t n)
{
    if (state() && state()->armed && mode("allocation")) { return NULL; }
    return __real_malloc(n);
}
void *__wrap_realloc(void *p, size_t n)
{
    fixture *f = state();
    if (f && f->armed) {
        unsigned index = f->reallocations++;
        if (mode("reallocation") || (mode("second-reallocation") && index == 1)) { return NULL; }
    }
    return __real_realloc(p, n);
}
void __wrap_brix_io_stall_arm(brix_io *io)
{
    assert(io == &state()->connection.io); state()->arms++;
}
void __wrap_brix_io_stall_disarm(brix_io *io)
{
    assert(io == &state()->connection.io); state()->disarms++;
}
brix_codec_rc_t __real_brix_codec_step(brix_codec_stream_t *, const uint8_t *, size_t,
    size_t *, uint8_t *, size_t, size_t *, int);
brix_codec_rc_t __wrap_brix_codec_step(brix_codec_stream_t *stream, const uint8_t *input,
    size_t length, size_t *in_pos, uint8_t *output, size_t capacity, size_t *out_pos, int finish)
{
    fixture *f = state();
    if (f->armed && mode("codec-stall")) { return BRIX_CODEC_OK; }
    if (f->armed && mode("codec-error")) { return BRIX_CODEC_ERR_DATA; }
    return __real_brix_codec_step(stream, input, length, in_pos, output, capacity, out_pos, finish);
}

static int sent(fixture *f, uint16_t *sid, brix_status *status)
{
    f->sends++; *sid = 7;
    if (mode("send")) { brix_status_set(status, XRDC_ESOCK, EPIPE, "send refused"); return -1; }
    return 0;
}

static void inspect_write(const ClientRequestHdr *header, const brix_payload *payload)
{
    fixture *f = state(); xrdw_write_req_t request; brix_status status = {0};
    uint8_t output[100000];
    xrdw_write_req_unpack(header->body, &request);
    assert(request.offset == 123 && memcmp(request.fhandle, "one1", 4) == 0);
    if (f->codec && f->length) {
        f->armed = 0;
        assert(brix_inflate_frame(f->codec, payload->data, payload->len, output,
                                  sizeof(output), &status) == (ssize_t) f->length);
        f->armed = 1;
        assert(memcmp(output, f->plain, f->length) == 0);
    } else {
        assert(payload->len == f->length && memcmp(payload->data, f->plain, f->length) == 0);
    }
}

int __wrap_brix_send(brix_conn *connection, void *raw, const brix_payload *payload,
                     uint16_t *sid, brix_status *status)
{
    fixture *f = state(); ClientRequestHdr *header = raw;
    assert(connection == &f->connection);
    switch (ntohs(header->requestid)) {
    case kXR_read: {
        xrdw_read_req_t request;
        xrdw_read_req_unpack(header->body, &request);
        assert(request.offset == 123 && request.rlen == (int32_t) f->length);
        assert(memcmp(request.fhandle, "one1", 4) == 0 && payload == NULL);
        break;
    }
    case kXR_write: inspect_write(header, payload); break;
    case kXR_readv:
        assert(payload->len == 32);
        assert(memcmp(payload->data, "one1", 4) == 0);
        assert(memcmp((const uint8_t *) payload->data + 16, f->multi ? "two2" : "one1", 4) == 0);
        break;
    default: assert(0);
    }
    return sent(f, sid, status);
}

int __wrap_brix_send_ext(brix_conn *connection, void *raw, const brix_payload_ext *payload,
                         uint16_t *sid, brix_status *status)
{
    fixture *f = state(); ClientRequestHdr *header = raw; xrdw_writev_req_t request;
    assert(connection == &f->connection && ntohs(header->requestid) == kXR_writev);
    xrdw_writev_req_unpack(header->body, &request);
    assert(request.options == (f->sync ? kXR_wv_doSync : 0));
    assert(payload->dlen == 32 && payload->len == 40);
    assert(memcmp((const uint8_t *) payload->data + 32, "abcdefgh", 8) == 0);
    assert(brix_readv_seg_rlen(payload->data) == 4);
    assert(brix_readv_seg_rlen((const uint8_t *) payload->data + 16) == 4);
    return sent(f, sid, status);
}

int __wrap_brix_recv(brix_conn *connection, uint16_t sid, brix_resp_out *out, brix_status *status)
{
    fixture *f = state(); size_t count;
    assert(connection == &f->connection && sid == 7); f->receives++;
    if (mode("receive") || (mode("receive-second") && f->receives == 2)) {
        brix_status_set(status, XRDC_ESOCK, ECONNRESET, "receive refused"); return -1;
    }
    count = f->response_length - f->position;
    if (count > 60000) { count = 60000; }
    if (mode("fragment") && count > 3) { count = 3; }
    *out->body = __real_malloc(count ? count : 1); assert(*out->body != NULL);
    memcpy(*out->body, f->response + f->position, count); f->position += count;
    *out->blen = (uint32_t) count;
    if (mode("vector-cap")) { *out->blen = XRDC_VEC_MAXBYTES + 1U; }
    *out->status = f->position < f->response_length ? kXR_oksofar : kXR_ok;
    return 0;
}

static void prepare_read(fixture *f)
{
    brix_status status = {0}; size_t n; uint8_t *compressed;
    if (f->codec) {
        compressed = brix_deflate_frame(BRIX_CODEC_GZIP, f->plain, f->length, &n, &status);
        assert(compressed != NULL && n < sizeof(f->response));
        memcpy(f->response, compressed, n); f->response_length = n; free(compressed);
    } else {
        memcpy(f->response, f->plain, f->length); f->response_length = f->length;
    }
    if (mode("corrupt")) { f->response[0] ^= 255; }
    if (mode("oversized")) { f->response_length = f->codec ? 5000 : f->length + 1; }
    if (mode("empty")) { f->response_length = 0; }
}

static void prepare_vector(fixture *f)
{
    brix_readv_seg_pack(f->response, (const uint8_t *) "one1", 4, 9);
    memcpy(f->response + 16, "abcd", 4);
    brix_readv_seg_pack(f->response + 20, (const uint8_t *) "two2", 4, 17);
    memcpy(f->response + 36, "efgh", 4); f->response_length = 40;
    if (mode("short-header")) { f->response_length = 8; }
    if (mode("short-body")) { f->response_length = 18; }
    if (mode("segment-overrun")) { brix_readv_seg_pack(f->response, (const uint8_t *) "one1", 5, 9); }
}

static ssize_t vector_read(fixture *f, brix_file *file, unsigned *partials, brix_status *status)
{
    char first[4] = {0}, second[4] = {0}; brix_file other = {0};
    brix_file *files[] = {file, &other};
    brix_readv_seg segments[] = {{.offset=9, .len=4, .buf=first}, {.offset=17, .len=4, .buf=second}};
    memcpy(other.fhandle, "two2", 4);
    size_t count = mode("count-zero") ? 0 : mode("count-large") ? XRDC_VEC_MAXSEGS + 1 : 2;
    ssize_t result = brix_readv_frames(&f->connection, file, f->multi ? files : NULL,
                                      segments, count, partials, status);
    if (result >= 0) {
        assert(result == 8 && memcmp(first, "abcd", 4) == 0 && memcmp(second, "efgh", 4) == 0);
        assert(segments[0].got == 4 && segments[1].got == 4);
    }
    return result;
}
static ssize_t vector_write(fixture *f, brix_file *file, brix_status *status)
{
    brix_writev_seg segments[] = {{.offset=9, .len=4, .data="abcd"}, {.offset=17, .len=4, .data="efgh"}};
    size_t count = mode("count-zero") ? 0 : mode("count-large") ? XRDC_VEC_MAXSEGS + 1 : 2;
    if (mode("single-cap")) { segments[0].len = XRDC_VEC_MAXBYTES + 1U; }
    if (mode("sum-cap")) { segments[0].len = XRDC_VEC_MAXBYTES; }
    return brix_file_writev(&f->connection, file, segments, count, f->sync, status);
}

int main(int argc, char **argv)
{
    fixture f = {0}; brix_file file = {0}; brix_status status = {0};
    char pointer[32]; uint8_t output[100000]; unsigned partials = 0; ssize_t result;
    uint32_t random = 42;
    assert(argc == 8); f.operation = argv[1]; f.mode = argv[2]; f.codec = atoi(argv[3]);
    f.length = (size_t) atoi(argv[4]); f.sync = atoi(argv[6]); f.multi = atoi(argv[6]);
    assert(f.length <= sizeof(f.plain));
    snprintf(pointer, sizeof(pointer), "%llx", (unsigned long long) (uintptr_t) &f);
    assert(setenv("BRIX_RW_STATE", pointer, 1) == 0);
    for (size_t i = 0; i < f.length; i++) {
        random ^= random << 13; random ^= random >> 17; random ^= random << 5;
        f.plain[i] = (uint8_t) random;
    }
    memcpy(file.fhandle, "one1", 4); file.read_codec = f.codec; file.write_codec = f.codec;
    if (!strcmp(f.operation, "read")) { prepare_read(&f); }
    if (!strcmp(f.operation, "readv")) { prepare_vector(&f); }
    f.armed = 1;
    if (!strcmp(f.operation, "read")) {
        result = brix_file_read_profile(&f.connection, &file, 123, output, f.length, &partials, &status);
        if (result > 0) { assert(result == (ssize_t) f.length && !memcmp(output, f.plain, f.length)); }
        assert(f.arms == 1 && f.disarms == 1);
    } else if (!strcmp(f.operation, "write")) {
        result = brix_file_write(&f.connection, &file, 123, f.plain, f.length, &status);
    } else if (!strcmp(f.operation, "readv")) { result = vector_read(&f, &file, &partials, &status); }
    else { assert(!strcmp(f.operation, "writev")); result = vector_write(&f, &file, &status); }
    f.armed = 0;
    assert(result == atoll(argv[5]));
    assert(partials == (unsigned) atoi(argv[7]));
    printf("sends=%u receives=%u partials=%u reallocations=%u\n%s\n",
        f.sends, f.receives, partials, f.reallocations, status.msg);
    return 0;
}
