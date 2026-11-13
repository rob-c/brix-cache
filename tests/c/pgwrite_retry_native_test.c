/* Real page-write encoding and CSE repair over an observed finite transport. */
#include "protocols/root/ops_internal.h"
#include <assert.h>

typedef struct {
    brix_conn connection;
    const char *mode;
    int64_t base, sent_offset;
    size_t length;
    unsigned sends, bodies;
    uint8_t data[9000], trailer[40];
    uint32_t trailer_size;
} fixture;

/* WHAT: Select a fault. WHY: Keep scenarios independent. HOW: Fixture string. */
static int mode(const fixture *f, const char *name) { return !strcmp(f->mode, name); }

void *__real_malloc(size_t);
/* WHAT: Fail one allocation. WHY: Prove clean OOM handling. HOW: One-shot arm. */
void *__wrap_malloc(size_t size)
{
    if (getenv("BRIX_PGW_ALLOC")) {
        assert(unsetenv("BRIX_PGW_ALLOC") == 0); errno = ENOMEM; return NULL;
    }
    return __real_malloc(size);
}

/* WHAT: Check wire payload against source bytes. WHY: Retries must slice one page.
 * HOW: Canonical decode plus independent extent and content assertions. */
static void check_payload(fixture *f, ClientRequestHdr *header, const brix_payload *payload)
{
    xrdw_pgwrite_req_t request;
    uint8_t decoded[9000]; int64_t bad = -1;
    size_t offset, length;
    xrdw_pgwrite_req_unpack(header->body, &request);
    assert(ntohs(header->requestid) == kXR_pgwrite);
    assert(memcmp(request.fhandle, "file", 4) == 0 && request.pathid == 0);
    assert(request.offset >= f->base); offset = (size_t) (request.offset - f->base);
    assert(offset < f->length || f->length == 0);
    length = f->length - offset;
    if (f->sends > 1) {
        size_t boundary = kXR_pgPageSZ - (size_t) (request.offset % kXR_pgPageSZ);
        assert(request.reqflags == kXR_pgRetry);
        length = length < boundary ? length : boundary;
    } else { assert(request.reqflags == 0 && request.offset == f->base); }
    assert(xrdp_pg_decode(payload->data, payload->len, request.offset,
        decoded, sizeof(decoded), &bad) == (ssize_t) length);
    assert(memcmp(decoded, f->data + offset, length) == 0);
    f->sent_offset = request.offset;
    printf("SEND %lld %zu\n", (long long) request.offset, length);
}

/* WHAT: Observe sent requests. WHY: Error recovery must not lose page boundaries.
 * HOW: Count calls, inspect bytes, then inject a selected transport failure. */
int __wrap_brix_send(brix_conn *c, void *header, const brix_payload *payload,
    uint16_t *sid, brix_status *st)
{
    fixture *f = (fixture *) c; f->sends++; *sid = (uint16_t) f->sends;
    check_payload(f, header, payload);
    if (mode(f, "send-error") || (mode(f, "retry-send-error") && f->sends > 1)) {
        brix_status_set(st, XRDC_ESOCK, EPIPE, "send failed"); return -1;
    }
    return 0;
}

/* WHAT: Build a valid server CSE list. WHY: Repair must follow each advertised page.
 * HOW: Encode offsets using repository wire types and compute the trailer CRC. */
static void make_trailer(fixture *f)
{
    unsigned count = 0; int64_t off = f->base; uint32_t crc;
    uint16_t first, last;
    memset(f->trailer, 0, sizeof(f->trailer));
    while ((uint64_t) (off - f->base) < f->length) {
        uint64_t wire;
        int64_t selected = off;
        if (mode(f, "before-base")) { selected = f->base - 1; }
        if (mode(f, "after-end")) { selected = f->base + (int64_t) f->length; }
        wire = htobe64((uint64_t) selected);
        assert(count < 4); memcpy(f->trailer + 8 + 8 * count++, &wire, 8);
        off += kXR_pgPageSZ - off % kXR_pgPageSZ;
    }
    f->trailer_size = 8 + count * 8;
    if (mode(f, "empty-cse")) { f->trailer_size = 8; }
    first = (uint16_t) (kXR_pgPageSZ - f->base % kXR_pgPageSZ);
    if (first > f->length) { first = (uint16_t) f->length; }
    last = count <= 1 ? first : (uint16_t) ((f->base + f->length - 1) % kXR_pgPageSZ + 1);
    first = htons(first); last = htons(last);
    memcpy(f->trailer + 4, &first, 2); memcpy(f->trailer + 6, &last, 2);
    crc = htonl(brix_crc32c_value(f->trailer + 4, f->trailer_size - 4));
    memcpy(f->trailer, &crc, 4);
}

/* WHAT: Provide status framing results. WHY: The production CSE walker owns repair.
 * HOW: Return the selected offsets, trailer size, and finite bad-page verdicts. */
int __wrap_read_status_frame(brix_conn *c, uint16_t sid, uint8_t delta,
    uint8_t *type, uint32_t *size, int64_t *offset, brix_status *st)
{
    fixture *f = (fixture *) c;
    assert(sid == f->sends && delta == kXR_pgwrite - kXR_1stRequest);
    if (mode(f, "frame-error") || (mode(f, "retry-frame-error") && f->sends > 1)) {
        brix_status_set(st, XRDC_ESOCK, EIO, "frame failed"); return -1;
    }
    *type = kXR_FinalResult; *offset = f->sent_offset; *size = 0;
    if (mode(f, "offset") || (mode(f, "retry-offset") && f->sends > 1)) { (*offset)++; }
    if (mode(f, "clean")) { return 0; }
    if (f->sends == 1 || mode(f, "uncorrectable") || (mode(f, "twice-bad") && f->sends < 4)) {
        *size = f->trailer_size;
    }
    if (!strncmp(f->mode, "malformed", 9)) { *size = (uint32_t) atoi(f->mode + 9); }
    if (mode(f, "cse-allocation")) { assert(setenv("BRIX_PGW_ALLOC", "1", 1) == 0); }
    return 0;
}

/* WHAT: Deliver a trailer. WHY: Short transport reads must terminate repair.
 * HOW: Copy independently encoded data or return the chosen I/O error. */
int __wrap_brix_read_full(brix_io *io, void *buffer, size_t size, brix_status *st)
{
    fixture *f = (fixture *) ((char *) io - offsetof(brix_conn, io)); f->bodies++;
    assert(size <= sizeof(f->trailer));
    if (mode(f, "body-error")) {
        brix_status_set(st, XRDC_ESOCK, EIO, "body failed"); return -1;
    }
    memcpy(buffer, f->trailer, size); return 0;
}

/* WHAT: Execute one page repair scenario. WHY: Check terminal status and budgets.
 * HOW: Stack-owned connection, deterministic data, and explicit expected results. */
int main(int argc, char **argv)
{
    fixture f = {0}; brix_file file = {0}; brix_status st = {0}; int rc;
    assert(argc == 7); f.mode = argv[1]; f.base = atoll(argv[2]); f.length = (size_t) atoi(argv[3]);
    assert(f.length < sizeof(f.data)); memcpy(file.fhandle, "file", 4);
    for (size_t i = 0; i < f.length; i++) { f.data[i] = (uint8_t) (i % 251); }
    make_trailer(&f);
    if (mode(&f, "allocation")) { assert(setenv("BRIX_PGW_ALLOC", "1", 1) == 0); }
    rc = brix_file_pgwrite(&f.connection, &file, f.base, f.data, f.length, &st);
    printf("RESULT %d STATUS %d sends=%u bodies=%u %s\n", rc, st.kxr, f.sends, f.bodies, st.msg);
    assert(rc == atoi(argv[4]) && st.kxr == atoi(argv[5]) && f.sends == (unsigned) atoi(argv[6]));
    return 0;
}
