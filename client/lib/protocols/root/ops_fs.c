/*
 * ops_fs.c — namespace / filesystem operations behind the xrdfs subcommands.
 *
 * WHAT: mkdir, rm, rmdir, mv, chmod, truncate, query, statvfs, locate, prepare.
 * WHY:  These make the native xrdfs feature-complete (M9) — the same opcode set
 *       the system xrdfs exposes — so the harness can drive every subcommand.
 * HOW:  Each builds its packed Client*Request (wire_write_extended_requests.h /
 *       wire_core_requests.h), big-endian fields, and exchanges one frame via
 *       brix_roundtrip so path-based ops transparently follow a cluster redirect.
 *       Mutating ops expect kXR_ok (no body); query/locate/statvfs return the
 *       server's text reply verbatim for the CLI to print.
 *
 * wire: kXR_mv payload is "src ' ' dst" with arg1len=len(src) (src/protocols/root/write/mv.c).
 * wire: kXR_locate reply is an "S<rw><host>:<port>" token (src/protocols/root/read/locate.c).
 */
#include "brix.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Send one path-style request via the redirect-aware AND resilient roundtrip and
 * require a kXR_ok with no meaningful body (mkdir/rm/rmdir/mv/chmod/truncate).
 * cls/benign_errno tune re-issue after a sever (every tool inherits this). */
static int
fs_simple(brix_conn *c, void *hdr24, const void *payload, uint32_t plen,
          brix_op_class cls, int benign_errno, brix_status *st)
{
    uint16_t status;
    uint8_t *body = NULL;
    uint32_t blen = 0;

    if (brix_roundtrip_resilient(c, hdr24, payload, plen, cls, benign_errno,
                                 &status, &body, &blen, st) != 0) {
        return -1;
    }
    free(body);
    return 0;
}

/* Send a request whose kXR_ok body is a text reply; copy it (NUL-terminated,
 * trailing CR/LF trimmed) into out[outsz]. Read-only/idempotent (query / locate /
 * statvfs / prepare): safe to retry freely on a sever. */
static int
fs_text(brix_conn *c, void *hdr24, const void *payload, uint32_t plen,
        char *out, size_t outsz, brix_status *st)
{
    uint16_t status;
    uint8_t *body = NULL;
    uint32_t blen = 0;
    size_t   n;

    if (brix_roundtrip_resilient(c, hdr24, payload, plen, XRDC_OP_READONLY, 0,
                                 &status, &body, &blen, st) != 0) {
        return -1;
    }
    n = (blen < outsz - 1) ? blen : outsz - 1;
    memcpy(out, body, n);
    out[n] = '\0';
    free(body);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r')) {
        out[--n] = '\0';
    }
    return 0;
}

/* fs_simple on a bare-path payload (plen = strlen(path)) — every path-based
 * mutation below runs through this. */
static int
fs_path(brix_conn *c, void *hdr24, const char *path, int op_class,
        int benign_errno, brix_status *st)
{
    return fs_simple(c, hdr24, path, (uint32_t) strlen(path), op_class,
                     benign_errno, st);
}

/* Declare + build the 24-byte request every fs op sends: zero `req`, stamp the
 * request id, pack the body word via the matching xrdw_<op>_req writer (FS_REQ
 * takes the body initializer; FS_REQ_EMPTY packs the all-zero body). One shared
 * spelling so the build discipline cannot drift between ops. */
#define FS_REQ(REQT, reqid, op, ...) \
    REQT req; \
    memset(&req, 0, sizeof(req)); \
    req.requestid = htons(reqid); \
    { \
        xrdw_##op##_req_t b_ = __VA_ARGS__; \
        xrdw_##op##_req_pack(&b_, ((ClientRequestHdr *) &req)->body); \
    }

#define FS_REQ_EMPTY(REQT, reqid) \
    REQT req; \
    memset(&req, 0, sizeof(req)); \
    req.requestid = htons(reqid); \
    xrdw_empty_req_pack(((ClientRequestHdr *) &req)->body)

int
brix_mkdir(brix_conn *c, const char *path, int mode, int parents, brix_status *st)
{
    FS_REQ(ClientMkdirRequest, kXR_mkdir, mkdir,
           { .options = (uint8_t) (parents ? kXR_mkdirpath : 0),
             .mode = (uint16_t) mode });
    /* A resumed mkdir whose first attempt already landed reports EEXIST → success. */
    return fs_path(c, &req, path, XRDC_OP_MUTATION_NORMALIZE, EEXIST, st);
}

int
brix_rm(brix_conn *c, const char *path, brix_status *st)
{
    FS_REQ_EMPTY(ClientRmRequest, kXR_rm);
    /* A resumed rm whose first attempt already landed reports ENOENT → success. */
    return fs_path(c, &req, path, XRDC_OP_MUTATION_NORMALIZE, ENOENT, st);
}

int
brix_rmdir(brix_conn *c, const char *path, brix_status *st)
{
    FS_REQ_EMPTY(ClientRmdirRequest, kXR_rmdir);
    return fs_path(c, &req, path, XRDC_OP_MUTATION_NORMALIZE, ENOENT, st);
}

int
brix_mv(brix_conn *c, const char *src, const char *dst, brix_status *st)
{
    ClientMvRequest req;
    char           *payload;
    size_t          sl = strlen(src), dl = strlen(dst), total = sl + 1 + dl;
    int             rc;

    if (sl == 0 || sl > 0x7fff) {
        brix_status_set(st, XRDC_EUSAGE, 0, "mv source path length out of range");
        return -1;
    }
    payload = (char *) malloc(total);
    if (payload == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }
    /* wire: src + ' ' + dst; arg1len = len(src). */
    memcpy(payload, src, sl);
    payload[sl] = ' ';
    memcpy(payload + sl + 1, dst, dl);

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_mv);
    {
        xrdw_twopath_req_t b = { .arg1len = (int16_t) sl };
        xrdw_twopath_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    /* A resumed mv whose first attempt already moved the file reports ENOENT on
     * the (now-absent) source → success. */
    rc = fs_simple(c, &req, payload, (uint32_t) total,
                   XRDC_OP_MUTATION_NORMALIZE, ENOENT, st);
    free(payload);
    return rc;
}

int
brix_chmod(brix_conn *c, const char *path, int mode, brix_status *st)
{
    FS_REQ(ClientChmodRequest, kXR_chmod, chmod, { .mode = (uint16_t) mode });
    /* Re-applying the same mode is harmless — retry freely. */
    return fs_path(c, &req, path, XRDC_OP_IDEMPOTENT, 0, st);
}

int
brix_truncate(brix_conn *c, const char *path, int64_t size, brix_status *st)
{
    /* offset with fhandle 0 = path-based truncate. */
    FS_REQ(ClientTruncateRequest, kXR_truncate, truncate, { .offset = size });
    /* Truncating to the same size is idempotent — retry freely. */
    return fs_path(c, &req, path, XRDC_OP_IDEMPOTENT, 0, st);
}

int
brix_query(brix_conn *c, int infotype, const char *args, char *out, size_t outsz,
           brix_status *st)
{
    FS_REQ(ClientQueryRequest, kXR_query, query, { .infotype = (uint16_t) infotype });
    return fs_text(c, &req, args, args ? (uint32_t) strlen(args) : 0, out, outsz, st);
}

int
brix_statvfs(brix_conn *c, const char *path, char *out, size_t outsz,
             brix_status *st)
{
    FS_REQ(ClientStatRequest, kXR_stat, stat, { .options = (uint8_t) kXR_vfs });
    return fs_text(c, &req, path, (uint32_t) strlen(path), out, outsz, st);
}

int
brix_locate(brix_conn *c, const char *path, char *out, size_t outsz,
            brix_status *st)
{
    FS_REQ(ClientLocateRequest, kXR_locate, locate, { .options = 0 });
    return fs_text(c, &req, path, (uint32_t) strlen(path), out, outsz, st);
}

int
brix_prepare(brix_conn *c, const char *const *paths, int npaths, int options,
             int optionX, int prty, char *out, size_t outsz, brix_status *st)
{
    ClientPrepareRequest req;
    char                *payload;
    size_t               total = 0;
    int                  i, rc;
    char                *p;

    for (i = 0; i < npaths; i++) {
        total += strlen(paths[i]) + 1;   /* path + '\n' (or final, see below) */
    }
    if (total == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0, "prepare needs at least one path");
        return -1;
    }
    payload = (char *) malloc(total);
    if (payload == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }
    /* Newline-separated paths (no trailing newline). */
    p = payload;
    for (i = 0; i < npaths; i++) {
        size_t L = strlen(paths[i]);
        memcpy(p, paths[i], L);
        p += L;
        if (i + 1 < npaths) {
            *p++ = '\n';
        }
    }

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_prepare);
    {
        xrdw_prepare_req_t b = { .options = (uint8_t) (options ? options : kXR_stage),
                                 .prty = (uint8_t) (prty & 0x03),
                                 .port = 0,
                                 .optionX = (uint16_t) optionX };
        xrdw_prepare_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    rc = fs_text(c, &req, payload, (uint32_t) (p - payload), out, outsz, st);
    free(payload);
    return rc;
}
