/*
 * ops_fs.c — namespace / filesystem operations behind the xrdfs subcommands.
 *
 * WHAT: mkdir, rm, rmdir, mv, chmod, truncate, query, statvfs, locate, prepare.
 * WHY:  These make the native xrdfs feature-complete (M9) — the same opcode set
 *       the system xrdfs exposes — so the harness can drive every subcommand.
 * HOW:  Each builds its packed Client*Request (wire_write_extended_requests.h /
 *       wire_core_requests.h), big-endian fields, and exchanges one frame via
 *       xrdc_roundtrip so path-based ops transparently follow a cluster redirect.
 *       Mutating ops expect kXR_ok (no body); query/locate/statvfs return the
 *       server's text reply verbatim for the CLI to print.
 *
 * wire: kXR_mv payload is "src ' ' dst" with arg1len=len(src) (src/protocols/root/write/mv.c).
 * wire: kXR_locate reply is an "S<rw><host>:<port>" token (src/protocols/root/read/locate.c).
 */
#include "xrdc.h"

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
fs_simple(xrdc_conn *c, void *hdr24, const void *payload, uint32_t plen,
          xrdc_op_class cls, int benign_errno, xrdc_status *st)
{
    uint16_t status;
    uint8_t *body = NULL;
    uint32_t blen = 0;

    if (xrdc_roundtrip_resilient(c, hdr24, payload, plen, cls, benign_errno,
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
fs_text(xrdc_conn *c, void *hdr24, const void *payload, uint32_t plen,
        char *out, size_t outsz, xrdc_status *st)
{
    uint16_t status;
    uint8_t *body = NULL;
    uint32_t blen = 0;
    size_t   n;

    if (xrdc_roundtrip_resilient(c, hdr24, payload, plen, XRDC_OP_READONLY, 0,
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

int
xrdc_mkdir(xrdc_conn *c, const char *path, int mode, int parents, xrdc_status *st)
{
    ClientMkdirRequest req;
    memset(&req, 0, sizeof(req));
    req.requestid  = htons(kXR_mkdir);
    {
        xrdw_mkdir_req_t b = { .options = (uint8_t) (parents ? kXR_mkdirpath : 0),
                               .mode = (uint16_t) mode };
        xrdw_mkdir_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
    /* A resumed mkdir whose first attempt already landed reports EEXIST → success. */
    return fs_simple(c, &req, path, (uint32_t) strlen(path),
                     XRDC_OP_MUTATION_NORMALIZE, EEXIST, st);
}

int
xrdc_rm(xrdc_conn *c, const char *path, xrdc_status *st)
{
    ClientRmRequest req;
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_rm);
    xrdw_empty_req_pack(((ClientRequestHdr *) &req)->body);
    /* A resumed rm whose first attempt already landed reports ENOENT → success. */
    return fs_simple(c, &req, path, (uint32_t) strlen(path),
                     XRDC_OP_MUTATION_NORMALIZE, ENOENT, st);
}

int
xrdc_rmdir(xrdc_conn *c, const char *path, xrdc_status *st)
{
    ClientRmdirRequest req;
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_rmdir);
    xrdw_empty_req_pack(((ClientRequestHdr *) &req)->body);
    return fs_simple(c, &req, path, (uint32_t) strlen(path),
                     XRDC_OP_MUTATION_NORMALIZE, ENOENT, st);
}

int
xrdc_mv(xrdc_conn *c, const char *src, const char *dst, xrdc_status *st)
{
    ClientMvRequest req;
    char           *payload;
    size_t          sl = strlen(src), dl = strlen(dst), total = sl + 1 + dl;
    int             rc;

    if (sl == 0 || sl > 0x7fff) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "mv source path length out of range");
        return -1;
    }
    payload = (char *) malloc(total);
    if (payload == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
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
xrdc_chmod(xrdc_conn *c, const char *path, int mode, xrdc_status *st)
{
    ClientChmodRequest req;
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_chmod);
    {
        xrdw_chmod_req_t b = { .mode = (uint16_t) mode };
        xrdw_chmod_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
    /* Re-applying the same mode is harmless — retry freely. */
    return fs_simple(c, &req, path, (uint32_t) strlen(path),
                     XRDC_OP_IDEMPOTENT, 0, st);
}

int
xrdc_truncate(xrdc_conn *c, const char *path, int64_t size, xrdc_status *st)
{
    ClientTruncateRequest req;
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_truncate);
    {
        xrdw_truncate_req_t b = { .offset = size };   /* fhandle 0 = path-based */
        xrdw_truncate_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
    /* Truncating to the same size is idempotent — retry freely. */
    return fs_simple(c, &req, path, (uint32_t) strlen(path),
                     XRDC_OP_IDEMPOTENT, 0, st);
}

int
xrdc_query(xrdc_conn *c, int infotype, const char *args, char *out, size_t outsz,
           xrdc_status *st)
{
    ClientQueryRequest req;
    size_t             alen = (args != NULL) ? strlen(args) : 0;
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_query);
    {
        xrdw_query_req_t b = { .infotype = (uint16_t) infotype };
        xrdw_query_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
    return fs_text(c, &req, args, (uint32_t) alen, out, outsz, st);
}

int
xrdc_statvfs(xrdc_conn *c, const char *path, char *out, size_t outsz,
             xrdc_status *st)
{
    ClientStatRequest req;
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_stat);
    {
        xrdw_stat_req_t b = { .options = (uint8_t) kXR_vfs };
        xrdw_stat_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
    return fs_text(c, &req, path, (uint32_t) strlen(path), out, outsz, st);
}

int
xrdc_locate(xrdc_conn *c, const char *path, char *out, size_t outsz,
            xrdc_status *st)
{
    ClientLocateRequest req;
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_locate);
    {
        xrdw_locate_req_t b = { .options = 0 };
        xrdw_locate_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
    return fs_text(c, &req, path, (uint32_t) strlen(path), out, outsz, st);
}

int
xrdc_prepare(xrdc_conn *c, const char *const *paths, int npaths, int options,
             int optionX, int prty, char *out, size_t outsz, xrdc_status *st)
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
        xrdc_status_set(st, XRDC_EUSAGE, 0, "prepare needs at least one path");
        return -1;
    }
    payload = (char *) malloc(total);
    if (payload == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
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
