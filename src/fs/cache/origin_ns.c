/*
 * cache/origin_ns.c — origin-side namespace + extended-attribute operations for
 * cache write-through / mirroring: kXR_mv (rename), kXR_rm, and kXR_fattr
 * get/list/set/del against the upstream origin.  Split out of origin_protocol.c
 * so that file stays focused on the connection bootstrap + read/write data path,
 * and the namespace-mutation surface is reviewed on its own.  The public
 * brix_cache_origin_{rename,rm,getfattr,listfattr,setfattr,delfattr}() are
 * declared in cache_internal.h.
 */

#include "cache_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared request packers */
#include "core/compat/fattr_codec.h"        /* xrdp_fattr_nvec_parse (kXR_fattr replies) */
#include "protocols/root/protocol/frame_hdr.h"        /* xrd_error_body_decode (kXR_error errnum) */
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* origin_request — send a generic 24-byte ClientRequestHdr (requestid + packed
 * `body`) plus `payload`, then read the response into (*status, *rbody, *rdlen).
 * The caller owns *rbody (free it). Returns 0 (response received — check *status)
 * or -1 on a transport failure.  Shared by the namespace/fattr ops below. */
static int
origin_request(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    uint16_t requestid, const uint8_t body[XRDW_BODY_LEN],
    const void *payload, size_t plen, uint16_t *status, u_char **rbody,
    uint32_t *rdlen, size_t rmax)
{
    size_t            total = sizeof(ClientRequestHdr) + plen;
    u_char           *buf;
    ClientRequestHdr *req;

    buf = malloc(total);
    if (buf == NULL) {
        return -1;
    }
    ngx_memzero(buf, sizeof(ClientRequestHdr));
    req = (ClientRequestHdr *) buf;
    req->streamid[1] = 8;                       /* unused stream slot */
    req->requestid   = htons(requestid);
    ngx_memcpy(req->body, body, XRDW_BODY_LEN);
    req->dlen = htonl((kXR_int32) plen);
    if (plen > 0) {
        ngx_memcpy(buf + sizeof(ClientRequestHdr), payload, plen);
    }

    if (brix_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        return -1;
    }
    free(buf);

    *rbody = NULL;
    return brix_cache_read_response(t, oc, status, rbody, rdlen, rmax);
}

/* Map a non-ok origin response to errno. A failure is a kXR_error frame whose
 * body is [int32 errnum][msg]; decode the kXR errnum (kXR_NotFound, …) from it.
 * (Some servers may also place the kXR code directly in the status word.) */
static int
origin_status_errno(uint16_t status, const u_char *body, uint32_t dlen)
{
    int errcode = (int) status;

    if (status == kXR_error) {
        const char *m = NULL;
        size_t      ml = 0;
        (void) xrd_error_body_decode(body, dlen, &errcode, &m, &ml);
    }
    switch (errcode) {
    case kXR_NotFound:      return ENOENT;
    case kXR_NotAuthorized: return EACCES;
    case kXR_isDirectory:   return EISDIR;
    case kXR_ItExists:      return ENOTEMPTY; /* non-empty dir: kXR_rmdir, or kXR_mv onto one */
    default:                return EIO;
    }
}

/* brix_cache_origin_rename — kXR_mv old→new on the origin. Wire payload is
 * "src ' ' dst" with arg1len=len(src). Returns 0, or -1 with errno set. */
int
brix_cache_origin_rename(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *src, const char *dst)
{
    uint8_t   body[XRDW_BODY_LEN];
    size_t    sl = strlen(src), dl = strlen(dst), total = sl + 1 + dl;
    char     *payload;
    uint16_t  status;
    uint32_t  dlen;
    u_char   *rbody;
    int       rc;

    if (sl == 0 || sl > 0x7fff) {
        errno = EINVAL;
        return -1;
    }
    payload = malloc(total);
    if (payload == NULL) {
        errno = ENOMEM;
        return -1;
    }
    ngx_memcpy(payload, src, sl);
    payload[sl] = ' ';
    ngx_memcpy(payload + sl + 1, dst, dl);

    {
        xrdw_twopath_req_t b = { .arg1len = (int16_t) sl };
        xrdw_twopath_req_pack(&b, body);
    }
    rc = origin_request(t, oc, kXR_mv, body, payload, total, &status, &rbody,
                        &dlen, 256);
    free(payload);
    if (rc != 0) {
        errno = EIO;
        return -1;
    }
    if (status != kXR_ok) {
        errno = origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    free(rbody);
    return 0;
}

/* brix_cache_origin_rm — kXR_rm <path> on the origin (delete a file). The rm
 * request carries no params (the 16-byte body is reserved/zero); the path is the
 * payload. Returns 0, or -1 with errno set (ENOENT when the origin reports the
 * path already gone, so a best-effort reclaim/evict is idempotent). */
int
brix_cache_origin_rm(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const char *path)
{
    uint8_t   body[XRDW_BODY_LEN];
    size_t    pl = (path != NULL) ? strlen(path) : 0;
    uint16_t  status;
    uint32_t  dlen;
    u_char   *rbody = NULL;
    int       rc;

    if (pl == 0 || pl > 0x7fff) {
        errno = EINVAL;
        return -1;
    }
    ngx_memzero(body, sizeof(body));            /* kXR_rm params are reserved */
    rc = origin_request(t, oc, kXR_rm, body, path, pl, &status, &rbody,
                        &dlen, 256);
    if (rc != 0) {
        errno = EIO;
        return -1;
    }
    if (status != kXR_ok) {
        errno = origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    free(rbody);
    return 0;
}

/* brix_cache_origin_rmdir — kXR_rmdir <path> on the origin (remove an empty
 * directory). The rmdir request has the same wire shape as kXR_rm: the 16-byte
 * body is reserved/zero; the path is the payload. Returns 0, or -1 with errno
 * set. Non-empty directory is surfaced as ENOTEMPTY (origin sends kXR_ItExists
 * in the kXR_error body for this case); ENOENT when the path is already gone. */
int
brix_cache_origin_rmdir(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const char *path)
{
    uint8_t   body[XRDW_BODY_LEN];
    size_t    pl = (path != NULL) ? strlen(path) : 0;
    uint16_t  status;
    uint32_t  dlen;
    u_char   *rbody = NULL;
    int       rc;

    if (pl == 0 || pl > 0x7fff) {
        errno = EINVAL;
        return -1;
    }
    ngx_memzero(body, sizeof(body));         /* kXR_rmdir params are reserved */
    rc = origin_request(t, oc, kXR_rmdir, body, path, pl, &status, &rbody,
                        &dlen, 256);
    if (rc != 0) {
        errno = EIO;
        return -1;
    }
    if (status != kXR_ok) {
        errno = origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    free(rbody);
    return 0;
}

/* Build "<path>\0[int16 rc=0]<name>\0" (+ "[int32 BE vlen]<value>") for a single-
 * attribute fattr request. Returns a malloc'd buffer + *plen, or NULL (OOM). */
static u_char *
origin_fattr_payload(const char *path, const char *name, const void *val,
    size_t vlen, int with_value, size_t *plen)
{
    size_t   pn = strlen(path), nn = strlen(name);
    size_t   need = pn + 1 + 2 + nn + 1 + (with_value ? 4 + vlen : 0);
    u_char  *buf, *p;

    buf = malloc(need);
    if (buf == NULL) {
        return NULL;
    }
    p = buf;
    ngx_memcpy(p, path, pn); p += pn; *p++ = 0;
    *p++ = 0; *p++ = 0;                          /* nvec int16 rc=0 */
    ngx_memcpy(p, name, nn); p += nn; *p++ = 0;
    if (with_value) {
        uint32_t vbe = htonl((uint32_t) vlen);
        ngx_memcpy(p, &vbe, 4); p += 4;
        if (vlen > 0) { ngx_memcpy(p, val, vlen); p += vlen; }
    }
    *plen = (size_t) (p - buf);
    return buf;
}

/* brix_cache_origin_getfattr — kXR_fattr Get of ONE attribute on `path`. Copies
 * the value into buf[cap] and returns its length, 0 if absent, or -1 (errno). */
ssize_t
brix_cache_origin_getfattr(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *path, const char *name,
    void *buf, size_t cap)
{
    uint8_t   body[XRDW_BODY_LEN];
    u_char   *payload, *rbody = NULL, *after;
    size_t    plen, next;
    uint16_t  status, rc = 0;
    uint32_t  dlen, vlen;

    payload = origin_fattr_payload(path, name, NULL, 0, 0, &plen);
    if (payload == NULL) { errno = ENOMEM; return -1; }
    {
        xrdw_fattr_req_t b = { .subcode = kXR_fattrGet, .numattr = 1 };
        xrdw_fattr_req_pack(&b, body);
    }
    if (origin_request(t, oc, kXR_fattr, body, payload, plen, &status, &rbody,
                       &dlen, 65536) != 0)
    {
        free(payload);
        errno = EIO;
        return -1;
    }
    free(payload);
    if (status != kXR_ok) {
        errno = origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    if (rbody == NULL || dlen < 2
        || xrdp_fattr_nvec_parse(rbody, dlen, 2, &rc, NULL, NULL, &next) != 0)
    {
        free(rbody);
        errno = EIO;
        return -1;
    }
    if (rc != 0) {                               /* attribute not present */
        free(rbody);
        errno = ENODATA;
        return -1;
    }
    after = rbody + next;
    if (after + 4 > rbody + dlen) { free(rbody); errno = EIO; return -1; }
    ngx_memcpy(&vlen, after, 4); vlen = ntohl(vlen); after += 4;
    if (after + vlen > rbody + dlen) { vlen = (uint32_t) (rbody + dlen - after); }
    if (buf != NULL && cap > 0) {
        ngx_memcpy(buf, after, (vlen < cap) ? vlen : cap);
    }
    free(rbody);
    return (ssize_t) vlen;
}

/* brix_cache_origin_listfattr — kXR_fattr List on `path`; copies the NUL-
 * separated name list into buf[cap]. Returns the byte count, or -1 (errno). */
ssize_t
brix_cache_origin_listfattr(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *path, void *buf, size_t cap)
{
    uint8_t   body[XRDW_BODY_LEN];
    size_t    pn = strlen(path);
    u_char   *payload, *rbody = NULL;
    uint16_t  status;
    uint32_t  dlen;

    payload = malloc(pn + 1);
    if (payload == NULL) { errno = ENOMEM; return -1; }
    ngx_memcpy(payload, path, pn); payload[pn] = 0;
    {
        xrdw_fattr_req_t b = { .subcode = kXR_fattrList, .numattr = 0 };
        xrdw_fattr_req_pack(&b, body);
    }
    if (origin_request(t, oc, kXR_fattr, body, payload, pn + 1, &status, &rbody,
                       &dlen, 65536) != 0)
    {
        free(payload);
        errno = EIO;
        return -1;
    }
    free(payload);
    if (status != kXR_ok) {
        errno = origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    if (buf != NULL && cap > 0 && dlen > 0) {
        ngx_memcpy(buf, rbody, (dlen < cap) ? dlen : cap);
    }
    free(rbody);
    return (ssize_t) dlen;
}

/* Shared Set/Del: build payload, send, parse the per-attribute rc. 0 / -1. */
static int
origin_fattr_set_or_del(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const char *path, const char *name, const void *val, size_t vlen,
    int with_value, uint8_t subcode)
{
    uint8_t   body[XRDW_BODY_LEN];
    u_char   *payload, *rbody = NULL;
    size_t    plen, next;
    uint16_t  status, rc = 0;
    uint32_t  dlen;

    payload = origin_fattr_payload(path, name, val, vlen, with_value, &plen);
    if (payload == NULL) { errno = ENOMEM; return -1; }
    {
        xrdw_fattr_req_t b = { .subcode = subcode, .numattr = 1 };
        xrdw_fattr_req_pack(&b, body);
    }
    if (origin_request(t, oc, kXR_fattr, body, payload, plen, &status, &rbody,
                       &dlen, 4096) != 0)
    {
        free(payload);
        errno = EIO;
        return -1;
    }
    free(payload);
    if (status != kXR_ok) {
        errno = origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    if (rbody == NULL || dlen < 2
        || xrdp_fattr_nvec_parse(rbody, dlen, 2, &rc, NULL, NULL, &next) != 0)
    {
        free(rbody);
        errno = EIO;
        return -1;
    }
    free(rbody);
    if (rc != 0) {
        errno = (subcode == kXR_fattrDel) ? ENODATA : EIO;
        return -1;
    }
    return 0;
}

int
brix_cache_origin_setfattr(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *path, const char *name,
    const void *val, size_t vlen)
{
    return origin_fattr_set_or_del(t, oc, path, name, val, vlen, 1,
                                   kXR_fattrSet);
}

int
brix_cache_origin_delfattr(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *path, const char *name)
{
    return origin_fattr_set_or_del(t, oc, path, name, NULL, 0, 0, kXR_fattrDel);
}
