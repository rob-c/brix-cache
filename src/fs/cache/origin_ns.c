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
#include "origin_ns_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared request packers */
#include "protocols/root/protocol/flags.h"  /* kXR_isDir (ASCII-stat flag bit) */
#include "protocols/root/protocol/opcodes.h"          /* kXR_Qspace infotype */
#include "protocols/root/protocol/codec/wire_codec.h" /* xrdw_query_req_t/pack */
#include "protocols/root/protocol/qspace.h"           /* brix_qspace_parse */
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

/* Shared with origin_ns_dirlist.c; contract in origin_ns_internal.h. */
int
brix_cache_origin_status_errno(uint16_t status, const u_char *body,
    uint32_t dlen)
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
        errno = brix_cache_origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    free(rbody);
    return 0;
}

/* origin_path_ok — send `requestid` with a prepared 16-byte body and the path
 * as payload; the shared shape of every single-path namespace op. Returns 0
 * with the reply body handed to the caller (*rbody, free it), or -1 with errno
 * set (EINVAL bad path, EIO transport, else the mapped origin error). */
static int
origin_path_ok(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    uint16_t requestid, const uint8_t body[XRDW_BODY_LEN], const char *path,
    u_char **rbody, uint32_t *dlen)
{
    size_t    pl = (path != NULL) ? strlen(path) : 0;
    uint16_t  status;

    *rbody = NULL;
    if (pl == 0 || pl > 0x7fff) {
        errno = EINVAL;
        return -1;
    }
    if (origin_request(t, oc, requestid, body, path, pl, &status, rbody,
                       dlen, 512) != 0)
    {
        errno = EIO;
        return -1;
    }
    if (status != kXR_ok) {
        errno = brix_cache_origin_status_errno(status, *rbody, *dlen);
        free(*rbody);
        *rbody = NULL;
        return -1;
    }
    return 0;
}

/* Shared kXR_rm / kXR_rmdir shape: the 16-byte body is reserved/zero and the
 * path is the payload. Returns 0, or -1 with errno set (ENOENT when the origin
 * reports the path already gone, so a best-effort reclaim/evict is idempotent;
 * ENOTEMPTY for a populated directory — kXR_ItExists in the kXR_error body). */
static int
origin_unlink_like(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    uint16_t requestid, const char *path)
{
    uint8_t   body[XRDW_BODY_LEN];
    uint32_t  dlen;
    u_char   *rbody;
    int       rc;

    ngx_memzero(body, sizeof(body));      /* rm/rmdir params are reserved */
    rc = origin_path_ok(t, oc, requestid, body, path, &rbody, &dlen);
    if (rc == 0) {
        free(rbody);
    }
    return rc;
}

/* brix_cache_origin_rm — kXR_rm <path> on the origin (delete a file). */
int
brix_cache_origin_rm(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const char *path)
{
    return origin_unlink_like(t, oc, kXR_rm, path);
}

/* brix_cache_origin_rmdir — kXR_rmdir <path> (remove an empty directory). */
int
brix_cache_origin_rmdir(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const char *path)
{
    return origin_unlink_like(t, oc, kXR_rmdir, path);
}

/* brix_cache_origin_mkdir — kXR_mkdir <path> on the origin (create a directory).
 * Body layout (kXR_mkdir): options(1) reserved(13) mode(2, big-endian). We set
 * kXR_mkdirpath so the origin also creates any missing parents — harmless for the
 * single-level callers (brix_vfs_backend_mkpath walks prefix-by-prefix) and lets a
 * direct deep mkdir succeed too. EEXIST is surfaced to the caller, which treats it
 * as idempotent success for the mkpath walk. Returns 0, or -1 with errno set. */
int
brix_cache_origin_mkdir(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const char *path, mode_t mode)
{
    uint8_t   body[XRDW_BODY_LEN];
    uint32_t  dlen;
    u_char   *rbody;

    ngx_memzero(body, sizeof(body));
    body[0] = kXR_mkdirpath;                     /* options: create parents too */
    body[XRDW_BODY_LEN - 2] = (uint8_t) ((mode >> 8) & 0xff);   /* mode BE hi */
    body[XRDW_BODY_LEN - 1] = (uint8_t) (mode & 0xff);          /* mode BE lo */
    if (origin_path_ok(t, oc, kXR_mkdir, body, path, &rbody, &dlen) != 0) {
        /* For a mkdir the origin's kXR_ItExists means the target directory is
         * already present — an EEXIST condition, NOT the ENOTEMPTY that the
         * shared status→errno mapping assigns for the rmdir/mv "non-empty
         * directory" case (kXR_ItExists is the ONLY source of ENOTEMPTY there,
         * so remapping the errno is exact).  The prefix-by-prefix mkpath walk
         * (brix_vfs_backend_mkpath) and the -p flag both treat EEXIST as
         * idempotent success but abort on ENOTEMPTY, so without this the
         * gateway fails an otherwise-conformant `mkdir -p` on an existing dir
         * where the stock origin idempotently succeeds.  Stock xrootd reports
         * this as "...; file exists"; matching the errno lets clients that
         * classify the error (go-hep MkdirAll) recognise already-present. */
        if (errno == ENOTEMPTY) {
            errno = EEXIST;
        }
        return -1;
    }
    free(rbody);
    return 0;
}

/* brix_cache_origin_chmod — kXR_chmod <path> on the origin (§4.6): change a
 * named file/dir's POSIX permission bits with NO open handle, so a chmod over a
 * proxy/cache export reaches the real origin instead of being a silent no-op.
 * Body layout (ClientChmodRequest): reserved(14) mode(2, big-endian) — the mode
 * occupies the last two bytes of the 16-byte body, exactly like kXR_mkdir's.
 * The reply must be kXR_ok. Returns 0, or -1 with errno set. */
int
brix_cache_origin_chmod(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const char *path, mode_t mode)
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
    ngx_memzero(body, sizeof(body));
    body[XRDW_BODY_LEN - 2] = (uint8_t) (((mode & 0777) >> 8) & 0xff); /* BE hi */
    body[XRDW_BODY_LEN - 1] = (uint8_t) (mode & 0xff);                 /* BE lo */
    rc = origin_request(t, oc, kXR_chmod, body, path, pl, &status, &rbody,
                        &dlen, 256);
    if (rc != 0) {
        errno = EIO;
        return -1;
    }
    if (status != kXR_ok) {
        errno = brix_cache_origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    free(rbody);
    return 0;
}

/* brix_cache_origin_space — kXR_query/kXR_Qspace <path> on the origin (§4.6):
 * ask the real origin for its oss.* capacity report so a proxy/cache export's
 * kXR_Qspace reflects the ORIGIN's space, not the proxy's local cache disk.
 * The infotype rides in the query body (xrdw_query_req_pack); the path is the
 * payload. The reply is the "&"-joined oss.* report — parse oss.space/oss.free
 * with the shared grammar (brix_qspace_parse) and derive used = total - free.
 * Returns 0 with the three out-params set, or -1 with errno set. */
int
brix_cache_origin_space(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const char *path, uint64_t *total_out, uint64_t *free_out,
    uint64_t *used_out)
{
    uint8_t             body[XRDW_BODY_LEN];
    size_t              pl = (path != NULL) ? strlen(path) : 0;
    uint16_t            status;
    uint32_t            dlen;
    u_char             *rbody = NULL;
    int                 rc;
    unsigned long long  total = 0, freeb = 0;

    if (pl == 0 || pl > 0x7fff) {
        errno = EINVAL;
        return -1;
    }
    ngx_memzero(body, sizeof(body));
    {
        xrdw_query_req_t q = { .infotype = kXR_Qspace };  /* fhandle 0 ⇒ by path */
        xrdw_query_req_pack(&q, body);
    }
    rc = origin_request(t, oc, kXR_query, body, path, pl, &status, &rbody,
                        &dlen, 512);
    if (rc != 0) {
        errno = EIO;
        return -1;
    }
    if (status != kXR_ok || rbody == NULL) {
        errno = brix_cache_origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    /* The report is NUL-terminated ASCII; parse the total/free tokens. */
    brix_qspace_parse((const char *) rbody, &total, &freeb);
    free(rbody);

    if (total_out != NULL) { *total_out = (uint64_t) total; }
    if (free_out  != NULL) { *free_out  = (uint64_t) freeb; }
    if (used_out  != NULL) {
        *used_out = (total > freeb) ? (uint64_t) (total - freeb) : 0;
    }
    return 0;
}

/* brix_cache_origin_stat — kXR_stat <path> on the origin. Body is a zeroed
 * 16-byte region (options=0, no fhandle) so the origin describes the path by
 * NAME — a directory is reported with the kXR_isDir flag rather than failing an
 * open the way the size-probe (sd_xroot_origin_open) does. The reply body is the
 * classic 4-field ASCII stat line "id size flags mtime"; we parse size, the flag
 * bitmask (for is_dir), and mtime. Returns 0, or -1 with errno set. */
int
brix_cache_origin_stat(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const char *path, brix_cache_stat_out_t *out)
{
    uint8_t            body[XRDW_BODY_LEN];
    uint32_t           dlen;
    u_char            *rbody;
    long long          id = 0, size = 0, mtime = 0;
    int                flags = 0;

    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    ngx_memzero(out, sizeof(*out));
    ngx_memzero(body, sizeof(body));            /* options=0, wants=0, fhandle=0 */
    if (origin_path_ok(t, oc, kXR_stat, body, path, &rbody, &dlen) != 0) {
        return -1;
    }
    /* rbody is NUL-terminated by brix_cache_read_response (alloc dlen+1). */
    if (rbody == NULL
        || sscanf((const char *) rbody, "%lld %lld %d %lld",
                  &id, &size, &flags, &mtime) != 4)
    {
        free(rbody);
        errno = EIO;                            /* malformed stat line */
        return -1;
    }
    free(rbody);
    out->size   = (off_t) size;
    out->mtime  = (time_t) mtime;
    out->flags  = flags;
    out->is_dir = (flags & kXR_isDir) ? 1 : 0;
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

/* origin_fattr_send — send a prepared kXR_fattr request (body + payload) to the
 * origin and check the reply status; frees payload either way. On success
 * returns 0 with rbody/dlen set (caller frees rbody); on failure returns -1
 * with errno set and rbody already freed. `respcap` bounds the reply body. */
static int
origin_fattr_send(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const uint8_t *body, u_char *payload, size_t plen, uint32_t respcap,
    u_char **rbody, uint32_t *dlen)
{
    uint16_t status;

    *rbody = NULL;
    if (origin_request(t, oc, kXR_fattr, body, payload, plen, &status, rbody,
                       dlen, respcap) != 0)
    {
        free(payload);
        errno = EIO;
        return -1;
    }
    free(payload);
    if (status != kXR_ok) {
        errno = brix_cache_origin_status_errno(status, *rbody, *dlen);
        free(*rbody);
        return -1;
    }
    return 0;
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
    uint16_t  rc = 0;
    uint32_t  dlen, vlen;

    payload = origin_fattr_payload(path, name, NULL, 0, 0, &plen);
    if (payload == NULL) { errno = ENOMEM; return -1; }
    {
        xrdw_fattr_req_t b = { .subcode = kXR_fattrGet, .numattr = 1 };
        xrdw_fattr_req_pack(&b, body);
    }
    if (origin_fattr_send(t, oc, body, payload, plen, 65536, &rbody, &dlen) != 0) {
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
    uint32_t  dlen;

    payload = malloc(pn + 1);
    if (payload == NULL) { errno = ENOMEM; return -1; }
    ngx_memcpy(payload, path, pn); payload[pn] = 0;
    {
        xrdw_fattr_req_t b = { .subcode = kXR_fattrList, .numattr = 0 };
        xrdw_fattr_req_pack(&b, body);
    }
    if (origin_fattr_send(t, oc, body, payload, pn + 1, 65536, &rbody, &dlen) != 0) {
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
    uint16_t  rc = 0;
    uint32_t  dlen;

    payload = origin_fattr_payload(path, name, val, vlen, with_value, &plen);
    if (payload == NULL) { errno = ENOMEM; return -1; }
    {
        xrdw_fattr_req_t b = { .subcode = subcode, .numattr = 1 };
        xrdw_fattr_req_pack(&b, body);
    }
    if (origin_fattr_send(t, oc, body, payload, plen, 4096, &rbody, &dlen) != 0) {
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

