/*
 * ops_ext.c — client wrappers for the nginx-xrootd vendor extension opcodes
 *             (kXR_setattr / kXR_symlink / kXR_readlink / kXR_link).
 *
 * WHAT: Path-based ops that close POSIX gaps the base XRootD protocol lacks, so a
 *       FUSE mount can honour `cp -p` / `touch -d` (setattr times), chown (setattr
 *       owner), and `ln`/`ln -s` (link/symlink). Plus xrdc_ext_probe(), which
 *       queries kXR_Qconfig "xrdfs.ext" so a caller only emits these opcodes
 *       against a server that advertises support.
 * HOW:  Each builds its 24-byte ClientXxxRequest (wire_vendor_ext.h) + payload and
 *       exchanges it via xrdc_roundtrip (redirect-aware). setattr's variable
 *       attribute block is encoded big-endian into the payload prefix.
 *
 * Clean-room: the shared wire structs + frame.c only. No XrdCl.
 */
#include "xrdc.h"
#include "compat/vendor_ext.h"   /* shared kXR_setattr prefix codec (libxrdproto) */

#include <endian.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* roundtrip wrapper that discards the (empty) reply body. 0 / -1 (st set). */
static int
ext_simple(xrdc_conn *c, void *hdr24, const void *payload, uint32_t plen,
           xrdc_status *st)
{
    uint16_t status;
    uint8_t *body = NULL;
    uint32_t blen = 0;

    if (xrdc_roundtrip(c, hdr24, payload, plen, &status, &body, &blen, st) != 0) {
        return -1;
    }
    free(body);
    return 0;
}

int
xrdc_setattr(xrdc_conn *c, const char *path, int set_times,
             const struct timespec times[2], int set_owner,
             uint32_t uid, uint32_t gid, xrdc_status *st)
{
    ClientSetattrRequest req;
    uint8_t             *payload;
    size_t               plen = strlen(path);
    size_t               total = XROOTD_SETATTR_PREFIX_LEN + plen + 1;
    uint8_t             *p;
    uint32_t             flags = 0;
    int                  rc;

    if (set_times) { flags |= kXR_sa_times; }
    if (set_owner) { flags |= kXR_sa_owner; }

    payload = (uint8_t *) calloc(1, total);
    if (payload == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }
    p = payload;
    {
        /* Shared 44-byte attribute-prefix codec (libxrdproto) — the offset layout
         * lives in one place so client-encode == server-decode. */
        xrdp_setattr_t a;
        a.flags      = flags;
        a.atime_sec  = set_times ? (int64_t) times[0].tv_sec  : 0;
        a.atime_nsec = set_times ? (int64_t) times[0].tv_nsec : 0;
        a.mtime_sec  = set_times ? (int64_t) times[1].tv_sec  : 0;
        a.mtime_nsec = set_times ? (int64_t) times[1].tv_nsec : 0;
        a.uid        = set_owner ? (int32_t) uid : -1;
        a.gid        = set_owner ? (int32_t) gid : -1;
        xrdp_setattr_prefix_pack(&a, p);
    }
    memcpy(p + XROOTD_SETATTR_PREFIX_LEN, path, plen + 1);

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_setattr);
    xrdw_empty_req_pack(((ClientRequestHdr *) &req)->body);  /* 44B prefix is in the payload */

    rc = ext_simple(c, &req, payload, (uint32_t) total, st);
    free(payload);
    return rc;
}

int
xrdc_symlink(xrdc_conn *c, const char *target, const char *linkpath,
             xrdc_status *st)
{
    ClientSymlinkRequest req;
    char                *payload;
    size_t               tl = strlen(target), ll = strlen(linkpath);
    size_t               total = tl + 1 + ll;
    int                  rc;

    if (tl == 0 || tl > 0x7fff) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "symlink target length out of range");
        return -1;
    }
    payload = (char *) malloc(total);
    if (payload == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }
    memcpy(payload, target, tl);
    payload[tl] = ' ';
    memcpy(payload + tl + 1, linkpath, ll);

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_symlink);
    {
        xrdw_twopath_req_t b = { .arg1len = (int16_t) tl };
        xrdw_twopath_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    rc = ext_simple(c, &req, payload, (uint32_t) total, st);
    free(payload);
    return rc;
}

int
xrdc_link(xrdc_conn *c, const char *oldpath, const char *newpath,
          xrdc_status *st)
{
    ClientLinkRequest req;
    char             *payload;
    size_t            ol = strlen(oldpath), nl = strlen(newpath);
    size_t            total = ol + 1 + nl;
    int               rc;

    if (ol == 0 || ol > 0x7fff) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "link source length out of range");
        return -1;
    }
    payload = (char *) malloc(total);
    if (payload == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }
    memcpy(payload, oldpath, ol);
    payload[ol] = ' ';
    memcpy(payload + ol + 1, newpath, nl);

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_link);
    {
        xrdw_twopath_req_t b = { .arg1len = (int16_t) ol };
        xrdw_twopath_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    rc = ext_simple(c, &req, payload, (uint32_t) total, st);
    free(payload);
    return rc;
}

ssize_t
xrdc_readlink(xrdc_conn *c, const char *path, char *out, size_t outsz,
              xrdc_status *st)
{
    ClientReadlinkRequest req;
    uint16_t              status;
    uint8_t             *body = NULL;
    uint32_t             blen = 0;
    size_t               n;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_readlink);
    xrdw_empty_req_pack(((ClientRequestHdr *) &req)->body);

    if (xrdc_roundtrip(c, &req, path, (uint32_t) strlen(path),
                       &status, &body, &blen, st) != 0) {
        return -1;
    }
    n = (blen < outsz - 1) ? blen : (outsz - 1);
    memcpy(out, body, n);
    out[n] = '\0';
    free(body);
    return (ssize_t) n;
}

int
xrdc_ext_probe(xrdc_conn *c, int *has_setattr, int *has_symlink,
               int *has_readlink, int *has_link, xrdc_status *st)
{
    char reply[256];

    if (has_setattr)  { *has_setattr  = 0; }
    if (has_symlink)  { *has_symlink  = 0; }
    if (has_readlink) { *has_readlink = 0; }
    if (has_link)     { *has_link     = 0; }

    if (xrdc_query(c, kXR_Qconfig, "xrdfs.ext", reply, sizeof(reply), st) != 0) {
        return -1;
    }
    /* reply is "xrdfs.ext=setattr,symlink,readlink,link" or "xrdfs.ext=0". */
    if (has_setattr  && strstr(reply, "setattr")  != NULL) { *has_setattr  = 1; }
    if (has_symlink  && strstr(reply, "symlink")  != NULL) { *has_symlink  = 1; }
    if (has_readlink && strstr(reply, "readlink") != NULL) { *has_readlink = 1; }
    if (has_link     && strstr(reply, "link")     != NULL) { *has_link     = 1; }
    return 0;
}
