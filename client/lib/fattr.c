/*
 * fattr.c — client wrappers for kXR_fattr (file extended attributes).
 *
 * WHAT: brix_fattr_get/set/del/list over kXR_fattr (3020), path-based and
 *       redirect-aware (via brix_roundtrip), for a single attribute at a time
 *       (what a FUSE getxattr/setxattr/removexattr call needs) plus a full list.
 * WHY:  The native client (and the xrootdfs FUSE driver) needs POSIX extended-
 *       attribute access; kXR_fattr is the wire op the module implements.
 * HOW:  Request body (path-based): "<path>\0" + nvec + (set only) vvec, where an
 *       nvec entry is [int16 rc=0][name\0] and a vvec entry is [int32 BE vlen]
 *       [value]. Responses: Get/Set/Del = [u8 errcount][u8 numattr][nvec-with-rc]
 *       (Get also appends a vvec of [int32 BE vlen][value]); List = a NUL-
 *       separated name list. The per-attribute rc (a kXR_* code, e.g.
 *       kXR_AttrNotFound) is surfaced via st->kxr so the caller maps it to errno.
 *
 * Clean-room: wire facts from src/protocols/root/protocol headers only (cross-checked vs the
 * module's src/protocols/root/fattr handler). No goto.
 */
#include "brix.h"
#include "core/compat/fattr_codec.h"   /* shared kXR_fattr nvec parser (libxrdproto) */

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

/* Build "<path>\0[int16 rc=0]<name>\0" (+ "[int32 vlen]<value>" when with_value)
 * into a malloc'd buffer; *plen set. Returns NULL on OOM. */
static uint8_t *
fattr_build_payload(const char *path, const char *name,
                    const void *value, size_t vlen, int with_value,
                    uint32_t *plen)
{
    size_t   pathn = strlen(path);
    size_t   namen = strlen(name);
    size_t   need  = pathn + 1 + 2 + namen + 1;
    uint8_t *buf, *p;

    if (with_value) {
        need += 4 + vlen;
    }
    buf = (uint8_t *) malloc(need);
    if (buf == NULL) {
        return NULL;
    }
    p = buf;
    memcpy(p, path, pathn); p += pathn; *p++ = 0;       /* path\0          */
    *p++ = 0; *p++ = 0;                                 /* nvec int16 rc=0 */
    memcpy(p, name, namen); p += namen; *p++ = 0;       /* name\0          */
    if (with_value) {
        uint32_t vbe = htonl((uint32_t) vlen);
        memcpy(p, &vbe, 4); p += 4;
        if (vlen > 0) {
            memcpy(p, value, vlen); p += vlen;
        }
    }
    *plen = (uint32_t) (p - buf);
    return buf;
}

/* Parse the leading "[u8 errcount][u8 numattr][int16 rc][name\0]" common to every
 * single-attr reply; on success *after points just past the name's NUL and *rc
 * holds the per-attribute kXR status. Returns 0 / -1 (+ st on a framing error). */
static int
fattr_parse_status(uint8_t *body, uint32_t blen, uint16_t *rc,
                   uint8_t **after, brix_status *st)
{
    size_t next;

    if (blen < 2 || body[1] < 1) {
        brix_status_set(st, XRDC_EPROTO, 0, "fattr reply too short");
        return -1;
    }
    /* Reply = [u8 errcount][u8 numattr] then one nvec entry [int16 rc][name\0].
     * Shared read-only parser (libxrdproto) — same scan the server's request
     * parse uses. */
    if (xrdp_fattr_nvec_parse(body, blen, 2, rc, NULL, NULL, &next) != 0) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "fattr nvec truncated or name not terminated");
        return -1;
    }
    *after = body + next;                    /* past the echoed name's NUL */
    return 0;
}

int
brix_fattr_get(brix_conn *c, const char *path, const char *name,
               void *value, size_t bufsz, size_t *out_vlen, brix_status *st)
{
    ClientFattrRequest req;
    uint8_t           *payload, *body = NULL, *p;
    uint32_t           plen, blen = 0, vlen;
    uint16_t           status, rc = 0;

    payload = fattr_build_payload(path, name, NULL, 0, 0, &plen);
    if (payload == NULL) {
        brix_status_set(st, XRDC_ESOCK, 0, "out of memory");
        return -1;
    }
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_fattr);
    {
        xrdw_fattr_req_t b = { .subcode = kXR_fattrGet, .numattr = 1 };
        xrdw_fattr_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    if (brix_roundtrip(c, &req, payload, plen, &status, &body, &blen, st) != 0) {
        free(payload);
        return -1;
    }
    free(payload);

    if (fattr_parse_status(body, blen, &rc, &p, st) != 0) {
        free(body);
        return -1;
    }
    if (rc != 0) {
        free(body);
        brix_status_set(st, (int) rc, 0, "fattr get: attribute error");
        return -1;
    }
    if (p + 4 > body + blen) {
        free(body);
        brix_status_set(st, XRDC_EPROTO, 0, "fattr value vector truncated");
        return -1;
    }
    memcpy(&vlen, p, 4); vlen = ntohl(vlen); p += 4;
    if (p + vlen > body + blen) {            /* defensive clamp */
        vlen = (uint32_t) (body + blen - p);
    }
    if (out_vlen != NULL) {
        *out_vlen = vlen;
    }
    if (value != NULL && bufsz > 0) {
        memcpy(value, p, (vlen < bufsz) ? vlen : bufsz);
    }
    free(body);
    return 0;
}

/* Shared Set/Del path: build (with or without value), send, parse the rc. */
static int
fattr_set_or_del(brix_conn *c, const char *path, const char *name,
                 const void *value, size_t vlen, int with_value,
                 int subcode, int options, brix_status *st)
{
    ClientFattrRequest req;
    uint8_t           *payload, *body = NULL, *after;
    uint32_t           plen, blen = 0;
    uint16_t           status, rc = 0;

    payload = fattr_build_payload(path, name, value, vlen, with_value, &plen);
    if (payload == NULL) {
        brix_status_set(st, XRDC_ESOCK, 0, "out of memory");
        return -1;
    }
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_fattr);
    {
        xrdw_fattr_req_t b = { .subcode = (uint8_t) subcode, .numattr = 1,
                               .options = (uint8_t) options };
        xrdw_fattr_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    if (brix_roundtrip(c, &req, payload, plen, &status, &body, &blen, st) != 0) {
        free(payload);
        return -1;
    }
    free(payload);

    if (fattr_parse_status(body, blen, &rc, &after, st) != 0) {
        free(body);
        return -1;
    }
    free(body);
    if (rc != 0) {
        brix_status_set(st, (int) rc, 0, "fattr %s: attribute error",
                        subcode == kXR_fattrSet ? "set" : "del");
        return -1;
    }
    return 0;
}

int
brix_fattr_set(brix_conn *c, const char *path, const char *name,
               const void *value, size_t vlen, int create_only, brix_status *st)
{
    return fattr_set_or_del(c, path, name, value, vlen, 1, kXR_fattrSet,
                            create_only ? kXR_fa_isNew : 0, st);
}

int
brix_fattr_del(brix_conn *c, const char *path, const char *name, brix_status *st)
{
    return fattr_set_or_del(c, path, name, NULL, 0, 0, kXR_fattrDel, 0, st);
}

int
brix_fattr_list(brix_conn *c, const char *path, char *out, size_t bufsz,
                size_t *out_len, brix_status *st)
{
    ClientFattrRequest req;
    uint8_t           *payload, *body = NULL;
    uint32_t           plen, blen = 0;
    uint16_t           status;
    size_t             pathn = strlen(path);

    /* Path-based list: payload is just "<path>\0" (numattr 0, no nvec). */
    payload = (uint8_t *) malloc(pathn + 1);
    if (payload == NULL) {
        brix_status_set(st, XRDC_ESOCK, 0, "out of memory");
        return -1;
    }
    memcpy(payload, path, pathn);
    payload[pathn] = 0;
    plen = (uint32_t) (pathn + 1);

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_fattr);
    {
        xrdw_fattr_req_t b = { .subcode = kXR_fattrList, .numattr = 0 };
        xrdw_fattr_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    if (brix_roundtrip(c, &req, payload, plen, &status, &body, &blen, st) != 0) {
        free(payload);
        return -1;
    }
    free(payload);

    if (out_len != NULL) {
        *out_len = blen;
    }
    if (out != NULL && bufsz > 0 && blen > 0) {
        memcpy(out, body, (blen < bufsz) ? blen : bufsz);
    }
    free(body);
    return 0;
}
