/*
 * sd_http_xattr_write.c — writing extended attributes on an http origin, as
 * WebDAV dead properties.
 *
 * WHAT: The setxattr/removexattr vtable slots and their credential-scoped twins,
 *       over PROPPATCH (RFC 4918 §9.2).
 *
 * WHY:  Split from the reader (sd_http_xattr.c) because one file carrying both
 *       halves passes the 600-line cap — not because they are two mappings. The
 *       shared wire spelling and the three helpers both halves need live in
 *       sd_http_xattr_internal.h.
 *
 * HOW:  One PROPPATCH per mutation, sent through the driver's no-failover
 *       namespace sender: replaying a property write against a second endpoint
 *       could apply it twice. Two POSIX contracts that PROPPATCH does not have
 *       natively are bought with a preceding size-enquiry read — XATTR_CREATE /
 *       XATTR_REPLACE (PROPPATCH is an unconditional upsert) and "removing an
 *       absent attribute is ENODATA" (RFC 4918 §9.2 makes it a success).
 */

#include "sd_http_xattr_internal.h"

#include "core/compat/hex.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>


/*
 * WHAT: The PROPPATCH status→errno verdict.
 * WHY:  A property write fails differently from a namespace mutation: 405/409
 *       mean "this origin does not keep dead properties here", which the VFS
 *       must see as ENOTSUP so it can fall back, not as EEXIST/ENOENT.
 * HOW:  Override the three codes that differ, delegate the rest to the shared
 *       mutation map so 401/403/404 keep one spelling across the driver.
 */
static int
sd_http_xattr_errno(long status)
{
    switch (status) {
    case 405:
    case 409: return ENOTSUP;
    case 507: return ENOSPC;
    default:  return sd_http_status_to_errno(status);
    }
}


/*
 * WHAT: Send one PROPPATCH body and judge the reply.
 * WHY:  set and remove differ only in the body; the credential path, the header
 *       block and the two-level verdict (transport status, then the per-property
 *       propstat status) belong to both.
 * HOW:  The shared no-failover namespace sender — replaying a property write
 *       against a second endpoint could apply it twice — then 200/204 accepted
 *       outright and a 207 accepted only if its propstat says 2xx.
 */
static ngx_int_t
sd_http_xattr_patch(sd_http_inst_state *is, const char *path,
    const char *body, size_t blen, const brix_sd_cred_t *cred)
{
    char              open_auth[SD_HTTP_AUTH_MAX];
    char              hdrs[SD_HTTP_AUTH_MAX + 96];
    char              full[SD_HTTP_PATH_MAX];
    const char       *auth, *cert;
    brix_s3_resp_t    resp;
    sd_http_ns_req_t  nsr = { "PROPPATCH", NULL, hdrs, NULL, body, blen };
    char              errbuf[256];
    const void       *rbody;
    size_t            rlen = 0;
    int               ok;

    if (sd_http_xattr_auth(is, cred, open_auth, sizeof(open_auth),
                           &auth, &cert) != 0)
    {
        return NGX_ERROR;
    }
    snprintf(hdrs, sizeof(hdrs), "Content-Type: application/xml\r\n%s",
             (auth != NULL) ? auth : "");
    sd_http_write_path(is, path, full, sizeof(full));
    nsr.path     = full;
    nsr.cert_pem = (cert != NULL && cert[0] != '\0') ? cert : NULL;

    if (sd_http_ns_send(is, &nsr, &resp, errbuf, sizeof(errbuf)) != 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    if (resp.status != 200 && resp.status != 204 && resp.status != 207) {
        errno = sd_http_xattr_errno(resp.status);
        is->transport->resp_free(&resp);
        return NGX_ERROR;
    }
    ok = 1;
    if (resp.status == 207) {
        rbody = is->transport->resp_body(&resp, &rlen);
        ok = (rbody != NULL && rlen != 0 && rlen <= SD_HTTP_XATTR_XML_MAX)
             && sd_http_xattr_status_ok((const char *) rbody,
                                        (const char *) rbody + rlen);
    }
    is->transport->resp_free(&resp);
    if (!ok) {
        errno = ENOTSUP;      /* the origin declined to keep this property */
        return NGX_ERROR;
    }
    return NGX_OK;
}


/*
 * WHAT: Enforce XATTR_CREATE / XATTR_REPLACE before a write.
 * WHY:  PROPPATCH has no conditional set — it is an upsert — so the exclusivity
 *       the POSIX flags promise has to be asked for separately or it is silently
 *       not enforced, which is worse than not offering the flags at all.
 * HOW:  One size-enquiry read; EEXIST when CREATE finds a value, ENODATA when
 *       REPLACE finds none, and no probe at all when neither flag is set.
 *       Inherently racy against a concurrent writer on the same origin, exactly
 *       as it is on any network filesystem; the flags are advisory there too.
 */
static int
sd_http_xattr_flag_gate(brix_sd_instance_t *inst, const char *path,
    const char *name, int flags, const brix_sd_cred_t *cred)
{
    ssize_t have;

    if ((flags & (XATTR_CREATE | XATTR_REPLACE)) == 0) {
        return 0;
    }
    have = sd_http_getxattr_common(inst, path, name, NULL, 0, cred);
    if (have >= 0 && (flags & XATTR_CREATE) != 0) {
        errno = EEXIST;
        return -1;
    }
    if (have < 0 && errno == ENODATA && (flags & XATTR_REPLACE) != 0) {
        return -1;                          /* errno already ENODATA */
    }
    if (have < 0 && errno != ENODATA) {
        return -1;                          /* the probe itself failed */
    }
    return 0;
}


static ngx_int_t
sd_http_setxattr_common(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *value, size_t len, int flags,
    const brix_sd_cred_t *cred)
{
    char      elem[SD_HTTP_XATTR_ELEM_MAX];
    char     *body;
    size_t    cap;
    ngx_int_t rc;
    int       n;

    if (inst == NULL || inst->state == NULL || path == NULL
        || (value == NULL && len != 0))
    {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (len > SD_HTTP_XATTR_VALUE_MAX) {
        errno = E2BIG;
        return NGX_ERROR;
    }
    if (sd_http_xattr_elem(name, elem, sizeof(elem)) != 0
        || sd_http_xattr_flag_gate(inst, path, name, flags, cred) != 0)
    {
        return NGX_ERROR;
    }
    cap  = sizeof(elem) * 2 + 2 * len + 256;
    body = malloc(cap);
    if (body == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    /* The hex of the value is written straight into the body buffer, so the
     * only bytes between the tags are [0-9a-f] whatever the caller stored. */
    n = snprintf(body, cap,
                 "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                 "<D:propertyupdate xmlns:D=\"DAV:\" xmlns:B=\"%s\">"
                 "<D:set><D:prop><B:%s>", SD_HTTP_XATTR_NS, elem);
    brix_hex_encode((const uint8_t *) value, len, body + n);
    n += (int) (2 * len);
    n += snprintf(body + n, cap - (size_t) n,
                  "</B:%s></D:prop></D:set></D:propertyupdate>", elem);

    rc = sd_http_xattr_patch(inst->state, path, body, (size_t) n, cred);
    free(body);
    return rc;
}


static ngx_int_t
sd_http_removexattr_common(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred)
{
    char elem[SD_HTTP_XATTR_ELEM_MAX];
    char body[SD_HTTP_XATTR_ELEM_MAX + 256];
    int  n;

    if (inst == NULL || inst->state == NULL || path == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (sd_http_xattr_elem(name, elem, sizeof(elem)) != 0) {
        return NGX_ERROR;
    }
    /* RFC 4918 §9.2 makes removing an absent property a SUCCESS, where POSIX
     * demands ENODATA — so ask first rather than report a removal that removed
     * nothing. */
    if (sd_http_getxattr_common(inst, path, name, NULL, 0, cred) < 0) {
        return NGX_ERROR;                   /* errno = ENODATA, or the probe's */
    }
    n = snprintf(body, sizeof(body),
                 "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                 "<D:propertyupdate xmlns:D=\"DAV:\" xmlns:B=\"%s\">"
                 "<D:remove><D:prop><B:%s/></D:prop></D:remove>"
                 "</D:propertyupdate>", SD_HTTP_XATTR_NS, elem);

    return sd_http_xattr_patch(inst->state, path, body, (size_t) n, cred);
}


ngx_int_t
sd_http_setxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    const void *value, size_t len, int flags)
{
    return sd_http_setxattr_common(inst, path, name, value, len, flags, NULL);
}

ngx_int_t
sd_http_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *value, size_t len, int flags,
    const brix_sd_cred_t *cred)
{
    return sd_http_setxattr_common(inst, path, name, value, len, flags, cred);
}

ngx_int_t
sd_http_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    return sd_http_removexattr_common(inst, path, name, NULL);
}

ngx_int_t
sd_http_removexattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred)
{
    return sd_http_removexattr_common(inst, path, name, cred);
}
