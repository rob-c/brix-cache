/*
 * sd_remote_xattr_read.c — read-only x-amz-meta-* xattr surface for the
 * remote-origin (s3://) storage driver. Split from sd_remote_meta.c so the
 * namespace classifier and metadata readers remain independently reviewable.
 */

#include "sd_remote_internal.h"
#include "platform/platform_api.h"
#include "fs/backend/s3/sd_s3.h"

#include <errno.h>
#include <string.h>

/* ---- xattr surface: x-amz-meta-* as the `user.` namespace --------------
 *
 * getxattr("user.<name>") reads x-amz-meta-<name> via a signed HEAD;
 * listxattr enumerates every x-amz-meta-* header (needs a transport with the
 * optional resp_headers_raw slot — without it sd_s3_list_meta reports
 * ENOTSUP). Both open the object read-only just for the HEAD.
 *
 * The HEAD signs with the per-user ak/sk/region/session when the caller passes
 * them (NULL = the instance's static service credential), exactly as the stat
 * and mutation bodies do. Reading metadata is a read of the user's data, and
 * while these two slots had no *_cred sibling brix_sd_{get,list}xattr_maybe_cred
 * fell through to the plain slot for every caller it could not refuse: a user
 * presenting perfectly good S3 keys had the read signed as the EXPORT, so it
 * returned attributes that identity's own keys would have been denied. (The
 * forwarder's fallback_deny backstop already refused a credential it could not
 * route — that arm was never the hole; the silent service-key signing was.) */
static sd_s3_file *
sd_remote_meta_open(brix_sd_instance_t *inst, const char *path,
    const char *ak, const char *sk, const char *region, const char *session)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params           p;
    char                        objpath[768];
    char                        errbuf[256];

    sd_remote_s3_key(cfg, path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);
    return sd_s3_open_read(&p, errbuf, sizeof(errbuf));
}

static ssize_t
sd_remote_getxattr_impl(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap,
    const char *ak, const char *sk, const char *region, const char *session)
{
    char           val[2048];
    char           errbuf[256];
    sd_s3_meta_buf dst = { val, sizeof(val) };
    sd_s3_file    *s3;
    ssize_t        n;

    if (strncmp(name, "user.", 5) != 0 || name[5] == '\0') {
        errno = ENODATA;      /* only the user. namespace maps to x-amz-meta- */
        return -1;
    }
    s3 = sd_remote_meta_open(inst, path, ak, sk, region, session);
    if (s3 == NULL) {
        errno = ENOMEM;
        return -1;
    }
    errno = 0;
    n = sd_s3_get_meta(s3, name + 5, &dst, errbuf, sizeof(errbuf));
    sd_s3_close(s3);
    if (n < 0) {
        if (errno == 0) { errno = EIO; }
        return -1;
    }
    if (n == 0) {
        errno = ENODATA;      /* HEAD ok, attribute absent */
        return -1;
    }
    if (buf == NULL || cap == 0) {
        return n;             /* getxattr(2) size probe */
    }
    if ((size_t) n > cap) {
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, val, (size_t) n);
    return n;
}

ssize_t
sd_remote_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    return sd_remote_getxattr_impl(inst, path, name, buf, cap,
                                   NULL, NULL, NULL, NULL);
}

/* Cred-scoped getxattr: the HEAD runs as the requesting user. Gate semantics
 * identical to sd_remote_stat_cred — a cred this S3-only backend cannot use is
 * refused under fallback_deny rather than signed with the service credential. */
ssize_t
sd_remote_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_getxattr_impl(inst, path, name, buf, cap,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return -1;
    }
    return sd_remote_getxattr_impl(inst, path, name, buf, cap,
                                   NULL, NULL, NULL, NULL);
}

static ssize_t
sd_remote_listxattr_impl(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap,
    const char *ak, const char *sk, const char *region, const char *session)
{
    char        errbuf[256];
    sd_s3_file *s3;
    ssize_t     n;

    s3 = sd_remote_meta_open(inst, path, ak, sk, region, session);
    if (s3 == NULL) {
        errno = ENOMEM;
        return -1;
    }
    errno = 0;
    n = sd_s3_list_meta(s3, buf, cap, errbuf, sizeof(errbuf));
    sd_s3_close(s3);
    if (n < 0 && errno == 0) {
        errno = EIO;
    }
    return n;
}

ssize_t
sd_remote_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap)
{
    return sd_remote_listxattr_impl(inst, path, buf, cap,
                                    NULL, NULL, NULL, NULL);
}

/* Cred-scoped listxattr: enumerating an object's metadata keys is as much a
 * read of the user's object as getxattr, so it takes the same gate. */
ssize_t
sd_remote_listxattr_cred(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_listxattr_impl(inst, path, buf, cap,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return -1;
    }
    return sd_remote_listxattr_impl(inst, path, buf, cap,
                                    NULL, NULL, NULL, NULL);
}
