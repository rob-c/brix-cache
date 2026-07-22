/*
 * sd_remote_meta.c — HEAD-based metadata slots for the remote-origin (s3://)
 * storage driver: stat/stat_cred plus the x-amz-meta-* xattr surface. Split out
 * of sd_remote.c verbatim; the driver table lives there and references these via
 * sd_remote_internal.h. Shared path/param/cred helpers stay in sd_remote.c.
 */

#include "sd_remote_internal.h"
#include "fs/backend/s3/sd_s3.h"

#include <errno.h>
#include <string.h>

/* ---- xattr surface: x-amz-meta-* as the `user.` namespace --------------
 *
 * getxattr("user.<name>") reads x-amz-meta-<name> via a signed HEAD;
 * listxattr enumerates every x-amz-meta-* header (needs a transport with the
 * optional resp_headers_raw slot — without it sd_s3_list_meta reports
 * ENOTSUP). Both open the object read-only just for the HEAD, mirroring the
 * stat body below. */
static sd_s3_file *
sd_remote_meta_open(brix_sd_instance_t *inst, const char *path)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params           p;
    char                        objpath[768];
    char                        errbuf[256];

    sd_remote_s3_key(cfg, path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);
    return sd_s3_open_read(&p, errbuf, sizeof(errbuf));
}

ssize_t
sd_remote_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
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
    s3 = sd_remote_meta_open(inst, path);
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
sd_remote_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap)
{
    char        errbuf[256];
    sd_s3_file *s3;
    ssize_t     n;

    s3 = sd_remote_meta_open(inst, path);
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

/* Shared stat body: HEAD the object, optionally signing with a per-user
 * ak/sk/region override (NULL = the instance's static service credential). */
static ngx_int_t
sd_remote_stat_impl(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const char *ak, const char *sk, const char *region)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          objpath[768];
    char                          errbuf[256];
    sd_s3_file                   *s3;
    int64_t                       size = 0;

    sd_remote_s3_key(cfg, path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);
    if (ak != NULL)     { p.ak     = ak; }
    if (sk != NULL)     { p.sk     = sk; }
    if (region != NULL) { p.region = region; }

    s3 = sd_s3_open_read(&p, errbuf, sizeof(errbuf));
    if (s3 == NULL) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    if (sd_s3_size(s3, &size, errbuf, sizeof(errbuf)) != 0) {
        sd_s3_close(s3);
        errno = EIO;
        return NGX_ERROR;
    }
    sd_s3_close(s3);

    memset(out, 0, sizeof(*out));
    out->size   = (off_t) size;
    out->mode   = S_IFREG | 0444;
    out->is_reg = 1;
    return NGX_OK;
}

ngx_int_t
sd_remote_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    return sd_remote_stat_impl(inst, path, out, NULL, NULL, NULL);
}

/* Cred-scoped stat (P80.3): the probe/HEAD runs as the requesting user, so a
 * deny-mode request never reaches the origin under the service credential.
 * Registering this slot is also the canonical capability gate that turns on
 * per-user namespace credential resolution in brix_vfs_ns_cred(). */
ngx_int_t
sd_remote_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_stat_impl(inst, path, out,
            cred->s3_ak, cred->s3_sk, cred->s3_region);
    }
    if (gate < 0) {
        errno = EACCES;
        return NGX_ERROR;
    }
    return sd_remote_stat_impl(inst, path, out, NULL, NULL, NULL);
}
