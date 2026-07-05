#ifndef BRIX_FS_BACKEND_XROOT_SD_XROOT_INTERNAL_H
#define BRIX_FS_BACKEND_XROOT_SD_XROOT_INTERNAL_H

/*
 * sd_xroot_internal.h — driver-private state + cross-file entry points for the
 * root:// origin driver.
 *
 * The per-export instance state and the errno helper are shared by the I/O /
 * lifecycle path (sd_xroot.c) and the namespace + metadata path
 * (sd_xroot_ns.c); the namespace vtable ops are defined in sd_xroot_ns.c but
 * referenced by the driver struct in sd_xroot.c.  Driver-private: not part of
 * the sd_xroot public surface (sd_xroot.h).
 */

#include "sd_xroot.h"                    /* brix_sd_instance_t, module conf */
#include "fs/cache/cache_internal.h"     /* brix_cache_fill_t + origin wire client */

/* Per-export instance state (inst->state): the resolved origin params.  For a
 * cache-constructed instance `conf` is the real export conf; for a registry-built
 * PRIMARY backend (a stream/http export with no stream conf) `synth` owns a
 * minimal conf carrying just cache_origin_host/port/tls (+ trusted_ca, TLS-only). */
typedef struct {
    ngx_stream_brix_srv_conf_t *conf;    /* origin params (real or synthetic) */
    ngx_stream_brix_srv_conf_t *synth;   /* owned synthetic conf, or NULL */
    char                          host[256];
    char                          bearer[4096]; /* §14/C-3 ztn token ("" = anon) */
    char                          x509_proxy[1024]; /* §14/C-3 GSI proxy path */
    char                          ca_dir[1024];     /* §14/C-3 GSI origin-cert CA */
    char                          sss_keytab[1024]; /* §14 SSS shared-secret keytab */
} sd_xroot_inst_state;

/* errno for a completed fill task (sd_xroot.c), shared by both paths. */
int sd_xroot_errno(const brix_cache_fill_t *t);

/* Namespace + metadata vtable ops (sd_xroot_ns.c), wired into the driver struct
 * in sd_xroot.c. */
ssize_t   sd_xroot_getxattr(brix_sd_instance_t *inst, const char *path,
              const char *name, void *buf, size_t cap);
ssize_t   sd_xroot_listxattr(brix_sd_instance_t *inst, const char *path,
              void *buf, size_t cap);
ngx_int_t sd_xroot_setxattr(brix_sd_instance_t *inst, const char *path,
              const char *name, const void *val, size_t len, int flags);
ngx_int_t sd_xroot_removexattr(brix_sd_instance_t *inst, const char *path,
              const char *name);
ngx_int_t sd_xroot_rename(brix_sd_instance_t *inst, const char *src,
              const char *dst, int noreplace);
ngx_int_t sd_xroot_unlink(brix_sd_instance_t *inst, const char *path, int is_dir);
ngx_int_t sd_xroot_server_copy(brix_sd_instance_t *inst, const char *src,
              const char *dst, off_t *bytes_out);

#endif /* BRIX_FS_BACKEND_XROOT_SD_XROOT_INTERNAL_H */
