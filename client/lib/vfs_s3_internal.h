/*
 * vfs_s3_internal.h - private split contract for the S3 backend client shell.
 * Not a public API: include only from client/lib/.
 *
 * The S3 storage logic (SigV4, HEAD/Range-GET, single-PUT, multipart upload)
 * now lives in the shared driver src/fs/backend/sd_s3.c (ngx-free, libxrdproto).
 * This shell only: parses the s3:// URL, loads credentials, picks the backend,
 * and adapts the brix_vfs vtable onto the shared driver via vfs_s3_transport.c.
 */
#ifndef BRIX_VFS_S3_INTERNAL_H
#define BRIX_VFS_S3_INTERNAL_H

#include "vfs.h"
#include "brix.h"
#include "core/compat/host_format.h"
#include "fs/backend/s3/sd_s3.h"            /* the shared S3 driver */
#include "fs/backend/s3/sd_s3_transport.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define S3_PART_MAX_DEFAULT  (64LL * 1024 * 1024)
#define S3_PART_MAX_ENV      "S3_PART_MAX_OVERRIDE"
#define S3_REQ_TIMEOUT_MS    300000
#define S3_REGION_DEFAULT    "us-east-1"

/* Client-side S3 handle: the URL endpoint + credentials it parsed, plus the
 * shared driver handle that does all the actual S3 I/O. */
typedef struct {
    brix_vfs_file  base;          /* MUST be first — aliased by the façade */
    char           host[256];
    int            port;
    int            tls;
    char           key_path[XRDC_PATH_MAX];
    char           ak[128];
    char           sk[256];
    char           region[64];
    int64_t        obj_size;      /* cached object size for read fstat (-1 lazy) */
    int            is_write;      /* 1 = write handle, 0 = read */
    sd_s3_file    *sd;            /* shared S3 driver handle (does the I/O) */
} vfs_s3_file;

extern const brix_vfs_ops s_s3_ops;
extern const brix_vfs_backend s_s3_backend;
extern const brix_s3_transport_t brix_s3_http_transport;

/* vfs_s3_http.c — credential loading (the only HTTP helper still client-side). */
void s3_creds_load(vfs_s3_file *sf, const brix_vfs_open_opts *opts);

/* vfs_s3_io.c — the brix_vfs vtable, delegating to the shared driver. */
int     s3_load_size(vfs_s3_file *sf, brix_status *st);
ssize_t s3_pread(brix_vfs_file *f, int64_t off, void *buf, size_t n, brix_status *st);
int     s3_pwrite(brix_vfs_file *f, int64_t off, const void *buf, size_t n, brix_status *st);
int     s3_fstat(brix_vfs_file *f, brix_vfs_stat *out, brix_status *st);
int     s3_truncate(brix_vfs_file *f, int64_t size, brix_status *st);
int     s3_sync(brix_vfs_file *f, brix_status *st);
int     s3_commit(brix_vfs_file *f, brix_status *st);
void    s3_abort(brix_vfs_file *f);
void    s3_close(brix_vfs_file *f);

/* vfs_s3.c — URL parse + backend open/stat. */
int64_t      s3_part_size_from_env(void);
/* Map an errno set by the shared sd_s3 backend at a write/open error site to the
 * client XRDC_* status code (EACCES→XRDC_EAUTH, EINVAL→XRDC_EUSAGE,
 * ENOENT→XRDC_ENOENT, else XRDC_EIO), so an auth or usage failure is not
 * flattened into a generic XRDC_EIO. */
int          s3_brix_from_errno(int e);
vfs_s3_file *s3_alloc_handle(void);
int          s3_open_read(vfs_s3_file *sf, brix_status *st);
int          s3_be_open(const brix_vfs_backend *be, const char *url, int flags,
                        const brix_vfs_open_opts *opts, brix_vfs_file **out,
                        brix_status *st);
int          s3_be_stat(const brix_vfs_backend *be, const char *url,
                        brix_vfs_stat *out, brix_status *st);

#endif /* BRIX_VFS_S3_INTERNAL_H */
