/*
 * vfs_s3.c - (kept) routing + shared helpers
 * Phase-38 split of vfs_s3.c; behavior-identical.
 */
#include "vfs_s3_internal.h"

const xrdc_vfs_ops s_s3_ops = {
    .pread    = s3_pread,
    .pwrite   = s3_pwrite,
    .fstat    = s3_fstat,
    .truncate = s3_truncate,
    .sync     = s3_sync,
    .commit   = s3_commit,
    .abort    = s3_abort,
    .close    = s3_close,
};

const xrdc_vfs_backend s_s3_backend = {
    .scheme = "s3",
    .caps   = 0,   /* no RANDOM_WRITE, no TRUNCATE, no ATOMIC_TEMP */
    .open   = s3_be_open,
    .stat   = s3_be_stat,
};



/* vtable singleton */

/* Backend open + stat */
/*
 * s3_part_size_from_env — load the effective MPU part size.
 *
 * WHAT: returns S3_PART_MAX_DEFAULT unless S3_PART_MAX_OVERRIDE is set in the
 *       environment, in which case that value is used (minimum 1 byte).
 * WHY:  tests need to exercise the multipart code path with small objects; the
 *       env override lets a test set part_size=512 without recompiling.
 * HOW:  getenv + strtoll; fall back to default on absent/invalid values.
 */
int64_t
s3_part_size_from_env(void)
{
    const char *e = getenv(S3_PART_MAX_ENV);
    int64_t     v;

    if (e == NULL || e[0] == '\0') {
        return S3_PART_MAX_DEFAULT;
    }
    v = strtoll(e, NULL, 10);
    return (v > 0) ? v : S3_PART_MAX_DEFAULT;
}


/*
 * s3_alloc_handle — allocate and zero-fill a vfs_s3_file.
 *
 * WHAT: calloc a vfs_s3_file; return NULL on OOM.
 * WHY:  factor allocation out of s3_be_open so that path is readable.
 * HOW:  calloc; no other initialisation (caller sets fields).
 */
vfs_s3_file *
s3_alloc_handle(void)
{
    return (vfs_s3_file *) calloc(1, sizeof(vfs_s3_file));
}


/*
 * s3_open_read — open a handle for reading.
 *
 * WHAT: sets the read-mode-specific field (lazy obj_size); common fields
 *       (host/port/tls/key_path/creds/ops/caps) are already set by s3_be_open.
 * WHY:  deferred HEAD avoids a round-trip for callers that only write or never
 *       call fstat.
 * HOW:  set obj_size = -1; base ops/caps are set by s3_be_open after dispatch.
 */
int
s3_open_read(vfs_s3_file *sf, xrdc_status *st)
{
    (void) st;

    sf->obj_size = -1;   /* loaded lazily by s3_fstat → s3_load_size */
    return 0;
}


/*
 * s3_open_write_single — initialise a single-PUT write handle.
 *
 * WHAT: allocates the in-memory PUT buffer; decides the initial capacity from
 *       opts->expected_size (when known) or S3_PUT_BUF_INIT.
 * WHY:  single-PUT mode is used when the full object fits in one part and the
 *       size is known at open() time.
 * HOW:  malloc put_buf to max(expected_size, S3_PUT_BUF_INIT); set is_write=1.
 */
int
s3_open_write_single(vfs_s3_file *sf, const xrdc_vfs_open_opts *opts,
                     xrdc_status *st)
{
    size_t cap;

    cap = (opts->expected_size > 0)
          ? (size_t) opts->expected_size
          : S3_PUT_BUF_INIT;
    if (cap < (size_t) S3_PUT_BUF_INIT) {
        cap = S3_PUT_BUF_INIT;
    }
    sf->put_buf = malloc(cap);
    if (sf->put_buf == NULL) {
        xrdc_status_set(st, XRDC_EIO, ENOMEM,
                        "s3 open write: out of memory for PUT buffer");
        return -1;
    }
    sf->put_cap      = cap;
    sf->put_len      = 0;
    sf->put_write_off = 0;
    sf->is_write     = 1;
    sf->is_mpu       = 0;
    return 0;
}


/*
 * s3_open_write_mpu — initiate a multipart upload and initialise the MPU handle.
 *
 * WHAT: issues CreateMultipartUpload (POST /key?uploads), stores the UploadId,
 *       and allocates the part buffer.
 * WHY:  MPU is used when expected_size is unknown or larger than one part;
 *       the upload handle is ready for s3_pwrite_mpu calls immediately after.
 * HOW:  CreateMultipartUpload → parse UploadId → malloc part_buf of part_size;
 *       set is_write=1, is_mpu=1.  sf->part_size is set by s3_be_open before
 *       dispatch so it is not re-read here.
 */
int
s3_open_write_mpu(vfs_s3_file *sf, xrdc_status *st)
{
    if (s3_mpu_create(sf, st) != 0) {
        return -1;
    }
    sf->part_buf = malloc((size_t) sf->part_size);
    if (sf->part_buf == NULL) {
        xrdc_status_set(st, XRDC_EIO, ENOMEM,
                        "s3 open write mpu: out of memory for part buffer");
        /* upload was created on server; best-effort abort */
        s3_mpu_abort_upload(sf);
        return -1;
    }
    sf->part_buf_len  = 0;
    sf->mpu_write_off = 0;
    sf->part_count    = 0;
    sf->etags         = NULL;
    sf->etag_cap      = 0;
    sf->is_write      = 1;
    sf->is_mpu        = 1;
    return 0;
}


/*
 * s3_be_open — allocate a vfs_s3_file and prepare the handle.
 *
 * WHAT: parses the URL; reads credentials; chooses single-PUT or MPU write mode;
 *       returns a ready handle in *out.
 * WHY:  single entry point for the S3 backend; hides URL/mode routing from the
 *       façade.
 * HOW:  xrdc_weburl_parse; s3_alloc_handle; route to s3_open_read /
 *       s3_open_write_single / s3_open_write_mpu based on flags + expected_size.
 *       On any failure, free sf and return -1.
 */
int
s3_be_open(const xrdc_vfs_backend *be, const char *url, int flags,
           const xrdc_vfs_open_opts *opts, xrdc_vfs_file **out,
           xrdc_status *st)
{
    xrdc_weburl     wu;
    vfs_s3_file    *sf;
    int64_t         part_sz;
    int             rc;

    (void) be;

    *out = NULL;

    if (xrdc_weburl_parse(url, &wu) != 0 || !wu.is_s3) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "s3 backend: not an S3 URL: %s", url);
        return -1;
    }

    sf = s3_alloc_handle();
    if (sf == NULL) {
        xrdc_status_set(st, XRDC_EIO, ENOMEM,
                        "s3 open: out of memory allocating handle");
        return -1;
    }
    snprintf(sf->host,     sizeof(sf->host),     "%s", wu.host);
    sf->port = wu.port;
    sf->tls  = wu.tls;
    snprintf(sf->key_path, sizeof(sf->key_path), "%s", wu.path);
    s3_creds_load(sf, opts);

    if (flags & XRDC_VFS_WRITE) {
        /* Choose single-PUT vs MPU based on expected_size and part_size. */
        part_sz = s3_part_size_from_env();
        if (opts != NULL && opts->expected_size >= 0
            && opts->expected_size <= part_sz) {
            rc = s3_open_write_single(sf, opts, st);
        } else {
            sf->part_size = part_sz;
            rc = s3_open_write_mpu(sf, st);
        }
    } else {
        rc = s3_open_read(sf, st);
    }

    if (rc != 0) {
        free(sf);
        return -1;
    }

    sf->base.ops  = &s_s3_ops;
    sf->base.caps = 0;   /* S3: no RANDOM_WRITE, no TRUNCATE, no ATOMIC_TEMP */

    *out = &sf->base;
    return 0;
}


/*
 * s3_be_stat — stat an S3 object URL without opening a handle.
 *
 * WHAT: allocates a temporary handle, issues HEAD, fills *out, frees the handle.
 * WHY:  allows existence/size checks without a full open (mirrors posix_be_stat).
 * HOW:  s3_alloc_handle; parse URL; s3_load_size; fill xrdc_vfs_stat; free.
 *       ENOENT-equivalent (404) → exists=0, return 0; other errors → -1.
 */
int
s3_be_stat(const xrdc_vfs_backend *be, const char *url,
           xrdc_vfs_stat *out, xrdc_status *st)
{
    xrdc_weburl     wu;
    vfs_s3_file    *sf;
    int             rc;

    (void) be;

    if (xrdc_weburl_parse(url, &wu) != 0 || !wu.is_s3) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "s3 stat: not an S3 URL: %s", url);
        return -1;
    }

    sf = s3_alloc_handle();
    if (sf == NULL) {
        xrdc_status_set(st, XRDC_EIO, ENOMEM,
                        "s3 stat: out of memory");
        return -1;
    }
    snprintf(sf->host,     sizeof(sf->host),     "%s", wu.host);
    sf->port = wu.port;
    sf->tls  = wu.tls;
    snprintf(sf->key_path, sizeof(sf->key_path), "%s", wu.path);

    /* Use no-op open_opts for stat (no cred store yet). */
    {
        xrdc_vfs_open_opts dummy_opts;
        memset(&dummy_opts, 0, sizeof(dummy_opts));
        dummy_opts.expected_size = -1;
        s3_creds_load(sf, &dummy_opts);
    }

    sf->obj_size = -1;
    rc = s3_load_size(sf, st);
    if (rc != 0) {
        /* 404 → exists=0 (not an error at the stat level) */
        if (st->kxr == XRDC_ENOENT) {
            out->exists = 0;
            out->size   = 0;
            out->mtime  = 0;
            out->is_dir = 0;
            free(sf);
            xrdc_status_clear(st);
            return 0;
        }
        free(sf);
        return -1;
    }

    out->size   = sf->obj_size;
    out->mtime  = 0;
    out->is_dir = 0;
    out->exists = 1;
    free(sf);
    return 0;
}


/* Backend descriptor + accessor */

/*
 * xrdc_vfs_s3_backend — pure factory: return the S3 backend descriptor.
 *
 * WHAT: strong definition that overrides the weak stub in vfs.c; called once
 *       during vfs_init_backends() (pthread_once).  Returns the static
 *       descriptor; vfs.c's init owns the xrdc_vfs_register_backend() call.
 * WHY:  registration is the façade's responsibility — the accessor must not
 *       double-register (which would consume registry slots).
 * HOW:  return the static descriptor directly.
 */
const xrdc_vfs_backend *
xrdc_vfs_s3_backend(void)
{
    return &s_s3_backend;
}
