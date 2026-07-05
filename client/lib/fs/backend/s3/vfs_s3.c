/*
 * vfs_s3.c - (kept) routing + shared helpers
 * Phase-38 split of vfs_s3.c; behavior-identical.
 */
#include "vfs_s3_internal.h"

const brix_vfs_ops s_s3_ops = {
    .pread    = s3_pread,
    .pwrite   = s3_pwrite,
    .fstat    = s3_fstat,
    .truncate = s3_truncate,
    .sync     = s3_sync,
    .commit   = s3_commit,
    .abort    = s3_abort,
    .close    = s3_close,
};

const brix_vfs_backend s_s3_backend = {
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


int
s3_brix_from_errno(int e)
{
    switch (e) {
    case EACCES:
    case EPERM:  return XRDC_EAUTH;    /* HTTP 401/403 → auth */
    case EINVAL: return XRDC_EUSAGE;   /* non-sequential write → usage */
    case ENOENT: return XRDC_ENOENT;   /* HTTP 404 → not found */
    default:     return XRDC_EIO;      /* everything else: local/IO error */
    }
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
s3_open_read(vfs_s3_file *sf, brix_status *st)
{
    char              errbuf[256] = "";
    sd_s3_open_params p;

    sf->obj_size = -1;   /* loaded lazily by s3_fstat → s3_load_size */

    /* Read goes through the shared S3 driver (src/fs/backend/sd_s3.c) over the
     * client's HTTP transport: HEAD-size + Range-GET live there, once. */
    memset(&p, 0, sizeof(p));
    p.host       = sf->host;
    p.port       = sf->port;
    p.tls        = sf->tls;
    p.key        = sf->key_path;
    p.ak         = sf->ak;
    p.sk         = sf->sk;
    p.region     = sf->region;
    p.transport  = &brix_s3_http_transport;
    p.tctx       = NULL;
    p.timeout_ms = S3_REQ_TIMEOUT_MS;

    sf->sd = sd_s3_open_read(&p, errbuf, sizeof(errbuf));
    if (sf->sd == NULL) {
        brix_status_set(st, XRDC_EIO, 0, "s3 open read: %s", errbuf);
        return -1;
    }
    return 0;
}




/*
 * s3_be_open — allocate a vfs_s3_file and prepare the handle.
 *
 * WHAT: parses the URL; reads credentials; chooses single-PUT or MPU write mode;
 *       returns a ready handle in *out.
 * WHY:  single entry point for the S3 backend; hides URL/mode routing from the
 *       façade.
 * HOW:  brix_weburl_parse; s3_alloc_handle; route to s3_open_read /
 *       s3_open_write_single / s3_open_write_mpu based on flags + expected_size.
 *       On any failure, free sf and return -1.
 */
int
s3_be_open(const brix_vfs_backend *be, const char *url, int flags,
           const brix_vfs_open_opts *opts, brix_vfs_file **out,
           brix_status *st)
{
    brix_weburl     wu;
    vfs_s3_file    *sf;
    int             rc;

    (void) be;

    *out = NULL;

    if (brix_weburl_parse(url, &wu) != 0 || !wu.is_s3) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "s3 backend: not an S3 URL: %s", url);
        return -1;
    }

    sf = s3_alloc_handle();
    if (sf == NULL) {
        brix_status_set(st, XRDC_EIO, ENOMEM,
                        "s3 open: out of memory allocating handle");
        return -1;
    }
    snprintf(sf->host,     sizeof(sf->host),     "%s", wu.host);
    sf->port = wu.port;
    sf->tls  = wu.tls;
    snprintf(sf->key_path, sizeof(sf->key_path), "%s", wu.path);
    s3_creds_load(sf, opts);

    if (flags & XRDC_VFS_WRITE) {
        /* Write goes through the shared S3 driver (single-PUT vs MPU decided
         * there from expected_size + part_size). */
        char              errbuf[256] = "";
        sd_s3_open_params p;
        int64_t           exp = (opts != NULL) ? opts->expected_size : -1;

        memset(&p, 0, sizeof(p));
        p.host       = sf->host;
        p.port       = sf->port;
        p.tls        = sf->tls;
        p.key        = sf->key_path;
        p.ak         = sf->ak;
        p.sk         = sf->sk;
        p.region     = sf->region;
        p.transport  = &brix_s3_http_transport;
        p.tctx       = NULL;
        p.timeout_ms = S3_REQ_TIMEOUT_MS;

        errno = 0;   /* the driver sets errno at its error sites; see below */
        sf->sd = sd_s3_open_write(&p, exp, s3_part_size_from_env(),
                                  errbuf, sizeof(errbuf));
        if (sf->sd == NULL) {
            int e = errno;
            brix_status_set(st, s3_brix_from_errno(e), e,
                            "s3 open write: %s", errbuf);
            rc = -1;
        } else {
            sf->is_write = 1;
            rc = 0;
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
 * HOW:  s3_alloc_handle; parse URL; s3_load_size; fill brix_vfs_stat; free.
 *       ENOENT-equivalent (404) → exists=0, return 0; other errors → -1.
 */
int
s3_be_stat(const brix_vfs_backend *be, const char *url,
           brix_vfs_stat *out, brix_status *st)
{
    brix_weburl     wu;
    vfs_s3_file    *sf;
    int             rc;

    (void) be;

    if (brix_weburl_parse(url, &wu) != 0 || !wu.is_s3) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "s3 stat: not an S3 URL: %s", url);
        return -1;
    }

    sf = s3_alloc_handle();
    if (sf == NULL) {
        brix_status_set(st, XRDC_EIO, ENOMEM,
                        "s3 stat: out of memory");
        return -1;
    }
    snprintf(sf->host,     sizeof(sf->host),     "%s", wu.host);
    sf->port = wu.port;
    sf->tls  = wu.tls;
    snprintf(sf->key_path, sizeof(sf->key_path), "%s", wu.path);

    /* Use no-op open_opts for stat (no cred store yet). */
    {
        brix_vfs_open_opts dummy_opts;
        memset(&dummy_opts, 0, sizeof(dummy_opts));
        dummy_opts.expected_size = -1;
        s3_creds_load(sf, &dummy_opts);
    }

    /* Create the shared read driver handle (s3_load_size delegates to it). */
    if (s3_open_read(sf, st) != 0) {
        free(sf);
        return -1;
    }
    rc = s3_load_size(sf, st);
    if (rc != 0) {
        /* 404 → exists=0 (not an error at the stat level) */
        if (st->kxr == XRDC_ENOENT) {
            out->exists = 0;
            out->size   = 0;
            out->mtime  = 0;
            out->is_dir = 0;
            sd_s3_close(sf->sd);
            free(sf);
            brix_status_clear(st);
            return 0;
        }
        sd_s3_close(sf->sd);
        free(sf);
        return -1;
    }

    out->size   = sf->obj_size;
    out->mtime  = 0;
    out->is_dir = 0;
    out->exists = 1;
    sd_s3_close(sf->sd);
    free(sf);
    return 0;
}


/* Backend descriptor + accessor */

/*
 * brix_vfs_s3_backend — pure factory: return the S3 backend descriptor.
 *
 * WHAT: strong definition that overrides the weak stub in vfs.c; called once
 *       during vfs_init_backends() (pthread_once).  Returns the static
 *       descriptor; vfs.c's init owns the brix_vfs_register_backend() call.
 * WHY:  registration is the façade's responsibility — the accessor must not
 *       double-register (which would consume registry slots).
 * HOW:  return the static descriptor directly.
 */
const brix_vfs_backend *
brix_vfs_s3_backend(void)
{
    return &s_s3_backend;
}
