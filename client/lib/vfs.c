/* client/lib/vfs.c
 *
 * WHAT: Façade dispatch for xrdc_vfs_* API + a small backend registry.
 *       Routes URL→scheme→backend; thin wrappers call the per-handle vtable.
 * WHY:  Copy endpoints (local POSIX, block device, S3/object) need a single
 *       open-file abstraction. The registry lets backends (A3/A4/A5) plug in
 *       without touching this file.
 * HOW:  g_backends[] static array; lazy one-time init via pthread_once calls
 *       the three backend accessors (defined in tasks A3/A4/A5). URL→scheme:
 *       s3://…/s3s://… if xrdc_is_web_url && is_s3; block:// or /dev/... →
 *       "block"; else "file" (strip file:// prefix). Façade calls ops vtable.
 *       ngx-free; no goto; functional/modular design.
 */

#include "vfs.h"
#include "xrdc.h"

#include <string.h>
#include <pthread.h>

/* Backend registry */
#define VFS_MAX_BACKENDS 8

static const xrdc_vfs_backend *g_backends[VFS_MAX_BACKENDS];
static int                     g_n_backends;
static pthread_once_t          g_init_once = PTHREAD_ONCE_INIT;

/*
 * xrdc_vfs_register_backend — add *be to the registry.
 *
 * WHAT: appends be to g_backends[]; silently ignores NULL and overflow.
 * WHY:  called by each backend accessor during lazy init; callers never
 *       need a return value (double-register is benign).
 * HOW:  guard NULL and capacity, then store.
 */
void
xrdc_vfs_register_backend(const xrdc_vfs_backend *be)
{
    if (be == NULL || g_n_backends >= VFS_MAX_BACKENDS) {
        return;
    }
    g_backends[g_n_backends++] = be;
}

/*
 * Backend accessor prototypes — defined in tasks A3 (posix), A4 (block),
 * A5 (s3).  Declared __attribute__((weak)) so libxrdc.{a,so} builds cleanly
 * before those tasks land; a NULL weak symbol is skipped in vfs_init_backends.
 */
extern const xrdc_vfs_backend *xrdc_vfs_posix_backend(void)
    __attribute__((weak));
extern const xrdc_vfs_backend *xrdc_vfs_block_backend(void)
    __attribute__((weak));
extern const xrdc_vfs_backend *xrdc_vfs_s3_backend(void)
    __attribute__((weak));

/*
 * vfs_init_backends — one-time registration of all known backends.
 *
 * WHAT: called via pthread_once on the first xrdc_vfs_open or stat_url.
 * WHY:  defers backend init until needed; avoids ordering issues at startup.
 * HOW:  guards each call on a non-NULL weak accessor before invoking it.
 */
static void
vfs_init_backends(void)
{
    if (xrdc_vfs_posix_backend != NULL) {
        xrdc_vfs_register_backend(xrdc_vfs_posix_backend());
    }
    if (xrdc_vfs_block_backend != NULL) {
        xrdc_vfs_register_backend(xrdc_vfs_block_backend());
    }
    if (xrdc_vfs_s3_backend != NULL) {
        xrdc_vfs_register_backend(xrdc_vfs_s3_backend());
    }
}

/* URL→scheme routing */
/*
 * vfs_url_to_scheme — classify a URL string into a backend scheme + effective path.
 *
 * WHAT: fills *scheme_out and *path_out from the URL grammar.
 * WHY:  one place owns the URL grammar for the VFS layer; keeps open/stat DRY.
 * HOW:
 *   s3://…  / s3s://…  → scheme "s3" / "s3s";  path = original URL (backend parses it).
 *   block://…           → scheme "block";         path = URL + 8 (strip "block://").
 *   /dev/…              → scheme "block";         path = URL (raw device path).
 *   file:///…           → scheme "file";          path = URL + 7 (strip "file://").
 *   bare path / other   → scheme "file";          path = URL.
 *   http/dav (non-s3)   → *scheme_out = NULL (no VFS backend; caller errors out).
 */
static void
vfs_url_to_scheme(const char *url, const char **scheme_out,
                  const char **path_out)
{
    if (xrdc_is_web_url(url)) {
        xrdc_weburl wu;
        if (xrdc_weburl_parse(url, &wu) == 0 && wu.is_s3) {
            *scheme_out = (wu.proto == XRDC_WEB_S3S) ? "s3s" : "s3";
            *path_out   = url;
            return;
        }
        /* Non-s3 web URL (http/https/dav/davs) — no VFS backend. */
        *scheme_out = NULL;
        *path_out   = url;
        return;
    }

    if (strncmp(url, "block://", 8) == 0) {
        *scheme_out = "block";
        *path_out   = url + 8;
        return;
    }

    if (strncmp(url, "/dev/", 5) == 0) {
        *scheme_out = "block";
        *path_out   = url;
        return;
    }

    if (strncmp(url, "file://", 7) == 0) {
        *scheme_out = "file";
        *path_out   = url + 7;
        return;
    }

    /* Bare path or any other local-looking string → POSIX file backend. */
    *scheme_out = "file";
    *path_out   = url;
}

/*
 * vfs_find_backend — look up a registered backend by scheme name.
 *
 * WHAT: linear scan of g_backends[0..g_n_backends); returns NULL on miss.
 * WHY:  registry is small (≤8 entries); a linear scan is fast and obvious.
 * HOW:  strcmp on be->scheme; returns first match.
 */
static const xrdc_vfs_backend *
vfs_find_backend(const char *scheme)
{
    int i;
    for (i = 0; i < g_n_backends; i++) {
        if (strcmp(g_backends[i]->scheme, scheme) == 0) {
            return g_backends[i];
        }
    }
    return NULL;
}

/* Façade: URL-level operations */
/*
 * xrdc_vfs_open — open a storage URL and return a VFS file handle.
 *
 * WHAT: routes URL to the right backend; calls be->open; stores result in *out.
 * WHY:  single entry point for copy.c/tools; hides backend selection.
 * HOW:  lazy-init backends; classify URL; look up backend; delegate to be->open.
 *       Returns 0 on success, -1 with *st filled on error.
 */
int
xrdc_vfs_open(const char *url, int flags, const xrdc_vfs_open_opts *opts,
              xrdc_vfs_file **out, xrdc_status *st)
{
    const char             *scheme;
    const char             *path;
    const xrdc_vfs_backend *be;

    pthread_once(&g_init_once, vfs_init_backends);
    vfs_url_to_scheme(url, &scheme, &path);

    if (scheme == NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "vfs: no backend for non-s3 web URL '%s'", url);
        return -1;
    }

    be = vfs_find_backend(scheme);
    if (be == NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "vfs: no registered backend for scheme '%s'", scheme);
        return -1;
    }

    return be->open(be, path, flags, opts, out, st);
}

/*
 * xrdc_vfs_stat_url — stat a storage URL without opening it.
 *
 * WHAT: routes URL to the right backend; calls be->stat; fills *out.
 * WHY:  allows pre-transfer existence/size checks without a full open.
 * HOW:  same routing as xrdc_vfs_open; delegates to be->stat.
 *       Returns 0 on success, -1 with *st filled on error.
 */
int
xrdc_vfs_stat_url(const char *url, const xrdc_vfs_open_opts *opts,
                  xrdc_vfs_stat *out, xrdc_status *st)
{
    const char             *scheme;
    const char             *path;
    const xrdc_vfs_backend *be;

    (void)opts;   /* passed to be->stat in future; backend vtable does not yet consume it */

    pthread_once(&g_init_once, vfs_init_backends);
    vfs_url_to_scheme(url, &scheme, &path);

    if (scheme == NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "vfs: no backend for non-s3 web URL '%s'", url);
        return -1;
    }

    be = vfs_find_backend(scheme);
    if (be == NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "vfs: no registered backend for scheme '%s'", scheme);
        return -1;
    }

    return be->stat(be, path, out, st);
}

/* Façade: per-handle vtable wrappers */
/*
 * xrdc_vfs_pread — read n bytes at offset off into buf.
 *
 * WHAT: thin wrapper; forward to f->ops->pread.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward all args; return the backend result.
 */
ssize_t
xrdc_vfs_pread(xrdc_vfs_file *f, int64_t off, void *buf, size_t n,
               xrdc_status *st)
{
    return f->ops->pread(f, off, buf, n, st);
}

/*
 * xrdc_vfs_pwrite — write n bytes from buf at offset off.
 *
 * WHAT: thin wrapper; forward to f->ops->pwrite.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward all args; return the backend result.
 */
int
xrdc_vfs_pwrite(xrdc_vfs_file *f, int64_t off, const void *buf, size_t n,
                xrdc_status *st)
{
    return f->ops->pwrite(f, off, buf, n, st);
}

/*
 * xrdc_vfs_fstat — stat an open file handle.
 *
 * WHAT: thin wrapper; forward to f->ops->fstat.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward all args; return the backend result.
 */
int
xrdc_vfs_fstat(xrdc_vfs_file *f, xrdc_vfs_stat *out, xrdc_status *st)
{
    return f->ops->fstat(f, out, st);
}

/*
 * xrdc_vfs_truncate — truncate an open file to size bytes.
 *
 * WHAT: thin wrapper; forward to f->ops->truncate.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward all args; return the backend result.
 */
int
xrdc_vfs_truncate(xrdc_vfs_file *f, int64_t size, xrdc_status *st)
{
    return f->ops->truncate(f, size, st);
}

/*
 * xrdc_vfs_sync — flush dirty pages to durable storage.
 *
 * WHAT: thin wrapper; forward to f->ops->sync.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward all args; return the backend result.
 */
int
xrdc_vfs_sync(xrdc_vfs_file *f, xrdc_status *st)
{
    return f->ops->sync(f, st);
}

/*
 * xrdc_vfs_commit — finalise a write (rename temp→final / complete MPU / fsync).
 *
 * WHAT: thin wrapper; forward to f->ops->commit.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward all args; return the backend result.
 */
int
xrdc_vfs_commit(xrdc_vfs_file *f, xrdc_status *st)
{
    return f->ops->commit(f, st);
}

/*
 * xrdc_vfs_abort — discard a partial write (unlink temp / abort MPU).
 *
 * WHAT: thin wrapper; forward to f->ops->abort.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward; no return value.
 */
void
xrdc_vfs_abort(xrdc_vfs_file *f)
{
    f->ops->abort(f);
}

/*
 * xrdc_vfs_close — release the file handle after commit or abort.
 *
 * WHAT: thin wrapper; forward to f->ops->close.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward; no return value.
 */
void
xrdc_vfs_close(xrdc_vfs_file *f)
{
    f->ops->close(f);
}

/*
 * xrdc_vfs_get_caps — return the capability flags for an open handle.
 *
 * WHAT: direct read of f->caps (set by the backend's open()).
 * WHY:  copy.c picks the I/O strategy (random-write vs append/stream) from
 *       caps; it is a field, not a vtable call, so no indirection needed.
 * HOW:  return f->caps.
 */
uint32_t
xrdc_vfs_get_caps(const xrdc_vfs_file *f)
{
    return f->caps;
}
