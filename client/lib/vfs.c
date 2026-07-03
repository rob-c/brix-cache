/* client/lib/vfs.c
 *
 * WHAT: Façade dispatch for brix_vfs_* API + a small backend registry.
 *       Routes URL→scheme→backend; thin wrappers call the per-handle vtable.
 * WHY:  Copy endpoints (local POSIX, block device, S3/object) need a single
 *       open-file abstraction. The registry lets backends (A3/A4/A5) plug in
 *       without touching this file.
 * HOW:  g_backends[] static array; lazy one-time init via pthread_once calls
 *       the three backend accessors (defined in tasks A3/A4/A5). URL→scheme:
 *       s3://…/s3s://… if brix_is_web_url && is_s3; block:// or /dev/... →
 *       "block"; else "file" (strip file:// prefix). Façade calls ops vtable.
 *       ngx-free; no goto; functional/modular design.
 */

#include "vfs.h"
#include "brix.h"

#include <string.h>
#include <pthread.h>

/* Backend registry */
#define VFS_MAX_BACKENDS 8

static const brix_vfs_backend *g_backends[VFS_MAX_BACKENDS];
static int                     g_n_backends;
static pthread_once_t          g_init_once = PTHREAD_ONCE_INIT;

/*
 * brix_vfs_register_backend — add *be to the registry.
 *
 * WHAT: appends be to g_backends[]; silently ignores NULL and overflow.
 * WHY:  called by each backend accessor during lazy init; callers never
 *       need a return value (double-register is benign).
 * HOW:  guard NULL and capacity, then store.
 */
void
brix_vfs_register_backend(const brix_vfs_backend *be)
{
    if (be == NULL || g_n_backends >= VFS_MAX_BACKENDS) {
        return;
    }
    g_backends[g_n_backends++] = be;
}

/*
 * Backend accessor prototypes — defined in tasks A3 (posix), A4 (block),
 * A5 (s3).  Declared __attribute__((weak)) so libbrix.{a,so} builds cleanly
 * before those tasks land; a NULL weak symbol is skipped in vfs_init_backends.
 */
extern const brix_vfs_backend *brix_vfs_posix_backend(void)
    __attribute__((weak));
extern const brix_vfs_backend *brix_vfs_block_backend(void)
    __attribute__((weak));
extern const brix_vfs_backend *brix_vfs_s3_backend(void)
    __attribute__((weak));

/*
 * vfs_init_backends — one-time registration of all known backends.
 *
 * WHAT: called via pthread_once on the first brix_vfs_open or stat_url.
 * WHY:  defers backend init until needed; avoids ordering issues at startup.
 * HOW:  guards each call on a non-NULL weak accessor before invoking it.
 */
static void
vfs_init_backends(void)
{
    if (brix_vfs_posix_backend != NULL) {
        brix_vfs_register_backend(brix_vfs_posix_backend());
    }
    if (brix_vfs_block_backend != NULL) {
        brix_vfs_register_backend(brix_vfs_block_backend());
    }
    if (brix_vfs_s3_backend != NULL) {
        brix_vfs_register_backend(brix_vfs_s3_backend());
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
    if (brix_is_web_url(url)) {
        brix_weburl wu;
        if (brix_weburl_parse(url, &wu) == 0 && wu.is_s3) {
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
static const brix_vfs_backend *
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
 * brix_vfs_open — open a storage URL and return a VFS file handle.
 *
 * WHAT: routes URL to the right backend; calls be->open; stores result in *out.
 * WHY:  single entry point for copy.c/tools; hides backend selection.
 * HOW:  lazy-init backends; classify URL; look up backend; delegate to be->open.
 *       Returns 0 on success, -1 with *st filled on error.
 */
int
brix_vfs_open(const char *url, int flags, const brix_vfs_open_opts *opts,
              brix_vfs_file **out, brix_status *st)
{
    const char             *scheme;
    const char             *path;
    const brix_vfs_backend *be;

    pthread_once(&g_init_once, vfs_init_backends);
    vfs_url_to_scheme(url, &scheme, &path);

    if (scheme == NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "vfs: no backend for non-s3 web URL '%s'", url);
        return -1;
    }

    be = vfs_find_backend(scheme);
    if (be == NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "vfs: no registered backend for scheme '%s'", scheme);
        return -1;
    }

    return be->open(be, path, flags, opts, out, st);
}

/*
 * brix_vfs_stat_url — stat a storage URL without opening it.
 *
 * WHAT: routes URL to the right backend; calls be->stat; fills *out.
 * WHY:  allows pre-transfer existence/size checks without a full open.
 * HOW:  same routing as brix_vfs_open; delegates to be->stat.
 *       Returns 0 on success, -1 with *st filled on error.
 */
int
brix_vfs_stat_url(const char *url, const brix_vfs_open_opts *opts,
                  brix_vfs_stat *out, brix_status *st)
{
    const char             *scheme;
    const char             *path;
    const brix_vfs_backend *be;

    (void)opts;   /* passed to be->stat in future; backend vtable does not yet consume it */

    pthread_once(&g_init_once, vfs_init_backends);
    vfs_url_to_scheme(url, &scheme, &path);

    if (scheme == NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "vfs: no backend for non-s3 web URL '%s'", url);
        return -1;
    }

    be = vfs_find_backend(scheme);
    if (be == NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "vfs: no registered backend for scheme '%s'", scheme);
        return -1;
    }

    return be->stat(be, path, out, st);
}

/* Façade: per-handle vtable wrappers */
/*
 * brix_vfs_pread — read n bytes at offset off into buf.
 *
 * WHAT: thin wrapper; forward to f->ops->pread.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward all args; return the backend result.
 */
ssize_t
brix_vfs_pread(brix_vfs_file *f, int64_t off, void *buf, size_t n,
               brix_status *st)
{
    return f->ops->pread(f, off, buf, n, st);
}

/*
 * brix_vfs_pwrite — write n bytes from buf at offset off.
 *
 * WHAT: thin wrapper; forward to f->ops->pwrite.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward all args; return the backend result.
 */
int
brix_vfs_pwrite(brix_vfs_file *f, int64_t off, const void *buf, size_t n,
                brix_status *st)
{
    return f->ops->pwrite(f, off, buf, n, st);
}

/*
 * brix_vfs_fstat — stat an open file handle.
 *
 * WHAT: thin wrapper; forward to f->ops->fstat.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward all args; return the backend result.
 */
int
brix_vfs_fstat(brix_vfs_file *f, brix_vfs_stat *out, brix_status *st)
{
    return f->ops->fstat(f, out, st);
}

/*
 * brix_vfs_truncate — truncate an open file to size bytes.
 *
 * WHAT: thin wrapper; forward to f->ops->truncate.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward all args; return the backend result.
 */
int
brix_vfs_truncate(brix_vfs_file *f, int64_t size, brix_status *st)
{
    return f->ops->truncate(f, size, st);
}

/*
 * brix_vfs_sync — flush dirty pages to durable storage.
 *
 * WHAT: thin wrapper; forward to f->ops->sync.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward all args; return the backend result.
 */
int
brix_vfs_sync(brix_vfs_file *f, brix_status *st)
{
    return f->ops->sync(f, st);
}

/*
 * brix_vfs_commit — finalise a write (rename temp→final / complete MPU / fsync).
 *
 * WHAT: thin wrapper; forward to f->ops->commit.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward all args; return the backend result.
 */
int
brix_vfs_commit(brix_vfs_file *f, brix_status *st)
{
    return f->ops->commit(f, st);
}

/*
 * brix_vfs_abort — discard a partial write (unlink temp / abort MPU).
 *
 * WHAT: thin wrapper; forward to f->ops->abort.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward; no return value.
 */
void
brix_vfs_abort(brix_vfs_file *f)
{
    f->ops->abort(f);
}

/*
 * brix_vfs_close — release the file handle after commit or abort.
 *
 * WHAT: thin wrapper; forward to f->ops->close.
 * WHY:  callers never dereference the vtable directly.
 * HOW:  forward; no return value.
 */
void
brix_vfs_close(brix_vfs_file *f)
{
    f->ops->close(f);
}

/*
 * brix_vfs_get_caps — return the capability flags for an open handle.
 *
 * WHAT: direct read of f->caps (set by the backend's open()).
 * WHY:  copy.c picks the I/O strategy (random-write vs append/stream) from
 *       caps; it is a field, not a vtable call, so no indirection needed.
 * HOW:  return f->caps.
 */
uint32_t
brix_vfs_get_caps(const brix_vfs_file *f)
{
    return f->caps;
}
