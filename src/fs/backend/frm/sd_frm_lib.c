/*
 * sd_frm_lib.c — the library-native MSS adapter: drives a real HSM through an
 * operator-supplied shared object (dlopen) instead of forking a stage command.
 *
 * Same residency/recall/migrate/purge model as the exec adapter (sd_frm_exec.c),
 * and it reuses the same online-buffer filesystem helpers (frm_mkparents /
 * open / pread live here or in sd_frm_stub.c); the ONLY difference is that each
 * verb is an in-process dlsym'd call rather than a posix_spawn + waitpid. On a
 * busy silo that removes the per-verb fork+exec that dominates small-object
 * staging latency — the phase-64 "library-native adapter" residual.
 *
 * The vendor .so is a runtime plug-in (exactly like a driver): if it is absent or
 * missing a required symbol, brix_mss_lib_create returns NULL and sd_frm.c falls
 * back to the exec/stub transport. The symbol ABI is sd_frm_lib_abi.h.
 */

#include "sd_frm_mss.h"
#include "sd_frm_lib_abi.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    char                     base[PATH_MAX];   /* local online-buffer root */
    void                    *dl;               /* dlopen handle            */
    brix_frm_hsm_exists_fn   fn_exists;
    brix_frm_hsm_recall_fn   fn_recall;
    brix_frm_hsm_migrate_fn  fn_migrate;
    brix_frm_hsm_purge_fn    fn_purge;         /* optional (may be NULL)   */
    ngx_log_t               *log;
} lib_ctx_t;

static int
lib_online_path(const lib_ctx_t *c, const char *key, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/.online/%s", c->base,
                     (key[0] == '/') ? key + 1 : key);

    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

static int
lib_residency(void *mss, const char *key, off_t *size_out, time_t *mtime_out)
{
    lib_ctx_t  *c = mss;
    char        online[PATH_MAX];
    struct stat sb;

    if (lib_online_path(c, key, online, sizeof(online)) == 0
        && stat(online, &sb) == 0)
    {
        if (size_out)  { *size_out = sb.st_size; }
        if (mtime_out) { *mtime_out = sb.st_mtime; }
        return BRIX_RESIDENCY_ONLINE;
    }
    /* Ask the library: 0 = on tape (offline), non-zero = absent. Size is unknown
     * until recalled; the cache fill restats the online buffer. */
    if (c->fn_exists(key) == 0) {
        if (size_out)  { *size_out = 0; }
        if (mtime_out) { *mtime_out = time(NULL); }
        return BRIX_RESIDENCY_OFFLINE;
    }
    return BRIX_RESIDENCY_ABSENT;
}

static int
lib_recall_begin(void *mss, const char *key)
{
    lib_ctx_t *c = mss;
    char       online[PATH_MAX];

    if (lib_online_path(c, key, online, sizeof(online)) != 0) {
        return -1;
    }
    if (access(online, F_OK) == 0) {
        return 0;                            /* already online */
    }
    frm_mkparents(online);                   /* the library writes the online buffer */
    return (c->fn_recall(key, online) == 0) ? 0 : -1;
}

static int
lib_recall_poll(void *mss, const char *key)
{
    lib_ctx_t *c = mss;
    char       online[PATH_MAX];

    if (lib_online_path(c, key, online, sizeof(online)) != 0) {
        return -1;
    }
    return (access(online, F_OK) == 0) ? 1 : 0;
}

static int
lib_migrate(void *mss, const char *key)
{
    lib_ctx_t *c = mss;
    char       online[PATH_MAX];

    if (lib_online_path(c, key, online, sizeof(online)) != 0) {
        return -1;
    }
    return (c->fn_migrate(key, online) == 0) ? 0 : -1;
}

static int
lib_purge(void *mss, const char *key)
{
    lib_ctx_t *c = mss;
    char       online[PATH_MAX];

    if (lib_online_path(c, key, online, sizeof(online)) == 0) {
        (void) unlink(online);
    }
    if (c->fn_purge != NULL) {
        (void) c->fn_purge(key);             /* best-effort MSS-side drop */
    }
    return 0;
}

static int
lib_open_online(void *mss, const char *key)
{
    lib_ctx_t *c = mss;
    char       online[PATH_MAX];

    if (lib_online_path(c, key, online, sizeof(online)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return open(online, O_RDONLY | O_CLOEXEC);
}

static int
lib_create_online(void *mss, const char *key, mode_t mode)
{
    lib_ctx_t *c = mss;
    char       online[PATH_MAX];

    if (lib_online_path(c, key, online, sizeof(online)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    frm_mkparents(online);
    return open(online, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC,
                mode ? mode : 0644);
}

static void
lib_destroy(void *mss)
{
    lib_ctx_t *c = mss;

    if (c == NULL) {
        return;
    }
    if (c->dl != NULL) {
        (void) dlclose(c->dl);
    }
    free(c);
}

const brix_mss_adapter_t brix_mss_lib_adapter = {
    .name          = "lib",
    .residency     = lib_residency,
    .recall_begin  = lib_recall_begin,
    .recall_poll   = lib_recall_poll,
    .migrate       = lib_migrate,
    .purge         = lib_purge,
    .open_online   = lib_open_online,
    .create_online = lib_create_online,
    .destroy       = lib_destroy,
};

/* brix_mss_lib_create — dlopen `libpath` and bind the HSM ABI.
 *
 * Returns the adapter context on success, or NULL when the library cannot be
 * opened or a REQUIRED symbol (exists/recall/migrate) is missing — the caller
 * (sd_frm.c) then WARNs and falls back to the exec/stub transport. `purge` is
 * optional. RTLD_LOCAL keeps the HSM library's symbols out of the global scope
 * so it cannot collide with nginx or another dlopen'd module. */
void *
brix_mss_lib_create(const char *location, const char *libpath, ngx_log_t *log)
{
    lib_ctx_t *c;

    if (libpath == NULL || libpath[0] == '\0') {
        return NULL;
    }
    c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    ngx_cpystrn((u_char *) c->base, (u_char *) location, sizeof(c->base));
    c->log = log;

    c->dl = dlopen(libpath, RTLD_NOW | RTLD_LOCAL);
    if (c->dl == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd frm: cannot dlopen HSM library \"%s\": %s",
            libpath, dlerror());
        free(c);
        return NULL;
    }
    (void) dlerror();
    c->fn_exists  = (brix_frm_hsm_exists_fn)  dlsym(c->dl, BRIX_FRM_HSM_SYM_EXISTS);
    c->fn_recall  = (brix_frm_hsm_recall_fn)  dlsym(c->dl, BRIX_FRM_HSM_SYM_RECALL);
    c->fn_migrate = (brix_frm_hsm_migrate_fn) dlsym(c->dl, BRIX_FRM_HSM_SYM_MIGRATE);
    c->fn_purge   = (brix_frm_hsm_purge_fn)   dlsym(c->dl, BRIX_FRM_HSM_SYM_PURGE);

    if (c->fn_exists == NULL || c->fn_recall == NULL || c->fn_migrate == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd frm: HSM library \"%s\" is missing a required symbol "
            "(need %s, %s, %s)", libpath, BRIX_FRM_HSM_SYM_EXISTS,
            BRIX_FRM_HSM_SYM_RECALL, BRIX_FRM_HSM_SYM_MIGRATE);
        (void) dlclose(c->dl);
        free(c);
        return NULL;
    }
    return c;
}
