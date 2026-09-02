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
    frm_mss_head_t           head;             /* base + invoke — shared-op seam */
    void                    *dl;               /* dlopen handle            */
    brix_frm_hsm_exists_fn   fn_exists;
    brix_frm_hsm_recall_fn   fn_recall;
    brix_frm_hsm_migrate_fn  fn_migrate;
    brix_frm_hsm_purge_fn    fn_purge;         /* optional (may be NULL)   */
    ngx_log_t               *log;
} lib_ctx_t;

/* The lib adapter's frm_mss_invoke_fn: each MSS verb is a direct dlsym'd call.
 * `purge` is optional in the ABI — absent means the MSS-side drop is a no-op
 * (the shared op already unlinked the online buffer). */
static int
lib_invoke(void *mss, const char *verb, const char *key, const char *online)
{
    lib_ctx_t *c = mss;

    if (strcmp(verb, "exists") == 0) {
        return c->fn_exists(key);
    }
    if (strcmp(verb, "recall") == 0) {
        return c->fn_recall(key, online);
    }
    if (strcmp(verb, "migrate") == 0) {
        return c->fn_migrate(key, online);
    }
    if (strcmp(verb, "purge") == 0) {
        return (c->fn_purge != NULL) ? c->fn_purge(key) : 0;
    }
    return -1;
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
    .residency     = frm_mss_residency,
    .recall_begin  = frm_mss_recall_begin,
    .recall_poll   = frm_mss_recall_poll,
    .migrate       = frm_mss_migrate,
    .purge         = frm_mss_purge,
    .exchange      = frm_mss_exchange,       /* phase-107 C6 */
    .open_online   = frm_mss_open_online,
    .create_online = frm_mss_create_online,
    .sync_publish  = frm_mss_sync_publish,   /* phase-107 C3 */
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
    ngx_cpystrn((u_char *) c->head.base, (u_char *) location,
                sizeof(c->head.base));
    c->head.invoke = lib_invoke;
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
