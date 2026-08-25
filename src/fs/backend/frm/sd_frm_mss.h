#ifndef BRIX_FS_BACKEND_FRM_SD_FRM_MSS_H
#define BRIX_FS_BACKEND_FRM_SD_FRM_MSS_H

/*
 * sd_frm_mss.h — the FRM driver's mass-storage-system (MSS) adapters.
 *
 * Two pluggable back ends behind the brix_mss_adapter_t vtable: the built-in
 * "stub" local-directory tape simulator (test/dev + the default) and the "exec"
 * adapter that drives a real HSM via an external stage command.  Split out of
 * sd_frm.c so the adapter implementations live apart from the driver that
 * dispatches to them.  Each adapter's context is opaque — the driver holds it as
 * a void * and only ever touches it through the vtable; brix_mss_*_create build
 * it, brix_mss_adapter_t::destroy frees it.
 */

#include "sd_frm.h"            /* brix_mss_adapter_t */

#include <limits.h>            /* PATH_MAX (frm_mss_head_t.base) */

extern const brix_mss_adapter_t brix_mss_stub_adapter;
extern const brix_mss_adapter_t brix_mss_exec_adapter;
extern const brix_mss_adapter_t brix_mss_lib_adapter;

/* Run one MSS verb ("exists" / "recall" / "migrate" / "purge") for `key`;
 * `online` is the online-buffer path the recall/migrate verbs write (unused by
 * exists/purge). Returns the MSS's exit/return code (0 = ok). */
typedef int (*frm_mss_invoke_fn)(void *mss, const char *verb, const char *key,
    const char *online);

/* Common HEAD every real-HSM adapter context starts with. The exec and lib
 * adapters share one online-buffer discipline (resolve <base>/.online/<key>,
 * stat/access/open/unlink it locally, call the MSS only through `invoke`), so
 * the whole vtable except destroy is implemented ONCE against this head
 * (frm_mss_* below, defined in sd_frm_stub.c) and the adapters differ only in
 * their invoker: posix_spawn of $BRIX_FRM_STAGECMD vs a dlsym'd call. */
typedef struct {
    char               base[PATH_MAX];   /* local online-buffer root */
    frm_mss_invoke_fn  invoke;
} frm_mss_head_t;

/* The shared online-buffer vtable ops (brix_mss_adapter_t signatures; `mss`
 * must begin with frm_mss_head_t). */
int frm_mss_residency(void *mss, const char *key, off_t *size_out,
        time_t *mtime_out);
int frm_mss_recall_begin(void *mss, const char *key);
int frm_mss_recall_poll(void *mss, const char *key);
int frm_mss_migrate(void *mss, const char *key);
int frm_mss_purge(void *mss, const char *key);
int frm_mss_open_online(void *mss, const char *key);
int frm_mss_create_online(void *mss, const char *key, mode_t mode);

/* Resolve <base>/.online/<key> (key's leading '/' stripped) into out[cap]. */
int frm_online_path(const char *base, const char *key, char *out, size_t cap);

/* Build an adapter context (the sd_frm_state mss_ctx).  Returns the opaque
 * context, or NULL with errno = ENOMEM.  `location` is the online-buffer / stub
 * tape root; `stagecmd` is the exec adapter's stage command. */
void *brix_mss_stub_create(const char *location, ngx_log_t *log);
void *brix_mss_exec_create(const char *location, const char *stagecmd,
          ngx_log_t *log);

/* Build the library-native (dlopen) adapter context: opens `libpath` and binds
 * the HSM ABI (sd_frm_lib_abi.h).  Returns NULL when the library is absent or
 * missing a required symbol (the caller then falls back to exec/stub) — unlike
 * the create() calls above, a NULL here is a graceful fallback, not ENOMEM. */
void *brix_mss_lib_create(const char *location, const char *libpath,
          ngx_log_t *log);

/* Filesystem helpers shared by both adapters (defined in sd_frm_stub.c). */
void frm_mkparents(const char *path);
int  stub_copyfile(const char *src, const char *dst, mode_t mode);

#endif /* BRIX_FS_BACKEND_FRM_SD_FRM_MSS_H */
