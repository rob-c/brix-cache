/* sd_frm_adapter.c — MSS adapter dialect selection for the sd_frm backend.
 *
 * WHAT: Maps an operator `adapter` string (exec / hpss / cta / lib / stub) onto
 *       a concrete MSS transport and binds it into the sd_frm state: exec-family
 *       dialects resolve a stage command, lib-family dialects resolve a shared
 *       object to dlopen, and the stub is the always-available fallback.
 *
 * WHY:  Split out of sd_frm.c, which crossed the 600-line cap
 *       (coding-standards §1). Adapter selection is construction-time policy;
 *       the parent TU keeps the runtime driver vtable.
 *
 * HOW:  Family predicates first (pure string classification), then one
 *       frm_select_* per family returning 0 = bound, 1 = not mine, -1 = hard
 *       failure. brix_sd_frm_create() in sd_frm.c drives them in order. */

#include "sd_frm.h"
#include "sd_frm_mss.h"     /* MSS adapters (stub/exec) split out */
#include "sd_frm_internal.h" /* sd_frm_state + the frm_select_* contract */
#include "fs/xfer/xfer.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


/* ---- exec-family MSS dialects (exec / hpss / cta) ----
 *
 * WHAT: Is `adapter` one of the exec-family dialects? All three drive a real MSS
 * through an operator stage command (the classic FRM model); "hpss" and "cta" are
 * named HSM dialects over the same transport, differing only in which stage
 * command they resolve. A NULL adapter is not exec-family.
 */
static int
frm_adapter_is_exec_family(const char *adapter)
{
    return adapter != NULL
        && (ngx_strcmp(adapter, "exec") == 0
         || ngx_strcmp(adapter, "hpss") == 0
         || ngx_strcmp(adapter, "cta") == 0);
}

/* Resolve a per-dialect env override with a generic fallback.
 *
 * WHY: a node can front an HPSS silo and a CTA silo at once, so each named
 * dialect gets its own env var; an unmatched adapter, or an unset/empty
 * override, falls back to the generic var. Returns the value, or NULL when
 * nothing is set/non-empty. */
static const char *
frm_dialect_env(const char *adapter, const char *hpss_name,
    const char *hpss_var, const char *cta_name, const char *cta_var,
    const char *generic_var)
{
    const char *v = NULL;

    if (ngx_strcmp(adapter, hpss_name) == 0) {
        v = getenv(hpss_var);
    } else if (ngx_strcmp(adapter, cta_name) == 0) {
        v = getenv(cta_var);
    }
    if (v == NULL || v[0] == '\0') {
        v = getenv(generic_var);
    }
    return (v != NULL && v[0] != '\0') ? v : NULL;
}

/* Resolve the stage command for an exec-family `adapter` (an `hsi`/`pftp`
 * HPSS stager, an `eos`/`cta-admin` CTA stager, or the generic
 * $BRIX_FRM_STAGECMD). */
static const char *
frm_exec_stagecmd(const char *adapter)
{
    return frm_dialect_env(adapter, "hpss", "BRIX_FRM_HPSS_STAGECMD",
                           "cta", "BRIX_FRM_CTA_STAGECMD",
                           "BRIX_FRM_STAGECMD");
}

/* ---- library-native MSS dialects (lib / libhpss / libcta) ----
 *
 * WHAT: Is `adapter` one of the library-native dialects? All three drive a real
 * HSM through a dlopen'd shared object (sd_frm_lib.c) instead of forking a stage
 * command; "libhpss"/"libcta" are named silo dialects over the same transport,
 * differing only in which library path they resolve. A NULL adapter is not
 * lib-family.
 */
static int
frm_adapter_is_lib_family(const char *adapter)
{
    return adapter != NULL
        && (ngx_strcmp(adapter, "lib") == 0
         || ngx_strcmp(adapter, "libhpss") == 0
         || ngx_strcmp(adapter, "libcta") == 0);
}

/* Resolve the HSM shared-object path for a library-native `adapter` (a
 * per-silo override or the generic $BRIX_FRM_LIB). */
static const char *
frm_lib_path(const char *adapter)
{
    return frm_dialect_env(adapter, "libhpss", "BRIX_FRM_HPSS_LIB",
                           "libcta", "BRIX_FRM_CTA_LIB",
                           "BRIX_FRM_LIB");
}

/* ---- Select a library-native MSS adapter (lib / libhpss / libcta) ----
 *
 * WHAT: If `adapter` names a library-native dialect AND its .so path is
 * resolvable AND the library loads with the required ABI, points st->mss/mss_ctx
 * at the dlopen'd adapter. ALWAYS returns 0 (the caller may proceed): a
 * non-lib-family adapter, an unset path, an absent library, or a missing symbol
 * all leave st->mss NULL so the exec/stub fallback runs. The vendor library is a
 * runtime plug-in; its absence is a graceful degrade, never a hard failure.
 *
 * WHY: isolates the library-native decision so brix_sd_frm_create stays a flat
 * orchestration below the complexity cap, and mirrors frm_select_exec_adapter.
 */
int
frm_select_lib_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log)
{
    const char *path;

    if (!frm_adapter_is_lib_family(adapter)) {
        return 0;
    }
    path = frm_lib_path(adapter);
    if (path == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd frm: the \"%s\" MSS adapter needs an HSM library path "
            "($BRIX_FRM_LIB, or the per-dialect override); "
            "falling back to the built-in stub", adapter);
        return 0;
    }
    st->mss_ctx = brix_mss_lib_create(location, path, log);
    if (st->mss_ctx == NULL) {
        /* brix_mss_lib_create already WARN-logged the dlopen/symbol failure. */
        return 0;                            /* graceful fallback to exec/stub */
    }
    st->mss = &brix_mss_lib_adapter;
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
        "xrootd frm: \"%s\" library-native MSS adapter (lib=%s, online buffer=%s)",
        adapter, path, location);
    return 0;
}

/* ---- Select an exec-family MSS adapter (exec / hpss / cta) when requested ----
 *
 * WHAT: If `adapter` names an exec-family HSM dialect AND its stage command is
 * resolvable (`frm_exec_stagecmd`), builds the exec MSS context and points
 * `st->mss`/`st->mss_ctx` at it. Returns 0 whenever the caller may proceed
 * (adapter not exec-family, or no stage command - in both cases `st->mss` is left
 * NULL so the stub fallback runs); returns -1 with errno set to ENOMEM only when
 * the exec context allocation itself fails.
 *
 * WHY: Isolates the exec-adapter decision (the classic FRM model over an external
 * stage command) so brix_sd_frm_create stays a flat orchestration below the
 * complexity cap. HPSS/CTA are real named dialects here, not stub fallthroughs.
 *
 * HOW:
 *   1. If `adapter` is not exec-family, return 0 (fall through to the stub).
 *   2. Resolve the stage command; if none, WARN and return 0 (stub fallback).
 *   3. Create the exec MSS context; on failure set errno=ENOMEM and return -1.
 *   4. On success, publish the exec adapter, NOTICE-log the dialect, return 0.
 */
int
frm_select_exec_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log)
{
    const char *cmd;

    if (!frm_adapter_is_exec_family(adapter)) {
        return 0;
    }
    cmd = frm_exec_stagecmd(adapter);
    if (cmd == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd frm: the \"%s\" MSS adapter needs a stage command "
            "($BRIX_FRM_STAGECMD, or the per-dialect override); "
            "falling back to the built-in stub", adapter);
        return 0;
    }
    st->mss_ctx = brix_mss_exec_create(location, cmd, log);
    if (st->mss_ctx == NULL) {
        errno = ENOMEM;
        return -1;
    }
    st->mss = &brix_mss_exec_adapter;
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
        "xrootd frm: \"%s\" MSS adapter (stagecmd=%s, online buffer=%s)",
        adapter, cmd, location);
    return 0;
}

/* ---- Select the built-in local-dir stub MSS adapter (default / fallback) ----
 *
 * WHAT: Builds the stub MSS context that simulates tape with local directories and
 * points `st->mss`/`st->mss_ctx` at it. Returns 0 on success, or -1 with errno set
 * to ENOMEM when the stub context allocation fails. An `adapter` name that is
 * neither empty, "stub", nor "exec" is WARN-logged as not-yet-implemented before
 * the stub is used, matching the original in-place behaviour.
 *
 * WHY: The stub is the default and the fallback for every adapter that is not a
 * working "exec"; factoring it out keeps the create orchestrator flat and under
 * the complexity cap while preserving the exact warning and errno semantics.
 *
 * HOW:
 *   1. If `adapter` is a non-empty name that is neither "stub" nor an
 *      exec-family dialect (exec/hpss/cta), WARN that it is unrecognized.
 *   2. Create the stub MSS context; on failure set errno=ENOMEM and return -1.
 *   3. Publish the stub adapter and return 0.
 */
int
frm_select_stub_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log)
{
    if (adapter != NULL && adapter[0] != '\0'
        && ngx_strcmp(adapter, "stub") != 0
        && !frm_adapter_is_exec_family(adapter)
        && !frm_adapter_is_lib_family(adapter))
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd frm: MSS adapter \"%s\" is not recognized (known: stub, "
            "exec, hpss, cta, lib, libhpss, libcta); using the built-in stub",
            adapter);
    }
    st->mss_ctx = brix_mss_stub_create(location, log);
    if (st->mss_ctx == NULL) {
        errno = ENOMEM;
        return -1;
    }
    st->mss = &brix_mss_stub_adapter;
    return 0;
}
