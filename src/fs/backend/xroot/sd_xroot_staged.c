/*
 * sd_xroot_staged.c — staged atomic-publish (Mode A passthrough) for the
 * root:// origin driver.
 *
 * WHAT: The staged-write vtable slots — staged_open/staged_open_cred (connect +
 *       bootstrap + kXR_open(write) a fresh writable origin handle),
 *       staged_write (kXR_write at offset), staged_commit (kXR_sync + close,
 *       consuming the handle), and staged_abort (close, leaving whatever bytes
 *       already streamed).
 *
 * WHY:  Split out of sd_xroot.c (phase-79 file-size split): the staged handle is
 *       a distinct object (its own state struct + connection) from the read/
 *       write object (sd_xroot_io.c), the shared origin machinery + driver
 *       vtable (sd_xroot.c), and the namespace ops (sd_xroot_ns.c).
 *
 * HOW:  The staged handle is a live origin write handle. With NO local staging
 *       store the write streams straight to the FINAL remote path (transparent
 *       write-through, no local copy), so it is NOT atomic — a failed upload can
 *       leave a partial object on the origin. Configure a local staging directory
 *       (Mode B) for atomic / durable publish (a later phase). The opaque
 *       brix_sd_staged_t (sd.h) carries our state in ->state.
 */

#include "sd_xroot_internal.h"    /* inst_state + errno + copy_cred helper */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    brix_cache_origin_conn_t  oc;
    u_char                      fhandle[XRD_FHANDLE_LEN];
    brix_cache_fill_t        *t;
    int                         file_open;
} sd_xroot_staged_state;

/* Free a staged handle + its origin connection (closing an open file handle). */
static void
sd_xroot_staged_teardown(brix_sd_staged_t *handle)
{
    sd_xroot_staged_state *ss;

    if (handle == NULL) {
        return;
    }
    ss = handle->state;
    if (ss != NULL) {
        if (ss->file_open) {
            brix_cache_origin_close_file(&ss->oc, ss->fhandle);
        }
        brix_cache_origin_close(&ss->oc);
        free(ss->t);
        free(ss);
    }
    free(handle);
}

/* sd_xroot_staged_connect_open — connect + bootstrap + write-open a staged handle.
 *
 * WHAT: Run connect → bootstrap → kXR_open(write) on the staged handle's origin
 *       session for `final_path`. Returns 0 on success (ss->file_open set), or
 *       -1 with *err_out set on any step failure (the origin connection is
 *       closed on failure; the caller frees the shells).
 * WHY:  Isolating the three-step origin bring-up keeps sd_xroot_staged_open_common
 *       a flat allocate-then-open orchestrator and shares the failure logging in
 *       one place.
 * HOW:  1) connect, 2) bootstrap (using whatever credential the fill task already
 *       carries), 3) open_write with the create mode; on any failure log the
 *       actual origin reason, map errno, and close the connection. */
static int
sd_xroot_staged_connect_open(sd_xroot_staged_state *ss, const char *final_path,
    mode_t mode, int *err_out)
{
    brix_cache_fill_t *t = ss->t;

    if (brix_cache_origin_connect(t, &ss->oc) != 0
        || brix_cache_origin_bootstrap(t, &ss->oc) != 0
        || brix_cache_origin_open_write(t, &ss->oc, final_path,
               (uint16_t) ((mode != 0) ? (mode & 0777) : 0644), ss->fhandle) != 0)
    {
        /* Surface the ACTUAL origin failure reason (auth/TLS/protocol) — the
         * caller only sees the mapped errno, which hides why the origin session
         * failed (e.g. "requires TLS", "no credential set", gsi handshake). */
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "brix sd_xroot: origin staged-open \"%s\" failed: %s (kXR %d)",
            final_path,
            (t->err_msg[0] != '\0') ? t->err_msg : "(no detail)",
            t->xrd_error);
        if (err_out) { *err_out = sd_xroot_errno(t); }
        brix_cache_origin_close(&ss->oc);
        return -1;
    }
    ss->file_open = 1;
    return 0;
}

/* sd_xroot_staged_open_common — shared body for plain and cred-scoped staged opens.
 *
 * WHAT: Connect, bootstrap (with optional per-user credential), kXR_open write,
 *       and wire up the staged handle.
 * WHY:  Plain and cred paths share identical connect/bootstrap/open logic; the
 *       only difference is whether the fill task carries a per-user proxy.
 * HOW:  1) allocate handle + state + fill task (zeroed cred fields ⇒ cred=NULL
 *       behaves like Phase-0). 2) copy the credential via the shared helper. 3)
 *       delegate connect/bootstrap/open-write to sd_xroot_staged_connect_open;
 *       free all three shells on failure. */
static brix_sd_staged_t *
sd_xroot_staged_open_common(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_xroot_inst_state   *is = inst->state;
    brix_sd_staged_t    *handle = calloc(1, sizeof(*handle));
    sd_xroot_staged_state *ss = calloc(1, sizeof(*ss));
    brix_cache_fill_t   *t = calloc(1, sizeof(*t));

    if (handle == NULL || ss == NULL || t == NULL) {
        free(handle);
        free(ss);
        free(t);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    ss->t     = t;
    ss->oc.fd = -1;
    t->conf   = is->conf;
    ngx_cpystrn((u_char *) t->clean_path, (u_char *) final_path,
                sizeof(t->clean_path));

    sd_xroot_copy_cred_into_task(t, cred);

    if (sd_xroot_staged_connect_open(ss, final_path, mode, err_out) != 0) {
        free(t);
        free(ss);
        free(handle);
        return NULL;
    }
    handle->inst  = inst;
    handle->state = ss;
    return handle;
}

/* sd_xroot_staged_open — vtable staged_open slot: service credential / anonymous.
 *
 * WHAT: Plain staged open for callers that do not carry a per-user credential.
 * WHY:  Preserves the existing public vtable signature; cred=NULL means the
 *       bootstrap uses the static service credential (or anonymous).
 * HOW:  Delegates to sd_xroot_staged_open_common with cred=NULL. */
brix_sd_staged_t *
sd_xroot_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    return sd_xroot_staged_open_common(inst, final_path, mode, NULL, err_out);
}

/* sd_xroot_staged_open_cred — vtable staged_open_cred slot: per-user proxy.
 *
 * WHAT: Credential-scoped staged open that authenticates as the requesting user.
 * WHY:  Write operations that carry user identity must present the user's proxy
 *       to the origin, not the service credential, even during staged uploads.
 * HOW:  Delegates to sd_xroot_staged_open_common with the supplied cred. */
brix_sd_staged_t *
sd_xroot_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    return sd_xroot_staged_open_common(inst, final_path, mode, cred, err_out);
}

ssize_t
sd_xroot_staged_write(brix_sd_staged_t *handle, const void *buf, size_t len,
    off_t off)
{
    sd_xroot_staged_state *ss = handle->state;

    if (len == 0) {
        return 0;
    }
    if (brix_cache_origin_write_chunk(ss->t, &ss->oc, ss->fhandle,
            (uint64_t) off, (const u_char *) buf, len) != 0)
    {
        errno = EIO;
        return -1;
    }
    return (ssize_t) len;
}

/* Publish: sync + close the origin file. On success the handle is consumed (freed);
 * on failure it stays valid for the caller to staged_abort. `noreplace` cannot be
 * enforced on a Mode-A direct write (open_write already created the destination) —
 * use a staging dir (Mode B) for exclusive/atomic publish. */
ngx_int_t
sd_xroot_staged_commit(brix_sd_staged_t *handle, int noreplace)
{
    sd_xroot_staged_state *ss = handle->state;

    (void) noreplace;

    if (brix_cache_origin_sync(ss->t, &ss->oc, ss->fhandle) != 0) {
        return NGX_ERROR;                    /* leave valid; caller aborts */
    }
    sd_xroot_staged_teardown(handle);        /* close_file + free (consumed) */
    return NGX_OK;
}

void
sd_xroot_staged_abort(brix_sd_staged_t *handle)
{
    /* Mode A: the partial bytes already streamed to the final remote path; closing
     * leaves them (non-atomic by design). Mode B staging gives a clean abort. */
    sd_xroot_staged_teardown(handle);
}
