/*
 * sd_xroot.c — read-only remote root:// origin storage driver. See the header.
 *
 * Wraps the in-process XRootD origin wire client (cache/origin_*.c) behind the SD
 * vtable. The per-open object holds a live origin connection + open file handle;
 * pread issues a kXR_read range into a memory sink. Anonymous login only (the
 * client's native mode); authenticated origins use the cache's native-client
 * delegation. Only the read slots are populated → CAP_RANGE_READ.
 */

#include "sd_xroot.h"
#include "sd_xroot_internal.h"    /* inst_state + errno + ns ops (split out) */
#include "fs/cache/cache_internal.h"   /* origin wire client + fill-task ctx */
#include "auth/crypto/pki_build.h"       /* brix_build_ca_store (GSI MITM verify) */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* Per-open state: a live origin connection + open file handle + the synthetic
 * fill-task the origin functions need (conf + clean_path + error scratch). */
typedef struct {
    brix_cache_origin_conn_t  oc;
    u_char                      fhandle[XRD_FHANDLE_LEN];
    brix_cache_fill_t        *t;
    int                         file_open;   /* 1 once kXR_open succeeded */
    int                         is_write;    /* 1 = opened for write (open_write) */
} sd_xroot_obj_state;

/* Map a fill-task XRootD error (kXR_*) to an errno-style fact for *err_out. */
int
sd_xroot_errno(const brix_cache_fill_t *t)
{
    switch (t->xrd_error) {
    case kXR_NotFound:      return ENOENT;
    case kXR_NotAuthorized: return EACCES;
    case kXR_isDirectory:   return EISDIR;
    default:                return EIO;
    }
}

/* sd_xroot_copy_cred_into_task — copy a per-user credential into the fill task.
 *
 * WHAT: When `cred` is non-NULL, copy its x509 proxy path, bearer token, and
 *       principal into the fill task's cred_* fields (each only when non-empty).
 *       No-op when cred is NULL.
 * WHY:  The origin bootstrap is the sole auth decision point; a task-level copy
 *       lets each open carry independent identity without touching the shared
 *       conf. Both the plain-open and staged-open paths need the identical copy,
 *       so it lives in one place to prevent divergence.
 * HOW:  1) return early on NULL cred (the fill task was calloc-zeroed, so the
 *       bootstrap sees the service credential / anonymous). 2) Exactly one of
 *       {x509_proxy, bearer} is non-NULL for a credential-scoped open (mutually
 *       exclusive); copy whichever is present. 3) Copy principal when present. */
static void
sd_xroot_copy_cred_into_task(brix_cache_fill_t *t, const brix_sd_cred_t *cred)
{
    if (cred == NULL) {
        return;
    }
    if (cred->x509_proxy != NULL && cred->x509_proxy[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_x509_proxy, (u_char *) cred->x509_proxy,
                    sizeof(t->cred_x509_proxy));
    }
    if (cred->bearer != NULL && cred->bearer[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_bearer, (u_char *) cred->bearer,
                    sizeof(t->cred_bearer));
    }
    if (cred->principal != NULL) {
        ngx_cpystrn((u_char *) t->cred_principal, (u_char *) cred->principal,
                    sizeof(t->cred_principal));
    }
}

static void
sd_xroot_obj_teardown(sd_xroot_obj_state *st)
{
    if (st == NULL) {
        return;
    }
    if (st->file_open) {
        brix_cache_origin_close_file(&st->oc, st->fhandle);
    }
    brix_cache_origin_close(&st->oc);
    free(st->t);
    free(st);
}

/* Inputs to a single origin file open. Bundling the seven loose arguments into a
 * file-local struct keeps sd_xroot_origin_open() and its callers (open_common,
 * stat, stat_cred) below the parameter-count gate without touching any shared
 * header. `size_out`/`err_out` may be NULL; the remaining fields are required. */
typedef struct {
    ngx_stream_brix_srv_conf_t  *conf;       /* origin params (real or synthetic) */
    const brix_sd_cred_t          *cred;       /* per-user credential, or NULL      */
    const char                    *path;       /* remote path to open               */
    int                            want_write; /* 1 = writable open, 0 = read open  */
    mode_t                         mode;        /* create mode (write opens only)    */
    off_t                         *size_out;   /* out: file size (may be NULL)      */
    int                           *err_out;    /* out: errno on failure (may be NULL) */
} sd_xroot_origin_open_req_t;

/* sd_xroot_origin_do_open — issue the kXR_open for a bootstrapped connection.
 *
 * WHAT: Perform the write- or read-open on an already connected+bootstrapped
 *       origin session, recording the fhandle and file size. Returns 0 on
 *       success (st->file_open set), or -1 with *req->err_out set on failure.
 * WHY:  Splitting the open branch off the connect/bootstrap sequence keeps
 *       sd_xroot_origin_open a flat orchestrator and isolates the write-vs-read
 *       distinction (mode bits, size source) in one place.
 * HOW:  1) want_write → kXR_open(update) with mode bits, size 0 (truncated). 2)
 *       else → kXR_open(read|retstat), size from the returned stat. 3) on either
 *       failure map the fill-task kXR error to errno. */
static int
sd_xroot_origin_do_open(sd_xroot_obj_state *st,
    const sd_xroot_origin_open_req_t *req)
{
    brix_cache_fill_t *t = st->t;

    if (req->want_write) {
        uint16_t mode_bits =
            (uint16_t) ((req->mode != 0) ? (req->mode & 0777) : 0644);

        if (brix_cache_origin_open_write(t, &st->oc, req->path, mode_bits,
                                           st->fhandle) != 0)
        {
            if (req->err_out) { *req->err_out = sd_xroot_errno(t); }
            return -1;
        }
        st->is_write = 1;
        if (req->size_out) { *req->size_out = 0; } /* open_write truncates to empty */
    } else {
        if (brix_cache_origin_open(t, &st->oc, st->fhandle) != 0) {
            if (req->err_out) { *req->err_out = sd_xroot_errno(t); }
            return -1;
        }
        if (req->size_out) { *req->size_out = t->file_size; }
    }
    st->file_open = 1;
    return 0;
}

/* Open the origin file: connect → bootstrap (handshake + anon or per-user login)
 * → kXR_open. `req->want_write` selects kXR_open(update+delete+mkpath) (a fresh
 * writable handle, size 0) over the read open (read|retstat for the size).
 * `req->cred` carries a per-user x509 proxy path; when non-NULL and non-empty the
 * bootstrap uses it instead of the conf's static service credential. Namespace
 * callers (stat, sd_xroot_session) pass cred=NULL — they stay on the service
 * credential in Phase 1. Returns the populated object state, or NULL with
 * *req->err_out set.
 *
 * WHAT: Allocate and wire up the per-open fill task, copy the per-user proxy into
 *       it, then run connect → bootstrap → open as a flat sequence.
 * WHY:  The bootstrap is the sole auth decision point for every origin session; a
 *       task-level field lets each open carry independent identity without touching
 *       the shared conf or the connection pool.
 * HOW:  1) calloc the state + fill task (zeroed cred fields ⇒ cred=NULL behaves
 *       like Phase-0). 2) copy the credential via the shared helper. 3) connect +
 *       bootstrap; on failure log the actual origin reason and map errno. 4)
 *       delegate the kXR_open branch to sd_xroot_origin_do_open. */
static sd_xroot_obj_state *
sd_xroot_origin_open(const sd_xroot_origin_open_req_t *req)
{
    sd_xroot_obj_state *st = calloc(1, sizeof(*st));
    brix_cache_fill_t *t = calloc(1, sizeof(*t));

    if (st == NULL || t == NULL) {
        free(st);
        free(t);
        if (req->err_out) { *req->err_out = ENOMEM; }
        return NULL;
    }
    st->t      = t;
    st->oc.fd  = -1;
    t->conf    = req->conf;
    ngx_cpystrn((u_char *) t->clean_path, (u_char *) req->path,
                sizeof(t->clean_path));

    sd_xroot_copy_cred_into_task(t, req->cred);

    if (brix_cache_origin_connect(t, &st->oc) != 0
        || brix_cache_origin_bootstrap(t, &st->oc) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "brix sd_xroot: origin open \"%s\" failed: %s (kXR %d)",
            req->path, (t->err_msg[0] != '\0') ? t->err_msg : "(no detail)",
            t->xrd_error);
        if (req->err_out) { *req->err_out = sd_xroot_errno(t); }
        sd_xroot_obj_teardown(st);
        return NULL;
    }

    if (sd_xroot_origin_do_open(st, req) != 0) {
        sd_xroot_obj_teardown(st);
        return NULL;
    }
    return st;
}

/* sd_xroot_open_common — shared body for plain and cred-scoped opens.
 *
 * WHAT: Translate SD flags to want_write, call sd_xroot_origin_open with the
 *       supplied credential (NULL for the plain slot), build the SD object.
 * WHY:  Plain and cred paths differ only in the cred argument; a single body
 *       prevents divergence in error handling and object initialisation.
 *       A cred whose selected kind (bearer/S3) this driver cannot present —
 *       carrying neither an x509 proxy nor a bearer token — must not silently
 *       open on the service credential when the operator asked fallback_deny:
 *       that is exactly the leak the deny flag exists to prevent.
 * HOW:  want_write derived from sd_flags; a fallback_deny cred with no usable
 *       kind is refused (EACCES) before any origin session is opened;
 *       otherwise sd_xroot_origin_open owns the credential copy into the fill
 *       task; obj is heap-allocated (heap_shell=1). */
static brix_sd_obj_t *
sd_xroot_open_common(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_xroot_inst_state *is = inst->state;
    sd_xroot_obj_state  *st;
    brix_sd_obj_t     *obj;
    off_t                size = 0;
    int                  want_write;

    /* fallback_deny: cred kind unusable by this driver — refuse, don't fall
     * back to service cred */
    if (cred != NULL && cred->fallback_deny
        && (cred->x509_proxy == NULL || cred->x509_proxy[0] == '\0')
        && (cred->bearer == NULL || cred->bearer[0] == '\0'))
    {
        if (err_out) { *err_out = EACCES; }
        errno = EACCES;
        return NULL;
    }

    want_write = (sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE
                              | BRIX_SD_O_TRUNC | BRIX_SD_O_APPEND)) != 0;

    sd_xroot_origin_open_req_t req = {
        .conf = is->conf, .cred = cred, .path = path,
        .want_write = want_write, .mode = mode,
        .size_out = &size, .err_out = err_out,
    };
    st = sd_xroot_origin_open(&req);
    if (st == NULL) {
        return NULL;
    }

    obj = calloc(1, sizeof(*obj));
    if (obj == NULL) {
        sd_xroot_obj_teardown(st);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    obj->driver      = inst->driver;
    obj->inst        = inst;
    obj->fd          = NGX_INVALID_FILE;     /* no kernel fd — memory-served */
    obj->state       = st;
    obj->heap_shell  = 1;
    obj->snap.size   = size;
    obj->snap.mode   = S_IFREG | (want_write ? 0644 : 0444);
    obj->snap.is_reg = 1;
    return obj;
}

/* sd_xroot_open — vtable open slot: service credential / anonymous.
 *
 * WHAT: Plain open for callers that do not carry a per-user credential.
 * WHY:  Preserves the existing public vtable signature; passes cred=NULL so
 *       the bootstrap uses the static service credential (or anonymous).
 * HOW:  Delegates to sd_xroot_open_common with cred=NULL. */
static brix_sd_obj_t *
sd_xroot_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    return sd_xroot_open_common(inst, path, sd_flags, mode, NULL, err_out);
}

/* sd_xroot_open_cred — vtable open_cred slot: per-user x509 proxy credential.
 *
 * WHAT: Credential-scoped open that authenticates to the origin as the
 *       requesting user rather than the static service credential.
 * WHY:  Per-user backend auth requires the user's proxy to be presented at
 *       the origin bootstrap; the fill task copies it before connecting.
 * HOW:  Delegates to sd_xroot_open_common with the supplied cred; the common
 *       path copies x509_proxy + principal into the fill task before bootstrap. */
static brix_sd_obj_t *
sd_xroot_open_cred(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    return sd_xroot_open_common(inst, path, sd_flags, mode, cred, err_out);
}

static ngx_int_t
sd_xroot_close(brix_sd_obj_t *obj)
{
    if (obj != NULL && obj->state != NULL) {
        sd_xroot_obj_teardown(obj->state);
        obj->state = NULL;
    }
    return NGX_OK;
}

static ssize_t
sd_xroot_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_xroot_obj_state       *st = obj->state;
    brix_cache_sink_t         sink;
    brix_cache_read_range_t   rng;

    if (len == 0) {
        return 0;
    }
    ngx_memzero(&sink, sizeof(sink));
    sink.fd      = -1;
    sink.mem     = buf;
    sink.mem_cap = len;

    ngx_memzero(&rng, sizeof(rng));
    rng.read_off = (uint64_t) off;
    rng.want     = len;

    if (brix_cache_origin_read_chunk(st->t, &st->oc, st->fhandle, &sink,
                                       &rng) != 0)
    {
        errno = EIO;
        return -1;
    }
    return (ssize_t) rng.got;
}

/* Write `len` bytes at `off` to the origin file via kXR_write. The origin file
 * is offset-addressed, so sequential and random writes both map directly. Only
 * valid on a write handle. Returns bytes written, or -1 with errno. */
static ssize_t
sd_xroot_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    sd_xroot_obj_state *st = obj->state;

    if (st == NULL || !st->is_write) {
        errno = EBADF;
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (brix_cache_origin_write_chunk(st->t, &st->oc, st->fhandle,
            (uint64_t) off, (const u_char *) buf, len) != 0)
    {
        errno = EIO;
        return -1;
    }
    return (ssize_t) len;
}

/* kXR_truncate the origin file. Write handles only. */
static ngx_int_t
sd_xroot_ftruncate(brix_sd_obj_t *obj, off_t len)
{
    sd_xroot_obj_state *st = obj->state;

    if (st == NULL || !st->is_write) {
        errno = EBADF;
        return NGX_ERROR;
    }
    if (brix_cache_origin_truncate(st->t, &st->oc, st->fhandle,
                                     (uint64_t) len) != 0)
    {
        errno = EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* kXR_sync the origin file (flush to stable storage). A no-op on a read handle. */
static ngx_int_t
sd_xroot_fsync(brix_sd_obj_t *obj)
{
    sd_xroot_obj_state *st = obj->state;

    if (st == NULL || !st->is_write) {
        return NGX_OK;
    }
    if (brix_cache_origin_sync(st->t, &st->oc, st->fhandle) != 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
sd_xroot_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    *out = obj->snap;
    return NGX_OK;
}

static ngx_int_t
sd_xroot_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    sd_xroot_inst_state *is = inst->state;
    sd_xroot_obj_state  *st;
    off_t                size = 0;
    int                  e = 0;
    sd_xroot_origin_open_req_t req = {
        .conf = is->conf, .cred = NULL /* service cred */, .path = path,
        .want_write = 0 /* read */, .mode = 0,
        .size_out = &size, .err_out = &e,
    };

    st = sd_xroot_origin_open(&req);
    if (st == NULL) {
        errno = e;
        return NGX_ERROR;
    }
    sd_xroot_obj_teardown(st);

    ngx_memzero(out, sizeof(*out));
    out->size   = size;
    out->mode   = S_IFREG | 0444;
    out->is_reg = 1;
    return NGX_OK;
}

/* sd_xroot_stat_cred — vtable stat_cred slot: probe path metadata under the
 * per-user x509 proxy credential (Phase 2 Task 1).
 *
 * WHAT: Stat the remote path using the requesting user's proxy rather than the
 *       static service credential, so a deny-mode probe authenticates (or fails)
 *       as the user — never opening a session on the service credential.
 * WHY:  brix_vfs_probe dispatches through this slot when the credential gate
 *       fires, closing the gap where a denied stat still reached the origin.
 * HOW:  Delegates to sd_xroot_origin_open with the supplied cred (same as
 *       sd_xroot_open_cred) then tears down the file handle; only the size is
 *       captured from the open-time stat, identical to sd_xroot_stat. */
ngx_int_t
sd_xroot_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    sd_xroot_inst_state *is = inst->state;
    sd_xroot_obj_state  *st;
    off_t                size = 0;
    int                  e = 0;
    sd_xroot_origin_open_req_t req = {
        .conf = is->conf, .cred = cred, .path = path,
        .want_write = 0 /* read */, .mode = 0,
        .size_out = &size, .err_out = &e,
    };

    st = sd_xroot_origin_open(&req);
    if (st == NULL) {
        errno = e;
        return NGX_ERROR;
    }
    sd_xroot_obj_teardown(st);

    ngx_memzero(out, sizeof(*out));
    out->size   = size;
    out->mode   = S_IFREG | 0444;
    out->is_reg = 1;
    return NGX_OK;
}

/* ---- staged atomic publish (Mode A passthrough) --------------------------- *
 * The staged handle is a live origin write handle. With NO local staging store
 * the write streams straight to the FINAL remote path (transparent write-through,
 * no local copy), so it is NOT atomic — a failed upload can leave a partial object
 * on the origin. Configure a local staging directory (Mode B) for atomic / durable
 * publish (a later phase). The opaque brix_sd_staged_t (sd.h) carries our state
 * in ->state. */

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
static brix_sd_staged_t *
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
static brix_sd_staged_t *
sd_xroot_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    return sd_xroot_staged_open_common(inst, final_path, mode, cred, err_out);
}

static ssize_t
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
static ngx_int_t
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

static void
sd_xroot_staged_abort(brix_sd_staged_t *handle)
{
    /* Mode A: the partial bytes already streamed to the final remote path; closing
     * leaves them (non-atomic by design). Mode B staging gives a clean abort. */
    sd_xroot_staged_teardown(handle);
}

/* Vectored read: serve each iov segment from the origin (contiguous from `off`).
 * Reuses sd_xroot_pread per segment — short read on any segment ends the read. */
static ssize_t
sd_xroot_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    ssize_t total = 0;
    int     i;

    for (i = 0; i < iovcnt; i++) {
        ssize_t n = sd_xroot_pread(obj, iov[i].iov_base, iov[i].iov_len,
                                   off + total);
        if (n < 0) {
            return (total > 0) ? total : -1;
        }
        total += n;
        if ((size_t) n < iov[i].iov_len) {
            break;                               /* short read = EOF */
        }
    }
    return total;
}


/* Remote root:// driver (anonymous). Read slots + the write data path
 * (pwrite/ftruncate/fsync over kXR_write/_truncate/_sync) — the foundation for a
 * writable remote backend (Phase 1; staged-write and namespace slots are later
 * phases). No fd, so reads/writes are memory-served like every object backend. */
static const brix_sd_driver_t brix_sd_xroot_driver = {
    .name      = "xroot",
    .caps      = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_RANDOM_WRITE
                 | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_XATTR
                 | BRIX_SD_CAP_XATTR_WRITE
                 | BRIX_SD_CAP_HARD_RENAME | BRIX_SD_CAP_SERVER_COPY
                 | BRIX_SD_CAP_DIRS | BRIX_SD_CAP_DIRS_WRITE
                 | BRIX_SD_CAP_MEMFILE,
    .cred_accept = BRIX_SD_CRED_BEARER | BRIX_SD_CRED_PROXY_PEM,
    .open          = sd_xroot_open,
    .close         = sd_xroot_close,
    .pread         = sd_xroot_pread,
    .preadv        = sd_xroot_preadv,
    .pwrite        = sd_xroot_pwrite,
    .fstat         = sd_xroot_fstat,
    .ftruncate     = sd_xroot_ftruncate,
    .fsync         = sd_xroot_fsync,
    .stat          = sd_xroot_stat,
    .rename        = sd_xroot_rename,
    .unlink        = sd_xroot_unlink,
    .server_copy   = sd_xroot_server_copy,
    .getxattr      = sd_xroot_getxattr,
    .listxattr     = sd_xroot_listxattr,
    .setxattr      = sd_xroot_setxattr,
    .removexattr   = sd_xroot_removexattr,
    .opendir       = sd_xroot_opendir,
    .readdir       = sd_xroot_readdir,
    .closedir      = sd_xroot_closedir,
    .staged_open         = sd_xroot_staged_open,
    .staged_write        = sd_xroot_staged_write,
    .staged_commit       = sd_xroot_staged_commit,
    .staged_abort        = sd_xroot_staged_abort,
    .open_cred           = sd_xroot_open_cred,
    .staged_open_cred    = sd_xroot_staged_open_cred,
    /* Phase 2 Task 1: credential-scoped namespace vtable slots. */
    .stat_cred           = sd_xroot_stat_cred,
    .unlink_cred         = sd_xroot_unlink_cred,
    .rename_cred         = sd_xroot_rename_cred,
    .server_copy_cred    = sd_xroot_server_copy_cred,
    .getxattr_cred       = sd_xroot_getxattr_cred,
    .listxattr_cred      = sd_xroot_listxattr_cred,
    .setxattr_cred       = sd_xroot_setxattr_cred,
    .removexattr_cred    = sd_xroot_removexattr_cred,
    .opendir_cred        = sd_xroot_opendir_cred,
};

void
brix_sd_xroot_query_checksum(brix_sd_obj_t *obj, char *alg, size_t algsz,
    char *hex, size_t hexsz)
{
    sd_xroot_obj_state *st;

    if (algsz) { alg[0] = '\0'; }
    if (hexsz) { hex[0] = '\0'; }
    if (obj == NULL || obj->state == NULL) {
        return;
    }
    st = obj->state;

    brix_cache_cksum_out_t out = {
        .alg = alg, .alg_sz = algsz, .hex = hex, .hex_sz = hexsz,
    };
    (void) brix_cache_origin_query_checksum(st->t, &st->oc, &out);
}

brix_sd_instance_t *
brix_sd_xroot_create(void *conf, ngx_log_t *log)
{
    brix_sd_instance_t *inst;
    sd_xroot_inst_state  *is;

    if (conf == NULL) {
        errno = EINVAL;
        return NULL;
    }
    inst = calloc(1, sizeof(*inst));
    is   = calloc(1, sizeof(*is));
    if (inst == NULL || is == NULL) {
        free(inst);
        free(is);
        errno = ENOMEM;
        return NULL;
    }
    is->conf     = conf;
    is->synth    = NULL;                       /* borrowed real conf */
    inst->driver = &brix_sd_xroot_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = is;
    return inst;
}

/* sd_xroot_origin_apply_creds — copy the optional credential paths onto synth.
 *
 * WHAT: For each non-empty field of `cfg`, copy the path onto the instance state
 *       and point the matching synth->cache_origin_* ngx_str_t at those stable
 *       bytes. No-op fields (NULL/"") are left as the calloc-zeroed default.
 * WHY:  synth is a synthetic conf whose ngx_str_t members must reference storage
 *       that outlives the call; the instance-owned char[] buffers provide that
 *       lifetime. Grouping the four independent copies keeps the create function
 *       flat and below the parameter gate.
 * HOW:  copy bearer, x509_proxy, x509_key (separate key when cert+key were given
 *       rather than a combined PEM), and sss_keytab in turn, each guarded by a
 *       non-empty check. */
static void
sd_xroot_origin_apply_creds(sd_xroot_inst_state *is,
    ngx_stream_brix_srv_conf_t *synth, const brix_sd_xroot_origin_cfg_t *cfg)
{
    if (cfg->bearer != NULL && cfg->bearer[0] != '\0') {
        ngx_cpystrn((u_char *) is->bearer, (u_char *) cfg->bearer,
                    sizeof(is->bearer));
        synth->cache_origin_bearer.data = (u_char *) is->bearer;
        synth->cache_origin_bearer.len  = ngx_strlen(is->bearer);
    }
    if (cfg->x509_proxy != NULL && cfg->x509_proxy[0] != '\0') {
        ngx_cpystrn((u_char *) is->x509_proxy, (u_char *) cfg->x509_proxy,
                    sizeof(is->x509_proxy));
        synth->cache_origin_x509_proxy.data = (u_char *) is->x509_proxy;
        synth->cache_origin_x509_proxy.len  = ngx_strlen(is->x509_proxy);
    }
    if (cfg->x509_key != NULL && cfg->x509_key[0] != '\0') {
        ngx_cpystrn((u_char *) is->x509_key, (u_char *) cfg->x509_key,
                    sizeof(is->x509_key));
        synth->cache_origin_x509_key.data = (u_char *) is->x509_key;
        synth->cache_origin_x509_key.len  = ngx_strlen(is->x509_key);
    }
    if (cfg->sss_keytab != NULL && cfg->sss_keytab[0] != '\0') {
        ngx_cpystrn((u_char *) is->sss_keytab, (u_char *) cfg->sss_keytab,
                    sizeof(is->sss_keytab));
        synth->cache_origin_sss_keytab.data = (u_char *) is->sss_keytab;
        synth->cache_origin_sss_keytab.len  = ngx_strlen(is->sss_keytab);
    }
}

/* sd_xroot_origin_build_ca_store — build the GSI verify store for the origin.
 *
 * WHAT: When `ca_dir` is non-empty, record it on synth and build the per-worker
 *       X509 verify store (a hashed CA dir vs a bundle file) into synth->gsi_store;
 *       a build failure is logged and leaves gsi_store NULL. No-op on empty ca_dir.
 * WHY:  A NULL store makes the GSI handshake refuse the origin rather than trust
 *       an unverifiable one; isolating the stat-and-build keeps the create
 *       function flat.
 * HOW:  1) copy ca_dir onto the instance and point synth at it. 2) stat to decide
 *       hashed-dir vs bundle-file. 3) call brix_build_ca_store with proxy certs
 *       allowed, signing-policy OFF and best-effort CRL (pre-existing outbound
 *       cache→origin trust behaviour — unchanged). 4) log on failure. */
static void
sd_xroot_origin_build_ca_store(sd_xroot_inst_state *is,
    ngx_stream_brix_srv_conf_t *synth, const char *ca_dir, ngx_log_t *log)
{
    struct stat ca_st;
    int         is_dir;
    int         crl_count = 0;

    if (ca_dir == NULL || ca_dir[0] == '\0') {
        return;
    }
    ngx_cpystrn((u_char *) is->ca_dir, (u_char *) ca_dir, sizeof(is->ca_dir));
    synth->cache_origin_ca_dir.data = (u_char *) is->ca_dir;
    synth->cache_origin_ca_dir.len  = ngx_strlen(is->ca_dir);
    /* Also expose the origin CA as the generic trust anchor so the root:// TLS
     * upgrade (brix_cache_origin_tls_upgrade → origin_tls_load_verify) verifies
     * the origin's TLS cert against THIS store (CAfile or hashed CApath) instead
     * of falling back to the system CAs. Same backing buffer as ca_dir. */
    synth->trusted_ca.data = (u_char *) is->ca_dir;
    synth->trusted_ca.len  = ngx_strlen(is->ca_dir);

    is_dir = (stat(is->ca_dir, &ca_st) == 0 && S_ISDIR(ca_st.st_mode));
    synth->gsi_store = brix_build_ca_store(log,
        is_dir ? is->ca_dir : NULL, is_dir ? NULL : is->ca_dir, NULL,
        X509_V_FLAG_ALLOW_PROXY_CERTS, &crl_count,
        BRIX_SP_MODE_OFF, BRIX_CRL_MODE_TRY);
    if (synth->gsi_store == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix: gsi origin CA store build failed for \"%s\" — GSI to this "
            "origin will be refused", ca_dir);
    }
}

brix_sd_instance_t *
brix_sd_xroot_create_origin(const brix_sd_xroot_origin_cfg_t *cfg,
    ngx_log_t *log)
{
    brix_sd_instance_t         *inst;
    sd_xroot_inst_state          *is;
    ngx_stream_brix_srv_conf_t *synth;

    if (cfg == NULL || cfg->host == NULL || cfg->host[0] == '\0'
        || cfg->port <= 0 || cfg->port > 65535)
    {
        errno = EINVAL;
        return NULL;
    }
    inst  = calloc(1, sizeof(*inst));
    is    = calloc(1, sizeof(*is));
    synth = calloc(1, sizeof(*synth));         /* minimal: just the origin params */
    if (inst == NULL || is == NULL || synth == NULL) {
        free(inst);
        free(is);
        free(synth);
        errno = ENOMEM;
        return NULL;
    }
    ngx_cpystrn((u_char *) is->host, (u_char *) cfg->host, sizeof(is->host));
    synth->cache_origin_host.data = (u_char *) is->host;
    synth->cache_origin_host.len  = ngx_strlen(is->host);
    synth->cache_origin_port      = (uint16_t) cfg->port;
    synth->cache_origin_tls       = cfg->tls ? 1 : 0;
    synth->cache_origin_family    = (ngx_uint_t) cfg->af_policy;

    /* Credentials + CA store: each stores bytes on the instance so synth's
     * ngx_str_t members reference storage valid for the instance lifetime. */
    sd_xroot_origin_apply_creds(is, synth, cfg);
    sd_xroot_origin_build_ca_store(is, synth, cfg->ca_dir, log);

    is->conf     = synth;
    is->synth    = synth;                       /* owned: free on destroy */
    inst->driver = &brix_sd_xroot_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = is;
    return inst;
}

void
brix_sd_xroot_destroy(brix_sd_instance_t *inst)
{
    if (inst == NULL) {
        return;
    }
    if (inst->state != NULL) {
        sd_xroot_inst_state *is = inst->state;

        if (is->synth != NULL && is->synth->gsi_store != NULL) {
            X509_STORE_free(is->synth->gsi_store);
        }
        free(is->synth);
    }
    free(inst->state);
    free(inst);
}
