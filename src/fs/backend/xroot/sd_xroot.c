/*
 * sd_xroot.c — remote root:// origin storage driver: core.
 *
 * Wraps the in-process XRootD origin wire client (cache/origin_*.c) behind the SD
 * vtable. This translation unit owns the shared origin-open machinery (the
 * per-open object state, the connect → bootstrap → kXR_open orchestrator, and the
 * credential-copy / teardown helpers), the driver vtable, the origin-checksum
 * query, and instance lifecycle (create / create_origin / destroy).  The object
 * I/O + open + stat slots live in sd_xroot_io.c, the staged atomic-publish slots
 * in sd_xroot_staged.c, and the namespace + metadata slots in sd_xroot_ns.c
 * (phase-79 file-size split); all share driver-private state via
 * sd_xroot_internal.h.  Anonymous login is the wire client's native mode;
 * authenticated origins use the cache's native-client delegation or a per-user
 * credential copied into the fill task.
 */

#include "sd_xroot.h"
#include "sd_xroot_internal.h"    /* obj_state + machinery + cross-file ops */
#include "fs/cache/cache_internal.h"   /* origin wire client + fill-task ctx */
#include "auth/crypto/pki_build.h"       /* brix_build_ca_store (GSI MITM verify) */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

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
void
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

/* Free an object's origin connection + open file handle + fill task; NULL-safe.
 * Shared with the open + stat slots (sd_xroot_io.c) via sd_xroot_internal.h. */
void
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
sd_xroot_obj_state *
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
