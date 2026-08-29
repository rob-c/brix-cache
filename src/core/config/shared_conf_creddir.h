/*
 * shared_conf_creddir.h — config-time provisioning of the delegated-credential
 * store directory.
 *
 * Split out of shared_conf.h so both files stay under the per-file line ceiling.
 * Included at the exact original position by shared_conf.h; every consumer sees
 * the helpers transitively, so no call site changes.
 */

#ifndef NGX_HTTP_BRIX_SHARED_CONF_CREDDIR_H
#define NGX_HTTP_BRIX_SHARED_CONF_CREDDIR_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * brix_shared_credential_dir_ensure() — Config-time guarantee for
 * brix_storage_credential_dir: create the directory 0700 (chown'd to the
 * worker user when the master runs as root) if it is missing, and shout —
 * NGX_LOG_WARN at parse time — when it cannot be created, is not a
 * directory, is group/other-accessible, or is owned by a user the workers
 * do not run as.
 *
 * WHY: The store holds delegated PRIVATE KEYS, and the default lives on
 * tmpfs (/dev/shm) precisely so nothing persists across reboots or lands in
 * backups — but /dev/shm is world-writable (1777), so the entire security
 * boundary is this directory's 0700 mode + ownership, which must therefore
 * be enforced here rather than left to operator setup. A broken or
 * foreign-owned path must NOT kill startup (the store may be unused, and
 * fallback=allow keeps requests on the service credential), but the admin
 * must be told that credential delegation will not work until it is fixed.
 *
 * HOW: stat(); on ENOENT mkdir(0700) + chown to ccf->user when euid==0
 * (mirroring ngx_create_paths). Every failure and every unsafe pre-existing
 * state warns via ngx_conf_log_error and returns — never fatal. Called from
 * every shared merge (per server/location), so a broken path is shouted per
 * context; the healthy path prints nothing and costs one stat().
 */
/* Resolved POST-de-escalation worker identity (defined in
 * src/auth/impersonate/lifecycle_worker.c; contract in lifecycle.h). Workers
 * are force-dropped to brix_worker_user/nobody when root-capable, so dirs
 * provisioned for them must be owned by THAT identity, not raw ccf->user. */
ngx_int_t brix_imp_worker_runtime_ids(ngx_uid_t conf_uid, ngx_gid_t conf_gid,
    uid_t *uid_out, gid_t *gid_out);

/* The uid/gid worker-writable provisioned dirs must be handed to: the runtime
 * worker identity when the master runs as root, else the invoking user. */
static inline void
brix_shared_worker_dir_ids(ngx_conf_t *cf, uid_t *uid_out, gid_t *gid_out)
{
    ngx_core_conf_t *ccf = (ngx_core_conf_t *)
                               ngx_get_conf(cf->cycle->conf_ctx, ngx_core_module);

    *uid_out = geteuid();
    *gid_out = (gid_t) -1;
    if (geteuid() == 0) {
        (void) brix_imp_worker_runtime_ids(
            (ccf != NULL) ? ccf->user  : (ngx_uid_t) NGX_CONF_UNSET_UINT,
            (ccf != NULL) ? (ngx_gid_t) ccf->group
                          : (ngx_gid_t) NGX_CONF_UNSET_UINT,
            uid_out, gid_out);      /* on failure the invoking-root ids stay */
    }
}

/* Rewrite the COMPILED default store path to its worker-uid-scoped form
 * (BRIX_CREDENTIAL_DIR_DEFAULT ".<uid>", the cred_stage.c convention).  Two
 * services sharing one host — the distro's own www-data nginx and a user's
 * test fleet both defaulting to the same 0700 tmpfs dir — otherwise fight
 * over ownership: whichever creates it first locks every other identity out
 * of credential delegation (seen live: a www-data-owned /dev/shm/brix-creds
 * broke delegation for the whole unprivileged test lane).  An operator's
 * EXPLICIT brix_storage_credential_dir is never touched. */
static inline void
brix_shared_credential_dir_default_scope(ngx_conf_t *cf, ngx_str_t *dir)
{
    uid_t   want_uid;
    gid_t   want_gid;
    u_char *p;

    if (dir->len != sizeof(BRIX_CREDENTIAL_DIR_DEFAULT) - 1
        || ngx_strncmp(dir->data, BRIX_CREDENTIAL_DIR_DEFAULT, dir->len) != 0)
    {
        return;                 /* operator-chosen path — leave it alone */
    }
    brix_shared_worker_dir_ids(cf, &want_uid, &want_gid);
    p = ngx_pnalloc(cf->pool,
                    sizeof(BRIX_CREDENTIAL_DIR_DEFAULT) + NGX_INT64_LEN + 2);
    if (p == NULL) {
        return;                 /* keep the shared default; ensure still runs */
    }
    dir->len = ngx_sprintf(p, BRIX_CREDENTIAL_DIR_DEFAULT ".%d",
                           (int) want_uid) - p;
    dir->data = p;
    p[dir->len] = '\0';         /* conf strings are read as C strings below */
}

static inline void
brix_shared_credential_dir_ensure(ngx_conf_t *cf, const ngx_str_t *dir)
{
    struct stat       st;
    const char       *path;
    uid_t             want_uid;
    gid_t             want_gid;

    if (dir == NULL || dir->len == 0) {
        return;                 /* explicit "" = per-user store disabled */
    }

    path = (const char *) dir->data;    /* conf tokens are NUL-terminated */
    brix_shared_worker_dir_ids(cf, &want_uid, &want_gid);

    if (stat(path, &st) != 0) {
        if (errno != ENOENT) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
                "brix: credential store \"%s\" is not accessible — "
                "credential delegation will not work until "
                "brix_storage_credential_dir is fixed", path);
            return;
        }

        if (mkdir(path, 0700) != 0 && errno != EEXIST) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
                "brix: cannot create credential store \"%s\" — "
                "credential delegation will not work until "
                "brix_storage_credential_dir is fixed", path);
            return;
        }

        if (stat(path, &st) != 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
                "brix: credential store \"%s\" vanished after create — "
                "credential delegation will not work", path);
            return;
        }

        /* The master parses config as root but the workers write the store
         * as the RUNTIME worker identity (the `user` account, or the
         * de-escalation target for a root-capable worker) — hand the fresh
         * directory to them, as ngx_create_paths does for the temp paths. */
        if (geteuid() == 0 && st.st_uid != want_uid
            && chown(path, want_uid, want_gid) != 0)
        {
            ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
                "brix: cannot chown credential store \"%s\" to the worker "
                "user — credential delegation will not work", path);
        }
        return;
    }

    if (!S_ISDIR(st.st_mode)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: credential store \"%s\" is not a directory — "
            "credential delegation will not work until "
            "brix_storage_credential_dir is fixed", path);
        return;
    }

    if ((st.st_mode & 0077) != 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: credential store \"%s\" is group/other-accessible "
            "(mode %04uo) — delegated private keys may be exposed; "
            "chmod 0700", path, (ngx_uint_t) (st.st_mode & 07777));
    }

    if (st.st_uid != want_uid) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: credential store \"%s\" is owned by uid %ud but the "
            "workers run as uid %ud — credential delegation will not work "
            "until ownership or brix_storage_credential_dir is fixed",
            path, (ngx_uint_t) st.st_uid, (ngx_uint_t) want_uid);
    }
}

#endif /* NGX_HTTP_BRIX_SHARED_CONF_CREDDIR_H */
