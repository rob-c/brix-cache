/*
 * runtime_server_backend_stage.c — zero-config default write-staging for a
 * whole-object remote gateway (WebDAV/S3 backend) plus the systemd PrivateTmp
 * posture warning. Split verbatim out of runtime_server_backend.c (mechanical
 * file-size split); the two entry points crossing back into
 * brix_tier_register_stores() are declared in runtime_server_backend_internal.h.
 */

#include "config.h"
#include "root_prepare.h"
#include "credential_block.h"             /* §14 brix_credential lookup/bearer */
#include "core/compat/staged_file.h"
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "fs/vfs/vfs_backend_registry.h"   /* per-export backend registration */
#include "fs/path/path.h"                 /* brix_mkdir_recursive (pblock:// init) */
#include "fs/tier/tier.h"              /* phase-64 tier parse + cache/stage register */
#include "fs/cache/cache_internal.h"   /* brix_cache_state_root (effective sidecar tree) */
#include "core/config/export_guard.h"  /* brix_assert_dir_outside_export (hard guard) */
#include "runtime_server_backend_internal.h"

#include <stdlib.h>                    /* strtol (F8 peer-ring port parse)   */
#include <string.h>                    /* strrchr                            */

#define BRIX_TIER_DEFAULT_STAGE_BASE  "/tmp/staging"

/* 1 iff this process's /tmp is a systemd PrivateTmp mount — the /tmp
 * mountpoint's root inside its filesystem is a /tmp/systemd-private-<id>/tmp
 * subtree. Parsed from /proc/self/mountinfo (fields: id parent major:minor
 * ROOT MOUNTPOINT ...). Config-domain read, best-effort (0 on any failure). */
static int
brix_tmp_is_systemd_private(void)
{
    FILE *f;
    char  line[1024];
    int   private_tmp = 0;

    f = fopen("/proc/self/mountinfo", "re");
    if (f == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        char root[512], mnt[512];

        if (sscanf(line, "%*d %*d %*31s %511s %511s", root, mnt) == 2
            && strcmp(mnt, "/tmp") == 0
            && strstr(root, "/systemd-private-") != NULL)
        {
            private_tmp = 1;
            break;
        }
    }
    (void) fclose(f);
    return private_tmp;
}

/* Shout — loudly, per store — when a stage/cache store lives under a systemd
 * PrivateTmp /tmp: that mount is PRIVATE to the service and DELETED on every
 * service stop/restart, so staged-but-unflushed writes and cached objects do
 * not survive. The shipped unit sets PrivateTmp=true, making this the default
 * deployment posture — the operator must be told, not left to find out from a
 * post-restart empty spool. */
void
brix_tier_warn_private_tmp(ngx_conf_t *cf,
    const ngx_http_brix_shared_conf_t *common)
{
    const ngx_str_t *stores[2];
    int               i, shouted = 0;

    if (!brix_tmp_is_systemd_private()) {
        return;
    }
    stores[0] = &common->stage_store;
    stores[1] = &common->cache_store;

    for (i = 0; i < 2; i++) {
        if (stores[i]->len == 0
            || ngx_strnstr(stores[i]->data, ":/tmp/", stores[i]->len) == NULL)
        {
            continue;
        }
        if (!shouted) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "brix: ==================== PrivateTmp DETECTED "
                "====================");
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "brix: this service runs with systemd PrivateTmp: /tmp is "
                "PRIVATE to the service and is DELETED on every service "
                "stop/restart.");
            shouted = 1;
        }
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: the store \"%V\" therefore does NOT survive a restart — "
            "staged-but-unflushed writes / cached objects are LOST. Point "
            "it at a durable path or set PrivateTmp=no in the unit.",
            stores[i]);
    }
    if (shouted) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: ==========================================================="
            "====");
    }
}

/* Build "<base>/<sanitised backend URL>.<worker-uid>" for the brix-managed
 * default stage store: every backend-URL byte outside [A-Za-z0-9._-] becomes
 * '_', capped at 160 bytes, so distinct backends get distinct filesystem-safe
 * spool directories under the one managed base. The runtime worker uid is
 * part of the leaf name: the base is shared between every instance on the
 * host, and two instances of different identities (a root-launched gateway
 * spooling as nobody next to an unprivileged dev instance) hitting the SAME
 * backend URL must not fight over one 0700 leaf only one of them can use. */
static void
brix_tier_default_stage_dir(const ngx_str_t *backend, uid_t worker_uid,
    char *dir, size_t cap)
{
    size_t  pos = sizeof(BRIX_TIER_DEFAULT_STAGE_BASE "/") - 1;
    size_t  i;

    ngx_cpystrn((u_char *) dir, (u_char *) BRIX_TIER_DEFAULT_STAGE_BASE "/",
                cap);
    for (i = 0; i < backend->len && i < 160 && pos + 1 < cap; i++) {
        u_char c = backend->data[i];
        int    keep = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                   || (c >= '0' && c <= '9') || c == '.' || c == '_'
                   || c == '-';

        dir[pos++] = keep ? (char) c : '_';
    }
    dir[pos] = '\0';
    if (pos < cap) {
        (void) snprintf(dir + pos, cap - pos, ".%lu",
                        (unsigned long) worker_uid);
    }
}

/*
 * brix_tier_default_stage_store() — zero-config write staging for a
 * whole-object remote gateway (WebDAV/S3 backend).
 *
 * WHAT: When a writable export forwards to a whole-object remote backend and
 *       the operator configured NO stage tier at all, provision the stock
 *       stage decorator over a brix-managed posix store at
 *       /tmp/staging/<sanitised-backend-url>.<worker-uid>: create the
 *       directory (0711
 *       base, 0700 leaf chown'd to the worker user, exactly as
 *       brix_shared_credential_dir_ensure hands over /dev/shm/brix-creds),
 *       point common->stage_store at "posix:<dir>", flip stage_enable on,
 *       and shout a multi-line [warn] banner naming the directory, the tmpfs
 *       option and the opt-outs.
 *
 * WHY: Without a stage tier the remote driver rejects random-offset writes
 *      at the cap (kXR_Unsupported / EINVAL) — correct but hostile as the
 *      default posture of a POSIX-speaking gateway. Routing the default
 *      through the SAME tier grammar the operator would write by hand
 *      (brix_stage on + brix_stage_store posix:…) keeps one code path:
 *      tier_parse_local validates the directory like an export root and the
 *      stock sd_stage decorator does all buffering and flushing — no bespoke
 *      staging machinery.
 *
 * HOW: Build the sanitised leaf path; mkdir base 0711 (root-owned, traverse
 *      only) and leaf 0700; chown the leaf to ccf->user when the master runs
 *      as root (the workers write the spool). On ANY failure warn and return
 *      with staging left off — writes then require strictly sequential
 *      offsets, exactly as before — never fatal. On success rewrite
 *      stage_store (cf->pool) + stage_enable and emit the banner.
 */
void
brix_tier_default_stage_store(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common)
{
    char         dir[PATH_MAX];
    u_char      *url;
    size_t       url_len;
    struct stat  st;
    uid_t        want_uid;
    gid_t        want_gid;

    brix_shared_worker_dir_ids(cf, &want_uid, &want_gid);
    brix_tier_default_stage_dir(&common->storage_backend, want_uid,
                                dir, sizeof(dir));

    if (brix_mkdir_recursive(BRIX_TIER_DEFAULT_STAGE_BASE, 0711) != 0
        || (mkdir(dir, 0700) != 0 && errno != EEXIST))
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
            "brix: cannot create the default stage store \"%s\" — "
            "write staging stays OFF; random writes to the remote backend "
            "will be rejected (set brix_stage_store, or \"brix_stage off\" "
            "to silence this warning)", dir);
        return;
    }
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
            "brix: default stage store \"%s\" is not a usable directory — "
            "write staging stays OFF", dir);
        return;
    }

    /* The master parses config as root but the workers write the spool as
     * the RUNTIME worker identity — the `user` account, or the always-on
     * de-escalation target (brix_worker_user/nobody) for a root-capable
     * worker — hand the directory to them, exactly as ngx_create_paths does
     * for the temp paths. */
    if (geteuid() == 0 && st.st_uid != want_uid
        && chown(dir, want_uid, want_gid) != 0)
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
            "brix: cannot chown the default stage store \"%s\" to the "
            "worker user — write staging stays OFF", dir);
        return;
    }

    /* An unprivileged master cannot repossess a foreign leaf (a squatter, or
     * debris from another identity despite the uid-suffixed name) — refuse it
     * and keep the documented never-fatal contract: warn, staging stays OFF,
     * rather than adopting a store the later tier validation would [emerg] on
     * (or worse, one a hostile local user controls). */
    if (geteuid() != 0
        && (st.st_uid != geteuid() || access(dir, W_OK | X_OK) != 0))
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: the default stage store \"%s\" exists but is not owned/"
            "writable by this user (owner uid %lu, we are uid %lu) — "
            "write staging stays OFF; remove the directory or set "
            "brix_stage_store", dir, (unsigned long) st.st_uid,
            (unsigned long) geteuid());
        return;
    }

    url_len = sizeof("posix:") - 1 + ngx_strlen(dir);
    url = ngx_pnalloc(cf->pool, url_len + 1);
    if (url == NULL) {
        return;
    }
    ngx_sprintf(url, "posix:%s%Z", dir);
    common->stage_store.data = url;
    common->stage_store.len  = url_len;
    common->stage_enable     = 1;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "brix: ==================== DEFAULT WRITE-STAGING ===================");
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "brix: no stage tier is configured for the whole-object remote "
        "backend \"%V\";", &common->storage_backend);
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "brix: random writes will be buffered in \"%s\",", dir);
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "brix: a directory MANAGED BY BRIX (created, filled and cleaned by "
        "brix — do not place files there; mount it tmpfs if you want "
        "RAM-tier performance).");
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "brix: override with \"brix_stage_store <store-url>\", or opt out "
        "with \"brix_stage off\" (writes must then be strictly sequential).");
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "brix: ===============================================================");
}
