/* Worker privilege hardening and identity transition (phase 40). */

#include "core/compat/log_event.h"
#include "lifecycle.h"
#include "impersonate.h"
#include "impersonate_proto.h"
#include "observability/metrics/metrics.h"   /* brix_config_version_publish() */
#include "core/compat/log_diag.h"
#include "lifecycle_internal.h"
#include "platform/platform_api.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>                       /* PATH_MAX (P80.21 gate map load) */
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>


/* Shed privilege-escalation, DAC-bypass and identity capabilities before the
 * worker handles recovery state or requests. */
static ngx_int_t
imp_worker_prepare_drop(ngx_log_t *log)
{
#if BRIX_HAS_CAPABILITIES
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct   data[2];
    unsigned                        keep;
    /* The dangerous set — always shed from the bounding set (best-effort) and
     * from permitted+effective. SETUID/SETGID are deliberately NOT here: they are
     * retained IFF currently held, so a legitimate later identity drop still works
     * — the end-of-init worker de-escalation (brix_imp_worker_deescalate) uses them
     * to setuid the worker down to brix_worker_user/nobody, and the pblock backend's
     * off-root drop uses them too. Keeping SETUID adds no escalation a root (or
     * already-CAP_SETUID) worker does not already have, and it is stripped again by
     * the re-harden right after the de-escalation setuid. */
    static const int kill_caps[] = {
        CAP_SETPCAP, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER,
        CAP_CHOWN, CAP_FSETID, CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_MKNOD,
        CAP_SETFCAP,
    };
    unsigned i;
#endif

#if BRIX_HAS_NO_NEW_PRIVS
    if (brix_plat_prctl(PR_SET_NO_NEW_PRIVS, 1) != 0) {
        if (log != NULL) {
            BRIX_LOG(NGX_LOG_EMERG, log, ngx_errno,
                "impersonate: worker no-new-privileges unavailable; "
                "refusing to start without the promised exec confinement");
        }
        return NGX_ERROR;
    }
#else
    /* A host without no-new-privileges or capabilities may serve only when it
     * arrived as an ordinary, untainted non-root process.  Root/set-id images
     * are refused because this PAL cannot prove an irreversible transition. */
    if (getuid() == 0 || geteuid() == 0 || brix_plat_process_tainted()) {
        BRIX_LOG(NGX_LOG_EMERG, log, 0,
            "impersonate: host cannot enforce no-new-privileges; refusing "
            "a root or set-id worker");
        return NGX_ERROR;
    }
#endif

#if BRIX_HAS_CAPABILITIES
    ngx_memzero(&hdr, sizeof(hdr));
    ngx_memzero(data, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid     = 0;

    /* Retain {SETUID,SETGID} only if actually held now (a root worker has all
     * caps; a non-root worker granted CAP_SETUID via file/ambient caps keeps just
     * that) — everything else (DAC_OVERRIDE/MKNOD/SYS_ADMIN/PTRACE/CHOWN/...) is
     * dropped, so uid 0 without CAP_DAC_OVERRIDE now respects on-disk DAC. A plain
     * unprivileged worker holds nothing and keeps nothing. */
    keep = ((1u << CAP_SETUID) | (1u << CAP_SETGID));
    if (!brix_imp_cap_held(CAP_SETUID)) { keep &= ~(1u << CAP_SETUID); }
    if (!brix_imp_cap_held(CAP_SETGID)) { keep &= ~(1u << CAP_SETGID); }
    data[0].permitted = data[0].effective = keep;

    if (brix_plat_capset(&hdr, data) != 0) {
        if (log != NULL) {
            BRIX_LOG(NGX_LOG_EMERG, log, ngx_errno,
                "impersonate: worker capability shedding failed; refusing "
                "to start with potentially retained privileges");
        }
        return NGX_ERROR;
    }
    /* Best-effort bounding-set drop of the dangerous caps (needs CAP_SETPCAP). */
    for (i = 0; i < sizeof(kill_caps) / sizeof(kill_caps[0]); i++) {
        (void) brix_plat_prctl(PR_CAPBSET_DROP, kill_caps[i]);
    }
#endif
    return NGX_OK;
}

/*
 * WHAT: Irreversibly clear every effective, permitted and inheritable worker
 *       capability after the identity transition is complete.
 * WHY:  The preparation pass retains SETUID/SETGID just long enough to reach
 *       the confined uid.  An already-target worker or a securebits-enabled
 *       post-setuid worker must not carry those transition capabilities into
 *       request processing.
 * HOW:  Submit two zeroed v3 capability words, then read them back.  Failure to
 *       set or verify the terminal state aborts worker startup.
 */
static ngx_int_t
imp_worker_drop_all_caps(ngx_log_t *log)
{
#if BRIX_HAS_CAPABILITIES
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct   data[2];
    unsigned                        i;

    ngx_memzero(&hdr, sizeof(hdr));
    ngx_memzero(data, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (brix_plat_capset(&hdr, data) != 0) {
        BRIX_LOG(NGX_LOG_EMERG, log, ngx_errno,
            "impersonate: terminal worker capability shedding failed; "
            "refusing to serve");
        return NGX_ERROR;
    }
    if (brix_plat_capget(&hdr, data) != 0) {
        BRIX_LOG(NGX_LOG_EMERG, log, ngx_errno,
            "impersonate: terminal worker capability state cannot be verified; "
            "refusing to serve");
        return NGX_ERROR;
    }
    for (i = 0; i < sizeof(data) / sizeof(data[0]); i++) {
        if (data[i].effective != 0 || data[i].permitted != 0
            || data[i].inheritable != 0)
        {
            BRIX_LOG(NGX_LOG_EMERG, log, 0,
                "impersonate: worker retained capabilities after terminal "
                "shedding; refusing to serve");
            return NGX_ERROR;
        }
    }
    return NGX_OK;
#else
    (void) log;
    return NGX_OK;
#endif
}

/* Return 1 only when primary/effective and every supplementary group are the
 * confined target gid; 0 for a mismatch and -1 when the group set is unreadable. */
static int
imp_worker_groups_allowed(const char *acct, gid_t target)
{
    gid_t *groups = NULL;
    gid_t  allowed[256];
    gid_t  rgid;
    gid_t  egid;
#if BRIX_HAS_SAVED_IDS
    gid_t  sgid;
#endif
    int    count;
    int    allowed_count = (int) (sizeof(allowed) / sizeof(allowed[0]));
    int    i;
    int    j;
    int    found;
    int    result = -1;

#if BRIX_HAS_SAVED_IDS
    if (brix_plat_getresgid(&rgid, &egid, &sgid) != 0
        || rgid != target || egid != target || sgid != target)
#else
    rgid = getgid();
    egid = getegid();
    if (brix_plat_process_tainted()
        || rgid != target || egid != target)
#endif
    {
        return 0;
    }
    count = getgroups(0, NULL);
    if (count < 0) {
        return -1;
    }
    if (count > 0) {
        groups = malloc((size_t) count * sizeof(groups[0]));
    }
    if (count > 0 && groups == NULL) {
        errno = ENOMEM;
        return -1;
    }
    if ((count > 0 && getgroups(count, groups) != count)
        || brix_plat_getgrouplist(acct, target, allowed, &allowed_count) < 0)
    {
        free(groups);
        return -1;
    }
    result = 1;
    for (i = 0; i < count; i++) {
        if (groups[i] == 0) {
            result = 0;
            break;
        }
        found = 0;
        for (j = 0; j < allowed_count; j++) {
            if (groups[i] == allowed[j]) {
                found = 1;
                break;
            }
        }
        if (!found) {
            result = 0;
            break;
        }
    }
    free(groups);
    return result;
}

/* A capability-free nginx service identity may win when brix_worker_user was
 * not explicitly set.  Saved ids must be inert and group 0 is never accepted. */
static int
imp_worker_current_identity_safe(void)
{
    uid_t  ruid;
    uid_t  euid;
#if BRIX_HAS_SAVED_IDS
    uid_t  suid;
#endif
    gid_t  rgid;
    gid_t  egid;
#if BRIX_HAS_SAVED_IDS
    gid_t  sgid;
#endif
    struct passwd *pw;

#if BRIX_HAS_SAVED_IDS
    if (brix_plat_getresuid(&ruid, &euid, &suid) != 0
        || brix_plat_getresgid(&rgid, &egid, &sgid) != 0
        || ruid == 0 || rgid == 0 || ruid != euid || ruid != suid
        || rgid != egid || rgid != sgid)
    {
        return 0;
    }
#else
    ruid = getuid();
    euid = geteuid();
    rgid = getgid();
    egid = getegid();
    if (brix_plat_process_tainted() || ruid == 0 || rgid == 0
        || ruid != euid || rgid != egid)
    {
        return 0;
    }
#endif
    pw = getpwuid(ruid);
    if (pw == NULL || pw->pw_gid != rgid) {
        return 0;
    }
    return imp_worker_groups_allowed(pw->pw_name, rgid) == 1;
}

static int
imp_worker_uids_confined(uid_t target)
{
    uid_t ruid;
    uid_t euid;
#if BRIX_HAS_SAVED_IDS
    uid_t suid;
#endif

#if BRIX_HAS_SAVED_IDS
    return brix_plat_getresuid(&ruid, &euid, &suid) == 0
        && ruid == target && euid == target && suid == target;
#else
    ruid = getuid();
    euid = geteuid();
    return !brix_plat_process_tainted()
        && ruid == target && euid == target;
#endif
}

/* Normalize an already-target uid's group identity before discarding CAP_SETGID. */
static ngx_int_t
imp_worker_finish_target(ngx_log_t *log, const char *acct, uid_t target_uid,
    gid_t target_gid)
{
    int confined = imp_worker_groups_allowed(acct, target_gid);

    if (confined < 0) {
        BRIX_LOG(NGX_LOG_EMERG, log, ngx_errno,
            "brix_worker_user: cannot verify group identity for \"%s\"; "
            "refusing to serve", acct);
        return NGX_ERROR;
    }
    if (confined == 0) {
        if (geteuid() != 0 && !brix_imp_cap_held(CAP_SETGID)) {
            BRIX_LOG(NGX_LOG_EMERG, log, 0,
                "brix_worker_user: uid matches \"%s\" but its group identity "
                "cannot be confined; refusing to serve", acct);
            return NGX_ERROR;
        }
        if (setgroups(1, &target_gid) != 0
            || brix_plat_setresgid(target_gid, target_gid, target_gid) != 0
            || imp_worker_groups_allowed(acct, target_gid) != 1)
        {
            BRIX_LOG(NGX_LOG_EMERG, log, ngx_errno,
                "brix_worker_user: failed to confine group identity for \"%s\"; "
                "refusing to serve", acct);
            return NGX_ERROR;
        }
    }
    if (!imp_worker_uids_confined(target_uid)) {
        if (!brix_imp_cap_held(CAP_SETUID)
            || brix_plat_setresuid(target_uid, target_uid, target_uid) != 0
            || !imp_worker_uids_confined(target_uid))
        {
            BRIX_LOG(NGX_LOG_EMERG, log, ngx_errno,
                "brix_worker_user: failed to confine saved uid for \"%s\"; "
                "refusing to serve", acct);
            return NGX_ERROR;
        }
    }
    return imp_worker_drop_all_caps(log);
}

/* ---- brix_imp_worker_harden ----
 *
 * WHAT: Set NO_NEW_PRIVS and shed every capability except SETUID/SETGID needed
 *       for the immediately following confined-identity transition.
 * WHY:  A worker never needs capabilities; a worker (mis)configured to run as
 *       root must not keep CAP_DAC_OVERRIDE/CAP_MKNOD/CAP_SETUID/… — a worker-code
 *       exploit would otherwise be root. The old code only dropped caps in `map`
 *       mode, leaving the default posture (and HTTP-only workers) fully privileged
 *       when the worker ran as root.
 * HOW:  Delegates to imp_worker_prepare_drop(). Called from per-worker init
 *       BEFORE the stream-config early-return so WebDAV/S3 (HTTP-only) workers are
 *       hardened too, not just stream/root:// workers.
 */
ngx_int_t
brix_imp_worker_harden(ngx_log_t *log)
{
    return imp_worker_prepare_drop(log);
}

/* ---- brix_worker_user: the confined account the worker is forced down to ----
 *
 * Process-global (there is one worker uid per process; the strictest posture is
 * shared across every brix server, stream + http). Empty => unset => default to
 * "nobody" with a startup warning. Set by the `brix_worker_user` directive. */
char brix_worker_user[64] = "";

char *
brix_conf_set_worker_user(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;

    (void) cmd;
    (void) conf;

    if (value[1].len == 0 || value[1].len >= sizeof(brix_worker_user)) {
        return "invalid brix_worker_user account name";
    }
    /* Last non-empty setting wins; the account is resolved at worker init. */
    ngx_memcpy(brix_worker_user, value[1].data, value[1].len);
    brix_worker_user[value[1].len] = '\0';
    return NGX_CONF_OK;
}

/* ---- brix_imp_worker_runtime_ids ----
 *
 * WHAT: Resolve the uid/gid the workers actually serve as (see lifecycle.h).
 * WHY:  Config-time provisioning of worker-writable directories (the default
 *       credential store, the default gateway stage spool) must chown to the
 *       POST-de-escalation identity: with the always-on drop, `user root` (or
 *       no `user` at all under a root master) yields workers running as
 *       brix_worker_user/nobody, and a root:0700 directory would EACCES them.
 * HOW:  A real unprivileged `user` account wins (the drop no-ops for it);
 *       otherwise resolve brix_worker_user (default "nobody") exactly as
 *       brix_imp_worker_deescalate will at worker init. */
ngx_int_t
brix_imp_worker_runtime_ids(ngx_uid_t conf_uid, ngx_gid_t conf_gid,
    uid_t *uid_out, gid_t *gid_out)
{
    const char    *acct;
    struct passwd *pw;

    if (conf_uid != (ngx_uid_t) NGX_CONF_UNSET_UINT && conf_uid != 0) {
        *uid_out = (uid_t) conf_uid;
        *gid_out = (gid_t) conf_gid;
        return NGX_OK;
    }

    /* nginx fills an omitted `user` directive from its compile-time
     * --user/--group defaults only in the core module's init_conf, after
     * location merges have already asked us to provision stage/credential
     * stores.  At that earlier point ccf->user is still UNSET.  Resolve the
     * same compiled account here so distro builds such as Fedora's
     * --user=nginx do not get a nobody-owned 0700 store for an nginx worker.
     * An explicitly root-capable worker must still take the fail-closed
     * brix_worker_user/nobody path below. */
    if (conf_uid == (ngx_uid_t) NGX_CONF_UNSET_UINT) {
        pw = getpwnam(NGX_USER);
        if (pw != NULL && pw->pw_uid != 0) {
            *uid_out = pw->pw_uid;
            *gid_out = pw->pw_gid;
            return NGX_OK;
        }
    }
    acct = brix_worker_user[0] ? brix_worker_user : "nobody";
    pw   = getpwnam(acct);
    if (pw == NULL || pw->pw_uid == 0) {
        return NGX_ERROR;
    }
    *uid_out = pw->pw_uid;
    *gid_out = pw->pw_gid;
    return NGX_OK;
}

/*
 * WHAT: Resolve and validate the configured confined worker identity.
 * WHY: Keep account lookup policy separate from the capability transition.
 * HOW: Select the configured account or nobody, reject missing/root identities,
 *      and return its uid/gid plus whether the default was selected.
 */
static ngx_int_t
imp_worker_resolve_target(ngx_log_t *log, const char **acct_out,
    uid_t *uid_out, gid_t *gid_out, int *defaulted_out)
{
    struct passwd *pw;
    const char    *acct;
    int            defaulted;

    defaulted = (brix_worker_user[0] == '\0');
    acct = defaulted ? "nobody" : brix_worker_user;
    errno = 0;
    pw = getpwnam(acct);
    if (pw == NULL) {
        BRIX_LOG(NGX_LOG_EMERG, log, errno,
            "brix_worker_user: account \"%s\" not found — refusing to serve "
            "(set brix_worker_user to an existing unprivileged account)", acct);
        return NGX_ERROR;
    }
    if (pw->pw_uid == 0 || pw->pw_gid == 0) {
        BRIX_LOG(NGX_LOG_EMERG, log, 0,
            "brix_worker_user: \"%s\" is a uid/gid 0 account — refusing to serve "
            "(the worker must run as a confined, non-root account)", acct);
        return NGX_ERROR;
    }
    *acct_out = acct;
    *uid_out = pw->pw_uid;
    *gid_out = pw->pw_gid;
    *defaulted_out = defaulted;
    return NGX_OK;
}


/*
 * WHAT: Drop a root-capable worker to its resolved confined account.
 * WHY: Ensure pre-authentication parsing cannot retain root-capable identity.
 * HOW: Apply groups, gid, then uid; verify both real/effective ids; strip the
 *      transition capabilities and report whether the default account was used.
 */
static ngx_int_t
imp_worker_apply_drop(ngx_log_t *log, const char *acct, uid_t tgt_uid,
    gid_t tgt_gid, int defaulted)
{
    if (setgroups(1, &tgt_gid) != 0
        || setgid(tgt_gid) != 0
        || setuid(tgt_uid) != 0)
    {
        BRIX_LOG(NGX_LOG_EMERG, log, ngx_errno,
            "brix_worker_user: FAILED to drop worker to \"%s\" — refusing to "
            "serve (pre-auth parsing must never run as a root-capable identity)",
            acct);
        return NGX_ERROR;
    }
    if (!imp_worker_uids_confined(tgt_uid)
        || imp_worker_groups_allowed(acct, tgt_gid) != 1)
    {
        BRIX_LOG(NGX_LOG_EMERG, log, 0,
            "brix_worker_user: identity drop to \"%s\" did not stick — "
            "refusing to serve", acct);
        return NGX_ERROR;
    }

    if (imp_worker_drop_all_caps(log) != NGX_OK) {
        return NGX_ERROR;
    }
    if (defaulted) {
        BRIX_LOG(NGX_LOG_WARN, log, 0,
            "brix_worker_user not set: dropped a root-capable worker to "
            "\"nobody\" (uid=%d); set a dedicated confined account instead",
            (int) tgt_uid);
    } else {
        BRIX_LOG(NGX_LOG_NOTICE, log, 0,
            "brix_worker_user: worker dropped to \"%s\" (uid=%d); pre-auth "
            "parsing runs unprivileged", acct, (int) tgt_uid);
    }
    return NGX_OK;
}


/* ---- brix_imp_worker_deescalate ----
 *
 * WHAT: Force a worker that can trivially become root — running as root, OR
 *       holding CAP_SETUID (even as a non-root service account) — down to a
 *       confined account (brix_worker_user, else "nobody"), fail-closed, then
 *       re-harden to strip the retained SETUID/SETGID. Runs in EVERY mode and
 *       protocol (stream + http-only), once per worker, right after the cap-harden
 *       and BEFORE backend init / broker connect / the seccomp install.
 * WHY:  The pre-authentication credential parsers (JWT/macaroon/X.509/VOMS/krb5)
 *       run in the worker on fully attacker-controlled bytes; a parse bug must not
 *       land as a root-capable identity. euid==0 is NOT the right test — a non-root
 *       account with CAP_SETUID (or passwordless sudo) is root-equivalent. This
 *       neutralizes the CAP_SETUID case by dropping it; NO_NEW_PRIVS (set by the
 *       harden above, sticky + inherited) neutralizes the setuid-binary/sudo
 *       escalation path for the worker's own exec chain regardless of uid.
 * HOW:  Resolve the target account (fail-closed on missing / uid|gid 0). If already
 *       that uid, normalize real/effective/saved ids and supplementary groups,
 *       then shed all transition capabilities. If we can change uid (root or
 *       CAP_SETUID), perform and verify the full identity drop. If we cannot
 *       reach the configured identity, refuse to serve.
 * Returns NGX_OK to continue, NGX_ERROR to fail the worker closed.
 */
ngx_int_t
brix_imp_worker_deescalate(ngx_log_t *log)
{
    const char    *acct;
    uid_t          tgt_uid;
    gid_t          tgt_gid;
    int            defaulted;

    /* Single-process mode serves requests in the privileged master without a
     * safe pre-fork ownership/backend handoff. Refuse it rather than retain
     * privileges or mutate root-composed state in place. */
    if (ngx_process == NGX_PROCESS_SINGLE) {
        BRIX_LOG(NGX_LOG_EMERG, log, 0,
            "master_process off is unsupported: BriX requires a worker "
            "privilege boundary; refusing to serve");
        return NGX_ERROR;
    }
    if (ngx_process != NGX_PROCESS_WORKER) {
        return NGX_OK;
    }

    if (imp_worker_resolve_target(log, &acct, &tgt_uid, &tgt_gid,
                                  &defaulted) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* nginx may already have selected the confined uid, including when its
     * executable carried ambient/file SETUID.  End the transition explicitly;
     * the preparation pass alone intentionally retained that capability. */
    if (getuid() == tgt_uid && geteuid() == tgt_uid) {
        return imp_worker_finish_target(log, acct, tgt_uid, tgt_gid);
    }

    if (geteuid() == 0 || brix_imp_cap_held(CAP_SETUID)) {
        return imp_worker_apply_drop(log, acct, tgt_uid, tgt_gid, defaulted);
    }

    if (defaulted && imp_worker_drop_all_caps(log) == NGX_OK
        && imp_worker_current_identity_safe())
    {
        BRIX_LOG(NGX_LOG_INFO, log, 0,
            "worker already runs as a safe unprivileged nginx account uid=%d; "
            "preserving that configured identity", (int) geteuid());
        return NGX_OK;
    }

    BRIX_LOG(NGX_LOG_EMERG, log, 0,
        "brix_worker_user: worker uid=%d cannot transition to \"%s\" and has "
        "no CAP_SETUID; refusing to serve", (int) geteuid(), acct);
    return NGX_ERROR;
}
