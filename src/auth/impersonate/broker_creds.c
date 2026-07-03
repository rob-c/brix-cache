/*
 * broker_creds.c - extracted concern
 * Phase-38 split of broker.c; behavior-identical.
 */
#include "broker_internal.h"


/* Broker base credentials, captured at startup; restored after each op. */

/* The broker's OWN real uid, captured at startup.  The broker structurally
 * refuses to impersonate to its own uid (config-independent), so it can never be
 * coerced into acting as the privileged service/root account it runs as. */

/*
 * Non-root broker identity (hyper-hardening).  When set to a real uid/gid (not
 * (uid_t)-1), the broker drops its REAL uid/gid to this dedicated service account
 * while KEEPING only CAP_SETUID/CAP_SETGID — so nothing runs as root after the
 * master-side rootfd open; the broker's base/idle identity is unprivileged and
 * it holds exactly the two capabilities impersonation needs.  Set by the
 * lifecycle layer (from brix_impersonation_broker_user) before broker_run; the
 * forked broker inherits them.  (uid_t)-1 => stay as the current uid.
 */
uid_t brix_imp_broker_user_uid = (uid_t) -1;
gid_t brix_imp_broker_user_gid = (gid_t) -1;

/* Set effective=permitted={SETUID,SETGID} (inheritable empty).  Returns 0/-1. */
int
imp_capset_setuid_setgid(int with_effective, ngx_log_t *log)
{
    struct __user_cap_header_struct  hdr;
    struct __user_cap_data_struct    data[2];

    ngx_memzero(&hdr, sizeof(hdr));
    ngx_memzero(data, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid     = 0;
    data[0].permitted   = (1u << CAP_SETUID) | (1u << CAP_SETGID);
    data[0].effective   = with_effective ? data[0].permitted : 0;
    data[0].inheritable = 0;
    if (syscall(SYS_capset, &hdr, data) != 0) {
        if (log) ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                               "impersonate broker: capset failed");
        return -1;
    }
    return 0;
}



/*
 * Drop the broker's real uid/gid to the configured non-root service account while
 * retaining only CAP_SETUID/CAP_SETGID.  Must be called while still root and AFTER
 * the bounding set + permitted caps have been reduced to the two we keep.  Uses
 * PR_SET_KEEPCAPS so the permitted set survives the uid transition, then re-raises
 * the effective set.  No-op (returns 0) when no broker user is configured or we
 * are not root.  Returns -1 on a hard failure (fail closed).
 */
int
imp_drop_to_service_user(ngx_log_t *log)
{
    uid_t svc_uid = brix_imp_broker_user_uid;
    gid_t svc_gid = brix_imp_broker_user_gid;
    gid_t one[1];

    if (svc_uid == (uid_t) -1 || getuid() != 0) {
        return 0;                        /* no drop requested, or not root */
    }
    if (svc_uid == 0) {
        if (log) BRIX_DIAG_EMERG(log, 0,
            "impersonate broker: service user resolves to root (uid 0)",
            "the broker must run as an unprivileged account so it cannot be "
            "abused to act as root",
            "set brix_impersonation_broker_user to a dedicated non-root "
            "account");
        return -1;
    }
    if (svc_gid == (gid_t) -1) {
        svc_gid = (gid_t) svc_uid;
    }

    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
        if (log) ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                               "impersonate broker: PR_SET_KEEPCAPS failed");
        return -1;
    }
    one[0] = svc_gid;
    if (syscall(SYS_setgroups, (size_t) 1, one) != 0
        || setresgid(svc_gid, svc_gid, svc_gid) != 0
        || setresuid(svc_uid, svc_uid, svc_uid) != 0)
    {
        if (log) BRIX_DIAG_EMERG(log, ngx_errno,
            "impersonate broker: cannot drop to service uid %d",
            "the service account is invalid, or the container/host blocks the "
            "setresuid/setgroups transition",
            "verify the broker account exists and that the master runs with "
            "the privileges to switch to it; the OS reason is appended below",
            (int) svc_uid);
        return -1;
    }
    (void) prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);

    /* Effective caps were cleared by the uid transition; re-raise the two we kept
     * (permitted retained them via KEEPCAPS). */
    if (imp_capset_setuid_setgid(1, log) != 0) {
        return -1;
    }
    /*
     * Verify the real, effective AND saved uids/gids all became the service id, so
     * setresuid cannot be undone by a plain setuid()/setgid().  NOTE: we do NOT
     * probe "can't regain root" — the broker MUST keep CAP_SETUID for setfsuid, and
     * CAP_SETUID inherently lets a process setuid(0).  So the non-root base reduces
     * incidental-root exposure (idle state, NSS, path bugs run as the service uid)
     * but does NOT contain a code-execution exploit, which is root-equivalent via
     * CAP_SETUID regardless of the base uid.  This is documented.
     */
    {
        uid_t ru, eu, su;
        gid_t rg, eg, sg;
        if (getresuid(&ru, &eu, &su) != 0 || getresgid(&rg, &eg, &sg) != 0
            || ru != svc_uid || eu != svc_uid || su != svc_uid
            || rg != svc_gid || eg != svc_gid || sg != svc_gid)
        {
            if (log) ngx_log_error(NGX_LOG_EMERG, log, 0,
                                   "impersonate broker: service-uid drop did not "
                                   "stick (r/e/s mismatch)");
            return -1;
        }
    }
    if (log) ngx_log_error(NGX_LOG_NOTICE, log, 0,
                           "impersonate broker: running as non-root service uid %d "
                           "with only CAP_SETUID+CAP_SETGID", (int) svc_uid);
    return 0;
}


int
brix_imp_broker_drop_caps(ngx_log_t *log)
{
    int cap;

    /* No new privileges (defence in depth: no setuid-binary escalation). */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        if (log) ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                               "impersonate broker: PR_SET_NO_NEW_PRIVS failed");
        return -1;
    }

    /* Clear the bounding set of everything but SETUID/SETGID so the dropped caps
     * can never be re-acquired (even via a future exec).  Done while root, which
     * holds CAP_SETPCAP. */
    for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
        if (cap == CAP_SETUID || cap == CAP_SETGID) {
            continue;
        }
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && ngx_errno != EINVAL) {
            /* EINVAL = unknown cap on this kernel; ignore. Other errors fail. */
            if (log) ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                                   "impersonate broker: CAPBSET_DROP(%d) failed",
                                   cap);
            return -1;
        }
    }

    /* Reduce permitted + effective to {SETUID, SETGID}. */
    if (imp_capset_setuid_setgid(1, log) != 0) {
        return -1;
    }

    /* Hyper-harden: drop to the non-root service account (keeping the two caps),
     * so the broker's base identity is unprivileged and nothing runs as root after
     * this point.  No-op when no broker user is configured. */
    if (imp_drop_to_service_user(log) != 0) {
        return -1;
    }

    if (log) ngx_log_error(NGX_LOG_NOTICE, log, 0,
                           "impersonate broker: dropped to CAP_SETUID+CAP_SETGID "
                           "(DAC now enforced for the impersonated user)");
    return 0;
}



/*
 * Become the mapped user for the duration of one op.  Returns 0 on success, -1 on
 * a transient failure, or IMP_REFUSE_PRIV if the target identity is reserved.
 *
 * HARD GUARD (non-bypassable, the whole point of this function): BEFORE touching
 * any credential syscall, refuse outright if the target uid, primary gid, or ANY
 * supplementary gid is 0 or below BRIX_IMP_HARD_MIN_ID.  The mapping layer
 * already rejects such principals, so reaching here with a reserved id is a
 * should-be-impossible invariant breach — we perform NO setgroups/setfsgid/
 * setfsuid and signal the caller to abort.  This makes a privileged file op
 * impossible in the code path even if the mapping layer were bypassed.
 *
 * Order: setgroups/setfsgid first, fsuid LAST; each set is read back (setfsuid(-1)
 * returns the current fsuid without changing it) because a failed setfsuid
 * silently keeps the old fsuid, which would be a privilege leak.  Finally the
 * REALIZED fsuid/fsgid are re-checked against the hard floor — belt and suspenders
 * against any kernel/edge anomaly.
 */
int
imp_become(const brix_idmap_creds_t *cr)
{
    uid_t got_uid;
    gid_t got_gid;

    if (brix_imp_creds_privileged(cr, BRIX_IMP_HARD_MIN_ID, NULL, NULL)) {
        return IMP_REFUSE_PRIV;          /* reserved id — touch NO syscall */
    }

    /*
     * Config-independent confused-deputy guard: never impersonate to the broker's
     * OWN uid (the privileged service/root account it runs as) nor to the nginx
     * worker uid (the SO_PEERCRED-gated peer).  Even if the mapping layer's
     * deny-lists were misconfigured, the broker cannot be coerced into acting as
     * the gateway's own service identity.
     */
    if (cr->uid == imp_self_uid
        || (brix_imp_broker_allow_uid != 0
            && cr->uid == brix_imp_broker_allow_uid))
    {
        return IMP_REFUSE_PRIV;
    }

    if (syscall(SYS_setgroups, (size_t) cr->ngroups, cr->groups) != 0) {
        return -1;
    }
    (void) setfsgid(cr->gid);
    if ((gid_t) setfsgid((gid_t) -1) != cr->gid) {
        return -1;
    }
    (void) setfsuid(cr->uid);
    if ((uid_t) setfsuid((uid_t) -1) != cr->uid) {
        return -1;                       /* fsuid did not take — refuse the op */
    }

    /* Re-verify the realized fs-credentials are non-reserved before any file op. */
    got_uid = (uid_t) setfsuid((uid_t) -1);
    got_gid = (gid_t) setfsgid((gid_t) -1);
    if (got_uid == 0 || got_uid < (uid_t) BRIX_IMP_HARD_MIN_ID
        || got_gid == 0 || got_gid < (gid_t) BRIX_IMP_HARD_MIN_ID)
    {
        return IMP_REFUSE_PRIV;          /* realized fsuid/fsgid is reserved */
    }
    return 0;
}


/* Restore the broker's own credentials (reverse order: fsuid, fsgid, groups). */
void
imp_restore(void)
{
    (void) setfsuid(imp_base_uid);
    (void) setfsgid(imp_base_gid);
    (void) syscall(SYS_setgroups, (size_t) imp_base_ngroups, imp_base_groups);
}



/* Strip a leading '/' so the path is relative to rootfd; "" / "/" -> ".". */
const char *
imp_rel(const char *path)
{
    while (*path == '/') {
        path++;
    }
    return *path ? path : ".";
}
