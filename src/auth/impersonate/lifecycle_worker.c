/*
 * lifecycle_worker.c — worker-side impersonation client glue (phase 40).
 * Split verbatim from lifecycle.c.
 *
 * Owns everything that runs in the nginx worker: hyper-hardening the worker by
 * shedding the privilege-escalation / DAC-bypass / identity capabilities (the
 * worker is a pure broker CLIENT), connecting the worker client to the broker
 * socket, and setting/clearing the broker's target principal around each
 * request.  Everything here is inert unless the mode is `map` (see
 * lifecycle_internal.h for the shared settings block).
 */

#include "lifecycle.h"
#include "impersonate.h"
#include "impersonate_proto.h"
#include "observability/metrics/metrics.h"   /* brix_config_version_publish() */
#include "core/compat/log_diag.h"
#include "lifecycle_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <linux/capability.h>


/*
 * Hyper-harden the worker: shed the privilege-escalation / DAC-bypass / identity
 * capabilities so a compromised worker can never setfsuid/setgid or override DAC,
 * even if nginx was granted them via file/ambient capabilities to feed the broker.
 * Best-effort: clearing effective+permitted always succeeds; bounding-set drops
 * need CAP_SETPCAP and are skipped (with no error) when already unprivileged.  The
 * worker is a pure broker CLIENT and needs none of these.
 */
/* True iff this process currently holds `cap` in its effective OR permitted set.
 * cap < 32 for every cap we test (SETUID=7, SETGID=6, DAC_OVERRIDE=1, SYS_ADMIN=21),
 * so word 0 suffices. Best-effort: a capget failure reports "not held". */
int
brix_imp_cap_held(int cap)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct   data[2];

    ngx_memzero(&hdr, sizeof(hdr));
    ngx_memzero(data, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid     = 0;
    if (syscall(SYS_capget, &hdr, data) != 0) {
        return 0;
    }
    return (data[0].effective & (1u << cap)) != 0
        || (data[0].permitted & (1u << cap)) != 0;
}

static void
imp_worker_drop_caps(ngx_log_t *log)
{
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

    (void) prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

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

    if (syscall(SYS_capset, &hdr, data) != 0) {
        if (log) ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                               "impersonate: worker capset failed "
                               "(continuing — worker is an unprivileged client)");
    }
    /* Best-effort bounding-set drop of the dangerous caps (needs CAP_SETPCAP). */
    for (i = 0; i < sizeof(kill_caps) / sizeof(kill_caps[0]); i++) {
        (void) prctl(PR_CAPBSET_DROP, kill_caps[i], 0, 0, 0);
    }
}

/* ---- brix_imp_worker_harden ----
 *
 * WHAT: Shed ALL worker capabilities + set NO_NEW_PRIVS, in EVERY impersonation
 *       mode (off/single/map). Idempotent.
 * WHY:  A worker never needs capabilities; a worker (mis)configured to run as
 *       root must not keep CAP_DAC_OVERRIDE/CAP_MKNOD/CAP_SETUID/… — a worker-code
 *       exploit would otherwise be root. The old code only dropped caps in `map`
 *       mode, leaving the default posture (and HTTP-only workers) fully privileged
 *       when the worker ran as root.
 * HOW:  Delegates to imp_worker_drop_caps(). Called from the per-worker init
 *       BEFORE the stream-config early-return so WebDAV/S3 (HTTP-only) workers are
 *       hardened too, not just stream/root:// workers.
 */
void
brix_imp_worker_harden(ngx_log_t *log)
{
    imp_worker_drop_caps(log);
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
    acct = brix_worker_user[0] ? brix_worker_user : "nobody";
    pw   = getpwnam(acct);
    if (pw == NULL || pw->pw_uid == 0) {
        return NGX_ERROR;
    }
    *uid_out = pw->pw_uid;
    *gid_out = pw->pw_gid;
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
 *       that uid, done. If we can change uid (root or CAP_SETUID): setgroups/setgid/
 *       setuid, verify it stuck, re-harden. If we CANNOT (plain non-root, no cap):
 *       refuse to serve if any escalation capability somehow survived; else warn.
 * Returns NGX_OK to continue, NGX_ERROR to fail the worker closed.
 */
ngx_int_t
brix_imp_worker_deescalate(ngx_log_t *log)
{
    const char    *acct;
    struct passwd *pw;
    uid_t          tgt_uid;
    gid_t          tgt_gid;
    int            defaulted;

    /* Only real workers de-escalate. The master must stay privileged (bind
     * privileged ports, fork the map-mode broker); single-process (dev) mode
     * doubles as the master, so leave it alone too. */
    if (ngx_process != NGX_PROCESS_WORKER) {
        return NGX_OK;
    }

    defaulted = (brix_worker_user[0] == '\0');
    acct = defaulted ? "nobody" : brix_worker_user;

    errno = 0;
    pw = getpwnam(acct);
    if (pw == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, errno,
            "brix_worker_user: account \"%s\" not found — refusing to serve "
            "(set brix_worker_user to an existing unprivileged account)", acct);
        return NGX_ERROR;
    }
    if (pw->pw_uid == 0 || pw->pw_gid == 0) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
            "brix_worker_user: \"%s\" is a uid/gid 0 account — refusing to serve "
            "(the worker must run as a confined, non-root account)", acct);
        return NGX_ERROR;
    }
    tgt_uid = pw->pw_uid;
    tgt_gid = pw->pw_gid;

    /* Already the confined target (e.g. nginx `user` already dropped us): done. */
    if (getuid() == tgt_uid && geteuid() == tgt_uid) {
        return NGX_OK;
    }

    if (geteuid() == 0 || brix_imp_cap_held(CAP_SETUID)) {
        /* We have the means to change uid — force the drop, fail closed. */
        if (setgroups(1, &tgt_gid) != 0
            || setgid(tgt_gid) != 0
            || setuid(tgt_uid) != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                "brix_worker_user: FAILED to drop worker to \"%s\" — refusing to "
                "serve (pre-auth parsing must never run as a root-capable "
                "identity)", acct);
            return NGX_ERROR;
        }
        if (getuid() != tgt_uid || geteuid() != tgt_uid) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                "brix_worker_user: privilege drop to \"%s\" did not stick — "
                "refusing to serve", acct);
            return NGX_ERROR;
        }
        /* Now unprivileged — strip the SETUID/SETGID we retained for the drop. */
        brix_imp_worker_harden(log);
        if (defaulted) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "brix_worker_user not set: dropped a root-capable worker to "
                "\"nobody\" (uid=%d) so pre-auth credential parsing never runs as "
                "a root-capable identity — set brix_worker_user to a dedicated "
                "confined account instead", (int) tgt_uid);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "brix_worker_user: worker dropped to \"%s\" (uid=%d); pre-auth "
                "parsing runs unprivileged", acct, (int) tgt_uid);
        }
        return NGX_OK;
    }

    /* Cannot change uid (plain non-root, no CAP_SETUID). NO_NEW_PRIVS already
     * blocks the setuid-binary/sudo escalation path for this worker. Refuse only
     * if an escalation capability somehow survived the harden; otherwise serve,
     * warning that the account itself must be sudo-free. */
    if (brix_imp_cap_held(CAP_SETUID) || brix_imp_cap_held(CAP_SETGID)
        || brix_imp_cap_held(CAP_DAC_OVERRIDE) || brix_imp_cap_held(CAP_SYS_ADMIN))
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
            "worker runs as uid=%d and still holds escalation capabilities that "
            "could not be dropped — refusing to serve", (int) geteuid());
        return NGX_ERROR;
    }
    if (!defaulted) {
        /* Operator explicitly named a confined account but the worker is neither
         * it nor able to drop to it — a real misconfiguration worth a warning. */
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "brix_worker_user \"%s\" requested but the worker runs as uid=%d and "
            "holds no CAP_SETUID to drop — run nginx as root (brix will drop) or "
            "start it directly as \"%s\"", brix_worker_user, (int) geteuid(),
            brix_worker_user);
        return NGX_OK;
    }
    /* Plain unprivileged worker (the normal rootless posture): non-root, no caps,
     * NO_NEW_PRIVS set — not root-capable via its own exec chain, so serve quietly.
     * INFO (not WARN) records it without cluttering a steady-state log; the residual
     * to mind is only the account's own sudo/home persistence, a deploy-hygiene note
     * brix cannot act on from here. */
    ngx_log_error(NGX_LOG_INFO, log, 0,
        "worker runs unprivileged as uid=%d (no CAP_SETUID; NO_NEW_PRIVS set); "
        "pre-auth parsing is unprivileged. For defense in depth ensure this account "
        "has no passwordless sudo", (int) geteuid());
    return NGX_OK;
}

ngx_int_t
brix_imp_init_worker(ngx_cycle_t *cycle)
{
    char sockbuf[256];

    /* Cap-drop is now done earlier + unconditionally via brix_imp_worker_harden()
     * (called before the stream-config early-return in ngx_stream_brix_init_process
     * so HTTP-only workers are covered too). */
    if (imp_settings.mode != BRIX_IMP_MAP) {
        return NGX_OK;                    /* off/single: no broker client */
    }

    ngx_snprintf((u_char *) sockbuf, sizeof(sockbuf), "%V%Z",
                 &imp_settings.socket);

    if (brix_imp_client_connect(sockbuf, cycle->log) != NGX_OK) {
        /* Broker may still be starting; the client retries lazily per op. */
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "impersonate: broker not reachable yet at \"%s\" "
                      "(will reconnect on first op)", sockbuf);
    }
    return NGX_OK;
}


/* Best principal string for impersonation: DN first, then token subject. */
static const char *
imp_principal_of(const brix_identity_t *id)
{
    const char *p = brix_identity_dn_cstr(id);

    if (p != NULL && p[0] != '\0') {
        return p;
    }
    p = brix_identity_subject_cstr(id);
    return (p != NULL && p[0] != '\0') ? p : NULL;
}

void
brix_imp_request_begin(const brix_identity_t *id)
{
    if (imp_settings.mode != BRIX_IMP_MAP) {
        return;
    }
    /* Mark the request active BEFORE setting the principal: even if the identity
     * yields no mappable principal (empty subject), confined ops must route to the
     * broker (which denies) rather than fall back to the worker. */
    brix_imp_mark_in_request(1);
    brix_imp_set_principal(id != NULL ? imp_principal_of(id) : NULL);
}

void
brix_imp_request_end(void)
{
    if (imp_settings.mode != BRIX_IMP_MAP) {
        return;
    }
    brix_imp_clear_principal();
    brix_imp_mark_in_request(0);
}
