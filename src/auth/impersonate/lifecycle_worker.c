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
static void
imp_worker_drop_caps(ngx_log_t *log)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct   data[2];
    /* The dangerous set — always shed from the bounding set (best-effort) and,
     * for a root worker, from permitted+effective. SETUID/SETGID are deliberately
     * NOT here: a root worker retains them so a legitimate later identity drop
     * (the pblock backend's off-root drop, `single`-mode squash) still works.
     * A root worker is uid 0 regardless, so keeping SETUID adds no escalation it
     * does not already have; a non-root worker has no caps to keep. */
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

    if (geteuid() == 0) {
        /* Root worker: reduce permitted+effective to ONLY {SETUID,SETGID},
         * shedding DAC_OVERRIDE/MKNOD/SYS_ADMIN/PTRACE/CHOWN/... — the caps a
         * worker-code exploit would abuse (uid 0 without CAP_DAC_OVERRIDE now
         * respects on-disk DAC). */
        data[0].permitted = data[0].effective =
            (1u << CAP_SETUID) | (1u << CAP_SETGID);
    }
    /* else: non-root worker keeps nothing (data stays zeroed). */

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
