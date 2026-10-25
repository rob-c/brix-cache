/* Fixed-identity helper creation and irreversible credential transitions.
 * The supervisor forks all helpers before shedding root. Native process
 * descriptors own their lifetime; closed descriptors cannot strand daemons.
 * Requires: broker_internal.h and the shared transport/descriptor seal helpers.
 */
#include "broker_internal.h"
#include "broker_fixed.h"
#include "client_internal.h"
#include <sys/time.h>
#include <sys/resource.h>

#if BRIX_HAS_FIXED_ID_BROKER

/* WHAT: Verify every realized uid/gid slot and supplementary group.
 * WHY: Neither a saved root ID nor an inherited group may lend authority.
 * HOW: Read all slots/groups back and require an exact order-independent set. */
static int
fixed_verify_ids(const brix_idmap_creds_t *creds)
{
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    brix_idmap_creds_t realized = *creds;

    if (brix_plat_getresuid(&real_uid, &effective_uid, &saved_uid) != 0
        || brix_plat_getresgid(&real_gid, &effective_gid, &saved_gid) != 0
        || brix_plat_prctl(PR_GET_NO_NEW_PRIVS, 0) != 1)
    {
        return -1;
    }
    if (real_uid != creds->uid || effective_uid != creds->uid
        || saved_uid != creds->uid || real_gid != creds->gid
        || effective_gid != creds->gid || saved_gid != creds->gid)
    {
        errno = EPERM;
        return -1;
    }
    realized.ngroups = getgroups(BRIX_IDMAP_MAXGROUPS, realized.groups);
    if (!brix_imp_fixed_creds_equal(creds, &realized)) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

/* WHAT: Irreversibly become one non-root account, without Linux capabilities.
 * WHY: Request-serving helpers and their supervisor must never retain root.
 * HOW: Set no-new-privileges, groups, all gid/uid slots, then verify the result. */
int
brix_imp_fixed_drop(const brix_idmap_creds_t *creds)
{
    struct rlimit no_core = {0, 0};

    if (creds == NULL || creds->uid == 0 || creds->gid == 0
        || creds->ngroups < 0 || creds->ngroups > BRIX_IDMAP_MAXGROUPS)
    {
        errno = EPERM;
        return -1;
    }
    if (setrlimit(RLIMIT_CORE, &no_core) != 0
        || brix_plat_prctl(PR_SET_NO_NEW_PRIVS, 1) != 0
        || syscall(SYS_setgroups, (size_t) creds->ngroups, creds->groups) != 0
        || brix_plat_setresgid(creds->gid, creds->gid, creds->gid) != 0
        || brix_plat_setresuid(creds->uid, creds->uid, creds->uid) != 0)
    {
        return -1;
    }
    return fixed_verify_ids(creds);
}

/* WHAT: Set bounded native helper transport buffers and waiting time.
 * WHY: One frame/payload must fit, and a dead helper cannot stall every user.
 * HOW: Enlarge both socket buffers and install symmetric 30-second deadlines. */
static int
fixed_channel_options(int channel, int supervisor)
{
    int capacity = 2 * (IMP_XATTR_MAX + sizeof(imp_req_t));
    struct timeval deadline = {30, 0};

    if (setsockopt(channel, SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) != 0
        || setsockopt(channel, SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) != 0
        || setsockopt(channel, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline)) != 0)
    {
        return -1;
    }
    if (supervisor) {
        return setsockopt(channel, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
    }
    return 0; /* a healthy helper may remain idle indefinitely */
}

/* WHAT: Enter the fixed account and sandbox before acknowledging readiness.
 * WHY: The supervisor must never dispatch to an unconfined or root helper.
 * HOW: Seal unrelated descriptors, irreversibly drop, confine, then serve. */
static void
fixed_child(int channel, int rootfd, const brix_idmap_creds_t *creds,
            ngx_log_t *log)
{
    int logfd = log && log->file ? log->file->fd : -1;
    imp_rep_t ready;

    brix_imp_broker_seal_fds(channel, rootfd, log);
    if (brix_imp_fixed_drop(creds) != 0
        || brix_plat_broker_confine(channel, rootfd, logfd) != 0)
    {
        _exit(EXIT_FAILURE);
    }
    ngx_memzero(&ready, sizeof(ready));
    if (imp_send_reply(channel, &ready, -1, NULL, 0) != 0) {
        _exit(EXIT_FAILURE);
    }
    brix_imp_fixed_serve(channel, rootfd, creds, log);
    _exit(0);
}

/* WHAT: Spawn and attest one process-descriptor-owned, fixed-identity helper.
 * WHY: Partial setup must close only its owned child/channel, without pid races.
 * HOW: Create a private record socket, fork, and require post-confinement ACK. */
int
brix_imp_fixed_spawn(int rootfd, const brix_idmap_creds_t *creds,
    int *channel, int *process_fd, ngx_log_t *log)
{
    int pair[2], descriptor = -1, received = -1;
    pid_t child;
    imp_rep_t ready;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0) {
        return -1;
    }
    if (fixed_channel_options(pair[0], 1) != 0
        || fixed_channel_options(pair[1], 0) != 0)
    {
        close(pair[0]);
        close(pair[1]);
        return -1;
    }
    child = brix_plat_broker_fork(&descriptor);
    if (child == 0) {
        fixed_child(pair[1], rootfd, creds, log);
    }
    close(pair[1]);
    if (child < 0) {
        close(pair[0]);
        return -1;
    }
    int status = imp_recv_reply(pair[0], &ready, &received, NULL, 0);
    if (received >= 0) { close(received); }
    if (status != 0 || ready.status != 0 || ready.rep_flags != 0 || received >= 0) {
        close(pair[0]);
        close(descriptor);
        errno = EPERM;
        return -1;
    }
    *channel = pair[0];
    *process_fd = descriptor;
    return 0;
}
#endif
