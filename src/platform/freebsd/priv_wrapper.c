/* Native FreeBSD identity and no-new-privileges operations; no Linux emulation. */
#include "../platform_api.h"
#include <sys/procctl.h>
#include <sys/procdesc.h>
#include <sys/capsicum.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>

/* WHAT: Set all uid slots. WHY: Make privilege loss irreversible.
 * HOW: Delegate to the native saved-ID interface. */
int brix_plat_setresuid(uid_t real, uid_t effective, uid_t saved)
{ return setresuid(real, effective, saved); }

/* WHAT: Set all gid slots. WHY: Make privilege loss irreversible.
 * HOW: Delegate to the native saved-ID interface. */
int brix_plat_setresgid(gid_t real, gid_t effective, gid_t saved)
{ return setresgid(real, effective, saved); }

/* WHAT: Read all uid slots. WHY: Verify actual, not assumed, privilege loss.
 * HOW: Use native getresuid. */
int brix_plat_getresuid(uid_t *real, uid_t *effective, uid_t *saved)
{ return getresuid(real, effective, saved); }

/* WHAT: Read all gid slots. WHY: Verify actual, not assumed, privilege loss.
 * HOW: Use native getresgid. */
int brix_plat_getresgid(gid_t *real, gid_t *effective, gid_t *saved)
{ return getresgid(real, effective, saved); }

/* WHAT: Report set-id process state. WHY: Do not trust an inherited environment.
 * HOW: Use FreeBSD's authoritative taint predicate. */
int brix_plat_process_tainted(void) { return issetugid() != 0; }

/* WHAT: Enforce/query native no-new-privileges, refusing every other request.
 * WHY: Successful no-op prctl emulation would falsely attest confinement.
 * HOW: Map the two supported operations to procctl and propagate errors. */
int
brix_plat_prctl(int operation, unsigned long argument)
{
    int value;

    if (operation == PR_SET_NO_NEW_PRIVS && argument == 1) {
        value = PROC_NO_NEW_PRIVS_ENABLE;
        return procctl(P_PID, 0, PROC_NO_NEW_PRIVS_CTL, &value);
    }
    if (operation == PR_GET_NO_NEW_PRIVS) {
        if (procctl(P_PID, 0, PROC_NO_NEW_PRIVS_STATUS, &value) != 0) {
            return -1;
        }
        return value == PROC_NO_NEW_PRIVS_ENABLE;
    }
    errno = ENOTSUP;
    return -1;
}

/* WHAT: Refuse Linux capability reads. WHY: Capsicum is not Linux capabilities.
 * HOW: Return an explicit unsupported error, never fabricated zero state. */
int brix_plat_capget(struct __user_cap_header_struct *header,
                    struct __user_cap_data_struct *data)
{ (void) header; (void) data; errno = ENOTSUP; return -1; }

/* WHAT: Refuse Linux capability writes. WHY: Never pretend a privilege drop.
 * HOW: Return an explicit unsupported error. */
int brix_plat_capset(struct __user_cap_header_struct *header,
                    struct __user_cap_data_struct *data)
{ (void) header; (void) data; errno = ENOTSUP; return -1; }

/* WHAT: Fork with an owned, close-on-exec process descriptor.
 * WHY: A non-root supervisor must terminate its differently-owned helpers
 * without root, numeric-pid races or a daemon surviving supervisor failure.
 * HOW: Use pdfork without PD_DAEMON, retaining terminate-on-last-close. */
pid_t
brix_plat_broker_fork(int *process_fd)
{
    return pdfork(process_fd, PD_CLOEXEC);
}

/* WHAT: Remove executable, ioctl and namespace authority from one descriptor.
 * WHY: Inherited descriptor rights must not undermine capability confinement.
 * HOW: Install exactly the supplied rights and deny every ioctl/fcntl command. */
static int
broker_limit_fd(int fd, const cap_rights_t *rights, uint32_t fcntls)
{
    if (cap_rights_limit(fd, rights) != 0
        || cap_ioctls_limit(fd, NULL, 0) != 0
        || cap_fcntls_limit(fd, fcntls) != 0)
    {
        return -1;
    }
    return 0;
}

/* WHAT: Verify a fixed non-root identity and distinct private descriptors.
 * WHY: No saved root slot may survive into the helper sandbox.
 * HOW: Read back all uid slots and fail closed on root or partial drops. */
static int
broker_fixed_identity(int channel, int rootfd)
{
    uid_t real, effective, saved;
    gid_t real_gid, effective_gid, saved_gid;

    if (getresuid(&real, &effective, &saved) != 0
        || getresgid(&real_gid, &effective_gid, &saved_gid) != 0)
    {
        return -1;
    }
    if (real == 0 || real != effective || real != saved
        || real_gid == 0 || real_gid != effective_gid || real_gid != saved_gid
        || channel < 3 || rootfd < 3 || channel == rootfd)
    {
        errno = EPERM;
        return -1;
    }
    return 0;
}

/* WHAT: Prevent a same-uid process from tracing inherited master memory.
 * WHY: A fixed helper inherits sensitive pre-fork state despite dropping uid.
 * HOW: Disable tracing persistently and verify the kernel's reported status. */
static int
broker_disable_trace(void)
{
    int setting = PROC_TRACE_CTL_DISABLE_EXEC;
    int status = 0;

    if (procctl(P_PID, 0, PROC_TRACE_CTL, &setting) != 0
        || procctl(P_PID, 0, PROC_TRACE_STATUS, &status) != 0)
    {
        return -1;
    }
    if (status != -1) { errno = EPERM; return -1; }
    return 0;
}

/* WHAT: Restrict helper IPC, stdio and optional logging descriptors.
 * WHY: They carry bytes only, never ioctl, exec or new network authority.
 * HOW: Apply the bounded rights sets through the common limit helper. */
static int
broker_limit_channels(int channel, int rootfd, int logfd)
{
    cap_rights_t rights;

    cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_FSTAT);
    if (broker_limit_fd(channel, &rights, 0) != 0) {
        return -1;
    }
    cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_FSTAT);
    for (int fd = 0; fd <= 2; fd++) {
        if (broker_limit_fd(fd, &rights, 0) != 0) {
            return -1;
        }
    }
    if (logfd > 2 && logfd != channel && logfd != rootfd) {
        cap_rights_init(&rights, CAP_WRITE, CAP_FSTAT);
        if (broker_limit_fd(logfd, &rights, 0) != 0) {
            return -1;
        }
    }
    return 0;
}

/* WHAT: Seal a fixed-identity helper into descriptor-only capability mode.
 * WHY: It must neither regain root nor reach ambient paths, exec or devices.
 * HOW: Verify identity, restrict descriptor rights, then enter and read back
 * the irreversible native capability-mode flag. */
int
brix_plat_broker_confine(int channel, int rootfd, int logfd)
{
    cap_rights_t rights;
    unsigned mode = 0;

    if (broker_fixed_identity(channel, rootfd) != 0
        || broker_disable_trace() != 0
        || broker_limit_channels(channel, rootfd, logfd) != 0)
    {
        return -1;
    }
    cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_SEEK, CAP_FSYNC, CAP_FLOCK,
        CAP_FCNTL,
        CAP_FTRUNCATE, CAP_LOOKUP, CAP_CREATE, CAP_FSTATAT, CAP_FSTATFS,
        CAP_FCHMODAT, CAP_FCHOWNAT, CAP_FUTIMESAT, CAP_LINKAT_SOURCE,
        CAP_LINKAT_TARGET, CAP_MKDIRAT, CAP_UNLINKAT, CAP_RENAMEAT_SOURCE,
        CAP_RENAMEAT_TARGET, CAP_SYMLINKAT, CAP_EXTATTR_GET,
        CAP_EXTATTR_SET, CAP_EXTATTR_DELETE, CAP_EXTATTR_LIST);
    if (broker_limit_fd(rootfd, &rights, CAP_FCNTL_GETFL | CAP_FCNTL_SETFL) != 0
        || cap_enter() != 0
        || cap_getmode(&mode) != 0)
    {
        return -1;
    }
    if (mode == 0) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

/* WHAT: Read an environment variable only for an untainted process.
 * WHY: Set-id programs cannot trust inherited configuration. HOW: Check first. */
const char *brix_plat_secure_getenv(const char *name)
{ return issetugid() ? NULL : getenv(name); }

/* WHAT: Hash using the host crypt provider. WHY: Preserve password policy.
 * HOW: Delegate without changing salt or algorithm selection. */
char *brix_plat_crypt(const char *key, const char *setting)
{ return crypt(key, setting); }
