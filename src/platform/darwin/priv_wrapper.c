/*
 * src/platform/darwin/priv_wrapper.c - darwin identity and privilege calls
 *
 * WHAT: setresuid/setresgid, getresuid/getresgid, prctl, capget/capset,
 *       secure_getenv and crypt declared
 *       in platform_api_posix.h.
 * WHY:  Module-only (crypt needs libcrypt on glibc; the impersonation broker
 *       is the caller), kept apart from the libc-only process_wrapper.c the
 *       native client links.
 * HOW:  Thin wrappers; where the host has no counterpart the gap is stated in
 *       the host README rather than hidden in a caller.
 */

#include "../platform.h"
#include "../platform_api.h"

#if BRIX_PLATFORM_DARWIN

#include <errno.h>
#include <sandbox.h>
#include <stdlib.h>
#include <unistd.h>

/* WHAT: Refuse unsupported process-descriptor ownership.
 * WHY: A numeric pid is not an equivalent lifetime capability.
 * HOW: Return ENOTSUP instead of silently substituting fork. */
pid_t brix_plat_broker_fork(int *process_fd)
{ (void) process_fd; errno = ENOTSUP; return -1; }

/* WHAT: Refuse the fixed-identity Capsicum helper boundary.
 * WHY: Seatbelt/uid transitions do not implement this native contract.
 * HOW: Return ENOTSUP; no success-shaped emulation is permitted. */
int brix_plat_broker_confine(int channel, int rootfd, int logfd)
{ (void) channel; (void) rootfd; (void) logfd; errno = ENOTSUP; return -1; }

/* Darwin exposes no authoritative getres* interface.  Refuse these Linux
 * contracts instead of fabricating a saved ID that may still be privileged. */
int
brix_plat_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    (void) ruid; (void) euid; (void) suid;
    errno = ENOTSUP;
    return -1;
}

int
brix_plat_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
    (void) rgid; (void) egid; (void) sgid;
    errno = ENOTSUP;
    return -1;
}

int
brix_plat_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
    (void) ruid; (void) euid; (void) suid;
    errno = ENOTSUP;
    return -1;
}

int
brix_plat_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
    (void) rgid; (void) egid; (void) sgid;
    errno = ENOTSUP;
    return -1;
}

int
brix_plat_process_tainted(void)
{
    return issetugid() != 0;
}

int
brix_plat_prctl(int option, unsigned long arg)
{
    char *error = NULL;
    int   rc;
    static const char no_exec_profile[] =
        "(version 1)\n"
        "(allow default)\n"
        "(deny process-exec)\n";

    if (option != PR_SET_NO_NEW_PRIVS || arg != 1) {
        errno = ENOTSUP;
        return -1;
    }
    /* Darwin has no Linux NNP bit. A sandbox profile which forbids every
     * subsequent exec blocks both set-id helpers and sudo after parsing. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    rc = sandbox_init(no_exec_profile, 0, &error);
    if (error != NULL) {
        sandbox_free_error(error);
    }
#pragma clang diagnostic pop
    if (rc != 0 && errno == 0) {
        errno = EPERM;
    }
    return rc;
}

int
brix_plat_capget(struct __user_cap_header_struct *hdr,
    struct __user_cap_data_struct *data)
{
    (void) hdr; (void) data;
    errno = ENOSYS;
    return -1;
}

int
brix_plat_capset(struct __user_cap_header_struct *hdr,
    struct __user_cap_data_struct *data)
{
    (void) hdr; (void) data;
    errno = ENOSYS;
    return -1;
}

const char *
brix_plat_secure_getenv(const char *name)
{
    return issetugid() ? NULL : getenv(name);
}

char *
brix_plat_crypt(const char *key, const char *setting)
{
    return crypt(key, setting);
}

#endif /* BRIX_PLATFORM_DARWIN */
