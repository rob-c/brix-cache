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
#include <stdlib.h>
#include <unistd.h>

/* Darwin has no saved-set ids: seteuid/setegid carry the effective id and
 * the real/saved ids read as the real ones (the pre-PAL emulation). */
int
brix_plat_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    (void) ruid; (void) suid;
    return seteuid(euid);
}

int
brix_plat_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
    (void) rgid; (void) sgid;
    return setegid(egid);
}

int
brix_plat_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
    *ruid = getuid();
    *euid = geteuid();
    *suid = getuid();
    return 0;
}

int
brix_plat_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
    *rgid = getgid();
    *egid = getegid();
    *sgid = getgid();
    return 0;
}

int
brix_plat_prctl(int option, unsigned long arg)
{
    (void) option; (void) arg;
    return 0;   /* no prctl on Darwin: documented no-op */
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
