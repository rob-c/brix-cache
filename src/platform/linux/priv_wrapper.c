/*
 * src/platform/linux/priv_wrapper.c - linux identity and privilege calls
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

/* The glibc feature-test macro these bodies need (setres[ug]id, getres[ug]id, secure_getenv).  Guarded, not
 * bare, because both real builds already pass -D_GNU_SOURCE on the command
 * line (./config for the module, client/Makefile's HARDEN for the client) and
 * an unguarded redefinition is an error under -Werror.  Declared HERE rather
 * than left to the caller so a standalone harness that links one PAL body --
 * every tests/cmdscripts compile line that reaches brix_plat_* -- gets the
 * prototypes too, instead of an implicit declaration and a silent link
 * failure.  It must precede every include, hence its place above them. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../platform.h"
#include "../platform_api.h"

#if BRIX_PLATFORM_LINUX

#include <crypt.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

int
brix_plat_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    return setresuid(ruid, euid, suid);
}

int
brix_plat_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
    return setresgid(rgid, egid, sgid);
}

int
brix_plat_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
    return getresuid(ruid, euid, suid);
}

int
brix_plat_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
    return getresgid(rgid, egid, sgid);
}

int
brix_plat_prctl(int option, unsigned long arg)
{
    return prctl(option, arg, 0, 0, 0);
}

int
brix_plat_capget(struct __user_cap_header_struct *hdr,
    struct __user_cap_data_struct *data)
{
    return (int) syscall(SYS_capget, hdr, data);
}

int
brix_plat_capset(struct __user_cap_header_struct *hdr,
    struct __user_cap_data_struct *data)
{
    return (int) syscall(SYS_capset, hdr, data);
}

const char *
brix_plat_secure_getenv(const char *name)
{
    return secure_getenv(name);
}

char *
brix_plat_crypt(const char *key, const char *setting)
{
    return crypt(key, setting);
}

#endif /* BRIX_PLATFORM_LINUX */
