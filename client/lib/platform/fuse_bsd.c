/*
 * Shared BSD client FUSE lifecycle policy; selected by the client Makefile.
 * Native unmount syscalls and host-specific mount options remain in each host.
 */
#include "platform/platform.h"
#include <errno.h>
#include <string.h>

/* WHAT: Refuse unavailable two-stage idle expiry. WHY: A force unmount is not
 * Linux MNT_EXPIRE. HOW: Preserve the established caller's EPERM contract. */
int
brix_plat_umount_expire(const char *path)
{
    (void) path;
    errno = EPERM;
    return -1;
}

/* WHAT: Return the single native owner-unmount argv tier, or zero when absent.
 * WHY: Neither BSD uses fusermount3 or Linux lazy-detach semantics.
 * HOW: Keep force explicit and always retain the path and NULL terminator. */
int
brix_plat_fuse_umount_argv(const char *path, int force, int tier, char **arguments)
{
    int count = 0;

    if (tier != 0) {
        return 0;
    }
    arguments[count++] = (char *) "umount";
    if (force) {
        arguments[count++] = (char *) "-f";
    }
    arguments[count++] = (char *) path;
    arguments[count] = NULL;
    return count;
}

/* WHAT: Reject missing options and Linux-only auto_unmount.
 * WHY: Do not advertise mount behavior the native FUSE implementation refuses.
 * HOW: Match the complete option name, never a substring or an empty element. */
int
brix_plat_fuse_opt_supported(const char *option)
{
    if (option == NULL || option[0] == '\0') {
        return 0;
    }
    return strcmp(option, "auto_unmount") != 0;
}
