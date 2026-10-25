/* Private namespace NSS isolation. Requires an already-private mount namespace.
 * Bind-mounted passwd/group fixtures must not query the host's nscd socket:
 * that cache describes the host identities, not this namespace's files.
 */
#pragma once

#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>

/* WHAT: Hide an existing host cache directory in this mount namespace only.
 * WHY: NixOS normally runs nscd; its cached misses otherwise bypass fixtures.
 * HOW: 1. Ignore an absent daemon. 2. Cover its directory with empty tmpfs.
 */
static inline int
brix_test_hide_nscd(const char *path)
{
    struct stat metadata;
    if (stat(path, &metadata) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!S_ISDIR(metadata.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    return mount("tmpfs", path, "tmpfs", MS_RDONLY | MS_NOSUID | MS_NODEV
                 | MS_NOEXEC, "size=4096,mode=0755");
}

/* WHAT: Remove both usual nscd socket spellings from the private fixture view.
 * WHY: Neither stop the host daemon nor change its configuration for tests.
 * HOW: Cover /run/nscd and the legacy /var/run spelling; propagate any error.
 */
static inline int
brix_test_isolate_nscd(void)
{
    if (brix_test_hide_nscd("/run/nscd") != 0) {
        return -1;
    }
    return brix_test_hide_nscd("/var/run/nscd");
}
