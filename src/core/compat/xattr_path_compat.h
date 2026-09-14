/* xattr_path_compat.h — libc-only Darwin xattr signature adaptation.
 * Requires: no nginx types. Includes the platform's xattr declarations.
 * Shared by the confined path and metadata-record owners; callers retain
 * confinement and VFS policy checks. Linux uses its native declarations.
 */
#pragma once
#include <sys/types.h>
#include <sys/xattr.h>

/* macOS xattr compatibility - different signatures than Linux */
#if defined(__APPLE__) && defined(__MACH__)
static inline ssize_t brix_getxattr_compat(const char *path, const char *name, void *value, size_t size) {
    return getxattr(path, name, value, size, 0, 0); /* vfs-seam-allow: SEAM_CORRECT - Darwin signature adapter for confined metadata I/O */
}
static inline int brix_setxattr_compat(const char *path, const char *name, const void *value, size_t size, int flags) {
    return setxattr(path, name, value, size, 0, flags); /* vfs-seam-allow: SEAM_CORRECT - Darwin signature adapter for confined metadata I/O */
}
static inline int brix_removexattr_compat(const char *path, const char *name) {
    return removexattr(path, name, 0); /* vfs-seam-allow: SEAM_CORRECT - Darwin signature adapter for confined metadata I/O */
}
static inline ssize_t brix_listxattr_compat(const char *path, char *list, size_t size) {
    return listxattr(path, list, size, 0); /* vfs-seam-allow: SEAM_CORRECT - Darwin signature adapter for confined metadata I/O */
}
#define getxattr(path, name, value, size) brix_getxattr_compat(path, name, value, size)
#define setxattr(path, name, value, size, flags) brix_setxattr_compat(path, name, value, size, flags)
#define removexattr(path, name) brix_removexattr_compat(path, name)
#define listxattr(path, list, size) brix_listxattr_compat(path, list, size)
#endif
