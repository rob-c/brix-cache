/* Linux-shaped user xattrs over FreeBSD extattr; native namespace ownership. */
#include "../platform_api.h"
#include <stdlib.h>
#include <string.h>

/* WHAT: Return a native user-namespace name or NULL/errno.
 * WHY: Never reinterpret security/system attributes as user-owned metadata.
 * HOW: Require a nonempty user. prefix and the portable total-name bound. */
static const char *freebsd_xattr_name(const char *name)
{
    if (name == NULL || strncmp(name, "user.", 5) != 0 || name[5] == '\0') {
        errno = EOPNOTSUPP; return NULL;
    }
    if (strlen(name) > BRIX_XATTR_NAME_MAX) { errno = ENAMETOOLONG; return NULL; }
    return name + 5;
}

/* WHAT: Refuse unsupported atomic create/replace requests.
 * WHY: extattr_set has no atomic conditional-update flag; a stat-then-set race
 * must not be advertised as atomic. HOW: Accept zero only, reject unknown bits. */
static int freebsd_xattr_flags(int flags)
{
    if (flags == 0) { return 0; }
    errno = (flags & ~(XATTR_CREATE | XATTR_REPLACE)) ? EINVAL : ENOTSUP;
    return -1;
}

/* WHAT: Read a path attribute or return required size/ERANGE.
 * WHY: Native extattr may truncate reads; the PAL must expose undersized buffers.
 * HOW: Query size first and verify a value read still matches its native size. */
ssize_t brix_freebsd_getxattr(const char *path, const char *name, void *value,
                            size_t capacity, int nofollow)
{
    const char *native = freebsd_xattr_name(name);
    ssize_t required, count, current;

    if (native == NULL) { return -1; }
    required = nofollow ? extattr_get_link(path, EXTATTR_NAMESPACE_USER, native, NULL, 0)
                        : extattr_get_file(path, EXTATTR_NAMESPACE_USER, native, NULL, 0);
    if (required < 0 || capacity == 0) { return required; }
    if (value == NULL) { errno = EINVAL; return -1; }
    if ((size_t) required > capacity) { errno = ERANGE; return -1; }
    count = nofollow ? extattr_get_link(path, EXTATTR_NAMESPACE_USER, native, value, capacity)
                     : extattr_get_file(path, EXTATTR_NAMESPACE_USER, native, value, capacity);
    if (count < 0) { return -1; }
    current = nofollow ? extattr_get_link(path, EXTATTR_NAMESPACE_USER, native, NULL, 0)
                       : extattr_get_file(path, EXTATTR_NAMESPACE_USER, native, NULL, 0);
    if (current != count) { errno = ERANGE; return -1; }
    return count;
}

/* WHAT: Read an fd attribute without accepting silent truncation.
 * WHY: Handle metadata remains bound to the open inode. HOW: Check native sizes. */
ssize_t brix_freebsd_fgetxattr(int descriptor, const char *name, void *value, size_t capacity)
{
    const char *native = freebsd_xattr_name(name);
    ssize_t required, count;
    if (native == NULL) { return -1; }
    required = extattr_get_fd(descriptor, EXTATTR_NAMESPACE_USER, native, NULL, 0);
    if (required < 0 || capacity == 0) { return required; }
    if (value == NULL) { errno = EINVAL; return -1; }
    if ((size_t) required > capacity) { errno = ERANGE; return -1; }
    count = extattr_get_fd(descriptor, EXTATTR_NAMESPACE_USER, native, value, capacity);
    if (count < 0) { return -1; }
    if (extattr_get_fd(descriptor, EXTATTR_NAMESPACE_USER, native, NULL, 0) != count) {
        errno = ERANGE; return -1;
    }
    return count;
}

/* WHAT: Set a user attribute, returning Linux's zero-on-success result.
 * WHY: Native extattr returns the byte count, not zero. HOW: Normalize exactly. */
int brix_freebsd_setxattr(const char *path, const char *name, const void *value,
                        size_t length, int flags, int nofollow)
{
    const char *native = freebsd_xattr_name(name);
    ssize_t count;
    if (native == NULL || freebsd_xattr_flags(flags) != 0) { return -1; }
    count = nofollow ? extattr_set_link(path, EXTATTR_NAMESPACE_USER, native, value, length)
                     : extattr_set_file(path, EXTATTR_NAMESPACE_USER, native, value, length);
    if (count < 0) { return -1; }
    if ((size_t) count != length) { errno = EIO; return -1; }
    return 0;
}

/* WHAT: Set an fd attribute with explicit conditional-update refusal.
 * WHY: Never fall back to a pathname for handle-bound metadata.
 * HOW: Use the native fd verb and normalize its byte-count result. */
int brix_freebsd_fsetxattr(int descriptor, const char *name, const void *value,
                         size_t length, int flags)
{
    const char *native = freebsd_xattr_name(name);
    ssize_t count;
    if (native == NULL || freebsd_xattr_flags(flags) != 0) { return -1; }
    count = extattr_set_fd(descriptor, EXTATTR_NAMESPACE_USER, native, value, length);
    if (count < 0) { return -1; }
    if ((size_t) count != length) { errno = EIO; return -1; }
    return 0;
}

/* WHAT: Convert length-prefixed native names to NUL-separated user. names.
 * WHY: Linux listxattr uses a different wire layout; no name may overrun output.
 * HOW: Validate every native extent, calculate full size, then copy only if fit. */
static ssize_t freebsd_xattr_names(const unsigned char *native, size_t length,
                                  char *output, size_t capacity)
{
    size_t cursor = 0, total = 0;
    while (cursor < length) {
        size_t count = native[cursor++];
        if (count == 0 || count > length - cursor || memchr(native + cursor, 0, count)) {
            errno = EIO; return -1;
        }
        if (capacity != 0 && (total > capacity || count + 6 > capacity - total)) {
            errno = ERANGE; return -1;
        }
        if (capacity != 0) {
            if (output == NULL) { errno = EINVAL; return -1; }
            memcpy(output + total, "user.", 5);
            memcpy(output + total + 5, native + cursor, count);
            output[total + count + 5] = '\0';
        }
        total += count + 6;
        cursor += count;
    }
    return (ssize_t) total;
}

/* WHAT: Read or size the native list using one explicit target kind.
 * WHY: Every phase must use the same fd/link/file operation.
 * HOW: Select fd first, otherwise honor the caller's nofollow policy. */
static ssize_t
freebsd_xattr_list_read(const char *path, int descriptor, int nofollow,
                       void *buffer, size_t capacity)
{
    if (path == NULL) {
        return extattr_list_fd(descriptor, EXTATTR_NAMESPACE_USER, buffer, capacity);
    }
    if (nofollow) {
        return extattr_list_link(path, EXTATTR_NAMESPACE_USER, buffer, capacity);
    }
    return extattr_list_file(path, EXTATTR_NAMESPACE_USER, buffer, capacity);
}

/* WHAT: Read one native length-prefixed name list into bounded owned storage.
 * WHY: Conversion requires native content even for a Linux size-only query.
 * HOW: Query, bound to 1 MiB, allocate, fetch and return actual content length. */
static unsigned char *freebsd_xattr_list(const char *path, int descriptor,
                                        int nofollow, ssize_t *length)
{
    unsigned char *buffer;
    size_t capacity;
    ssize_t current;

    *length = freebsd_xattr_list_read(path, descriptor, nofollow, NULL, 0);
    if (*length < 0) { return NULL; }
    if (*length > 1024 * 1024) { errno = E2BIG; return NULL; }
    capacity = (size_t) *length;
    buffer = malloc(capacity + 1);
    if (buffer == NULL) { return NULL; }
    /* A zero-capacity call is another size query, not a fetch. Return the
     * observed empty snapshot instead of decoding a later size as data. */
    if (capacity == 0) { return buffer; }
    *length = freebsd_xattr_list_read(path, descriptor, nofollow, buffer, capacity);
    if (*length < 0) { free(buffer); return NULL; }
    current = freebsd_xattr_list_read(path, descriptor, nofollow, NULL, 0);
    if ((size_t) *length > capacity || current != *length) {
        free(buffer); errno = ERANGE; return NULL;
    }
    return buffer;
}

/* WHAT: Return Linux-shaped names for a native pathname.
 * WHY: Preserve user namespace and Linux sizing semantics. HOW: Fetch/convert/free. */
ssize_t brix_freebsd_listxattr(const char *path, char *output, size_t capacity, int nofollow)
{
    ssize_t length, result;
    unsigned char *buffer = freebsd_xattr_list(path, -1, nofollow, &length);
    if (buffer == NULL) { return -1; }
    result = freebsd_xattr_names(buffer, (size_t) length, output, capacity);
    free(buffer);
    return result;
}

/* WHAT: Return Linux-shaped names bound to an open descriptor.
 * WHY: Never re-resolve an fd's pathname. HOW: Fetch/convert/free the native list. */
ssize_t brix_freebsd_flistxattr(int descriptor, char *output, size_t capacity)
{
    ssize_t length, result;
    unsigned char *buffer = freebsd_xattr_list(NULL, descriptor, 0, &length);
    if (buffer == NULL) { return -1; }
    result = freebsd_xattr_names(buffer, (size_t) length, output, capacity);
    free(buffer);
    return result;
}

/* WHAT: Remove exactly one native user attribute. WHY: Preserve the namespace
 * boundary. HOW: Validate and select link/file semantics without fallback. */
int brix_freebsd_removexattr(const char *path, const char *name, int nofollow)
{
    const char *native = freebsd_xattr_name(name);
    if (native == NULL) { return -1; }
    return nofollow ? extattr_delete_link(path, EXTATTR_NAMESPACE_USER, native)
                    : extattr_delete_file(path, EXTATTR_NAMESPACE_USER, native);
}

/* WHAT: Remove one fd-bound attribute. WHY: Keep handle metadata inode-bound.
 * HOW: Validate namespace and delegate to the native fd operation. */
int brix_freebsd_fremovexattr(int descriptor, const char *name)
{
    const char *native = freebsd_xattr_name(name);
    if (native == NULL) { return -1; }
    return extattr_delete_fd(descriptor, EXTATTR_NAMESPACE_USER, native);
}

/* WHAT: Expose the common PAL get/set/list/remove family. WHY: Keep the ABI
 * independent of the Linux-shaped call aliases. HOW: Delegate to this owner. */
ssize_t brix_plat_getxattr(const char *p, const char *n, void *v, size_t s)
{ return brix_freebsd_getxattr(p, n, v, s, 0); }
ssize_t brix_plat_fgetxattr(int f, const char *n, void *v, size_t s)
{ return brix_freebsd_fgetxattr(f, n, v, s); }
int brix_plat_setxattr(const char *p, const char *n, const void *v, size_t s, int flags)
{ return brix_freebsd_setxattr(p, n, v, s, flags, 0); }
int brix_plat_fsetxattr(int f, const char *n, const void *v, size_t s, int flags)
{ return brix_freebsd_fsetxattr(f, n, v, s, flags); }
int brix_plat_removexattr(const char *p, const char *n)
{ return brix_freebsd_removexattr(p, n, 0); }
int brix_plat_fremovexattr(int f, const char *n)
{ return brix_freebsd_fremovexattr(f, n); }
ssize_t brix_plat_listxattr(const char *p, char *v, size_t s)
{ return brix_freebsd_listxattr(p, v, s, 0); }
ssize_t brix_plat_flistxattr(int f, char *v, size_t s)
{ return brix_freebsd_flistxattr(f, v, s); }
