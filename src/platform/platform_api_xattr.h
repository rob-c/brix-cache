/* Extended attribute access.
 * Requires: platform_api.h platform selection and system types before inclusion.
 * Include platform/platform_api.h at call sites.
 */
#pragma once

/* ==========================================================================
 * EXTENDED ATTRIBUTES
 *
 * Cross-platform xattr operations.
 * Note: Windows uses NTFS Alternate Data Streams (ADS).
 * ========================================================================== */

/**
 * Get extended attribute
 *
 * Linux: getxattr(path, name, value, size)
 * macOS: getxattr(path, name, value, size, 0, 0)
 * Windows: NTFS Alternate Data Streams (ADS)
 *
 * Windows Implementation:
 * - Maps xattr names to ADS streams ("user.key" → "file:key")
 * - Uses CreateFileW() with stream name syntax
 * - Reads stream content into value buffer
 * - Returns ENODATA if stream doesn't exist
 *
 * @param path File path
 * @param name Attribute name (e.g., "user.key")
 * @param value Output buffer
 * @param size Buffer size
 * @return Bytes read, or -1 on error
 */
ssize_t brix_plat_getxattr(const char *path, const char *name,
                           void *value, size_t size);

/**
 * Get extended attribute (file descriptor version)
 *
 * Windows Implementation:
 * - Converts fd to HANDLE via _get_osfhandle()
 * - Uses GetFinalPathNameByHandle() to get path
 * - Delegates to brix_plat_getxattr()
 *
 * @param fd File descriptor
 * @param name Attribute name
 * @param value Output buffer
 * @param size Buffer size
 * @return Bytes read, or -1 on error
 */
ssize_t brix_plat_fgetxattr(int fd, const char *name,
                            void *value, size_t size);

/**
 * Set extended attribute
 *
 * Windows Implementation:
 * - Maps xattr names to ADS streams
 * - Uses CreateFileW() with stream name syntax
 * - Writes value to stream
 * - Supports XATTR_CREATE (FAIL_IF_EXISTS)
 * - Supports XATTR_REPLACE (TRUNCATE_EXISTING)
 *
 * @param path File path
 * @param name Attribute name
 * @param value Attribute value
 * @param size Value size
 * @param flags Flags (0, BRIX_XATTR_CREATE, BRIX_XATTR_REPLACE)
 * @return 0 on success, -1 on error
 */
int brix_plat_setxattr(const char *path, const char *name,
                       const void *value, size_t size, int flags);

/**
 * Set extended attribute (file descriptor version)
 *
 * Windows Implementation:
 * - Converts fd to HANDLE via _get_osfhandle()
 * - Uses GetFinalPathNameByHandle() to get path
 * - Delegates to brix_plat_setxattr()
 *
 * @param fd File descriptor
 * @param name Attribute name
 * @param value Attribute value
 * @param size Value size
 * @param flags Flags
 * @return 0 on success, -1 on error
 */
int brix_plat_fsetxattr(int fd, const char *name,
                        const void *value, size_t size, int flags);

/**
 * Remove extended attribute
 *
 * Windows Implementation:
 * - Maps xattr name to ADS stream
 * - Uses DeleteFileW() with stream name syntax
 * - Returns ENODATA if stream doesn't exist
 *
 * @param path File path
 * @param name Attribute name
 * @return 0 on success, -1 on error
 */
int brix_plat_removexattr(const char *path, const char *name);

/**
 * Remove extended attribute (file descriptor version)
 *
 * Windows Implementation:
 * - Converts fd to HANDLE via _get_osfhandle()
 * - Uses GetFinalPathNameByHandle() to get path
 * - Delegates to brix_plat_removexattr()
 *
 * @param fd File descriptor
 * @param name Attribute name
 * @return 0 on success, -1 on error
 */
int brix_plat_fremovexattr(int fd, const char *name);

/**
 * List extended attributes
 *
 * Windows Implementation:
 * - Uses FindFirstStreamW()/FindNextStreamW() to enumerate NTFS ADS streams
 * - Fully implemented for Windows 8+ / Server 2012+
 * - Returns null-separated attribute names
 * - NTFS filesystem required (FAT32/exFAT do not support ADS)
 *
 * Linux Implementation:
 * - Uses lgetxattr() with XATTR_NAME_ALL
 * - Fully implemented
 *
 * macOS Implementation:
 * - Uses getxattr() with XATTR_NOFOLLOW
 * - Fully implemented
 *
 * @param path File path
 * @param list Output buffer (null-separated names)
 * @param size Buffer size
 * @return Bytes written, or -1 on error
 */
ssize_t brix_plat_listxattr(const char *path, char *list, size_t size);

/**
 * List extended attributes (file descriptor version)
 *
 * Windows Implementation:
 * - Converts fd to HANDLE via _get_osfhandle()
 * - Uses GetFinalPathNameByHandleW() to get file path
 * - Delegates to brix_plat_listxattr()
 * - Fully implemented
 *
 * Linux Implementation:
 * - Uses flistxattr()
 * - Fully implemented
 *
 * macOS Implementation:
 * - Uses flistxattr()
 * - Fully implemented
 *
 * @param fd File descriptor
 * @param list Output buffer
 * @param size Buffer size
 * @return Bytes written, or -1 on error
 */
ssize_t brix_plat_flistxattr(int fd, char *list, size_t size);

/** Extended attribute flags */
#define BRIX_XATTR_CREATE       0x0002  /**< Fail if attr exists */
#define BRIX_XATTR_REPLACE      0x0004  /**< Fail if attr doesn't exist */
#define BRIX_XATTR_NOFOLLOW     0x0001  /**< Don't follow symlinks */

/**
 * BRIX_XATTR_NOFOLLOW Platform Support Matrix
 *
 * This flag requests that symlink targets not be followed when setting/getting
 * extended attributes. Support varies by platform:
 *
 * | Platform | Status | Notes |
 * |----------|--------|-------|
 * | Linux | ✅ Supported | Uses AT_SYMLINK_NOFOLLOW with *xattrat() |
 * | macOS | ✅ Supported | Native lgetxattr/lsetxattr APIs |
 * | Windows | ⚠️ NOT IMPLEMENTED | Returns EINVAL if flag set |
 *
 * Windows Limitation:
 * - NTFS ADS operations always follow symlinks by default
 * - Would require FILE_FLAG_OPEN_REPARSE_POINT + CreateFileW()
 * - Complex implementation due to ADS path construction with reparse points
 * - Security implication: Attributes may be set on symlink target, not link
 *
 * Workaround on Windows:
 * - Use GetFileAttributesW() to detect FILE_ATTRIBUTE_REPARSE_POINT
 * - Manually check for symlinks before calling setxattr/getxattr
 * - Or accept that attributes follow symlinks (matches most use cases)
 *
 * Future Enhancement:
 * - Implement symlink detection in Windows xattr wrapper
 * - Return ENOTSUP or EINVAL when flag is set on symlink
 * - See: src/platform/windows/xattr.c for implementation notes
 */
