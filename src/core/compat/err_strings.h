/*
 * err_strings.h — canonical error message strings for common errnos.
 *
 * brix_kxr_err_string(err) returns the lowercase message string that
 * conformance tests assert for each errno.  strerror(EACCES) returns
 * "Permission denied" (capital P) on Linux; centralising here prevents
 * any future case or format drift across handlers.
 */
#ifndef BRIX_COMPAT_ERR_STRINGS_H
#define BRIX_COMPAT_ERR_STRINGS_H
#include <errno.h>
#include <string.h>

static inline const char *
brix_kxr_err_string(int err)
{
    switch (err) {
    case EACCES: /* fall through */
    case EPERM:  return "permission denied";
    case ENOENT: return "no such file or directory";
    case ENOTDIR:return "not a directory";
    case EISDIR: return "is a directory";
    case ENOSPC: return "no space left on device";
    case EEXIST: return "already exists";
    case ENOMEM: return "out of memory";
    default:     return strerror(err);
    }
}

#endif /* BRIX_COMPAT_ERR_STRINGS_H */
