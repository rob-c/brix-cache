/*
 * snprintf_check.h — truncation-checked formatted write into a fixed buffer.
 *
 * WHAT: a thin wrapper over vsnprintf that returns whether the *entire* formatted
 *       string fit, instead of silently truncating. The buffer is always
 *       NUL-terminated (when cap > 0) so the result is safe to hand to C string
 *       APIs even on the failure path.
 *
 * WHY: bare `snprintf(buf, cap, ...)` discards its return value, so a too-long
 *      result is truncated without a trace. That is harmless for numeric/label
 *      formatting, but dangerous when the buffer is a *filesystem path*: a
 *      truncated path names a different (or parent) object, so the subsequent
 *      open/rename/unlink acts on the wrong target. This helper turns that into a
 *      checkable error at the callsite — the path-building analogue of the
 *      bounded-copy guarantee ngx_cpystrn already gives for plain copies.
 *
 * HOW: pure C (no nginx, no libc beyond <stdarg.h>/<stdio.h>) so it is usable in
 *      the ngx-free storage backends too. `__attribute__((format(printf, 3, 4)))`
 *      lets the compiler check fmt/arg agreement at every callsite.
 */
#ifndef XROOTD_COMPAT_SNPRINTF_CHECK_H
#define XROOTD_COMPAT_SNPRINTF_CHECK_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

/*
 * Format into buf[cap]. Returns 1 if the whole string fit (buf holds the complete
 * NUL-terminated result), 0 on truncation or encoding error. When cap > 0 buf is
 * always NUL-terminated; a NULL buf or cap == 0 returns 0 without writing.
 */
static inline int
xrootd_snprintf_ok(char *buf, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4), warn_unused_result));

static inline int
xrootd_snprintf_ok(char *buf, size_t cap, const char *fmt, ...)
{
    va_list ap;
    int     n;

    if (buf == NULL || cap == 0) {
        return 0;
    }

    va_start(ap, fmt);
    n = vsnprintf(buf, cap, fmt, ap);
    va_end(ap);

    return (n >= 0 && (size_t) n < cap);
}

#endif /* XROOTD_COMPAT_SNPRINTF_CHECK_H */
