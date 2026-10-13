/*
 * Standalone object units exercise code paths unrelated to nginx logging.
 * BRIX_LOG is header-only, so merely linking one such production object also
 * inherits ngx_vslprintf/ngx_snprintf even when the unit's ngx_log_t is NULL.
 * Keep that incidental dependency inert.  The definitions are weak: a unit
 * that deliberately links nginx's string kernel still tests the real formatter.
 */
#include <stdarg.h>
#include <stddef.h>

typedef unsigned char u_char;

__attribute__((weak)) u_char *
ngx_vslprintf(u_char *buffer, u_char *last, const char *format,
    va_list arguments)
{
    (void) last;
    (void) format;
    (void) arguments;
    return buffer;
}

__attribute__((weak)) u_char *
ngx_snprintf(u_char *buffer, size_t maximum, const char *format, ...)
{
    (void) maximum;
    (void) format;
    return buffer;
}
