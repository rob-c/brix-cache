/*
 * log_stdio.h — standalone client/tool diagnostic adapter (libc only).
 * WHAT: Emit one bounded structured diagnostic to an explicit stream.
 * WHY: Command results belong on stdout; operational diagnostics need consistent
 * severity, source and event fields without depending on nginx or global state.
 * HOW: Header-only formatting and one stdio write preserve library link closure.
 */
#pragma once

#include "log_fields.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

typedef struct {
    const char *role;
    const char *source;
    const char *event;
} brix_stdio_log_site_t;

/*
 * WHAT: Emit a printf-formatted message as one structured record; return the
 * stdio result, preserving the caller's errno even on a logging failure.
 * WHY: Failed operations must retain their original errno and untrusted text
 * must not insert forged records. Logging cannot change the operation outcome.
 * HOW: 1. Format bounded text. 2. Trim its final newline and escape fields.
 * 3. Write timestamp/severity/context/message atomically through stdio.
 */
static inline int
brix_stdio_log(FILE *stream, const char *level, brix_stdio_log_site_t site,
    const char *format, ...) __attribute__((format(printf, 4, 5)));

static inline int
brix_stdio_log(FILE *stream, const char *level, brix_stdio_log_site_t site,
    const char *format, ...)
{
    char message[1024];
    char escaped[4096];
    char source[192];
    char event[128];
    va_list arguments;
    int saved_errno = errno;
    int length;
    int result;
    size_t bounded;
    size_t consumed;

    va_start(arguments, format);
    length = vsnprintf(message, sizeof(message), format, arguments);
    va_end(arguments);
    bounded = length < 0 ? 0 : (size_t) length;
    if (bounded >= sizeof(message)) {
        bounded = sizeof(message) - 1;
    }
    if (bounded > 0 && message[bounded - 1] == '\n') {
        bounded--;
    }
    consumed = brix_log_quote(message, bounded, escaped, sizeof(escaped));
    brix_log_quote(brix_log_source(site.source),
        strlen(brix_log_source(site.source)), source, sizeof(source));
    brix_log_quote(site.event, strlen(site.event), event, sizeof(event));
    result = fprintf(stream,
        "timestamp=%lld level=%s service=brix role=%s source=\"%s\" "
        "event=\"%s\" message=\"%s\" truncated=%d\n",
        (long long) time(NULL), level, site.role, source, event, escaped,
        length < 0 || (size_t) length >= sizeof(message) || consumed < bounded);
    errno = saved_errno;
    return result;
}

#define BRIX_STDIO_LOG(stream, level, role, ...)                           \
    brix_stdio_log(stream, level,                                        \
        (brix_stdio_log_site_t) { role, __FILE__, __func__ }, __VA_ARGS__)
#define BRIX_CLIENT_LOG(level, ...)                                      \
    BRIX_STDIO_LOG(stderr, level, "client", __VA_ARGS__)
#define BRIX_TOOL_LOG(level, ...)                                        \
    BRIX_STDIO_LOG(stderr, level, "tool", __VA_ARGS__)
