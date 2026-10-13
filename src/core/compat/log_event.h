/*
 * log_event.h — the server diagnostic record template.
 * WHAT: Preserve nginx levels, lazy filtering, errno and config context while
 * emitting bounded source/event/message fields on one line.
 * WHY: All protocol planes need the same machine-readable diagnostic envelope.
 * HOW: Header-only adapters keep standalone native regression link closures
 * unchanged. Requires nginx core and HTTP config types before inclusion.
 */
#pragma once

#include <ngx_config.h>
#include <ngx_core.h>
#include "../../../shared/observability/log_fields.h"

/* A call site's immutable identity; passed by value through the adapters. */
typedef struct {
    const char *source;
    const char *event;
} brix_log_site_t;

/*
 * WHAT: Map nginx severity to the common standalone vocabulary.
 * WHY: Collectors need one level field while nginx retains its native prefix.
 * HOW: Table-free selection; NOTICE is informational, ALERT/EMERG are fatal.
 */
static inline const char *
brix_log_level(ngx_uint_t level)
{
    switch (level) {
    case NGX_LOG_DEBUG: return "DEBUG";
    case NGX_LOG_INFO:
    case NGX_LOG_NOTICE: return "INFO";
    case NGX_LOG_WARN: return "WARN";
    case NGX_LOG_ERR: return "ERROR";
    case NGX_LOG_CRIT: return "CRIT";
    default: return "FATAL";
    }
}

/*
 * WHAT: Format the common diagnostic body into a caller-owned bounded buffer.
 * WHY: nginx formatting (%V, %ui, %uz) must run before byte escaping.
 * HOW: 1. Render the original message. 2. Escape its explicit byte span.
 * 3. Add source/event fields and an explicit truncation flag.
 */
static inline void
brix_log_event_body(char *output, size_t capacity, brix_log_site_t site,
    const char *format, va_list arguments)
{
    u_char message[768];
    char escaped[1024];
    char source[192];
    char event[128];
    u_char *end;
    size_t length;
    size_t consumed;

    if (capacity == 0) {
        return;
    }
    end = ngx_vslprintf(message, message + sizeof(message), format, arguments);
    length = (size_t) (end - message);
    consumed = brix_log_quote((char *) message, length, escaped, sizeof(escaped));
    brix_log_quote(brix_log_source(site.source),
        strlen(brix_log_source(site.source)), source, sizeof(source));
    brix_log_quote(site.event, strlen(site.event), event, sizeof(event));
    end = ngx_snprintf((u_char *) output, capacity - 1,
        "service=brix role=server source=\"%s\" event=\"%s\" "
        "message=\"%s\" truncated=%ui", source, event, escaped,
        (ngx_uint_t) (length == sizeof(message) || consumed < length));
    *end = '\0';
}

/*
 * WHAT: Emit an already-enabled server diagnostic through nginx's error sink.
 * WHY: nginx owns timestamp, severity, PID, connection context and errno text.
 * HOW: 1. Format one body. 2. Call the original nginx macro once.
 */
static inline void
brix_log_event_emit(ngx_uint_t level, ngx_log_t *log, ngx_err_t error,
    brix_log_site_t site, const char *format, ...)
{
    char body[1536];
    va_list arguments;
    int saved_errno = errno;

    va_start(arguments, format);
    brix_log_event_body(body, sizeof(body), site, format, arguments);
    va_end(arguments);
    ngx_log_error(level, log, error, "level=%s %s", brix_log_level(level), body);
    errno = saved_errno;
}

/*
 * WHAT: Emit a configuration diagnostic retaining filename/line context.
 * WHY: An invalid directive must still point operators to its original source.
 * HOW: 1. Format one body. 2. Delegate to ngx_conf_log_error once.
 */
static inline void
brix_log_event_conf(ngx_uint_t level, ngx_conf_t *conf, ngx_err_t error,
    brix_log_site_t site, const char *format, ...)
{
    char body[1536];
    va_list arguments;
    int saved_errno = errno;

    va_start(arguments, format);
    brix_log_event_body(body, sizeof(body), site, format, arguments);
    va_end(arguments);
    ngx_conf_log_error(level, conf, error, "level=%s %s", brix_log_level(level), body);
    errno = saved_errno;
}

#define BRIX_LOG_SITE ((brix_log_site_t) { __FILE__, __func__ })
/* Filter before evaluating format arguments, matching nginx macro semantics. */
#define BRIX_LOG(level, log, error, ...)                                  \
    do {                                                                \
        if ((log) != NULL && (log)->log_level >= (level)) {               \
            brix_log_event_emit(level, log, error, BRIX_LOG_SITE,         \
                                __VA_ARGS__);                           \
        }                                                               \
    } while (0)
#define BRIX_CONF_LOG(level, conf, error, ...)                            \
    brix_log_event_conf(level, conf, error, BRIX_LOG_SITE, __VA_ARGS__)

#if (NGX_DEBUG)
#define BRIX_LOG_DEBUG(category, log, error, ...)                         \
    do {                                                                \
        if ((log) != NULL && ((log)->log_level & (category))) {           \
            brix_log_event_emit(NGX_LOG_DEBUG, log, error, BRIX_LOG_SITE, \
                                __VA_ARGS__);                           \
        }                                                               \
    } while (0)
#else
#define BRIX_LOG_DEBUG(category, log, error, ...) do { } while (0)
#endif
