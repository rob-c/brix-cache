#ifndef BRIX_OBSERVABILITY_ACCESS_LOG_H
#define BRIX_OBSERVABILITY_ACCESS_LOG_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * WHAT: Shared access-log writer entry points.
 * WHY: Session lifecycle logging writes into the same batched access-log stream
 * as per-request XRootD records, so both paths must share timestamping,
 * buffering, fd switching, and explicit flushes.
 * HOW: access_log.c owns the per-worker buffer; callers pass complete lines to
 * brix_alog_emit() and call brix_access_log_time_prefix() for the standard
 * "[dd/Mon/yyyy:hh:mm:ss +zzzz] " prefix.
 */
void brix_alog_emit(ngx_fd_t fd, const char *line, size_t n);
void brix_access_log_flush(void);
size_t brix_access_log_time_prefix(char *dst, size_t dst_size);

#endif /* BRIX_OBSERVABILITY_ACCESS_LOG_H */
