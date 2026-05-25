/*
 * logging.c — WebDAV safe-path log formatting helpers.
 *
 * WHAT: Provides the `xrootd_log_safe_path()` function for emitting nginx error
 *       log lines with path strings that contain control bytes, quotes, backslashes,
 *       or non-ASCII characters safely escaped into \xNN hex notation.
 *
 * WHY: Path strings from XRootD wire protocol, HTTP URIs, and filesystem syscalls
 *      may contain bytes that corrupt nginx error-log formatting (e.g. 0x00 nulls,
 *      0x1a substitute, embedded quotes). Without sanitization, a single bad path
 *      can break log parsing, truncate lines, or inject malformed entries.
 *
 * HOW: Callers pass the raw path string to xrootd_log_safe_path() along with an
 *      ngx_log_t pointer, a syslog-level constant (NGX_LOG_ERR etc.), an optional
 *      errno value, and a printf-style fmt containing exactly one %s placeholder.
 *      The function:
 *        1. Calls xrootd_sanitize_log_string() from src/path/path.c to produce a
 *           safe_path[] buffer with all control bytes escaped as \xNN.
 *        2. Substitutes the sanitized path into fmt via ngx_log_error().
 *
 * MIGRATION: This module was originally defined inside webdav/util/ when WebDAV
 *            was the only HTTP protocol. After S3 and proxy-mode were added, the
 *            same logging helper was needed across all protocols. It was moved to
 *            src/compat/log.h / log.c as a shared compat-level function.
 *
 *            The webdav/util/logging.h and .c files remain as stubs for backward
 *            compatibility — they re-export the header guard and include statement
 *            so that any code still #including "webdav/util/logging.h" continues to
 *            resolve to the same declaration. No new callers should use this path;
 *            prefer src/compat/log.h directly.
 *
 * CALLER EXAMPLE:
 *   xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, 0,
 *                        "open failed for %s", fs_path);
 *
 * SEE ALSO: src/compat/log.c (implementation), src/path/path.c
 *           (xrootd_sanitize_log_string()), webdav/README.md → Utilities
 */

#include "logging.h"
