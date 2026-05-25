#ifndef XROOTD_WEBDAV_UTIL_LOGGING_H
#define XROOTD_WEBDAV_UTIL_LOGGING_H

/*
 * logging.h — WebDAV safe-path log formatting header (deprecated stub).
 *
 * WHAT: Re-exports the declaration of `xrootd_log_safe_path()` for backward
 *       compatibility. Originally this was the primary header defining the
 *       function; after migration to src/compat/log.h, this file remains as a
 *       shim so that existing #include "webdav/util/logging.h" resolves correctly.
 *
 * WHY: During the webdav-only era (early project), safe-path logging lived inside
 *      webdav/util/. When S3 and proxy-mode were added, the same helper was needed
 *      across all protocols — it was moved to src/compat/log.h / log.c as a shared
 *      compat-level function. Some callers still #include "webdav/util/logging.h"
 *      from older code paths; this stub prevents build failures during migration.
 *
 * MIGRATION: No new callers should use this header. Prefer src/compat/log.h directly.
 *            All existing webdav callers already resolve to the same declaration via
 *            this shim — no source changes required on caller side.
 *
 * SEE ALSO: src/webdav/util/logging.c (stub implementation), src/compat/log.h
 *           (current primary header), webdav/README.md → Utilities
 */

#endif /* XROOTD_WEBDAV_UTIL_LOGGING_H */
