/*
 * dashboard/config_download_internal.h - private split contract for
 * config_download.c and its file-size siblings (config_download_classify.c,
 * config_download_scrub.c). Not a public API: include only from
 * src/observability/dashboard/.
 *
 * Declares only the symbols that cross a split boundary (defined in one sibling,
 * referenced from another). Single-file helpers stay static in their .c.
 */
#ifndef BRIX_DASHBOARD_CONFIG_DOWNLOAD_INTERNAL_H
#define BRIX_DASHBOARD_CONFIG_DOWNLOAD_INTERNAL_H

#include <ngx_config.h>
#include <ngx_core.h>

#define DASHBOARD_REDACTED           "[redacted]"

/*
 * config_download_classify.c — fail-closed directive classification.
 *   dashboard_name_eq  : case-insensitive [name,len) vs NUL-terminated literal
 *                        (also used by the query-key match in the scrub sibling).
 *   dashboard_keep_value: keep (show value) ONLY when not secret AND a project
 *                        brix_* directive OR a safe stock directive.
 */
ngx_uint_t dashboard_name_eq(const u_char *name, size_t len, const char *lit);
ngx_uint_t dashboard_keep_value(const u_char *name, size_t len);

/*
 * config_download_scrub.c — in-place embedded-credential scrubbing.
 *   dashboard_scrub_value_creds: scrub scheme://user:pass@host userinfo and
 *                        ?token=/&secret=/&sig= query params in [p,end); the
 *                        region may shrink — returns the new end pointer.
 */
u_char *dashboard_scrub_value_creds(u_char *p, u_char *end);

#endif /* BRIX_DASHBOARD_CONFIG_DOWNLOAD_INTERNAL_H */
