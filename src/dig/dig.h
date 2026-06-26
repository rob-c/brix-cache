#ifndef NGX_XROOTD_DIG_H
#define NGX_XROOTD_DIG_H

/*
 * dig.h — XrdDig-style remote diagnostics (§3).
 *
 * WHAT: read-only, authorization-gated exposure of whitelisted server files
 *       (config, logs, …) over HTTP under "/.well-known/dig/<export>/<rel>".
 * WHY:  operators need to fetch a node's config/logs remotely for diagnosis,
 *       the capability XrdDig provides — without a shell on the box.
 * HOW:  every access is (a) default-off, (b) confined to a config-declared export
 *       directory by the kernel openat2(RESOLVE_BENEATH) primitive (so "../" and
 *       symlink escapes are impossible), (c) fail-closed authorized against a
 *       principal→export allow-file, and (d) read-only (GET/HEAD only). The
 *       declared export dirs are realpath'd at config time (the BENEATH anchors).
 *
 * The public entry point is xrootd_dig_handle(), called from the WebDAV dispatch
 * when the request path is under the dig prefix.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* The reserved URI prefix that routes to the dig handler. */
#define XROOTD_DIG_PREFIX     "/.well-known/dig/"
#define XROOTD_DIG_PREFIX_LEN (sizeof(XROOTD_DIG_PREFIX) - 1)

/* Declared in webdav.h (shared with the config setter): xrootd_dig_export_t,
 * and the handler prototype xrootd_dig_handle(). This header documents the
 * contract; the implementation lives in dig.c. */

#endif /* NGX_XROOTD_DIG_H */
