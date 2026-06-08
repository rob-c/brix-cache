#pragma once

/*
 * ngx_xrootd_module.h — umbrella internal header for the nginx XRootD stream module.
 *
 * Every .c file in the module includes this header.  It provides:
 *   1. All system, nginx, and OpenSSL headers needed across the codebase.
 *   2. Core type definitions (via src/types/ sub-headers).
 *   3. Forward declarations of every subsystem's public API.
 *
 * To find a specific type, see the corresponding src/types/ file:
 *   types/tunables.h — XROOTD_* size limits, auth constants, metric macros
 *   types/identity.h — xrootd_identity_t (verified principal state)
 *   types/state.h    — xrootd_state_t enum, opaque forward decls
 *   types/file.h     — xrootd_file_t (per-open-file bookkeeping)
 *   types/context.h  — xrootd_ctx_t  (per-connection state)
 *   types/config.h   — ngx_stream_xrootd_srv_conf_t (per-server config)
 *
 * Maintainer map for non-XRootD specialists:
 *   - stream/       owns the nginx module descriptor, command table, and lifecycle hooks.
 *   - config/       owns directive parsing, config inheritance, and startup validation.
 *   - connection/   owns nginx event wiring and the byte-accumulation state machine.
 *   - handshake/    owns the initial client hello and opcode dispatcher.
 *   - session/      owns protocol/login/auth/liveness requests.
 *   - read/         owns file-handle lifecycle: stat/open/read/readv/close.
 *   - write/        owns storage mutation: write/pgwrite/sync/truncate/mkdir/rm/rmdir/mv/chmod.
 *   - query/        owns kXR_query and kXR_prepare.
 *   - dirlist/      owns kXR_dirlist (directory listing with optional dStat).
 *   - fattr/        owns kXR_fattr (file extended attribute operations).
 *   - path/         translates untrusted client paths and enforces VO ACL policy.
 *   - response/     owns response formatting and the wire send helpers.
 *   - aio/          owns async pread/pwrite (thread-pool path) and response chain builders.
 *   - upstream/     owns the XRootD upstream redirector query flow.
 *   - cache/        owns read-through cache fill and lock management.
 *   - cms/          owns CMS manager heartbeat/registration.
 *   - manager/      owns the server registry (cluster/redirector mode) and CMS server handler.
 *   - gsi/          owns GSI/x509 certificate operations.
 *   - voms/         owns VOMS attribute-certificate extraction (runtime dlopen).
 *   - token/        owns JWT/WLCG bearer-token validation and scope checks.
 *   - metrics/      owns Prometheus shared-memory counters.
 *   - protocol/     owns XRootD wire-format constants and packed structs (headers only).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <arpa/inet.h>

#include <regex.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

/* VOMS support is loaded at runtime via dlopen; no compile-time header needed */

#if (XROOTD_HAVE_KRB5)
#include <krb5.h>
#endif

#include "protocol/protocol.h"
#include "metrics/metrics.h"
#include "dashboard/dashboard.h"
#include "token/token.h"

#include <ngx_thread_pool.h>

/* ------------------------------------------------------------------ */
/* Module forward declaration                                           */
/* ------------------------------------------------------------------ */

extern ngx_module_t ngx_stream_xrootd_module;

/* ------------------------------------------------------------------ */
/* Core types (see src/types/ for full definitions with field comments) */
/* ------------------------------------------------------------------ */

#include "types/tunables.h"
#include "types/identity.h"
#include "types/state.h"
#include "types/file.h"
#include "types/context.h"
#include "types/config.h"

/* ------------------------------------------------------------------ */
/* Config + lifecycle (stream/module.c references these)               */
/* ------------------------------------------------------------------ */

void *ngx_stream_xrootd_create_srv_conf(ngx_conf_t *cf);
char *ngx_stream_xrootd_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
char *ngx_stream_xrootd_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_stream_xrootd_postconfiguration(ngx_conf_t *cf);
ngx_int_t ngx_stream_xrootd_init_process(ngx_cycle_t *cycle);
ngx_int_t ngx_xrootd_metrics_shm_init(ngx_shm_zone_t *shm_zone, void *data);
ngx_int_t xrootd_rebuild_gsi_store(ngx_stream_xrootd_srv_conf_t *xcf,
    ngx_log_t *log);
ngx_int_t xrootd_check_pki_consistency_stream(ngx_log_t *log,
    ngx_stream_xrootd_srv_conf_t *xcf);
char *xrootd_conf_set_require_vo(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *xrootd_conf_set_authdb(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *xrootd_conf_set_inherit_parent_group(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

char *xrootd_conf_set_manager_map(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *xrootd_conf_set_cms_manager(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *xrootd_conf_set_upstream(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *xrootd_conf_set_cache_origin(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *xrootd_conf_set_cache_eviction_threshold(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
char *xrootd_conf_set_cache_max_file_size(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
char *xrootd_conf_set_cache_include_regex(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
char *xrootd_conf_set_wt_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *xrootd_conf_set_wt_mode(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *xrootd_conf_set_wt_origin(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *xrootd_conf_set_wt_deny_prefix(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *xrootd_conf_set_wt_allow_prefix(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* ------------------------------------------------------------------ */
/* Subsystem public APIs                                                */
/* ------------------------------------------------------------------ */
/*
 * Include architecture — why the headers look circular but are safe:
 *
 * Every sub-header (e.g. read/read.h) starts with:
 *   #include "../ngx_xrootd_module.h"
 * so it can use xrootd_ctx_t, ngx_stream_xrootd_srv_conf_t, etc.
 *
 * This file then #includes those same sub-headers below to pull their
 * function declarations into every translation unit that includes us.
 * The resulting include cycle (A includes B, B includes A) is broken
 * by the #pragma once at the top of this file: when B tries to include
 * A a second time, the pragma is already in effect and the re-include
 * is a no-op.  By the time B is processed, all types defined earlier
 * in this file are already visible to B.
 *
 * The net effect: every .c file that does #include "ngx_xrootd_module.h"
 * automatically gets the declarations from every subsystem header too.
 * No .c file needs to know which sub-header declares a particular function.
 */

/* connection/ — nginx event wiring and byte-accumulation state machine */
#include "connection/handler.h"
#include "connection/event_sched.h"
#include "connection/write_helpers.h"
#include "connection/tls.h"
#include "connection/fd_table.h"
#include "connection/disconnect.h"
#include "connection/chain_helpers.h"

/* handshake/ — initial client hello and opcode dispatcher entry points */
ngx_int_t xrootd_process_handshake(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_dispatch(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_check_token_scope(xrootd_ctx_t *ctx,
    const char *logical_path, int need_write);

/* session/ — protocol/login/auth/liveness/sigver/bind handlers */
#include "session/session.h"
ngx_int_t xrootd_handle_bind(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* read/ — stat/open/read/readv/pgread/locate/close handlers */
#include "read/stat.h"
#include "read/open.h"
#include "read/read.h"
#include "read/statx.h"
#include "read/locate.h"
#include "read/close.h"

/* query/ — kXR_query (checksum / space / config), kXR_prepare, kXR_set */
ngx_int_t xrootd_handle_query(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_prepare(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_set(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_prepare_invoke_command(ngx_log_t *log,
    ngx_stream_xrootd_srv_conf_t *conf,
    const char **paths, ngx_uint_t count);

/* manager map lookup helper (longest-prefix match) */
const xrootd_manager_map_t *xrootd_find_manager_map(const char *reqpath,
    ngx_array_t *map);

/* fattr/ — kXR_fattr: file extended attributes */
#include "fattr/ngx_xrootd_fattr.h"
ngx_int_t xrootd_handle_fattr(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* dirlist/ — kXR_dirlist: directory listing with optional dStat */
#include "dirlist/dirlist.h"

/* write/ — kXR_write / kXR_pgwrite / kXR_sync / kXR_truncate / mkdir / rm / mv / chmod */
#include "write/write.h"

/* response/ — response formatting and wire send helpers */
#include "response/response.h"

/* path/ — client path resolution, VO ACL, group policy, access log */
#include "path/path.h"

/* upstream/ — dynamic XRootD redirector query */
#include "upstream/upstream.h"

/* cache/ — read-through cache open-or-fill */
ngx_int_t xrootd_cache_open_or_fill(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const char *clean_path,
    const char *cache_path, uint16_t options, uint16_t mode_bits);

/* tpc/ — XRootD root:// third-party copy (TPC) */
#include "tpc/tpc_internal.h"

/* cms/ — CMS manager heartbeat/registration */
void ngx_xrootd_cms_start(ngx_cycle_t *cycle,
    ngx_stream_xrootd_srv_conf_t *conf);

/* voms/ — VOMS attribute-certificate extraction (runtime dlopen) */
ngx_int_t  xrootd_voms_init(ngx_log_t *log);
ngx_flag_t xrootd_voms_available(void);
ngx_int_t  xrootd_extract_voms_info(ngx_log_t *log, X509 *leaf,
    STACK_OF(X509) *chain, const ngx_str_t *vomsdir,
    const ngx_str_t *cert_dir, char *primary_vo, size_t primary_vo_sz,
    char *vo_list, size_t vo_list_sz);

/* aio/ — AIO response chain builders and thread-pool callbacks */
#include "aio/aio.h"

/* sss/ — SSS credential builder for proxy-mode upstream authentication */
ngx_int_t xrootd_sss_build_proxy_credential(const xrootd_sss_key_t *key,
    const char *username, u_char *buf, size_t buf_max, size_t *out_len);

/* unix/krb5 stream authentication plugins */
ngx_int_t xrootd_handle_unix_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_krb5_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
