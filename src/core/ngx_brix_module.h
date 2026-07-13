#ifndef BRIX_NGX_BRIX_MODULE_H
#define BRIX_NGX_BRIX_MODULE_H

/*
 * ngx_brix_module.h — umbrella internal header for the nginx XRootD stream module.
 *
 * Every .c file in the module includes this header.  It provides:
 *   1. All system, nginx, and OpenSSL headers needed across the codebase.
 *   2. Core type definitions (via src/types/ sub-headers).
 *   3. Forward declarations of every subsystem's public API.
 *
 * To find a specific type, see the corresponding src/types/ file:
 *   types/tunables.h — BRIX_* size limits, auth constants, metric macros
 *   types/identity.h — brix_identity_t (verified principal state)
 *   types/state.h    — brix_state_t enum, opaque forward decls
 *   types/file.h     — brix_file_t (per-open-file bookkeeping)
 *   types/context.h  — brix_ctx_t  (per-connection state)
 *   types/config.h   — ngx_stream_brix_srv_conf_t (per-server config)
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

#if (BRIX_HAVE_KRB5)
#include <krb5.h>
#endif

#include "protocols/root/protocol/protocol.h"
#include "observability/metrics/metrics.h"
#include "observability/dashboard/dashboard.h"
#include "auth/token/token.h"

#include <ngx_thread_pool.h>

/* compat/ — shared helpers and macro infrastructure (phase 1) */
#include "core/compat/err_strings.h"
#include "core/compat/error_mapping.h"

/* config/ — merge helpers for custom field types */
#include "core/config/merge_macros.h"

/* path/ — kernel-confined file operations (beneath API) */
#include "fs/path/beneath.h"

/* ------------------------------------------------------------------ */
/* Module forward declaration                                           */
/* ------------------------------------------------------------------ */

extern ngx_module_t ngx_stream_brix_module;

/* ------------------------------------------------------------------ */
/* Core types (see src/types/ for full definitions with field comments) */
/* ------------------------------------------------------------------ */

#include "core/types/tunables.h"
#include "core/types/identity.h"
#include "core/types/state.h"
#include "core/types/file.h"
#include "core/types/context.h"
#include "core/types/config.h"

/* ------------------------------------------------------------------ */
/* Config + lifecycle (stream/module.c references these)               */
/* ------------------------------------------------------------------ */

/* Allocate a per-server-block config (pool-owned), all fields set to
 * NGX_CONF_UNSET / NULL so the merge step can tell omitted from explicit.
 * Returns the conf, or NULL on allocation failure. */
void *ngx_stream_brix_create_srv_conf(ngx_conf_t *cf);
/* Apply nginx parent->child inheritance (scalars via ngx_conf_merge_*,
 * rule arrays via brix_merge_arrays). Returns NGX_CONF_OK / NGX_CONF_ERROR. */
char *ngx_stream_brix_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
/* "xrootd on|off;" directive: when on, swaps the stream server-block handler
 * to the xrootd session handler. Returns NGX_CONF_OK / NGX_CONF_ERROR. */
char *ngx_stream_brix_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* Postconfig phase: load VOMS, init auth (GSI/TLS/token/SSS), finalize ACL
 * rules, create the SHM registries, and size AIO pools. NGX_OK / NGX_ERROR. */
ngx_int_t ngx_stream_brix_postconfiguration(ngx_conf_t *cf);
/* Per-worker init after fork: proxy pool, CMS heartbeat clients, per-worker
 * CRL-reload timers. NGX_OK, or NGX_ERROR on timer alloc failure. */
ngx_int_t ngx_stream_brix_init_process(ngx_cycle_t *cycle);
/* Per-worker teardown at shutdown (also fires the ASAN leak check in
 * sanitizer builds). Best-effort; never fails. */
void      brix_exit_process(ngx_cycle_t *cycle);
/* SHM-zone init callback: zeroes a fresh metrics region, or preserves the
 * existing one across reload when data != NULL. Always NGX_OK. */
ngx_int_t ngx_brix_metrics_shm_init(ngx_shm_zone_t *shm_zone, void *data);
/* (Re)build the GSI X509_STORE from xcf->trusted_ca + xcf->crl and atomically
 * swap it into xcf->gsi_store (old store freed; left intact on failure).
 * NGX_OK / NGX_ERROR. Safe to call at runtime for CRL reload. */
/* cache_scope: a per-config-parse token (pass cf->cycle) that lets identical
 * GSI blocks share one built CA/CRL store instead of each reloading the IGTF
 * CRL directory (~1s each) at startup. Pass NULL from the CRL hot-reload timer
 * so it always rebuilds from fresh CRLs. */
ngx_int_t brix_rebuild_gsi_store(ngx_stream_brix_srv_conf_t *xcf,
    ngx_log_t *log, void *cache_scope);
/* Validate CA/CRL cross-consistency for the stream config; logs mismatches as
 * warnings. Always NGX_OK (server starts even with a broken CRL). */
ngx_int_t brix_check_pki_consistency_stream(ngx_log_t *log,
    ngx_stream_brix_srv_conf_t *xcf);
/* Config directive parsers. All take (cf, cmd, conf=srv_conf) and return
 * NGX_CONF_OK / NGX_CONF_ERROR, appending to the relevant array or scalar in
 * the per-server config. Run once at startup; not thread-safe by design. */

/* "require_vo <prefix> <vo>": append a path-prefix VO-membership ACL rule. */
char *brix_conf_set_require_vo(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* "authdb <file>": load an identity-based ACL ruleset (u/g/p/a + privs). */
char *brix_conf_set_authdb(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* "inherit_parent_group <prefix>": append a rule taking group ownership from
 * the parent directory rather than file metadata under that prefix. */
char *brix_conf_set_inherit_parent_group(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* "manager_map <prefix> <host:port>": append a longest-prefix routing entry
 * to the manager map (validates IPv6 brackets and port range). */
char *brix_conf_set_manager_map(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* "brix_cms_manager <host:port>": resolve and store the CMS heartbeat
 * endpoint (one per server block; duplicate is an error). */
char *brix_conf_set_cms_manager(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* "brix_upstream <host:port>": parse the proxy upstream address
 * (supports [v6]:port and host:port). */
char *brix_conf_set_upstream(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* "brix_cache_origin [root[s]://]host:port": cache origin; roots:// turns
 * on origin TLS. */
/* "brix_cache_origin_family auto|inet|inet6": address-family policy for the
 * origin connect (brix_af_policy_t). */
char *brix_conf_set_cache_origin_family(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* "brix_cache_eviction_threshold <ratio|N%>": occupancy trigger, stored
 * as parts-per-million. */
char *brix_conf_set_cache_eviction_threshold(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
/* "brix_cache_{high,low}_watermark" + "brix_wt_stage_{high,low}_watermark":
 * parse a fullness watermark (0.9 / 90%) into ppm at cmd->offset. Shared parser. */
char *brix_conf_set_cache_watermark(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
/* "brix_cache_max_file_size <N[k|m|g]>": max cacheable file size (off_t). */
char *brix_conf_set_cache_max_file_size(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
/* "brix_cache_include_regex <re>": POSIX-extended admission filter; only
 * matching paths are cached. */
char *brix_conf_set_cache_include_regex(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
/* "brix_cache_verify off|best-effort|require": checksum-on-fill policy —
 * verify a completed fill against the origin's advertised checksum before
 * publishing it (src/cache/verify.h). */
char *brix_conf_set_cache_verify(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
/* "brix_cache_verify_digest <alg>": preferred checksum algorithm to request
 * from an HTTP/Pelican origin (Want-Digest); advisory for root://. */
char *brix_conf_set_cache_verify_digest(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
/* "brix_cache_advertise_namespace <prefix>" (repeatable): a federation
 * namespace this cache advertises to the Pelican Director. */
char *brix_conf_set_cache_advertise_ns(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
/* "brix_write_through on|off": enable mirroring dirty handles to origin on
 * sync/close. */
char *brix_conf_set_wt_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* "brix_write_through_mode sync|async": flush close-time data inline vs via
 * the thread pool (explicit kXR_sync always flushes inline). */
char *brix_conf_set_wt_mode(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* "brix_write_through_origin [root[s]://]host:port": write-back destination
 * (same format as cache_origin). */
char *brix_conf_set_wt_origin(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* "brix_write_through_deny_prefix <prefix>": block write-through under this
 * prefix; deny wins over allow. */
char *brix_conf_set_wt_deny_prefix(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* "brix_write_through_allow_prefix <prefix>": permit write-through under
 * this prefix unless a deny prefix matches. */
char *brix_conf_set_wt_allow_prefix(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* "brix_cache_deny_prefix" / "brix_cache_allow_prefix": read-cache admission
 * prefixes (parity with the write-through lists; deny wins over allow). */
char *brix_conf_set_cache_deny_prefix(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *brix_conf_set_cache_allow_prefix(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* ------------------------------------------------------------------ */
/* Subsystem public APIs                                                */
/* ------------------------------------------------------------------ */
/*
 * Include architecture — why the headers look circular but are safe:
 *
 * Every sub-header (e.g. read/read.h) starts with:
 *   #include "../ngx_brix_module.h"
 * so it can use brix_ctx_t, ngx_stream_brix_srv_conf_t, etc.
 *
 * This file then #includes those same sub-headers below to pull their
 * function declarations into every translation unit that includes us.
 * The resulting include cycle (A includes B, B includes A) is broken
 * by the include guard at the top of this file: when B tries to include
 * A a second time, BRIX_NGX_BRIX_MODULE_H is already defined and the
 * re-include is a no-op.  By the time B is processed, all types defined
 * earlier in this file are already visible to B.
 *
 * The net effect: every .c file that does #include "ngx_brix_module.h"
 * automatically gets the declarations from every subsystem header too.
 * No .c file needs to know which sub-header declares a particular function.
 */

/* connection/ — nginx event wiring and byte-accumulation state machine */
#include "protocols/root/connection/handler.h"
#include "protocols/root/connection/event_sched.h"
#include "protocols/root/connection/write_helpers.h"
#include "protocols/root/connection/tls.h"
#include "protocols/root/connection/fd_table.h"
#include "protocols/root/connection/disconnect.h"
#include "protocols/root/connection/chain_helpers.h"

/* handshake/ — initial client hello and opcode dispatcher entry points */
/* Validate the 20-byte client hello and queue the 8-byte server reply
 * (protover + role). NGX_OK once queued; NGX_ERROR on bad magic / alloc. */
ngx_int_t brix_process_handshake(brix_ctx_t *ctx, ngx_connection_t *c);
/* Route one fully-buffered request: resets per-request timing, enforces
 * pending sigver, then tries session/proxy/read/write dispatch in order.
 * Returns the handler result (NGX_OK/NGX_DONE/NGX_AGAIN/NGX_ERROR). */
ngx_int_t brix_dispatch(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);
/* Enforce WLCG token scopes on a logical (client-facing, not resolved) path.
 * No-op (NGX_OK) for non-token sessions; need_write=1 for mutations.
 * NGX_OK granted / NGX_ERROR denied (caller sends the error + audit log). */
ngx_int_t brix_check_token_scope(brix_ctx_t *ctx,
    const char *logical_path, int need_write);

/* session/ — protocol/login/auth/liveness/sigver/bind handlers */
#include "protocols/root/session/session.h"
/* kXR_bind: attach a secondary data channel to a primary session (looked up
 * by sessid). Inherits logged_in/auth_done, assigns a pathid (1-253), and
 * replies kXR_ok + 1-byte pathid. Secondaries are read-only on primary
 * handles. NGX_OK on reply queued; error response on failure. */
ngx_int_t brix_handle_bind(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/* read/ — stat/open/read/readv/pgread/locate/close handlers */
#include "protocols/root/read/stat.h"
#include "protocols/root/read/open.h"
#include "protocols/root/read/read.h"
#include "protocols/root/read/statx.h"
#include "protocols/root/read/locate.h"
#include "protocols/root/read/close.h"

/* query/ — kXR_query (checksum / space / config), kXR_prepare, kXR_set */
/* kXR_query: dispatch on the infotype field to a sub-handler (checksum,
 * space, config, fattr, ...); kXR_Unsupported error for unknown types. */
ngx_int_t brix_handle_query(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);
/* kXR_prepare: auth/ACL/existence-check each path; optionally fire the
 * staging command; record request id + paths in ctx for later QPrep.
 * NGX_OK on accept (reply queued); NGX_DONE/error response on failure. */
ngx_int_t brix_handle_prepare(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);
/* kXR_set: accept client advisory hints (appid/CMS-space, clttl); always
 * replies kXR_ok even for unknown modifiers. */
ngx_int_t brix_handle_set(brix_ctx_t *ctx, ngx_connection_t *c);
/* Fire-and-forget spawn of the configured staging command with the resolved
 * absolute paths as argv (double-fork; no shell, no injection; paths must be
 * pre-confined by the caller). coloc sets BRIX_PREPARE_COLOC=1 in the child.
 * NGX_OK after the intermediate child is reaped; NGX_ERROR on alloc/fork fail. */
ngx_int_t brix_prepare_invoke_command(ngx_log_t *log,
    ngx_stream_brix_srv_conf_t *conf,
    const char **paths, ngx_uint_t count, ngx_flag_t coloc);

/* Longest-prefix match of reqpath against the manager map. Returns the
 * best entry (borrowed, array-owned) or NULL when no prefix matches. */
const brix_manager_map_t *brix_find_manager_map(const char *reqpath,
    ngx_array_t *map);

/* fattr/ — kXR_fattr: file extended attributes */
#include "protocols/root/fattr/ngx_brix_fattr.h"
/* kXR_fattr: parse the overloaded frame (fhandle vs inline path; sub-codes
 * get/set/del/list), auth-gate path targets, then dispatch. Owns and closes
 * any fd it opens. NGX_OK on reply queued; error response otherwise. */
ngx_int_t brix_handle_fattr(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/* dirlist/ — kXR_dirlist: directory listing with optional dStat */
#include "protocols/root/dirlist/dirlist.h"

/* write/ — kXR_write / kXR_pgwrite / kXR_sync / kXR_truncate / mkdir / rm / mv / chmod */
#include "protocols/root/write/write.h"
#include "protocols/root/write/op_table.h"

/* response/ — response formatting and wire send helpers */
#include "protocols/root/response/response.h"
#include "protocols/root/response/async.h"

/* path/ — client path resolution, VO ACL, group policy, access log */
#include "fs/path/path.h"
#include "auth/authz/auth_gate.h"
#include "protocols/root/path/op_path.h"

/* upstream/ — dynamic XRootD redirector query */
#include "net/upstream/upstream.h"

/* cache/ — read-through cache open-or-fill */
/* On a kXR_open hit: serve directly from cache_path if ready, else post a
 * thread-pool fill task (puts the connection into the AIO state, completes
 * via callback). clean_path is the logical path, cache_path the on-disk copy.
 * NGX_OK / async; error response on I/O failure or when built without cache
 * (the no-op stub replies kXR_Unsupported). */
ngx_int_t brix_cache_open_or_fill(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *clean_path,
    const char *cache_path, uint16_t options, uint16_t mode_bits);

/* Composed-cache (tier grammar) slow-tier miss offload (phase-64 SP2, the
 * stream twin of shared/http_cache_fill.c): run the whole-file fill of
 * `full_path` through `inst` (the registry's composed sd_cache) on the async
 * thread pool with the connection parked in XRD_ST_AIO; the done callback
 * serves the now-cached object. Call only when
 * brix_sd_cache_fill_needs_offload() said 1. NGX_OK = parked/async;
 * NGX_DECLINED = no pool (caller opens inline); else a queued-error rc. */
ngx_int_t brix_cache_open_fill_offload(brix_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf,
    const char *clean_path, const char *full_path, brix_sd_instance_t *inst,
    uint16_t options, uint16_t mode_bits);

/* tpc/ — XRootD root:// third-party copy (TPC) */
#include "tpc/engine/tpc_internal.h"

/* cms/ — CMS manager heartbeat/registration */
/* Start this worker's CMS heartbeat client (allocates ctx in the cycle pool,
 * schedules the first connect after a short delay). No-op when cms_addr is
 * unset or already started. Each worker keeps its own connection. */
void ngx_brix_cms_start(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *conf);

/* voms/ — VOMS attribute-certificate extraction (runtime dlopen) */
/* dlopen libvomsapi.so.1 and resolve its symbols once at startup.
 * NGX_OK (or already loaded), NGX_DECLINED if the lib is absent (graceful
 * degradation), NGX_ERROR if a required symbol is missing. */
ngx_int_t  brix_voms_init(ngx_log_t *log);
/* 1 if VOMS was loaded successfully, else 0 (immutable after startup). */
ngx_flag_t brix_voms_available(void);
/* Extract VO membership from a verified proxy chain into the caller's
 * primary_vo/vo_list buffers (always NUL-set first; sizes are buffer caps).
 * NGX_OK on success, NGX_DECLINED if VOMS unavailable / no extension,
 * NGX_ERROR on bad args or oversized dir paths. Borrows leaf/chain. */
ngx_int_t  brix_extract_voms_info(ngx_log_t *log, X509 *leaf,
    STACK_OF(X509) *chain, const ngx_str_t *vomsdir,
    const ngx_str_t *cert_dir, char *primary_vo, size_t primary_vo_sz,
    char *vo_list, size_t vo_list_sz);

/* aio/ — AIO response chain builders and thread-pool callbacks */
#include "core/aio/aio.h"

/* sss/ — SSS credential builder for proxy-mode upstream authentication */
/* Build a BF32-encrypted SSS kXR_auth payload (header + nonce + username TLV
 * + CRC32) into buf; writes the total length to *out_len. username defaults
 * to "xrd" if NULL/empty. buf_max must be >= BRIX_SSS_HDR_LEN + 64.
 * NGX_OK / NGX_ERROR (missing key or crypto failure). */
ngx_int_t brix_sss_build_proxy_credential(const brix_sss_key_t *key,
    const char *username, u_char *buf, size_t buf_max, size_t *out_len);

/* unix/krb5 stream authentication plugins */
/* kXR_auth "unix" handler: client-asserted (unverified) user/group name.
 * Fail-closed — loopback peers only unless conf->unix_trust_remote. Validates
 * names, sets identity, registers the session. Always bumps the unix auth
 * metric. NGX_OK on kXR_ok; error response (kXR_NotAuthorized/NoMemory). */
ngx_int_t brix_handle_unix_auth(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);
/* kXR_auth "krb5" handler: verify the AP_REQ against the server keytab,
 * map the client principal to a local name, register the session. Always
 * denies when built without krb5. NGX_OK on success; error response on fail. */
ngx_int_t brix_handle_krb5_auth(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);
/* kXR_auth "host" handler (Phase 52 WS-C): reverse-resolve the peer host and
 * authenticate it against brix_host_allow.  NGX_OK on kXR_ok; error response
 * (kXR_NotAuthorized) on no-match / resolution failure / malformed credential. */
ngx_int_t brix_handle_host_auth(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);
/* kXR_auth "pwd" handler (Phase 52 WS-B): XrdSecpwd password handshake.  Round 1
 * exchanges DH publics + the asserted user; round 2 decrypts the credential with
 * the DH session cipher and verifies it (PBKDF2-HMAC-SHA1) against brix_pwd_file.
 * Returns NGX_OK on kXR_authmore (round 1) or kXR_ok (round 2 success); an error
 * response (kXR_NotAuthorized) on bad credential / disabled / malformed input. */
ngx_int_t brix_handle_pwd_auth(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/* Phase 25: charge nbytes against the bandwidth bucket the rate-limit dispatch
 * gate selected for the current request (no-op when none).  Declared here so
 * the read/write hot-path callers need not include the HTTP-pulling
 * ratelimit.h. */
void brix_rl_charge_ctx(brix_ctx_t *ctx, size_t nbytes);

#endif /* BRIX_NGX_BRIX_MODULE_H */
