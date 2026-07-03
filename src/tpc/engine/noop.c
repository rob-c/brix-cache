/* File: noop.c — Stub native-TPC implementation for builds without TPC
 * WHAT: Provides empty/refusing stand-ins for the entire native-TPC public API
 *       (brix_tpc_parse_opaque, the key-registry lifecycle —
 *       brix_tpc_key_configure_registry / _generate_key / _register / _validate
 *       / _consume / _remove, the source-policy gate brix_tpc_check_src_policy,
 *       and the pull entry points brix_tpc_prepare_pull / _start_pull /
 *       _launch_pull). This translation unit is compiled in place of the real
 *       SHM key-registry + pull-thread implementation when native TPC is disabled
 *       at build time, so the rest of the module links and runs unchanged.
 *
 * WHY:  Native TPC pull depends on a cross-process SHM key registry and a
 *       thread-pool data mover (src/tpc/engine/key_registry.c, launch.c, thread.c,
 *       source.c). Builds that omit those features still reference the same
 *       symbols from the stream dispatch and config layers. Supplying inert
 *       definitions here keeps callsites symbol-resolved while guaranteeing that
 *       any actual TPC request is cleanly refused rather than silently misbehaving.
 *
 * HOW:  Query/lookup helpers return failure or empty results
 *       (brix_tpc_parse_opaque → -1 after zeroing *out; key validate/consume → 0;
 *       generate_key → empty string; register/remove → no-op). The build-time
 *       configure hook brix_tpc_key_configure_registry returns NGX_OK so module
 *       init succeeds. brix_tpc_check_src_policy denies (returns -1) with the
 *       message "native TPC is disabled at build time" copied via ngx_cpystrn.
 *       The pull entry points brix_tpc_prepare_pull / _start_pull send
 *       kXR_Unsupported via brix_send_error; brix_tpc_launch_pull forwards to
 *       brix_tpc_prepare_pull so every wire-level pull attempt is rejected.
 * */

#include "tpc_internal.h"

/* WHAT: Stub opaque-parameter parser — zeroes *out (when non-NULL) and always
 *       reports failure (-1); native TPC opaque parsing is unavailable in this build. */
int
brix_tpc_parse_opaque(const char *opaque, brix_tpc_params_t *out)
{
    (void) opaque;

    if (out != NULL) {
        ngx_memzero(out, sizeof(*out));
    }

    return -1;
}

/* WHAT: Stub build-time registry configure hook — no SHM registry to set up, so
 *       returns NGX_OK to let module configuration succeed. */
ngx_int_t
brix_tpc_key_configure_registry(ngx_conf_t *cf)
{
    (void) cf;
    return NGX_OK;
}

/* WHAT: Stub key generator — writes an empty string (no real TPC key minted). */
void
brix_tpc_generate_key(char *buf, size_t buf_sz)
{
    if (buf != NULL && buf_sz > 0) {
        buf[0] = '\0';
    }
}

/* WHAT: Stub key registration — no-op (no SHM registry to record the key/TTL). */
void
brix_tpc_key_register(const char *key, ngx_msec_t ttl_ms)
{
    (void) key;
    (void) ttl_ms;
}

/* WHAT: Stub key validation — always reports "not valid" (0); no keys exist. */
int
brix_tpc_key_validate(const char *key)
{
    (void) key;
    return 0;
}

/* WHAT: Stub one-shot key consume — always reports "nothing consumed" (0). */
int
brix_tpc_key_consume(const char *key)
{
    (void) key;
    return 0;
}

/* WHAT: Stub key removal — no-op (nothing is ever registered). */
void
brix_tpc_key_remove(const char *key)
{
    (void) key;
}

/* WHAT: Stub source-policy gate — denies every source (-1) and writes
 *       "native TPC is disabled at build time" into err_msg via ngx_cpystrn. */
int
brix_tpc_check_src_policy(const char *src_host, uint16_t src_port,
    ngx_flag_t allow_local, ngx_flag_t allow_private,
    char *err_msg, size_t err_msg_sz)
{
    (void) src_host;
    (void) src_port;
    (void) allow_local;
    (void) allow_private;

    if (err_msg != NULL && err_msg_sz > 0) {
        ngx_cpystrn((u_char *) err_msg,
                    (u_char *) "native TPC is disabled at build time",
                    err_msg_sz);
    }

    return -1;
}

/* WHAT: Stub TPC pull preparation — refuses the request by sending
 *       kXR_Unsupported ("native TPC is disabled at build time") to the client. */
ngx_int_t
brix_tpc_prepare_pull(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits)
{
    (void) conf;
    (void) tpc;
    (void) dst_path;
    (void) options;
    (void) mode_bits;

    return brix_send_error(ctx, c, kXR_Unsupported,
                             "native TPC is disabled at build time");
}

/* WHAT: Stub TPC pull start — refuses the request by sending kXR_Unsupported
 *       ("native TPC is disabled at build time") to the client. */
ngx_int_t
brix_tpc_start_pull(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int fhandle_idx)
{
    (void) conf;
    (void) fhandle_idx;

    return brix_send_error(ctx, c, kXR_Unsupported,
                             "native TPC is disabled at build time");
}

/* WHAT: Stub TPC pull launch — forwards to brix_tpc_prepare_pull, which refuses
 *       with kXR_Unsupported; provided so callsites resolve in TPC-disabled builds. */
ngx_int_t
brix_tpc_launch_pull(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits)
{
    return brix_tpc_prepare_pull(ctx, c, conf, tpc, dst_path, options,
                                   mode_bits);
}
