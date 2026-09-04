#include "core/ngx_brix_module.h"
#include "protocols/root/path/op_path.h"   /* brix_beneath_full_path, auth gate */
#include "fs/vfs/vfs.h"                    /* VFS ctx + export-relative key */
#include "fs/path/n2n_stage.h"
#include "fs/backend/cache/sd_cache.h"     /* brix_sd_cache_evict */

#include <stdlib.h>

/*
 * kXR_set (3018) — client sends advisory configuration hints to the server.
 *
 * WHAT: Handles the SET opcode where a client provides optional metadata about
 *       its identity or session parameters. The modifier byte determines which
 *       hint type is being sent; unrecognized modifiers are accepted with kXR_ok.
 *
 * WHY: CMS grid infrastructure sends "cms.space" appid reports to advertise
 *      disk capacity at storage nodes. Session TTL hints (clttl) let clients
 *      suggest keep-alive duration. The server accepts all SET requests per spec,
 *      enabling monitoring and operational visibility without strict enforcement.
 *
 * HOW: Parse modifier byte from the request header → switch on known values
 *      (appid, clttl) → handle payload for recognized types → log details at
 *      debug/info level → always return kXR_ok regardless of modifier value.
 */

/*
 * CMS space report constants.
 *
 * The "cms.space" appid payload format is: "cms.space <total_bytes> <free_bytes>"
 * where both values are ASCII decimal unsigned integers. Used by the CMS grid
 * to advertise storage node capacity in kXR_set(appid) requests.
 */
#define CMS_SPACE_PREFIX     "cms.space"
#define CMS_SPACE_PREFIX_LEN (sizeof(CMS_SPACE_PREFIX) - 1)

/*
 * brix_set_handle_cms_space — parse and log CMS space-availability report.
 *
 * WHAT: Extracts total and free byte counts from a "cms.space" payload string,
 *       then logs the capacity breakdown at INFO level for operational visibility.
 *
 * WHY: The CMS grid sends kXR_set(appid) with "cms.space <total> <free>" payloads
 *      to advertise storage node disk availability. This function parses those
 *      reports so operators can monitor capacity via nginx access logs.
 *
 * HOW: Skip the "cms.space" prefix, parse two ASCII decimal unsigned integers
 *      separated by a space using strtoull, validate separator presence between
 *      them, compute used = total - free, log at INFO level. Returns silently on
 *      malformed payload (warn logged).
 */
static void
brix_set_handle_cms_space(ngx_connection_t *c, const char *payload,
                             size_t payload_len)
{
    /* Expected format: "cms.space <total_bytes> <free_bytes>" */
    const char        *p;
    char              *end;
    unsigned long long total_bytes, free_bytes;

    p = payload + CMS_SPACE_PREFIX_LEN;
    while (p < payload + payload_len && *p == ' ') {
        p++;
    }

    total_bytes = strtoull(p, &end, 10);
    if (end == p || *end != ' ') {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: kXR_set cms.space: malformed payload");
        return;
    }
    p = end;
    while (*p == ' ') {
        p++;
    }
    free_bytes = strtoull(p, &end, 10);
    if (end == p) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: kXR_set cms.space: missing free_bytes");
        return;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "brix: cms.space report: total=%lluB free=%lluB "
                  "used=%lluB",
                  total_bytes, free_bytes,
                  (total_bytes > free_bytes) ? total_bytes - free_bytes : 0ULL);
}

/* Stock xrdfs "cache {evict|fevict} <path>" arrives as kXR_set with this
 * payload prefix (pinned live against xrdfs 5.6.9 with XRD_LOGLEVEL=Dump). */
#define CACHE_EVICT_PREFIX      "cache evict "
#define CACHE_EVICT_PREFIX_LEN  (sizeof(CACHE_EVICT_PREFIX) - 1)
#define CACHE_FEVICT_PREFIX     "cache fevict "
#define CACHE_FEVICT_PREFIX_LEN (sizeof(CACHE_FEVICT_PREFIX) - 1)

/* ---- Operator cache-evict command (stock xrdfs "cache evict|fevict") ----
 *
 * WHAT: Handles a kXR_set payload of "cache evict <path>" / "cache fevict
 *       <path>": authorizes the caller, then removes the path's cached copy
 *       (data + cinfo + L1 entry) from the export's cache tier. Replies
 *       kXR_ok whether or not a copy was cached (the engine is idempotent),
 *       kXR_Unsupported when the export has no cache tier, kXR_NotAuthorized
 *       on a failed gate. Returns the response's queue result.
 *
 * WHY:  Parity audit §4.11/§7.12 — the programmatic evict existed but no
 *       operator command reached it; stock ships `xrdfs cache evict`.
 *       Eviction destroys cached state, so it is gated like a delete
 *       (allow_write first — invariant 3 — then the BRIX_AUTH_DELETE
 *       authz/token-scope chain on the CONFINED path — invariant 4).
 *
 * HOW:  1. Extract and NUL-terminate the path operand; refuse empty or
 *          over-long operands and any ".." component outright.
 *       2. Confine beneath root_canon + run the shared auth gate
 *          (need_write ⇒ allow_write is checked before token scope).
 *       3. Build a transient VFS ctx; no cache decorator on the export ⇒
 *          kXR_Unsupported.
 *       4. brix_sd_cache_evict on the export-relative key; log the freed
 *          bytes. evict and fevict act identically here — the engine has no
 *          in-use refusal — a documented divergence from stock's evict.
 */
static ngx_int_t
brix_set_handle_cache_evict(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *operand, size_t operand_len,
    int force)
{
    brix_vfs_ctx_t  vctx;
    char            reqpath[BRIX_MAX_PATH + 1];
    char            full_path[PATH_MAX];
    char            physical[PATH_MAX];
    uint64_t        freed_bytes;
    const char     *verb = force ? "fevict" : "evict";

    while (operand_len > 0
           && (operand[operand_len - 1] == '\0'
               || operand[operand_len - 1] == '\n'
               || operand[operand_len - 1] == ' '))
    {
        operand_len--;
    }
    if (operand_len == 0 || operand_len > BRIX_MAX_PATH) {
        BRIX_OP_ERR(ctx, BRIX_OP_SET);
        return brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "cache evict: bad path operand");
    }
    ngx_memcpy(reqpath, operand, operand_len);
    reqpath[operand_len] = '\0';

    if (brix_reject_dotdot_path(ctx, c, BRIX_OP_SET, "SET", reqpath)) {
        return ctx->write_rc;
    }

    /* Invariant 3: the global write gate comes BEFORE any token-scope or
     * authdb evaluation. kXR_set is normally advisory and routes through the
     * session dispatcher (no write gate there), so the destructive cache
     * command enforces it here itself. */
    if (!conf->common.allow_write) {
        brix_log_access(ctx, c, "SET", reqpath, verb, 0,
                          kXR_NotAuthorized, "read-only export", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_SET);
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "cache evict: server is read-only");
    }

    brix_beneath_full_path(conf->common.root_canon, reqpath,
                             full_path, sizeof(full_path));

    if (brix_auth_gate(ctx, c, BRIX_OP_SET, "SET", reqpath, full_path,
                          conf, BRIX_AUTH_DELETE, 1 /* need_write */)
        != NGX_OK)
    {
        return ctx->write_rc;
    }

    /* phase-105: the only mutation below is brix_sd_cache_evict — the SERVICE
     * cache store, which Appendix H.1 places outside export policy (dropping a
     * cached copy changes no exported object). The ctx is ALLOWED so that
     * intent is stated at the construction site rather than inferred from the
     * fact that eviction happens not to route through a VFS mutator. */
    brix_vfs_ctx_init(&vctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL, BRIX_VFS_MUTATION_ALLOWED, 0 /* is_tls */,
        ctx->identity, full_path);
    brix_root_vfs_bind_session(ctx, conf, &vctx);

    if (vctx.sd == NULL || !brix_sd_cache_instance_is(vctx.sd)) {
        BRIX_OP_ERR(ctx, BRIX_OP_SET);
        return brix_send_error(ctx, c, kXR_Unsupported,
                                 "no cache tier on this export");
    }

    if (brix_path_resolved_to_pfn(&vctx, full_path, physical,
                                  sizeof(physical)) != NGX_OK)
    {
        BRIX_OP_ERR(ctx, BRIX_OP_SET);
        return brix_send_error(ctx, c, kXR_IOError,
                               "cache key translation failed");
    }
    freed_bytes = brix_sd_cache_evict(vctx.sd, physical);
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "brix: cache %s \"%s\": %uL bytes evicted",
                  verb, reqpath, (uint64_t) freed_bytes);

    BRIX_RETURN_OK(ctx, c, BRIX_OP_SET, "SET", reqpath, verb, 0);
}

/*
 * brix_handle_set — handle kXR_set (3018) opcode.
 *
 * WHAT: Dispatches the SET opcode based on its modifier byte, handling known
 *       hint types (appid with CMS space reports, clttl session TTL) and
 *       returning kXR_ok for all modifiers including unrecognized ones.
 *
 * WHY: The XRootD protocol allows clients to send advisory hints about their
 *      identity or session parameters. The server accepts all SET requests per
 *      spec — it does not enforce TTL or validate appid format strictly, but
 *      logs recognized types for operational visibility (CMS space reports at
 *      INFO level, other modifiers at debug level).
 *
 * HOW: Extract modifier byte from request header → switch on known values
 *      (kXR_set_appid → parse CMS space payload; kXR_set_clttl → log silently)
 *      → default → accept with kXR_ok. Always return kXR_ok regardless of
 *      modifier value. Payload snippet logged at debug level for all types.
 *
 * Parameters:
 *   ctx — xrootd connection context containing parsed request header and payload
 *   c   — nginx connection for logging
 */

/* Copy up to cap-1 bytes of the SET payload into `snippet` for display, stripped
 * of trailing newline/NUL. Empty snippet when the payload is empty. */
static void
set_build_snippet(const char *payload, size_t payload_len, char *snippet,
    size_t cap)
{
    size_t snap;

    snippet[0] = '\0';
    if (payload_len == 0) {
        return;
    }
    snap = payload_len < cap - 1 ? payload_len : cap - 1;
    ngx_memcpy(snippet, payload, snap);
    snippet[snap] = '\0';
    while (snap > 0 && (snippet[snap - 1] == '\n' || snippet[snap - 1] == '\0')) {
        snippet[--snap] = '\0';
    }
}

ngx_int_t
brix_handle_set(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    xrdw_set_req_t    req;
    char              detail[128];
    u_char            modifier;
    const char       *mod_name;
    char              payload_snippet[64];
    size_t            payload_len;
    const char       *payload;

    xrdw_set_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    modifier = (u_char) req.modifier;

    switch (modifier) {
    case kXR_set_appid: mod_name = "appid"; break;
    case kXR_set_clttl: mod_name = "clttl"; break;
    default:            mod_name = "unknown"; break;
    }

    payload_len = (size_t) ctx->recv.cur_dlen;
    payload     = (ctx->recv.cur_dlen > 0 && ctx->recv.payload != NULL)
                  ? (const char *) ctx->recv.payload : "";

    set_build_snippet(payload, payload_len, payload_snippet,
                      sizeof(payload_snippet));

    /* CMS space report: modifier=appid, payload starts with "cms.space" */
    if (modifier == kXR_set_appid
        && payload_len > CMS_SPACE_PREFIX_LEN
        && ngx_strncmp(payload, CMS_SPACE_PREFIX, CMS_SPACE_PREFIX_LEN) == 0)
    {
        brix_set_handle_cms_space(c, payload, payload_len);
        BRIX_RETURN_OK(ctx, c, BRIX_OP_SET, "SET", "-", "cms.space", 0);
    }

    /* Operator cache-evict (stock xrdfs `cache evict|fevict <path>`) —
     * matched by payload prefix regardless of modifier: stock sends the
     * command as an ordinary appid-modifier set. */
    if (payload_len > CACHE_EVICT_PREFIX_LEN
        && ngx_strncmp(payload, CACHE_EVICT_PREFIX,
                       CACHE_EVICT_PREFIX_LEN) == 0)
    {
        return brix_set_handle_cache_evict(ctx, c, conf,
                                             payload + CACHE_EVICT_PREFIX_LEN,
                                             payload_len
                                             - CACHE_EVICT_PREFIX_LEN, 0);
    }
    if (payload_len > CACHE_FEVICT_PREFIX_LEN
        && ngx_strncmp(payload, CACHE_FEVICT_PREFIX,
                       CACHE_FEVICT_PREFIX_LEN) == 0)
    {
        return brix_set_handle_cache_evict(ctx, c, conf,
                                             payload + CACHE_FEVICT_PREFIX_LEN,
                                             payload_len
                                             - CACHE_FEVICT_PREFIX_LEN, 1);
    }

    snprintf(detail, sizeof(detail), "modifier=0x%02x(%s) val=\"%s\"",
             (unsigned) modifier, mod_name, payload_snippet);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: kXR_set %s", detail);

    BRIX_RETURN_OK(ctx, c, BRIX_OP_SET, "SET", "-", detail, 0);
}
