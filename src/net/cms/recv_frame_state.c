/*
 * cms/recv_frame_state.c — kYR_state existence probe + supervisor fan-down.
 *
 * WHAT: Two manager-frame handlers that both walk the namespace rather than
 *       just answering from context: cms_frame_state (kYR_state — "do you hold
 *       <path>?", answered kYR_have / silence) with its pure payload validator,
 *       and cms_super_fan_down (Phase-61 W7 — an explicit supervisor relaying a
 *       forwarded mutation down to its own data nodes).
 *
 * WHY:  Split out of recv_frame.c (coding-standards §1, 600-line cap). The
 *       remaining handlers answer from in-memory node state; these two reach
 *       into the namespace/registry and carry their own path-validation and
 *       per-child relay logic, so they review as a unit apart from the small
 *       context-only handlers and the dispatch table.
 */


#include "cms_internal.h"
#include "action_log.h"             /* cmsd-action NOTICE lines */
#include "recv_internal.h"
#include "node_ops.h"               /* Plane B forwarded-op planner */
#include "router.h"                 /* node-role opcode routing */
#include "rrdata.h"                 /* Pup decode for supervisor fan-down */
#include "forward.h"                /* per-node forwarded-op re-emit */
#include "server.h"                 /* child node list (supervisor role) */
#include "state_relay.h"            /* multi-tier kYR_state recursion */
#include "net/manager/pending.h"
#include "net/manager/registry.h"
#include "fs/path/beneath.h"
#include "fs/path/path.h"           /* brix_sanitize_log_string (WS6) */
#include "core/compat/net_target.h"   /* brix_net_host_chars_valid (WS6) */

#include <errno.h>
#include <unistd.h>


/* cms_state_extract_path — pure validation of a kYR_state payload: bound the
 * NUL-terminated namespace path, require an absolute path that fits the buffer,
 * and reject any ".." traversal before the registry/filesystem is touched
 * (cheap defence-in-depth ahead of the kernel-confined probe). Copies the
 * NUL-terminated path into pathz and returns its length via *pl_out; returns
 * NGX_OK or NGX_ERROR (caller stays silent, matching real cmsd). */
static ngx_int_t
cms_state_extract_path(const u_char *payload, size_t plen, char *pathz,
    size_t pathz_size, size_t *pl_out)
{
    size_t  pl;
    size_t  k;

    /* bounded length of the NUL-terminated path */
    for (pl = 0; pl < plen && payload[pl] != '\0'; pl++) { /* void */ }
    if (pl == 0 || payload[0] != '/' || pl >= pathz_size) {
        return NGX_ERROR;
    }

    /* reject path traversal before touching the registry/filesystem */
    for (k = 0; k + 1 < pl; k++) {
        if (payload[k] == '.' && payload[k + 1] == '.') {
            return NGX_ERROR;
        }
    }

    ngx_memcpy(pathz, payload, pl);
    pathz[pl] = '\0';
    *pl_out = pl;
    return NGX_OK;
}

/* cms_frame_state — kYR_state (raw): the manager asks "do you hold <path>?" as
 * part of on-demand selection.  The payload is the raw NUL-terminated namespace
 * path (no Pup framing).  We answer kYR_have (echoing streamid = path hash) if
 * we can serve the path, else stay silent so the manager won't select us —
 * matching real cmsd.
 *
 * Two ways to "have" a path:
 *   - manager_mode (a sub-manager registered UP to a meta-manager): forward the
 *     query to our own server registry — if any registered leaf data node
 *     exports a prefix covering the path, we have it (the client will be
 *     redirected to us and we then redirect down to the leaf).  This is what
 *     makes a multi-tier meta->nginx->leaf mesh resolve.
 *   - data node: the file exists on our local export filesystem. */
ngx_int_t
cms_frame_state(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, u_char code)
{
    const u_char  *payload = ctx->inbuf + NGX_BRIX_CMS_HDR_LEN;
    size_t         plen = ctx->in_need - NGX_BRIX_CMS_HDR_LEN;
    char           pathz[1024];
    char           safe[256];
    size_t         pl;
    struct stat    st;

    if (cms_state_extract_path(payload, plen, pathz, sizeof(pathz), &pl)
        != NGX_OK)
    {
        return NGX_OK;
    }

    /* WS6: cms_state_extract_path bounds the path and rejects "..", but it
     * accepts every other byte — including CR/LF.  The probe comes from the
     * manager leg, so an unsanitised %s here lets a hostile (or compromised)
     * manager forge whole lines into error.log.  Every log site below uses the
     * escaped rendering; the wire/VFS calls keep the real path. */
    brix_sanitize_log_string(pathz, safe, sizeof(safe));

    if (ctx->conf->manager_mode) {
        char      host[256];
        uint16_t  dport;
        if (brix_srv_select(pathz, 0, host, sizeof(host), &dport)) {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                           "brix: CMS state(mgr): registry serves "
                           "\"%s\", replying kYR_have", safe);
            brix_cms_log_action(ctx->cycle->log, "state-probe",
                                (const char *) ctx->mgr_name.data,
                                "in", safe, 1,
                                "sub-manager: a downstream node holds it "
                                "-> kYR_have");
            return ngx_brix_cms_send_have(ctx, streamid, pathz, pl);
        }

        /*
         * Phase-61 W7: registry miss.  With brix_cms_state_relay on, recurse
         * — park the parent's leg and re-ask our own nodes; the first child
         * kYR_have (server-leg ingest) is echoed back up under the parent's
         * streamid.  Off, or table full, or no child took the probe: stay
         * silent, which the parent reads as "not here" (stock semantics).
         */
        if (ctx->conf->cms.state_relay) {
            uint32_t              down_sid;
            ngx_uint_t            i, sent = 0;
            brix_cms_srv_ctx_t   *node;

            down_sid = brix_cms_state_relay_add(ctx, streamid, pathz);
            if (down_sid == 0) {
                return NGX_OK;
            }
            for (i = 0; i < brix_cms_srv_node_count(); i++) {
                node = brix_cms_srv_node_at(i);
                if (node == NULL || !node->logged_in || node->c == NULL) {
                    continue;
                }
                if (brix_cms_srv_send_state(node, down_sid, pathz) == NGX_OK) {
                    sent++;
                }
            }
            if (sent == 0) {
                /* Parked a leg no child will ever answer: the entry now just
                 * holds relay-table capacity until its TTL reaps it, and the
                 * parent degrades to "not here".  Logged unconditionally —
                 * a debug-only counter is invisible in the builds that hit
                 * this, which is every production one. */
                ngx_log_error(NGX_LOG_INFO, ctx->cycle->log, 0,
                              "brix: CMS state(mgr): relayed \"%s\" down to no "
                              "eligible node; parent will read silence",
                              safe);
            }
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                           "brix: CMS state(mgr): relayed \"%s\" down to "
                           "%ui node(s)", safe, sent);
        }
        return NGX_OK;
    }

    /*
     * Kernel-confined existence probe.  A malicious manager can ask
     * "do you hold <path>?" for ANY path; the raw stat() this replaced
     * followed symlinks, so a symlink planted under the export root
     * (e.g. /link -> /etc) would make us answer kYR_have for a file
     * OUTSIDE the root — a cross-root information leak and a
     * cluster-poisoning vector.  brix_stat_beneath() resolves the
     * path under the persistent export rootfd with openat2
     * RESOLVE_BENEATH, so any symlink or ".." that escapes the root is
     * rejected by the kernel and we correctly stay silent.  (The ".."
     * pre-check in cms_state_extract_path remains as cheap
     * defence-in-depth.)  A node with no local export root (rootfd < 0)
     * never holds files locally.
     */
    if (ctx->conf->rootfd >= 0
        && brix_stat_beneath(ctx->conf->rootfd, pathz, &st) == 0)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                       "brix: CMS state: have \"%s\", "
                       "replying kYR_have", safe);
        brix_cms_log_action(ctx->cycle->log, "state-probe",
                            (const char *) ctx->mgr_name.data,
                            "in", safe, 1, "file present on export -> kYR_have");
        return ngx_brix_cms_send_have(ctx, streamid, pathz, pl);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                   "brix: CMS state: do not have \"%s\"", safe);
    return NGX_OK;
}

/* cms_super_fan_down — Phase-61 W7: an explicit supervisor pushes a manager-
 * forwarded namespace op DOWN to its own logged-in data nodes instead of
 * executing it locally (supVOps marks these Forward in stock cmsd's
 * initSUProuting).  The Pup payload is decoded once and re-encoded per child
 * hop; rrdata spans are NUL-terminated in place on the wire, so they pass
 * straight through as C strings.  Silent toward the manager either way —
 * per-child failures are the child's to report on its own leg. */
ngx_int_t
cms_super_fan_down(ngx_brix_cms_ctx_t *ctx, u_char code,
    const u_char *payload, size_t plen)
{
    brix_cms_rrdata_t     rr;
    brix_cms_srv_ctx_t   *node;
    ngx_uint_t            i, sent;
    uint32_t              sid;

    if (brix_cms_rrdata_parse(code, payload, plen, &rr) != 0) {
        ngx_log_error(NGX_LOG_WARN, ctx->cycle->log, 0,
                      "brix: CMS super: malformed forwarded op=%ui — dropped",
                      (ngx_uint_t) code);
        return NGX_OK;
    }

    sid = brix_cms_srv_next_streamid();
    sent = 0;

    for (i = 0; i < brix_cms_srv_node_count(); i++) {
        node = brix_cms_srv_node_at(i);
        if (node == NULL || !node->logged_in || node->c == NULL) {
            continue;
        }
        if (brix_cms_forward_to_node(node->c, code, sid,
                                     (const char *) rr.ident,
                                     (const char *) rr.path,
                                     (const char *) rr.path2,
                                     (const char *) rr.mode,
                                     (const char *) rr.opaque) == NGX_OK)
        {
            sent++;
        }
    }

    if (sent == 0) {
        /* A forwarded op that reached nobody is a silently dropped op — the
         * one outcome of this function worth seeing without a debug build. */
        ngx_log_error(NGX_LOG_WARN, ctx->cycle->log, 0,
                      "brix: CMS super: forwarded op=%ui reached no node — "
                      "dropped", (ngx_uint_t) code);
    }
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                   "brix: CMS super: forwarded op=%ui down to %ui node(s)",
                   (ngx_uint_t) code, sent);
    return NGX_OK;
}
