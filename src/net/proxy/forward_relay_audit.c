/*
 * File: proxy write-path audit — JSON-formatted operation logging
 *
 * WHAT:
 *   Implements security audit logging for path modification operations
 *   during XRootD proxy forwarding. Writes JSON-formatted entries to
 *   configured proxy_audit_log_fd.
 *
 * CAPTURED FIELDS:
 *   - Operation type (rm, mkdir, rmdir, mv, chmod, truncate)
 *   - Path (source for mv, single path for others)
 *   - Destination (mv operations only, "dest" field)
 *   - Status result ("ok" or "error")
 *   - Authenticated user identity (from client_ctx->login.user)
 *
 * LOGGING CONDITIONS:
 *   - Only logs when proxy config exists AND
 *   - proxy_audit_log_fd is valid (NGX_INVALID_FILE = disabled)
 *   - Unrecognized opcodes skip logging (default case return)
 *
 * JSON FORMAT:
 *   - type="path" distinguishes from other audit categories (TPC, read/write)
 *   - mv operations: {"type":"path","op":"mv","path":"...","dest":"...",...}
 *   - Other ops: {"type":"path","op":"<op>","path":"...",...}
 *   - Each entry terminated with newline for line-oriented consumption
 *
 * IMPLEMENTATION:
 *   - Written via ngx_write_fd() to avoid blocking event loop during I/O
 *   - User identity: client_ctx->login.user if available, empty string otherwise
 */

/* One of three standalone translation units split from the proxy relay path
 * (with forward_relay_response.c and forward_relay_dispatch.c); each is compiled
 * directly (registered in ./config). See forward.c for the design overview. */

#include "proxy_internal.h"
#include "protocols/root/session/registry.h"

void
proxy_write_path_audit(brix_proxy_ctx_t *proxy, uint16_t status)
{
    ngx_stream_brix_srv_conf_t *conf = proxy->conf;
    const char  *op_str;
    const char  *status_str = (status == kXR_ok) ? "ok" : "error";
    const char  *user = "";
    u_char       buf[256 + BRIX_PROXY_PATH_MAX * 2];
    u_char      *p;

    if (conf == NULL || conf->proxy.audit_log_fd == NGX_INVALID_FILE) {
        return;
    }

    switch (proxy->fwd_reqid) {
    case kXR_rm:       op_str = "rm";       break;
    case kXR_mkdir:    op_str = "mkdir";    break;
    case kXR_rmdir:    op_str = "rmdir";    break;
    case kXR_mv:       op_str = "mv";       break;
    case kXR_chmod:    op_str = "chmod";    break;
    case kXR_truncate: op_str = "truncate"; break;
    default: return;
    }

    if (proxy->client_ctx != NULL && proxy->client_ctx->login.user[0] != '\0') {
        user = proxy->client_ctx->login.user;
    }

    if (proxy->fwd_reqid == kXR_mv && proxy->fwd_path2[0] != '\0') {
        p = ngx_snprintf(buf, sizeof(buf) - 2,
            "{\"type\":\"path\",\"op\":\"%s\","
            "\"path\":\"%s\",\"dest\":\"%s\","
            "\"status\":\"%s\",\"user\":\"%s\"}\n",
            op_str, proxy->fwd_path, proxy->fwd_path2,
            status_str, user);
    } else {
        p = ngx_snprintf(buf, sizeof(buf) - 2,
            "{\"type\":\"path\",\"op\":\"%s\","
            "\"path\":\"%s\","
            "\"status\":\"%s\",\"user\":\"%s\"}\n",
            op_str, proxy->fwd_path, status_str, user);
    }

    ngx_write_fd(conf->proxy.audit_log_fd, buf, (size_t)(p - buf));
}

