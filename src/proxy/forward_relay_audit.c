/* File: proxy write-path audit — JSON-formatted operation logging
 * WHAT: Implements security audit logging for path modification operations during XRootD proxy forwarding. Writes JSON-formatted entries to configured proxy_audit_log_fd capturing operation type, path, destination (for mv ops), status result, and authenticated user identity. Only logs when both proxy config exists AND audit log file descriptor is valid (NGX_INVALID_FILE means disabled). Six supported operations: rm, mkdir, rmdir, mv, chmod, truncate — unrecognized opcodes skip logging via default case return. User identity sourced from client_ctx->login_user if available; empty string otherwise. JSON format follows structured pattern with type="path" field distinguishing from other audit categories (TPC, read/write). mv operations include separate "dest" field for destination path; all other ops use single "path" field. Each entry terminated with newline for line-oriented log consumption. Written via ngx_write_fd() to avoid blocking event loop during I/O. */

/* One of three standalone translation units split from the proxy relay path
 * (with forward_relay_response.c and forward_relay_dispatch.c); each is compiled
 * directly (registered in ./config). See forward.c for the design overview. */

#include "proxy_internal.h"
#include "../session/registry.h"

void
proxy_write_path_audit(xrootd_proxy_ctx_t *proxy, uint16_t status)
{
    ngx_stream_xrootd_srv_conf_t *conf = proxy->conf;
    const char  *op_str;
    const char  *status_str = (status == kXR_ok) ? "ok" : "error";
    const char  *user = "";
    u_char       buf[256 + XROOTD_PROXY_PATH_MAX * 2];
    u_char      *p;

    if (conf == NULL || conf->proxy_audit_log_fd == NGX_INVALID_FILE) {
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

    if (proxy->client_ctx != NULL && proxy->client_ctx->login_user[0] != '\0') {
        user = proxy->client_ctx->login_user;
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

    ngx_write_fd(conf->proxy_audit_log_fd, buf, (size_t)(p - buf));
}

