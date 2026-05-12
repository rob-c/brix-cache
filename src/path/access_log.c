#include "../ngx_xrootd_module.h"

#include <arpa/inet.h>
#include <time.h>

void
xrootd_log_access(xrootd_ctx_t *ctx, ngx_connection_t *c,
                  const char *verb, const char *path, const char *detail,
                  ngx_uint_t xrd_ok, uint16_t errcode, const char *errmsg,
                  size_t bytes)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    ngx_msec_int_t                duration_ms;
    char                          line[4096];
    int                           n;
    const char                   *authmethod;
    const char                   *identity;
    char                          client_ip[INET6_ADDRSTRLEN + 8];
    char                          safe_client_ip[128];
    char                          safe_identity[1024];
    char                          safe_verb[64];
    char                          safe_path[1024];
    char                          safe_detail[512];
    char                          safe_errmsg[1024];
    ngx_time_t                   *tp;
    struct tm                     tm;
    char                          timebuf[64];
    char                          errbuf[64];

    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_xrootd_module);

    if (conf->access_log_fd == NGX_INVALID_FILE) {
        return;
    }

    if (c->addr_text.len > 0 && c->addr_text.len < sizeof(client_ip)) {
        ngx_memcpy(client_ip, c->addr_text.data, c->addr_text.len);
        client_ip[c->addr_text.len] = '\0';
    } else {
        client_ip[0] = '-';
        client_ip[1] = '\0';
    }

    if (conf->auth == XROOTD_AUTH_GSI) {
        authmethod = "gsi";
        identity = (ctx->dn[0] != '\0') ? ctx->dn : "-";
    } else if (conf->auth == XROOTD_AUTH_SSS) {
        authmethod = "sss";
        identity = (ctx->dn[0] != '\0') ? ctx->dn : "-";
    } else {
        authmethod = "anon";
        identity = "-";
    }

    tp = ngx_timeofday();
    ngx_libc_localtime(tp->sec, &tm);
    strftime(timebuf, sizeof(timebuf), "%d/%b/%Y:%H:%M:%S %z", &tm);

    duration_ms = (ngx_msec_int_t) (ngx_current_msec - ctx->req_start);
    if (duration_ms < 0) {
        duration_ms = 0;
    }

    if (!xrd_ok && errmsg == NULL) {
        snprintf(errbuf, sizeof(errbuf), "code:%u", (unsigned) errcode);
        errmsg = errbuf;
    }

    xrootd_sanitize_log_string(client_ip, safe_client_ip, sizeof(safe_client_ip));
    xrootd_sanitize_log_string(identity, safe_identity, sizeof(safe_identity));
    xrootd_sanitize_log_string(verb ? verb : "-", safe_verb, sizeof(safe_verb));
    xrootd_sanitize_log_string(path ? path : "-", safe_path, sizeof(safe_path));
    xrootd_sanitize_log_string(detail ? detail : "-", safe_detail, sizeof(safe_detail));
    xrootd_sanitize_log_string(errmsg ? errmsg : "-", safe_errmsg,
                               sizeof(safe_errmsg));

    if (xrd_ok) {
        n = snprintf(line, sizeof(line),
                     "%s %s \"%s\" [%s] \"%s %s %s\" OK %zu %dms\n",
                     safe_client_ip, authmethod, safe_identity, timebuf,
                     safe_verb, safe_path, safe_detail, bytes,
                     (int) duration_ms);
    } else {
        n = snprintf(line, sizeof(line),
                     "%s %s \"%s\" [%s] \"%s %s %s\" ERR %zu %dms \"%s\"\n",
                     safe_client_ip, authmethod, safe_identity, timebuf,
                     safe_verb, safe_path, safe_detail, bytes,
                     (int) duration_ms, safe_errmsg);
    }

    if (n > 0 && (size_t) n < sizeof(line)) {
        (void) ngx_write_fd(conf->access_log_fd, line, (size_t) n);
    }
}
