/*
 * WHAT: Format and write an access log line for every XRootD request. Produces a structured
 * one-line record containing client IP, authentication method, user identity (DN), timestamp,
 * verb/path/detail triple, result status (OK/ERR), byte count, and request duration in milliseconds.
 * All fields are sanitized through brix_sanitize_log_string() before inclusion in the log line.
 */

/* WHY: Every request must be observable for security auditing, capacity planning, and anomaly detection.
 * Access logs provide three critical data streams: (1) Security — authmethod+identity shows who accessed
 * what resources; (2) Operations — duration_ms enables SLA monitoring and performance trending; (3)
 * Capacity — bytes sent per op reveals bandwidth utilization patterns across protocols. Sanitization is
 * mandatory because wire protocol paths, error messages, and client addresses may contain arbitrary byte
 * sequences that would corrupt downstream log parsers (Prometheus exporters, ELK collectors). The 4096-byte
 * buffer accommodates the worst-case expanded sanitized output where each dangerous byte becomes a \xNN escape. */

/* HOW: Six-phase formatting pipeline. Phase 1: Extract client IP from c->addr_text or fallback to '-'.
 * Phase 2: Determine authmethod (gsi/sss/anon) and identity (ctx->login.dn or '-') based on server config + session state.
 * Phase 3: Format timestamp using ngx_timeofday() + strftime() in Apache-like "%d/%b/%Y:%H:%M:%S %z" format.
 * Phase 4: Compute request duration from ngx_current_msec - ctx->req_start with floor at zero (clock skew protection).
 * Phase 5: Sanitize ALL fields through brix_sanitize_log_string() — client_ip, identity, verb, path, detail, errmsg.
 * If error but no errmsg provided, generate "code:N" placeholder from errcode. Phase 6: Select line template based on
 * xrd_ok flag (OK or ERR variant), snprintf into 4096-byte buffer, write to conf->access_log_fd if valid. Early return
 * if access_log_fd == NGX_INVALID_FILE (logging disabled by config). */

#include "core/ngx_brix_module.h"
#include "core/compat/cstr.h"

#include <arpa/inet.h>
#include <time.h>

/*
 * Phase 33 C1 — per-worker access-log batch buffer.
 *
 * Previously every logged request did its own write(2).  Under high op rates
 * (steady reads) that syscall is the dominant per-request fixed cost when
 * logging is on.  The nginx stream worker is a single-threaded event loop, so a
 * single static buffer per worker needs no locking: lines accumulate and are
 * flushed with one write(2) on buffer-full, a target-fd switch, a 1s timer, and
 * connection close (brix_on_disconnect → brix_access_log_flush).  The log fd
 * is opened O_APPEND (src/config/runtime_server.c), so a batched multi-line
 * write stays atomic per call and interleaves cleanly with other workers.
 */
#define BRIX_ALOG_BUF_SIZE  (64 * 1024)

static u_char       brix_alog_buf[BRIX_ALOG_BUF_SIZE];
static size_t       brix_alog_len;
static ngx_fd_t     brix_alog_fd = NGX_INVALID_FILE;
static ngx_event_t  brix_alog_timer;
static ngx_uint_t   brix_alog_timer_set;

void
brix_access_log_flush(void)
{
    if (brix_alog_len > 0 && brix_alog_fd != NGX_INVALID_FILE) {
        (void) ngx_write_fd(brix_alog_fd, brix_alog_buf, brix_alog_len);
    }
    brix_alog_len = 0;
}

static void
brix_alog_timer_handler(ngx_event_t *ev)
{
    brix_alog_timer_set = 0;
    brix_access_log_flush();
}

/* Append one formatted line to the per-worker buffer, flushing as needed. */
static void
brix_alog_emit(ngx_fd_t fd, const char *line, size_t n)
{
    if (fd == NGX_INVALID_FILE || n == 0) {
        return;
    }

    /* Never let lines cross fds: if this line targets a different log than what
     * is buffered, flush the buffered run first, then adopt the new fd. */
    if (brix_alog_len > 0 && fd != brix_alog_fd) {
        brix_access_log_flush();
    }
    brix_alog_fd = fd;

    /* A line at least as large as the whole buffer can never be batched; flush
     * any pending run and write it directly so nothing is dropped/truncated. */
    if (n >= BRIX_ALOG_BUF_SIZE) {
        brix_access_log_flush();
        (void) ngx_write_fd(fd, (void *) line, n);
        return;
    }

    if (brix_alog_len + n > BRIX_ALOG_BUF_SIZE) {
        brix_access_log_flush();
    }
    ngx_memcpy(brix_alog_buf + brix_alog_len, line, n);
    brix_alog_len += n;

    /* Bound how long a buffered line waits on a low-rate connection.  The timer
     * fires once (no rearm here); the next append re-arms it.  A flush from any
     * other path before it fires just makes the eventual fire a no-op. */
    if (!brix_alog_timer_set) {
        brix_alog_timer.handler = brix_alog_timer_handler;
        brix_alog_timer.log = ngx_cycle->log;
        brix_alog_timer.data = NULL;
        ngx_add_timer(&brix_alog_timer, 1000);
        brix_alog_timer_set = 1;
    }
}

void
brix_log_access(brix_ctx_t *ctx, ngx_connection_t *c,
                  const char *verb, const char *path, const char *detail,
                  ngx_uint_t xrd_ok, uint16_t errcode, const char *errmsg,
                  size_t bytes)
{
    ngx_stream_brix_srv_conf_t *conf;
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

    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_brix_module);

    if (conf->access_log_fd == NGX_INVALID_FILE) {
        return;
    }

    if (c->addr_text.len == 0
        || brix_str_cbuf(client_ip, sizeof(client_ip), &c->addr_text) == NULL)
    {
        client_ip[0] = '-';
        client_ip[1] = '\0';
    }

    if (conf->auth == BRIX_AUTH_GSI) {
        authmethod = "gsi";
        identity = (ctx->login.dn[0] != '\0') ? ctx->login.dn : "-";
    } else if (conf->auth == BRIX_AUTH_SSS) {
        authmethod = "sss";
        identity = (ctx->login.dn[0] != '\0') ? ctx->login.dn : "-";
    } else if (conf->auth == BRIX_AUTH_UNIX) {
        authmethod = "unix";
        identity = (ctx->login.dn[0] != '\0') ? ctx->login.dn : "-";
    } else if (conf->auth == BRIX_AUTH_KRB5) {
        authmethod = "krb5";
        identity = (ctx->login.dn[0] != '\0') ? ctx->login.dn : "-";
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

    brix_sanitize_log_string(client_ip, safe_client_ip, sizeof(safe_client_ip));
    brix_sanitize_log_string(identity, safe_identity, sizeof(safe_identity));
    brix_sanitize_log_string(verb ? verb : "-", safe_verb, sizeof(safe_verb));
    brix_sanitize_log_string(path ? path : "-", safe_path, sizeof(safe_path));
    brix_sanitize_log_string(detail ? detail : "-", safe_detail, sizeof(safe_detail));
    brix_sanitize_log_string(errmsg ? errmsg : "-", safe_errmsg,
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
        brix_alog_emit(conf->access_log_fd, line, (size_t) n);
    }
}
