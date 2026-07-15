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
#include "observability/accesslog/access_log.h"
#include "observability/sesslog/sesslog_ngx.h"

#include <arpa/inet.h>
#include <string.h>
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

/*
 * WHAT: Render the access-log timestamp prefix shared by request and session
 * logs.
 * WHY: SESS records must be grep-compatible with the existing access-log
 * convention and must not drift from it over time.
 * HOW: Use nginx's cached time and the same strftime pattern access_log.c has
 * used for request records, wrapping it as "[timestamp] ".
 */
size_t
brix_access_log_time_prefix(char *dst, size_t dst_size)
{
    ngx_time_t *tp;
    struct tm   tm;
    char        timebuf[64];
    int         n;

    if (dst == NULL || dst_size == 0) {
        return 0;
    }

    tp = ngx_timeofday();
    ngx_libc_localtime(tp->sec, &tm);
    if (strftime(timebuf, sizeof(timebuf), "%d/%b/%Y:%H:%M:%S %z", &tm) == 0) {
        /* On failure the buffer contents are unspecified — emit an empty
         * timestamp rather than garbage (cannot happen with a 64-byte buf). */
        timebuf[0] = '\0';
    }

    n = snprintf(dst, dst_size, "[%s] ", timebuf);
    if (n <= 0 || (size_t) n >= dst_size) {
        dst[0] = '\0';
        return 0;
    }

    return (size_t) n;
}

/* Append one formatted line to the per-worker buffer, flushing as needed. */
void
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
        /* Shared dummy connection (src/core/config/process.c): nginx's
         * --with-debug timer-expiry log reads ngx_event_ident(ev->data)->fd, so a
         * connection-less timer must not leave ev->data NULL (worker SIGSEGV). */
        extern ngx_connection_t brix_maint_timer_conn;
        brix_alog_timer.handler = brix_alog_timer_handler;
        brix_alog_timer.log = ngx_cycle->log;
        brix_alog_timer.data = &brix_maint_timer_conn;
        ngx_add_timer(&brix_alog_timer, 1000);
        brix_alog_timer_set = 1;
    }
}

static ngx_flag_t
brix_access_streq(const char *a, const char *b)
{
    return a != NULL && b != NULL && ngx_strcmp(a, b) == 0;
}

static ngx_flag_t
brix_access_contains(const char *s, const char *needle)
{
    return s != NULL && needle != NULL && strstr(s, needle) != NULL;
}

/*
 * WHAT: Convert the legacy access-log auth detail into a sesslog auth method.
 * WHY: Existing root auth handlers already log AUTH records; piggybacking those
 * calls keeps method-specific auth code untouched.
 * HOW: Prefer the detail token when it names a method, otherwise derive from
 * the authenticated ctx/config state.
 */
static brix_sess_am_t
brix_access_sess_auth_method(brix_ctx_t *ctx,
    ngx_stream_brix_srv_conf_t *conf, const char *detail)
{
    if (brix_access_streq(detail, "gsi")) {
        return BRIX_SESS_AM_GSI;
    }
    if (brix_access_streq(detail, "ztn") || brix_access_streq(detail, "token")) {
        return BRIX_SESS_AM_TOKEN;
    }
    if (brix_access_streq(detail, "sss")) {
        return BRIX_SESS_AM_SSS;
    }
    if (brix_access_streq(detail, "krb5")) {
        return BRIX_SESS_AM_KRB5;
    }
    if (brix_access_streq(detail, "pwd")) {
        return BRIX_SESS_AM_PWD;
    }
    if (brix_access_streq(detail, "unix")) {
        return BRIX_SESS_AM_UNIX;
    }
    if (brix_access_streq(detail, "host")) {
        return BRIX_SESS_AM_HOST;
    }
    if (ctx != NULL && ctx->token.auth) {
        return BRIX_SESS_AM_TOKEN;
    }
    return brix_sess_am_from_stream_auth(conf != NULL ? conf->auth
                                                      : BRIX_AUTH_NONE);
}

/*
 * WHAT: Collapse method-specific auth messages into stable sesslog err tokens.
 * WHY: AUTH failure text is deliberately human-readable and inconsistent; the
 * session grammar requires a small closed token set.
 * HOW: Preserve high-signal substrings where available and fall back to kXR
 * status mapping.
 */
static const char *
brix_access_sess_auth_err(uint16_t errcode, const char *errmsg, char *scratch,
    size_t scratch_size)
{
    if (brix_access_contains(errmsg, "scope")) {
        return "scope";
    }
    if (brix_access_contains(errmsg, "expired")) {
        return "expired-cert";
    }
    if (brix_access_contains(errmsg, "signature")
        || brix_access_contains(errmsg, "validation")
        || brix_access_contains(errmsg, "verification")
        || brix_access_contains(errmsg, "decrypt"))
    {
        return "bad-signature";
    }
    if (brix_access_contains(errmsg, "rate limit")) {
        return "busy";
    }
    if (brix_access_contains(errmsg, "not authorized")
        || brix_access_contains(errmsg, "denied"))
    {
        return "permission";
    }

    return brix_sesslog_err_from_kxr((int) errcode, scratch, scratch_size);
}

/*
 * WHAT: Static verb→sesslog-mode mapping for the fixed-mode namespace verbs.
 * WHY: The mode assignment for these verbs is a pure lookup; expressing it as a
 * data table (rather than an if/else ladder) keeps the classifier flat and makes
 * adding a verb a one-row edit (coding-standards §8.6, table-driven dispatch).
 * HOW: One row per verb naming its sesslog mode. OPEN is deliberately absent —
 * its mode depends on the detail token and is resolved separately.
 */
typedef struct {
    const char       *verb;
    brix_sess_mode_t  mode;
} brix_access_verb_mode_t;

static const brix_access_verb_mode_t  brix_access_verb_modes[] = {
    { "STAT",     BRIX_SESS_MODE_META },
    { "STATX",    BRIX_SESS_MODE_META },
    { "LOCATE",   BRIX_SESS_MODE_META },
    { "QUERY",    BRIX_SESS_MODE_META },
    { "SET",      BRIX_SESS_MODE_META },
    { "READLINK", BRIX_SESS_MODE_META },
    { "DIRLIST",  BRIX_SESS_MODE_LIST },
    { "RM",       BRIX_SESS_MODE_DELETE },
    { "RMDIR",    BRIX_SESS_MODE_DELETE },
    { "DELETE",   BRIX_SESS_MODE_DELETE },
    { "MKDIR",    BRIX_SESS_MODE_WRITE },
    { "MV",       BRIX_SESS_MODE_WRITE },
    { "TRUNCATE", BRIX_SESS_MODE_WRITE },
    { "CHMOD",    BRIX_SESS_MODE_WRITE },
    { "SETATTR",  BRIX_SESS_MODE_WRITE },
    { "LINK",     BRIX_SESS_MODE_WRITE },
    { "SYMLINK",  BRIX_SESS_MODE_WRITE },
};

/*
 * WHAT: Resolve an OPEN verb to its sesslog mode from the detail token.
 * WHY: OPEN is the one namespace verb whose direction (read vs write) is not
 * fixed by the verb name — write/staging/tpc-pull opens count as WRITE, every
 * other open as READ.
 * HOW: Inspect the detail substring; return WRITE for any write-shaped open,
 * READ otherwise. Behavior identical to the former inline OPEN branch.
 */
static brix_sess_mode_t
brix_access_open_mode(const char *detail)
{
    if (brix_access_contains(detail, "wr")
        || brix_access_contains(detail, "staging")
        || brix_access_contains(detail, "tpc-pull"))
    {
        return BRIX_SESS_MODE_WRITE;
    }
    return BRIX_SESS_MODE_READ;
}

/*
 * WHAT: Map root access-log verbs to sesslog access modes.
 * WHY: The legacy access logger is already present on namespace-operation exits;
 * this table lets it produce uniform ATTEMPT/RESULT pairs without touching every
 * handler in the root plane.
 * HOW: OPEN resolves via detail (brix_access_open_mode); every other namespace
 * verb is a row lookup in brix_access_verb_modes. Lifecycle and pure I/O verbs
 * match nothing and return 0 (they aggregate into AUTH, XFER, or END).
 */
static ngx_flag_t
brix_access_sess_mode(const char *verb, const char *detail,
    brix_sess_mode_t *mode)
{
    size_t  i;

    if (verb == NULL || mode == NULL) {
        return 0;
    }

    if (brix_access_streq(verb, "OPEN")) {
        *mode = brix_access_open_mode(detail);
        return 1;
    }

    for (i = 0; i < sizeof(brix_access_verb_modes)
                    / sizeof(brix_access_verb_modes[0]); i++)
    {
        if (brix_access_streq(verb, brix_access_verb_modes[i].verb)) {
            *mode = brix_access_verb_modes[i].mode;
            return 1;
        }
    }

    return 0;
}

/*
 * WHAT: File-local descriptor of one access-log event to be mirrored into the
 * sesslog lifecycle.
 * WHY: The mirror entry point needs the raw (un-sanitized) request fields;
 * grouping them into one struct keeps brix_access_maybe_sesslog under the
 * parameter gate without altering what it consumes.
 * HOW: Populated once in brix_log_access from its own arguments and passed by
 * const pointer to the mirror helper and its AUTH/namespace sub-helpers.
 */
typedef struct {
    const char  *verb;
    const char  *path;
    const char  *detail;
    ngx_uint_t   xrd_ok;
    uint16_t     errcode;
    const char  *errmsg;
} brix_access_event_t;

/*
 * WHAT: Emit the sesslog AUTH event for an AUTH access-log record.
 * WHY: Keeps the AUTH-specific method/identity/err derivation out of the mirror
 * dispatcher so each stays single-purpose.
 * HOW: On success pass DN/VO (or "-"); on failure derive a stable err token.
 */
static void
brix_access_sesslog_auth(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *conf,
    const brix_access_event_t *ev)
{
    char         errscratch[64];
    const char  *err;

    err = ev->xrd_ok ? NULL
                     : brix_access_sess_auth_err(ev->errcode, ev->errmsg,
                                                 errscratch, sizeof(errscratch));
    brix_sess_auth(ctx->sess, ev->xrd_ok,
                   brix_access_sess_auth_method(ctx, conf, ev->detail),
                   ev->xrd_ok && ctx->login.dn[0] != '\0'
                       ? ctx->login.dn : "-",
                   ev->xrd_ok && ctx->login.primary_vo[0] != '\0'
                       ? ctx->login.primary_vo : "-",
                   err);
}

/*
 * WHAT: Emit the sesslog ATTEMPT/RESULT pair for a namespace access-log record.
 * WHY: Isolates the namespace-verb path (mode classification + attempt/result)
 * from the AUTH path in the dispatcher.
 * HOW: Classify the verb into a mode; ignore verbs with no mode; otherwise emit
 * ATTEMPT then RESULT with a derived err token on failure.
 */
static void
brix_access_sesslog_namespace(brix_ctx_t *ctx, const brix_access_event_t *ev)
{
    char              errscratch[64];
    brix_sess_mode_t  mode = 0;
    const char       *err;
    const char       *path;

    if (!brix_access_sess_mode(ev->verb, ev->detail, &mode)) {
        return;
    }

    err = ev->xrd_ok ? NULL
                     : brix_sesslog_err_from_kxr((int) ev->errcode, errscratch,
                                                 sizeof(errscratch));
    path = ev->path != NULL ? ev->path : "-";
    brix_sess_attempt(ctx->sess, path, mode);
    brix_sess_result(ctx->sess, ev->xrd_ok, path, mode, err);
}

/*
 * WHAT: Mirror selected legacy access-log calls into the sesslog lifecycle.
 * WHY: Root handlers already have well-audited success/error exits; using this
 * chokepoint gives root:// ATTEMPT/RESULT and AUTH coverage with minimal risk.
 * HOW: AUTH emits auth events; namespace verbs emit immediate ATTEMPT followed
 * by RESULT; pure data I/O is intentionally ignored and summarized by XFER.
 */
static void
brix_access_maybe_sesslog(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *conf,
    const brix_access_event_t *ev)
{
    if (ctx == NULL || ctx->sess == NULL || ev->verb == NULL) {
        return;
    }

    if (brix_access_streq(ev->verb, "AUTH")) {
        brix_access_sesslog_auth(ctx, conf, ev);
        return;
    }

    brix_access_sesslog_namespace(ctx, ev);
}

/*
 * WHAT: Static auth-mode → access-log method-label mapping.
 * WHY: The access-log "authmethod" token for each authenticated mode is a fixed
 * string; a table keeps the resolver flat and colocates the label set.
 * HOW: One row per authenticated brix_auth mode. Modes absent from the table
 * (anonymous/none) fall through to the "anon" default in the resolver.
 */
typedef struct {
    ngx_uint_t   auth;
    const char  *label;
} brix_access_authlabel_t;

static const brix_access_authlabel_t  brix_access_authlabels[] = {
    { BRIX_AUTH_GSI,  "gsi" },
    { BRIX_AUTH_SSS,  "sss" },
    { BRIX_AUTH_UNIX, "unix" },
    { BRIX_AUTH_KRB5, "krb5" },
};

/*
 * WHAT: File-local record carrying the fully-prepared fields of one access-log
 * line between the compute helpers and the formatter.
 * WHY: brix_log_access has a frozen 9-param public signature; threading the
 * derived state through an internal struct (rather than a dozen locals) keeps
 * each helper below the complexity gate without touching the extern.
 * HOW: Populated by the resolve/sanitize helpers, then consumed read-only by
 * brix_access_format_line. All char buffers are sized for the sanitized worst
 * case, matching the original inline buffers exactly.
 */
typedef struct {
    const char      *authmethod;
    char             timebuf[64];
    ngx_msec_int_t   duration_ms;
    size_t           bytes;
    ngx_uint_t       xrd_ok;
    char             safe_client_ip[128];
    char             safe_identity[1024];
    char             safe_verb[64];
    char             safe_path[1024];
    char             safe_detail[512];
    char             safe_errmsg[1024];
} brix_alog_record_t;

/*
 * WHAT: Resolve the access-log auth-method label and identity string for a
 * request from the server auth mode and login state.
 * WHY: Isolating this lookup keeps the orchestrator flat and expresses the
 * fixed-label modes as a data table (coding-standards §8.6).
 * HOW: Table lookup on conf->auth for the label; identity is the login DN when
 * present. Any mode not in the table is anonymous → "anon"/"-".
 */
static void
brix_access_resolve_identity(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *conf,
    const char **authmethod, const char **identity)
{
    size_t  i;

    for (i = 0; i < sizeof(brix_access_authlabels)
                    / sizeof(brix_access_authlabels[0]); i++)
    {
        if (conf->auth == brix_access_authlabels[i].auth) {
            *authmethod = brix_access_authlabels[i].label;
            *identity = (ctx->login.dn[0] != '\0') ? ctx->login.dn : "-";
            return;
        }
    }

    *authmethod = "anon";
    *identity = "-";
}

/*
 * WHAT: Render the bare access-log timestamp into dst.
 * WHY: brix_log_access emits the timestamp inside its own "[...]" template (not
 * the "[ts] " prefix form), so it needs the unwrapped strftime output.
 * HOW: Cached nginx time + the shared strftime pattern; empty string on the
 * (unreachable, 64-byte-buffer) strftime failure, matching prior behavior.
 */
static void
brix_access_format_time(char *dst, size_t dst_size)
{
    ngx_time_t *tp;
    struct tm   tm;

    tp = ngx_timeofday();
    ngx_libc_localtime(tp->sec, &tm);
    if (strftime(dst, dst_size, "%d/%b/%Y:%H:%M:%S %z", &tm) == 0) {
        /* On failure the buffer contents are unspecified — emit an empty
         * timestamp rather than garbage (cannot happen with a 64-byte buf). */
        dst[0] = '\0';
    }
}

/*
 * WHAT: File-local bundle of the raw (un-sanitized) string fields of one
 * access-log record.
 * WHY: Lets the sanitize helper take one input group and one output record,
 * keeping it under the parameter gate.
 * HOW: client_ip/identity are already normalized to non-NULL; verb/path/detail/
 * errmsg may be NULL and are mapped to "-" during sanitization.
 */
typedef struct {
    const char  *client_ip;
    const char  *identity;
    const char  *verb;
    const char  *path;
    const char  *detail;
    const char  *errmsg;
} brix_access_raw_t;

/*
 * WHAT: Sanitize every wire-derived field of one request into the record's safe
 * buffers.
 * WHY: Wire paths/messages/addresses may carry arbitrary bytes that would
 * corrupt downstream log parsers; sanitization is mandatory before formatting.
 * HOW: Each field passes through brix_sanitize_log_string into its own
 * fixed-size buffer, NULLs mapped to "-", identical to the former inline block.
 */
static void
brix_access_sanitize_fields(brix_alog_record_t *rec,
    const brix_access_raw_t *raw)
{
    brix_sanitize_log_string(raw->client_ip, rec->safe_client_ip,
                             sizeof(rec->safe_client_ip));
    brix_sanitize_log_string(raw->identity, rec->safe_identity,
                             sizeof(rec->safe_identity));
    brix_sanitize_log_string(raw->verb ? raw->verb : "-", rec->safe_verb,
                             sizeof(rec->safe_verb));
    brix_sanitize_log_string(raw->path ? raw->path : "-", rec->safe_path,
                             sizeof(rec->safe_path));
    brix_sanitize_log_string(raw->detail ? raw->detail : "-", rec->safe_detail,
                             sizeof(rec->safe_detail));
    brix_sanitize_log_string(raw->errmsg ? raw->errmsg : "-", rec->safe_errmsg,
                             sizeof(rec->safe_errmsg));
}

/*
 * WHAT: Format the final access-log line from a fully-prepared record.
 * WHY: The OK/ERR line templates are byte-frozen (tests grep them); keeping the
 * formatting in one leaf helper isolates the frozen format strings.
 * HOW: Select the OK or ERR template on rec->xrd_ok and snprintf into line.
 * Returns snprintf's result (negative on error, >= dst_size on truncation).
 */
static int
brix_access_format_line(const brix_alog_record_t *rec, char *line,
    size_t line_size)
{
    if (rec->xrd_ok) {
        return snprintf(line, line_size,
                        "%s %s \"%s\" [%s] \"%s %s %s\" OK %zu %dms\n",
                        rec->safe_client_ip, rec->authmethod,
                        rec->safe_identity, rec->timebuf, rec->safe_verb,
                        rec->safe_path, rec->safe_detail, rec->bytes,
                        (int) rec->duration_ms);
    }

    return snprintf(line, line_size,
                    "%s %s \"%s\" [%s] \"%s %s %s\" ERR %zu %dms \"%s\"\n",
                    rec->safe_client_ip, rec->authmethod, rec->safe_identity,
                    rec->timebuf, rec->safe_verb, rec->safe_path,
                    rec->safe_detail, rec->bytes, (int) rec->duration_ms,
                    rec->safe_errmsg);
}

void
brix_log_access(brix_ctx_t *ctx, ngx_connection_t *c,
                  const char *verb, const char *path, const char *detail,
                  ngx_uint_t xrd_ok, uint16_t errcode, const char *errmsg,
                  size_t bytes)
{
    ngx_stream_brix_srv_conf_t *conf;
    brix_alog_record_t            rec = {0};
    char                          line[4096];
    int                           n;
    const char                   *identity;
    char                          client_ip[INET6_ADDRSTRLEN + 8];
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

    brix_access_resolve_identity(ctx, conf, &rec.authmethod, &identity);
    brix_access_format_time(rec.timebuf, sizeof(rec.timebuf));

    rec.duration_ms = (ngx_msec_int_t) (ngx_current_msec - ctx->req_start);
    if (rec.duration_ms < 0) {
        rec.duration_ms = 0;
    }
    rec.bytes = bytes;
    rec.xrd_ok = xrd_ok;

    if (!xrd_ok && errmsg == NULL) {
        snprintf(errbuf, sizeof(errbuf), "code:%u", (unsigned) errcode);
        errmsg = errbuf;
    }

    {
        brix_access_event_t  ev = {
            .verb = verb, .path = path, .detail = detail,
            .xrd_ok = xrd_ok, .errcode = errcode, .errmsg = errmsg
        };
        brix_access_maybe_sesslog(ctx, conf, &ev);
    }

    {
        brix_access_raw_t  raw = {
            .client_ip = client_ip, .identity = identity, .verb = verb,
            .path = path, .detail = detail, .errmsg = errmsg
        };
        brix_access_sanitize_fields(&rec, &raw);
    }

    n = brix_access_format_line(&rec, line, sizeof(line));

    if (n > 0 && (size_t) n < sizeof(line)) {
        brix_alog_emit(conf->access_log_fd, line, (size_t) n);
    }
}
