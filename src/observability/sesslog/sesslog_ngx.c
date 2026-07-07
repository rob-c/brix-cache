#include "core/ngx_brix_module.h"
#include "observability/accesslog/access_log.h"
#include "observability/sesslog/sesslog_ngx.h"
#include "fs/path/path.h"

#include <inttypes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

static brix_sess_t  brix_sess_registry[BRIX_SESSLOG_REGISTRY_SLOTS];
static int          brix_sess_free_head = -1;
static ngx_uint_t   brix_sess_registry_ready;
static ngx_uint_t   brix_sess_full_warned;
static uint64_t     brix_sess_fallback_counter;

/*
 * WHAT: Return a bounded length for a possibly NULL string.
 * WHY: Glue stores short copies for teardown and transfer records, but the
 * caller may provide NULL or a much longer path.
 * HOW: Treat NULL as "-" and count until NUL or max bytes.
 */
static size_t
brix_sess_ngx_strnlen_or_dash(const char *s, size_t max)
{
    size_t n;

    if (s == NULL) {
        return 1;
    }

    for (n = 0; n < max && s[n] != '\0'; n++) {
        /* count only */
    }

    return n;
}

/*
 * WHAT: Initialize the fixed per-worker registry free list.
 * WHY: Session begin/end must be O(1) on the event loop and must never allocate.
 * HOW: Thread every BSS slot through registry_next once per worker.
 */
static void
brix_sess_registry_init(void)
{
    int i;

    if (brix_sess_registry_ready) {
        return;
    }

    for (i = 0; i < BRIX_SESSLOG_REGISTRY_SLOTS - 1; i++) {
        brix_sess_registry[i].registry_next = i + 1;
    }
    brix_sess_registry[BRIX_SESSLOG_REGISTRY_SLOTS - 1].registry_next = -1;
    brix_sess_free_head = 0;
    brix_sess_registry_ready = 1;
}

/*
 * WHAT: Copy a possibly non-NUL peer/path/id string into fixed session storage.
 * WHY: Teardown-synthesized RESULT and XFER lines need stable values after the
 * caller's request buffer has gone away.
 * HOW: Truncate with a terminal NUL; full untruncated values are still used by
 * immediate ATTEMPT/RESULT formatting at the call site.
 */
static void
brix_sess_copy_value(char *dst, size_t dst_size, const char *src,
    size_t src_len)
{
    size_t n;

    if (dst_size == 0) {
        return;
    }

    if (src == NULL || src_len == 0) {
        src = "-";
        src_len = 1;
    }

    n = src_len;
    if (n >= dst_size) {
        n = dst_size - 1;
    }
    if (n > 0) {
        ngx_memcpy(dst, src, n);
    }
    dst[n] = '\0';
}

/*
 * WHAT: Adapter from the existing access-log sanitizer to sesslog's len-aware
 * sanitizer signature.
 * WHY: The line grammar requires the same escaping policy as access_log.c.
 * HOW: Copy the bounded source into a temporary NUL-terminated buffer, then use
 * brix_sanitize_log_string().
 */
static size_t
brix_sess_sanitize_ngx(char *dst, size_t dst_size, const char *src,
    size_t src_len)
{
    char tmp[BRIX_SESSLOG_PATH_MAX + 4];
    size_t n;

    if (dst_size == 0) {
        return 0;
    }

    if (src == NULL) {
        src = "-";
        src_len = 1;
    }

    n = src_len;
    if (n >= sizeof(tmp)) {
        n = sizeof(tmp) - 1;
    }
    if (n > 0) {
        ngx_memcpy(tmp, src, n);
    }
    tmp[n] = '\0';

    return brix_sanitize_log_string(tmp, dst, dst_size);
}

/*
 * WHAT: Mint a 64-bit lowercase hex session-log ID.
 * WHY: Operators need a compact correlation key distinct from the wire-level
 * XRootD session id.
 * HOW: Prefer RAND_bytes(8); fall back to pid/random/monotonic counter if the
 * entropy source is unavailable.
 */
static void
brix_sess_mint_id(char id[BRIX_SESSLOG_ID_LEN + 1])
{
    uint64_t v = 0;

    if (RAND_bytes((unsigned char *) &v, sizeof(v)) != 1) {
        brix_sess_fallback_counter++;
        v = ((uint64_t) ngx_pid << 48)
            ^ ((uint64_t) ngx_random() << 16)
            ^ brix_sess_fallback_counter;
    }

    snprintf(id, BRIX_SESSLOG_ID_LEN + 1, "%016" PRIx64, v);
}

/*
 * WHAT: Emit one formatter-produced event through the existing batched writer.
 * WHY: Sesslog lines must share the access log's timestamp and fd semantics.
 * HOW: Prefix with brix_access_log_time_prefix() and call brix_alog_emit().
 */
static void
brix_sess_emit(brix_sess_t *s, const char *event, size_t event_len)
{
    char   line[BRIX_SESSLOG_LINE_MAX + 96];
    size_t prefix_len;

    if (s == NULL || !s->in_use || s->log_fd == NGX_INVALID_FILE
        || event == NULL || event_len == 0)
    {
        return;
    }

    prefix_len = brix_access_log_time_prefix(line, sizeof(line));
    if (prefix_len == 0 || prefix_len >= sizeof(line)) {
        return;
    }

    if (event_len > sizeof(line) - prefix_len) {
        event_len = sizeof(line) - prefix_len;
    }
    ngx_memcpy(line + prefix_len, event, event_len);
    brix_alog_emit((ngx_fd_t) s->log_fd, line, prefix_len + event_len);
}

/*
 * WHAT: Claim one registry slot for a new live session.
 * WHY: The event loop cannot allocate or lock in the accept hot path.
 * HOW: Pop the free list; return NULL and warn once if the registry is full.
 */
static brix_sess_t *
brix_sess_alloc(ngx_log_t *log)
{
    brix_sess_t *s;
    int          idx;
    int          next;

    brix_sess_registry_init();
    idx = brix_sess_free_head;
    if (idx < 0) {
        if (!brix_sess_full_warned) {
            if (log != NULL) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "sesslog: registry full (%d); further sessions "
                              "unlogged", BRIX_SESSLOG_REGISTRY_SLOTS);
            }
            brix_sess_full_warned = 1;
        }
        return NULL;
    }

    s = &brix_sess_registry[idx];
    next = s->registry_next;
    ngx_memzero(s, sizeof(*s));
    s->registry_next = -1;
    s->in_use = 1;
    brix_sess_free_head = next;

    return s;
}

/*
 * WHAT: Release a completed session slot.
 * WHY: Long-lived workers must recycle session state without heap churn.
 * HOW: Clear ownership-visible state and push the slot back onto the free list.
 */
static void
brix_sess_release(brix_sess_t *s)
{
    int idx;

    if (s == NULL) {
        return;
    }

    idx = (int) (s - brix_sess_registry);
    if (idx < 0 || idx >= BRIX_SESSLOG_REGISTRY_SLOTS) {
        return;
    }

    s->in_use = 0;
    s->xfers = NULL;
    s->pending_attempt = 0;
    s->registry_next = brix_sess_free_head;
    brix_sess_free_head = idx;
}

brix_sess_t *
brix_sess_begin(ngx_uint_t enabled, ngx_fd_t log_fd, brix_sess_proto_t proto,
    brix_sess_dir_t dir, const char *peer, size_t peer_len,
    brix_sess_am_t am, const brix_sess_t *parent)
{
    brix_sess_t *s;
    char         line[BRIX_SESSLOG_LINE_MAX];
    size_t       n;

    if (!enabled || log_fd == NGX_INVALID_FILE) {
        return NULL;
    }

    s = brix_sess_alloc(ngx_cycle != NULL ? ngx_cycle->log : NULL);
    if (s == NULL) {
        return NULL;
    }

    brix_sess_mint_id(s->id);
    s->proto = proto;
    s->dir = dir;
    s->authmethod = am;
    s->start_msec = (uint64_t) ngx_current_msec;
    s->log_fd = (int) log_fd;
    brix_sess_copy_value(s->peer, sizeof(s->peer), peer, peer_len);
    if (parent != NULL && parent->id[0] != '\0') {
        brix_sess_copy_value(s->parent, sizeof(s->parent), parent->id,
                             BRIX_SESSLOG_ID_LEN);
    }

    n = brix_sesslog_fmt_connect(line, sizeof(line), s,
                                 brix_sess_sanitize_ngx);
    brix_sess_emit(s, line, n);

    return s;
}

void
brix_sess_auth(brix_sess_t *s, int ok, brix_sess_am_t m, const char *user,
    const char *vo, const char *err)
{
    char   line[BRIX_SESSLOG_LINE_MAX];
    size_t n;

    if (s == NULL || !s->in_use || s->end_logged) {
        return;
    }

    n = brix_sesslog_fmt_auth(line, sizeof(line), s, ok, m,
                              user != NULL ? user : "-",
                              vo != NULL && vo[0] != '\0' ? vo : "-",
                              err, brix_sess_sanitize_ngx);
    brix_sess_emit(s, line, n);

    if (ok) {
        size_t user_len = brix_sess_ngx_strnlen_or_dash(user,
                                                        BRIX_SESSLOG_USER_MAX);
        s->auth_method_logged = m;
        s->auth_logged = 1;
        brix_sess_copy_value(s->user, sizeof(s->user), user, user_len);
    }
}

void
brix_sess_auth_once(brix_sess_t *s, brix_sess_am_t m, const char *user,
    const char *vo)
{
    char   candidate[BRIX_SESSLOG_USER_MAX];
    size_t user_len;

    if (s == NULL || !s->in_use || s->end_logged) {
        return;
    }

    user_len = brix_sess_ngx_strnlen_or_dash(user, BRIX_SESSLOG_USER_MAX);
    brix_sess_copy_value(candidate, sizeof(candidate), user, user_len);
    if (s->auth_logged && s->auth_method_logged == m
        && ngx_strncmp(candidate, s->user, sizeof(s->user)) == 0)
    {
        return;
    }

    brix_sess_auth(s, 1, m, user != NULL ? user : "-", vo, NULL);
}

void
brix_sess_attempt(brix_sess_t *s, const char *path, brix_sess_mode_t mode)
{
    char   line[BRIX_SESSLOG_LINE_MAX];
    size_t n;

    if (s == NULL || !s->in_use || s->end_logged) {
        return;
    }

    if (s->pending_attempt) {
        brix_sess_result(s, 0, s->pending_path, s->pending_mode,
                         "session-closed");
    }

    n = brix_sesslog_fmt_attempt(line, sizeof(line), s, path, mode,
                                 brix_sess_sanitize_ngx);
    brix_sess_emit(s, line, n);
    brix_sess_copy_value(s->pending_path, sizeof(s->pending_path),
                         path != NULL ? path : "-",
                         brix_sess_ngx_strnlen_or_dash(path,
                             BRIX_SESSLOG_PENDING_PATH_MAX));
    s->pending_mode = mode;
    s->pending_attempt = 1;
}

void
brix_sess_result(brix_sess_t *s, int ok, const char *path,
    brix_sess_mode_t mode, const char *err)
{
    char   line[BRIX_SESSLOG_LINE_MAX];
    size_t n;

    if (s == NULL || !s->in_use || s->end_logged) {
        return;
    }

    if (!s->pending_attempt) {
        return;
    }

    n = brix_sesslog_fmt_result(line, sizeof(line), s, ok,
                                path != NULL ? path : s->pending_path,
                                mode, err, brix_sess_sanitize_ngx);
    brix_sess_emit(s, line, n);
    s->pending_attempt = 0;
}

void
brix_sess_xfer_start(brix_sess_t *s, brix_sess_xfer_t *x, const char *path,
    brix_sess_mode_t mode, int64_t expected)
{
    if (s == NULL || x == NULL || !s->in_use || s->end_logged || x->active) {
        return;
    }

    ngx_memzero(x, sizeof(*x));
    brix_sess_copy_value(x->path, sizeof(x->path), path,
                         brix_sess_ngx_strnlen_or_dash(path,
                             BRIX_SESSLOG_PENDING_PATH_MAX));
    x->mode = mode;
    x->expected = expected;
    x->start_msec = (uint64_t) ngx_current_msec;
    x->active = 1;
    x->next = s->xfers;
    x->prevp = &s->xfers;
    if (s->xfers != NULL) {
        s->xfers->prevp = &x->next;
    }
    s->xfers = x;
}

void
brix_sess_xfer_add(brix_sess_xfer_t *x, uint64_t n)
{
    if (x == NULL || !x->active) {
        return;
    }
    x->bytes += n;
}

void
brix_sess_xfer_end(brix_sess_t *s, brix_sess_xfer_t *x,
    brix_sess_xfer_status_t st)
{
    char   line[BRIX_SESSLOG_LINE_MAX];
    size_t n;

    if (s == NULL || x == NULL || !s->in_use || s->end_logged || !x->active) {
        return;
    }

    n = brix_sesslog_fmt_xfer(line, sizeof(line), s, x, st,
                              (uint64_t) ngx_current_msec,
                              brix_sess_sanitize_ngx);
    brix_sess_emit(s, line, n);

    if (x->prevp != NULL) {
        *x->prevp = x->next;
    }
    if (x->next != NULL) {
        x->next->prevp = x->prevp;
    }
    x->next = NULL;
    x->prevp = NULL;
    x->active = 0;
}

void
brix_sess_end(brix_sess_t *s, brix_sess_end_t why)
{
    char                      line[BRIX_SESSLOG_LINE_MAX];
    size_t                    n;
    brix_sess_xfer_status_t   xfer_status;

    if (s == NULL || !s->in_use || s->end_logged) {
        return;
    }

    if (s->pending_attempt) {
        brix_sess_result(s, 0, s->pending_path, s->pending_mode,
                         "session-closed");
    }

    xfer_status = (why == BRIX_SESS_END_SHUTDOWN)
                  ? BRIX_SESS_XFER_SHUTDOWN : BRIX_SESS_XFER_ABORTED;
    while (s->xfers != NULL) {
        brix_sess_xfer_end(s, s->xfers, xfer_status);
    }

    n = brix_sesslog_fmt_end(line, sizeof(line), s, why,
                             (uint64_t) ngx_current_msec,
                             brix_sess_sanitize_ngx);
    brix_sess_emit(s, line, n);
    s->end_logged = 1;
    brix_sess_release(s);
}

void
brix_sesslog_shutdown_flush(void)
{
    int i;

    brix_sess_registry_init();
    for (i = 0; i < BRIX_SESSLOG_REGISTRY_SLOTS; i++) {
        if (brix_sess_registry[i].in_use
            && !brix_sess_registry[i].end_logged)
        {
            brix_sess_end(&brix_sess_registry[i], BRIX_SESS_END_SHUTDOWN);
        }
    }

    brix_access_log_flush();
}

brix_sess_am_t
brix_sess_am_from_stream_auth(ngx_uint_t auth)
{
    switch (auth) {
    case BRIX_AUTH_GSI:
    case BRIX_AUTH_BOTH:
        return BRIX_SESS_AM_GSI;
    case BRIX_AUTH_TOKEN:
        return BRIX_SESS_AM_TOKEN;
    case BRIX_AUTH_SSS:
        return BRIX_SESS_AM_SSS;
    case BRIX_AUTH_KRB5:
        return BRIX_SESS_AM_KRB5;
    case BRIX_AUTH_PWD:
        return BRIX_SESS_AM_PWD;
    case BRIX_AUTH_UNIX:
        return BRIX_SESS_AM_UNIX;
    case BRIX_AUTH_HOST:
        return BRIX_SESS_AM_HOST;
    default:
        return BRIX_SESS_AM_ANON;
    }
}

const char *
brix_sess_id(const brix_sess_t *s)
{
    if (s == NULL || !s->in_use) {
        return NULL;
    }

    return s->id;
}
