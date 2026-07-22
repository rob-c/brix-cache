#include "observability/sesslog/sesslog.h"
#include "protocols/root/protocol/opcodes.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char  *pos;
    size_t rem;
    size_t used;
} brix_sess_buf_t;

static const char *const brix_sess_proto_labels[] = {
    "root", "webdav", "s3", "cvmfs", "cms", "tpc", "fill"
};

static const char *const brix_sess_dir_labels[] = {
    "in", "out"
};

static const char *const brix_sess_am_labels[] = {
    "gsi", "token", "sss", "krb5", "pwd", "unix", "host", "sigv4",
    "anon"
};

static const char *const brix_sess_mode_labels[] = {
    "read", "write", "meta", "delete", "list", "copy"
};

static const char *const brix_sess_xfer_labels[] = {
    "complete", "aborted", "shutdown"
};

static const char *const brix_sess_end_labels[] = {
    "client-disconnect", "server-close", "timeout", "shutdown", "error"
};

/*
 * WHAT: Return the bounded string length for a possibly NULL C string.
 * WHY: Formatters accept caller-owned strings from wire paths and identities;
 * bounding before copies keeps stack scratch buffers finite.
 * HOW: Count bytes until NUL or max is reached, treating NULL as "-".
 */
static size_t
brix_sess_strnlen_or_dash(const char *s, size_t max)
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
 * WHAT: Default sanitizer used when unit callers pass NULL.
 * WHY: The formatter remains usable in pure C tests without linking the nginx
 * path helper; production glue injects the normal access-log sanitizer.
 * HOW: Escape quotes, backslashes, controls, DEL, and non-ASCII as \xNN.
 */
static size_t
brix_sess_default_sanitize(char *dst, size_t dst_size, const char *src,
    size_t src_len)
{
    static const char hex[] = "0123456789abcdef";
    size_t            di;
    size_t            si;

    if (dst_size == 0) {
        return 0;
    }

    if (src == NULL) {
        src = "-";
        src_len = 1;
    }

    di = 0;
    for (si = 0; si < src_len && di + 1 < dst_size; si++) {
        unsigned char ch = (unsigned char) src[si];

        if (ch == '"' || ch == '\\') {
            if (di + 2 >= dst_size) {
                break;
            }
            dst[di++] = '\\';
            dst[di++] = (char) ch;
            continue;
        }

        if (ch < 0x20 || ch >= 0x7f) {
            if (di + 4 >= dst_size) {
                break;
            }
            dst[di++] = '\\';
            dst[di++] = 'x';
            dst[di++] = hex[(ch >> 4) & 0x0f];
            dst[di++] = hex[ch & 0x0f];
            continue;
        }

        dst[di++] = (char) ch;
    }

    dst[di] = '\0';
    return di;
}

/*
 * WHAT: Append formatted text to a bounded line buffer.
 * WHY: Every event must remain one complete parseable line even when values are
 * long or malicious.
 * HOW: Advance the cursor only when snprintf reports data that fit.
 */
static void
brix_sess_append(brix_sess_buf_t *b, const char *fmt, ...)
{
    va_list ap;
    int     n;

    if (b->rem == 0) {
        return;
    }

    va_start(ap, fmt);
    /* phase74-fp: fmt is always a compile-time string literal — every caller of
     * this static varargs forwarder passes a literal format (audited; no table,
     * no user input reaches fmt). */
    n = vsnprintf(b->pos, b->rem, fmt, ap);  /* NOLINT(clang-diagnostic-format-nonliteral) */
    va_end(ap);

    if (n < 0) {
        return;
    }

    if ((size_t) n >= b->rem) {
        b->used += b->rem - 1;
        b->pos += b->rem - 1;
        b->rem = 1;
        b->pos[0] = '\0';
        return;
    }

    b->pos += n;
    b->rem -= (size_t) n;
    b->used += (size_t) n;
}

/*
 * WHAT: Append a fixed-order quoted field with sanitization.
 * WHY: Paths, users, VOs, peers, and errors can contain arbitrary wire bytes;
 * quoting them uniformly makes the session log split-safe.
 * HOW: Clip the raw value, preserve the fact of truncation with "...", sanitize,
 * and append key="value".
 */
static void
brix_sess_append_quoted(brix_sess_buf_t *b, const char *key, const char *value,
    size_t raw_cap, brix_sess_sanitize_fn san)
{
    char   clipped[BRIX_SESSLOG_PATH_MAX + 4];
    char   safe[BRIX_SESSLOG_PATH_MAX * 4 + 8];
    size_t src_len;
    size_t copy_len;
    size_t cap;

    if (raw_cap > BRIX_SESSLOG_PATH_MAX) {
        raw_cap = BRIX_SESSLOG_PATH_MAX;
    }
    if (raw_cap == 0) {
        raw_cap = 1;
    }

    if (value == NULL) {
        value = "-";
    }

    cap = raw_cap;
    src_len = brix_sess_strnlen_or_dash(value, cap + 1);
    copy_len = src_len;
    if (copy_len > cap) {
        copy_len = (cap > 3) ? cap - 3 : cap;
    }

    if (copy_len > 0) {
        memcpy(clipped, value, copy_len);
    }
    if (src_len > cap && cap > 3) {
        memcpy(clipped + copy_len, "...", 3);
        copy_len += 3;
    }
    clipped[copy_len] = '\0';

    if (san == NULL) {
        san = brix_sess_default_sanitize;
    }
    (void) san(safe, sizeof(safe), clipped, copy_len);
    brix_sess_append(b, " %s=\"%s\"", key, safe);
}

/*
 * WHAT: Initialize a formatter cursor and make even tiny buffers safe.
 * WHY: Public formatters should be NULL/tiny-buffer tolerant for tests and
 * defensive production callers.
 * HOW: Seed an empty string when there is room; all appends update rem/used.
 */
static brix_sess_buf_t
brix_sess_buf(char *line, size_t line_max)
{
    brix_sess_buf_t b;

    b.pos = line;
    b.rem = line_max;
    b.used = 0;
    if (line != NULL && line_max > 0) {
        line[0] = '\0';
    } else {
        b.rem = 0;
    }

    return b;
}

/*
 * WHAT: Compute a non-negative millisecond duration.
 * WHY: nginx's cached millisecond clock can appear to move backwards across
 * lifecycle observations on reload or coarse clock updates.
 * HOW: Clamp underflow to zero.
 */
static uint64_t
brix_sess_duration(uint64_t start_msec, uint64_t now_msec)
{
    if (now_msec < start_msec) {
        return 0;
    }

    return now_msec - start_msec;
}

/*
 * WHAT: Calculate integer bytes per second for an XFER line.
 * WHY: Operators need a grep-friendly transfer rate that cannot overflow on
 * large files.
 * HOW: Use 64-bit arithmetic and divide by max(duration, 1 ms).
 */
static uint64_t
brix_sess_rate(uint64_t bytes, uint64_t dur_ms)
{
    uint64_t divisor = dur_ms == 0 ? 1 : dur_ms;

    if (bytes > UINT64_MAX / 1000) {
        return UINT64_MAX / divisor;
    }

    return (bytes * 1000) / divisor;
}

const char *
brix_sesslog_proto_label(brix_sess_proto_t p)
{
    if (p < 0 || p >= BRIX_SESS_PROTO_MAX) {
        return "?";
    }
    return brix_sess_proto_labels[p];
}

const char *
brix_sesslog_dir_label(brix_sess_dir_t d)
{
    if (d < 0 || d > BRIX_SESS_DIR_OUT) {
        return "?";
    }
    return brix_sess_dir_labels[d];
}

const char *
brix_sesslog_am_label(brix_sess_am_t m)
{
    if (m < 0 || m >= BRIX_SESS_AM_MAX) {
        return "?";
    }
    return brix_sess_am_labels[m];
}

const char *
brix_sesslog_mode_label(brix_sess_mode_t m)
{
    if (m < 0 || m >= BRIX_SESS_MODE_MAX) {
        return "?";
    }
    return brix_sess_mode_labels[m];
}

const char *
brix_sesslog_xfer_label(brix_sess_xfer_status_t st)
{
    if (st < 0 || st > BRIX_SESS_XFER_SHUTDOWN) {
        return "?";
    }
    return brix_sess_xfer_labels[st];
}

const char *
brix_sesslog_end_label(brix_sess_end_t e)
{
    if (e < 0 || e > BRIX_SESS_END_ERROR) {
        return "?";
    }
    return brix_sess_end_labels[e];
}

size_t
brix_sesslog_fmt_connect(char *line, size_t line_max, const brix_sess_t *s,
    brix_sess_sanitize_fn san)
{
    brix_sess_buf_t b = brix_sess_buf(line, line_max);

    if (s == NULL) {
        return 0;
    }

    brix_sess_append(&b, "SESS %s CONNECT proto=%s dir=%s", s->id,
                     brix_sesslog_proto_label(s->proto),
                     brix_sesslog_dir_label(s->dir));
    brix_sess_append_quoted(&b, "peer", s->peer, BRIX_SESSLOG_PEER_MAX, san);
    brix_sess_append(&b, " authmethod=%s",
                     brix_sesslog_am_label(s->authmethod));
    if (s->parent[0] != '\0') {
        brix_sess_append(&b, " parent=%s", s->parent);
    }
    brix_sess_append(&b, "\n");

    return b.used;
}

size_t
brix_sesslog_fmt_auth(char *line, size_t line_max, const brix_sess_t *s,
    const brix_sesslog_auth_fields_t *f, brix_sess_sanitize_fn san)
{
    brix_sess_buf_t b = brix_sess_buf(line, line_max);

    if (s == NULL || f == NULL) {
        return 0;
    }

    brix_sess_append(&b, "SESS %s AUTH %s method=%s", s->id,
                     f->ok ? "ok" : "fail", brix_sesslog_am_label(f->method));
    brix_sess_append_quoted(&b, "user", f->user, BRIX_SESSLOG_USER_MAX, san);
    brix_sess_append_quoted(&b, "vo", f->vo, BRIX_SESSLOG_VO_MAX, san);
    if (!f->ok) {
        brix_sess_append_quoted(&b, "err", f->err != NULL ? f->err : "code:0",
                                BRIX_SESSLOG_ERR_MAX, san);
    }
    brix_sess_append(&b, "\n");

    return b.used;
}

size_t
brix_sesslog_fmt_attempt(char *line, size_t line_max, const brix_sess_t *s,
    const brix_sesslog_attempt_fields_t *f, brix_sess_sanitize_fn san)
{
    brix_sess_buf_t b = brix_sess_buf(line, line_max);

    if (s == NULL || f == NULL) {
        return 0;
    }

    brix_sess_append(&b, "SESS %s ATTEMPT", s->id);
    brix_sess_append_quoted(&b, "path", f->path, BRIX_SESSLOG_PATH_MAX, san);
    brix_sess_append(&b, " mode=%s\n", brix_sesslog_mode_label(f->mode));

    return b.used;
}

size_t
brix_sesslog_fmt_result(char *line, size_t line_max, const brix_sess_t *s,
    const brix_sesslog_result_fields_t *f, brix_sess_sanitize_fn san)
{
    brix_sess_buf_t b = brix_sess_buf(line, line_max);

    if (s == NULL || f == NULL) {
        return 0;
    }

    brix_sess_append(&b, "SESS %s RESULT %s", s->id, f->ok ? "ok" : "fail");
    brix_sess_append_quoted(&b, "path", f->path, BRIX_SESSLOG_PATH_MAX, san);
    brix_sess_append(&b, " mode=%s", brix_sesslog_mode_label(f->mode));
    if (!f->ok) {
        brix_sess_append_quoted(&b, "err", f->err != NULL ? f->err : "code:0",
                                BRIX_SESSLOG_ERR_MAX, san);
    }
    brix_sess_append(&b, "\n");

    return b.used;
}

size_t
brix_sesslog_fmt_xfer(char *line, size_t line_max, const brix_sess_t *s,
    const brix_sesslog_xfer_fields_t *f, brix_sess_sanitize_fn san)
{
    brix_sess_buf_t          b = brix_sess_buf(line, line_max);
    const brix_sess_xfer_t  *x;
    uint64_t                 dur;
    uint64_t                 avg;

    if (s == NULL || f == NULL || f->x == NULL) {
        return 0;
    }

    x = f->x;
    dur = brix_sess_duration(x->start_msec, f->now_msec);
    avg = brix_sess_rate(x->bytes, dur);

    brix_sess_append(&b, "SESS %s XFER %s", s->id,
                     brix_sesslog_xfer_label(f->st));
    brix_sess_append_quoted(&b, "path", x->path,
                            BRIX_SESSLOG_PENDING_PATH_MAX, san);
    brix_sess_append(&b, " mode=%s bytes=%llu/",
                     brix_sesslog_mode_label(x->mode),
                     (unsigned long long) x->bytes);
    if (x->expected >= 0) {
        brix_sess_append(&b, "%llu", (unsigned long long) x->expected);
    } else {
        brix_sess_append(&b, "-");
    }
    brix_sess_append(&b, " dur=%llu avg=%llu\n",
                     (unsigned long long) dur, (unsigned long long) avg);

    return b.used;
}

size_t
brix_sesslog_fmt_end(char *line, size_t line_max, const brix_sess_t *s,
    const brix_sesslog_end_fields_t *f, brix_sess_sanitize_fn san)
{
    brix_sess_buf_t b = brix_sess_buf(line, line_max);

    (void) san;
    if (s == NULL || f == NULL) {
        return 0;
    }

    brix_sess_append(&b, "SESS %s END reason=%s dur=%llu\n", s->id,
                     brix_sesslog_end_label(f->why),
                     (unsigned long long) brix_sess_duration(s->start_msec,
                                                             f->now_msec));

    return b.used;
}
