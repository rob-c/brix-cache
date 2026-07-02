#include "access_log.h"

/*
 * access_log.c — structured JSON access-log line emitter for VFS operations.
 *
 * WHAT: Emits one machine-parsable JSON access record per completed VFS I/O
 *       operation via xrootd_access_log_emit(). Each line carries timestamp,
 *       protocol, op name, request path, byte count, offset, latency, error
 *       status, cache-hit flag, auth method, and the authenticated subject/DN.
 * WHY:  Prometheus counters are aggregate and low-cardinality (no paths or DNs
 *       as labels — INVARIANT #8), but operators still need per-request audit
 *       detail. A JSON log line carries the high-cardinality fields (path,
 *       subject) that must never become metric labels, while reusing the same
 *       unified vocabulary (xrootd_metric_proto_name / _op_name / _err_name /
 *       _auth_method_name) so logs and metrics line up.
 * HOW:  The line is written with ngx_log_error at NGX_LOG_INFO and prefixed
 *       "xrootd_access_json: " so a log pipeline can grep and strip the prefix.
 *       Free-text fields are run through xrootd_access_json_escape() into fixed
 *       stack buffers before being interpolated, so untrusted wire bytes can
 *       never break out of the JSON string. Subject is taken from the identity
 *       (subject, falling back to DN); path/offset/cache come from the
 *       xrootd_vfs_io_result_t when present.
 */

/*
 * xrootd_access_json_escape — copy src into dst as a JSON-string-safe sequence.
 *
 * Escapes '"' and '\\' with a backslash and renders any byte outside printable
 * ASCII (< 0x20 or >= 0x7f) as a \u00NN escape, so control bytes and non-ASCII
 * from the wire cannot terminate the surrounding JSON string. Always writes a
 * NUL terminator (unless dstsz == 0) and never exceeds dstsz, truncating cleanly
 * if an escape sequence would not fit.
 */
static void
xrootd_access_json_escape(const char *src, char *dst, size_t dstsz)
{
    static const char hex[] = "0123456789abcdef";
    size_t            used;

    if (dstsz == 0) {
        return;
    }

    used = 0;
    if (src == NULL) {
        src = "";
    }

    while (*src != '\0' && used + 1 < dstsz) {
        unsigned char ch = (unsigned char) *src++;

        if (ch == '"' || ch == '\\') {
            if (used + 2 >= dstsz) {
                break;
            }
            dst[used++] = '\\';
            dst[used++] = (char) ch;
            continue;
        }

        if (ch >= 0x20 && ch < 0x7f) {
            dst[used++] = (char) ch;
            continue;
        }

        if (used + 6 >= dstsz) {
            break;
        }
        dst[used++] = '\\';
        dst[used++] = 'u';
        dst[used++] = '0';
        dst[used++] = '0';
        dst[used++] = hex[ch >> 4];
        dst[used++] = hex[ch & 0x0f];
    }

    dst[used] = '\0';
}

/*
 * xrootd_access_log_emit — write one JSON access-log record for a VFS op.
 *
 * Pulls protocol/auth/subject from ctx, path/offset/cache-hit from result (when
 * non-NULL), escapes the free-text fields, and emits a single NGX_LOG_INFO line.
 * No-op if ctx or ctx->log is NULL. bytes, err, and latency_usec are supplied by
 * the caller because they describe the just-finished operation, not the handle.
 */
void
xrootd_access_log_emit(const xrootd_vfs_ctx_t *ctx, const char *path,
    xrootd_metric_op_t op, const xrootd_vfs_io_result_t *result,
    size_t bytes, xrootd_err_class_t err, ngx_msec_t latency_usec)
{
    char        path_json[1024];
    char        subject_json[256];
    const char *subject;
    off_t       offset;
    ngx_uint_t  from_cache;
    ngx_time_t *tp;

    if (ctx == NULL || ctx->log == NULL) {
        return;
    }

    subject = "";
    if (ctx->identity != NULL) {
        subject = xrootd_identity_subject_cstr(ctx->identity);
        if (subject == NULL || subject[0] == '\0') {
            subject = xrootd_identity_dn_cstr(ctx->identity);
        }
    }

    xrootd_access_json_escape(path, path_json, sizeof(path_json));
    xrootd_access_json_escape(subject, subject_json, sizeof(subject_json));

    offset = result != NULL ? result->offset : 0;
    from_cache = result != NULL && result->from_cache ? 1 : 0;
    tp = ngx_timeofday();

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                  "xrootd_access_json: "
                  "{\"ts\":%T.%03M,\"proto\":\"%s\","
                  "\"remote\":\"-\",\"op\":\"%s\","
                  "\"path\":\"%s\",\"bytes\":%uz,\"offset\":%O,"
                  "\"latency_us\":%M,\"status\":\"%s\","
                  "\"from_cache\":%s,\"auth_method\":\"%s\","
                  "\"subject\":\"%s\"}",
                  tp->sec, tp->msec,
                  xrootd_metric_proto_name(ctx->metrics_proto),
                  xrootd_metric_op_name(op),
                  path_json, bytes, offset, latency_usec,
                  xrootd_metric_err_name(err),
                  from_cache ? "true" : "false",
                  ctx->identity != NULL
                      ? xrootd_metric_auth_method_name(ctx->identity->auth_method)
                      : "none",
                  subject_json);
}
