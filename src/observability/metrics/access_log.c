#include "access_log.h"

/*
 * access_log.c — structured JSON access-log line emitter for VFS operations.
 *
 * WHAT: Emits one machine-parsable JSON access record per completed VFS I/O
 *       operation via brix_access_log_emit(). Each line carries timestamp,
 *       protocol, op name, request path, byte count, offset, latency, error
 *       status, cache-hit flag, auth method, and the authenticated subject/DN.
 * WHY:  Prometheus counters are aggregate and low-cardinality (no paths or DNs
 *       as labels — INVARIANT #8), but operators still need per-request audit
 *       detail. A JSON log line carries the high-cardinality fields (path,
 *       subject) that must never become metric labels, while reusing the same
 *       unified vocabulary (brix_metric_proto_name / _op_name / _err_name /
 *       _auth_method_name) so logs and metrics line up.
 * HOW:  The line is written with ngx_log_error at NGX_LOG_INFO and prefixed
 *       "brix_access_json: " so a log pipeline can grep and strip the prefix.
 *       Free-text fields are run through brix_access_json_escape() into fixed
 *       stack buffers before being interpolated, so untrusted wire bytes can
 *       never break out of the JSON string. Subject is taken from the identity
 *       (subject, falling back to DN); path/offset/cache come from the
 *       brix_vfs_io_result_t when present.
 */

/*
 * brix_access_json_escape — copy src into dst as a JSON-string-safe sequence.
 *
 * Escapes '"' and '\\' with a backslash and renders any byte outside printable
 * ASCII (< 0x20 or >= 0x7f) as a \u00NN escape, so control bytes and non-ASCII
 * from the wire cannot terminate the surrounding JSON string. Always writes a
 * NUL terminator (unless dstsz == 0) and never exceeds dstsz, truncating cleanly
 * if an escape sequence would not fit.
 */
static void
brix_access_json_escape(const char *src, char *dst, size_t dstsz)
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
 * brix_access_log_emit — write one JSON access-log record for a VFS op.
 *
 * Pulls protocol/auth/subject from ctx, path/offset/cache-hit from result (when
 * non-NULL), escapes the free-text fields, and emits a single NGX_LOG_INFO line.
 * No-op if ctx or ctx->log is NULL. bytes, err, and latency_usec are supplied by
 * the caller because they describe the just-finished operation, not the handle.
 */
void
brix_access_log_emit(const brix_vfs_ctx_t *ctx, const char *path,
    brix_metric_op_t op, const brix_vfs_io_result_t *result,
    size_t bytes, brix_err_class_t err, ngx_msec_t latency_usec)
{
    char        path_json[1024];
    char        subject_json[256];
    char        remote_json[128];
    const char *subject;
    off_t       offset;
    ngx_uint_t  from_cache;
    ngx_time_t *tp;

    if (ctx == NULL || ctx->log == NULL) {
        return;
    }

    subject = "";
    if (ctx->identity != NULL) {
        subject = brix_identity_subject_cstr(ctx->identity);
        if (subject == NULL || subject[0] == '\0') {
            subject = brix_identity_dn_cstr(ctx->identity);
        }
    }

    brix_access_json_escape(path, path_json, sizeof(path_json));
    brix_access_json_escape(subject, subject_json, sizeof(subject_json));
    /* phase-110 W7: the client address, so the JSON log is self-sufficient.
     * NULL peer (an unbound/internal ctx) stays the "-" sentinel. */
    brix_access_json_escape(ctx->peer != NULL ? ctx->peer : "-",
                            remote_json, sizeof(remote_json));

    offset = result != NULL ? result->offset : 0;
    from_cache = result != NULL && result->from_cache ? 1 : 0;
    tp = ngx_timeofday();

    /* phase-110 rule 3: a JSON key is the $brix_* variable's name minus
     * "brix_", carrying the SAME value string as that variable and as the
     * Prometheus label of the same name (one word per fact on every surface):
     *   cache_status  ← brix_metric_cache_status_name (was the bool from_cache)
     *   sub           ← the identity subject (was "subject")
     *   bytes_served  ← this op's bytes (was "bytes")
     *   backend_time_us ← this op's latency; unit suffix per rule 4 because the
     *                   variable renders seconds (was "latency_us")
     * The old keys are still emitted for one release (deprecated aliases,
     * removal phase-112) so no existing consumer breaks. A per-op line
     * reports the op's own cache decision: HIT/MISS/- (BYPASS/NEGHIT are
     * request-level decisions the variable can carry, an op line cannot). */
    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                  "brix_access_json: "
                  "{\"ts\":%T.%03M,\"proto\":\"%s\","
                  "\"remote\":\"%s\",\"op\":\"%s\","
                  "\"path\":\"%s\",\"bytes_served\":%uz,\"bytes\":%uz,"
                  "\"offset\":%O,"
                  "\"backend_time_us\":%M,\"latency_us\":%M,"
                  "\"status\":\"%s\","
                  "\"cache_status\":\"%s\",\"from_cache\":%s,"
                  "\"auth_method\":\"%s\","
                  "\"sub\":\"%s\",\"subject\":\"%s\"}",
                  tp->sec, tp->msec,
                  brix_metric_proto_name(ctx->metrics_proto),
                  remote_json,
                  brix_metric_op_name(op),
                  path_json, bytes, bytes, offset, latency_usec, latency_usec,
                  brix_metric_err_name(err),
                  brix_metric_cache_status_name(
                      result == NULL ? BRIX_CACHE_STATUS_NONE
                      : from_cache   ? BRIX_CACHE_STATUS_HIT
                      : ctx->cache_enabled ? BRIX_CACHE_STATUS_MISS
                                           : BRIX_CACHE_STATUS_NONE),
                  from_cache ? "true" : "false",
                  ctx->identity != NULL
                      ? brix_metric_auth_method_name(ctx->identity->auth_method)
                      : "none",
                  subject_json, subject_json);
}
