#include "dashboard_tracking.h"
#include "dashboard_http.h"

#include <string.h>

/*
 * dashboard/http_tracking.c — HTTP-request lifecycle binding for live transfer slots.
 *
 * WHAT: Implements the xrootd_dashboard_http_*() API declared in
 *       dashboard_tracking.h.  Each tracked WebDAV/S3/TPC request gets one
 *       transfer slot in the dashboard SHM table; this file allocates that slot
 *       on start, streams byte/state/error updates into it during the request,
 *       reports redacted TPC remote endpoints, and releases it on finish.  The
 *       per-request binding is stored as the request's module ctx
 *       (xrootd_dashboard_http_track_t) so any handler can reach the slot.
 * WHY:  WebDAV and S3 run in the HTTP module where the unit of work is an
 *       ngx_http_request_t, not a stream session; this layer adapts the
 *       protocol-agnostic transfer_table.c slot operations to that lifecycle and
 *       guarantees the slot is freed even on abnormal teardown via an
 *       ngx_pool_cleanup handler (dashboard_http_cleanup) tied to r->pool.
 * HOW:  xrootd_dashboard_http_start_identity() is the workhorse — it validates
 *       the SHM zone, reserves a slot with xrootd_transfer_slot_alloc_ex(),
 *       registers the pool cleanup, and parks the binding in module ctx; the
 *       _start() variant is a thin "anonymous" wrapper.  Updates look up the
 *       binding via dashboard_http_track() and forward to the slot ops, all
 *       stamped with ngx_current_msec.  dashboard_http_client() copies the
 *       non-NUL-terminated addr_text into a bounded buffer, and
 *       dashboard_redact_url() strips userinfo/query from TPC URLs before they
 *       are stored, so secrets never reach the dashboard.
 */

typedef struct {
    int                      slot;
    xrootd_transfer_table_t *table;
    ngx_http_request_t      *r;
} xrootd_dashboard_http_track_t;

static void
dashboard_http_cleanup(void *data)
{
    xrootd_dashboard_http_track_t *track = data;

    if (track == NULL || track->slot < 0 || track->table == NULL) {
        return;
    }

    xrootd_transfer_slot_free(track->table, track->slot);
    track->slot = -1;
}

static xrootd_dashboard_http_track_t *
dashboard_http_track(ngx_http_request_t *r)
{
    return ngx_http_get_module_ctx(r, ngx_http_xrootd_dashboard_module);
}

/*
 * Copy the client address into a NUL-terminated, length-bounded buffer.
 *
 * r->connection->addr_text is an ngx_str_t whose .data is NOT NUL-terminated
 * (only .len bytes are valid; the tail of the buffer is uninitialised).  The
 * dashboard slot copier uses ngx_cpystrn(), which scans for a NUL — handing it
 * the raw .data reads past .len into uninitialised memory (Phase 27 / Valgrind
 * finding) and can copy garbage.  Always pass this bounded copy instead.
 */
static const char *
dashboard_http_client(ngx_http_request_t *r, char *buf, size_t bufsz)
{
    size_t n;

    if (r != NULL && r->connection != NULL
        && r->connection->addr_text.data != NULL
        && r->connection->addr_text.len > 0
        && bufsz > 0)
    {
        n = ngx_min(r->connection->addr_text.len, bufsz - 1);
        ngx_memcpy(buf, r->connection->addr_text.data, n);
        buf[n] = '\0';
        return buf;
    }

    return "-";
}

/*
 * Begin tracking an HTTP request: reserve a transfer slot and bind it to r.
 *
 * Returns the slot index (>= 0) on success, or -1 if the dashboard SHM zone is
 * absent/uninitialised or slot/cleanup allocation fails.  Idempotent — if r is
 * already bound to a slot the existing index is returned without re-allocating.
 * The slot is automatically released when r->pool is destroyed (see
 * dashboard_http_cleanup) even if xrootd_dashboard_http_finish() is never called.
 */
int
xrootd_dashboard_http_start_identity(ngx_http_request_t *r,
    const char *path, const char *identity, const char *vo,
    uint8_t proto, uint8_t direction, const char *op,
    int64_t expected_bytes)
{
    xrootd_dashboard_http_track_t *track;
    ngx_pool_cleanup_t            *cln;
    u_char                         sessid[16];
    char                           ipbuf[NGX_SOCKADDR_STRLEN + 1];
    int                            slot;

    if (r == NULL || ngx_xrootd_dashboard_shm_zone == NULL
        || ngx_xrootd_dashboard_shm_zone->data == NULL
        || ngx_xrootd_dashboard_shm_zone->data == (void *) 1)
    {
        return -1;
    }

    track = dashboard_http_track(r);
    if (track != NULL && track->slot >= 0) {
        return track->slot;
    }

    ngx_memzero(sessid, sizeof(sessid));
    slot = xrootd_transfer_slot_alloc_ex(ngx_xrootd_dashboard_shm_zone->data,
                                         sessid,
                                         dashboard_http_client(r, ipbuf,
                                                               sizeof(ipbuf)),
                                         identity ? identity : "anonymous",
                                         vo ? vo : "", path, op, direction,
                                         proto, expected_bytes,
                                         (int64_t) ngx_current_msec);
    if (slot < 0) {
        return -1;
    }

    cln = ngx_pool_cleanup_add(r->pool, sizeof(*track));
    if (cln == NULL) {
        xrootd_transfer_slot_free(ngx_xrootd_dashboard_shm_zone->data, slot);
        return -1;
    }

    track = cln->data;
    track->slot = slot;
    track->table = ngx_xrootd_dashboard_shm_zone->data;
    track->r = r;
    cln->handler = dashboard_http_cleanup;
    ngx_http_set_ctx(r, track, ngx_http_xrootd_dashboard_module);

    if (op != NULL) {
        xrootd_transfer_slot_count_op(track->table, track->slot, op);
    }

    return slot;
}

int
xrootd_dashboard_http_start(ngx_http_request_t *r, const char *path,
    uint8_t proto, uint8_t direction, const char *op,
    int64_t expected_bytes)
{
    return xrootd_dashboard_http_start_identity(r, path, "anonymous", "",
                                                proto, direction, op,
                                                expected_bytes);
}

void
xrootd_dashboard_http_add(ngx_http_request_t *r, ngx_atomic_int_t bytes)
{
    xrootd_dashboard_http_track_t *track = dashboard_http_track(r);

    if (track == NULL || track->slot < 0 || track->table == NULL) {
        return;
    }

    xrootd_transfer_slot_update_bytes(track->table, track->slot, bytes,
                                      (int64_t) ngx_current_msec);
}

void
xrootd_dashboard_http_state(ngx_http_request_t *r, uint8_t state)
{
    xrootd_dashboard_http_track_t *track = dashboard_http_track(r);

    if (track == NULL || track->slot < 0 || track->table == NULL) {
        return;
    }

    xrootd_transfer_slot_set_state(track->table, track->slot, state,
                                   (int64_t) ngx_current_msec);
}

void
xrootd_dashboard_http_error(ngx_http_request_t *r, const char *reason)
{
    xrootd_dashboard_http_track_t *track = dashboard_http_track(r);

    if (track == NULL || track->slot < 0 || track->table == NULL) {
        return;
    }

    xrootd_transfer_slot_set_error(track->table, track->slot, reason,
                                   (int64_t) ngx_current_msec);
}

/*
 * Split a TPC remote URL into a display-safe "scheme://host[:port]" string and a
 * basename-only path hint, dropping anything sensitive or noisy.
 *
 * userinfo ("user:pass@") is stripped from the authority, and the path is
 * reduced to its final segment with the query ("?") and fragment ("#") removed,
 * so credentials and full object paths never land in the dashboard event/slot
 * record.  Both outputs are NUL-terminated and bounded by hostsz / pathsz.
 */
static void
dashboard_redact_url(const char *url, char *host, size_t hostsz,
    char *path_hint, size_t pathsz)
{
    const char *scheme_end;
    const char *authority;
    const char *path;
    const char *at;
    const char *end;
    const char *base;
    size_t      n;

    if (hostsz > 0) {
        host[0] = '\0';
    }
    if (pathsz > 0) {
        path_hint[0] = '\0';
    }

    if (url == NULL) {
        return;
    }

    scheme_end = strstr(url, "://");
    authority = scheme_end != NULL ? scheme_end + 3 : url;
    path = strchr(authority, '/');
    end = path != NULL ? path : authority + ngx_strlen(authority);

    at = memchr(authority, '@', (size_t) (end - authority));
    if (at != NULL) {
        authority = at + 1;
    }

    if (scheme_end != NULL) {
        n = (size_t) (scheme_end - url + 3);
        if (n >= hostsz) {
            n = hostsz > 0 ? hostsz - 1 : 0;
        }
        if (n > 0) {
            ngx_memcpy(host, url, n);
        }
        if (hostsz > 0) {
            host[n] = '\0';
        }
        if (n + 1 < hostsz) {
            size_t hn = (size_t) (end - authority);
            if (hn > hostsz - n - 1) {
                hn = hostsz - n - 1;
            }
            ngx_memcpy(host + n, authority, hn);
            host[n + hn] = '\0';
        }
    } else if (hostsz > 0) {
        n = (size_t) (end - authority);
        if (n >= hostsz) {
            n = hostsz - 1;
        }
        ngx_memcpy(host, authority, n);
        host[n] = '\0';
    }

    if (path == NULL || pathsz == 0) {
        return;
    }

    end = path;
    while (*end != '\0' && *end != '?' && *end != '#') {
        end++;
    }
    base = end;
    while (base > path && *(base - 1) != '/') {
        base--;
    }

    n = (size_t) (end - base);
    if (n == 0) {
        base = "/";
        n = 1;
    }
    if (n >= pathsz) {
        n = pathsz - 1;
    }
    ngx_memcpy(path_hint, base, n);
    path_hint[n] = '\0';
}

void
xrootd_dashboard_http_tpc_remote(ngx_http_request_t *r,
    const char *remote_url, int remote_status, int curl_exit)
{
    xrootd_dashboard_http_track_t *track = dashboard_http_track(r);
    char                           host[XROOTD_DASHBOARD_HOST_LEN];
    char                           path_hint[XROOTD_DASHBOARD_PATH_LEN];

    if (track == NULL || track->slot < 0 || track->table == NULL) {
        return;
    }

    dashboard_redact_url(remote_url, host, sizeof(host), path_hint,
                         sizeof(path_hint));
    xrootd_transfer_slot_set_tpc_remote(track->table, track->slot, host,
                                        path_hint, remote_status, curl_exit);
}

void
xrootd_dashboard_http_finish(ngx_http_request_t *r)
{
    xrootd_dashboard_http_track_t *track = dashboard_http_track(r);

    if (track == NULL || track->slot < 0 || track->table == NULL) {
        return;
    }

    xrootd_transfer_slot_set_state(track->table, track->slot,
                                   XROOTD_XFER_STATE_CLOSING,
                                   (int64_t) ngx_current_msec);
    xrootd_transfer_slot_free(track->table, track->slot);
    track->slot = -1;
}
