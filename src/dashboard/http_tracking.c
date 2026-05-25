#include "dashboard_tracking.h"
#include "dashboard_http.h"

#include <string.h>

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

static const char *
dashboard_http_client(ngx_http_request_t *r)
{
    if (r != NULL && r->connection != NULL
        && r->connection->addr_text.data != NULL)
    {
        return (const char *) r->connection->addr_text.data;
    }

    return "-";
}

int
xrootd_dashboard_http_start_identity(ngx_http_request_t *r,
    const char *path, const char *identity, const char *vo,
    uint8_t proto, uint8_t direction, const char *op,
    int64_t expected_bytes)
{
    xrootd_dashboard_http_track_t *track;
    ngx_pool_cleanup_t            *cln;
    u_char                         sessid[16];
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
                                         sessid, dashboard_http_client(r),
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
