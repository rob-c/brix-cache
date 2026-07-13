#include "dashboard_tracking.h"
#include "dashboard_http.h"

#include <string.h>

/*
 * dashboard/http_tracking.c — HTTP-request lifecycle binding for live transfer slots.
 *
 * WHAT: Implements the brix_dashboard_http_*() API declared in
 *       dashboard_tracking.h.  Each tracked WebDAV/S3/TPC request gets one
 *       transfer slot in the dashboard SHM table; this file allocates that slot
 *       on start, streams byte/state/error updates into it during the request,
 *       reports redacted TPC remote endpoints, and releases it on finish.  The
 *       per-request binding is stored as the request's module ctx
 *       (brix_dashboard_http_track_t) so any handler can reach the slot.
 * WHY:  WebDAV and S3 run in the HTTP module where the unit of work is an
 *       ngx_http_request_t, not a stream session; this layer adapts the
 *       protocol-agnostic transfer_table.c slot operations to that lifecycle and
 *       guarantees the slot is freed even on abnormal teardown via an
 *       ngx_pool_cleanup handler (dashboard_http_cleanup) tied to r->pool.
 * HOW:  brix_dashboard_http_start_identity() is the workhorse — it validates
 *       the SHM zone, reserves a slot with brix_transfer_slot_alloc_ex(),
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
    brix_transfer_table_t *table;
    ngx_http_request_t      *r;
} brix_dashboard_http_track_t;

/*
 * Per-request start metadata, bundled to keep helper signatures under the
 * parameter cap.  Mirrors the arguments of the frozen brix_dashboard_http_
 * start_identity() public signature; populated once at the top of that
 * function and threaded into the slot-reservation helper.
 */
typedef struct {
    const char *path;
    const char *identity;
    const char *vo;
    const char *op;
    int64_t     expected_bytes;
    uint8_t     proto;
    uint8_t     direction;
} brix_dashboard_http_meta_t;

static void
dashboard_http_cleanup(void *data)
{
    brix_dashboard_http_track_t *track = data;

    if (track == NULL || track->slot < 0 || track->table == NULL) {
        return;
    }

    brix_transfer_slot_free(track->table, track->slot);
    track->slot = -1;
}

static brix_dashboard_http_track_t *
dashboard_http_track(ngx_http_request_t *r)
{
    return ngx_http_get_module_ctx(r, ngx_http_brix_dashboard_module);
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
 * Report whether the dashboard SHM zone is present and fully initialised.
 *
 * WHAT: Returns non-zero when ngx_brix_dashboard_shm_zone points at a live
 *       transfer table (not NULL, not the (void *) 1 "reserved but uninit"
 *       sentinel nginx parks in ->data before shm init runs).
 * WHY:  Every tracking entry point must bail out to a no-op when the zone is
 *       absent; hoisting the check keeps the guard identical everywhere and
 *       trims branch count out of the start path.
 * HOW:  Pure predicate over the global zone pointer — no side effects.
 */
static int
dashboard_shm_ready(void)
{
    return ngx_brix_dashboard_shm_zone != NULL
        && ngx_brix_dashboard_shm_zone->data != NULL
        && ngx_brix_dashboard_shm_zone->data != (void *) 1;
}

/*
 * Register the pool cleanup that binds a reserved slot to the request.
 *
 * WHAT: Allocates a brix_dashboard_http_track_t inside an r->pool cleanup,
 *       fills it in for the given slot, parks it as the module ctx, and returns
 *       the slot index; on cleanup-allocation failure it frees the slot and
 *       returns -1 so the caller reports "not tracked".
 * WHY:  The slot must be released even on abnormal teardown; tying the binding
 *       to the pool cleanup guarantees that, and isolating it keeps the start
 *       function's control flow flat.
 * HOW:  ngx_pool_cleanup_add() → populate track → ngx_http_set_ctx(); the
 *       cleanup handler (dashboard_http_cleanup) frees the slot on pool destroy.
 */
static int
dashboard_http_bind_slot(ngx_http_request_t *r, int slot, const char *op)
{
    brix_dashboard_http_track_t *track;
    ngx_pool_cleanup_t            *cln;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(*track));
    if (cln == NULL) {
        brix_transfer_slot_free(ngx_brix_dashboard_shm_zone->data, slot);
        return -1;
    }

    track = cln->data;
    track->slot = slot;
    track->table = ngx_brix_dashboard_shm_zone->data;
    track->r = r;
    cln->handler = dashboard_http_cleanup;
    ngx_http_set_ctx(r, track, ngx_http_brix_dashboard_module);

    if (op != NULL) {
        brix_transfer_slot_count_op(track->table, track->slot, op);
    }

    return slot;
}

/*
 * Reserve a fresh transfer slot for a starting request.
 *
 * WHAT: Builds the zeroed session id + bounded client-address string and calls
 *       brix_transfer_slot_alloc_ex() with the request's identity/VO/path/op
 *       metadata, returning the slot index (>= 0) or -1 when the table is full.
 * WHY:  Concentrates the argument marshalling (NUL-safe client copy, anonymous
 *       identity default) so the public start function stays a thin orchestrator
 *       under the CCN/param caps.
 * HOW:  Pure allocation call — no ctx binding here; the caller binds on success.
 */
static int
dashboard_http_reserve_slot(ngx_http_request_t *r,
    const brix_dashboard_http_meta_t *m)
{
    u_char sessid[16];
    char   ipbuf[NGX_SOCKADDR_STRLEN + 1];

    ngx_memzero(sessid, sizeof(sessid));
    return brix_transfer_slot_alloc_ex(ngx_brix_dashboard_shm_zone->data,
                                        sessid,
                                        dashboard_http_client(r, ipbuf,
                                                              sizeof(ipbuf)),
                                        m->identity ? m->identity : "anonymous",
                                        m->vo ? m->vo : "", m->path, m->op,
                                        m->direction, m->proto,
                                        m->expected_bytes,
                                        (int64_t) ngx_current_msec);
}

/*
 * Begin tracking an HTTP request: reserve a transfer slot and bind it to r.
 *
 * Returns the slot index (>= 0) on success, or -1 if the dashboard SHM zone is
 * absent/uninitialised or slot/cleanup allocation fails.  Idempotent — if r is
 * already bound to a slot the existing index is returned without re-allocating.
 * The slot is automatically released when r->pool is destroyed (see
 * dashboard_http_cleanup) even if brix_dashboard_http_finish() is never called.
 */
int
brix_dashboard_http_start_identity(ngx_http_request_t *r,
    const char *path, const char *identity, const char *vo,
    uint8_t proto, uint8_t direction, const char *op,
    int64_t expected_bytes)
{
    brix_dashboard_http_track_t *track;
    brix_dashboard_http_meta_t   meta;
    int                            slot;

    if (r == NULL || !dashboard_shm_ready()) {
        return -1;
    }

    track = dashboard_http_track(r);
    if (track != NULL && track->slot >= 0) {
        return track->slot;
    }

    meta.path = path;
    meta.identity = identity;
    meta.vo = vo;
    meta.op = op;
    meta.expected_bytes = expected_bytes;
    meta.proto = proto;
    meta.direction = direction;

    slot = dashboard_http_reserve_slot(r, &meta);
    if (slot < 0) {
        return -1;
    }

    return dashboard_http_bind_slot(r, slot, op);
}

int
brix_dashboard_http_start(ngx_http_request_t *r, const char *path,
    uint8_t proto, uint8_t direction, const char *op,
    int64_t expected_bytes)
{
    return brix_dashboard_http_start_identity(r, path, "anonymous", "",
                                                proto, direction, op,
                                                expected_bytes);
}

void
brix_dashboard_http_add(ngx_http_request_t *r, ngx_atomic_int_t bytes)
{
    brix_dashboard_http_track_t *track = dashboard_http_track(r);

    if (track == NULL || track->slot < 0 || track->table == NULL) {
        return;
    }

    brix_transfer_slot_update_bytes(track->table, track->slot, bytes,
                                      (int64_t) ngx_current_msec);
}

void
brix_dashboard_http_state(ngx_http_request_t *r, uint8_t state)
{
    brix_dashboard_http_track_t *track = dashboard_http_track(r);

    if (track == NULL || track->slot < 0 || track->table == NULL) {
        return;
    }

    brix_transfer_slot_set_state(track->table, track->slot, state,
                                   (int64_t) ngx_current_msec);
}

void
brix_dashboard_http_error(ngx_http_request_t *r, const char *reason)
{
    brix_dashboard_http_track_t *track = dashboard_http_track(r);

    if (track == NULL || track->slot < 0 || track->table == NULL) {
        return;
    }

    brix_transfer_slot_set_error(track->table, track->slot, reason,
                                   (int64_t) ngx_current_msec);
}

/*
 * Parsed view of a URL split at scheme/authority/path boundaries.  All members
 * point into the original url buffer (no copies): url is the full string,
 * scheme_end is the "://" position (or NULL when scheme-less), authority is the
 * userinfo-stripped host start, end is one-past the authority, and path is the
 * first '/' of the path component (or NULL).
 */
typedef struct {
    const char *url;
    const char *scheme_end;
    const char *authority;
    const char *end;
    const char *path;
} redact_parts_t;

/*
 * Locate the userinfo-stripped authority span of a URL.
 *
 * WHAT: Fills p with the scheme/authority/path boundaries of url: authority is
 *       set past any "scheme://" prefix and any "user:pass@" userinfo, path to
 *       the first '/' (or NULL), and end to one-past the authority byte.
 * WHY:  Isolating the parse keeps the host/path writers branch-flat and makes
 *       the userinfo-drop (credential redaction) a single, testable step.
 * HOW:  strstr("://") → advance past userinfo '@' within [authority,end); all
 *       pointers refer into the caller's url buffer (no copies).
 */
static void
redact_split_authority(const char *url, redact_parts_t *p)
{
    const char *auth;
    const char *at;

    p->url = url;
    p->scheme_end = strstr(url, "://");
    auth = p->scheme_end != NULL ? p->scheme_end + 3 : url;
    p->path = strchr(auth, '/');
    p->end = p->path != NULL ? p->path : auth + ngx_strlen(auth);

    at = memchr(auth, '@', (size_t) (p->end - auth));
    if (at != NULL) {
        auth = at + 1;
    }

    p->authority = auth;
}

/*
 * Write "scheme://host" (userinfo-stripped) into a bounded host buffer.
 *
 * WHAT: Emits the "scheme://" prefix (bytes url..scheme_end+3) followed by the
 *       authority span [authority,end) into host, NUL-terminated and capped at
 *       hostsz.  When p->scheme_end is NULL only the authority is written.
 * WHY:  The scheme-present and scheme-less cases share the same bounds logic;
 *       one writer keeps the truncation math (and the byte-identical output)
 *       in a single place.
 * HOW:  Copy the prefix first, then as much of the authority as remaining
 *       capacity allows; every branch NUL-terminates within [0,hostsz).
 */
static void
redact_write_host(const redact_parts_t *p, char *host, size_t hostsz)
{
    size_t n;
    size_t hn;

    if (p->scheme_end != NULL) {
        n = (size_t) (p->scheme_end - p->url + 3);
        if (n >= hostsz) {
            n = hostsz > 0 ? hostsz - 1 : 0;
        }
        if (n > 0) {
            ngx_memcpy(host, p->url, n);
        }
        if (hostsz > 0) {
            host[n] = '\0';
        }
        if (n + 1 < hostsz) {
            hn = (size_t) (p->end - p->authority);
            if (hn > hostsz - n - 1) {
                hn = hostsz - n - 1;
            }
            ngx_memcpy(host + n, p->authority, hn);
            host[n + hn] = '\0';
        }
        return;
    }

    if (hostsz > 0) {
        n = (size_t) (p->end - p->authority);
        if (n >= hostsz) {
            n = hostsz - 1;
        }
        ngx_memcpy(host, p->authority, n);
        host[n] = '\0';
    }
}

/*
 * Reduce a URL path to its basename, dropping query and fragment.
 *
 * WHAT: Writes the final path segment of [path, …) (stopping at '?' or '#')
 *       into path_hint, NUL-terminated and capped at pathsz; an empty basename
 *       (path ends in '/') collapses to "/".
 * WHY:  Full object paths and query strings can carry sensitive or
 *       high-cardinality data; keeping only the basename preserves a useful
 *       display hint without leaking them into the dashboard record.
 * HOW:  Scan to the query/fragment terminator, walk back to the last '/', then
 *       copy the [base,end) run under the size cap.
 */
static void
redact_write_path_hint(const char *path, char *path_hint, size_t pathsz)
{
    const char *end;
    const char *base;
    size_t      n;

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
    redact_parts_t parts;

    if (hostsz > 0) {
        host[0] = '\0';
    }
    if (pathsz > 0) {
        path_hint[0] = '\0';
    }

    if (url == NULL) {
        return;
    }

    redact_split_authority(url, &parts);
    redact_write_host(&parts, host, hostsz);

    if (parts.path == NULL || pathsz == 0) {
        return;
    }

    redact_write_path_hint(parts.path, path_hint, pathsz);
}

void
brix_dashboard_http_tpc_remote(ngx_http_request_t *r,
    const char *remote_url, int remote_status, int curl_exit)
{
    brix_dashboard_http_track_t *track = dashboard_http_track(r);
    char                           host[BRIX_DASHBOARD_HOST_LEN];
    char                           path_hint[BRIX_DASHBOARD_PATH_LEN];

    if (track == NULL || track->slot < 0 || track->table == NULL) {
        return;
    }

    dashboard_redact_url(remote_url, host, sizeof(host), path_hint,
                         sizeof(path_hint));
    brix_transfer_slot_set_tpc_remote(track->table, track->slot, host,
                                        path_hint, remote_status, curl_exit);
}

void
brix_dashboard_http_finish(ngx_http_request_t *r)
{
    brix_dashboard_http_track_t *track = dashboard_http_track(r);

    if (track == NULL || track->slot < 0 || track->table == NULL) {
        return;
    }

    brix_transfer_slot_set_state(track->table, track->slot,
                                   BRIX_XFER_STATE_CLOSING,
                                   (int64_t) ngx_current_msec);
    brix_transfer_slot_free(track->table, track->slot);
    track->slot = -1;
}
