#include "core/http/sesslog_conn.h"

#define BRIX_HTTP_SESS_CONN_SLOTS 4096

typedef struct {
    ngx_connection_t  *connection;
    brix_sess_t      *sess;
    brix_sess_proto_t proto;
    int               next;
    unsigned          in_use:1;
} brix_http_sess_conn_t;

typedef struct {
    brix_http_sess_conn_t *record;
} brix_http_sess_cleanup_t;

static brix_http_sess_conn_t  brix_http_sess_records[BRIX_HTTP_SESS_CONN_SLOTS];
static int                    brix_http_sess_free_head = -1;
static ngx_uint_t             brix_http_sess_ready;
static ngx_uint_t             brix_http_sess_full_warned;

static void
brix_http_sess_registry_init(void)
{
    int i;

    if (brix_http_sess_ready) {
        return;
    }

    for (i = 0; i < BRIX_HTTP_SESS_CONN_SLOTS - 1; i++) {
        brix_http_sess_records[i].next = i + 1;
    }
    brix_http_sess_records[BRIX_HTTP_SESS_CONN_SLOTS - 1].next = -1;
    brix_http_sess_free_head = 0;
    brix_http_sess_ready = 1;
}

static brix_http_sess_conn_t *
brix_http_sess_lookup(ngx_connection_t *c)
{
    int i;

    if (c == NULL) {
        return NULL;
    }

    brix_http_sess_registry_init();
    for (i = 0; i < BRIX_HTTP_SESS_CONN_SLOTS; i++) {
        if (brix_http_sess_records[i].in_use
            && brix_http_sess_records[i].connection == c)
        {
            return &brix_http_sess_records[i];
        }
    }

    return NULL;
}

static brix_http_sess_conn_t *
brix_http_sess_alloc(ngx_log_t *log)
{
    brix_http_sess_conn_t *record;
    int                    idx;
    int                    next;

    brix_http_sess_registry_init();
    idx = brix_http_sess_free_head;
    if (idx < 0) {
        if (!brix_http_sess_full_warned && log != NULL) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "sesslog: HTTP connection registry full (%d); "
                          "further HTTP sessions unlogged",
                          BRIX_HTTP_SESS_CONN_SLOTS);
            brix_http_sess_full_warned = 1;
        }
        return NULL;
    }

    record = &brix_http_sess_records[idx];
    next = record->next;
    ngx_memzero(record, sizeof(*record));
    record->next = -1;
    record->in_use = 1;
    brix_http_sess_free_head = next;
    return record;
}

static void
brix_http_sess_release(brix_http_sess_conn_t *record)
{
    int idx;

    if (record == NULL) {
        return;
    }

    idx = (int) (record - brix_http_sess_records);
    if (idx < 0 || idx >= BRIX_HTTP_SESS_CONN_SLOTS) {
        return;
    }

    record->connection = NULL;
    record->sess = NULL;
    record->in_use = 0;
    record->next = brix_http_sess_free_head;
    brix_http_sess_free_head = idx;
}

static brix_sess_end_t
brix_http_sess_end_reason(ngx_connection_t *c)
{
    if (ngx_exiting || ngx_terminate) {
        return BRIX_SESS_END_SHUTDOWN;
    }

    if (c != NULL && c->timedout) {
        return BRIX_SESS_END_TIMEOUT;
    }

    if (c != NULL && c->error) {
        return BRIX_SESS_END_ERROR;
    }

    return BRIX_SESS_END_CLIENT;
}

static void
brix_http_sess_cleanup(void *data)
{
    brix_http_sess_cleanup_t *cleanup = data;
    brix_http_sess_conn_t    *record;

    if (cleanup == NULL) {
        return;
    }

    record = cleanup->record;
    if (record == NULL || !record->in_use) {
        return;
    }

    brix_sess_end(record->sess, brix_http_sess_end_reason(record->connection));
    brix_http_sess_release(record);
}

static ngx_int_t
brix_http_sess_register_cleanup(ngx_http_request_t *r,
    brix_http_sess_conn_t *record)
{
    ngx_pool_cleanup_t       *cln;
    brix_http_sess_cleanup_t *cleanup;

    cln = ngx_pool_cleanup_add(r->connection->pool, sizeof(*cleanup));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cleanup = cln->data;
    cleanup->record = record;
    cln->handler = brix_http_sess_cleanup;
    return NGX_OK;
}

brix_sess_t *
brix_http_sess(ngx_http_request_t *r, const ngx_http_brix_shared_conf_t *conf,
    brix_sess_proto_t proto, brix_sess_am_t am)
{
    brix_http_sess_conn_t *record;
    ngx_connection_t      *c;
    ngx_fd_t               fd;

    if (r == NULL || r->connection == NULL || conf == NULL) {
        return NULL;
    }

    c = r->connection;
    record = brix_http_sess_lookup(c);
    if (record != NULL) {
        return record->sess;
    }

    fd = brix_http_shared_access_log_fd(conf);
    record = brix_http_sess_alloc(c->log);
    if (record == NULL) {
        return NULL;
    }

    record->connection = c;
    record->proto = proto;
    record->sess = brix_sess_begin(conf->session_log, fd, proto,
                                   BRIX_SESS_DIR_IN,
                                   (const char *) c->addr_text.data,
                                   c->addr_text.len, am, NULL);
    if (record->sess == NULL) {
        brix_http_sess_release(record);
        return NULL;
    }

    if (brix_http_sess_register_cleanup(r, record) != NGX_OK) {
        brix_sess_end(record->sess, BRIX_SESS_END_ERROR);
        brix_http_sess_release(record);
        return NULL;
    }

    return record->sess;
}

const char *
brix_http_sess_uri(ngx_http_request_t *r, char *dst, size_t dst_size)
{
    size_t n;

    if (dst == NULL || dst_size == 0) {
        return "-";
    }

    if (r == NULL || r->uri.data == NULL || r->uri.len == 0) {
        if (dst_size > 1) {
            dst[0] = '-';
            dst[1] = '\0';
        } else {
            dst[0] = '\0';
        }
        return dst;
    }

    n = r->uri.len;
    if (n >= dst_size) {
        n = dst_size - 1;
    }
    ngx_memcpy(dst, r->uri.data, n);
    dst[n] = '\0';
    return dst;
}
