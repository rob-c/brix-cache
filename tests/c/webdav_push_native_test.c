/* Push orchestration uses the configured HTTP code with finite I/O boundaries. */
#include "protocols/webdav/tpc_internal_split.h"
#include "tpc/common/registry.h"
#include "observability/dashboard/dashboard_http.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_http_request_t request;
    ngx_connection_t connection;
    ngx_http_brix_webdav_loc_conf_t conf;
    const char *mode, *destination, *overwrite;
    unsigned stats, auth, posts, adds, runs, updates, removes, responses;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }

ngx_int_t __wrap_webdav_resolve_stat(ngx_http_request_t *r, char *path,
    size_t capacity, struct stat *sb)
{
    assert(r == &state()->request && capacity > 32);
    state()->stats++;
    if (mode("missing")) { return NGX_HTTP_NOT_FOUND; }
    strcpy(path, "/export/source");
    memset(sb, 0, sizeof(*sb)); sb->st_size = 17;
    sb->st_mode = mode("directory") ? S_IFDIR : S_IFREG;
    return NGX_OK;
}
ngx_int_t __wrap_webdav_tpc_authorize(ngx_http_request_t *r,
    const ngx_str_t *src, const ngx_str_t *dst)
{
    assert(src->len == r->uri.len && !memcmp(src->data, r->uri.data, src->len));
    assert(dst == NULL && state()->stats == 1);
    state()->auth++;
    return mode("denied") ? NGX_HTTP_FORBIDDEN : NGX_OK;
}

/* WHAT: Check exactly what the handler forwards across the transfer boundary.
 * WHY: COPY overwrite and delegated headers must retain their PUT semantics.
 * HOW: Inspect the actual array produced by the HTTP header collectors. */
static void check_headers(ngx_array_t *headers)
{
    ngx_str_t *items = headers->elts;
    unsigned expected = strcmp(state()->overwrite, "absent") ? 2 : 1;
    assert(headers->nelts == expected);
    assert(items[0].len == 13 && !memcmp(items[0].data, "X-Test: value", 13));
    if (expected == 1) { return; }
    char value[128];
    if (!strcmp(state()->overwrite, "F")) { strcpy(value, "If-None-Match: *"); }
    else { snprintf(value, sizeof(value), "Overwrite: %s", state()->overwrite); }
    assert(items[1].len == strlen(value) && !memcmp(items[1].data, value, items[1].len));
}
ngx_int_t __wrap_webdav_tpc_post_thread_task(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, int push, ngx_flag_t existed,
    ngx_flag_t overwrite, const char *url, const char *local, const char *dest,
    ngx_array_t *headers, ngx_uint_t streams, const char *cert, const char *key)
{
    assert(r == &state()->request && conf == &state()->conf && state()->auth == 1);
    assert(push == 1 && existed == 0 && overwrite == 0 && streams == 1);
    assert(!strcmp(url, state()->destination) && !strcmp(local, "/export/source"));
    assert(dest == NULL && cert == NULL && key == NULL);
    check_headers(headers); state()->posts++;
    if (mode("async")) { return NGX_DONE; }
    if (mode("post-error")) { return NGX_ERROR; }
    if (mode("post-full")) { return NGX_HTTP_SERVICE_UNAVAILABLE; }
    return NGX_DECLINED;
}
uint64_t __wrap_brix_tpc_registry_add(const brix_tpc_transfer_t *transfer,
    ngx_log_t *log, ngx_uint_t maximum)
{
    (void) log;
    assert(maximum == 7 && transfer->bytes_total == 17);
    assert(transfer->direction == BRIX_TPC_DIR_PUSH && transfer->state == BRIX_TPC_STATE_PENDING);
    assert(transfer->src_url.len == 14 && !memcmp(transfer->src_url.data, "/export/source", 14));
    assert(transfer->dst_path.len == strlen(state()->destination));
    assert(!memcmp(transfer->dst_path.data, state()->destination, transfer->dst_path.len));
    state()->adds++; return mode("registry-full") ? 0 : 42;
}
ngx_int_t __wrap_webdav_tpc_run_curl_push(ngx_log_t *log,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *url, const char *path,
    ngx_array_t *headers, uint64_t id)
{
    (void) log;
    assert(conf == &state()->conf && id == 42 && state()->adds == 1);
    assert(!strcmp(url, state()->destination) && !strcmp(path, "/export/source"));
    check_headers(headers); state()->runs++;
    return mode("transfer-error") ? NGX_HTTP_BAD_GATEWAY : NGX_OK;
}
ngx_int_t __wrap_brix_tpc_registry_update(uint64_t id, off_t bytes,
    ngx_uint_t status, ngx_log_t *log)
{
    (void) log; assert(id == 42 && state()->runs == 1);
    assert(bytes == (mode("transfer-error") ? 0 : 17));
    assert(status == (mode("transfer-error") ? BRIX_TPC_STATE_ERROR : BRIX_TPC_STATE_DONE));
    state()->updates++; return NGX_OK;
}
ngx_int_t __wrap_brix_tpc_registry_remove(uint64_t id, ngx_log_t *log)
{
    (void) log; assert(id == 42 && state()->updates == 1);
    state()->removes++; return NGX_OK;
}
ngx_int_t __wrap_ngx_http_send_header(ngx_http_request_t *r)
{
    assert(r->headers_out.status == 201 && r->headers_out.content_length_n == 0);
    state()->responses++; return NGX_OK;
}
ngx_int_t __wrap_ngx_http_send_special(ngx_http_request_t *r, ngx_uint_t flags)
{ (void) r; assert(flags & NGX_HTTP_LAST); return NGX_OK; }

static ngx_table_elt_t *header(ngx_http_request_t *r, const char *name, const char *value)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_in.headers); assert(h);
    memset(h, 0, sizeof(*h)); h->hash = 1;
    h->key = (ngx_str_t) {.len = strlen(name), .data = (u_char *) name};
    h->value = (ngx_str_t) {.len = strlen(value), .data = (u_char *) value};
    return h;
}

/* WHAT: Construct a private request around real header and credential parsing.
 * WHY: Invalid inputs must stop before authorization, scheduling or I/O.
 * HOW: A fresh pool and empty module contexts isolate every executable run. */
int main(int argc, char **argv)
{
    assert(argc == 5);
    fixture f = {0}; f.mode = argv[1]; f.destination = argv[2]; f.overwrite = argv[3];
    f.cycle.log = &f.log; ngx_cycle = &f.cycle; ngx_time_init();
    assert(ngx_strerror_init() == NGX_OK);
    ngx_http_request_t *r = &f.request;
    r->pool = ngx_create_pool(16384, &f.log); assert(r->pool);
    f.cycle.pool = r->pool; r->connection = &f.connection; f.connection.log = &f.log;
    r->main = r; r->uri = (ngx_str_t) ngx_string("/source");
    r->ctx = ngx_pcalloc(r->pool, 128 * sizeof(void *));
    r->loc_conf = ngx_pcalloc(r->pool, 128 * sizeof(void *));
    r->main_conf = ngx_pcalloc(r->pool, 128 * sizeof(void *));
    assert(r->ctx && r->loc_conf && r->main_conf);
    ngx_http_brix_webdav_module.ctx_index = 1;
    ngx_http_brix_dashboard_module.ctx_index = 2;
    r->loc_conf[ngx_http_brix_webdav_module.ctx_index] = &f.conf; f.conf.tpc_xfr = 7;
    assert(ngx_list_init(&r->headers_in.headers, r->pool, 2, sizeof(ngx_table_elt_t)) == NGX_OK);
    ngx_table_elt_t *dest = header(r, "Destination", f.destination);
    header(r, "TransferHeaderX-Test", mode("header-injection") ? "bad\r\nX: y" : "value");
    if (strcmp(f.overwrite, "absent")) { header(r, "Overwrite", f.overwrite); }
    if (strcmp(argv[4], "absent")) { header(r, "Credential", argv[4]); }
    ngx_int_t rc = webdav_tpc_handle_push(r, &f.conf, dest);
    printf("rc=%ld\nstats=%u\nauth=%u\nposts=%u\nadds=%u\nruns=%u\nupdates=%u\nremoves=%u\nresponses=%u\n",
        (long) rc, f.stats, f.auth, f.posts, f.adds, f.runs, f.updates, f.removes, f.responses);
    ngx_destroy_pool(r->pool); ngx_cycle = NULL; return 0;
}
