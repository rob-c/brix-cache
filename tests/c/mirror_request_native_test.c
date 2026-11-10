/* Exact configured mirror callbacks: header framing, ownership and refusal. */
#include "net/mirror/http_mirror.h"
#include "net/mirror/http_mirror_internal.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *fault;
    int armed, dns_failures;
    ngx_shm_zone_t metrics_zone;
    ngx_brix_metrics_t metrics;
} fixture;
/* WHAT: Access fixture state. WHY: Avoid added globals. HOW: Borrow its cycle prefix. */
static fixture *state(void) { return (fixture *) ngx_cycle; }
/* WHAT: Supply isolated counters. WHY: Assert finalization outcomes. HOW: Return fixture-owned metric storage. */
ngx_shm_zone_t *__wrap_brix_metrics_get_shm_zone(void)
{ state()->metrics_zone.data = &state()->metrics; return &state()->metrics_zone; }
/* WHAT: Observe a failed origin. WHY: Pin DNS retry feedback. HOW: Count the callback without scheduling network work. */
void __wrap_brix_dns_target_note_failure(brix_dns_target_t *target)
{ assert(target == NULL); state()->dns_failures++; }
ngx_buf_t *__real_ngx_create_temp_buf(ngx_pool_t *, size_t);
ngx_chain_t *__real_ngx_alloc_chain_link(ngx_pool_t *);
/* WHAT: Fail header allocation. WHY: Verify no partial request escapes. HOW: Arm only after fixture setup. */
ngx_buf_t *__wrap_ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    if (state()->armed && !strcmp(state()->fault, "header-oom")) { return NULL; }
    return __real_ngx_create_temp_buf(pool, size);
}
/* WHAT: Fail chain allocation. WHY: Verify body ownership on failure. HOW: Replace only the allocation boundary. */
ngx_chain_t *__wrap_ngx_alloc_chain_link(ngx_pool_t *pool)
{
    if (state()->armed && !strcmp(state()->fault, "chain-oom")) { return NULL; }
    return __real_ngx_alloc_chain_link(pool);
}
/* WHAT: Add an input header. WHY: Use the real case-insensitive lookup. HOW: Populate nginx's list representation. */
static ngx_table_elt_t *header(ngx_http_request_t *r, const char *name, const char *value)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_in.headers); assert(h);
    memset(h, 0, sizeof(*h)); h->hash = 1;
    h->key = (ngx_str_t) {strlen(name), (u_char *) name};
    h->value = (ngx_str_t) {strlen(value), (u_char *) value}; return h;
}
/* WHAT: Parse and finalize a shadow response. WHY: Check fragmented/malformed input and divergence. HOW: Use nginx's actual HTTP parser and metrics callback. */
static void response(ngx_http_request_t *r, const char *wire, const char *mode)
{
    ngx_http_upstream_state_t upstream_state = {0};
    r->upstream->state = &upstream_state;
    r->upstream->buffer = (ngx_buf_t) {.pos = (u_char *)wire,
        .last = (u_char *)wire + strlen(wire)};
    ngx_http_brix_webdav_req_ctx_t parent_ctx = {.primary_status = 200};
    void *parent_contexts[] = {&parent_ctx}; r->parent->ctx = parent_contexts;
    if (!strcmp(mode,"no-primary")) { parent_ctx.primary_status = 0; }
    if (!strcmp(mode,"no-parent-context")) { parent_contexts[0] = NULL; }
    if (!strcmp(mode,"no-parent")) { r->parent = NULL; }
    ngx_int_t rc = mirror_process_status_line(r);
    printf("ok=%d again=%d invalid=%d error=%d status=%lu\n", rc == NGX_OK,
        rc == NGX_AGAIN, rc == NGX_HTTP_UPSTREAM_INVALID_HEADER, rc == NGX_ERROR,
        (unsigned long)r->upstream->headers_in.status_n);
    mirror_finalize_request(r,rc);
    printf("total=%lu errors=%lu divergence=%lu dns=%d\n",
        (unsigned long)state()->metrics.mirror_http_total,
        (unsigned long)state()->metrics.mirror_http_errors_total,
        (unsigned long)state()->metrics.mirror_http_divergence_total,state()->dns_failures);
    ngx_http_brix_webdav_req_ctx_t *ctx = r->ctx[0];
    ngx_int_t reset=mirror_reinit_request(r);
    assert(reset == (ctx ? NGX_OK : NGX_ERROR));
    if(ctx) { assert(ctx->mirror_status.code == 0); }
}
/* WHAT: Emit a real mirror request. WHY: Check exact bytes and independent body cursors. HOW: Build a finite parent/subrequest pair. */
int main(int argc, char **argv)
{
    assert(argc == 5);
    fixture f = {0}; f.fault = argv[4]; ngx_cycle = &f.cycle;
    ngx_open_file_t file = {.fd = STDERR_FILENO};
    ngx_log_t log = {.log_level = NGX_LOG_ERR, .file = &file};
    f.cycle.log = &log; ngx_time_init(); ngx_os_argv = argv;
    assert(ngx_os_init(&log) == NGX_OK);
    ngx_pool_t *pool = ngx_create_pool(16384, &log); assert(pool);
    ngx_connection_t connection = {.log = &log};
    ngx_http_brix_webdav_loc_conf_t conf = {0};
    ngx_http_brix_webdav_req_ctx_t ctx = {0};
    void *locations[] = {&conf}, *contexts[] = {&ctx};
    ngx_http_brix_webdav_module.ctx_index = 0;
    brix_mirror_target_t target = {.host = ngx_string("shadow.example:8443"),
        .url_base = ngx_string("http://shadow.example:8443")};
    ngx_array_t targets = {.elts = &target, .nelts = 1};
    conf.common.mirror.targets = &targets;
    conf.common.mirror.strip_auth = strcmp(argv[2], "forward") != 0;
    if (!strcmp(argv[2], "inject")) { ngx_str_set(&conf.common.mirror.token, "shadow-token"); }
    ngx_http_upstream_t upstream = {0};
    ngx_http_request_t parent = {.pool = pool}, r = {.pool = pool,
        .connection = &connection, .loc_conf = locations, .ctx = contexts,
        .upstream = &upstream, .parent = &parent,
        .uri = ngx_string("/dav/source"), .args = ngx_string("opaque=%2f")};
    r.method_name = (ngx_str_t) {strlen(argv[1]), (u_char *) argv[1]};
    r.method = !strcmp(argv[1], "MOVE") ? NGX_HTTP_MOVE :
        !strcmp(argv[1], "COPY") ? NGX_HTTP_COPY : NGX_HTTP_PUT;
    assert(ngx_list_init(&r.headers_in.headers, pool, 8, sizeof(ngx_table_elt_t)) == NGX_OK);
    r.headers_in.authorization = header(&r, "Authorization", "Bearer client-secret");
    if (strcmp(argv[3], "none")) { header(&r, "Destination", argv[3]); }
    header(&r, "Depth", "infinity"); header(&r, "Overwrite", "F");
    u_char body[] = "payload";
    ngx_buf_t payload = {.pos = body, .last = body + 7, .memory = 1, .last_buf = 1};
    ngx_buf_t empty = {0};
    ngx_chain_t last = {.buf = &payload}, first = {.buf = &empty, .next = &last};
    ngx_http_request_body_t request_body = {.bufs = &first}; parent.request_body = &request_body;
    if (!strcmp(f.fault, "no-context")) { contexts[0] = NULL; }
    if (!strcmp(f.fault, "no-target")) { targets.nelts = 0; }
    if (!strcmp(argv[1], "RESPONSE")) {
        response(&r,argv[3],argv[2]); ngx_destroy_pool(pool); return 0;
    }
    f.armed = 1;
    ngx_int_t rc = mirror_create_request(&r); f.armed = 0;
    printf("rc=%ld\n", (long) rc);
    assert(payload.pos == body && payload.last == body + 7 && payload.last_buf);
    if (rc == NGX_OK) {
        ngx_chain_t *chain = upstream.request_bufs; assert(chain);
        fwrite(chain->buf->pos, 1, (size_t) ngx_buf_size(chain->buf), stdout);
        if (r.method == NGX_HTTP_PUT) {
            assert(chain->next && !chain->next->next && chain->next->buf != &payload);
            assert(!chain->next->buf->last_buf && !chain->next->buf->last_in_chain);
            assert(ngx_buf_size(chain->next->buf) == 7);
            chain->next->buf->pos++;
            assert(payload.pos == body);
        } else { assert(chain->next == NULL); }
    } else { assert(upstream.request_bufs == NULL); }
    mirror_abort_request(&r); ngx_destroy_pool(pool); return 0;
}
