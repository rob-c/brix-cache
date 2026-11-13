/* Handle translation owns no upstream I/O; observe its lazy-open handoff seam. */
#include "net/proxy/proxy_internal.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_connection_t connection;
    brix_proxy_ctx_t proxy;
    brix_ctx_t context;
    u_char *request;
    size_t total;
    int lazy, errors, first, lazy_result;
} fixture;

/* WHAT: Observe deferred request ownership. WHY: Unopened handles need one queue.
 * HOW: Validate every borrowed pointer and retain the request for test cleanup. */
ngx_int_t __wrap_brix_proxy_lazy_open(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    ngx_connection_t *connection, int fh, u_char *request, size_t total)
{
    fixture *f = (fixture *) ngx_cycle;
    assert(proxy == &f->proxy && ctx == &f->context && connection == &f->connection);
    assert(request == f->request && total == f->total);
    f->lazy++; f->first = fh; return f->lazy_result;
}

/* WHAT: Observe invalid-handle refusal. WHY: Freed requests cannot be forwarded.
 * HOW: The real reject helper releases the request before this terminal seam. */
ngx_int_t __wrap_brix_send_error(brix_ctx_t *ctx, ngx_connection_t *connection,
    uint16_t code, const char *message)
{
    fixture *f = (fixture *) ngx_cycle;
    assert(ctx == &f->context && connection == &f->connection && message);
    assert(code == kXR_InvalidRequest); f->errors++; return NGX_OK;
}

/* WHAT: Bind a deterministic opaque upstream handle. WHY: All four bytes count.
 * HOW: Use the production map setter with bytes unrelated to the local index. */
static void bind_handle(fixture *f, int index)
{
    const u_char bytes[] = {0xfe, 0xed, 0xfa, (u_char) index};
    brix_proxy_fh_bind(&f->proxy.fh_map[index], bytes, sizeof(bytes));
}

static void expect_handle(const u_char *bytes, int index)
{
    const u_char want[] = {0xfe, 0xed, 0xfa, (u_char) index};
    assert(!memcmp(bytes, want, sizeof(want)));
}

/* WHAT: Translate or defer one scalar request. WHY: Only bound reads are lazy.
 * HOW: Vary opcode and map state, asserting ownership and exact opaque bytes. */
static void scalar(fixture *f, const char *mode, uint16_t opcode)
{
    f->request[4] = 3;
    if (!strcmp(mode, "bound")) { bind_handle(f, 3); }
    if (!strcmp(mode, "invalid")) { f->request[4] = BRIX_MAX_FILES; }
    if (!strcmp(mode, "lazy-error")) { f->lazy_result = NGX_ERROR; }
    ngx_int_t rc = brix_proxy_fh_translate_single(&f->proxy, &f->context,
        &f->connection, f->request, f->total, opcode, 0);
    if (f->lazy) {
        assert(f->first == 3 && !f->errors);
        assert(rc == (f->lazy_result == NGX_OK ? NGX_DONE : NGX_ERROR));
    } else if (!strcmp(mode, "bound")) {
        assert(rc == NGX_OK && !f->errors && f->proxy.fwd_local_fh == 3);
        expect_handle(f->request + 4, 3);
    } else { assert(rc == NGX_ABORT && f->errors == 1); }
}

/* WHAT: Queue each unopened vector handle once, preserving encounter order.
 * WHY: Duplicate descriptors must not cause duplicate opens or lose later ones.
 * HOW: Mix repeated free handles with a bound slot and verify the exact queue. */
static void vector(fixture *f, const char *mode, uint16_t opcode)
{
    u_char *body = f->request + XRD_REQUEST_HDR_LEN;
    body[0] = 3; body[16] = 4; body[32] = 3; body[48] = 5;
    bind_handle(f, 4);
    if (!strcmp(mode, "bound")) { bind_handle(f, 3); bind_handle(f, 5); }
    if (!strcmp(mode, "invalid")) { body[48] = BRIX_MAX_FILES; f->context.is_bound = 0; }
    if (!strcmp(mode, "lazy-error")) { f->lazy_result = NGX_ERROR; }
    ngx_int_t rc = brix_proxy_fh_translate_vector(&f->proxy, &f->context,
        &f->connection, f->request, f->total, opcode, 64);
    if (f->lazy) {
        assert(f->lazy == 1 && f->first == 3 && !f->errors);
        assert(f->proxy.lazy_open_pending_count == 1 && f->proxy.lazy_open_pending_fhs[0] == 5);
        assert(rc == (f->lazy_result == NGX_OK ? NGX_DONE : NGX_ERROR));
    } else if (!strcmp(mode, "bound")) {
        assert(rc == NGX_OK && !f->errors && f->proxy.fwd_local_fh == -1);
        expect_handle(body, 3); expect_handle(body + 16, 4);
        expect_handle(body + 32, 3); expect_handle(body + 48, 5);
    } else { assert(rc == NGX_ABORT && f->errors == 1); }
}

/* WHAT: Translate nested checkpoint descriptors within their enclosing body.
 * WHY: Embedded handles are in the same local namespace as ordinary writes.
 * HOW: Include invalid subheaders, invalid descriptors and a clamped length. */
static void checkpoint(fixture *f, const char *mode, uint16_t opcode)
{
    bind_handle(f, 3); bind_handle(f, 4); bind_handle(f, 5);
    f->request[4] = 3; f->request[19] = kXR_ckpXeq;
    u_char *sub = f->request + XRD_REQUEST_HDR_LEN;
    sub[2] = (u_char) (opcode >> 8); sub[3] = (u_char) opcode;
    sub[4] = !strcmp(mode, "invalid-sub") ? BRIX_MAX_FILES : 4;
    sub[23] = !strcmp(mode, "clamp") ? 255 : 32;
    sub[24] = 5; sub[40] = !strcmp(mode, "invalid-vector") ? BRIX_MAX_FILES : 3;
    ngx_int_t rc = brix_proxy_fh_translate_single(&f->proxy, &f->context,
        &f->connection, f->request, f->total, kXR_chkpoint, 56);
    if (f->errors) { assert(rc == NGX_ABORT && f->errors == 1); return; }
    assert(rc == NGX_OK && !f->lazy && f->proxy.fwd_local_fh == 3);
    expect_handle(f->request + 4, 3); expect_handle(sub + 4, 4);
    if (opcode == kXR_writev) { expect_handle(sub + 24, 5); expect_handle(sub + 40, 3); }
}

int main(int argc, char **argv)
{
    assert(argc == 4); fixture *f = calloc(1, sizeof(*f)); assert(f);
    ngx_cycle = &f->cycle; f->cycle.log = &f->log; ngx_time_init();
    f->connection.log = &f->log; f->context.is_bound = 1;
    f->total = XRD_REQUEST_HDR_LEN + 64;
    f->request = ngx_alloc(f->total + 16, &f->log); assert(f->request);
    memset(f->request, 0, f->total); memset(f->request + f->total, 0xa5, 16);
    uint16_t opcode = (uint16_t) atoi(argv[3]);
    if (!strcmp(argv[1], "scalar")) { scalar(f, argv[2], opcode); }
    else if (!strcmp(argv[1], "vector")) { vector(f, argv[2], opcode); }
    else { assert(!strcmp(argv[1], "checkpoint")); checkpoint(f, argv[2], opcode); }
    if (!f->errors) {
        for (size_t i = 0; i < 16; i++) { assert(f->request[f->total + i] == 0xa5); }
        ngx_free(f->request);
    }
    free(f); return 0;
}
