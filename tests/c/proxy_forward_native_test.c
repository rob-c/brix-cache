/* Reuse the established real-socket proxy fixture for complete request dispatch. */
#define main brix_lazy_contract_main
#include "proxy_lazy_native_test.c"
#undef main

typedef struct {
    fixture_t fixture;
    unsigned allocations, fail_at;
} forward_fixture_t;

void *__real_ngx_alloc(size_t size, ngx_log_t *log);

/* WHAT: Refuse one request-buffer allocation at a selected ownership boundary.
 * WHY: Request admission and optional retry copies have different outcomes.
 * HOW: Count only allocations carrying this fixture's log context. */
void *__wrap_ngx_alloc(size_t size, ngx_log_t *log)
{
    forward_fixture_t *state = log->data;
    if (state != NULL && ++state->allocations == state->fail_at) { return NULL; }
    return __real_ngx_alloc(size, log);
}

/* WHAT: Translate test operation names to the repository's authoritative opcodes.
 * WHY: Tests should not invent a second numeric wire table.
 * HOW: Use a local declarative mapping and reject unknown cases. */
static uint16_t operation(const char *name)
{
    const struct { const char *name; uint16_t opcode; } operations[] = {
        {"open", kXR_open}, {"rm", kXR_rm}, {"rmdir", kXR_rmdir},
        {"mkdir", kXR_mkdir}, {"chmod", kXR_chmod}, {"mv", kXR_mv},
        {"truncate", kXR_truncate}, {"prepare", kXR_prepare},
        {"read", kXR_read}, {"write", kXR_write}, {"close", kXR_close},
        {"sync", kXR_sync}, {"stat", kXR_stat}, {"fattr", kXR_fattr},
        {"clone", kXR_clone}, {"ping", kXR_ping},
    };
    for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i) {
        if (!strcmp(name, operations[i].name)) { return operations[i].opcode; }
    }
    assert(!"unknown operation"); return 0;
}

/* WHAT: Populate a framed request in the real receive context.
 * WHY: The public forwarding entry owns its copy and must preserve stream IDs.
 * HOW: Build the header once and retain a borrowed payload until dispatch returns. */
static void input(fixture_t *f, uint16_t opcode, const char *payload)
{
    size_t size = strlen(payload);
    u_char *bytes = request(f, opcode, size);
    bytes[4] = 0;
    memcpy(f->ctx.recv.hdr_buf, bytes, XRD_REQUEST_HDR_LEN);
    free(bytes);
    f->ctx.recv.cur_reqid = opcode;
    f->ctx.recv.cur_dlen = size;
    f->ctx.recv.cur_streamid[0] = 0xa1; f->ctx.recv.cur_streamid[1] = 0xb2;
    f->ctx.recv.payload = (u_char *)payload;
}

/* WHAT: Verify the complete forwarded frame and retry copy on the real socket.
 * WHY: A successful status cannot prove byte-exact forwarding or correct ownership.
 * HOW: Receive the declared bytes, compare payload/IDs, and check queue release. */
static void output(fixture_t *f, uint16_t opcode, const char *payload, u_char *bytes)
{
    size_t length = XRD_REQUEST_HDR_LEN + strlen(payload);
    receive_exact(f, bytes, length);
    assert(bytes[0] == 0xa1 && bytes[1] == 0xb2);
    assert(ntohs(((ClientRequestHdr *)(void *)bytes)->requestid) == opcode);
    assert(ntohl(((ClientRequestHdr *)(void *)bytes)->dlen) == strlen(payload));
    assert(!memcmp(bytes + XRD_REQUEST_HDR_LEN, payload, strlen(payload)));
    assert(f->proxy.wait_retry_req_len == length);
    assert(!memcmp(f->proxy.wait_retry_req, bytes, length));
    assert(f->proxy.wbuf == NULL && f->ctx.state == XRD_ST_PROXY);
    assert(f->error == 0 && f->aborts == 0);
}

/* WHAT: Verify audit fields against the already checked upstream request.
 * WHY: Handle opens and two-path renames record distinct audit shapes.
 * HOW: Check the selected operation's path fields and pending handle state. */
static void audit_fields(fixture_t *f, uint16_t opcode, const char *expected,
                          int audit, int strip)
{
    if (!audit || opcode == kXR_prepare) { return; }
    if (opcode == kXR_open) {
        assert(f->proxy.fwd_local_fh == 0);
        assert(f->proxy.fh_map[0].fh_state == BRIX_PROXY_FH_PENDING);
        assert(!strcmp(f->proxy.fh_map[0].path, expected));
        return;
    }
    assert(f->proxy.fwd_path_audit == 1);
    if (opcode == kXR_mv) {
        assert(!strcmp(f->proxy.fwd_path, strip ? "/first" : "/export/first"));
        assert(!strcmp(f->proxy.fwd_path2, strip ? "/last" : "/export/last"));
    } else {
        assert(!strcmp(f->proxy.fwd_path, expected) && !f->proxy.fwd_path2[0]);
    }
}

/* WHAT: Forward namespace operations with optional rewriting and audit capture.
 * WHY: Audit fields must describe the operation actually sent upstream.
 * HOW: Select one valid payload, dispatch and compare wire and audit results. */
static void path_operation(fixture_t *f, ngx_stream_brix_srv_conf_t *conf,
                           const char *mode, uint16_t opcode)
{
    const char *payload = opcode == kXR_mv ? "/export/first /export/last" : "/export/file";
    const char *expected = payload;
    int strip = !strcmp(mode, "strip");
    int audit = strcmp(mode, "no-audit") != 0 && strcmp(mode, "no-conf") != 0;
    if (strip) { ngx_str_set(&conf->proxy.path_strip, "/export"); }
    if (!audit) { conf->proxy.audit_log_fd = NGX_INVALID_FILE; }
    if (!strcmp(mode, "no-conf")) { f->proxy.conf = NULL; }
    input(f, opcode, payload);
    if (opcode == kXR_mv) {
        uint16_t size = htons(strlen("/export/first"));
        memcpy(f->ctx.recv.hdr_buf + 18, &size, 2);
    }
    if (strip && opcode != kXR_truncate) {
        expected = opcode == kXR_mv ? "/first /last" : "/file";
    }
    assert(brix_proxy_forward_request(&f->proxy, &f->ctx, &f->client) == NGX_OK);
    u_char bytes[128]; output(f, opcode, expected, bytes);
    assert(f->proxy.fwd_payload_len == strlen(expected));
    audit_fields(f, opcode, expected, audit, strip);
}

/* WHAT: Translate every byte of known handles and refuse unbound handles.
 * WHY: Local handle IDs must never escape into the upstream namespace.
 * HOW: Seed two opaque mappings and inspect the resulting real wire frame. */
static void handle_operation(fixture_t *f, const char *mode, uint16_t opcode)
{
    const u_char first[] = {0xff, 0x23, 0x45, 0x67};
    const u_char second[] = {0x81, 0x32, 0x54, 0x76};
    size_t offset = opcode == kXR_stat ? 16 : 4;
    input(f, opcode, "");
    f->ctx.recv.hdr_buf[offset] = 3;
    f->proxy.fh_map[3].fh_state = BRIX_PROXY_FH_BOUND;
    memcpy(f->proxy.fh_map[3].upstream_fh, first, 4);
    f->proxy.fh_map[4].fh_state = BRIX_PROXY_FH_BOUND;
    memcpy(f->proxy.fh_map[4].upstream_fh, second, 4);
    if (opcode == kXR_clone) { f->ctx.recv.hdr_buf[8] = 4; }
    if (!strcmp(mode, "invalid-handle")) { f->proxy.fh_map[3].fh_state = BRIX_PROXY_FH_FREE; }
    assert(brix_proxy_forward_request(&f->proxy, &f->ctx, &f->client) == NGX_OK);
    if (!strcmp(mode, "invalid-handle")) {
        assert(f->error == kXR_InvalidRequest);
        assert(f->proxy.wait_retry_req == NULL && f->proxy.wbuf == NULL);
        return;
    }
    u_char bytes[XRD_REQUEST_HDR_LEN]; output(f, opcode, "", bytes);
    assert(!memcmp(bytes + offset, first, 4));
    if (opcode == kXR_clone) { assert(!memcmp(bytes + 8, second, 4)); }
}

/* WHAT: Check allocation, transport and event-arm failure ownership.
 * WHY: Optional retry failure may continue, while send/arm failure must abort.
 * HOW: Inject at the existing seams and verify queue, timer and callback state. */
static void forwarding_failure(forward_fixture_t *state, const char *mode)
{
    fixture_t *f = &state->fixture;
    input(f, kXR_ping, "");
    f->proxy.wait_retry_req = malloc(3);
    assert(f->proxy.wait_retry_req != NULL);
    f->proxy.wait_retry_req_len = 3;
    if (!strcmp(mode, "allocation")) { state->fail_at = 1; }
    if (!strcmp(mode, "retry-allocation")) { state->fail_at = 2; }
    f->send_error = !strcmp(mode, "send-error");
    f->send_again = !strcmp(mode, "park");
    f->arm_error = !strcmp(mode, "arm-error");
    f->log.data = state;
    ngx_int_t status = brix_proxy_forward_request(&f->proxy, &f->ctx, &f->client);
    f->log.data = NULL;
    if (f->send_error || f->arm_error) {
        assert(status == NGX_ERROR && f->aborts == 1 && f->proxy.wbuf == NULL); return;
    }
    assert(status == NGX_OK);
    if (state->fail_at == 1) {
        assert(f->error == kXR_IOError && f->proxy.wait_retry_req_len == 3); return;
    }
    if (state->fail_at == 2) {
        u_char bytes[XRD_REQUEST_HDR_LEN]; receive_exact(f, bytes, sizeof(bytes));
        assert(f->proxy.wait_retry_req == NULL && f->proxy.wait_retry_req_len == 0);
        assert(f->proxy.wbuf == NULL && f->error == 0); return;
    }
    assert(f->proxy.wbuf != NULL && f->proxy.wbuf_pos == 0);
    assert(f->upstream_write.timer_set);
    ngx_del_timer(&f->upstream_write);
}

/* WHAT: Reject malformed rename framing and allocation failures atomically.
 * WHY: Neither an audit copy nor a half-rewritten operation may escape bounds.
 * HOW: Build a two-path frame, inject the selected defect, and observe dispatch. */
static void rename_refusal(forward_fixture_t *state,
                           ngx_stream_brix_srv_conf_t *conf, const char *mode)
{
    fixture_t *f = &state->fixture;
    ngx_str_set(&conf->proxy.path_strip, "/export");
    const char *payload = "/export/first /export/last";
    uint16_t length = strlen("/export/first");
    if (!strcmp(mode, "length")) { length = 200; }
    if (!strcmp(mode, "negative")) { length = UINT16_MAX; }
    if (!strcmp(mode, "separator")) { length--; }
    if (!strcmp(mode, "source")) { payload = " /export/last"; length = 0; }
    if (!strcmp(mode, "destination")) { payload = "/export/first "; }
    if (!strcmp(mode, "no-space")) { payload = "/export/first"; length = 0; }
    input(f, kXR_mv, payload);
    length = htons(length); memcpy(f->ctx.recv.hdr_buf + 18, &length, 2);
    if (!strncmp(mode, "allocation-", 11)) { state->fail_at = atoi(mode + 11); }
    f->log.data = state;
    assert(brix_proxy_forward_request(&f->proxy, &f->ctx, &f->client) == NGX_OK);
    f->log.data = NULL;
    assert(f->error == (state->fail_at ? kXR_IOError : kXR_ArgInvalid));
    assert(f->proxy.wbuf == NULL && f->proxy.wait_retry_req == NULL);
    assert(f->proxy.fwd_path_audit == 0);
    u_char byte;
    assert(recv(f->pair[1], &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
}

/* WHAT: Preserve autosplit, spaces and long source paths across a rename.
 * WHY: The wire source length and audit truncation are different quantities.
 * HOW: Dispatch valid frames and compare rewritten framing and both audit paths. */
static void rename_boundaries(fixture_t *f, ngx_stream_brix_srv_conf_t *conf,
                              const char *mode)
{
    size_t source = !strcmp(mode, "long") ? BRIX_PROXY_PATH_MAX + 64 : 16;
    char *payload = malloc(source + 15);
    assert(payload != NULL);
    memset(payload, 'a', source);
    memcpy(payload, "/export/", 8);
    if (!strcmp(mode, "spaces")) { payload[10] = ' '; }
    strcpy(payload + source, " /export/last");
    input(f, kXR_mv, payload);
    uint16_t length = htons(!strcmp(mode, "autosplit") ? 0 : source);
    memcpy(f->ctx.recv.hdr_buf + 18, &length, 2);
    ngx_str_set(&conf->proxy.path_strip, "/export");
    assert(brix_proxy_forward_request(&f->proxy, &f->ctx, &f->client) == NGX_OK);
    char *expected = malloc(source + 8);
    u_char *bytes = malloc(source + 64);
    assert(expected != NULL && bytes != NULL);
    memcpy(expected, payload + 7, source - 7);
    strcpy(expected + source - 7, " /last");
    output(f, kXR_mv, expected, bytes);
    memcpy(&length, bytes + 18, 2);
    assert(ntohs(length) == source - 7);
    size_t audit = source - 7;
    if (audit >= BRIX_PROXY_PATH_MAX) { audit = BRIX_PROXY_PATH_MAX - 1; }
    assert(strlen(f->proxy.fwd_path) == audit);
    assert(!memcmp(f->proxy.fwd_path, expected, audit));
    assert(!strcmp(f->proxy.fwd_path2, "/last"));
    free(bytes); free(expected); free(payload);
}

/* WHAT: Run complete forwarding through the established socket/session fixture.
 * WHY: New dispatcher coverage must share the same transport ownership contract.
 * HOW: Initialize, select one operation family, then reuse fixture cleanup. */
int main(int argc, char **argv)
{
    assert(argc == 3);
    forward_fixture_t *state = calloc(1, sizeof(*state));
    assert(state != NULL);
    fixture_t *f = &state->fixture;
    signal(SIGPIPE, SIG_IGN); setup(f, argv);
    assert(ngx_event_timer_init(&f->log) == NGX_OK);
    ngx_stream_brix_srv_conf_t conf = {0};
    conf.proxy.audit_log_fd = 1; conf.proxy.write_timeout = 250;
    f->proxy.conf = &conf;
    if (!strcmp(argv[1], "rename-refusal")) { rename_refusal(state, &conf, argv[2]); }
    else if (!strcmp(argv[1], "rename-boundary")) { rename_boundaries(f, &conf, argv[2]); }
    else if (!strcmp(argv[2], "fault")) { forwarding_failure(state, argv[1]); }
    else if (!strcmp(argv[1], "handle") || !strcmp(argv[1], "invalid-handle")) {
        handle_operation(f, argv[1], operation(argv[2]));
    } else { path_operation(f, &conf, argv[1], operation(argv[2])); }
    teardown(f); free(state);
    return 0;
}
