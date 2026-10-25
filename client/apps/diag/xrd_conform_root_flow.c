/* Phase-118 redirect, wait and asynchronous-attention conformance probes. */
#include "xrd_conform_probe_helpers.h"
#include "protocols/root/protocol/frame_hdr.h"

#include <arpa/inet.h>
#include <unistd.h>

#define FLOW_BODY_MAX 4096U

typedef struct {
    uint16_t sid;
    uint16_t status;
    uint32_t length;
    uint8_t body[FLOW_BODY_MAX];
} flow_reply;


static void
set_result(xrd_conform_execution *execution, const char *id, int pass,
    const char *success, const char *failure)
{
    if (!xrd_conform_row_active(execution, id)) return;
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? success : failure, NULL, NULL);
}

static void
set_skip(xrd_conform_execution *execution, const char *id, const char *reason)
{
    if (!xrd_conform_row_active(execution, id)) return;
    xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_SKIPPED,
        reason, NULL, NULL);
}

static void
set_skip_if_inconclusive(xrd_conform_execution *execution, const char *id,
    const char *reason)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    if (row == NULL || row->verdict != BRIX_CONFORM_VERDICT_INCONCLUSIVE)
        return;
    xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_SKIPPED,
        reason, NULL, NULL);
}

/* WHAT: Give every still-unobserved conditional flow row an explicit verdict.
 * WHY: A data server that emits no redirect/wait/attention must not leave rows
 *      as probe-not-executed or receive credit for behavior it never exposed.
 * HOW: Run probes first, then mark only their untouched rows as unobserved. */
static void
finalize_conditional_skips(xrd_conform_execution *execution)
{
    static const char *const ids[] = {
        "RDR-001", "RDR-002", "RDR-003", "RDR-004", "RDR-005", "RDR-006",
        "WAI-001", "WAI-002", "WAI-003", "ATN-001", "ATN-002", "ATN-003"
    };
    size_t index;

    for (index = 0; index < sizeof(ids) / sizeof(ids[0]); index++)
        set_skip_if_inconclusive(execution, ids[index],
            "response-not-observed");
    set_skip_if_inconclusive(execution, "WAI-004",
        "fixture-required:load-shedding");
}


static int
read_reply(brix_conn *connection, flow_reply *reply, brix_status *status)
{
    return xrd_conform_read_bounded_frame(connection, &reply->sid,
        &reply->status, &reply->length, reply->body, sizeof(reply->body), status);
}

static int
send_stat(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, uint16_t *sid, flow_reply *reply, brix_status *status)
{
    ClientRequestHdr request;
    brix_payload payload;
    size_t length = strlen(path);

    if (length > UINT32_MAX || !xrd_conform_reserve_probe(execution, length)) return -1;
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_stat);
    payload.data = path;
    payload.len = (uint32_t) length;
    if (brix_send(connection, &request, &payload, sid, status) != 0)
        return -1;
    return read_reply(connection, reply, status);
}

static int
connect_aux(xrd_conform_execution *execution, const brix_url *url,
    brix_conn *connection, brix_status *status)
{
    brix_opts opts = execution->run->opts;

    opts.capture = NULL;
    brix_status_clear(status);
    return brix_connect(connection, url, &opts, status);
}

/* WHAT: Determine whether a failed roots redirect names a clear-only peer.
 * WHY: A secure connect failure alone may be a trust/configuration problem;
 *      accepting the same object over root proves the redirect downgraded it.
 * HOW: Re-probe the asserted redirect authority with the clear ROOT scheme and
 *      require a successful stat before recording the security divergence. */
static void
probe_redirect_clear_fallback(xrd_conform_execution *execution,
    const brix_url *target, const char *path)
{
    brix_url clear = *target;
    brix_conn connection;
    brix_statinfo info;
    brix_status status;
    int connected;
    int served = 0;

    if (!xrd_conform_row_active(execution, "RDR-004")) return;
    clear.scheme = XRDC_SCHEME_ROOT;
    connected = connect_aux(execution, &clear, &connection, &status) == 0;
    if (connected) {
        brix_status_clear(&status);
        served = xrd_conform_reserve_probe(execution, 0)
            && brix_stat(&connection, path, &info, &status) == 0;
        brix_close(&connection);
    }
    xrd_conform_result_set(execution, "RDR-004",
        served ? BRIX_CONFORM_VERDICT_DIVERGENT
               : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
        served ? "redirect-downgraded-tls"
               : "redirect-target-security-unresolved",
        "redirect target rejects roots and serves only root",
        served ? "cleartext-target-served-path" : status.msg);
}

static void
probe_redirect_opaque(xrd_conform_execution *execution,
    brix_conn *connection, const brix_url *source, const char *opaque,
    brix_status *status)
{
    char redirected_path[XRDC_PATH_MAX];
    brix_file file;

    if (opaque[0] == '\0'
        || (size_t) snprintf(redirected_path, sizeof(redirected_path),
            "%s?%s", source->path, opaque) >= sizeof(redirected_path)) {
        set_skip(execution, "RDR-005", "fixture-absent:redirect-opaque");
        return;
    }
    brix_status_clear(status);
    if (xrd_conform_reserve_probe(execution, 0)
        && brix_file_open_read(connection, redirected_path, &file,
            status) == 0) {
        brix_status close_status;

        brix_status_clear(&close_status);
        brix_file_close(connection, &file, &close_status);
        set_result(execution, "RDR-005", 1, "redirect-opaque-honoured",
            "redirect-opaque-not-honoured");
        return;
    }
    set_result(execution, "RDR-005", 0, "redirect-opaque-honoured",
        "redirect-opaque-not-honoured");
}

static void
probe_connected_redirect(xrd_conform_execution *execution,
    const brix_url *source, brix_conn *connection, const char *opaque,
    brix_status *status)
{
    brix_statinfo info;
    int served;

    brix_status_clear(status);
    served = xrd_conform_reserve_probe(execution, 0)
        && brix_stat(connection, source->path, &info, status) == 0;
    set_result(execution, "RDR-002", served, "redirect-target-served-path",
        "redirect-target-did-not-serve-path");
    if (served)
        set_result(execution, "RDR-003", 1, "redirect-chain-converged",
            "redirect-loop-or-budget-exhausted");
    else if (status->kxr == XRDC_EREDIRECT)
        set_result(execution, "RDR-003", 0, "redirect-chain-converged",
            "redirect-loop-or-budget-exhausted");
    if (source->scheme == XRDC_SCHEME_ROOTS)
        set_result(execution, "RDR-004", served && connection->io.ssl != NULL,
            "redirect-preserved-tls", "redirect-downgraded-tls");
    else
        set_skip(execution, "RDR-004", "not-applicable:cleartext-source");
    probe_redirect_opaque(execution, connection, source, opaque, status);
}

static void
probe_redirect_target(xrd_conform_execution *execution, const brix_url *source,
    const flow_reply *reply)
{
    char host[256], opaque[4096];
    brix_url target = *source;
    brix_conn connection;
    brix_status status;
    int port = 0;
    int decoded;

    decoded = xrd_redirect_body_decode(reply->body, reply->length, host,
        sizeof(host), &port, opaque, sizeof(opaque));
    set_result(execution, "RDR-001",
        decoded == 0 && host[0] != '\0' && port > 0 && port <= 65535,
        "redirect-target-valid", "redirect-target-malformed");
    if (decoded != 0 || host[0] == '\0' || port <= 0 || port > 65535) return;
    if (strcmp(host, source->host) == 0 && port == source->port) {
        set_result(execution, "RDR-003", 0, "redirect-converged",
            "redirect-loop-to-current-endpoint");
        return;
    }
    snprintf(target.host, sizeof(target.host), "%s", host);
    target.port = port;
    if (connect_aux(execution, &target, &connection, &status) == 0) {
        probe_connected_redirect(execution, source, &connection, opaque,
            &status);
        brix_close(&connection);
    } else {
        set_result(execution, "RDR-002", 0,
            "redirect-target-served-path", "redirect-target-unreachable");
        if (source->scheme == XRDC_SCHEME_ROOTS)
            probe_redirect_clear_fallback(execution, &target, source->path);
    }
    set_skip_if_inconclusive(execution, "RDR-003",
        "fixture-absent:redirect-loop");
}

static void
probe_wait(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, uint16_t first_sid, const flow_reply *first)
{
    flow_reply second;
    brix_status status;
    uint16_t second_sid = 0;
    unsigned seconds = first->length == 4 ? xrd_get_u32_be(first->body) : 0;
    int shape_ok = first->length == 4 && seconds <= 3600;

    set_result(execution, "WAI-001", shape_ok,
        "wait-delay-plausible", "wait-delay-malformed-or-implausible");
    set_result(execution, "WAI-004", shape_ok,
        "load-shed-with-defined-wait", "load-shed-with-malformed-wait");
    if (!shape_ok) return;
    if (seconds > 2) {
        set_skip(execution, "WAI-002", "bounded-probe:wait-over-two-seconds");
        return;
    }
    if (seconds > 0) sleep(seconds);
    brix_status_clear(&status);
    if (send_stat(execution, connection, path, &second_sid, &second, &status)
        != 0) {
        set_result(execution, "WAI-002", 0,
            "wait-retry-progressed", "wait-retry-failed");
        return;
    }
    set_result(execution, "WAI-002",
        second.sid == second_sid && (second.status != kXR_wait
            || second.length != first->length
            || memcmp(second.body, first->body, first->length) != 0),
        "wait-retry-progressed", "wait-retry-repeated-identically");
    (void) first_sid;
}

/* WHAT: Grade the zero-eligible-server answer from an advertised manager.
 * WHY: An empty redirect is not a defined refusal and strands clients in an
 *      endpoint-less retry path.
 * HOW: Accept a bounded protocol error body; reject only malformed redirects,
 *      leaving normal redirects ungraded because they prove eligible servers. */
static void
probe_empty_manager(xrd_conform_execution *execution,
    const brix_conn *connection, const flow_reply *reply)
{
    char host[256], opaque[4096];
    uint32_t error;
    int port = 0;
    int decoded;

    if ((connection->server_flags & kXR_isManager) == 0) return;
    if (reply->status == kXR_error) {
        error = reply->length >= 4 ? xrd_get_u32_be(reply->body) : 0;
        set_result(execution, "RDR-006",
            reply->length >= 5 && error >= 3000 && error < 4000
                && reply->body[reply->length - 1] == '\0',
            "empty-manager-returned-defined-error",
            "empty-manager-error-malformed");
        return;
    }
    if (reply->status != kXR_redirect) return;
    decoded = xrd_redirect_body_decode(reply->body, reply->length, host,
        sizeof(host), &port, opaque, sizeof(opaque));
    if (decoded != 0 || host[0] == '\0' || port <= 0 || port > 65535)
        set_result(execution, "RDR-006", 0,
            "empty-manager-returned-defined-error",
            "empty-manager-returned-empty-redirect");
}

static void
probe_waitresp(xrd_conform_execution *execution, brix_conn *connection,
    uint16_t request_sid, const flow_reply *first)
{
    flow_reply pushed;
    brix_status status;
    uint16_t inner_sid = 0, inner_status = 0;
    uint32_t inner_length = 0;
    int envelope_ok;

    brix_status_clear(&status);
    envelope_ok = first->length == 4
        && xrd_get_u32_be(first->body) <= 3600
        && read_reply(connection, &pushed, &status) == 0
        && pushed.sid == request_sid && pushed.status == kXR_attn
        && pushed.length >= 16
        && xrd_get_u32_be(pushed.body) == (uint32_t) kXR_asynresp
        && xrd_get_u32_be(pushed.body + 4) == 0;
    if (envelope_ok) {
        xrd_resp_hdr_unpack(pushed.body + 8, &inner_sid, &inner_status,
            &inner_length);
        envelope_ok = inner_sid == request_sid
            && inner_length <= pushed.length - 16;
    }
    set_result(execution, "WAI-003", envelope_ok,
        "waitresp-followed-by-matching-response",
        "waitresp-asynresp-malformed-or-mismatched");
    set_result(execution, "ATN-001", envelope_ok,
        "asynresp-envelope-valid", "asynresp-envelope-invalid");
    set_result(execution, "ATN-003", envelope_ok,
        "asynresp-bound-to-deferred-stream",
        "asynresp-not-bound-to-deferred-stream");
    (void) inner_status;
}

static void
probe_async_message(xrd_conform_execution *execution, brix_conn *connection,
    uint16_t request_sid, const flow_reply *first)
{
    flow_reply terminal;
    brix_status status;
    uint16_t inner_sid = 0, inner_status = 0;
    uint32_t inner_length = 0;
    int valid = first->sid == 0 && first->length >= 17
        && xrd_get_u32_be(first->body) == (uint32_t) kXR_asyncms
        && xrd_get_u32_be(first->body + 4) == 0;

    if (valid) {
        xrd_resp_hdr_unpack(first->body + 8, &inner_sid, &inner_status,
            &inner_length);
        valid = inner_sid == 0 && inner_status == kXR_ok
            && inner_length == first->length - 16
            && first->body[first->length - 1] == '\0';
    }
    brix_status_clear(&status);
    if (valid && read_reply(connection, &terminal, &status) != 0) valid = 0;
    if (valid && terminal.sid != request_sid) valid = 0;
    set_result(execution, "ATN-002", valid,
        "async-message-bounded-and-terminated",
        "async-message-malformed-or-poisoned-stream");
}

void
xrd_conform_probe_flow(xrd_conform_execution *execution, const brix_url *url)
{
    brix_conn connection;
    brix_status status;
    flow_reply first;
    uint16_t sid = 0;

    if (!xrd_conform_family_active(execution, "RDR")
        && !xrd_conform_family_active(execution, "WAI")
        && !xrd_conform_family_active(execution, "ATN")) return;
    if (connect_aux(execution, url, &connection, &status) != 0) {
        finalize_conditional_skips(execution);
        return;
    }
    if (send_stat(execution, &connection, url->path, &sid, &first, &status)
        != 0) {
        brix_close(&connection);
        finalize_conditional_skips(execution);
        return;
    }
    probe_empty_manager(execution, &connection, &first);
    if (first.status == kXR_redirect)
        probe_redirect_target(execution, url, &first);
    else if (first.status == kXR_wait)
        probe_wait(execution, &connection, url->path, sid, &first);
    else if (first.status == kXR_waitresp)
        probe_waitresp(execution, &connection, sid, &first);
    else if (first.status == kXR_attn)
        probe_async_message(execution, &connection, sid, &first);
    brix_close(&connection);
    finalize_conditional_skips(execution);
}
