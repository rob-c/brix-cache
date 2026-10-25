/* Phase-118 externally asserted kXR_open lifecycle fixtures. */
#include "xrd_conform_probe_helpers.h"
#include "protocols/root/protocol/frame_hdr.h"
#include "protocols/root/protocol/codec/wire_codec.h"

#include <arpa/inet.h>

static const char *
fixture_target(const xrd_conform_run *run, const char *kind)
{
    size_t index;

    for (index = 0; index < run->open_fixture_count; index++)
        if (strcmp(run->open_fixtures[index].kind, kind) == 0)
            return run->open_fixtures[index].target;
    return NULL;
}



static int
connect_fixture(xrd_conform_execution *execution, const char *target,
    int anonymous, brix_url *url, brix_conn *connection, brix_status *status)
{
    brix_opts opts = execution->run->opts;

    opts.capture = NULL;
    opts.force_anon = anonymous;
    brix_status_clear(status);
    return brix_endpoint_parse(target, url, status) == 0
        && (url->scheme == XRDC_SCHEME_ROOT
            || url->scheme == XRDC_SCHEME_ROOTS)
        && brix_connect(connection, url, &opts, status) == 0 ? 0 : -1;
}

static int
open_write_refusal(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_status *status)
{
    brix_file file;
    int rc;

    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    brix_status_clear(status);
    rc = brix_file_open_write(connection, object->path, 1, 0, &file, status);
    if (rc == 0 && xrd_conform_reserve_status(execution, 0, status))
        brix_file_close(connection, &file, status);
    return rc;
}

static void
readonly_attempt(xrd_conform_execution *execution, const char *target,
    int anonymous_mode, const xrd_conform_scratch_object *object,
    brix_url *url, brix_conn *connection, brix_status *status,
    int *connected, int *rc, int *authenticated_identity)
{
    *connected = connect_fixture(execution, target, anonymous_mode, url,
        connection, status) == 0;
    if (!*connected) return;
    if (!anonymous_mode)
        *authenticated_identity = connection->diag.chosen_auth != NULL;
    *rc = open_write_refusal(execution, connection, object, status);
}

static void
readonly_cleanup(xrd_conform_execution *execution,
    const xrd_conform_scratch_object *object, brix_conn *anonymous,
    brix_conn *authenticated, brix_status *status, int anonymous_connected,
    int authenticated_connected, int anonymous_rc, int authenticated_rc)
{
    if (authenticated_connected
        && (anonymous_rc == 0 || authenticated_rc == 0)
        && xrd_conform_reserve_status(execution, 0, status))
        brix_rm(authenticated, object->path, status);
    if (anonymous_connected) brix_close(anonymous);
    if (authenticated_connected) brix_close(authenticated);
}

/* WHAT: Compare read-only policy before and after credential evaluation.
 * WHY: Returning NotAuthorized to anonymous clients leaks auth ordering and
 *      contradicts the typed export policy's fail-closed EROFS precedence.
 * HOW: Connect once anonymously and once normally to the asserted read-only
 *      endpoint, then require the identical exact fsReadOnly create refusal. */
static void
probe_readonly(xrd_conform_execution *execution, const char *target)
{
    xrd_conform_scratch_object object;
    brix_url anonymous_url, authenticated_url;
    brix_conn anonymous, authenticated;
    brix_status anonymous_status, authenticated_status;
    int anonymous_connected = 0;
    int authenticated_connected = 0;
    int anonymous_rc = -1;
    int authenticated_rc = -1;
    int authenticated_identity = 0;
    char received[192];

    if (!xrd_conform_row_active(execution, "OPN-012") || target == NULL) return;
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-open-readonly-order", object.path,
            sizeof(object.path)) != 0) return;
    readonly_attempt(execution, target, 1, &object, &anonymous_url,
        &anonymous, &anonymous_status, &anonymous_connected, &anonymous_rc,
        &authenticated_identity);
    readonly_attempt(execution, target, 0, &object, &authenticated_url,
        &authenticated, &authenticated_status, &authenticated_connected,
        &authenticated_rc, &authenticated_identity);
    snprintf(received, sizeof(received),
        "anonymous=%d/%d authenticated=%d/%d identity=%d",
        anonymous_rc, anonymous_status.kxr, authenticated_rc,
        authenticated_status.kxr, authenticated_identity);
    if (!anonymous_connected || !authenticated_connected
        || !authenticated_identity) {
        xrd_conform_result_set(execution, "OPN-012",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "readonly-identity-pair-unavailable", NULL, received);
    } else {
        int pass = anonymous_rc != 0 && authenticated_rc != 0
            && anonymous_status.kxr == kXR_fsReadOnly
            && authenticated_status.kxr == kXR_fsReadOnly;

        xrd_conform_result_set(execution, "OPN-012",
            pass ? BRIX_CONFORM_VERDICT_CONFORMANT
                 : BRIX_CONFORM_VERDICT_DIVERGENT,
            pass ? "readonly-refusal-preceded-credential-evaluation"
                 : "readonly-refusal-depended-on-credential",
            "anonymous and authenticated kXR_fsReadOnly", received);
    }
    readonly_cleanup(execution, &object, &anonymous, &authenticated,
        &authenticated_status, anonymous_connected, authenticated_connected,
        anonymous_rc, authenticated_rc);
}

static int
send_open_once(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, uint16_t options, uint16_t *wire_status,
    uint8_t **body, uint32_t *body_length, brix_status *status)
{
    ClientOpenRequest request;
    xrdw_open_req_t fields = { .mode = 0, .options = options, .optiont = 0 };
    brix_payload payload = { path, (uint32_t) strlen(path) };
    brix_resp_out response = { wire_status, body, body_length };
    uint16_t sid;

    if (!xrd_conform_reserve_status(execution, sizeof(request) + payload.len, status)) return -1;
    xrd_creq_begin(&request, sizeof(request), 0, kXR_open);
    xrdw_open_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(status);
    if (brix_send(connection, (ClientRequestHdr *) &request, &payload,
            &sid, status) != 0) return -1;
    return brix_recv(connection, sid, &response, status);
}

static int
nowait_answer_defined(int connected, uint64_t elapsed_ms, int rc,
    uint16_t wire_status, const brix_status *status)
{
    if (!connected || elapsed_ms > 2000) return 0;
    if (rc == 0) return wire_status == kXR_ok || wire_status == kXR_wait;
    return status->kxr > 0 && status->kxr != kXR_ServerError
        && status->kxr != kXR_FSError;
}

static void
close_open_response(xrd_conform_execution *execution, brix_conn *connection,
    int rc, uint16_t wire_status, const uint8_t *body, uint32_t body_length,
    brix_status *status)
{
    brix_file file = { { 0 }, 0, 0 };

    if (rc != 0 || wire_status != kXR_ok || body_length < XRD_FHANDLE_LEN)
        return;
    memcpy(file.fhandle, body, XRD_FHANDLE_LEN);
    if (xrd_conform_reserve_status(execution, 0, status))
        brix_file_close(connection, &file, status);
}

/* WHAT: Require an asserted offline object to answer a nowait open promptly.
 * WHY: The ordinary roundtrip helper retries kXR_wait; this clause must inspect
 *      the first answer before any client-side sleep can hide server blocking.
 * HOW: Send/receive exactly once and accept success or any defined non-server
 *      error within two seconds, retaining the first wire status as evidence. */
static void
probe_staged_nowait(xrd_conform_execution *execution, const char *target)
{
    brix_url url;
    brix_conn connection;
    brix_status status;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    uint16_t wire_status = 0;
    uint64_t started;
    uint64_t elapsed_ms = 0;
    int connected;
    int rc = -1;
    int defined;
    char received[160];

    if (!xrd_conform_row_active(execution, "OPN-020") || target == NULL) return;
    connected = connect_fixture(execution, target, 0, &url, &connection,
        &status) == 0;
    started = brix_mono_ns();
    if (connected)
        rc = send_open_once(execution, &connection, url.path,
            kXR_open_read | kXR_nowait, &wire_status, &body, &body_length,
            &status);
    if (started != 0) elapsed_ms = (brix_mono_ns() - started) / 1000000U;
    defined = nowait_answer_defined(connected, elapsed_ms, rc, wire_status,
        &status);
    snprintf(received, sizeof(received), "elapsed_ms=%llu wire=%u kxr=%d",
        (unsigned long long) elapsed_ms, (unsigned) wire_status, status.kxr);
    xrd_conform_result_set(execution, "OPN-020",
        defined ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        defined ? "offline-nowait-returned-prompt-defined-answer"
                : "offline-nowait-blocked-or-returned-undefined-answer",
        "first answer in <=2000ms", received);
    close_open_response(execution, &connection, rc, wire_status, body,
        body_length, &status);
    free(body);
    if (connected) brix_close(&connection);
}

static int
idle_answer_defined(int opened, ssize_t got, const brix_status *status)
{
    if (!opened) return 0;
    if (got == 1) return 1;
    return got < 0 && status->kxr > 0 && status->kxr != kXR_ServerError
        && status->kxr != kXR_FSError;
}

/* WHAT: Exercise a handle after an asserted sub-two-second idle threshold.
 * WHY: A transport drop masquerading as handle expiry is not a defined answer.
 * HOW: Open, idle for two seconds, then require either one byte or a native kXR
 *      refusal; a socket/protocol failure is divergent. */
static void
probe_idle(xrd_conform_execution *execution, const char *target)
{
    brix_url url;
    brix_conn connection;
    brix_file file;
    brix_status status;
    struct timespec idle = { 2, 0 };
    uint8_t byte;
    ssize_t got = -1;
    int connected;
    int opened = 0;
    int pass;
    char received[128];

    if (!xrd_conform_row_active(execution, "OPN-033") || target == NULL) return;
    connected = connect_fixture(execution, target, 0, &url, &connection,
        &status) == 0;
    if (connected && xrd_conform_reserve_status(execution, 0, &status)
        && brix_file_open_read(&connection, url.path, &file, &status) == 0) {
        opened = 1;
        while (nanosleep(&idle, &idle) != 0 && errno == EINTR) { }
        if (xrd_conform_reserve_status(execution, 1, &status))
            got = brix_file_read(&connection, &file, 0, &byte, 1, &status);
    }
    pass = idle_answer_defined(opened, got, &status);
    snprintf(received, sizeof(received), "opened=%d read=%lld kxr=%d",
        opened, (long long) got, status.kxr);
    xrd_conform_result_set(execution, "OPN-033",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? (got == 1 ? "idle-handle-survived"
                         : "idle-handle-returned-defined-error")
             : "idle-handle-silently-invalidated",
        "two-second idle then byte or native kXR error", received);
    if (opened && xrd_conform_reserve_status(execution, 0, &status))
        brix_file_close(&connection, &file, &status);
    if (connected) brix_close(&connection);
}

void
xrd_conform_probe_open_fixtures(xrd_conform_execution *execution)
{
    probe_readonly(execution, fixture_target(execution->run, "readonly"));
    probe_staged_nowait(execution,
        fixture_target(execution->run, "staged-nowait"));
    probe_idle(execution, fixture_target(execution->run, "idle"));
}
