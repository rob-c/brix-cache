/* Phase-118 locate endpoint follow-through probe. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/codec/wire_codec.h"
#include "protocols/root/protocol/frame_hdr.h"

#include <arpa/inet.h>

#define CONFORM_LOCATE_URL_MAX 1024
#define CONFORM_LOCATE_ENDPOINT_MAX 32

int
xrd_conform_cms_outage_exact_selected(
    const xrd_conform_execution *execution)
{
    const char *only;

    if (execution == NULL || execution->run == NULL) return 0;
    only = execution->run->config.only;
    return only != NULL && strncmp(only, "CMS-", 4) == 0
        && strcmp(only, "CMS-001") >= 0 && strcmp(only, "CMS-007") <= 0;
}

static int
endpoint_compare(const void *left, const void *right)
{
    return strcmp((const char *) left, (const char *) right);
}

/* WHAT: Canonicalize a locate holder set independent of reply ordering.
 * WHY: Redundant managers may enumerate the same holders in different order.
 * HOW: Extract bounded S/s authorities, sort them, and join with newlines. */
int
xrd_conform_canonical_holder_set(const char *reply, char *canonical,
    size_t canonical_size)
{
    char endpoints[CONFORM_LOCATE_ENDPOINT_MAX][320];
    const char *cursor = reply;
    size_t count = 0;
    size_t used = 0;
    size_t index;

    while (cursor != NULL && *cursor != '\0') {
        const char *start;
        size_t length;

        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n') cursor++;
        start = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t'
            && *cursor != '\n') cursor++;
        length = (size_t) (cursor - start);
        if (length <= 2 || (start[0] != 'S' && start[0] != 's')) continue;
        if (count >= CONFORM_LOCATE_ENDPOINT_MAX
            || length - 2 >= sizeof(endpoints[0])) return -1;
        memcpy(endpoints[count], start + 2, length - 2);
        endpoints[count][length - 2] = '\0';
        count++;
    }
    if (count == 0) return -1;
    qsort(endpoints, count, sizeof(endpoints[0]), endpoint_compare);
    canonical[0] = '\0';
    for (index = 0; index < count; index++) {
        int written = snprintf(canonical + used, canonical_size - used,
            "%s%s", index == 0 ? "" : "\n", endpoints[index]);

        if (written < 0 || (size_t) written >= canonical_size - used)
            return -1;
        used += (size_t) written;
    }
    return 0;
}

static void
compare_manager_set(xrd_conform_execution *execution, const char *reply)
{
    char canonical[sizeof(execution->cms_manager_holder_set)];

    if (xrd_conform_canonical_holder_set(reply, canonical,
            sizeof(canonical)) != 0) return;
    if (execution->cms_manager_count == 0) {
        snprintf(execution->cms_manager_holder_set,
            sizeof(execution->cms_manager_holder_set), "%s", canonical);
        execution->cms_manager_sets_consistent = 1;
    } else {
        execution->cms_manager_sets_consistent &= strcmp(
            execution->cms_manager_holder_set, canonical) == 0;
    }
    execution->cms_manager_count++;
    if (execution->cms_manager_count >= 2) {
        xrd_conform_result_set(execution, "CMS-005",
            execution->cms_manager_sets_consistent
                ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
            execution->cms_manager_sets_consistent
                ? "redundant-manager-holder-sets-agree"
                : "redundant-manager-holder-set-mismatch",
            "canonical locate holder sets agree", NULL);
    }
}

/* WHAT: Observe the manager-only endpoint's first open response without the
 *       client's automatic redirect handling.
 * WHY: A followed redirect looks like a successful open and cannot prove that
 *      a manager-only role avoided serving object bytes itself.
 * HOW: Send one framed open, read only its response header, then close the
 *      assessment connection after the caller finishes this manager probe. */
static void
probe_manager_direct_service(xrd_conform_execution *execution,
    brix_conn *manager, const char *path, int *response_observed,
    uint16_t *response_status)
{
    ClientOpenRequest request;
    xrdw_open_req_t fields = {
        .mode = 0, .options = kXR_open_read, .optiont = 0
    };
    brix_payload payload = { path, (uint32_t) strlen(path) };
    brix_url url;
    brix_conn probe;
    brix_opts opts = execution->run->opts;
    uint8_t header[XRD_RESPONSE_HDR_LEN];
    uint16_t stream_id;
    uint16_t response_stream;
    uint16_t wire_status = 0;
    uint32_t response_length;
    brix_status status;
    char reason[64];
    int observed = 0;
    int pass = 0;

    *response_observed = 0;
    *response_status = 0;
    if ((manager->server_flags & (kXR_isServer | kXR_isManager))
        != kXR_isManager) return;
    opts.capture = NULL;
    brix_status_clear(&status);
    if (brix_endpoint_parse(execution->target, &url, &status) != 0
        || brix_connect(&probe, &url, &opts, &status) != 0) {
        xrd_conform_result_set(execution, "CMS-006",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "manager-open-probe-connection-unavailable", NULL, status.msg);
        return;
    }
    if (!xrd_conform_reserve(execution, sizeof(request) + payload.len,
            reason, sizeof(reason))) {
        xrd_conform_result_set(execution, "CMS-006",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, reason, NULL, NULL);
        brix_close(&probe);
        return;
    }
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_open);
    xrdw_open_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(&status);
    if (brix_send(&probe, &request, &payload, &stream_id, &status) == 0
        && brix_read_full(&probe.io, header, sizeof(header), &status) == 0) {
        xrd_resp_hdr_unpack(header, &response_stream, &wire_status,
            &response_length);
        observed = response_stream == stream_id;
        pass = observed && (wire_status == kXR_redirect
            || wire_status == kXR_error);
    }
    xrd_conform_result_set(execution, "CMS-006",
        !observed ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                  : pass ? BRIX_CONFORM_VERDICT_CONFORMANT
                         : BRIX_CONFORM_VERDICT_DIVERGENT,
        !observed ? "manager-open-response-unavailable"
                  : pass ? "manager-only-open-redirected-or-refused"
                         : "manager-only-open-served-directly",
        "kXR_redirect or defined error", observed ? NULL : status.msg);
    *response_observed = observed;
    *response_status = wire_status;
    brix_close(&probe);
}

int
xrd_conform_first_data_endpoint(const char *reply, char *endpoint,
    size_t endpoint_size)
{
    const char *cursor = reply;

    while (cursor != NULL && *cursor != '\0') {
        const char *start;
        size_t length;

        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n') cursor++;
        start = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t'
            && *cursor != '\n') cursor++;
        length = (size_t) (cursor - start);
        if (length > 2 && (start[0] == 'S' || start[0] == 's')) {
            length -= 2;
            if (length >= endpoint_size) return -1;
            memcpy(endpoint, start + 2, length);
            endpoint[length] = '\0';
            return 0;
        }
    }
    return -1;
}

/* WHAT: Prove that every advertised locate holder directly serves the path.
 * WHY: Checking only the first token misses stale or ghost replicas later in
 *      the manager's holder set and cannot substantiate CMS-001.
 * HOW: Parse the bounded reply, cap fan-out, connect to each S/s endpoint and
 *      issue a direct stat without reusing the manager connection. */
static int
verify_data_endpoints(xrd_conform_execution *execution, const char *reply,
    const char *path, char *received, size_t received_size,
    size_t *holder_count, size_t *served_count)
{
    const char *cursor = reply;
    brix_opts opts = execution->run->opts;
    size_t holders = 0;
    size_t served = 0;
    int malformed = 0;

    opts.capture = NULL;
    while (cursor != NULL && *cursor != '\0') {
        const char *start;
        size_t length;

        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n') cursor++;
        start = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t'
            && *cursor != '\n') cursor++;
        length = (size_t) (cursor - start);
        if (length <= 2 || (start[0] != 'S' && start[0] != 's')) continue;
        if (holders >= CONFORM_LOCATE_ENDPOINT_MAX) {
            malformed = 1;
            break;
        }
        {
            char endpoint[320];
            char url_text[CONFORM_LOCATE_URL_MAX];
            char reason[64];
            brix_url url;
            brix_conn connection;
            brix_statinfo info;
            brix_status status;
            size_t endpoint_length = length - 2;

            holders++;
            if (endpoint_length >= sizeof(endpoint)
                || !xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
                malformed = 1;
                break;
            }
            memcpy(endpoint, start + 2, endpoint_length);
            endpoint[endpoint_length] = '\0';
            if ((size_t) snprintf(url_text, sizeof(url_text), "root://%s%s",
                    endpoint, path) >= sizeof(url_text)) {
                malformed = 1;
                continue;
            }
            brix_status_clear(&status);
            if (brix_url_parse(url_text, &url, &status) == 0
                && brix_connect(&connection, &url, &opts, &status) == 0) {
                if (xrd_conform_reserve(execution, 0, reason,
                        sizeof(reason))) {
                    brix_status_clear(&status);
                    if (brix_stat(&connection, url.path, &info, &status) == 0)
                        served++;
                }
                brix_close(&connection);
            }
        }
    }
    snprintf(received, received_size, "holders=%zu served=%zu malformed=%d",
        holders, served, malformed);
    *holder_count = holders;
    *served_count = served;
    return holders != 0 && served == holders && !malformed;
}

/* WHAT: Grade controlled partial- and total-holder outage topologies.
 * WHY: CMS-003/004 require both locate reachability and unfollowed open status.
 * HOW: Only grade when the observed holder counts unambiguously identify the
 *      requested topology; otherwise leave the fixture gate untouched. */
static void
grade_outage_rows(xrd_conform_execution *execution, size_t holders,
    size_t served, int open_observed, uint16_t open_status)
{
    char received[96];

    snprintf(received, sizeof(received),
        "holders=%zu served=%zu open=%u observed=%d", holders, served,
        (unsigned) open_status, open_observed);
    if (holders >= 2 && served > 0 && served < holders)
        xrd_conform_result_set(execution, "CMS-003",
            open_observed && open_status == kXR_redirect
                ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
            open_observed && open_status == kXR_redirect
                ? "partial-outage-redirected-to-live-holder"
                : "partial-outage-did-not-return-redirect",
            "at least one live and one down holder; first-hop redirect",
            received);
    if (holders > 0 && served == 0)
        xrd_conform_result_set(execution, "CMS-004",
            open_observed && open_status == kXR_error
                ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
            open_observed && open_status == kXR_error
                ? "all-holders-down-returned-defined-error"
                : "all-holders-down-redirected-or-hung",
            "all advertised holders unreachable; first-hop defined error",
            received);
}

/* WHAT: Ask a manager to locate a deterministic path that cannot be planted.
 * WHY: CMS-002 requires a defined NotFound, never an empty successful answer.
 * HOW: Derive a sibling from the adopted path and run one bounded locate. */
static void
probe_missing_holder_set(xrd_conform_execution *execution,
    brix_conn *primary, const char *path)
{
    char missing[XRDC_PATH_MAX];
    char reply[64];
    char reason[64];
    brix_status status;
    int rc;

    if ((size_t) snprintf(missing, sizeof(missing),
            "%s.brix-conform-missing-%.8s", path,
            execution->run->key_hex) >= sizeof(missing)) {
        xrd_conform_result_set(execution, "CMS-002",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "derived-missing-path-too-long", NULL, NULL);
        return;
    }
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        xrd_conform_result_set(execution, "CMS-002",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, reason, NULL, NULL);
        return;
    }
    brix_status_clear(&status);
    rc = brix_locate(primary, missing, reply, sizeof(reply), &status);
    xrd_conform_result_set(execution, "CMS-002",
        rc != 0 && status.kxr == kXR_NotFound
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        rc != 0 && status.kxr == kXR_NotFound
            ? "empty-holder-set-is-not-found"
            : "empty-holder-set-wrong-answer",
        "kXR_NotFound", rc == 0 ? reply : status.msg);
}

/* WHAT: Assess manager holder semantics before any redirect mutates the conn.
 * WHY: libbrix follows redirects in place, replacing manager role flags and
 *      authority with the data server before ordinary object probes run.
 * HOW: Capture locate evidence immediately after the manager login, verify
 *      each advertised holder directly, then test a deterministic empty set. */
void
xrd_conform_probe_cms_manager(xrd_conform_execution *execution,
    brix_conn *manager, const char *path)
{
    char reply[2048];
    char observed[96];
    char reason[64];
    brix_status status;
    int all_served;
    int open_observed = 0;
    uint16_t open_status = 0;
    size_t holders = 0;
    size_t served = 0;

    if ((manager->server_flags & kXR_isManager) == 0) return;
    probe_manager_direct_service(execution, manager, path, &open_observed,
        &open_status);
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        xrd_conform_result_set(execution, "CMS-001",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, reason, NULL, NULL);
        return;
    }
    brix_status_clear(&status);
    if (brix_locate(manager, path, reply, sizeof(reply), &status) != 0) {
        xrd_conform_result_set(execution, "CMS-001",
            BRIX_CONFORM_VERDICT_DIVERGENT,
            "manager-locate-existing-path-failed", "non-empty holder set",
            status.msg);
        probe_missing_holder_set(execution, manager, path);
        return;
    }
    compare_manager_set(execution, reply);
    xrd_conform_probe_cms_map(execution, reply);
    all_served = verify_data_endpoints(execution, reply, path, observed,
        sizeof(observed), &holders, &served);
    xrd_conform_result_set(execution, "CMS-001",
        all_served ? BRIX_CONFORM_VERDICT_CONFORMANT
                   : BRIX_CONFORM_VERDICT_DIVERGENT,
        all_served ? "manager-holder-set-serves-path"
                   : "manager-holder-set-has-ghost",
        "every located holder directly stats the path", observed);
    grade_outage_rows(execution, holders, served, open_observed, open_status);
    probe_missing_holder_set(execution, manager, path);
}

static int
locate_row_active(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

static const char *
locate_fixture_target(const xrd_conform_run *run, const char *kind)
{
    size_t index;

    for (index = 0; index < run->locate_fixture_count; index++)
        if (strcmp(run->locate_fixtures[index].kind, kind) == 0)
            return run->locate_fixtures[index].target;
    return NULL;
}

static int
connect_locate_fixture(xrd_conform_execution *execution, const char *target,
    brix_url *url, brix_conn *connection, brix_status *status)
{
    brix_opts opts = execution->run->opts;

    opts.capture = NULL;
    brix_status_clear(status);
    return brix_endpoint_parse(target, url, status) == 0
        && (url->scheme == XRDC_SCHEME_ROOT
            || url->scheme == XRDC_SCHEME_ROOTS)
        && brix_connect(connection, url, &opts, status) == 0 ? 0 : -1;
}

/* WHAT: Compare cached and explicitly refreshed locate observations.
 * WHY: A single locate reply cannot prove that kXR_refresh bypassed cache.
 * HOW: Query the asserted mutable fixture normally and with kXR_refresh, then
 *      require two successful but distinct replies. */
static void
probe_locate_refresh_fixture(xrd_conform_execution *execution,
    const char *target)
{
    brix_url url;
    brix_conn connection;
    brix_status status;
    char cached[2048];
    char refreshed[2048];
    char received[192];
    char reason[64];
    int connected;
    int cached_rc = -1;
    int refreshed_rc = -1;

    if (!locate_row_active(execution, "LOC-005")) return;
    if (target == NULL) {
        xrd_conform_result_set(execution, "LOC-005",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:mutable-locate-cache", NULL, NULL);
        return;
    }
    connected = connect_locate_fixture(execution, target, &url, &connection,
        &status) == 0;
    if (connected && xrd_conform_reserve(execution, 0, reason, sizeof(reason)))
        cached_rc = brix_locate_opts(&connection, url.path, 0, cached,
            sizeof(cached), &status);
    if (cached_rc == 0
        && xrd_conform_reserve(execution, 0, reason, sizeof(reason)))
        refreshed_rc = brix_locate_opts(&connection, url.path, kXR_refresh,
            refreshed, sizeof(refreshed), &status);
    snprintf(received, sizeof(received),
        "connected=%d cached=%d refreshed=%d changed=%d",
        connected, cached_rc, refreshed_rc,
        cached_rc == 0 && refreshed_rc == 0
            && strcmp(cached, refreshed) != 0);
    xrd_conform_result_set(execution, "LOC-005",
        !connected || cached_rc != 0 || refreshed_rc != 0
            ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
            : strcmp(cached, refreshed) != 0
                ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        !connected || cached_rc != 0 || refreshed_rc != 0
            ? "mutable-locate-fixture-unavailable"
            : strcmp(cached, refreshed) != 0
                ? "refresh-returned-fresh-locate-answer"
                : "refresh-returned-cached-locate-answer",
        "ordinary and refreshed locate replies differ", received);
    if (connected) brix_close(&connection);
}

/* WHAT: Time one kXR_nowait locate against an asserted slow-member topology.
 * WHY: A normal fast cluster cannot establish the option's non-blocking rule.
 * HOW: Measure a single option-bearing request and require a valid reply within
 *      the protocol assessment's two-second promptness threshold. */
static void
probe_locate_nowait_fixture(xrd_conform_execution *execution,
    const char *target)
{
    brix_url url;
    brix_conn connection;
    brix_status status;
    char reply[2048];
    char received[160];
    char reason[64];
    uint64_t started = 0;
    uint64_t elapsed_ms = 0;
    int connected;
    int rc = -1;

    if (!locate_row_active(execution, "LOC-006")) return;
    if (target == NULL) {
        xrd_conform_result_set(execution, "LOC-006",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:slow-cluster-member", NULL, NULL);
        return;
    }
    connected = connect_locate_fixture(execution, target, &url, &connection,
        &status) == 0;
    if (connected && xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        started = brix_mono_ns();
        rc = brix_locate_opts(&connection, url.path, kXR_nowait, reply,
            sizeof(reply), &status);
        elapsed_ms = (brix_mono_ns() - started) / 1000000U;
    }
    snprintf(received, sizeof(received),
        "connected=%d rc=%d elapsed_ms=%llu kxr=%d", connected, rc,
        (unsigned long long) elapsed_ms, status.kxr);
    xrd_conform_result_set(execution, "LOC-006",
        !connected || rc != 0 ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
            : elapsed_ms <= 2000 ? BRIX_CONFORM_VERDICT_CONFORMANT
                                 : BRIX_CONFORM_VERDICT_DIVERGENT,
        !connected || rc != 0 ? "slow-locate-fixture-unavailable"
            : elapsed_ms <= 2000 ? "nowait-returned-promptly"
                                 : "nowait-blocked-on-slow-member",
        "kXR_nowait locate reply in <=2000ms", received);
    if (connected) brix_close(&connection);
}

void
xrd_conform_probe_locate_endpoint(xrd_conform_execution *execution,
    brix_conn *primary, const char *reply, const char *path)
{
    char endpoint[320];
    char observed[96];
    size_t holders = 0;
    size_t served = 0;
    int all_served;

    probe_locate_refresh_fixture(execution,
        locate_fixture_target(execution->run, "refresh"));
    probe_locate_nowait_fixture(execution,
        locate_fixture_target(execution->run, "slow"));
    if (xrd_conform_first_data_endpoint(reply, endpoint,
            sizeof(endpoint)) != 0) {
        xrd_conform_result_set(execution, "LOC-003",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "no-data-server-endpoint-returned", NULL, reply);
        return;
    }
    xrd_conform_probe_preferred_name(execution, primary, path, endpoint);
    all_served = verify_data_endpoints(execution, reply, path, observed,
        sizeof(observed), &holders, &served);
    xrd_conform_result_set(execution, "LOC-003",
        all_served ? BRIX_CONFORM_VERDICT_CONFORMANT
                   : BRIX_CONFORM_VERDICT_DIVERGENT,
        all_served ? "all-located-data-servers-serve-path"
                   : "located-data-server-did-not-serve-path",
        "every returned S/s endpoint serves the path", observed);
}
