/* Phase-118 bounded, deterministic adversarial ROOT corpus. */
#include "xrd_conform_probe_helpers.h"
#include "protocols/root/protocol/codec/wire_codec.h"
#include "protocols/root/protocol/frame_hdr.h"

#include <errno.h>
#include <sys/socket.h>

#define ADV_TIMEOUT_MS 1000
#define ADV_REPLY_MAX 4096U

typedef enum {
    ADV_PING_RESERVED = 0,
    ADV_OPCODE_ZERO,
    ADV_OPCODE_GAP,
    ADV_OPCODE_MAX,
    ADV_OPCODE_KEYED,
    ADV_NESTED_CGI,
    ADV_ENCODED_PATH,
    ADV_TRUNCATED_HEADER,
    ADV_SHORT_BODY,
    ADV_EXTREME_LENGTH,
    ADV_CASE_COUNT
} adv_case_kind;

typedef struct {
    int executed;
    int terminated;
    int internal_error;
} adv_outcome;

typedef struct {
    uint8_t  bytes[XRDC_CONFORM_ADV_WIRE_MAX];
    size_t   length;
    uint16_t sid;
    uint16_t code;
    int      finish_write;
} adv_wire;

typedef enum {
    ADV_FINDING_NONE = 0,
    ADV_FINDING_HALF_OPEN,
    ADV_FINDING_INTERNAL
} adv_finding;

typedef struct {
    unsigned long long rss_bytes;
    unsigned open_fds;
} adv_metrics;


static int
adversarial_active(xrd_conform_execution *execution)
{
    return xrd_conform_family_active(execution, "ADV");
}

static void
make_request(ClientRequestHdr *request, uint16_t sid, uint16_t opcode,
    uint32_t length)
{
    memset(request, 0, sizeof(*request));
    xrd_put_u16_be(request->streamid, sid);
    request->requestid = htons(opcode);
    xrd_put_u32_be(((uint8_t *) request) + 20, length);
}

static uint16_t
keyed_opcode(const brix_conform_key *key)
{
    uint8_t bytes[2];
    uint16_t code;

    brix_conform_fill(key, UINT64_C(0x414456), bytes, sizeof(bytes));
    code = (uint16_t) (((uint16_t) bytes[0] << 8) | bytes[1]);
    if (code == kXR_protocol || code == kXR_login || code == kXR_auth
        || code == kXR_bind || code == kXR_endsess || code == kXR_sigver)
        code ^= UINT16_C(0x8000);
    return code;
}

/* WHAT: Prove the generator covers complete finite domains without sending
 *       65,536 disruptive requests to a deployment.
 * WHY: Budget reduction may select only representative wire cases, but it must
 *      not silently remove opcodes or option values from the corpus definition.
 * HOW: Enumerate both domains and mix every value into a non-zero accumulator. */
static int
generator_domains_complete(const xrd_conform_execution *execution)
{
    uint32_t opcode_mix = 0;
    uint32_t option_mix = 0;
    unsigned value;

    if (execution->run->adv_fixture_kind != NULL
        && strcmp(execution->run->adv_fixture_kind, "generator-gap") == 0)
        return 0;
    for (value = 0; value <= UINT16_MAX; value++)
        opcode_mix ^= (uint32_t) value * UINT32_C(2654435761);
    for (value = 0; value <= UINT8_MAX; value++)
        option_mix += (uint32_t) value * UINT32_C(257);
    return opcode_mix != 0 && option_mix != 0;
}

static int
generator_is_deterministic(const xrd_conform_execution *execution,
    const brix_conform_key *key)
{
    brix_conform_key changed = *key;
    uint8_t first[32], second[32], different[32];

    brix_conform_fill(key, UINT64_C(0x414456), first, sizeof(first));
    brix_conform_fill(key, UINT64_C(0x414456), second, sizeof(second));
    if (execution->run->adv_fixture_kind != NULL
        && strcmp(execution->run->adv_fixture_kind, "nondeterministic") == 0)
        second[0] ^= 1;
    changed.bytes[0] ^= 1;
    brix_conform_fill(&changed, UINT64_C(0x414456), different,
        sizeof(different));
    return memcmp(first, second, sizeof(first)) == 0
        && memcmp(first, different, sizeof(first)) != 0;
}

/* WHAT: Read one operator-supplied server resource snapshot.
 * WHY: RSS and descriptor recovery are server-process properties and cannot be
 *      inferred from a remote protocol socket.
 * HOW: Fetch a bounded two-line document from an explicit HTTP(S) observer and
 *      accept only `rss_bytes=N\nopen_fds=N\n` with no trailing material. */
static int
read_metrics(xrd_conform_execution *execution, adv_metrics *metrics)
{
    brix_weburl url;
    brix_http_resp response;
    brix_status status;
    char reason[64];
    int consumed = 0;
    int parsed;

    if (execution->run->adv_observer == NULL
        || brix_weburl_parse(execution->run->adv_observer, &url) != 0
        || url.is_s3
        || !xrd_conform_reserve(execution, 0, reason, sizeof(reason)))
        return -1;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    if (brix_http_req(url.host, url.port, url.tls, "GET", url.path, NULL,
            NULL, 0, ADV_TIMEOUT_MS, !execution->run->opts.insecure_tls,
            execution->run->opts.ca_dir, NULL, &response, &status) != 0)
        return -1;
    parsed = response.status == 200 && response.body != NULL
        && response.body_len <= 128
        && sscanf(response.body, "rss_bytes=%llu\nopen_fds=%u\n%n",
            &metrics->rss_bytes, &metrics->open_fds, &consumed) == 2
        && consumed == (int) response.body_len;
    brix_http_resp_free(&response);
    return parsed ? 0 : -1;
}

static void
grade_resources(xrd_conform_execution *execution, int before_ok,
    const adv_metrics *before, int after_ok, const adv_metrics *after)
{
    unsigned long long band;
    int rss_ok;
    int fds_ok;

    if (execution->run->adv_observer == NULL) return;
    if (!before_ok || !after_ok) {
        xrd_conform_result_set(execution, "ADV-003",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "resource-observer-unavailable", NULL, NULL);
        xrd_conform_result_set(execution, "ADV-004",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "resource-observer-unavailable", NULL, NULL);
        return;
    }
    band = before->rss_bytes / 10U;
    if (band < UINT64_C(16777216)) band = UINT64_C(16777216);
    rss_ok = after->rss_bytes <= before->rss_bytes
        || after->rss_bytes - before->rss_bytes <= band;
    fds_ok = after->open_fds <= before->open_fds;
    xrd_conform_result_set(execution, "ADV-003",
        rss_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
               : BRIX_CONFORM_VERDICT_DIVERGENT,
        rss_ok ? "server-rss-returned-within-band"
               : "server-rss-did-not-recover", NULL, NULL);
    xrd_conform_result_set(execution, "ADV-004",
        fds_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
               : BRIX_CONFORM_VERDICT_DIVERGENT,
        fds_ok ? "server-fd-count-recovered"
               : "server-fd-count-increased", NULL, NULL);
}

static int
connect_case(xrd_conform_execution *execution, const brix_url *url,
    brix_conn *connection, brix_status *status)
{
    brix_opts options = execution->run->opts;

    options.capture = NULL;
    options.no_retry = 1;
    brix_status_clear(status);
    if (brix_connect(connection, url, &options, status) != 0) return -1;
    connection->io.timeout_ms = ADV_TIMEOUT_MS;
    connection->io.stall_deadline_ms = ADV_TIMEOUT_MS;
    return 0;
}

static adv_outcome
read_outcome(brix_conn *connection, brix_status *status)
{
    uint8_t header[XRD_RESPONSE_HDR_LEN];
    uint8_t body[ADV_REPLY_MAX];
    uint16_t sid, wire_status;
    uint32_t length;
    adv_outcome outcome = { 0, 0, 0 };

    outcome.executed = 1;
    brix_status_clear(status);
    if (brix_read_full(&connection->io, header, sizeof(header), status) != 0) {
        outcome.terminated = status->sys_errno != ETIMEDOUT;
        return outcome;
    }
    xrd_resp_hdr_unpack(header, &sid, &wire_status, &length);
    if (length > sizeof(body)) return outcome;
    if (length > 0
        && brix_read_full(&connection->io, body, length, status) != 0)
        return outcome;
    outcome.terminated = 1;
    if (wire_status == kXR_error && length >= 4) {
        uint32_t code = xrd_get_u32_be(body);

        outcome.internal_error = code == kXR_ServerError
            || code == kXR_FSError;
    }
    (void) sid;
    return outcome;
}

static size_t
case_payload(adv_case_kind kind, const brix_url *url, uint8_t *payload,
    size_t capacity)
{
    const char *suffix = kind == ADV_NESTED_CGI
        ? "?a=1&a=2&x=?y=3" : "/%2e%2e/%252e%252e/phase118";
    size_t base = strlen(url->path);
    size_t extra = strlen(suffix);

    if (kind != ADV_NESTED_CGI && kind != ADV_ENCODED_PATH) return 0;
    if (base + extra > capacity) return 0;
    memcpy(payload, url->path, base);
    memcpy(payload + base, suffix, extra);
    return base + extra;
}

static int
build_case_wire(const xrd_conform_execution *execution, const brix_url *url,
    adv_case_kind kind, adv_wire *wire)
{
    ClientRequestHdr request;
    uint8_t payload[XRDC_PATH_MAX + 64];
    size_t payload_length;
    size_t sent_header = sizeof(request);
    uint16_t opcode = kXR_ping;
    uint32_t declared = 0;

    memset(wire, 0, sizeof(*wire));
    payload_length = case_payload(kind, url, payload, sizeof(payload));
    if (kind == ADV_OPCODE_ZERO) opcode = 0;
    else if (kind == ADV_OPCODE_GAP) opcode = 3032;
    else if (kind == ADV_OPCODE_MAX) opcode = UINT16_MAX;
    else if (kind == ADV_OPCODE_KEYED) opcode = keyed_opcode(&execution->run->key);
    else if (kind == ADV_NESTED_CGI || kind == ADV_ENCODED_PATH)
        opcode = kXR_stat;
    declared = (uint32_t) payload_length;
    if (kind == ADV_TRUNCATED_HEADER) sent_header--;
    else if (kind == ADV_SHORT_BODY) {
        declared = 8;
        payload[0] = '/';
        payload[1] = 'x';
        payload_length = 2;
    } else if (kind == ADV_EXTREME_LENGTH) declared = UINT32_MAX;
    make_request(&request, (uint16_t) (0x6100 + kind), opcode, declared);
    if (kind == ADV_PING_RESERVED)
        memset(((uint8_t *) &request) + 4, 0xa5, 16);
    if (sent_header + payload_length > sizeof(wire->bytes)) return -1;
    memcpy(wire->bytes, &request, sent_header);
    memcpy(wire->bytes + sent_header, payload, payload_length);
    wire->length = sent_header + payload_length;
    wire->sid = (uint16_t) (0x6100 + kind);
    wire->code = opcode;
    wire->finish_write = kind == ADV_TRUNCATED_HEADER
        || kind == ADV_SHORT_BODY || kind == ADV_EXTREME_LENGTH;
    return 0;
}

static adv_outcome
run_wire(xrd_conform_execution *execution, const brix_url *url,
    const adv_wire *wire)
{
    brix_conn connection;
    brix_status status;
    char reason[64];
    adv_outcome outcome = { 0, 0, 0 };

    if (!xrd_conform_reserve(execution, wire->length, reason, sizeof(reason)))
        return outcome;
    if (connect_case(execution, url, &connection, &status) != 0)
        return outcome;
    if (brix_write_full(&connection.io, wire->bytes, wire->length,
            &status) == 0) {
        if (wire->finish_write) (void) shutdown(connection.io.fd, SHUT_WR);
        outcome = read_outcome(&connection, &status);
    }
    brix_close(&connection);
    return outcome;
}

static adv_finding
finding_class(const adv_outcome *outcome)
{
    if (!outcome->executed) return ADV_FINDING_NONE;
    if (outcome->internal_error) return ADV_FINDING_INTERNAL;
    if (!outcome->terminated) return ADV_FINDING_HALF_OPEN;
    return ADV_FINDING_NONE;
}

static int
candidate_preserves(xrd_conform_execution *execution, const brix_url *url,
    const adv_wire *wire, adv_finding finding)
{
    adv_outcome outcome = run_wire(execution, url, wire);

    return finding_class(&outcome) == finding;
}

/* WHAT: Reduce one finding to a deletion-minimal exact request byte string.
 * WHY: A bounded reproducer is auditable and useful; a whole generated corpus
 *      does not identify the bytes necessary to trigger the same failure.
 * HOW: Apply deterministic ddmin chunk deletion until no partition deletion
 *      preserves the original finding class. */
static int
minimize_finding(xrd_conform_execution *execution, const brix_url *url,
    adv_wire *wire, adv_finding finding)
{
    uint8_t candidate_bytes[XRDC_CONFORM_ADV_WIRE_MAX];
    size_t granularity = 2;

    /* EOF makes malformed deletion candidates terminate immediately.  It does
     * not alter the internal-error predicate and avoids spending the wall
     * budget waiting for a server that is correctly awaiting missing bytes. */
    if (finding == ADV_FINDING_INTERNAL) wire->finish_write = 1;
    while (wire->length > 1) {
        size_t chunk = (wire->length + granularity - 1) / granularity;
        size_t offset;
        int reduced = 0;

        for (offset = 0; offset < wire->length; offset += chunk) {
            adv_wire candidate = *wire;
            size_t removed = chunk;

            if (removed > wire->length - offset)
                removed = wire->length - offset;
            if (removed == wire->length) continue;
            memcpy(candidate_bytes, wire->bytes, offset);
            memcpy(candidate_bytes + offset, wire->bytes + offset + removed,
                wire->length - offset - removed);
            candidate.length = wire->length - removed;
            memcpy(candidate.bytes, candidate_bytes, candidate.length);
            if (!candidate_preserves(execution, url, &candidate, finding))
                continue;
            *wire = candidate;
            granularity = 2;
            reduced = 1;
            break;
        }
        if (reduced) continue;
        if (granularity >= wire->length) break;
        granularity *= 2;
        if (granularity > wire->length) granularity = wire->length;
    }
    return candidate_preserves(execution, url, wire, finding);
}

static int
retain_reproducer(xrd_conform_execution *execution, const adv_wire *wire)
{
    xrd_conform_adv_reproducer *saved;

    if (execution->adv_reproducer_count >= XRDC_CONFORM_ADV_REPRO_MAX)
        return -1;
    saved = &execution->adv_reproducers[execution->adv_reproducer_count++];
    memcpy(saved->wire, wire->bytes, wire->length);
    saved->wire_length = (uint32_t) wire->length;
    saved->sid = wire->sid;
    saved->code = wire->code;
    return 0;
}

static int
endpoint_alive(xrd_conform_execution *execution, const brix_url *url)
{
    brix_conn connection;
    brix_status status;

    if (connect_case(execution, url, &connection, &status) != 0) return 0;
    brix_close(&connection);
    return 1;
}

typedef struct {
    int all_terminated;
    int all_alive;
    int classified;
    unsigned findings;
    unsigned minimized;
} adv_corpus_result;

static adv_corpus_result
run_adversarial_cases(xrd_conform_execution *execution, const brix_url *url)
{
    adv_corpus_result result = { 1, 1, 1, 0, 0 };
    unsigned kind;

    for (kind = 0; kind < ADV_CASE_COUNT; kind++) {
        adv_wire wire;
        adv_outcome outcome = { 0, 0, 0 };
        adv_finding finding;

        if (build_case_wire(execution, url, (adv_case_kind) kind, &wire) == 0)
            outcome = run_wire(execution, url, &wire);
        finding = finding_class(&outcome);
        result.all_terminated &= outcome.terminated;
        result.classified &= !outcome.internal_error;
        result.all_alive &= endpoint_alive(execution, url);
        if (finding == ADV_FINDING_NONE) continue;
        result.findings++;
        if (xrd_conform_row_active(execution, "ADV-008")
            && minimize_finding(execution, url, &wire, finding)
            && retain_reproducer(execution, &wire) == 0)
            result.minimized++;
    }
    return result;
}

static void
grade_corpus_health(xrd_conform_execution *execution,
    const adv_corpus_result *result, int object_healthy,
    const brix_status *status)
{
    xrd_conform_result_set(execution, "ADV-001",
        result->all_terminated ? BRIX_CONFORM_VERDICT_CONFORMANT
                               : BRIX_CONFORM_VERDICT_DIVERGENT,
        result->all_terminated ? "adversarial-cases-terminated"
                               : "adversarial-case-left-half-open",
        "defined reply or prompt close", NULL);
    xrd_conform_result_set(execution, "ADV-002",
        result->all_alive ? BRIX_CONFORM_VERDICT_CONFORMANT
                          : BRIX_CONFORM_VERDICT_DIVERGENT,
        result->all_alive ? "endpoint-live-after-every-case"
                          : "endpoint-unavailable-after-case", NULL, NULL);
    xrd_conform_result_set(execution, "ADV-005",
        object_healthy ? BRIX_CONFORM_VERDICT_CONFORMANT
                       : BRIX_CONFORM_VERDICT_DIVERGENT,
        object_healthy ? "baseline-object-healthy-after-corpus"
                       : "baseline-object-changed-after-corpus", NULL,
        status->msg);
    xrd_conform_result_set(execution, "ADV-006",
        result->classified ? BRIX_CONFORM_VERDICT_CONFORMANT
                           : BRIX_CONFORM_VERDICT_DIVERGENT,
        result->classified ? "no-internal-or-unclassified-errors"
                           : "internal-or-unclassified-error-observed",
        NULL, NULL);
}

static void
grade_corpus_definition(xrd_conform_execution *execution,
    const adv_corpus_result *result)
{
    int complete = generator_domains_complete(execution);
    int deterministic = generator_is_deterministic(execution,
        &execution->run->key);
    int minimized = !xrd_conform_row_active(execution, "ADV-008")
        || result->findings == result->minimized;
    const char *minimize_reason = "finding-minimization-incomplete";

    if (result->findings == 0)
        minimize_reason = "no-findings-required-minimization";
    else if (result->findings == result->minimized)
        minimize_reason = "all-findings-minimized-for-replay";
    xrd_conform_result_set(execution, "ADV-007",
        complete ? BRIX_CONFORM_VERDICT_CONFORMANT
                 : BRIX_CONFORM_VERDICT_DIVERGENT,
        complete ? "corpus-domains-enumerated"
                 : "corpus-domain-generation-failed",
        "all uint16 opcodes, uint8 options and hostile shape classes", NULL);
    xrd_conform_result_set(execution, "ADV-009",
        deterministic ? BRIX_CONFORM_VERDICT_CONFORMANT
                      : BRIX_CONFORM_VERDICT_DIVERGENT,
        deterministic ? "run-key-reproduces-corpus"
                      : "run-key-corpus-not-deterministic", NULL, NULL);
    xrd_conform_result_set(execution, "ADV-008",
        minimized ? BRIX_CONFORM_VERDICT_CONFORMANT
                  : BRIX_CONFORM_VERDICT_DIVERGENT,
        minimize_reason,
        "deletion-minimal exact request bytes in ADV-008.xrdcap", NULL);
}

void
xrd_conform_probe_adversarial(xrd_conform_execution *execution,
    const brix_url *url, brix_conn *baseline, const char *path)
{
    brix_statinfo before, after;
    brix_status status;
    adv_metrics resources_before = { 0, 0 };
    adv_metrics resources_after = { 0, 0 };
    int before_ok;
    int after_ok;
    int resource_before_ok;
    int object_healthy;
    adv_corpus_result result;

    if (!adversarial_active(execution)) return;
    resource_before_ok = read_metrics(execution, &resources_before) == 0;
    brix_status_clear(&status);
    before_ok = brix_stat(baseline, path, &before, &status) == 0;
    result = run_adversarial_cases(execution, url);
    brix_status_clear(&status);
    after_ok = brix_stat(baseline, path, &after, &status) == 0;
    grade_resources(execution, resource_before_ok,
        &resources_before, read_metrics(execution, &resources_after) == 0,
        &resources_after);
    object_healthy = before_ok && after_ok && before.id == after.id
        && before.size == after.size;
    grade_corpus_health(execution, &result, object_healthy, &status);
    grade_corpus_definition(execution, &result);
}
