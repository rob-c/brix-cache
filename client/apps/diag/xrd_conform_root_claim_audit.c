/* Phase-118 advertised ROOT capability-to-behaviour audit. */
#include "xrd_conform_internal.h"

#define CLM_EC_FLAG kXR_ecRedir
#define CLM_KNOWN_FLAGS (kXR_isServer | kXR_isManager | kXR_attrCache \
    | kXR_attrMeta | kXR_attrProxy | kXR_attrSuper | kXR_attrVirtRdr \
    | kXR_recoverWrts | kXR_collapseRedir | CLM_EC_FLAG | kXR_supposc \
    | kXR_suppgrw | kXR_supgpf | kXR_anongpf | kXR_haveTLS | kXR_gotoTLS \
    | kXR_tlsAny | kXR_tlsGPFA)

static int
row_active(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

static void
grade(xrd_conform_execution *execution, const char *id, int pass,
    const char *success, const char *failure)
{
    if (!row_active(execution, id)) return;
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? success : failure, NULL, NULL);
}

static void
skip(xrd_conform_execution *execution, const char *id, const char *reason)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    if (row == NULL || row->verdict != BRIX_CONFORM_VERDICT_INCONCLUSIVE)
        return;
    xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_SKIPPED,
        reason, NULL, NULL);
}

static int
row_conformant(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict == BRIX_CONFORM_VERDICT_CONFORMANT;
}

static int
gpfile_state(xrd_conform_execution *execution)
{
    if (execution->gpfile_state == 2) return 1;
    if (execution->gpfile_state == 1) return 0;
    return -1;
}

static void
probe_role_claims(xrd_conform_execution *execution, const brix_conn *connection)
{
    uint32_t flags = connection->server_flags;
    int server = (flags & kXR_isServer) != 0;
    int manager = (flags & kXR_isManager) != 0;
    int role_served = server ? execution->have_root
        : manager && (row_conformant(execution, "LOC-001")
            || row_conformant(execution, "RDR-001"));
    int attributes = ((flags & kXR_attrMeta) == 0 || manager)
        && ((flags & kXR_attrSuper) == 0 || manager)
        && ((flags & kXR_attrProxy) == 0 || manager || server)
        && ((flags & kXR_attrCache) == 0 || server);

    grade(execution, "CLM-002", role_served,
        "advertised-role-behaviour-observed",
        "advertised-role-behaviour-missing");
    grade(execution, "CLM-003", attributes,
        "role-attributes-consistent", "role-attributes-contradict-role");
}

static void
probe_gpfile_claims(xrd_conform_execution *execution,
    const brix_conn *connection)
{
    uint32_t flags = connection->server_flags;
    int state = gpfile_state(execution);
    int supported = (flags & kXR_supgpf) != 0;
    int anonymous = (flags & kXR_anongpf) != 0;

    if (state < 0) {
        skip(execution, "CLM-004", "fixture-unavailable:gpfile-response");
        skip(execution, "CLM-006", "fixture-unavailable:gpfile-response");
        return;
    }
    grade(execution, "CLM-004", supported == state,
        "gpfile-claim-matches-behaviour", "gpfile-claim-diverges");
    grade(execution, "CLM-006", anonymous ? supported && state : !state,
        "anonymous-gpfile-claim-matches-behaviour",
        "anonymous-gpfile-claim-diverges");
}

static int
reserve_claim(xrd_conform_execution *execution, size_t bytes)
{
    char reason[64];

    return xrd_conform_reserve(execution, bytes, reason, sizeof(reason));
}

static int
unclaimed_posc_refused(xrd_conform_execution *execution,
    brix_conn *connection)
{
    xrd_conform_scratch_object object;
    brix_file file;
    brix_status status;
    int rc;

    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-claim-posc", object.path, sizeof(object.path)) != 0
        || !reserve_claim(execution, 0)) return -1;
    brix_status_clear(&status);
    rc = brix_file_open_write(connection, object.path, 1, 1, &file, &status);
    if (rc == 0) {
        if (reserve_claim(execution, 0))
            brix_file_close(connection, &file, &status);
        if (reserve_claim(execution, 0)) brix_rm(connection, object.path, &status);
        return 0;
    }
    return status.kxr == kXR_Unsupported ? 1 : -1;
}

static int
unclaimed_page_io_refused(xrd_conform_execution *execution,
    brix_conn *connection)
{
    static const uint8_t byte = 0x43;
    xrd_conform_scratch_object object;
    brix_file file;
    brix_status status;
    uint8_t observed = 0;
    int opened;
    int read_refused;
    int write_refused;

    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-claim-page", object.path, sizeof(object.path)) != 0
        || !reserve_claim(execution, 0)) return -1;
    brix_status_clear(&status);
    opened = brix_file_open_write(connection, object.path, 1, 0, &file,
        &status) == 0;
    if (!opened) return -1;
    if (!reserve_claim(execution, 1)
        || brix_file_write(connection, &file, 0, &byte, 1, &status) != 0) {
        if (reserve_claim(execution, 0))
            brix_file_close(connection, &file, &status);
        if (reserve_claim(execution, 0)) brix_rm(connection, object.path, &status);
        return -1;
    }
    if (!reserve_claim(execution, 1)) {
        if (reserve_claim(execution, 0))
            brix_file_close(connection, &file, &status);
        if (reserve_claim(execution, 0)) brix_rm(connection, object.path, &status);
        return -1;
    }
    brix_status_clear(&status);
    read_refused = brix_file_pgread(connection, &file, 0, &observed, 1,
        &status) < 0 && status.kxr == kXR_Unsupported;
    if (!reserve_claim(execution, 1)) {
        if (reserve_claim(execution, 0))
            brix_file_close(connection, &file, &status);
        if (reserve_claim(execution, 0)) brix_rm(connection, object.path, &status);
        return -1;
    }
    brix_status_clear(&status);
    write_refused = brix_file_pgwrite(connection, &file, 0, &byte, 1,
        &status) != 0 && status.kxr == kXR_Unsupported;
    if (reserve_claim(execution, 0)) brix_file_close(connection, &file, &status);
    if (reserve_claim(execution, 0)) brix_rm(connection, object.path, &status);
    return read_refused && write_refused ? 1 : 0;
}

static void
probe_clear_feature_claims(xrd_conform_execution *execution,
    brix_conn *connection)
{
    uint32_t flags = connection->server_flags;
    int gpfile_state_observed = gpfile_state(execution);
    int gpfile = (flags & kXR_supgpf) != 0 ? 1
        : gpfile_state_observed < 0 ? -1 : gpfile_state_observed == 0;
    int posc = 1;
    int page = 1;

    if (!row_active(execution, "CLM-007")) return;
    if ((flags & kXR_supposc) == 0)
        posc = unclaimed_posc_refused(execution, connection);
    if ((flags & kXR_suppgrw) == 0)
        page = unclaimed_page_io_refused(execution, connection);
    if (gpfile < 0 || posc < 0 || page < 0) {
        skip(execution, "CLM-007", "fixture-unavailable:clear-bit-verb");
        return;
    }
    grade(execution, "CLM-007", gpfile > 0 && posc > 0 && page > 0,
        "all-unclaimed-feature-verbs-refused",
        "unclaimed-feature-verb-served");
}

static void
probe_tls_claim(xrd_conform_execution *execution, const brix_url *source,
    const brix_conn *connection)
{
    brix_url tls_url = *source;
    brix_conn tls_connection;
    brix_opts options = execution->run->opts;
    brix_status status;
    int connected;

    if ((connection->server_flags & kXR_haveTLS) == 0) {
        skip(execution, "CLM-005", "claim-absent:kXR_haveTLS");
        return;
    }
    tls_url.scheme = XRDC_SCHEME_ROOTS;
    options.capture = NULL;
    brix_status_clear(&status);
    connected = brix_connect(&tls_connection, &tls_url,
        &options, &status) == 0;
    if (connected) brix_close(&tls_connection);
    grade(execution, "CLM-005", connected,
        "advertised-tls-handshake-completed",
        "advertised-tls-handshake-failed");
}

static int
claim_skip_valid(const brix_conform_result *row, uint32_t flags)
{
    const char *claim = row->reason + strlen("claim-absent:");

    if (strcmp(claim, "kXR_suppgrw") == 0)
        return (flags & kXR_suppgrw) == 0;
    if (strcmp(claim, "kXR_supposc") == 0)
        return (flags & kXR_supposc) == 0;
    if (strcmp(claim, "kXR_haveTLS") == 0)
        return (flags & kXR_haveTLS) == 0;
    if (strcmp(claim, "request-signing") == 0) return 1;
    return 0;
}

static void
audit_skip_ledger(xrd_conform_execution *execution, uint32_t flags)
{
    size_t index;
    int valid = 1;

    for (index = 0; index < execution->results.count; index++) {
        const brix_conform_result *row = &execution->results.results[index];

        if (row->verdict == BRIX_CONFORM_VERDICT_SKIPPED
            && strncmp(row->reason, "claim-absent:", 13) == 0
            && !claim_skip_valid(row, flags)) valid = 0;
    }
    grade(execution, "CLM-008", valid, "claim-skip-ledger-audited",
        "claim-skip-does-not-match-protocol-flags");
}

void
xrd_conform_probe_claim_audit(xrd_conform_execution *execution,
    const brix_url *url, brix_conn *connection)
{
    uint32_t flags;
    int version_ok;

    if (!row_active(execution, "CLM-001")
        && !row_active(execution, "CLM-002")
        && !row_active(execution, "CLM-003")
        && !row_active(execution, "CLM-004")
        && !row_active(execution, "CLM-005")
        && !row_active(execution, "CLM-006")
        && !row_active(execution, "CLM-007")
        && !row_active(execution, "CLM-008")
        && !row_active(execution, "CLM-009")
        && !row_active(execution, "CLM-010")) return;
    flags = connection->server_flags;
    grade(execution, "CLM-001", (flags & ~CLM_KNOWN_FLAGS) == 0,
        "all-advertised-bits-have-assessor-mappings",
        "unknown-advertised-capability-bit");
    probe_role_claims(execution, connection);
    probe_gpfile_claims(execution, connection);
    probe_clear_feature_claims(execution, connection);
    probe_tls_claim(execution, url, connection);
    audit_skip_ledger(execution, flags);
    version_ok = (flags & (kXR_suppgrw | kXR_supposc | kXR_supgpf)) == 0
        || connection->server_protocol >= 0x00000310U;
    grade(execution, "CLM-010", version_ok,
        "protocol-version-covers-advertised-features",
        "feature-newer-than-advertised-protocol");
}

/* WHAT: Reconcile the independently observed checksum and TPC claims.
 * WHY: CLM-009 previously remained a fixture marker even when a composed
 * data+tpc run had already exercised both advertised capabilities.
 * HOW: Finalize after every target and the paired TPC runner have completed;
 * require both observations, propagate either mismatch, and never infer a pass
 * from a missing topology. */
void
xrd_conform_finalize_claim_audit(xrd_conform_execution *execution)
{
    int checksum = execution->query_checksum_claim_state;
    int tpc = execution->tpc_claim_behavior_state;

    if (!row_active(execution, "CLM-009")) return;
    if (checksum < 0 || tpc < 0) {
        grade(execution, "CLM-009", 0, NULL,
            "qconfig-claim-behaviour-mismatch");
        return;
    }
    if (checksum == 0 || tpc == 0) {
        xrd_conform_result_set(execution, "CLM-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:tpc-and-checksum-claims",
            "working advertised checksums and paired TPC claim/behavior",
            checksum == 0 ? "checksum-claim-unobserved"
                          : "tpc-claim-unobserved");
        return;
    }
    grade(execution, "CLM-009", checksum > 0 && tpc > 0,
        "qconfig-claims-match-checksum-and-tpc-behaviour",
        "qconfig-claim-behaviour-mismatch");
}
