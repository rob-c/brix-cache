/* Phase-118 scratch-confined kXR_open mutation and option probes. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/codec/wire_codec.h"

#include <arpa/inet.h>

typedef struct {
    uint8_t *body;
    uint32_t length;
} open_reply;

/* WHAT: Return whether a row survived family/only filtering.
 * WHY: Some option probes are independently selectable and potentially mutate.
 * HOW: Read the initialized result and exclude only pre-skipped rows. */
static int
row_active(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

/* WHAT: Charge one exchange and reflect ceiling refusal in client status.
 * WHY: Mutation probes must obey the same bounded-run contract as read probes.
 * HOW: Delegate to the common reservation counter and translate its reason. */
static int
reserve_op(xrd_conform_execution *execution, size_t bytes, brix_status *status)
{
    char reason[64];

    if (xrd_conform_reserve(execution, bytes, reason, sizeof(reason))) return 1;
    brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
    return 0;
}

/* WHAT: Build a fixed leaf beneath the authorized scratch prefix.
 * WHY: No mutation probe may turn a test-generated name into raw path authority.
 * HOW: Use the Phase-118 capability builder for every independently named path. */
static int
scratch_path(xrd_conform_execution *execution, const char *leaf,
    xrd_conform_scratch_object *object)
{
    return brix_conform_scratch_path(execution->run->config.scratch, leaf,
        object->path, sizeof(object->path));
}

/* WHAT: Send an exact open mode/options word and retain its bounded reply.
 * WHY: Several conformance rows express combinations the typed convenience API
 *      deliberately cannot construct.
 * HOW: Pack the authoritative request body and use the shared framed roundtrip. */
static int
raw_open(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, uint16_t mode, uint16_t options, open_reply *reply,
    brix_status *status)
{
    ClientOpenRequest request;
    xrdw_open_req_t fields = { .mode = mode, .options = options, .optiont = 0 };
    brix_payload payload = { path, (uint32_t) strlen(path) };
    uint16_t wire_status = 0;
    brix_resp_out response = { &wire_status, &reply->body, &reply->length };

    memset(reply, 0, sizeof(*reply));
    if (!reserve_op(execution, sizeof(request) + payload.len, status)) return -1;
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_open);
    xrdw_open_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(status);
    return brix_roundtrip(connection, &request, &payload, &response, status);
}

/* WHAT: Close a successful raw-open reply as a typed handle.
 * WHY: Every admitted option case must release server handle state promptly.
 * HOW: Validate/copy the four-byte handle, charge close, then use shared close. */
static int
close_reply(xrd_conform_execution *execution, brix_conn *connection,
    const open_reply *reply, brix_status *status)
{
    brix_file file = { { 0 }, 0, 0 };

    if (reply->length < XRD_FHANDLE_LEN
        || !reserve_op(execution, 0, status)) return -1;
    memcpy(file.fhandle, reply->body, XRD_FHANDLE_LEN);
    return brix_file_close(connection, &file, status);
}

/* WHAT: Record a binary clause result with preserved wire-status evidence.
 * WHY: A defined refusal and a server error are materially different outcomes.
 * HOW: Map the boolean to the verdict algebra and format the bounded kXR value. */
static void
grade(xrd_conform_execution *execution, const char *id, int pass,
    const char *success, const char *failure, const brix_status *status)
{
    char received[192];

    snprintf(received, sizeof(received), "kxr=%d %.150s",
        status == NULL ? 0 : status->kxr,
        status == NULL ? "" : status->msg);
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? success : failure, NULL, received);
}

/* WHAT: Create/truncate a path and optionally write a small seed.
 * WHY: Exclusive and truncating opens need known pre-existing object state.
 * HOW: Use typed open/write/close, charging every request and payload byte. */
static int
seed_file(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, const void *data, size_t length,
    brix_status *status)
{
    brix_file file;
    int rc;

    if (!reserve_op(execution, 0, status)
        || brix_file_open_write(connection, object->path, 1, 0, &file,
            status) != 0)
        return -1;
    rc = reserve_op(execution, length, status)
        ? brix_file_write(connection, &file, 0, data, length, status) : -1;
    if (!reserve_op(execution, 0, status)
        || brix_file_close(connection, &file, status) != 0) rc = -1;
    return rc;
}

/* WHAT: Exercise exclusive-create and new+delete truncation semantics.
 * WHY: Silent replacement under kXR_new is a data-loss defect.
 * HOW: Seed one object, require ItExists for new-only, then require the
 *      admitted new+delete combination to leave the same object at size zero. */
static void
probe_create_disposition(xrd_conform_execution *execution,
    brix_conn *connection)
{
    xrd_conform_scratch_object object;
    open_reply reply = { 0 };
    brix_statinfo info;
    brix_status status;
    int rc;

    if (scratch_path(execution, "brix-conform-open-disposition", &object) != 0)
        return;
    brix_status_clear(&status);
    if (seed_file(execution, connection, &object, "seed", 4, &status) != 0)
        return;
    if (row_active(execution, "OPN-008")) {
        rc = raw_open(execution, connection, object.path, 0644,
            kXR_open_updt | kXR_new, &reply, &status);
        if (rc == 0) close_reply(execution, connection, &reply, &status);
        grade(execution, "OPN-008", rc != 0 && status.kxr == kXR_ItExists,
            "new-only-preserved-existing-object", "new-only-overwrote-object",
            &status);
        free(reply.body);
    }
    if (row_active(execution, "OPN-009")) {
        rc = raw_open(execution, connection, object.path, 0644,
            kXR_open_updt | kXR_new | kXR_delete, &reply, &status);
        if (rc == 0) rc = close_reply(execution, connection, &reply, &status);
        memset(&info, 0, sizeof(info));
        if (rc == 0 && reserve_op(execution, 0, &status))
            rc = brix_stat(connection, object.path, &info, &status);
        grade(execution, "OPN-009", rc == 0 && info.size == 0,
            "new-delete-truncated-existing-object", "new-delete-did-not-truncate",
            &status);
        free(reply.body);
    }
    if (reserve_op(execution, 0, &status))
        brix_rm(connection, object.path, &status);
}

/* WHAT: Compare missing-parent opens without and with kXR_mkpath.
 * WHY: Parent creation must be explicitly controlled by the advertised bit.
 * HOW: Address one nested scratch path, require NotFound first, then successful
 *      creation with mkpath, and remove the entire generated hierarchy. */
static void
probe_mkpath(xrd_conform_execution *execution, brix_conn *connection)
{
    xrd_conform_scratch_object parent, child, object;
    open_reply reply = { 0 };
    brix_status status;
    int absent_rc;
    int create_rc;
    int absent_kxr;

    if (!row_active(execution, "OPN-010")
        || scratch_path(execution, "brix-conform-open-parent", &parent) != 0
        || scratch_path(execution, "brix-conform-open-parent/child", &child) != 0
        || scratch_path(execution, "brix-conform-open-parent/child/file", &object)
            != 0) return;
    brix_status_clear(&status);
    absent_rc = raw_open(execution, connection, object.path, 0644,
        kXR_open_updt | kXR_new, &reply, &status);
    absent_kxr = status.kxr;
    if (absent_rc == 0) close_reply(execution, connection, &reply, &status);
    free(reply.body);
    reply.body = NULL;
    create_rc = raw_open(execution, connection, object.path, 0644,
        kXR_open_updt | kXR_new | kXR_mkpath, &reply, &status);
    if (create_rc == 0)
        create_rc = close_reply(execution, connection, &reply, &status);
    grade(execution, "OPN-010", absent_rc != 0
        && absent_kxr == kXR_NotFound && create_rc == 0,
        "mkpath-alone-created-missing-parents", "mkpath-semantics-wrong", &status);
    free(reply.body);
    if (reserve_op(execution, 0, &status)) brix_rm(connection, object.path, &status);
    if (reserve_op(execution, 0, &status)) brix_rmdir(connection, child.path, &status);
    if (reserve_op(execution, 0, &status)) brix_rmdir(connection, parent.path, &status);
}

/* WHAT: Verify that an append handle places an explicit-offset write at EOF.
 * WHY: Silently treating kXR_open_apnd as an ordinary update open corrupts
 *      existing bytes when clients still carry a protocol offset.
 * HOW: Seed a prefix, raw-open with the append bit, write at offset zero, then
 *      reopen and require the exact prefix-plus-suffix byte sequence. */
static void
probe_append(xrd_conform_execution *execution, brix_conn *connection)
{
    static const char prefix[] = "append-prefix";
    static const char suffix[] = "-suffix";
    static const char expected[] = "append-prefix-suffix";
    xrd_conform_scratch_object object;
    open_reply reply = { 0 };
    char actual[sizeof(expected)] = { 0 };
    brix_file file = { { 0 }, 0, 0 };
    brix_status status;
    ssize_t got = -1;
    int rc;

    if (!row_active(execution, "OPN-014")
        || scratch_path(execution, "brix-conform-open-append", &object) != 0)
        return;
    brix_status_clear(&status);
    rc = seed_file(execution, connection, &object, prefix,
        sizeof(prefix) - 1, &status);
    if (rc == 0)
        rc = raw_open(execution, connection, object.path, 0644,
            kXR_open_apnd, &reply, &status);
    if (rc == 0 && reply.length >= XRD_FHANDLE_LEN) {
        memcpy(file.fhandle, reply.body, XRD_FHANDLE_LEN);
        rc = reserve_op(execution, sizeof(suffix) - 1, &status)
            ? brix_file_write(connection, &file, 0, suffix,
                sizeof(suffix) - 1, &status) : -1;
        if (!reserve_op(execution, 0, &status)
            || brix_file_close(connection, &file, &status) != 0) rc = -1;
    } else if (rc == 0) {
        rc = -1;
    }
    free(reply.body);
    if (rc == 0 && reserve_op(execution, 0, &status)
        && brix_file_open_read(connection, object.path, &file, &status) == 0) {
        if (reserve_op(execution, sizeof(actual), &status))
            got = brix_file_read(connection, &file, 0, actual,
                sizeof(actual), &status);
        if (!reserve_op(execution, 0, &status)
            || brix_file_close(connection, &file, &status) != 0) got = -1;
    }
    grade(execution, "OPN-014", got == (ssize_t) (sizeof(expected) - 1)
        && memcmp(actual, expected, sizeof(expected) - 1) == 0,
        "append-write-landed-at-eof", "append-write-was-refused-or-misplaced",
        &status);
    if (reserve_op(execution, 0, &status)) brix_rm(connection, object.path, &status);
}

/* WHAT: Prove a clean POSC close publishes all written bytes.
 * WHY: Successful-close persistence is the positive half of POSC atomicity.
 * HOW: Typed POSC write/close, reopen, read the exact seed, then remove it. */
static void
probe_posc_close(xrd_conform_execution *execution, brix_conn *connection)
{
    static const char expected[] = "phase118-posc";
    xrd_conform_scratch_object object;
    char actual[sizeof(expected)] = { 0 };
    brix_file file;
    brix_statinfo pending_info;
    brix_statinfo closed_info;
    brix_status status;
    ssize_t got = -1;
    int rc = -1;
    int pending = 0;
    int cleared = 0;

    if (!row_active(execution, "OPN-016")
        && !row_active(execution, "STA-011")) return;
    if (scratch_path(execution, "brix-conform-open-posc", &object) != 0)
        return;
    memset(&pending_info, 0, sizeof(pending_info));
    memset(&closed_info, 0, sizeof(closed_info));
    if (reserve_op(execution, 0, &status)
        && brix_file_open_write(connection, object.path, 1, 1, &file, &status) == 0
        && reserve_op(execution, sizeof(expected), &status)
        && brix_file_write(connection, &file, 0, expected, sizeof(expected),
            &status) == 0) {
        if (reserve_op(execution, 0, &status)
            && brix_stat(connection, object.path, &pending_info, &status) == 0)
            pending = (pending_info.flags & kXR_poscpend) != 0;
        if (reserve_op(execution, 0, &status))
            rc = brix_file_close(connection, &file, &status);
    }
    if (rc == 0 && reserve_op(execution, 0, &status)
        && brix_stat(connection, object.path, &closed_info, &status) == 0)
        cleared = (closed_info.flags & kXR_poscpend) == 0;
    if (rc == 0 && reserve_op(execution, 0, &status)
        && brix_file_open_read(connection, object.path, &file, &status) == 0) {
        if (reserve_op(execution, sizeof(actual), &status))
            got = brix_file_read(connection, &file, 0, actual, sizeof(actual),
                &status);
        if (reserve_op(execution, 0, &status))
            brix_file_close(connection, &file, &status);
    }
    grade(execution, "STA-011", pending && cleared,
        "posc-pending-set-while-open-and-cleared-after-close",
        "posc-pending-flag-transition-mismatch", &status);
    grade(execution, "OPN-016", got == (ssize_t) sizeof(expected)
        && memcmp(actual, expected, sizeof(expected)) == 0,
        "clean-posc-close-published-complete-file", "clean-posc-file-mismatch",
        &status);
    if (reserve_op(execution, 0, &status)) brix_rm(connection, object.path, &status);
}

/* WHAT: Prove an abandoned POSC handle never publishes its partial object.
 * WHY: Crash/disconnect cleanup is the security half of persist-on-close.
 * HOW: Open and write on an auxiliary session, drop it without kXR_close,
 *      then poll bounded stat requests until the final name remains absent. */
static void
probe_posc_abort(xrd_conform_execution *execution, brix_conn *connection)
{
    xrd_conform_scratch_object object;
    brix_url url;
    brix_conn auxiliary;
    brix_opts options = execution->run->opts;
    brix_file file;
    brix_statinfo info;
    brix_status status;
    struct timespec pause = { 0, 10000000L };
    unsigned attempt;
    int opened = 0;
    int absent = 0;

    if (!row_active(execution, "OPN-015")
        || scratch_path(execution, "brix-conform-open-posc-abort", &object) != 0)
        return;
    options.capture = NULL;
    brix_status_clear(&status);
    if (brix_endpoint_parse(execution->target, &url, &status) == 0
        && reserve_op(execution, 0, &status)
        && brix_connect(&auxiliary, &url, &options, &status) == 0) {
        if (reserve_op(execution, 0, &status)
            && brix_file_open_write(&auxiliary, object.path, 1, 1, &file,
                &status) == 0) {
            opened = reserve_op(execution, 7, &status)
                && brix_file_write(&auxiliary, &file, 0, "partial", 7,
                    &status) == 0;
        }
        brix_close(&auxiliary);
    }
    for (attempt = 0; opened && !absent && attempt < 20; attempt++) {
        brix_status_clear(&status);
        absent = reserve_op(execution, 0, &status)
            && brix_stat(connection, object.path, &info, &status) != 0
            && status.kxr == kXR_NotFound;
        if (!absent) (void) nanosleep(&pause, NULL);
    }
    grade(execution, "OPN-015", opened && absent,
        "abandoned-posc-left-no-visible-file", "abandoned-posc-file-visible",
        &status);
    /* upload-resume endpoints intentionally retain an invisible, identity-keyed
     * partial after disconnect. Reopen/close it through the protocol, then
     * remove the published scratch object so the probe leaves no durable state. */
    if (opened && reserve_op(execution, 0, &status)
        && brix_file_open_write(connection, object.path, 1, 1, &file,
            &status) == 0) {
        if (reserve_op(execution, 0, &status))
            brix_file_close(connection, &file, &status);
    }
    if (reserve_op(execution, 0, &status))
        brix_rm(connection, object.path, &status);
}

/* WHAT: Resolve the POSC-when-unadvertised conditional clause.
 * WHY: Claim-conditioned rows must not remain inconclusive on a claiming server.
 * HOW: Skip when kXR_supposc is present; otherwise attempt POSC and require the
 *      exact Unsupported response, cleaning any unexpected success. */
static void
probe_posc_absent_claim(xrd_conform_execution *execution,
    brix_conn *connection)
{
    xrd_conform_scratch_object object;
    brix_file file;
    brix_status status;
    int rc;

    if (!row_active(execution, "OPN-017")) return;
    if ((connection->server_flags & kXR_supposc) != 0) {
        xrd_conform_result_set(execution, "OPN-017",
            BRIX_CONFORM_VERDICT_SKIPPED, "claim-present:kXR_supposc",
            NULL, NULL);
        return;
    }
    if (scratch_path(execution, "brix-conform-open-posc-unclaimed", &object)
        != 0) return;
    brix_status_clear(&status);
    rc = reserve_op(execution, 0, &status)
        ? brix_file_open_write(connection, object.path, 1, 1, &file, &status)
        : -1;
    if (rc == 0 && reserve_op(execution, 0, &status))
        brix_file_close(connection, &file, &status);
    grade(execution, "OPN-017", rc != 0 && status.kxr == kXR_Unsupported,
        "unclaimed-posc-refused", "unclaimed-posc-accepted", &status);
    if (reserve_op(execution, 0, &status)) brix_rm(connection, object.path, &status);
}

/* WHAT: Prove write-mode CGI is metadata rather than a storage-path suffix.
 * WHY: Passing opaque query bytes to storage produces ambiguous object names.
 * HOW: Open with the public opaque API, close, stat the bare capability, clean. */
static void
probe_write_cgi(xrd_conform_execution *execution, brix_conn *connection)
{
    xrd_conform_scratch_object object;
    brix_statinfo info;
    brix_file file;
    brix_status status;
    int rc;

    if (!row_active(execution, "OPN-023")
        || scratch_path(execution, "brix-conform-open-cgi", &object) != 0)
        return;
    rc = reserve_op(execution, 0, &status)
        ? brix_file_open_opaque(connection, object.path, "phase118=opaque",
            1, 1, 0, &file, &status) : -1;
    if (rc == 0 && reserve_op(execution, 0, &status))
        rc = brix_file_close(connection, &file, &status);
    memset(&info, 0, sizeof(info));
    if (rc == 0 && reserve_op(execution, 0, &status))
        rc = brix_stat(connection, object.path, &info, &status);
    grade(execution, "OPN-023", rc == 0,
        "write-cgi-stripped-before-storage", "write-cgi-became-storage-path",
        &status);
    if (reserve_op(execution, 0, &status)) brix_rm(connection, object.path, &status);
}

/* WHAT: Distinguish an honoured write-only mode from an unsupported replica.
 * WHY: Accepting either bit as an ignored hint creates false capabilities.
 * HOW: Require exact Unsupported for replica, then write through a wrto handle
 * and require a read through that same capability to fail NotAuthorized. */
static void
probe_replica_wrto(xrd_conform_execution *execution, brix_conn *connection)
{
    xrd_conform_scratch_object object;
    open_reply reply = { 0 };
    brix_file file = { { 0 }, 0, 0 };
    brix_status status;
    uint8_t byte = 0;
    int replica_rc;
    int replica_kxr;
    int write_rc = -1;
    int read_rc = 0;
    int read_kxr = 0;

    if (!row_active(execution, "OPN-022")
        || scratch_path(execution, "brix-conform-open-replica-wrto", &object)
            != 0) return;
    replica_rc = raw_open(execution, connection, object.path, 0644,
        kXR_open_read | kXR_replica, &reply, &status);
    replica_kxr = status.kxr;
    if (replica_rc == 0) close_reply(execution, connection, &reply, &status);
    free(reply.body);
    reply.body = NULL;
    if (raw_open(execution, connection, object.path, 0644,
            kXR_open_wrto | kXR_new, &reply, &status) == 0
        && reply.length >= XRD_FHANDLE_LEN) {
        memcpy(file.fhandle, reply.body, XRD_FHANDLE_LEN);
        write_rc = reserve_op(execution, 1, &status)
            ? brix_file_write(connection, &file, 0, "W", 1, &status) : -1;
        if (reserve_op(execution, 1, &status)) {
            read_rc = (int) brix_file_read(connection, &file, 0, &byte, 1,
                &status);
            read_kxr = status.kxr;
        }
        if (reserve_op(execution, 0, &status))
            brix_file_close(connection, &file, &status);
    }
    grade(execution, "OPN-022", replica_rc != 0
        && replica_kxr == kXR_Unsupported && write_rc == 0
        && read_rc < 0 && read_kxr == kXR_NotAuthorized,
        "replica-refused-and-wrto-honoured",
        "replica-or-wrto-was-accepted-and-ignored", &status);
    free(reply.body);
    if (reserve_op(execution, 0, &status)) brix_rm(connection, object.path, &status);
}

/* WHAT: Walk every single option bit and the contradictory all-bits word.
 * WHY: Unknown combinations must yield bounded defined errors, never server
 *      errors, crashes, or partially accepted all-bits mutation.
 * HOW: Use a fresh scratch path per bit, close success, remove residue, and
 *      require all-bits to return ArgInvalid. */
static void
probe_option_space(xrd_conform_execution *execution, brix_conn *connection)
{
    xrd_conform_scratch_object object;
    open_reply reply = { 0 };
    brix_status status;
    char leaf[64];
    unsigned bit;
    int safe = 1;
    int rc;

    if (row_active(execution, "OPN-024")) {
        for (bit = 0; safe && bit < 16; bit++) {
            snprintf(leaf, sizeof(leaf), "brix-conform-open-bit-%u", bit);
            if (scratch_path(execution, leaf, &object) != 0) return;
            rc = raw_open(execution, connection, object.path, 0644,
                (uint16_t) (1U << bit), &reply, &status);
            safe = rc == 0 || status.kxr != kXR_ServerError;
            if (rc == 0) close_reply(execution, connection, &reply, &status);
            free(reply.body);
            reply.body = NULL;
            if (reserve_op(execution, 0, &status))
                brix_rm(connection, object.path, &status);
        }
        grade(execution, "OPN-024", safe, "all-single-option-bits-defined",
            "single-option-produced-server-error", &status);
    }
    if (!row_active(execution, "OPN-025")
        || scratch_path(execution, "brix-conform-open-all-bits", &object) != 0)
        return;
    rc = raw_open(execution, connection, object.path, 0644, UINT16_MAX,
        &reply, &status);
    if (rc == 0) close_reply(execution, connection, &reply, &status);
    grade(execution, "OPN-025", rc != 0 && status.kxr == kXR_ArgInvalid,
        "contradictory-options-refused", "contradictory-options-accepted",
        &status);
    free(reply.body);
    if (reserve_op(execution, 0, &status)) brix_rm(connection, object.path, &status);
}

/* WHAT: Test that undefined create-mode bits cannot escape the nine-bit field.
 * WHY: Raw mode bits must not smuggle file-type or privilege metadata.
 * HOW: Accept explicit ArgInvalid, or require extended stat to show only 0777. */
static void
probe_mode_bits(xrd_conform_execution *execution, brix_conn *connection)
{
    xrd_conform_scratch_object object;
    open_reply reply = { 0 };
    brix_statinfo info;
    brix_status status;
    int rc;
    int pass;

    if (!row_active(execution, "OPN-026")
        || scratch_path(execution, "brix-conform-open-mode", &object) != 0)
        return;
    rc = raw_open(execution, connection, object.path, UINT16_MAX,
        kXR_open_updt | kXR_new | kXR_mkpath, &reply, &status);
    if (rc == 0) close_reply(execution, connection, &reply, &status);
    memset(&info, 0, sizeof(info));
    if (rc == 0 && reserve_op(execution, 0, &status)
        && brix_stat(connection, object.path, &info, &status) != 0) rc = -1;
    pass = (rc != 0 && status.kxr == kXR_ArgInvalid)
        || (rc == 0 && info.have_ext && (info.mode & ~0777U) == 0);
    if (rc == 0 && !info.have_ext) {
        xrd_conform_result_set(execution, "OPN-026",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "stat-mode-extension-unavailable",
            "rejection or mode limited to 0777", NULL);
    } else {
        grade(execution, "OPN-026", pass, "undefined-mode-bits-contained",
            "undefined-mode-bits-escaped", &status);
    }
    free(reply.body);
    if (reserve_op(execution, 0, &status)) brix_rm(connection, object.path, &status);
}

/* WHAT: Run implemented scratch-confined open mutation clauses.
 * WHY: Read-only object probes cannot establish create and persistence behavior.
 * HOW: Execute independent fixtures serially and clean each before proceeding. */
void
xrd_conform_probe_open_mutations(xrd_conform_execution *execution,
    brix_conn *connection)
{
    if (!xrd_conform_family_active(execution, "OPN")
        && !xrd_conform_family_active(execution, "STA")) return;
    probe_create_disposition(execution, connection);
    probe_mkpath(execution, connection);
    probe_append(execution, connection);
    probe_posc_close(execution, connection);
    probe_posc_abort(execution, connection);
    probe_posc_absent_claim(execution, connection);
    probe_write_cgi(execution, connection);
    probe_replica_wrto(execution, connection);
    probe_option_space(execution, connection);
    probe_mode_bits(execution, connection);
    xrd_conform_probe_open_refresh(execution, connection);
}
