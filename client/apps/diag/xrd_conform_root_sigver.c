/* Phase-118 active request-signing envelope probes. */
#include "xrd_conform_internal.h"
#include "auth/gsi/gsi_core.h"
#include "protocols/root/protocol/frame_hdr.h"

#include <arpa/inet.h>

typedef struct {
    uint16_t wire_status;
    int      kxr;
    int      rc;
} sigver_observation;

static int
reserve(xrd_conform_execution *execution, size_t bytes)
{
    char reason[64];

    return xrd_conform_reserve(execution, bytes, reason, sizeof(reason));
}

static int
connect_signing(xrd_conform_execution *execution, const brix_url *url,
    brix_conn *connection, brix_status *status)
{
    brix_opts opts = execution->run->opts;

    opts.capture = NULL;
    brix_status_clear(status);
    if (brix_connect(connection, url, &opts, status) != 0) return -1;
    if (!connection->signing_active || !connection->gsi_deleg_ready) {
        brix_close(connection);
        return -1;
    }
    return 0;
}

/* Build the exact covered open request before deriving its signature. */
static void
build_open(ClientOpenRequest *request, uint16_t stream_id, const char *path)
{
    xrdw_open_req_t fields = {
        .mode = 0, .options = kXR_open_read, .optiont = 0
    };
    uint32_t length = (uint32_t) strlen(path);
    uint32_t encoded = htonl(length);

    memset(request, 0, sizeof(*request));
    request->streamid[0] = (uint8_t) (stream_id >> 8);
    request->streamid[1] = (uint8_t) stream_id;
    request->requestid = htons(kXR_open);
    xrdw_open_req_pack(&fields, ((ClientRequestHdr *) request)->body);
    memcpy((uint8_t *) request + 20, &encoded, sizeof(encoded));
}

static uint8_t *
make_signature(const brix_conn *connection, uint64_t sequence,
    const ClientOpenRequest *request, const char *path, int nodata,
    size_t *signature_length)
{
    brix_gsi_cipher_t cipher;

    if (!brix_gsi_cipher_lookup(connection->gsi_deleg_cipher, &cipher)
        || connection->gsi_deleg_keylen < (size_t) cipher.key_len) return NULL;
    return brix_gsi_sigver_sign(&cipher, connection->gsi_deleg_key,
        connection->gsi_deleg_use_iv, sequence, (const uint8_t *) request,
        (const uint8_t *) path, strlen(path), nodata, signature_length);
}

static int
write_prefix(xrd_conform_execution *execution, brix_conn *connection,
    uint16_t stream_id, uint16_t expectrid, uint8_t version, uint8_t flags,
    uint64_t sequence, uint8_t crypto, const uint8_t *signature,
    size_t signature_length, brix_status *status)
{
    ClientSigverRequest request;
    xrdw_sigver_req_t fields = {
        .expectrid = expectrid,
        .version = version,
        .flags = flags,
        .seqno = sequence,
        .crypto = crypto,
    };

    if (signature_length > UINT32_MAX
        || !reserve(execution, sizeof(request) + signature_length)) return -1;
    memset(&request, 0, sizeof(request));
    request.streamid[0] = (uint8_t) (stream_id >> 8);
    request.streamid[1] = (uint8_t) stream_id;
    request.requestid = htons(kXR_sigver);
    xrdw_sigver_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    request.dlen = (int32_t) htonl((uint32_t) signature_length);
    brix_status_clear(status);
    if (brix_write_full(&connection->io, &request, sizeof(request), status) != 0)
        return -1;
    return brix_write_full(&connection->io, signature, signature_length,
        status);
}

static sigver_observation
receive_one(brix_conn *connection, uint16_t stream_id, brix_status *status)
{
    sigver_observation observed = { 0 };
    uint8_t *body = NULL;
    uint32_t length = 0;
    brix_resp_out response = { &observed.wire_status, &body, &length };

    observed.rc = brix_recv(connection, stream_id, &response, status);
    observed.kxr = status->kxr;
    free(body);
    return observed;
}

/* Send a prefix and its covered open, returning the covered response. */
static sigver_observation
signed_open(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, uint16_t expectrid, uint8_t version, uint8_t flags,
    uint64_t sequence, uint8_t crypto, int hash_without_payload)
{
    ClientOpenRequest request;
    brix_status status;
    brix_payload payload = { path, (uint32_t) strlen(path) };
    uint16_t stream_id = connection->next_sid++;
    uint8_t *signature;
    size_t signature_length = 0;
    sigver_observation failed = { .rc = -1 };

    build_open(&request, stream_id, path);
    signature = make_signature(connection, sequence, &request, path,
        hash_without_payload, &signature_length);
    if (signature == NULL) return failed;
    if (write_prefix(execution, connection, stream_id, expectrid, version,
            flags, sequence, crypto, signature, signature_length, &status) != 0
        || !reserve(execution, sizeof(request) + payload.len)
        || brix_write_full(&connection->io, &request, sizeof(request),
            &status) != 0
        || brix_write_full(&connection->io, path, payload.len, &status) != 0) {
        free(signature);
        failed.kxr = status.kxr;
        return failed;
    }
    free(signature);
    return receive_one(connection, stream_id, &status);
}

/* WHAT: Cover an open with the plain SHA-256 form authorized by secOFrce.
 * WHY: Merely observing the option is not evidence that the advertised form is
 *      both accepted and verified; a server that ignores the bytes is unsafe.
 * HOW: Hash the exact sequence/header/payload span, optionally corrupt the
 *      digest, then send it as the sigver body without session encryption. */
static sigver_observation
unencrypted_open(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, int corrupt)
{
    ClientOpenRequest request;
    brix_status status;
    brix_payload payload = { path, (uint32_t) strlen(path) };
    uint16_t stream_id = connection->next_sid++;
    uint8_t hash[32];
    sigver_observation failed = { .rc = -1 };

    build_open(&request, stream_id, path);
    if (!brix_gsi_sigver_hash(1, (const uint8_t *) &request,
            (const uint8_t *) path, strlen(path), 0, hash))
        return failed;
    if (corrupt) hash[0] ^= 0x80;
    if (write_prefix(execution, connection, stream_id, kXR_open, 0, 0, 1,
            kXR_SHA256_sig, hash, sizeof(hash), &status) != 0
        || !reserve(execution, sizeof(request) + payload.len)
        || brix_write_full(&connection->io, &request, sizeof(request),
            &status) != 0
        || brix_write_full(&connection->io, path, payload.len, &status) != 0)
    {
        failed.kxr = status.kxr;
        return failed;
    }
    return receive_one(connection, stream_id, &status);
}

/* Invalid prefix fields must be rejected before a covered request is needed. */
static sigver_observation
invalid_prefix(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, uint8_t version, uint8_t crypto, uint64_t sequence)
{
    ClientOpenRequest covered;
    brix_status status;
    uint16_t stream_id = connection->next_sid++;
    uint8_t *signature;
    size_t signature_length = 0;
    sigver_observation failed = { .rc = -1 };

    build_open(&covered, stream_id, path);
    signature = make_signature(connection, sequence, &covered, path, 0,
        &signature_length);
    if (signature == NULL) return failed;
    if (write_prefix(execution, connection, stream_id, kXR_open, version, 0,
            sequence, crypto, signature, signature_length, &status) != 0) {
        free(signature);
        failed.kxr = status.kxr;
        return failed;
    }
    free(signature);
    return receive_one(connection, stream_id, &status);
}

static int
is_refusal(sigver_observation observed)
{
    return observed.rc != 0 && observed.kxr > 0;
}

static void
grade(xrd_conform_execution *execution, const char *id, int pass,
    const char *success, sigver_observation observed)
{
    char received[64];

    snprintf(received, sizeof(received), "rc=%d wire=%u kxr=%d",
        observed.rc, (unsigned) observed.wire_status, observed.kxr);
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? success : "unexpected-sigver-answer", NULL, received);
}

static void
probe_one(xrd_conform_execution *execution, const brix_url *url,
    const char *id)
{
    brix_conn connection;
    brix_status status;
    sigver_observation first = { .rc = -1 };
    sigver_observation observed = { .rc = -1 };

    if (connect_signing(execution, url, &connection, &status) != 0) return;
    if (strcmp(id, "SIG-003") == 0) {
        observed = signed_open(execution, &connection, url->path, kXR_stat,
            0, 0, 1, kXR_SHA256_sig, 0);
        grade(execution, id, is_refusal(observed),
            "wrong-expectrid-refused", observed);
    } else if (strcmp(id, "SIG-004") == 0) {
        first = signed_open(execution, &connection, url->path, kXR_open,
            0, 0, 10, kXR_SHA256_sig, 0);
        observed = invalid_prefix(execution, &connection, url->path, 0,
            kXR_SHA256_sig, 10);
        grade(execution, id, first.rc == 0 && is_refusal(observed),
            "replayed-sequence-refused", observed);
    } else if (strcmp(id, "SIG-005") == 0) {
        observed = signed_open(execution, &connection, url->path, kXR_open,
            0, 0, UINT64_C(1) << 40, kXR_SHA256_sig, 0);
        grade(execution, id, observed.rc == 0,
            "forward-sequence-gap-accepted", observed);
    } else if (strcmp(id, "SIG-006") == 0) {
        if (connection.sec_level >= 4) {
            xrd_conform_result_set(execution, id,
                BRIX_CONFORM_VERDICT_SKIPPED,
                "claim-excludes-nodata:pedantic-payload-signing", NULL, NULL);
        } else {
            observed = signed_open(execution, &connection, url->path, kXR_open,
                0, kXR_nodata_sig, 1, kXR_SHA256_sig, 1);
            grade(execution, id, observed.rc == 0,
                "nodata-signature-ignored-payload-bytes", observed);
        }
    } else if (strcmp(id, "SIG-007") == 0) {
        observed = invalid_prefix(execution, &connection, url->path, 0,
            0x02, 1);
        grade(execution, id, is_refusal(observed),
            "unknown-signature-hash-refused", observed);
    } else if (strcmp(id, "SIG-008") == 0) {
        observed = invalid_prefix(execution, &connection, url->path, 1,
            kXR_SHA256_sig, 1);
        grade(execution, id, is_refusal(observed),
            "unknown-signature-version-refused", observed);
    }
    brix_close(&connection);
}

/* WHAT: Send a covered data opcode directly over a bound secondary stream.
 * WHY: A bind inherits the primary identity but must not shed its request-
 *      signing policy merely because the secondary has no independent login.
 * HOW: Open on a signed primary, bind an auxiliary connection, then require
 *      its unsigned direct read to receive an authorization/signature refusal. */
void
xrd_conform_probe_sigver_bound(xrd_conform_execution *execution,
    const brix_url *url)
{
    brix_conn primary;
    brix_conn secondary;
    brix_file file;
    brix_status status;
    uint8_t byte;
    ssize_t got;
    int enforced;

    memset(&secondary, 0, sizeof(secondary));
    if (connect_signing(execution, url, &primary, &status) != 0) {
        xrd_conform_result_set(execution, "SIG-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "signing-primary-unavailable", NULL, status.msg);
        return;
    }
    if (!reserve(execution, 0)) {
        xrd_conform_result_set(execution, "SIG-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "request-ceiling-before-signed-open", NULL, NULL);
        brix_close(&primary);
        return;
    }
    brix_status_clear(&status);
    if (brix_file_open_read(&primary, url->path, &file, &status) != 0) {
        xrd_conform_result_set(execution, "SIG-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "signed-open-unavailable", NULL, status.msg);
        brix_close(&primary);
        return;
    }
    if (!reserve(execution, 0)) {
        xrd_conform_result_set(execution, "SIG-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "request-ceiling-before-bind", NULL, NULL);
        (void) brix_file_close(&primary, &file, &status);
        brix_close(&primary);
        return;
    }
    brix_status_clear(&status);
    if (brix_bind(&secondary, &primary, &status) != 0) {
        xrd_conform_result_set(execution, "SIG-009",
            status.kxr == kXR_Unsupported ? BRIX_CONFORM_VERDICT_SKIPPED
                                          : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            status.kxr == kXR_Unsupported
                ? "claim-absent:data-substreams" : "bound-stream-unavailable",
            NULL, status.msg);
        (void) brix_file_close(&primary, &file, &status);
        brix_close(&primary);
        return;
    }
    if (!reserve(execution, sizeof(byte))) {
        xrd_conform_result_set(execution, "SIG-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "request-ceiling-before-bound-read", NULL, NULL);
        brix_close(&secondary);
        (void) brix_file_close(&primary, &file, &status);
        brix_close(&primary);
        return;
    }
    brix_status_clear(&status);
    got = brix_file_read(&secondary, &file, 0, &byte, sizeof(byte), &status);
    enforced = got < 0 && (status.kxr == kXR_SigVerErr
                          || status.kxr == kXR_NotAuthorized);
    xrd_conform_result_set(execution, "SIG-009",
        enforced ? BRIX_CONFORM_VERDICT_CONFORMANT
                 : BRIX_CONFORM_VERDICT_DIVERGENT,
        enforced ? "bound-unsigned-request-refused"
                 : "bound-stream-bypassed-signing-policy",
        "defined signing refusal", status.msg);
    brix_close(&secondary);
    (void) brix_file_close(&primary, &file, &status);
    brix_close(&primary);
}

void
xrd_conform_probe_sigver_active(xrd_conform_execution *execution,
    const brix_url *url)
{
    static const char *const ids[] = {
        "SIG-003", "SIG-004", "SIG-005", "SIG-006", "SIG-007", "SIG-008"
    };
    size_t index;

    for (index = 0; index < sizeof(ids) / sizeof(ids[0]); index++)
        probe_one(execution, url, ids[index]);
}

void
xrd_conform_probe_sigver_unencrypted(xrd_conform_execution *execution,
    const brix_url *url)
{
    brix_conn connection;
    brix_status status;
    sigver_observation positive = { .rc = -1 };
    sigver_observation negative = { .rc = -1 };
    char received[96];

    if (connect_signing(execution, url, &connection, &status) == 0) {
        positive = unencrypted_open(execution, &connection, url->path, 0);
        brix_close(&connection);
    }
    if (connect_signing(execution, url, &connection, &status) == 0) {
        negative = unencrypted_open(execution, &connection, url->path, 1);
        brix_close(&connection);
    }
    snprintf(received, sizeof(received),
        "valid_rc=%d valid_kxr=%d corrupt_rc=%d corrupt_kxr=%d",
        positive.rc, positive.kxr, negative.rc, negative.kxr);
    if (positive.rc == 0 && is_refusal(negative)) {
        xrd_conform_result_set(execution, "SIG-010",
            BRIX_CONFORM_VERDICT_CONFORMANT,
            "unencrypted-hash-accepted-and-corruption-refused", NULL,
            received);
    } else if (positive.rc == 0 && negative.rc == 0) {
        xrd_conform_result_set(execution, "SIG-010",
            BRIX_CONFORM_VERDICT_DIVERGENT,
            "unencrypted-hash-accepted-without-verification", NULL,
            received);
    } else {
        xrd_conform_result_set(execution, "SIG-010",
            BRIX_CONFORM_VERDICT_DIVERGENT,
            "advertised-unencrypted-hash-refused", NULL, received);
    }
}
