/* Phase-118 GridFTP and OCI cross-plane size/byte adoption. */
#include "xrd_conform_internal.h"
#include "protocols/ftp/ftp_client.h"
#include "oci/ref.h"
#include "oci/reg_client.h"

#define CONFORM_OCI_MANIFEST_CEILING (256U * 1024U)

typedef struct {
    uint8_t *bytes;
    size_t   length;
    size_t   capacity;
} conform_ftp_body;

static int
ftp_body_sink(void *context, const uint8_t *bytes, size_t length,
    brix_status *status)
{
    conform_ftp_body *body = context;

    if (length > body->capacity - body->length) {
        brix_status_set(status, XRDC_EPROTO, 0,
            "GridFTP body exceeds advertised SIZE");
        return -1;
    }
    memcpy(body->bytes + body->length, bytes, length);
    body->length += length;
    return 0;
}

/* WHAT: Adopt one GridFTP object into the common size/digest oracle.
 * WHY: XPR-001/002 must compare the actual FTP data channel, not an HTTP twin.
 * HOW: SIZE first, charge the exact byte budget, then RETR into a bounded body. */
int
xrd_conform_run_ftp(xrd_conform_execution *execution)
{
    brix_ftpurl url;
    brix_ftp_sess *session;
    brix_status status;
    conform_ftp_body body = { 0 };
    int64_t size = -1;
    int64_t mtime = -1;
    char reason[64];
    int rc = -1;

    if (brix_ftpurl_parse(execution->target, &url) != 0) return -1;
    session = calloc(1, sizeof(*session));
    if (session == NULL) return -1;
    brix_status_clear(&status);
    if (brix_ftp_session_open(session, &url, &execution->run->opts,
            &status) != 0
        || brix_ftp_stat(session, url.path, &size, &mtime, &status) != 0
        || size < 0 || (uint64_t) size > SIZE_MAX
        || !xrd_conform_reserve(execution, (size_t) size, reason,
            sizeof(reason))) {
        brix_ftp_close(session);
        free(session);
        return -1;
    }
    body.capacity = (size_t) size;
    body.bytes = malloc(body.capacity == 0 ? 1 : body.capacity);
    if (body.bytes != NULL
        && brix_ftp_retr(session, url.path, ftp_body_sink, &body, NULL, size,
            &status) == 0
        && body.length == body.capacity) {
        execution->ftp_size = (uint64_t) size;
        brix_s3_sha256_hex(body.bytes, body.length, execution->ftp_digest);
        execution->have_ftp = 1;
        rc = 0;
    }
    free(body.bytes);
    brix_ftp_close(session);
    free(session);
    (void) mtime;
    return rc;
}

/* WHAT: Adopt one OCI manifest into the common size/digest oracle.
 * WHY: A manifest is OCI's immutable named object and can be served verbatim
 *      through ROOT/HTTP/FTP twins for cross-plane integrity comparison.
 * HOW: Parse the explicit oci scheme, use the production registry client, and
 *      hash the verified manifest body returned by its bounded GET. */
int
xrd_conform_run_oci(xrd_conform_execution *execution)
{
    const char *target = execution->target;
    int insecure = strncmp(target, "oci+http://", 11) == 0;
    const char *spec = target + (insecure ? 11 : 6);
    brix_oci_ref_t reference;
    brix_oci_reg_t registry;
    brix_oci_desc_t manifest;
    char name[256];
    char error[256];
    char reason[64];
    int rc;

    memset(&manifest, 0, sizeof(manifest));
    if (!xrd_conform_reserve(execution, CONFORM_OCI_MANIFEST_CEILING,
            reason, sizeof(reason))
        || brix_oci_ref_parse(spec, &reference, error, sizeof(error)) != 0
        || brix_oci_reg_from_ref(&registry, &reference, insecure, name,
            sizeof(name), error, sizeof(error)) != BRIX_OCI_REG_OK)
        return -1;
    registry.verify = !execution->run->opts.insecure_tls;
    registry.ca_dir = brix_resolve_ca_dir(execution->run->opts.ca_dir);
    rc = brix_oci_reg_manifest(&registry, &reference, NULL, &manifest,
        error, sizeof(error));
    if (rc != BRIX_OCI_REG_OK
        || manifest.body_len > CONFORM_OCI_MANIFEST_CEILING) {
        brix_oci_desc_free(&manifest);
        return -1;
    }
    execution->oci_size = manifest.body_len;
    brix_s3_sha256_hex(manifest.body, manifest.body_len,
        execution->oci_digest);
    execution->have_oci = 1;
    brix_oci_desc_free(&manifest);
    return 0;
}
