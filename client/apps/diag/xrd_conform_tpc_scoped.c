/* Phase-118 path-scoped native-TPC delegated-credential probe. */
#include "xrd_conform_internal.h"

#define SCOPED_TPC_BYTES 8192U

static int
reserve_probe(xrd_conform_execution *execution, brix_status *status)
{
    char reason[64];
    unsigned index;

    for (index = 0; index < 20; index++) {
        size_t bytes = index == 0 ? SCOPED_TPC_BYTES * 3U : 0;

        if (!xrd_conform_reserve(execution, bytes, reason, sizeof(reason))) {
            brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
            return -1;
        }
    }
    return 0;
}

static int
read_source(brix_conn *source, const char *path,
    uint8_t payload[SCOPED_TPC_BYTES], brix_status *status)
{
    brix_file file;
    ssize_t length;
    brix_status close_status;

    if (brix_file_open_read(source, path, &file, status) != 0) return -1;
    length = brix_file_read(source, &file, 0, payload, SCOPED_TPC_BYTES,
        status);
    brix_status_clear(&close_status);
    if (brix_file_close(source, &file, &close_status) != 0 && length >= 0) {
        *status = close_status;
        return -1;
    }
    return length == SCOPED_TPC_BYTES ? 0 : -1;
}

static void
remove_destination(brix_conn *destination,
    const xrd_conform_scratch_object *object)
{
    brix_status status;

    brix_status_clear(&status);
    brix_rm(destination, object->path, &status);
}

/* WHAT: Prove a delegated bearer cannot read outside its transfer scope.
 * WHY: A successful in-scope TPC says nothing about confused-deputy expansion.
 * HOW: Read and copy an externally prepared scoped object with explicit
 *      delegation, then reuse the same credential for an out-of-scope source
 *      and require the exact authorization refusal. TPC-001/003/004 separately
 *      own byte-exact and failed-destination cleanup assertions. */
void
xrd_conform_probe_tpc_scoped(xrd_conform_execution *execution)
{
    brix_url source_url;
    brix_url destination_url;
    brix_conn source;
    brix_conn destination;
    brix_copy_opts copy = { 0 };
    brix_opts opts = execution->run->opts;
    brix_status status;
    xrd_conform_scratch_object allowed_source;
    xrd_conform_scratch_object denied_source;
    xrd_conform_scratch_object allowed_destination;
    xrd_conform_scratch_object denied_destination;
    uint8_t payload[SCOPED_TPC_BYTES];
    char allowed_source_url[XRDC_PATH_MAX + 320];
    char denied_source_url[XRDC_PATH_MAX + 320];
    char allowed_destination_url[XRDC_PATH_MAX + 320];
    char denied_destination_url[XRDC_PATH_MAX + 320];
    int connected_source = 0;
    int connected_destination = 0;
    int adopted = 0;
    int allowed = 0;
    int denied = 0;

    brix_status_clear(&status);
    if (execution->run->also_count == 0
        || brix_endpoint_parse(execution->run->config.target, &source_url,
            &status) != 0
        || brix_endpoint_parse(execution->run->also[0], &destination_url,
            &status) != 0
        || brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-tpc-source", allowed_source.path,
            sizeof(allowed_source.path)) != 0
        || brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-tpc-outside-scope", denied_source.path,
            sizeof(denied_source.path)) != 0
        || brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-tpc-destination", allowed_destination.path,
            sizeof(allowed_destination.path)) != 0
        || brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-tpc-denied-destination", denied_destination.path,
            sizeof(denied_destination.path)) != 0
        || xrd_conform_tpc_root_url(&source_url, allowed_source.path,
            allowed_source_url, sizeof(allowed_source_url)) != 0
        || xrd_conform_tpc_root_url(&source_url, denied_source.path,
            denied_source_url, sizeof(denied_source_url)) != 0
        || xrd_conform_tpc_root_url(&destination_url,
            allowed_destination.path, allowed_destination_url,
            sizeof(allowed_destination_url)) != 0
        || xrd_conform_tpc_root_url(&destination_url,
            denied_destination.path, denied_destination_url,
            sizeof(denied_destination_url)) != 0
        || reserve_probe(execution, &status) != 0) {
        xrd_conform_result_set(execution, "TPC-005",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:scoped-delegated-credential", NULL, status.msg);
        return;
    }
    opts.capture = NULL;
    if (brix_connect(&source, &source_url, &opts, &status) == 0)
        connected_source = 1;
    if (connected_source
        && brix_connect(&destination, &destination_url, &opts, &status) == 0)
        connected_destination = 1;
    if (connected_destination) {
        adopted = read_source(&source, allowed_source.path, payload, &status) == 0;
        remove_destination(&destination, &allowed_destination);
        remove_destination(&destination, &denied_destination);
        copy.tpc_mode = XRDC_TPC_DELEGATE;
        copy.tpc_token_mode = "passthrough";
        copy.force = 1;
        copy.posc = 1;
        copy.silent = 1;
        if (adopted)
            allowed = brix_copy(allowed_source_url, allowed_destination_url,
                &copy, &opts, &status) == 0;
        brix_status_clear(&status);
        denied = brix_copy(denied_source_url, denied_destination_url, &copy,
            &opts, &status) != 0 && status.kxr == kXR_NotAuthorized;
    }
    xrd_conform_result_set(execution, "TPC-005",
        adopted && allowed && denied
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : adopted ? BRIX_CONFORM_VERDICT_DIVERGENT
                      : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
        adopted && allowed && denied
            ? "delegated-credential-confined-to-transfer-scope"
            : !connected_source || !connected_destination
                ? "scoped-tpc-endpoint-unavailable"
            : !adopted ? "fixture-required:scoped-source-objects"
            : !allowed ? "in-scope-delegated-tpc-failed"
                       : "delegated-credential-escaped-transfer-scope",
        "in-scope TPC succeeds; sibling returns kXR_NotAuthorized",
        status.msg);
    if (connected_destination) {
        remove_destination(&destination, &allowed_destination);
        remove_destination(&destination, &denied_destination);
        brix_close(&destination);
    }
    if (connected_source) brix_close(&source);
}
