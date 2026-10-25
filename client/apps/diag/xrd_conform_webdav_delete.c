/* Phase-118 DAV-006 recursive atomic collection-delete probe. */
#include "xrd_conform_probe_helpers.h"

#include <pthread.h>

#define DAV_DELETE_SNAPSHOTS 6U

typedef struct {
    xrd_conform_execution *execution;
    brix_weburl            collection;
    char                  *headers;
    brix_http_resp         response;
    brix_status            status;
    int                    rc;
} dav_delete_job;


static void
set_delete_result(xrd_conform_execution *execution,
    brix_conform_verdict verdict, const char *reason, const char *expected,
    const char *received)
{
    static const char *const ids[] = { "DAV-006", "RM-008" };
    size_t index;

    for (index = 0; index < sizeof(ids) / sizeof(ids[0]); index++)
        if (xrd_conform_row_active(execution, ids[index]))
            xrd_conform_result_set(execution, ids[index], verdict, reason,
                expected, received);
}

static int child_url(const brix_weburl *parent, const char *suffix,
    brix_weburl *child)
{
    *child = *parent;
    return (size_t) snprintf(child->path, sizeof(child->path), "%s/%s",
        parent->path, suffix) < sizeof(child->path) ? 0 : -1;
}

static int request_status(xrd_conform_execution *execution,
    const brix_weburl *url, const char *method, const char *token,
    const char *fields, const char *body, int *http_status)
{
    brix_http_resp response;
    brix_status status;
    size_t body_length = body == NULL ? 0 : strlen(body);
    int rc;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(execution, url, method, token, fields,
        body, body_length, 65536, &response, &status);
    if (rc != 0) return -1;
    *http_status = response.status;
    brix_http_resp_free(&response);
    return 0;
}

static int plant_tree(xrd_conform_execution *execution,
    const brix_weburl *collection, const brix_weburl *nested,
    const brix_weburl *first, const brix_weburl *second, const char *token)
{
    int status = 0;

    return request_status(execution, collection, "MKCOL", token, NULL, NULL,
               &status) == 0 && status >= 200 && status < 300
        && request_status(execution, nested, "MKCOL", token, NULL, NULL,
               &status) == 0 && status >= 200 && status < 300
        && request_status(execution, first, "PUT", token, NULL, "first",
               &status) == 0 && status >= 200 && status < 300
        && request_status(execution, second, "PUT", token, NULL, "second",
               &status) == 0 && status >= 200 && status < 300;
}

static void *delete_worker(void *opaque)
{
    dav_delete_job *job = opaque;
    char proxy[XRDC_PATH_MAX];
    const char *client_cert = brix_web_proxy_pem(proxy, sizeof(proxy));

    memset(&job->response, 0, sizeof(job->response));
    brix_status_clear(&job->status);
    job->rc = brix_http_req(job->collection.host, job->collection.port,
        job->collection.tls, "DELETE", job->collection.path, job->headers,
        NULL, 0, 10000, job->execution->run->opts.verify_host,
        brix_resolve_ca_dir(job->execution->run->opts.ca_dir), client_cert,
        &job->response, &job->status);
    return NULL;
}

static int snapshot_complete(xrd_conform_execution *execution,
    const brix_weburl *collection, const char *token, int *absent)
{
    static const char body[] =
        "<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><allprop/>"
        "</propfind>";
    brix_http_resp response;
    brix_status status;
    size_t count = 0;
    int rc;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(execution, collection, "PROPFIND",
        token, "Depth: 1\r\nContent-Type: application/xml\r\n", body,
        sizeof(body) - 1, 65536, &response, &status);
    if (rc != 0) return -1;
    *absent = response.status == 404 || response.status == 410;
    if (response.status == 207)
        count = xrd_conform_webdav_xml_count(response.body, "response");
    rc = *absent || (response.status == 207 && count == 3) ? 0 : -1;
    brix_http_resp_free(&response);
    return rc;
}

static int resource_absent(xrd_conform_execution *execution,
    const brix_weburl *resource, const char *token)
{
    static const char body[] =
        "<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><allprop/>"
        "</propfind>";
    brix_http_resp response;
    brix_status status;
    int rc;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(execution, resource, "PROPFIND",
        token, "Depth: 0\r\nContent-Type: application/xml\r\n", body,
        sizeof(body) - 1, 4096, &response, &status);
    if (rc != 0) return 0;
    rc = response.status == 404 || response.status == 410;
    brix_http_resp_free(&response);
    return rc;
}

static void cleanup_tree(xrd_conform_execution *execution,
    const brix_weburl *collection, const char *token)
{
    int status = 0;

    (void) request_status(execution, collection, "DELETE", token, NULL, NULL,
        &status);
}

static int
prepare_delete_tree(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, brix_weburl *collection, brix_weburl *nested,
    brix_weburl *first, brix_weburl *second)
{
    return xrd_conform_webdav_scratch_url(execution, url,
            "brix-conform-dav-delete", collection) == 0
        && child_url(collection, "nested", nested) == 0
        && child_url(collection, "first", first) == 0
        && child_url(nested, "second", second) == 0
        && plant_tree(execution, collection, nested, first, second, token);
}

static int
start_delete_job(xrd_conform_execution *execution,
    const brix_weburl *collection, const char *token, dav_delete_job *job,
    pthread_t *thread, const char **failure, char *reason, size_t reason_size)
{
    memset(job, 0, sizeof(*job));
    job->execution = execution;
    job->collection = *collection;
    job->headers = xrd_conform_http_headers(collection, "DELETE", token, NULL,
        failure);
    return job->headers != NULL
        && xrd_conform_reserve(execution, 65536, reason, reason_size)
        && pthread_create(thread, NULL, delete_worker, job) == 0;
}

static int
observe_delete_snapshots(xrd_conform_execution *execution,
    const brix_weburl *collection, const char *token, int *absent)
{
    size_t snapshots = 0;
    int partial = 0;

    while (snapshots < DAV_DELETE_SNAPSHOTS && !*absent) {
        if (snapshot_complete(execution, collection, token, absent) != 0)
            partial = 1;
        snapshots++;
    }
    return partial;
}

static int
delete_completed(xrd_conform_execution *execution, dav_delete_job *job,
    pthread_t thread, const brix_weburl *collection, const brix_weburl *nested,
    const brix_weburl *first, const brix_weburl *second, const char *token,
    int partial, int *absent, int *descendants_absent)
{
    int joined = pthread_join(thread, NULL) == 0;

    *descendants_absent = resource_absent(execution, first, token)
        && resource_absent(execution, nested, token)
        && resource_absent(execution, second, token);
    return joined && !partial && job->rc == 0
        && job->response.status >= 200 && job->response.status < 300
        && snapshot_complete(execution, collection, token, absent) == 0
        && *absent && *descendants_absent;
}

void xrd_conform_probe_webdav_delete(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    brix_weburl collection = { 0 };
    brix_weburl nested = { 0 };
    brix_weburl first = { 0 };
    brix_weburl second = { 0 };
    dav_delete_job job;
    pthread_t thread;
    const char *failure = NULL;
    char reason[64] = "delete-worker-unavailable";
    int absent = 0;
    int partial = 0;
    int descendants_absent;
    int pass;

    if (!xrd_conform_row_active(execution, "DAV-006")
        && !xrd_conform_row_active(execution, "RM-008")) return;
    if (!prepare_delete_tree(execution, url, token, &collection, &nested,
            &first, &second)) {
        set_delete_result(execution, BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-setup:recursive-webdav-collection", NULL, NULL);
        if (collection.path[0] != '\0')
            cleanup_tree(execution, &collection, token);
        return;
    }
    if (!start_delete_job(execution, &collection, token, &job, &thread,
            &failure, reason, sizeof(reason))) {
        set_delete_result(execution, BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            job.headers == NULL ? "delete-header-construction-failed"
                                : "delete-worker-unavailable",
            NULL, failure == NULL ? reason : failure);
        free(job.headers);
        cleanup_tree(execution, &collection, token);
        return;
    }
    partial = observe_delete_snapshots(execution, &collection, token, &absent);
    pass = delete_completed(execution, &job, thread, &collection, &nested,
        &first, &second, token, partial, &absent, &descendants_absent);
    set_delete_result(execution,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "recursive-delete-observed-atomically"
             : "recursive-delete-partial-or-incomplete",
        "every Depth-1 snapshot is complete or absent; final tree absent",
        partial ? "partial-tree-observed"
                : descendants_absent ? job.status.msg
                                     : "orphaned-descendant-observed");
    if (job.rc == 0) brix_http_resp_free(&job.response);
    free(job.headers);
    cleanup_tree(execution, &collection, token);
}
