/*
 * ssi_service.c — native SSI service registry + built-in handlers. See header.
 *
 * Built-ins are pure C (no nginx), so they + the registry are unit-testable with
 * a recording responder. Sync handlers deliver inline via set_response(last=1);
 * a streaming/async handler would retain the responder and drive it from a
 * thread-pool job (the responder vtable is the same).
 */

#include "ssi_service.h"
#include <string.h>

/* echo: return the request verbatim as a single final response chunk. */
static int
svc_echo(const unsigned char *req, size_t req_len, brix_ssi_responder_t *r)
{
    r->set_response(r, req, req_len, 1);
    return 0;
}

/* meta: echo with a fixed metadata blob, exercising the metadata path. */
static int
svc_meta(const unsigned char *req, size_t req_len, brix_ssi_responder_t *r)
{
    static const unsigned char md[] = "ssi-meta";
    r->set_metadata(r, md, sizeof(md) - 1);
    r->set_response(r, req, req_len, 1);
    return 0;
}

/* stream: deliver the request back in three chunks (last=0,0,1), exercising the
 * read-pull streaming path. */
static int
svc_stream(const unsigned char *req, size_t req_len, brix_ssi_responder_t *r)
{
    (void) req;
    (void) req_len;
    r->set_response(r, (const unsigned char *) "part-A|", 7, 0);
    r->set_response(r, (const unsigned char *) "part-B|", 7, 0);
    r->set_response(r, (const unsigned char *) "part-C",  6, 1);
    return 0;
}

/* err: always fail with an SSI error, exercising the error-reply path. */
static int
svc_err(const unsigned char *req, size_t req_len, brix_ssi_responder_t *r)
{
    (void) req;
    (void) req_len;
    r->error(r, 22 /* EINVAL */, "ssi service rejected the request");
    return 0;
}

/* echo-async: the deferred sibling of echo. On submit it asks to defer (the
 * server replies kXR_waitresp and pushes the result later); when re-invoked for
 * completion (defer unavailable) it echoes the request inline. The defer-or-respond
 * shape is the template every async service follows. */
static int
svc_echo_async(const unsigned char *req, size_t req_len, brix_ssi_responder_t *r)
{
    if (r->defer != NULL && r->defer(r) == 0) {
        return 0;   /* submit phase: deferred, completed later */
    }
    r->set_response(r, req, req_len, 1);   /* completion phase: respond inline */
    return 0;
}

/* stream-async: the deferred sibling of stream. On submit it defers; on
 * completion it emits the response as three chunks (last=0,0,1), so the framework
 * signals the client pendResp and the client drains the buffer via kXR_read. */
static int
svc_stream_async(const unsigned char *req, size_t req_len, brix_ssi_responder_t *r)
{
    (void) req;
    (void) req_len;
    if (r->defer != NULL && r->defer(r) == 0) {
        return 0;   /* submit phase: deferred */
    }
    r->set_response(r, (const unsigned char *) "part-A|", 7, 0);
    r->set_response(r, (const unsigned char *) "part-B|", 7, 0);
    r->set_response(r, (const unsigned char *) "part-C",  6, 1);
    return 0;
}

/* alert-async: defers, then pushes two progress alerts before the final response,
 * exercising out-of-band alert delivery interleaved with the response push. */
static int
svc_alert_async(const unsigned char *req, size_t req_len, brix_ssi_responder_t *r)
{
    (void) req;
    (void) req_len;
    if (r->defer != NULL && r->defer(r) == 0) {
        return 0;   /* submit phase: deferred */
    }
    r->alert(r, (const unsigned char *) "progress-1", 10);
    r->alert(r, (const unsigned char *) "progress-2", 10);
    r->set_response(r, (const unsigned char *) "done", 4, 1);
    return 0;
}

static const struct {
    const char            *name;
    brix_ssi_process_fn  fn;
} services[] = {
    { "echo",         svc_echo },
    { "meta",         svc_meta },
    { "stream",       svc_stream },
    { "err",          svc_err },
    { "echo-async",   svc_echo_async },
    { "stream-async", svc_stream_async },
    { "alert-async",  svc_alert_async },
};

brix_ssi_process_fn
brix_ssi_service_lookup(const char *name)
{
    size_t i;

    if (name == NULL) {
        return NULL;
    }
    for (i = 0; i < sizeof(services) / sizeof(services[0]); i++) {
        if (strcmp(services[i].name, name) == 0) {
            return services[i].fn;
        }
    }
    return NULL;
}

const char *
brix_ssi_service_canon_name(const char *name)
{
    size_t i;

    if (name == NULL) {
        return NULL;
    }
    for (i = 0; i < sizeof(services) / sizeof(services[0]); i++) {
        if (strcmp(services[i].name, name) == 0) {
            return services[i].name;   /* static-lifetime literal */
        }
    }
    return NULL;
}
