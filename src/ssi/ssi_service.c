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
svc_echo(const unsigned char *req, size_t req_len, xrootd_ssi_responder_t *r)
{
    r->set_response(r, req, req_len, 1);
    return 0;
}

/* meta: echo with a fixed metadata blob, exercising the metadata path. */
static int
svc_meta(const unsigned char *req, size_t req_len, xrootd_ssi_responder_t *r)
{
    static const unsigned char md[] = "ssi-meta";
    r->set_metadata(r, md, sizeof(md) - 1);
    r->set_response(r, req, req_len, 1);
    return 0;
}

/* stream: deliver the request back in three chunks (last=0,0,1), exercising the
 * read-pull streaming path. */
static int
svc_stream(const unsigned char *req, size_t req_len, xrootd_ssi_responder_t *r)
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
svc_err(const unsigned char *req, size_t req_len, xrootd_ssi_responder_t *r)
{
    (void) req;
    (void) req_len;
    r->error(r, 22 /* EINVAL */, "ssi service rejected the request");
    return 0;
}

static const struct {
    const char            *name;
    xrootd_ssi_process_fn  fn;
} services[] = {
    { "echo",   svc_echo },
    { "meta",   svc_meta },
    { "stream", svc_stream },
    { "err",    svc_err },
};

xrootd_ssi_process_fn
xrootd_ssi_service_lookup(const char *name)
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
