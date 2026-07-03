#ifndef BRIX_SSI_SERVICE_H
#define BRIX_SSI_SERVICE_H

/*
 * ssi_service.h — native compiled-in SSI service interface + registry.
 *
 * WHAT: a request handler produces a response through a responder callback set
 *       (Approach 1 in the design). Synchronous services call set_response inline;
 *       async/streaming services retain the responder and drive it from a
 *       thread-pool job. This replaces the C++ XrdSsiService/XrdSsiResponder ABI
 *       with a native C interface.
 * WHY:  byte-exact SSI without the plugin ABI; the registry resolves the open
 *       resource path "/<service>" to a handler.
 * HOW:  pure C so the handlers + registry are unit-testable standalone with a
 *       recording responder.
 */

#include <stddef.h>

typedef struct brix_ssi_responder_s brix_ssi_responder_t;

/*
 * Responder ops a service calls to deliver its result.
 *   set_metadata : optional metadata blob (delivered before/with the response).
 *   set_response : response data; last=1 marks the final chunk (last=0 streams).
 *   alert        : out-of-band progress alert.
 *   error        : terminal error with an SSI error code + text.
 * All borrow the passed buffers for the duration of the call.
 */
struct brix_ssi_responder_s {
    void (*set_metadata)(brix_ssi_responder_t *r,
                         const unsigned char *md, size_t len);
    void (*set_response)(brix_ssi_responder_t *r,
                         const unsigned char *buf, size_t len, int last);
    void (*alert)(brix_ssi_responder_t *r,
                  const unsigned char *buf, size_t len);
    void (*error)(brix_ssi_responder_t *r, int code, const char *text);
    /*
     * defer: a service that wants to answer later calls this. Returns 0 if the
     * deferral was accepted (submit phase — the server replies kXR_waitresp and
     * the service is re-invoked later to produce its response), or -1 if deferral
     * is unavailable (completion phase — the service must respond inline now).
     * A service that ignores defer stays fully synchronous (Phase-1 behaviour).
     */
    int (*defer)(brix_ssi_responder_t *r);
    /*
     * svc_slot: returns a pointer to a per-request void* cookie that persists from
     * the submit call to the deferred completion call, letting a stateful service
     * correlate the two phases (e.g. stash its request-queue entry). May be NULL
     * if the host does not provide per-request service state.
     */
    void **(*svc_slot)(brix_ssi_responder_t *r);
    void *state;   /* responder implementation private data */
};

/*
 * A service handler: consume the request bytes and drive the responder. Returns
 * 0 if it accepted the request (response delivered now or later via the
 * responder), -1 on an immediate reject.
 */
typedef int (*brix_ssi_process_fn)(const unsigned char *req, size_t req_len,
                                     brix_ssi_responder_t *r);

/* Resolve a service name to its handler, or NULL if unknown. */
brix_ssi_process_fn brix_ssi_service_lookup(const char *name);

/* Return the registry's static-lifetime canonical name pointer for a known
 * service (stable for the program lifetime), or NULL if unknown. Lets callers
 * store a service name without owning the buffer. */
const char *brix_ssi_service_canon_name(const char *name);

#endif /* BRIX_SSI_SERVICE_H */
