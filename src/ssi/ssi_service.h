#ifndef XROOTD_SSI_SERVICE_H
#define XROOTD_SSI_SERVICE_H

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

typedef struct xrootd_ssi_responder_s xrootd_ssi_responder_t;

/*
 * Responder ops a service calls to deliver its result.
 *   set_metadata : optional metadata blob (delivered before/with the response).
 *   set_response : response data; last=1 marks the final chunk (last=0 streams).
 *   alert        : out-of-band progress alert.
 *   error        : terminal error with an SSI error code + text.
 * All borrow the passed buffers for the duration of the call.
 */
struct xrootd_ssi_responder_s {
    void (*set_metadata)(xrootd_ssi_responder_t *r,
                         const unsigned char *md, size_t len);
    void (*set_response)(xrootd_ssi_responder_t *r,
                         const unsigned char *buf, size_t len, int last);
    void (*alert)(xrootd_ssi_responder_t *r,
                  const unsigned char *buf, size_t len);
    void (*error)(xrootd_ssi_responder_t *r, int code, const char *text);
    void *state;   /* responder implementation private data */
};

/*
 * A service handler: consume the request bytes and drive the responder. Returns
 * 0 if it accepted the request (response delivered now or later via the
 * responder), -1 on an immediate reject.
 */
typedef int (*xrootd_ssi_process_fn)(const unsigned char *req, size_t req_len,
                                     xrootd_ssi_responder_t *r);

/* Resolve a service name to its handler, or NULL if unknown. */
xrootd_ssi_process_fn xrootd_ssi_service_lookup(const char *name);

#endif /* XROOTD_SSI_SERVICE_H */
