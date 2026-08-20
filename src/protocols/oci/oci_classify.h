/* oci_classify.h — the OCI Distribution `/v2/` route classifier (phase-104 D0.2).
 *
 * WHAT: turn one decoded request URI into a typed route — which endpoint of the
 *       §0.7.1 matrix it names, and the validated `<name>` / `<reference>` /
 *       `<digest>` / `<session>` spans inside it.
 * WHY:  every downstream decision (method gate, cache key, store path) keys off
 *       the route, and each of those turns wire bytes into path components. One
 *       validating classifier means the grammar is enforced exactly once, at the
 *       edge, and nothing further down has to sanitize: a name/digest that
 *       classifies cannot traverse, by construction (§0.7.2).
 * HOW:  pure C over the shared grammars (shared/oci/{name,digest}.h) — no nginx
 *       types, no allocation, spans point into the caller's URI. That is what
 *       lets the protocol-fuzz lane link this kernel standalone beside the other
 *       parser kernels, the way src/net/guard/ does.
 */
#ifndef BRIX_PROTOCOLS_OCI_CLASSIFY_H
#define BRIX_PROTOCOLS_OCI_CLASSIFY_H

#include <stddef.h>

#include "oci/digest.h"          /* BRIX_OCI_SHA256_HEXLEN */

/* Upload-session identifiers are ours on the registry surface (staged-file
 * basenames) and opaque on anyone else's; the cap bounds them before they
 * become a path component. */
#define BRIX_OCI_SESSION_MAX 128

typedef enum {
    BRIX_OCI_REQ_API_ROOT,        /* /v2/                          */
    BRIX_OCI_REQ_MANIFEST,        /* /v2/<name>/manifests/<ref>    */
    BRIX_OCI_REQ_BLOB,            /* /v2/<name>/blobs/<digest>     */
    BRIX_OCI_REQ_UPLOAD_START,    /* /v2/<name>/blobs/uploads/     */
    BRIX_OCI_REQ_UPLOAD_SESSION,  /* /v2/<name>/blobs/uploads/<id> */
    BRIX_OCI_REQ_TAGS_LIST,       /* /v2/<name>/tags/list          */
    BRIX_OCI_REQ_REFERRERS,       /* /v2/<name>/referrers/<digest> */
    BRIX_OCI_REQ_BAD              /* carries the error code to emit */
} brix_oci_class_t;

/* The spec error codes (§0.7.4). The HTTP status each maps to is the emitter's
 * business (oci_errors.c), not the classifier's — the same code answers 400 or
 * 404 depending on which surface raised it. */
typedef enum {
    BRIX_OCI_ERR_NONE = 0,
    BRIX_OCI_ERR_NAME_INVALID,
    BRIX_OCI_ERR_NAME_UNKNOWN,
    BRIX_OCI_ERR_MANIFEST_UNKNOWN,
    BRIX_OCI_ERR_MANIFEST_INVALID,
    BRIX_OCI_ERR_MANIFEST_BLOB_UNKNOWN,
    BRIX_OCI_ERR_BLOB_UNKNOWN,
    BRIX_OCI_ERR_BLOB_UPLOAD_UNKNOWN,
    BRIX_OCI_ERR_BLOB_UPLOAD_INVALID,
    BRIX_OCI_ERR_DIGEST_INVALID,
    BRIX_OCI_ERR_SIZE_INVALID,
    BRIX_OCI_ERR_UNAUTHORIZED,
    BRIX_OCI_ERR_DENIED,
    BRIX_OCI_ERR_UNSUPPORTED,
    BRIX_OCI_ERR_TOOMANYREQUESTS,
    BRIX_OCI_ERR_UNAVAILABLE      /* upstream/backend could not answer (J.4) */
} brix_oci_err_t;

typedef struct {
    brix_oci_class_t cls;
    brix_oci_err_t   err;                     /* set iff cls == _BAD          */
    const char      *name;    size_t name_len; /* validated repository name   */
    int              name_components;          /* 1 ⇒ DockerHub bare name     */
    const char      *ref;     size_t ref_len;  /* manifests/<ref> verbatim    */
    int              ref_is_digest;            /* manifests/<ref> only        */
    const char      *session; size_t session_len;
    brix_oci_digest_t digest;                  /* blob/ref/subject digest —
                                                  the PARSED value, algorithm
                                                  included: the store layout
                                                  is keyed by algorithm, so a
                                                  bare hex span cannot name a
                                                  path on its own */
} brix_oci_req_t;

/* Classify `uri` (DECODED, NUL-termination not required). Returns 0 with
 * out->cls set to a route, or -1 with out->cls == BRIX_OCI_REQ_BAD and
 * out->err naming what the caller should emit. `uri` must outlive `*out`:
 * every span points into it. */
int brix_oci_classify(const char *uri, size_t len, brix_oci_req_t *out);

/* Stable lowercase token for the route — metric label and log field. */
const char *brix_oci_class_str(brix_oci_class_t cls);

#endif /* BRIX_PROTOCOLS_OCI_CLASSIFY_H */
