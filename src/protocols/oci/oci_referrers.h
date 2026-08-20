/*
 * oci_referrers.h — the referrers graph internal to the registry surface
 *                   (D15.1, distribution-spec §"Listing Referrers").
 *
 * WHAT: index a pushed manifest under the subject it declares, forget that
 *       edge when the manifest is deleted, and answer
 *       GET /v2/<name>/referrers/<digest> from what the index holds.
 * WHY:  the referrers API is how a signature, an SBOM or a provenance
 *       attestation becomes DISCOVERABLE: the artifact is an ordinary
 *       manifest carrying `subject`, and without the reverse index a client
 *       holding an image digest has no way to ask "what did anyone say about
 *       this?" other than enumerating the whole repository. The index has to
 *       be written by the push that creates the edge, because that is the
 *       only moment the registry sees the referrer and the subject together.
 * HOW:  one empty-directory-per-subject fanout under the repository, holding
 *       one small JSON descriptor per referrer, plus a `.subject` back-
 *       pointer beside the manifest so a DELETE knows which edge to cut
 *       without scanning every subject in the repo. The descriptors are
 *       written once, at push time, so the read path is a bounded directory
 *       walk and a concatenation rather than a re-parse of every manifest.
 */
#ifndef BRIX_PROTOCOLS_OCI_REFERRERS_H
#define BRIX_PROTOCOLS_OCI_REFERRERS_H

#include "oci_registry.h"

#include <jansson.h>

/* One subject may collect this many referrers before the listing truncates.
 * A subject with hundreds of signatures is already pathological; the cap is
 * here so that a directory somebody filled cannot turn one GET into an
 * unbounded allocation. */
#define BRIX_OCI_REFERRERS_MAX      512

/* A stored descriptor is mediaType + digest + size + artifactType + a few
 * annotations. 4 KiB is roomy for that and small enough that 512 of them
 * still bound the assembled index well under the response cap. */
#define BRIX_OCI_REFERRER_DESC_MAX  4096

/* Is this document's `subject`, if it declares one, a descriptor this
 * registry can index? 0 = yes, or the manifest declares none; -1 with `*why`
 * set to the refusal detail. A manifest whose subject we cannot read must be
 * REFUSED rather than stored: accepting it would publish an artifact whose
 * edge is invisible, which is indistinguishable to the pusher from a
 * signature that was recorded. */
int brix_oci_referrers_subject_ok(json_t *doc, const char **why);

/* Record the edge `d` --subject--> doc["subject"], if the document declares
 * one. `doc` is the already-parsed manifest, `size` its stored byte count and
 * `ctype` its media type; both ride into the descriptor because the listing
 * must answer with them without opening the referrer.
 *
 * `subj` receives the subject's digest string ("<alg>:<hex>") for the
 * OCI-Subject response header, or "" when the manifest declares no subject.
 * NGX_OK either way; NGX_ERROR only when an edge was declared and could not
 * be recorded — a push whose discoverability silently failed is worse than a
 * push that failed. */
ngx_int_t brix_oci_referrers_index(const brix_oci_store_t *st,
    const brix_oci_req_t *req, json_t *doc, const brix_oci_digest_t *d,
    const char *ctype, off_t size, char *subj, size_t subjsz, ngx_log_t *log);

/* Cut the edge a manifest DELETE invalidates: the descriptor under its
 * subject, and the back-pointer beside it. Best-effort by construction — the
 * manifest is going away regardless, and a stale descriptor is a listing
 * entry that 404s, not a corrupt store. */
void brix_oci_referrers_forget(const brix_oci_store_t *st, const char *name,
    size_t name_len, const brix_oci_digest_t *d, ngx_log_t *log);

/* GET/HEAD /v2/<name>/referrers/<digest> — an image index of every manifest
 * in this repository that named `digest` as its subject. An unknown subject
 * is 200 with an empty list, never 404: the client is asking a question about
 * a graph, and "nothing refers to it" is a complete answer. */
ngx_int_t brix_oci_referrers_get(ngx_http_request_t *r,
    ngx_http_brix_oci_ctx_t *ctx, brix_oci_store_t *st);

#endif /* BRIX_PROTOCOLS_OCI_REFERRERS_H */
