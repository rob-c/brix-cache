#ifndef BRIX_OCI_LAYOUT_H
#define BRIX_OCI_LAYOUT_H
#include <stddef.h>

#include "oci/reg_client.h"    /* the shared BRIX_OCI_REG_E* result codes */

/* WHAT: the OCI image-layout store on disk — `oci-layout` + `index.json` +
 *       `blobs/<alg>/<hex>` (phase-104 D5.3).
 * WHY:  the spec's interchange directory is readable/writable by skopeo and
 *       podman (`oci:` transport), which makes our local store itself
 *       oracle-testable; pull lands here, push reads from here.
 * HOW:  every blob READ is verified against its path digest (the layout's
 *       contract — the path claims the content); every write is
 *       temp + rename inside the store, so a torn run never leaves a
 *       half-blob under its final name. Result codes are the reg_client
 *       ones — one table for the CLI to map onto exit codes. */

typedef struct {
    char dir[1024];
} brix_oci_layout_t;

/* Open (create=1: initialize an empty layout, mkdir -p style). Refuses a
 * directory whose oci-layout file exists but is not version 1.x. */
int brix_oci_layout_open(brix_oci_layout_t *l, const char *dir, int create,
                         char *err, size_t errlen);

/* Stage a new blob: creates + opens a temp file inside the store and
 * returns its fd (>= 0), with the temp path in tmppath for the commit /
 * unlink. Negative result code on failure. */
int brix_oci_layout_stage(brix_oci_layout_t *l, char *tmppath, size_t plen,
                          char *err, size_t errlen);

/* Commit a staged temp under its digest name. The CALLER vouches the bytes
 * match `digest` (the registry fetch already hash-verified them) — this is
 * the fsync + rename step only. Consumes tmppath on success. */
int brix_oci_layout_commit(brix_oci_layout_t *l, const char *tmppath,
                           const char *digest, char *err, size_t errlen);

/* Store [body, body+len) as a blob, computing its digest into
 * digest_out[dlen] ("<alg>:<hex>") — the manifest/config write path. */
int brix_oci_layout_blob_put_mem(brix_oci_layout_t *l, const void *body,
                                 size_t len, char *digest_out, size_t dlen,
                                 char *err, size_t errlen);

/* Load a whole blob (≤ cap bytes) with digest verification; *out is
 * malloc'd + NUL-terminated. EVERIFY names the digest on mismatch. */
int brix_oci_layout_blob_load(brix_oci_layout_t *l, const char *digest,
                              size_t cap, char **out, size_t *outlen,
                              char *err, size_t errlen);

/* Hash a stored blob against its path digest without loading it (the
 * pre-push gate for large layers) and report its size. */
int brix_oci_layout_blob_verify(brix_oci_layout_t *l, const char *digest,
                                long long *size, char *err, size_t errlen);

/* Open a stored blob for reading (pread-able fd >= 0, or a negative result
 * code). Gate large reads with brix_oci_layout_blob_verify first. */
int brix_oci_layout_blob_open(brix_oci_layout_t *l, const char *digest,
                              char *err, size_t errlen);

/* Bind `refname` (a tag; NULL = untagged entry) to a manifest in
 * index.json — replaces any existing entry with the same ref name.
 * Atomic (temp + rename). */
int brix_oci_layout_index_set(brix_oci_layout_t *l, const char *refname,
                              const char *digest, const char *mt,
                              size_t size, char *err, size_t errlen);

/* Look up a manifest by ref name (NULL = the first entry). */
int brix_oci_layout_index_get(brix_oci_layout_t *l, const char *refname,
                              char *digest, size_t dlen, char *mt,
                              size_t mtlen, char *err, size_t errlen);

/* List index entries, one "refname digest mediatype" line each (refname
 * "-" when untagged); *out malloc'd, may be "". */
int brix_oci_layout_ls(brix_oci_layout_t *l, char **out, char *err,
                       size_t errlen);

#endif /* BRIX_OCI_LAYOUT_H */
