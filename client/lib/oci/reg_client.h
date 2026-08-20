#ifndef BRIX_OCI_REG_CLIENT_H
#define BRIX_OCI_REG_CLIENT_H
#include <stddef.h>

#include "oci/ref.h"

/* WHAT: registry transport for the brixoci/brixcvmfs tools — manifest
 *       resolve (index → platform), blob fetch/push, manifest put, tags,
 *       delete, with the WWW-Authenticate Bearer token dance built in
 *       (phase-104 D5.1).
 * WHY:  every distribution verb is these six wire exchanges; one client
 *       means the ingest pipeline and the CLI share auth, redirect and
 *       digest-verify policy instead of drifting on them.
 * HOW:  over brix_http_req / the http_internal seams — zero new socket
 *       code. Every fetched byte-stream is digest-verified before success
 *       is reported. The realm allowlist mirrors the server's D1 rule:
 *       https-only (unless plain_http), same-host or the registry's
 *       well-known auth host; Basic credentials go ONLY to the allow-listed
 *       realm, never the data plane. */

/* Result codes — the CLI maps these onto the brixcvmfs exit-code table
 * (0 ok · 3 auth · 4 not-found · 5 verify · 6 transport). */
#define BRIX_OCI_REG_OK          0
#define BRIX_OCI_REG_ETRANSPORT (-1)   /* connect/timeout/TLS/proto fault */
#define BRIX_OCI_REG_EAUTH      (-2)   /* dance failed / 401 after dance */
#define BRIX_OCI_REG_ENOTFOUND  (-3)   /* 404 from the registry */
#define BRIX_OCI_REG_EVERIFY    (-4)   /* digest mismatch on fetched bytes */
#define BRIX_OCI_REG_EPROTO     (-5)   /* unexpected status / bad JSON */

/* One registry endpoint + auth material. Fill via brix_oci_reg_from_ref,
 * then override auth/TLS knobs before the first call. The token cache is
 * in-process, per (this host, scope) — a CLI run rarely outlives a token,
 * and a 401 on a cached token redoes the dance once. */
typedef struct {
    char host[256];
    int  port;               /* resolved (explicit or scheme default) */
    int  plain_http;         /* 1: cleartext http (lab fixtures only) */
    int  verify;             /* TLS peer+host verification (default 1) */
    const char *ca_dir;      /* NULL: system default */
    const char *client_cert; /* mutual-TLS PEM path, NULL for none */
    int  timeout_ms;
    char bearer[4096];       /* static token (--token-file); empty = none */
    char user[128];          /* Basic → allow-listed realm ONLY */
    char pass[256];
    struct {
        char scope[512];
        char token[4096];
        int  live;
    } tok[4];
    unsigned tok_next;
} brix_oci_reg_t;

/* A resolved manifest: media type, content digest of the body, the body. */
typedef struct {
    char   mediatype[128];
    char   digest[BRIX_OCI_DIGEST_STRLEN];   /* "<alg>:<hex>" of the body */
    char  *body;             /* malloc'd, NUL-terminated */
    size_t body_len;
} brix_oci_desc_t;

void brix_oci_desc_free(brix_oci_desc_t *d);

/* Turn a parsed ref into transport coordinates + the effective repository
 * name (DockerHub: docker.io → registry-1.docker.io, single-component name
 * → library/<name>; a ref with no host defaults to DockerHub). insecure=1
 * sets plain_http + verify off — the lab-fixture switch. 0 / result code. */
int brix_oci_reg_from_ref(brix_oci_reg_t *r, const brix_oci_ref_t *ref,
                          int insecure, char *name, size_t namelen,
                          char *err, size_t errlen);

/* GET the manifest for ref (digest wins over tag). accept NULL means the
 * §0.7.3 joined manifest Accept line. On OK the desc owns a malloc'd body;
 * when the ref pinned a digest the body is verified against it (EVERIFY on
 * mismatch, body freed). */
int brix_oci_reg_manifest(brix_oci_reg_t *r, const brix_oci_ref_t *ref,
                          const char *accept, brix_oci_desc_t *out,
                          char *err, size_t errlen);

/* Manifest resolve with index handling: fetch; if the result is an image
 * index, select `platform` ("os/arch[/variant]", NULL = this host's
 * linux/amd64|arm64) and re-fetch the selected manifest by digest. No
 * matching platform → ENOTFOUND with the available platforms in err. */
int brix_oci_reg_resolve(brix_oci_reg_t *r, const brix_oci_ref_t *ref,
                         const char *platform, brix_oci_desc_t *out,
                         char *err, size_t errlen);

/* GET a blob to out_fd — hash-on-stream against `digest` ("<alg>:<hex>",
 * hashed under the algorithm the digest itself names);
 * mismatch truncates out_fd and returns EVERIFY (the caller owns the temp
 * path and unlinks it on ANY failure). Follows ≤4 redirects (the CDN hop),
 * stripping Authorization on every redirect leg. out_fd must be a fresh
 * seekable temp file. */
int brix_oci_reg_blob_fetch(brix_oci_reg_t *r, const char *name,
                            const char *digest, int out_fd,
                            char *err, size_t errlen);

/* Push a blob (D4 session client): HEAD dedupe probe, then
 * POST /blobs/uploads/ + single streamed PUT ?digest=. in_fd must be
 * pread-able; len is the exact byte count. */
int brix_oci_reg_blob_push(brix_oci_reg_t *r, const char *name,
                           const char *digest, int in_fd, size_t len,
                           char *err, size_t errlen);

/* PUT a manifest body under ref's tag (or digest when pinned). */
int brix_oci_reg_manifest_put(brix_oci_reg_t *r, const brix_oci_ref_t *ref,
                              const char *mt, const void *body, size_t len,
                              char *err, size_t errlen);

/* List tags (Link-header pagination followed). *out is a malloc'd
 * newline-joined list (may be empty ""); caller frees. */
int brix_oci_reg_tags(brix_oci_reg_t *r, const char *name, char **out,
                      char *err, size_t errlen);

/* DELETE the manifest ref points at (a tag is first resolved to its
 * digest — registries delete by digest). */
int brix_oci_reg_manifest_del(brix_oci_reg_t *r, const brix_oci_ref_t *ref,
                              char *err, size_t errlen);

#endif /* BRIX_OCI_REG_CLIENT_H */
