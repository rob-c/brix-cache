/*
 * reg_internal.h - private split contract for the oci registry client
 * (reg_client.c / reg_verbs.c / reg_blob.c). Not a public API: include
 * only from client/lib/oci/.
 */
#ifndef BRIX_OCI_REG_INTERNAL_H
#define BRIX_OCI_REG_INTERNAL_H

#include "oci/reg_client.h"

#include "brix.h"
#include "brix_net.h"
#include "_brix_net_ext.h"

/* reg_client.c */
int  regc_fail(char *err, size_t errlen, int code, const char *fmt, ...);
/* DockerHub library/ normalization keyed off the handle's host. 0 / -1. */
int  regc_eff_name(const brix_oci_reg_t *r, const char *name, char *out, size_t outlen);
/* Split http(s)://host[:port]/path[?query] (or a relative /path against def_*). 0 / -1. */
int  regc_url_split(const char *url, const char *def_host, int def_port, int def_tls, char *host, size_t hostlen, int *port, int *tls, char *path, size_t pathlen);
/* Copy "Authorization: …\r\n" for the data plane (cached scope token, else static bearer, else ""). */
void regc_auth_header(brix_oci_reg_t *r, const char *scope, char *out, size_t outlen);
/* Run the Bearer dance for the given WWW-Authenticate value; cache under cache_scope. Result code. */
int  regc_token_dance(brix_oci_reg_t *r, const char *challenge, const char *cache_scope, char *err, size_t errlen);
/* One authed request: send with the scope's token, dance once on 401, retry. 0 = response in *resp (any status); else result code. Caller frees *resp. */
int  regc_call(brix_oci_reg_t *r, const char *method, const char *path, const char *scope, const char *extra_headers, const void *body, size_t blen, brix_http_resp *resp, char *err, size_t errlen);
/* Map a non-2xx registry status onto a result code + message. */
int  regc_status_fail(int status, const char *what, char *err, size_t errlen);
/* As above, but appends the OCI error envelope's errors[].message when the
 * response body carries one (use where the resp body was parsed). */
int  regc_status_fail_resp(const brix_http_resp *resp, const char *what, char *err, size_t errlen);

/* reg_verbs.c — grow-and-append for malloc'd accumulation buffers. 0 / -1 (OOM). */
int  regc_buf_append(char **buf, size_t *len, size_t *cap, const char *s, size_t n);

#endif /* BRIX_OCI_REG_INTERNAL_H */
