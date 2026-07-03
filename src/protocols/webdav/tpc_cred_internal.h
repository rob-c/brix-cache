#ifndef BRIX_WEBDAV_TPC_CRED_INTERNAL_H
#define BRIX_WEBDAV_TPC_CRED_INTERNAL_H

#include "tpc_cred.h"
#include "webdav.h"

/* Maximum token length (RFC 6750: opaque tokens rarely exceed 1 KiB). */
#define TPC_CRED_MAX_TOKEN_LEN  4096

ngx_int_t tpc_cred_parse_token_response(ngx_http_request_t *r,
    const char *json, ngx_str_t *token_out);

#endif /* BRIX_WEBDAV_TPC_CRED_INTERNAL_H */
