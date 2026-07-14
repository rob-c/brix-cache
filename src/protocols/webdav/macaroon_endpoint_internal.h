#ifndef BRIX_WEBDAV_MACAROON_ENDPOINT_INTERNAL_H
#define BRIX_WEBDAV_MACAROON_ENDPOINT_INTERNAL_H

/*
 * macaroon_endpoint_internal.h — shared internals of the WLCG macaroon-issuance
 * endpoint, split across macaroon_endpoint.c (common front-gate/response
 * helpers), macaroon_endpoint_oauth2.c (POST /.oauth2/token) and
 * macaroon_endpoint_request.c (dCache macaroon-request).
 *
 * Declares only the symbols DEFINED in macaroon_endpoint.c that are REFERENCED
 * from the sibling handler translation units.  Single-file helpers stay static
 * in their own .c.  Requires "webdav.h" (for ngx_http_request_t,
 * ngx_http_brix_webdav_loc_conf_t and the ngx integer/char types) to be
 * included first — every macaroon_endpoint*.c does so before this header.
 */

/* Canned JSON bodies shared by both issuance endpoints */
#define J_NOT_CONFIGURED   "{\"error\":\"not_configured\"}"
#define J_UNAUTHORIZED     "{\"error\":\"unauthorized\"}"
#define J_INVALID_REQUEST  "{\"error\":\"invalid_request\"}"
#define J_UNSUPPORTED_GT   "{\"error\":\"unsupported_grant_type\"}"
#define J_INVALID_SCOPE    "{\"error\":\"invalid_scope\"}"
#define J_SERVER_ERROR     "{\"error\":\"server_error\"}"

/* mac_respond — emit a JSON body and finalize request metrics. */
void mac_respond(ngx_http_request_t *r, ngx_int_t status,
                 const char *json, size_t json_len);

/* mac_gate_and_read_body — shared front gate: secret configured + caller
 * authenticated + body read.  Sends the rejection itself; NGX_OK to proceed. */
ngx_int_t mac_gate_and_read_body(ngx_http_request_t *r,
                                 ngx_http_brix_webdav_loc_conf_t *conf,
                                 size_t max_body, u_char **body,
                                 size_t *body_len);

/* mac_authorize — bearer-token authority bound.  Sends the 403 itself; NGX_OK
 * only when issuance is authorized. */
ngx_int_t mac_authorize(ngx_http_request_t *r, const char *activities,
                        const char *path);

/* mac_make_identifier — build "v=1;t=<unix>;n=<16-hex-random>". */
void mac_make_identifier(ngx_http_request_t *r, char *identifier, size_t idsz);

/* mac_build_location — pin macaroon location to issuer/config/Host. */
void mac_build_location(ngx_http_request_t *r,
                        ngx_http_brix_webdav_loc_conf_t *conf,
                        ngx_uint_t allow_conf_location,
                        char *location, size_t locsz);

#endif /* BRIX_WEBDAV_MACAROON_ENDPOINT_INTERNAL_H */
