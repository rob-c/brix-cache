/*
 * s3_post_internal.h - private split contract for post_object.c and its Phase-38 siblings.
 * Not a public API: include only from src/s3/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_S3_POST_INTERNAL_H
#define XROOTD_S3_POST_INTERNAL_H

#include "s3.h"
#include "../fs/backend/sd.h"   
#include "../impersonate/lifecycle.h"
#include "s3_auth_internal.h"
#include "../compat/crypto.h"
#include "../compat/hex.h"
#include "../compat/http_body.h"
#include "../compat/http_headers.h"
#include "../fs/vfs.h"
#include "../path/path.h"
#include <jansson.h>
#include <openssl/crypto.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../compat/alloc_guard.h"
#define S3_POST_MAX_BODY    (128 * 1024 * 1024)
#define S3_POST_MAX_FIELD   4096
#define S3_POST_MAX_FIELDS  64
#define S3_POST_MAX_POLICY  65536
typedef struct {
    char name[128];
    char value[S3_POST_MAX_FIELD];
} s3_post_field_t;

typedef struct {
    s3_post_field_t fields[S3_POST_MAX_FIELDS];
    ngx_uint_t      nfields;

    char            key[S3_MAX_KEY];
    char            filename[256];
    char            content_type[256];
    char            policy[S3_POST_MAX_POLICY];
    char            algorithm[64];
    char            credential[256];
    char            amz_date[32];
    char            signature[129];
    char            success_status[8];
    char            success_redirect[2048];

    u_char         *file_data;
    size_t          file_len;
    ngx_flag_t      have_file;
} s3_post_form_t;


/* post_object.c */
ngx_int_t s3_post_error(ngx_http_request_t *r, ngx_uint_t status, const char *code, const char *message);
ngx_int_t s3_post_copy_text(const u_char *data, size_t len, char *dst, size_t dstsz);

/* post_form.c */
const char * s3_post_field_value(const s3_post_form_t *form, const char *name);
ngx_int_t s3_post_store_field(s3_post_form_t *form, const char *name, const u_char *data, size_t len);
ngx_int_t s3_post_boundary(ngx_http_request_t *r, char *boundary, size_t boundary_sz);

/* post_object.c */
u_char * s3_memmem(u_char *hay, size_t hay_len, const u_char *needle, size_t needle_len);

/* post_form.c */
ngx_int_t s3_post_extract_param(const char *line, const char *name, char *out, size_t outsz);

/* post_object.c */
void s3_post_basename(char *s);

/* post_form.c */
ngx_int_t s3_post_expand_filename(ngx_http_request_t *r, s3_post_form_t *form);
ngx_int_t s3_post_parse_form(ngx_http_request_t *r, u_char *body, size_t body_len, const char *boundary, s3_post_form_t *form);

/* post_policy.c */
int64_t s3_post_days_from_civil(int y, unsigned m, unsigned d);
ngx_int_t s3_post_parse_iso8601(const char *s, time_t *out);
ngx_int_t s3_post_check_field_eq(const char *actual, const char *expected);
ngx_int_t s3_post_policy_condition(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form, json_t *cond);
ngx_int_t s3_post_validate_policy_json(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form, u_char *policy_json, size_t policy_len);
ngx_int_t s3_post_parse_credential(const char *credential, char *date, size_t date_sz, char *region, size_t region_sz, const char **akid);
ngx_int_t s3_post_verify_policy(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form);

/* post_object.c */
ngx_int_t s3_post_write_object(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form, const char *fs_path, char *etag, size_t etag_sz);

/* post_response.c */
ngx_int_t s3_post_send_empty(ngx_http_request_t *r, ngx_uint_t status);
ngx_int_t s3_post_send_created(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form, const char *etag);
ngx_int_t s3_post_send_success(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form, const char *etag);

/* post_object.c */
void s3_post_object_body_handler_inner(ngx_http_request_t *r);

#endif /* XROOTD_S3_POST_INTERNAL_H */
