/*
 * propfind_internal.h - private split contract for propfind.c and its Phase-38 siblings.
 * Not a public API: include only from src/webdav/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_PROPFIND_INTERNAL_H
#define BRIX_PROPFIND_INTERNAL_H

#include "webdav.h"
#include "fs/vfs/vfs.h"
#include "fs/path/path.h"
#include "auth/impersonate/lifecycle.h"
#include "core/http/etag.h"
#include "core/compat/fs_walk.h"
#include "core/compat/fs_usage.h"
#include "core/http/http_body.h"
#include "core/http/http_xml.h"
#include "core/compat/time.h"
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
typedef enum {
    PROPFIND_ALLPROP  = 0,   
    PROPFIND_PROPNAME = 1,   
    PROPFIND_PROP     = 2,   
} propfind_type_t;

#define PF_RESOURCETYPE        (1u <<  0)
#define PF_CONTENTLENGTH       (1u <<  1)
#define PF_LASTMODIFIED        (1u <<  2)
#define PF_ETAG                (1u <<  3)
#define PF_CREATIONDATE        (1u <<  4)
#define PF_DISPLAYNAME         (1u <<  5)
#define PF_QUOTA_AVAILABLE     (1u <<  6)
#define PF_QUOTA_USED          (1u <<  7)
#define PF_SUPPORTED_REPORT    (1u <<  8)
#define PF_SUPPORTEDLOCK       (1u <<  9)
#define PF_LOCKDISCOVERY       (1u << 10)
#define PF_CONTENTTYPE         (1u << 11)
#define PF_OWNER               (1u << 12)
#define PF_GROUP               (1u << 13)
#define PF_CURRENT_PRIVILEGE   (1u << 14)
#define PF_SUPPORTED_PRIVILEGE (1u << 15)
#define PF_ACL                 (1u << 16)
#define PF_ACL_RESTRICTIONS    (1u << 17)
#define PF_PRINCIPAL_SET       (1u << 18)
#define PF_ALL                 ((1u << 19) - 1)
#define PF_LOCALITY            (1u << 19)
#define PF_UNKNOWN_MAX     16
#define PF_UNKNOWN_XML_MAX 288   
#define PROPFIND_BODY_MAX  65536u
typedef struct {
    char             ns[128];
    char             local[128];
    char             xml[PF_UNKNOWN_XML_MAX];
} propfind_unknown_t;

typedef struct {
    propfind_type_t  type;
    unsigned         prop_mask;                        
    ngx_uint_t       unknown_count;
    propfind_unknown_t unknown[PF_UNKNOWN_MAX];
} propfind_req_t;

#define PROPFIND_INFINITY_MAX_ENTRIES  10000


/* propfind.c */
unsigned propfind_name_to_bit(const char *name);
const char * propfind_assemble_body(ngx_http_request_t *r, size_t *len);
void propfind_parse_request(ngx_http_request_t *r, propfind_req_t *req);

/* propfind_props.c */
ngx_int_t propfind_append_acl_properties(ngx_http_request_t *r, ngx_chain_t **head, ngx_chain_t **tail, unsigned mask);
ngx_int_t propfind_entry(ngx_http_request_t *r, ngx_chain_t **head, ngx_chain_t **tail, const char *href, const char *path, struct stat *sb, const propfind_req_t *req);

/* propfind.c */
int propfind_parse_depth(ngx_http_request_t *r);

/* propfind_walk.c */
ngx_int_t propfind_walk(ngx_http_request_t *r, ngx_chain_t **head, ngx_chain_t **tail, const char *dir_path, const char *base_href, ngx_uint_t *entry_count, ngx_uint_t max_entries, const propfind_req_t *req, ngx_flag_t recurse);
ngx_int_t propfind_do(ngx_http_request_t *r);

/* propfind.c */
void propfind_body_handler(ngx_http_request_t *r);

#endif /* BRIX_PROPFIND_INTERNAL_H */
