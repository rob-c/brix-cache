/*
 * search_internal.h - private split contract for search.c and its siblings.
 * Not a public API: include only from src/protocols/webdav/.
 * See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_WEBDAV_SEARCH_INTERNAL_H
#define BRIX_WEBDAV_SEARCH_INTERNAL_H

#include "webdav.h"

#define WEBDAV_SEARCH_BODY_MAX       65536u
#define WEBDAV_SEARCH_MAX_ENTRIES    10000u

typedef struct {
    int   depth;
    char  literal[256];
} webdav_search_query_t;

/* search_parse.c */
ngx_int_t webdav_search_parse(ngx_http_request_t *r, webdav_search_query_t *q);

#endif /* BRIX_WEBDAV_SEARCH_INTERNAL_H */
