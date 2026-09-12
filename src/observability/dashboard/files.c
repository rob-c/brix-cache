/*
 * files.c — macOS stub for dashboard files/download handlers
 */

#include "dashboard_http.h"
#include "dashboard_json.h"
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

/* GET /xrootd/api/v1/files?path=<rel> - stub implementation */
ngx_int_t
ngx_http_brix_dashboard_files_handler(ngx_http_request_t *r)
{
    /* Stub - returns 501 Not Implemented on macOS */
    return NGX_HTTP_NOT_IMPLEMENTED;
}

/* GET /xrootd/api/v1/download?path=<rel> - stub implementation */
ngx_int_t
ngx_http_brix_dashboard_download_handler(ngx_http_request_t *r)
{
    (void)r;
    return NGX_HTTP_NOT_IMPLEMENTED;
}
