/*
 * rpm.h — the RPM/dnf pull-through mirror plane: config, request ctx, seams.
 *
 * WHAT: the location config and per-request context for `src/protocols/rpm/`,
 *       plus the handler entry point and the prototypes its merge / gate /
 *       serve files share.
 * WHY:  an RPM mirror is a cache whose entire policy is one distinction the
 *       file NAMES already encode: `repodata/repomd.xml` is the mutable
 *       freshness root, everything createrepo writes beside it is
 *       `<checksum>-<name>` — immutable AND self-verifying — and packages are
 *       immutable in practice. Expressed as an nginx `proxy_cache` recipe
 *       (the phase-104 D11 deployment note) that distinction can only be
 *       approximated by a TTL, and the checksum in the file name cannot be
 *       checked at all. Expressed here it is exact: the classifier decides the
 *       freshness window, and the cache tier's third self-addressing verify
 *       mode (rpm-repodata) hashes every metadata fill against the digest its
 *       own name carries before the bytes are ever served.
 * HOW:  the shared preamble is the FIRST member of the loc conf (the tree-wide
 *       convention brix_http_common_adopt / ngx_http_brix_shared_merge rely
 *       on), the surface flag defaults off, and nothing here allocates: a
 *       location without brix_rpm_mirror never grows a handler, so a
 *       non-RPM deployment is structurally untouched.
 */
#ifndef BRIX_PROTOCOLS_RPM_H
#define BRIX_PROTOCOLS_RPM_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "rpm_classify.h"
#include "core/config/shared_conf.h"
#include "fs/backend/sd.h"                /* brix_sd_instance_t             */
#include "fs/vfs/vfs.h"                   /* brix_vfs_file_t                */
#include "observability/metrics/metrics_rpm.h"

/* The cache key IS the request URI (a repository path), so the key cap is the
 * classifier's path cap — one number, checked in one place. */
#define BRIX_RPM_KEY_MAX  BRIX_RPM_PATH_MAX

/* Default brix_rpm_metadata_ttl. dnf's own `metadata_expire` defaults to 48
 * hours for a stable repo, but a MIRROR must not add a second staleness
 * window on top of the client's: a minute is long enough that one `dnf
 * install` pulls one repomd.xml, short enough that a client asking for fresh
 * metadata gets metadata this mirror fetched within the minute. */
#define BRIX_RPM_METADATA_TTL_DEFAULT  60

typedef struct {
    ngx_http_brix_shared_conf_t   common;   /* MUST stay first               */

    ngx_flag_t   mirror;         /* brix_rpm_mirror present                  */
    ngx_str_t    mirror_url;     /* its argument, unparsed until merge        */
    ngx_flag_t   insecure;       /* brix_rpm_mirror_insecure                 */
    ngx_flag_t   prefetch;       /* brix_rpm_prefetch                        */
    time_t       metadata_ttl;   /* brix_rpm_metadata_ttl                    */
} ngx_http_brix_rpm_loc_conf_t;

typedef struct {
    brix_rpm_req_t             req;                    /* classifier output  */
    char                       key[BRIX_RPM_KEY_MAX];  /* == the request URI */
    size_t                     key_len;
    brix_rpm_outcome_metric_e  disp;                   /* metric outcome +   *
                                                        * $brix_cache_status */
    unsigned                   classified:1;
    unsigned                   counted:1;              /* observer ran       */
} ngx_http_brix_rpm_ctx_t;

extern ngx_module_t ngx_http_brix_rpm_module;

ngx_int_t ngx_http_brix_rpm_handler(ngx_http_request_t *r);

/* ---- rpm_merge.c --------------------------------------------------------- */

char *ngx_http_brix_rpm_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

/* ---- rpm_gate.c ---------------------------------------------------------- */

/* Method policing + classification + the cache key. NGX_DECLINED = a routable
 * object; anything else is a terminal HTTP status the handler must return. */
ngx_int_t brix_rpm_gate(ngx_http_request_t *r, ngx_http_brix_rpm_ctx_t *ctx);

/* ---- rpm_prefetch.c ------------------------------------------------------ *
 * Warm the metadata a dnf client asks for next (primary + filelists) after a
 * freshly pulled repomd.xml named them — phase-104 D15.10, Appendix X finding
 * X-3. Advisory in every direction: it acts only on a REPOMD-class FILL, it
 * reads the index through the handle the serve is about to use, it re-checks
 * every href with the request grammar, and it never touches the response. */
void brix_rpm_prefetch_repomd(ngx_http_request_t *r,
    ngx_http_brix_rpm_loc_conf_t *lcf, ngx_http_brix_rpm_ctx_t *ctx,
    brix_vfs_file_t *fh, off_t size, brix_sd_instance_t *sd);

/* ---- rpm_mirror.c -------------------------------------------------------- */

/* Pool-cleanup observer: charges the one metric row this request owes. */
void brix_rpm_finalize_observe(void *data);

#endif /* BRIX_PROTOCOLS_RPM_H */
