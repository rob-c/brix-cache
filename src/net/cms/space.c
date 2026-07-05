#include "cms_internal.h"

/* ngx_brix_cms_export_paths — select exported filesystem path for CMS registration
 * WHAT: Returns the list of filesystem paths this server exports to the CMS manager. If explicit `brix_cms_paths` directive is configured, returns that; otherwise falls back to the main `brix_root` directory. WHY: CMS manager needs to know which paths a data server can serve — clients use kYR_locate queries to find servers with specific file locations. HOW: Simple precedence check: cms_paths (explicit) > root (default). Returns ngx_str_t directly without allocation. */

ngx_str_t
ngx_brix_cms_export_paths(ngx_stream_brix_srv_conf_t *conf)
{
    if (conf->cms.paths.len > 0) {
        return conf->cms.paths;
    }

    return conf->common.root;
}

/* ngx_brix_cms_stat_space — measure filesystem space via statvfs
 * WHAT: Calls statvfs() on the configured root directory to measure total disk capacity and available free space. Returns total_gb, free_mb, and utilization percentage as uint32_t values (rounded). WHY: CMS heartbeat reports need current disk metrics to help managers decide where to route client requests — servers with more free space are preferred destinations. HOW: 1) statvfs(conf->common.root.data) → 2) Calculate total = f_blocks × f_frsize → 3) Free = f_bavail × f_frsize → 4) Used = f_blocks - f_bfree → 5) Convert to GB/MB/pct via integer division. Returns NGX_ERROR if statvfs fails or f_blocks == 0 (division by zero guard). */

ngx_int_t
ngx_brix_cms_stat_space(ngx_stream_brix_srv_conf_t *conf,
    uint32_t *total_gb, uint32_t *free_mb, uint32_t *util_pct)
{
    struct statvfs  st;
    uint64_t        total;
    uint64_t        free_bytes;
    uint64_t        used_blocks;

    if (statvfs((char *) conf->common.root.data, &st) != 0 || st.f_blocks == 0) {
        return NGX_ERROR;
    }

    total = (uint64_t) st.f_blocks * st.f_frsize;
    free_bytes = (uint64_t) st.f_bavail * st.f_frsize;
    used_blocks = st.f_blocks - st.f_bfree;

    if (total_gb != NULL) {
        *total_gb = (uint32_t) (total / (1024ULL * 1024ULL * 1024ULL));
    }

    if (free_mb != NULL) {
        *free_mb = (uint32_t) (free_bytes / (1024ULL * 1024ULL));
    }

    if (util_pct != NULL) {
        *util_pct = (uint32_t) ((used_blocks * 100) / st.f_blocks);
    }

    return NGX_OK;
}
