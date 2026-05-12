#include "cms_internal.h"


ngx_str_t
ngx_xrootd_cms_export_paths(ngx_stream_xrootd_srv_conf_t *conf)
{
    if (conf->cms_paths.len > 0) {
        return conf->cms_paths;
    }

    return conf->root;
}


ngx_int_t
ngx_xrootd_cms_stat_space(ngx_stream_xrootd_srv_conf_t *conf,
    uint32_t *total_gb, uint32_t *free_mb, uint32_t *util_pct)
{
    struct statvfs  st;
    uint64_t        total;
    uint64_t        free_bytes;
    uint64_t        used_blocks;

    if (statvfs((char *) conf->root.data, &st) != 0 || st.f_blocks == 0) {
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
