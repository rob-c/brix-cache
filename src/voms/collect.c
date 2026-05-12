#include "voms_internal.h"

#include <string.h>

/*
 * Helpers for converting VOMS API results into the module's comma-separated
 * VO list format.
 */

static ngx_flag_t
xrootd_append_vo_token(char *primary_vo, size_t primary_vo_sz,
    char *vo_list, size_t vo_list_sz, const char *vo)
{
    size_t list_len;
    size_t vo_len;

    if (vo == NULL || vo[0] == '\0') {
        return 1;
    }

    if (xrootd_vo_list_contains(vo_list, vo)) {
        return 1;
    }

    vo_len = strlen(vo);
    list_len = strlen(vo_list);

    if (list_len == 0) {
        if (vo_len + 1 > vo_list_sz || vo_len + 1 > primary_vo_sz) {
            return 0;
        }

        ngx_cpystrn((u_char *) vo_list, (u_char *) vo, vo_list_sz);
        ngx_cpystrn((u_char *) primary_vo, (u_char *) vo, primary_vo_sz);
        return 1;
    }

    if (list_len + 1 + vo_len + 1 > vo_list_sz) {
        return 0;
    }

    vo_list[list_len++] = ',';
    ngx_memcpy(vo_list + list_len, vo, vo_len);
    vo_list[list_len + vo_len] = '\0';
    return 1;
}


static ngx_flag_t
xrootd_fqan_to_vo(const char *fqan, char *vo, size_t vo_sz)
{
    const char *start;
    const char *end;
    size_t      len;

    if (fqan == NULL || fqan[0] != '/') {
        return 0;
    }

    start = fqan + 1;
    end = strchr(start, '/');
    if (end == NULL || end == start) {
        return 0;
    }

    len = (size_t) (end - start);
    if (len + 1 > vo_sz) {
        return 0;
    }

    ngx_memcpy(vo, start, len);
    vo[len] = '\0';
    return 1;
}


ngx_int_t
xrootd_collect_voms_vos(struct voms_data *vd,
    char *primary_vo, size_t primary_vo_sz,
    char *vo_list, size_t vo_list_sz)
{
    struct voms_entry **entry;

    if (vd->data == NULL) {
        return NGX_DECLINED;
    }

    for (entry = vd->data; *entry != NULL; entry++) {
        char **fqan;
        char   derived_vo[128];

        if ((*entry)->voname != NULL && (*entry)->voname[0] != '\0') {
            if (!xrootd_append_vo_token(primary_vo, primary_vo_sz,
                                        vo_list, vo_list_sz,
                                        (*entry)->voname)) {
                return NGX_ERROR;
            }
        }

        if ((*entry)->fqan == NULL) {
            continue;
        }

        for (fqan = (*entry)->fqan; *fqan != NULL; fqan++) {
            if (!xrootd_fqan_to_vo(*fqan, derived_vo, sizeof(derived_vo))) {
                continue;
            }

            if (!xrootd_append_vo_token(primary_vo, primary_vo_sz,
                                        vo_list, vo_list_sz,
                                        derived_vo)) {
                return NGX_ERROR;
            }
        }
    }

    return (vo_list != NULL && vo_list[0] != '\0') ? NGX_OK : NGX_DECLINED;
}
