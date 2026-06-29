/*
 * vfs_s3_http.c - extracted concern
 * Phase-38 split of vfs_s3.c; behavior-identical.
 */
#include "vfs_s3_internal.h"

void
s3_creds_load(vfs_s3_file *sf, const xrdc_vfs_open_opts *opts)
{
    const char *ak = getenv("AWS_ACCESS_KEY_ID");
    const char *sk = getenv("AWS_SECRET_ACCESS_KEY");
    const char *rg = getenv("AWS_DEFAULT_REGION");

    (void) opts;   /* cred store not yet wired (task C2) */

    snprintf(sf->ak,     sizeof(sf->ak),     "%s", ak ? ak : "");
    snprintf(sf->sk,     sizeof(sf->sk),     "%s", sk ? sk : "");
    snprintf(sf->region, sizeof(sf->region), "%s",
             (rg && rg[0]) ? rg : S3_REGION_DEFAULT);
}


/* SigV4 signing helpers */

/* HTTP status → xrdc error mapping */

/* XML tag extraction */

/* MPU ETag array management */
