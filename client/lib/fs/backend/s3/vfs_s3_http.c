/*
 * vfs_s3_http.c - extracted concern
 * Phase-38 split of vfs_s3.c; behavior-identical.
 */
#include "vfs_s3_internal.h"
#include "auth/cred/cred.h"

void
s3_creds_load(vfs_s3_file *sf, const brix_vfs_open_opts *opts)
{
    const char *ak = NULL;
    const char *sk = NULL;
    const char *rg = getenv("AWS_DEFAULT_REGION");

    /* Task C2: prefer the credential store attached to the open (CLI
     * --s3-access/--s3-secret → ~/.aws / ~/.s3cfg → $AWS_* discovery), matching
     * the xrdcp curl signing path. The store's S3KEYS handler already folds in
     * the $AWS_* fallback, so a complete store hit is a strict superset of the
     * env-only path. We only adopt a COMPLETE access/secret pair from the store;
     * a miss/partial result falls back to $AWS_* as a pair so a store access key
     * is never mixed with an env secret (which would produce a mis-signed, not
     * anonymous, request). An empty pair stays anonymous, as before. */
    if (opts != NULL && opts->cred != NULL) {
        brix_cred_view view;
        brix_status    st;

        if (brix_cred_acquire(opts->cred, XRDC_CRED_S3KEYS, 0, &view, &st) == 0
            && view.s3_access != NULL && view.s3_access[0] != '\0'
            && view.s3_secret != NULL && view.s3_secret[0] != '\0') {
            ak = view.s3_access;
            sk = view.s3_secret;
        }
    }
    if (ak == NULL) {
        ak = getenv("AWS_ACCESS_KEY_ID");
        sk = getenv("AWS_SECRET_ACCESS_KEY");
    }

    snprintf(sf->ak,     sizeof(sf->ak),     "%s", ak ? ak : "");
    snprintf(sf->sk,     sizeof(sf->sk),     "%s", sk ? sk : "");
    snprintf(sf->region, sizeof(sf->region), "%s",
             (rg && rg[0]) ? rg : S3_REGION_DEFAULT);
}


/* SigV4 signing helpers */

/* HTTP status → brix error mapping */

/* XML tag extraction */

/* MPU ETag array management */
