/*
 * sec.h — client auth-protocol module contract.
 *
 * WHAT: A small interface each auth protocol (token/unix/gsi) implements; the
 *       auth driver (auth.c) parses the server's "&P=..." list, picks a module we
 *       have credentials for, and drives the kXR_auth/kXR_authmore loop.
 * WHY:  Keeps each protocol self-contained and the driver protocol-agnostic.
 * HOW:  The driver builds the ClientAuthRequest (credtype from .credtype) carrying
 *       the payload from first()/more(); a single-round protocol leaves .more NULL.
 */
#ifndef XRDC_SEC_H
#define XRDC_SEC_H

#include "../brix.h"

typedef struct {
    const char *name;          /* matches &P=<name> (e.g. "ztn","gsi","unix") */
    char        credtype[4];   /* kXR_auth credtype field, e.g. {'z','t','n',0} */

    /* Do we have usable credentials for this protocol? (env/file probe).
     * c may be NULL (e.g. explain path); when c->opts.cred is non-NULL the
     * store's availability probe is used in place of the inline env probe. */
    int  (*have_creds)(brix_conn *c);

    /* Build the first kXR_auth payload. parms = args after "&P=<name>," ("" if
     * none). Allocates *payload (caller frees); sets *plen. 0 / -1. */
    int  (*first)(brix_conn *c, const char *parms,
                  uint8_t **payload, uint32_t *plen, brix_status *st);

    /* Handle a kXR_authmore challenge; build the next payload. Set *payload=NULL
     * when no further round is expected. NULL for single-round protocols. */
    int  (*more)(brix_conn *c, const uint8_t *sbody, uint32_t slen,
                 uint8_t **payload, uint32_t *plen, brix_status *st);

    void (*cleanup)(brix_conn *c);   /* optional teardown */
} brix_sec_module;

/* Module accessors. */
const brix_sec_module *brix_sec_token(void);
const brix_sec_module *brix_sec_unix(void);
const brix_sec_module *brix_sec_sss(void);   /* shared-secret (sss_keytab.c) */
const brix_sec_module *brix_sec_krb5(void);  /* Kerberos 5; NULL unless BRIX_HAVE_KRB5 */
const brix_sec_module *brix_sec_gsi(void);   /* NULL until Step 5 (sec_gsi.c) */
const brix_sec_module *brix_sec_host(void);  /* host-based; weakest, tried last */
const brix_sec_module *brix_sec_pwd(void);   /* XrdSecpwd password; opt-in, last */

#endif /* XRDC_SEC_H */
