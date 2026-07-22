/*
 * cache/origin_auth.c — origin-side authentication for cache fills.
 *
 * Split out of origin_protocol.c: the ztn (WLCG bearer), GSI (X.509 proxy), and
 * SSS auth handshakes a cache node performs against its upstream origin, plus
 * their credential-loading helpers.  Keeping the auth handshake (~430 lines) in
 * its own file leaves origin_protocol.c focused on the data/namespace protocol,
 * and lets the security-sensitive origin-auth path be reviewed on its own.
 *
 * The three brix_cache_origin_auth_{ztn,gsi,sss}() entry points are declared in
 * cache_internal.h and called from brix_cache_origin_bootstrap().
 */

#include "cache_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared handshake/login packers */
#include "protocols/root/protocol/frame_hdr.h"        /* xrd_error_body_decode */
#include "auth/gsi/gsi_core.h"              /* shared XrdSecgsi handshake kernel */
#include "protocols/root/protocol/gsi.h"              /* kXRS_x509 bucket id */
#include "auth/sss/sss_keytab_kernel.h"     /* §14 SSS keytab line grammar */
#include <stdio.h>                        /* fdopen/fgets for the keytab reader */
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* Frame one kXR_auth request (ClientAuthRequest header, credtype = the 4-byte
 * protocol id, + credential payload) on the connector stream.  Shared by the ztn
 * and sss auth helpers here and the gsi helpers in origin_auth_gsi.c (prototype in
 * cache_internal.h).  Returns 0, or -1 (errno set). */
int
cache_origin_send_kxr_auth(brix_cache_origin_conn_t *oc, const char credtype[4],
    const u_char *payload, uint32_t plen)
{
    ClientAuthRequest req;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 1;                         /* the connector stream */
    req.requestid   = htons(kXR_auth);
    ngx_memcpy(req.credtype, credtype, 4);
    req.dlen        = htonl((kXR_int32) plen);

    if (brix_cache_io_send(oc, &req, sizeof(req)) != 0
        || (plen > 0 && brix_cache_io_send(oc, payload, plen) != 0))
    {
        return -1;
    }
    return 0;
}

/* XrdSecProtocolztn credential wire format (stock XRootD, byte-frozen).
 *
 * The ztn credential is an XrdSecProtocolztn::TokenResp: an 8-byte TokenHdr, a
 * 2-byte big-endian length, then the token followed by one NUL terminator:
 *
 *   off 0..3  id[4]   = "ztn\0"        (NUL-terminated protocol id)
 *   off 4     ver     = 0              (XrdSecProtocolztn::ztnVersion)
 *   off 5     opr     = 'T'            (TokenHdr::IsTkn — "here is a token")
 *   off 6..7  rsvd[2] = 0, 0
 *   off 8..9  len     = htons(tsz + 1) (token length INCLUDING its trailing NUL)
 *   off 10..  tkn[tsz] + one NUL byte
 *
 * The stock server (Authenticate) reads opr at off 5 to route the request,
 * ntohs(len) at off 8, and the token at off 10 (pfxLen = sizeof(TokenHdr) +
 * sizeof(uint16_t) = 10). It requires len >= 1, len's byte at (10 + len - 1) to
 * be NUL, and (10 + len) <= credential size. The whole credential is
 * (10 + tsz + 1) bytes. */
#define BRIX_ZTN_VERSION      0
#define BRIX_ZTN_OPR_ISTKN    'T'
#define BRIX_ZTN_PREFIX_LEN   10        /* 8-byte TokenHdr + 2-byte length */

/* cache_origin_build_ztn_credential — frame a bearer token as a stock XrdSecztn
 * TokenResp credential.
 *
 * WHAT: allocate and fill the (10 + token->len + 1)-byte TokenResp blob for the
 *       given token and return it via *out / *outlen.
 * WHY : the earlier code sent a raw "ztn\0" + token blob (the format OUR own
 *       parser tolerates); a stock XrdSecProtocolztn reads byte 5 as the opr
 *       code, sees a token character instead of 'T', and rejects the exchange
 *       with "Invalid ztn response code". This produces the exact bytes stock
 *       expects.
 * HOW : write the 8-byte header (id/ver/opr/rsvd), the big-endian token length
 *       (token->len + 1, the trailing NUL counts), the token, and one NUL.
 * Returns 0 with *out malloc'd (caller frees), -1 on allocation failure. */
static int
cache_origin_build_ztn_credential(const ngx_str_t *token, u_char **out,
    size_t *outlen)
{
    u_char   *blob;
    size_t    blen;
    uint16_t  tlen_be;

    blen = BRIX_ZTN_PREFIX_LEN + token->len + 1;    /* hdr + len + token + NUL */
    blob = malloc(blen);
    if (blob == NULL) {
        return -1;
    }

    ngx_memcpy(blob, "ztn", 4);                     /* id[4], incl. trailing NUL */
    blob[4] = BRIX_ZTN_VERSION;                     /* ver */
    blob[5] = BRIX_ZTN_OPR_ISTKN;                   /* opr = IsTkn */
    blob[6] = 0;                                    /* rsvd[0] */
    blob[7] = 0;                                    /* rsvd[1] */

    tlen_be = htons((uint16_t) (token->len + 1));   /* length includes the NUL */
    ngx_memcpy(blob + 8, &tlen_be, sizeof(tlen_be));

    ngx_memcpy(blob + BRIX_ZTN_PREFIX_LEN, token->data, token->len);
    blob[BRIX_ZTN_PREFIX_LEN + token->len] = 0;     /* required trailing NUL */

    *out    = blob;
    *outlen = blen;
    return 0;
}

/* brix_cache_origin_auth_ztn — present a WLCG/SciToken bearer to the origin via
 * the XrdSecztn protocol after a kXR_login advertised "&P=ztn". The exchange is a
 * single-round kXR_auth: credtype "ztn\0", payload = the stock XrdSecztn
 * TokenResp (see cache_origin_build_ztn_credential for the exact framing). The
 * server (which advertised its version/maxtsz in the login parms) validates the
 * token and replies kXR_ok. Returns 0 on a kXR_ok auth, -1 otherwise (t error
 * set). §14/C-3. */
int
brix_cache_origin_auth_ztn(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const ngx_str_t *token)
{
    u_char           *blob;
    size_t            blen;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body;

    if (cache_origin_build_ztn_credential(token, &blob, &blen) != 0) {
        brix_cache_set_error(t, kXR_NoMemory, 0,
                               "cache origin ztn payload allocation failed");
        return -1;
    }

    if (cache_origin_send_kxr_auth(oc, "ztn", blob, (uint32_t) blen) != 0) {
        free(blob);
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin ztn auth write failed");
        return -1;
    }
    free(blob);

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen, 4096) != 0) {
        return -1;
    }
    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen,
                                      "cache origin token auth rejected");
        free(body);
        return -1;
    }
    free(body);

    if (status != kXR_ok) {
        /* ztn is single-round; a second authmore (or anything else) is a failure. */
        brix_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin token auth incomplete");
        return -1;
    }
    return 0;
}

/* cache_origin_load_sss_key — load the first usable key from an SSS keytab file into
 * *out. The keytab is an operator-configured, trusted path (opened O_NOFOLLOW so a
 * planted symlink cannot redirect it) parsed with the SHARED keytab line grammar
 * (sss_keytab_parse_line) — the exact tokenisation the server's loader uses, so a key
 * that works one side works the other. Returns 0 with *out filled, or -1 (unreadable /
 * malformed / no usable key). */
static int
cache_origin_load_sss_key(const char *path, brix_sss_key_t *out)
{
    int   fd;
    FILE *fp;
    char  line[1024];
    int   found = 0;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);  /* vfs-seam-allow: config-domain SSS keytab (not export storage) */
    if (fd < 0) {
        return -1;
    }
    fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        return -1;
    }
    ngx_memzero(out, sizeof(*out));
    while (!found && fgets(line, sizeof(line), fp) != NULL) {
        sss_keytab_entry_t entry;
        int                rc = sss_keytab_parse_line(line, &entry,
                                                      (int64_t) ngx_time());

        if (rc < 0) {                            /* malformed ⇒ fail closed */
            (void) fclose(fp);   /* read-only stream — nothing buffered to lose */
            return -1;
        }
        if (rc == 0) {                           /* blank / comment / expired */
            continue;
        }
        out->id      = entry.id;
        out->exp     = (time_t) entry.exp;
        out->key_len = entry.key_len;
        ngx_memcpy(out->key, entry.key, entry.key_len);
        ngx_cpystrn((u_char *) out->user,  (u_char *) entry.user,
                    sizeof(out->user));
        ngx_cpystrn((u_char *) out->group, (u_char *) entry.group,
                    sizeof(out->group));
        ngx_cpystrn((u_char *) out->name,  (u_char *) entry.name,
                    sizeof(out->name));
        found = 1;
    }
    (void) fclose(fp);   /* read-only stream — nothing buffered to lose */
    return found ? 0 : -1;
}

/* brix_cache_origin_auth_sss — present an SSS (Simple Shared Secret) credential to
 * the origin via the XrdSecsss protocol after a login advertised "&P=sss". Mints the
 * SAME kXR_auth blob the proxy path sends (brix_sss_build_proxy_credential): a
 * Blowfish-CFB block over a nonce + gen-time + the keytab user, keyed by the shared
 * secret. Single-round: expect kXR_ok. Returns 0, or -1 (t error set). §14. */
int
brix_cache_origin_auth_sss(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *keytab_path)
{
    brix_sss_key_t  key;
    u_char            cred[2048];
    size_t            cred_len = 0;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body = NULL;

    if (cache_origin_load_sss_key(keytab_path, &key) != 0) {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin SSS keytab unreadable or has no usable key");
        return -1;
    }
    if (brix_sss_build_proxy_credential(&key, key.user, cred, sizeof(cred),
                                          &cred_len) != NGX_OK)
    {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin SSS credential build failed");
        return -1;
    }
    if (cache_origin_send_kxr_auth(oc, "sss", cred, (uint32_t) cred_len) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
            "cache origin SSS auth write failed");
        return -1;
    }
    if (brix_cache_read_response(t, oc, &status, &body, &dlen, 4096) != 0) {
        return -1;
    }
    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen,
                                      "cache origin SSS auth rejected");
        free(body);
        return -1;
    }
    free(body);
    if (status != kXR_ok) {                      /* SSS is single-round */
        brix_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin SSS auth incomplete");
        return -1;
    }
    return 0;
}
