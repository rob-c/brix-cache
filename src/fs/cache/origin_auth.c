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

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);  /* vfs-seam-allow: DOMAIN_CONFIG — config-domain SSS keytab (not export storage) */
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
 * Blowfish-CFB block over a nonce + gen-time + an asserted username, keyed by the
 * shared secret. as_user == NULL asserts the keytab's own principal (the static
 * service leg); non-NULL is identity injection (phase-70 §5.6 / P90-70.3): assert
 * the CALLER, failing closed on an empty or over-long principal — the credential
 * builder would otherwise silently substitute "xrd" or truncate to the 63-byte
 * NAME TLV bound, either of which changes WHO reaches the origin. Single-round:
 * expect kXR_ok. Returns 0, or -1 (t error set). §14. */
int
brix_cache_origin_auth_sss(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *keytab_path,
    const char *as_user)
{
    brix_sss_key_t  key;
    u_char            cred[2048];
    size_t            cred_len = 0;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body = NULL;
    const char       *assert_user;

    if (as_user != NULL
        && (as_user[0] == '\0' || ngx_strlen(as_user) > 63))
    {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin SSS identity injection: caller principal is "
            "missing or exceeds the SSS name bound - refusing to assert "
            "a substituted or truncated identity");
        return -1;
    }

    if (cache_origin_load_sss_key(keytab_path, &key) != 0) {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin SSS keytab unreadable or has no usable key");
        return -1;
    }
    assert_user = (as_user != NULL) ? as_user : key.user;
    if (brix_sss_build_proxy_credential(&key, assert_user, cred, sizeof(cred),
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


#if (BRIX_HAVE_KRB5)
#include "auth/krb5/forward.h"     /* brix_krb5_deleg_negotiate / _available */
#include "auth/krb5/kxr_wire.h"    /* brix_krb5_kxr_wire codec */
#include "auth/krb5/apreq.h"       /* brix_krb5_apreq_from_ccache (raw leg) */

/* The kXR krb5 codec's byte transport over the origin connection: adapt the
 * cache I/O helpers (which return 0 / -1) to the codec's NGX_OK / NGX_ERROR. */
static ngx_int_t
cache_origin_krb5_send(void *io, const void *buf, size_t len)
{
    return brix_cache_io_send((brix_cache_origin_conn_t *) io, buf, len) == 0
         ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
cache_origin_krb5_recv(void *io, void *buf, size_t len)
{
    return brix_cache_io_recv_exact((brix_cache_origin_conn_t *) io, buf, len) == 0
         ? NGX_OK : NGX_ERROR;
}

/* brix_cache_origin_auth_krb5 — re-authenticate to the origin AS the inbound
 * user over GSSAPI/krb5 after a kXR_login advertised "&P=krb5" (phase-70 §5.7).
 * Drives the production multi-leg engine brix_krb5_deleg_negotiate(): every
 * initiator token is framed as a kXR_auth(credtype "krb5") request and the
 * origin's kXR_authmore reply is fed back through gss_init_sec_context() until
 * the context completes (kXR_ok) with mutual auth. deleg_gss_cred is the
 * captured gss_cred_id_t (NULL ⇒ the process default cred); origin_service_princ
 * is "host/<fqdn>@REALM" (see brix_krb5_origin_princ_from_host). Returns 0 on a
 * completed exchange, -1 otherwise (t error set).
 *
 * The kXR frame codec (brix_krb5_kxr_wire) and the engine are exercised live
 * over real GSS bytes by tests/test_krb5_forward_live.py (mode "kxrwire", a real
 * KDC + a kXR-framed acceptor over a socket).
 *
 * RETAINED REFERENCE DIALECT — SUPERSEDED, not on the production path. The live
 * krb5 origin leg is brix_cache_origin_auth_krb5_raw() below (dispatched from
 * origin_protocol_bootstrap.c), a RAW AP-REQ exchange — stock XRootD krb5 speaks
 * raw krb5_rd_req, NOT this GSSAPI gss_init_sec_context init-token negotiation
 * (phase-88 UPDATE (iv); phase-92 §5). This GSSAPI variant has zero production
 * callers and is kept only as a reference implementation of the GSSAPI dialect,
 * with its live-wire unit. Its lack of a caller is deliberate, NOT infra-blocked. */
int
brix_cache_origin_auth_krb5(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    void *deleg_gss_cred, const char *origin_service_princ)
{
    brix_krb5_kxr_wire_t  w;
    ngx_pool_t           *pool;
    ngx_int_t             rc;

    if (!brix_krb5_forward_available()) {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin krb5 auth unavailable (no krb5/GSSAPI support)");
        return -1;
    }

    /* A private pool for the transient token copies the engine hands to the
     * codec — thread-safe (a fresh malloc-backed pool, no shared nginx state). */
    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, t->c->log);
    if (pool == NULL) {
        brix_cache_set_error(t, kXR_NoMemory, 0,
            "cache origin krb5 pool allocation failed");
        return -1;
    }

    ngx_memzero(&w, sizeof w);
    w.send     = cache_origin_krb5_send;
    w.recv     = cache_origin_krb5_recv;
    w.io       = oc;
    w.max_body = 1 << 16;   /* a GSS/SPNEGO token is a few KiB; 64K is generous */

    rc = brix_krb5_deleg_negotiate(pool, deleg_gss_cred, origin_service_princ,
                                   brix_krb5_kxr_wire, &w, t->c->log);

    if (w.reply != NULL) {      /* free the final leg's borrowed reply token */
        free(w.reply);
        w.reply = NULL;
    }
    ngx_destroy_pool(pool);

    if (rc != NGX_OK) {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin krb5 negotiation failed");
        return -1;
    }
    return 0;
}

/* brix_cache_origin_auth_krb5_raw — re-authenticate to the origin AS the inbound
 * user with a RAW krb5 AP-REQ (phase-70 §5.7). This is the dialect stock XRootD
 * (libXrdSeckrb5) and brix's own acceptor (src/auth/krb5/auth.c) actually speak —
 * krb5_rd_req over an AP-REQ — as opposed to the GSSAPI init-context tokens the
 * multi-leg engine above emits, which no real "&P=krb5" origin can consume.
 *
 * The delegated user's TGT is already carried onto the fill task as a ccache PATH
 * (ccache_path), so brix_krb5_apreq_from_ccache builds the "krb5\0"+AP-REQ payload
 * — byte-for-byte the native client's wire — directly, with no GSS re-import.
 * origin_spn is the origin's advertised service principal ("&P=krb5,<princ>").
 *
 * A single leg suffices: the AP-REQ is self-contained, so a correct origin answers
 * kXR_ok. A kXR_authmore ("fwdtgt") — the origin asking us to chain-delegate onward
 * to ITS backend — is not chained here and fails closed. Returns 0 on kXR_ok, -1
 * otherwise (t error set). Per-user only: never falls back to a service credential.
 * Live-verified against a real KDC by tests/test_krb5_forward_live.py mode "apreq"
 * (the produced AP-REQ is accepted by krb5_rd_req against the origin keytab). */
int
brix_cache_origin_auth_krb5_raw(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *ccache_path,
    const char *origin_spn)
{
    brix_krb5_kxr_wire_t  w;
    ngx_pool_t           *pool;
    ngx_str_t             payload;
    ngx_str_t             in_token;
    int                   done = 0;
    ngx_int_t             rc;
    /* The bespoke-origin fill path carries a real ngx_connection_t (t->c) whose
     * ->log is the worker request log; the sd_xroot SOURCE-backend path
     * (sd_xroot_session) hands us a calloc'd task with t->c == NULL and manages
     * its own socket via oc, so fall back to the worker cycle log there — never
     * dereference t->c->log unguarded (it segfaults the fill worker). */
    ngx_log_t            *log = (t->c != NULL) ? t->c->log : ngx_cycle->log;

    if (origin_spn == NULL || origin_spn[0] == '\0') {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin krb5: origin advertised no service principal");
        return -1;
    }

    /* A private pool for the transient AP-REQ payload — a fresh malloc-backed
     * pool, no shared nginx state (thread-safe on the async fill worker). */
    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, log);
    if (pool == NULL) {
        brix_cache_set_error(t, kXR_NoMemory, 0,
            "cache origin krb5 pool allocation failed");
        return -1;
    }

    if (brix_krb5_apreq_from_ccache(pool, ccache_path, origin_spn, &payload,
                                    log) != NGX_OK)
    {
        ngx_destroy_pool(pool);
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin krb5 delegated AP-REQ build failed");
        return -1;
    }

    ngx_memzero(&w, sizeof w);
    w.send     = cache_origin_krb5_send;
    w.recv     = cache_origin_krb5_recv;
    w.io       = oc;
    w.max_body = 1 << 16;   /* a kXR_ok/AP-REP reply body is small; 64K is generous */

    /* The frame codec sends the "krb5" credtype header + our "krb5\0"+AP-REQ
     * payload and reads one ServerResponseHeader; done ⇔ kXR_ok. */
    rc = brix_krb5_kxr_wire(&w, &payload, &in_token, &done, log);
    if (w.reply != NULL) {
        free(w.reply);
        w.reply = NULL;
    }
    ngx_destroy_pool(pool);

    if (rc != NGX_OK || !done) {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin krb5 AP-REQ rejected by origin");
        return -1;
    }
    return 0;
}
#endif /* BRIX_HAVE_KRB5 */
