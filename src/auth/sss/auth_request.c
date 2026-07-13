#include "sss_internal.h"
#include "fs/path/path.h"
#include "protocols/root/response/response.h"
#include "protocols/root/session/registry.h"

#include <openssl/crypto.h>
#include <string.h>
#include "core/compat/alloc_guard.h"

/*
 * sss_cred_t — outputs of a successful SSS credential decode.
 *
 * WHAT: the verified key, the decoded identity, and the decrypted-buffer
 * span that sss_recv_cred() hands to the mapping/reply stages.
 * WHY: the wire-verify stage produces several coupled results that the later
 * stages consume together; grouping them keeps data flow explicit without new
 * globals.
 * HOW: zero-initialised by the caller; populated only on the NGX_OK path.
 */
typedef struct {
    const brix_sss_key_t *key;
    brix_sss_identity_t   id;
    u_char               *clear;      /* decrypted credential buffer */
    size_t                clear_span; /* bytes to OPENSSL_cleanse (== cipher_len) */
    ngx_int_t             replied_rc; /* wire result when recv returns NGX_DECLINED */
    const u_char         *cipher;     /* ciphertext start (past the outer header) */
    size_t                cipher_len; /* ciphertext length */
    size_t                hdr_len;    /* outer-header length (== cipher offset) */
} sss_cred_t;

/*
 * sss_header_framing_ok — pure predicate for the SSS outer-header framing.
 *
 * WHAT: validates the fixed magic ("sss\0"+BF32), the key-name-size field, and
 * the header-length/NUL-termination against the received datagram length.
 * WHY: bundling the several untrusted-framing bounds checks into one pure test
 * keeps the parse helper flat and the deny condition auditable.
 * HOW: pure — reads the payload and the datagram length, writes the computed
 * header length via *hdr_len; returns 1 when every check passes, else 0.
 */
static int
sss_header_framing_ok(const u_char *payload, size_t dlen, size_t *hdr_len)
{
    uint8_t kn_size;

    if (payload == NULL
        || dlen < BRIX_SSS_HDR_LEN + BRIX_SSS_DATA_HDR_LEN + 4)
    {
        return 0;
    }

    if (payload[0] != 's' || payload[1] != 's' || payload[2] != 's'
        || payload[3] != '\0' || payload[7] != BRIX_SSS_ENC_BF32)
    {
        return 0;
    }

    kn_size = payload[6];
    if (kn_size != 0 && (kn_size > BRIX_SSS_NAME_MAX || (kn_size & 0x07))) {
        return 0;
    }

    *hdr_len = BRIX_SSS_HDR_LEN + kn_size;
    if (*hdr_len >= dlen || (kn_size && payload[*hdr_len - 1] != '\0')) {
        return 0;
    }

    return 1;
}

/*
 * sss_parse_header — validate the SSS outer header and locate the key+cipher.
 *
 * WHAT: checks the "sss\0"+BF32 magic, the key-name-size field, the header
 * length/NUL-termination, looks up the configured key by wire id, and computes
 * the trailing ciphertext span.
 * WHY: the untrusted outer framing has several coupled bounds checks that must
 * all pass before any decryption; keeping them together makes the deny surface
 * auditable in one place.
 * HOW: on success sets out->key/cipher/cipher_len/hdr_len and returns NGX_OK.
 * Any malformed field or unknown key returns brix_sss_auth_failed() (deny).
 */
static ngx_int_t
sss_parse_header(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, sss_cred_t *out)
{
    const u_char *payload = ctx->recv.payload;
    size_t        hdr_len = 0;
    int64_t       key_id;

    if (!sss_header_framing_ok(payload, ctx->recv.cur_dlen, &hdr_len)) {
        return brix_sss_auth_failed(ctx, c);
    }

    key_id = (int64_t) brix_sss_read_be64(payload + 8);
    out->key = brix_sss_find_key(conf, key_id);
    if (out->key == NULL) {
        return brix_sss_auth_failed(ctx, c);
    }

    out->cipher = payload + hdr_len;
    out->cipher_len = ctx->recv.cur_dlen - hdr_len;
    if (out->cipher_len <= 4) {
        return brix_sss_auth_failed(ctx, c);
    }

    out->hdr_len = hdr_len;
    return NGX_OK;
}

/*
 * sss_verify_keytab — decrypt the credential and check its integrity/freshness.
 *
 * WHAT: Blowfish-CFB64 decrypts the ciphertext with the matched key, verifies
 * the trailing CRC32 (wrong-key/tamper guard), enforces the lifetime replay
 * window, handles the interactive SNDLID challenge form, and parses the
 * identity TLV.
 * WHY: this is the keytab-bound trust decision; isolating it freezes the
 * verification semantics as one reviewable unit.
 * HOW: allocates and fills out->clear/out->clear_span/out->id. Returns NGX_OK
 * when a self-contained credential verifies; NGX_DECLINED for SNDLID with the
 * authmore result in out->replied_rc; brix_sss_auth_failed() on any
 * wrong-key/expired/malformed credential (deny).
 */
static ngx_int_t
sss_verify_keytab(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, sss_cred_t *out)
{
    const u_char *payload = ctx->recv.payload;
    size_t        out_len, clear_len;
    uint8_t       options;
    uint32_t      got_crc, want_crc, gen_time, now;

    /* out->key is set non-NULL by sss_parse_header (which denies on a key miss)
     * and sss_recv_cred only reaches here on its NGX_OK; guard defensively so a
     * future caller reordering cannot turn a NULL key into a crash. */
    if (out->key == NULL) {
        return brix_sss_auth_failed(ctx, c);
    }

    BRIX_PALLOC_OR_RETURN(out->clear, c->pool, out->cipher_len, NGX_ERROR);
    out->clear_span = out->cipher_len;

    if (brix_sss_bf32_crypt(0, out->key->key, out->key->key_len,
                              out->cipher, out->cipher_len,
                              out->clear, out->cipher_len, &out_len)
        != NGX_OK)
    {
        return brix_sss_auth_failed(ctx, c);
    }

    if (out_len <= 4) {
        return brix_sss_auth_failed(ctx, c);
    }

    clear_len = out_len - 4;
    got_crc = brix_sss_read_be32(out->clear + clear_len);
    want_crc = brix_sss_crc32(out->clear, clear_len);
    /* Wrong-key detection: a CRC mismatch means either the wrong key was
     * used for decryption or the ciphertext was tampered with. */
    if (got_crc != want_crc || clear_len < BRIX_SSS_DATA_HDR_LEN) {
        return brix_sss_auth_failed(ctx, c);
    }

    gen_time = brix_sss_read_be32(out->clear + 32);
    now = (uint32_t) (ngx_time() - BRIX_SSS_BASE_TIME);
    /* Credential replay prevention: reject tokens older than sss_lifetime. */
    if (gen_time + (uint32_t) conf->sss_lifetime <= now) {
        return brix_sss_auth_failed(ctx, c);
    }

    options = out->clear[39];
    if (options == BRIX_SSS_OPT_SNDLID) {
        out->replied_rc = brix_sss_send_authmore(ctx, c, out->key,
                                                 payload, out->hdr_len);
        return NGX_DECLINED;
    }

    if (brix_sss_parse_identity(out->clear + BRIX_SSS_DATA_HDR_LEN,
                                  clear_len - BRIX_SSS_DATA_HDR_LEN,
                                  &out->id)
        != NGX_OK)
    {
        return brix_sss_auth_failed(ctx, c);
    }

    return NGX_OK;
}

/*
 * sss_recv_cred — receive and verify one SSS credential off the wire.
 *
 * WHAT: orchestrates the outer-header parse then the keytab decrypt/verify.
 * WHY: keeps the two-stage verification chain as one linear call the handler
 * consumes; the security decisions live in the two step helpers.
 * HOW: returns NGX_OK with *out filled, NGX_DECLINED for a sent SNDLID
 * challenge (out->replied_rc), or the deny/error result of a step.
 */
static ngx_int_t
sss_recv_cred(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, sss_cred_t *out)
{
    ngx_int_t rc;

    rc = sss_parse_header(ctx, c, conf, out);
    if (rc != NGX_OK) {
        return rc;
    }

    return sss_verify_keytab(ctx, c, conf, out);
}

/*
 * sss_map_identity — resolve the effective user and group for a credential.
 *
 * WHAT: applies the key's option flags to the decoded identity to pick the
 * authenticated user name and group string.
 * WHY: the ANYUSR/ALLUSR/USRGRP/ANYGRP mapping policy is a pure decision that
 * belongs apart from the I/O so it is trivially auditable.
 * HOW: pure — reads key opts + id, writes the user/group out-pointers
 * (pointers into id or the key, or static literals); no side effects.
 */
static void
sss_map_identity(const brix_sss_key_t *key, const brix_sss_identity_t *id,
    const char **user, const char **group)
{
    *user = key->user;
    if (key->opts & (BRIX_SSS_OPT_ANYUSR | BRIX_SSS_OPT_ALLUSR)) {
        *user = id->name[0] ? id->name : "nobody";
    }

    *group = "";
    if (!(key->opts & BRIX_SSS_OPT_USRGRP)) {
        if (key->opts & BRIX_SSS_OPT_ANYGRP) {
            *group = id->grps[0] ? id->grps : "nogroup";
        } else {
            *group = key->group;
        }
    }
}

/*
 * sss_track_metrics — record unique-user and VO activity at auth completion.
 *
 * WHAT: bumps the shared-memory unique-user set and the matching VO's
 * requests_total counter for the just-authenticated login.
 * WHY: metric bookkeeping is a self-contained side effect; keeping it out of
 * the reply orchestrator keeps that path linear.
 * HOW: no-ops when no SHM segment is mapped; low-cardinality labels only.
 */
static void
sss_track_metrics(brix_ctx_t *ctx)
{
    ngx_brix_metrics_t *shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    size_t vo_len = strlen(ctx->login.primary_vo);
    if (vo_len > 0 && vo_len < sizeof(ctx->login.primary_vo)) {
        brix_track_vo_activity(shm, ctx->login.primary_vo, 0, 0);
        ngx_uint_t vi;
        for (vi = 0; vi < BRIX_VO_MAX_TRACKED; vi++) {
            if (ngx_strncmp(shm->vo_global.slots[vi].name, ctx->login.primary_vo,
                            BRIX_VO_NAME_LEN) == 0)
            {
                BRIX_ATOMIC_INC(&shm->vo_global.slots[vi].requests_total);
                break;
            }
        }
    }

    brix_track_unique_user(shm, ctx->login.dn, strlen(ctx->login.dn));
}

/*
 * sss_reply — commit the authenticated identity and send the success response.
 *
 * WHAT: stamps the login/identity state, registers the session, tracks
 * metrics, logs the OK line, and emits kXR_ok (or kXR_error on identity-alloc
 * failure).
 * HOW: side-effecting orchestration edge; returns the wire result to the
 * caller unchanged.
 */
static ngx_int_t
sss_reply(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *user, const char *group)
{
    ctx->login.auth_done = 1;
    ctx->token.auth = 0;
    ngx_cpystrn((u_char *) ctx->login.dn, (u_char *) user, sizeof(ctx->login.dn));
    if (group[0]) {
        ngx_cpystrn((u_char *) ctx->login.vo_list, (u_char *) group,
                    sizeof(ctx->login.vo_list));
        ngx_cpystrn((u_char *) ctx->login.primary_vo, (u_char *) group,
                    sizeof(ctx->login.primary_vo));
    }
    if (ctx->identity != NULL) {
        if (brix_identity_set_dn(ctx->identity, c->pool, ctx->login.dn,
                                   BRIX_AUTHN_SSS) != NGX_OK
            || brix_identity_set_vos_csv(ctx->identity, c->pool,
                                           ctx->login.vo_list) != NGX_OK)
        {
            return brix_send_error(ctx, c, kXR_NoMemory,
                                     "identity allocation failed");
        }
    }

    sss_track_metrics(ctx);

    brix_session_register(ctx->login.sessid, ctx->login.dn, ctx->login.vo_list, 0);

    {
        char safe_user[256], safe_group[256];
        brix_sanitize_log_string(user, safe_user, sizeof(safe_user));
        brix_sanitize_log_string(group[0] ? group : "-",
                                   safe_group, sizeof(safe_group));
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "brix: SSS auth OK user=\"%s\" group=\"%s\"",
                      safe_user, safe_group);
    }

    BRIX_RETURN_OK(ctx, c, BRIX_OP_AUTH, "AUTH", "-", user, 0);
}

/* Handle the kXR_auth SSS (XrdSecsss shared-secret) credential: verify the
 * client token against the keytab, set the identity/session, and return kXR_ok
 * or kXR_error. */
ngx_int_t
brix_handle_sss_auth(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    sss_cred_t   cred;
    const char  *user, *group;
    ngx_int_t    rc;

    ngx_memzero(&cred, sizeof(cred));

    rc = sss_recv_cred(ctx, c, conf, &cred);
    if (rc != NGX_OK) {
        /* NGX_DECLINED: SNDLID authmore already sent — propagate its exact
         * result. Otherwise a deny/error response was already emitted by the
         * verify chain and rc is that result. */
        return rc == NGX_DECLINED ? cred.replied_rc : rc;
    }

    sss_map_identity(cred.key, &cred.id, &user, &group);

    /* Zero the decrypted credential buffer before it ages in the pool.
     * Prevents plaintext identity data from lingering across later requests. */
    OPENSSL_cleanse(cred.clear, cred.clear_span);

    return sss_reply(ctx, c, user, group);
}
