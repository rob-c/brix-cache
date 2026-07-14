/*
 * gsi_core.c - (kept) routing + shared helpers.
 *
 * Owns the ngx-free GSI kernels that are neither the round-2 cert-response
 * exchange nor a lower-level crypto primitive: the shared DH-params / cipher-
 * allowlist constants, the round-1 "gsi protocol parms" parser, the round-1
 * certreq builder, and the kXR_sigver opcode policy + HMAC. The round-2 cert-
 * response state machine and its leaf helpers were split out to
 * gsi_core_cresp.c / gsi_core_cresp_util.c under the phase-79 file-size guard;
 * they share gsi_core_internal.h. Behaviour-identical to the original.
 */
#include "gsi_core_internal.h"

const char brix_gsi_dh_params_pem[] =
"-----BEGIN DH PARAMETERS-----\n"
"MIIBiAKCAYEAzcEAf3ZCkm0FxJLgKd1YoT16Hietl7QV8VgJNc5CYKmRu/gKylxT\n"
"MVZJqtUmoh2IvFHCfbTGEmZM5LdVaZfMLQf7yXjecg0nSGklYZeQQ3P0qshFLbI9\n"
"u3z1XhEeCbEZPq84WWwXacSAAxwwRRrN5nshgAavqvyDiGNi+GqYpqGPb9JE38R3\n"
"GJ51FTPutZlvQvEycjCbjyajhpItBB+XvIjWj2GQyvi+cqB0WrPQAsxCOPrBTCZL\n"
"OjM0NfJ7PQfllw3RDQev2u1Q+Rt8QyScJQCFUj/SWoxpw2ydpWdgAkrqTmdVYrev\n"
"x5AoXE52cVIC8wfOxaaJ4cBpnJui3Y0jZcOQj0FtC0wf4WcBpHnLLBzKSOQwbxts\n"
"WE8LkskPnwwrup/HqWimFFg40bC9F5Lm3CTDCb45mtlBxi3DydIbRLFhGAjlKzV3\n"
"s9G3opHwwfgXpFf3+zg7NPV3g1//HLgWCvooOvMqaO+X7+lXczJJLMafEaarcAya\n"
"Kyo8PGKIAORrAgEF\n"
"-----END DH PARAMETERS-----\n";

const char *const gsi_cipher_allow[] = {
    "aes-128-cbc", "aes-256-cbc", "bf-cbc", "des-ede3-cbc", NULL
};


static void
brix_gsi_copy_parm(char *dst, size_t dst_cap, const char *value,
                   size_t value_len)
{
    size_t copy_len;

    if (dst == NULL || dst_cap == 0) {
        return;
    }

    copy_len = value_len < dst_cap - 1 ? value_len : dst_cap - 1;
    memcpy(dst, value, copy_len);
    dst[copy_len] = '\0';
}

static void
brix_gsi_parse_short_parm(const char *field, size_t field_len,
                          uint32_t *version, char *crypto, size_t cryptosz)
{
    const char *value;
    size_t value_len;

    if (field_len <= 2 || field[1] != ':') {
        return;
    }

    value = field + 2;
    value_len = field_len - 2;
    if (field[0] == 'v' && version != NULL) {
        *version = (uint32_t) strtoul(value, NULL, 10);
        return;
    }
    if (field[0] == 'c') {
        brix_gsi_copy_parm(crypto, cryptosz, value, value_len);
    }
}

static void
brix_gsi_parse_ca_parm(const char *field, size_t field_len,
                       char *ca, size_t casz)
{
    if (field_len <= 3 || field[0] != 'c' || field[1] != 'a'
        || field[2] != ':') {
        return;
    }

    brix_gsi_copy_parm(ca, casz, field + 3, field_len - 3);
}


/* Parse a gsi protocol parms string "v:10600,c:ssl,ca:HASH|HASH" into fields.
 * Any out pointer may be NULL.  `crypto`/`ca` are NUL-terminated, truncated. */
void
brix_gsi_parse_parms(const char *parms, uint32_t *version,
                       char *crypto, size_t cryptosz,
                       char *ca, size_t casz)
{
    const char *p;

    if (version != NULL) { *version = 0; }
    if (crypto != NULL && cryptosz > 0) { crypto[0] = '\0'; }
    if (ca != NULL && casz > 0) { ca[0] = '\0'; }
    if (parms == NULL) {
        return;
    }

    for (p = parms; *p != '\0'; ) {
        const char *comma = strchr(p, ',');
        size_t      flen  = comma ? (size_t) (comma - p) : strlen(p);

        brix_gsi_parse_short_parm(p, flen, version, crypto, cryptosz);
        brix_gsi_parse_ca_parm(p, flen, ca, casz);
        p += flen;
        if (*p == ',') { p++; }
    }
}


/*
 * Build the standard XrdSecgsi round-1 certreq buffer.  Outer (Step
 * kXGC_certreq) carries kXRS_cryptomod, kXRS_version, kXRS_issuer_hash,
 * kXRS_clnt_opts and a kXRS_main bucket whose data is a *nested* buffer
 * (Step kXGC_certreq + kXRS_rtag + kXRS_none).  Mirrors a stock client's first
 * message; the server's XrdSutBuffer parser reads the certreq opcode from the
 * main bucket (a bare top-level opcode is rejected with "main buffer missing").
 * Returns a malloc'd buffer (*outlen set), or NULL.
 */
uint8_t *
brix_gsi_build_certreq(const char *cryptomod, uint32_t version,
                         const char *issuer_hash, uint32_t clnt_opts,
                         const uint8_t *rtag, size_t rtaglen, size_t *outlen)
{
    brix_gbuf inner, outer;
    uint32_t    ver_be  = htonl(version);
    uint32_t    opts_be = htonl(clnt_opts);
    uint8_t    *result  = NULL;

    /* Nested main: "gsi\0" + kXGC_certreq + rtag bucket + terminator. */
    brix_gbuf_init(&inner);
    brix_gbuf_start(&inner, (uint32_t) kXGC_certreq);
    brix_gbuf_bucket(&inner, (uint32_t) kXRS_rtag, rtag, rtaglen);
    brix_gbuf_end(&inner);
    if (inner.err) {
        brix_gbuf_free(&inner);
        return NULL;
    }

    brix_gbuf_init(&outer);
    brix_gbuf_start(&outer, (uint32_t) kXGC_certreq);
    brix_gbuf_bucket(&outer, (uint32_t) kXRS_cryptomod,
                       cryptomod, strlen(cryptomod));
    brix_gbuf_bucket(&outer, (uint32_t) kXRS_version, &ver_be, 4);
    brix_gbuf_bucket(&outer, (uint32_t) kXRS_issuer_hash,
                       issuer_hash, strlen(issuer_hash));
    brix_gbuf_bucket(&outer, (uint32_t) kXRS_clnt_opts, &opts_be, 4);
    brix_gbuf_bucket(&outer, (uint32_t) kXRS_main, inner.p, inner.len);
    brix_gbuf_end(&outer);

    if (!outer.err) {
        result  = outer.p;
        *outlen = outer.len;
        outer.p = NULL;          /* ownership → caller */
    }
    brix_gbuf_free(&inner);
    brix_gbuf_free(&outer);
    return result;
}


int
brix_gsi_sigver_required(uint16_t op, int level)
{
    static const uint16_t exempt_ops[] = {
        kXR_login, kXR_protocol, kXR_auth, kXR_endsess,
        kXR_ping, kXR_sigver, kXR_bind
    };
    static const uint16_t level2_ops[] = {
        kXR_open, kXR_write, kXR_pgwrite, kXR_writev, kXR_truncate,
        kXR_mkdir, kXR_rm, kXR_rmdir, kXR_mv, kXR_chmod, kXR_fattr,
        kXR_chkpoint, kXR_clone
    };
    size_t op_index;

    if (level <= 1) {
        return 0;
    }

    for (op_index = 0; op_index < sizeof(exempt_ops) / sizeof(exempt_ops[0]);
         op_index++) {
        if (op == exempt_ops[op_index]) {
            return 0;
        }
    }

    if (level == 2) {
        for (op_index = 0; op_index < sizeof(level2_ops) / sizeof(level2_ops[0]);
             op_index++) {
            if (op == level2_ops[op_index]) {
                return 1;
            }
        }
        return 0;
    }
    return 1;   /* level >= 3 */
}


/* kXR_sigver HMAC — request signing (client) / verification (server). */

void
brix_gsi_sigver_seqno_be(uint64_t seq, uint8_t out[8])
{
    out[0] = (uint8_t) (seq >> 56);
    out[1] = (uint8_t) (seq >> 48);
    out[2] = (uint8_t) (seq >> 40);
    out[3] = (uint8_t) (seq >> 32);
    out[4] = (uint8_t) (seq >> 24);
    out[5] = (uint8_t) (seq >> 16);
    out[6] = (uint8_t) (seq >> 8);
    out[7] = (uint8_t) seq;
}


int
brix_gsi_sigver_hmac(const uint8_t key[32], uint64_t seqno,
                       const uint8_t hdr24[24], const uint8_t *payload,
                       size_t plen, int nodata, uint8_t mac_out[32])
{
    uint8_t  seqbe[8];
    uint8_t *msg;
    size_t   mlen;
    int      cover_payload, ok;

    if (key == NULL || hdr24 == NULL || mac_out == NULL) {
        return 0;
    }
    cover_payload = (!nodata && payload != NULL && plen > 0);
    mlen = 8 + 24 + (cover_payload ? plen : 0);
    msg  = (uint8_t *) malloc(mlen);
    if (msg == NULL) {
        return 0;
    }
    brix_gsi_sigver_seqno_be(seqno, seqbe);
    memcpy(msg, seqbe, 8);
    memcpy(msg + 8, hdr24, 24);
    if (cover_payload) {
        memcpy(msg + 32, payload, plen);
    }
    ok = brix_hmac_sha256(key, 32, msg, mlen, mac_out);
    free(msg);
    return ok;
}
