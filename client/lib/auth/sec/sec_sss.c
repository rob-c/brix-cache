/*
 * sec_sss.c — SSS (Simple Shared Secret) auth module.
 *
 * WHAT: Build the kXR_auth payload for the "sss" protocol: a self-contained
 *       credential the server decrypts with the shared key from its keytab.
 * WHY:  SSS lets trusted hosts authenticate with a pre-shared symmetric key (no
 *       PKI, no token issuer) — common for intra-site XRootD/CMS traffic.
 * HOW:  Discover the keytab ($XrdSecSSSKT / $XrdSecsssKT / ~/.xrd/sss.keytab),
 *       pick the first live key, and assemble exactly what the server's encoder
 *       produces (src/auth/sss/auth_proxy_credential.c): a 16-byte outer header
 *       ("sss\0" ver spare kn enc key-id-BE) followed by BF32( 40-byte data
 *       header [32 random + gen_time-BE + USEDATA] + identity TLVs + IEEE-CRC32 ).
 *
 *       Three shapes, in precedence order (release-2.0 F9):
 *         * a registry is attached (opts.sss_id) ⇒ mint the entity registered
 *           for opts.sss_lid, and FAIL when that login id is not registered;
 *         * --sss-sndlid ⇒ send the identity-less SNDLID form, then mint the
 *           login id the server names in its kXR_authmore reply (sss_more);
 *         * any of --sss-vorg/--sss-role/--sss-endorse/--sss-creds-file ⇒ a v2
 *           entity credential carrying those fields.
 *       With none of them the wire is byte-identical to the historical v1
 *       single-round NAME-only credential.
 *
 * wire: XProtocol.hh kXR_auth credtype "sss"; blob per src/auth/sss/sss_internal.h.
 */
#include "sec.h"
#include "auth/cred/cred.h"
#include "auth/sss/sss_keytab.h"
#include "auth/sss/sss_id.h"      /* per-connection identity registry (F9) */
#include "core/compat/sss_bf.h"     /* brix_sss_build_credential — shared with the server */
#include "core/compat/sss_entity.h" /* brix_sss_build_entity_credential + challenge decode */

#include <arpa/inet.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rand.h>

/* Fallback login name for the NAME TLV: this process's own user.  Callers that
 * serve several users from one process override it via opts.sss_user. */
static const char *
local_user(void)
{
    struct passwd *pw = getpwuid(geteuid());
    if (pw != NULL && pw->pw_name != NULL && pw->pw_name[0] != '\0') {
        return pw->pw_name;
    }
    return "xrd";
}

static int
sss_load_first_key(brix_sss_key *out, brix_status *st)
{
    char         path[XRDC_PATH_MAX];
    brix_sss_key keys[XRDC_SSS_KEYS_MAX];
    int          n = 0;

    brix_sss_keytab_default(path, sizeof(path));
    if (brix_sss_keytab_read(path, keys, XRDC_SSS_KEYS_MAX, &n, st) != 0) {
        return -1;
    }
    if (n == 0) {
        brix_status_set(st, XRDC_EAUTH, 0, "keytab %s has no usable keys", path);
        return -1;
    }
    *out = keys[0];
    return 0;
}

static int
sss_have(brix_conn *c)
{
    brix_sss_key key;
    brix_status  st;
    /* Store is a fast "yes"; a store miss falls through to keytab discovery so a
     * tool whose store lacks the sss handler still finds a local key. */
    if (c != NULL && c->opts.cred != NULL
        && brix_cred_available(c->opts.cred, XRDC_CRED_SSS)) {
        return 1;
    }
    brix_status_clear(&st);
    return sss_load_first_key(&key, &st) == 0;
}

static int
sss_pick_key(brix_conn *c, brix_sss_key *key, brix_status *st)
{
    /* Acquire the keytab from the credential store when present; fall back to
     * env/default discovery on failure so env-sourced keytabs work as today. */
    if (c != NULL && c->opts.cred != NULL) {
        brix_cred_view v;
        if (brix_cred_acquire(c->opts.cred, XRDC_CRED_SSS, 0, &v, st) == 0
            && v.path != NULL) {
            brix_sss_key keys[XRDC_SSS_KEYS_MAX];
            int          n = 0;
            if (brix_sss_keytab_read(v.path, keys, XRDC_SSS_KEYS_MAX, &n, st) != 0) {
                return -1;
            }
            if (n == 0) {
                brix_status_set(st, XRDC_EAUTH, 0,
                                "keytab %s has no usable keys", v.path);
                return -1;
            }
            *key = keys[0];
            return 0;
        }
        /* acquire failed or path missing — fall back to env discovery */
        brix_status_clear(st);
    }
    return sss_load_first_key(key, st);
}


/* The NAME this connection proposes when nothing else names it. */
static const char *
sss_proposed_user(brix_conn *c)
{
    if (c != NULL && c->opts.sss_user != NULL && c->opts.sss_user[0] != '\0') {
        return c->opts.sss_user;
    }
    return local_user();
}


/* 1 when any v2 entity field is configured, 0 for a plain v1 credential. */
static int
sss_entity_wanted(const brix_conn *c)
{
    return c != NULL
           && (c->opts.sss_vorg != NULL || c->opts.sss_role != NULL
               || c->opts.sss_endorse != NULL || c->opts.sss_creds_file != NULL);
}


/*
 * WHAT: Fill *id from the connection's entity options, under `name`.
 * WHY:  The bounded setters refuse an over-long field rather than truncating
 *       it, because a truncated VO or role is a DIFFERENT authorization claim
 *       — the server's parser refuses the same way, so both ends agree.
 * HOW:  brix_sss_ident_set() for the strings; the proxied credential is read
 *       from its file HERE, at mint time, so a rotated credential is picked up
 *       without reconnecting and the bytes are never cached in brix_opts.
 */
static int
sss_ident_from_opts(brix_conn *c, const char *name, brix_sss_ident *id,
                    brix_status *st)
{
    uint8_t creds[BRIX_SSS_ENT_CREDS_MAX];
    size_t  creds_len = 0;
    int     rc;

    if (brix_sss_ident_set(id, name, c->opts.sss_vorg, c->opts.sss_role,
                           NULL, c->opts.sss_endorse) != 0) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "sss: identity field too long for the wire format");
        return -1;
    }
    if (c->opts.sss_creds_file == NULL || c->opts.sss_creds_file[0] == '\0') {
        return 0;
    }
    if (brix_sss_creds_read_file(c->opts.sss_creds_file, creds, sizeof(creds),
                                 &creds_len) != 0) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "sss: cannot read proxied credential %s",
                        c->opts.sss_creds_file);
        return -1;
    }
    rc = brix_sss_ident_set_creds(id, creds, creds_len);
    if (rc != 0) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "sss: proxied credential %s is too large",
                        c->opts.sss_creds_file);
    }
    return rc;
}


/*
 * WHAT: Resolve the identity to mint: the registry entry for `lid` when a
 *       registry is attached, else the connection's own entity options under
 *       `name`.
 * WHY:  A registry means this process speaks for several users.  A lookup miss
 *       must therefore be an ERROR — substituting the process identity would
 *       present one user's request under another user's name, which is exactly
 *       the confused-deputy bug the registry exists to prevent.
 * HOW:  brix_sss_id_find() is an exact match with no fallback; its miss becomes
 *       an EAUTH status naming the login id that was not registered.
 */
static int
sss_resolve_ident(brix_conn *c, const char *lid, const char *name,
                  brix_sss_ident *id, brix_status *st)
{
    if (c == NULL) {
        brix_status_set(st, XRDC_EAUTH, 0, "sss: no connection context");
        return -1;
    }
    if (c->opts.sss_id != NULL) {
        if (brix_sss_id_find(c->opts.sss_id, lid, id) != 0) {
            brix_status_set(st, XRDC_EAUTH, 0,
                            "sss: no identity registered for login id \"%s\"",
                            (lid != NULL) ? lid : "");
            return -1;
        }
        return 0;
    }
    return sss_ident_from_opts(c, name, id, st);
}


/*
 * WHAT: The prologue both minters share: a fresh nonce, the SSS-epoch gen_time
 *       and a heap buffer of the caller's size.
 * WHY:  v1 and the entity form differ only in which kernel they call and how big
 *       the buffer is; one prologue means the RNG-failure and out-of-memory
 *       paths are written, and audited, exactly once.
 * HOW:  RAND_bytes into `nonce`, clock into `*gen_time`, malloc into `*blob`. On
 *       any failure `*blob` is left NULL and `st` carries the reason.
 */
static int
sss_mint_prepare(uint8_t nonce[32], uint32_t *gen_time, size_t size,
                 uint8_t **blob, brix_status *st)
{
    *blob = NULL;

    if (RAND_bytes(nonce, 32) != 1) {
        brix_status_set(st, XRDC_EAUTH, 0, "sss: RAND_bytes failed");
        return -1;
    }
    *gen_time = (uint32_t) (time(NULL) - XRDC_SSS_BASE_TIME);

    *blob = (uint8_t *) malloc(size);
    if (*blob == NULL) {
        brix_status_set(st, XRDC_EAUTH, 0, "sss: out of memory");
        return -1;
    }
    return 0;
}


/*
 * WHAT: Mint one SSS credential for `ent` (NULL ⇒ the SNDLID form) into a fresh
 *       heap buffer handed back as the kXR_auth payload.
 * WHY:  RNG and clock belong at the edge; the byte assembly lives in the shared
 *       kernel (brix_sss_build_entity_credential, libxrdproto) so client and
 *       server mint the identical wire format from one audited implementation.
 * HOW:  32 random bytes + the SSS-epoch gen_time, then the kernel; the buffer is
 *       BRIX_SSS_ENTITY_BLOB_MAX, which bounds every field at its cap.
 */
static int
sss_mint(const brix_sss_key *key, const brix_sss_entity_t *ent,
         uint8_t **payload, uint32_t *plen, brix_status *st)
{
    uint8_t *blob;
    uint8_t  nonce[32];
    uint32_t gen_time;
    size_t   blob_len = 0;

    if (sss_mint_prepare(nonce, &gen_time, BRIX_SSS_ENTITY_BLOB_MAX, &blob, st)
        != 0)
    {
        return -1;
    }
    if (brix_sss_build_entity_credential(key->key, key->key_len,
                                         (uint64_t) key->id, ent, nonce,
                                         gen_time, blob,
                                         BRIX_SSS_ENTITY_BLOB_MAX,
                                         &blob_len) != 0) {
        free(blob);
        brix_status_set(st, XRDC_EAUTH, 0, "sss: credential build failed");
        return -1;
    }

    *payload = blob;
    *plen = (uint32_t) blob_len;
    return 0;
}


/*
 * WHAT: Mint the historical v1 credential (a bare NAME TLV, no entity).
 * WHY:  This is the byte-for-byte path every deployed server already accepts,
 *       and it stays the default: a client that configures no entity field
 *       sends exactly what it sent before this feature existed.
 * HOW:  The v1 kernel, unchanged, into the 256-byte buffer it has always used
 *       (HDR + 40-byte data header + TLV + CRC).
 */
static int
sss_mint_v1(brix_conn *c, const brix_sss_key *key, uint8_t **payload,
            uint32_t *plen, brix_status *st)
{
    uint8_t *blob;
    uint8_t  nonce[32];
    uint32_t gen_time;
    size_t   blob_len = 0;

    if (sss_mint_prepare(nonce, &gen_time, 256, &blob, st) != 0) {
        return -1;
    }
    if (brix_sss_build_credential(key->key, key->key_len, (uint64_t) key->id,
                                  sss_proposed_user(c), nonce, gen_time, blob,
                                  256, &blob_len) != 0) {
        free(blob);
        brix_status_set(st, XRDC_EAUTH, 0,
                        "sss: credential build failed (legacy provider?)");
        return -1;
    }

    *payload = blob;
    *plen = (uint32_t) blob_len;
    return 0;
}


static int
sss_first(brix_conn *c, const char *parms, uint8_t **payload, uint32_t *plen,
          brix_status *st)
{
    brix_sss_key      key;
    brix_sss_ident    id;
    brix_sss_entity_t ent;
    int               rc;

    (void) parms;

    if (sss_pick_key(c, &key, st) != 0) {
        return -1;
    }

    /* --sss-sndlid: send the identity-less form and let the server name the
     * login id in its kXR_authmore reply; sss_more() then mints the entity. */
    if (c != NULL && c->opts.sss_sndlid) {
        return sss_mint(&key, NULL, payload, plen, st);
    }

    /* No registry and no entity field configured ⇒ the historical v1 wire. */
    if (c == NULL || (c->opts.sss_id == NULL && !sss_entity_wanted(c))) {
        return sss_mint_v1(c, &key, payload, plen, st);
    }

    if (sss_resolve_ident(c, c->opts.sss_lid, sss_proposed_user(c), &id, st) != 0) {
        return -1;
    }
    brix_sss_ident_to_entity(&id, &ent);
    rc = sss_mint(&key, &ent, payload, plen, st);
    brix_sss_ident_set_creds(&id, NULL, 0);   /* wipe any proxied credential */
    return rc;
}


/*
 * WHAT: Second round: the server answered the SNDLID form with an encrypted
 *       challenge naming the login id it wants; mint that identity.
 * WHY:  Without this the SNDLID form is unusable — the auth loop reports
 *       "server asked for more rounds (unsupported)" and the session dies.
 * HOW:  Decrypt the challenge with the same key (which also proves the peer
 *       holds the shared secret — a wrong key cannot produce a readable LGID),
 *       resolve that login id through the registry when one is attached, and
 *       mint a USEDATA credential for it.
 */
static int
sss_more(brix_conn *c, const uint8_t *sbody, uint32_t slen, uint8_t **payload,
         uint32_t *plen, brix_status *st)
{
    brix_sss_key      key;
    brix_sss_ident    id;
    brix_sss_entity_t ent;
    char              lgid[XRDC_SSS_LID_MAX];
    int               rc;

    if (sss_pick_key(c, &key, st) != 0) {
        return -1;
    }
    if (brix_sss_challenge_lgid(key.key, key.key_len, sbody, (size_t) slen,
                                lgid, sizeof(lgid)) != 0) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "sss: unreadable authmore challenge (wrong key?)");
        return -1;
    }
    if (sss_resolve_ident(c, lgid, lgid, &id, st) != 0) {
        return -1;
    }
    brix_sss_ident_to_entity(&id, &ent);
    rc = sss_mint(&key, &ent, payload, plen, st);
    brix_sss_ident_set_creds(&id, NULL, 0);   /* wipe any proxied credential */
    return rc;
}

const brix_sec_module *
brix_sec_sss(void)
{
    static const brix_sec_module m = {
        "sss",
        { 's', 's', 's', 0 },
        sss_have,
        sss_first,
        sss_more,   /* second round only when the server sends a login id */
        NULL,
    };
    return &m;
}
