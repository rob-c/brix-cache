/* File: sss_entity.c — SSS v2 entity credential builder + LGID challenge decoder
 * WHAT: Implements brix_sss_build_entity_credential() (USEDATA entity or the
 *       SNDLID first round) and brix_sss_challenge_lgid() (decrypt the server's
 *       kXR_authmore reply and pull the LGID out of it).  See sss_entity.h.
 * WHY: One ngx-free kernel for the proxy arm and the native client so the
 *      entity wire (field order, 2-byte BE lengths, NUL-included packed strings,
 *      per-field caps, CRC32-IEEE trailer, BF32 body, 16-byte outer header)
 *      cannot drift between the two producers and the server parser.
 * HOW: The cleartext is assembled in a stack buffer of BRIX_SSS_ENTITY_BLOB_MAX
 *      bytes through a small bounded TLV writer; every string is checked against
 *      its receiver-side cap and the builder fails closed instead of truncating.
 *      The trailer CRC and the cipher pass reuse the v1 kernels (crc32_ieee.c,
 *      sss_bf.c) unchanged, so a NAME-only entity is byte-identical to the v1
 *      brix_sss_build_credential() output for the same nonce and gen_time
 *      (pinned by sss_entity_unittest.c).
 */
#include "sss_entity.h"
#include "sss_bf.h"
#include "crc32_ieee.h"
#include "protocols/root/protocol/sss.h"

#include <string.h>

/* Bounded TLV writer over the cleartext buffer. */
typedef struct {
    uint8_t *cur;
    uint8_t *end;
} sss_tlv_writer_t;

static void
sss_put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t)  v;
}

static uint32_t
sss_get_u32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)  |  (uint32_t) p[3];
}

/* [type][len hi][len lo][value] — refuses anything that would overrun `end`. */
static int
sss_tlv_put(sss_tlv_writer_t *w, uint8_t type, const uint8_t *value,
            size_t len)
{
    if (len > 0xFFFF || (size_t) (w->end - w->cur) < 3 + len) {
        return -1;
    }
    *w->cur++ = type;
    *w->cur++ = (uint8_t) (len >> 8);
    *w->cur++ = (uint8_t)  len;
    memcpy(w->cur, value, len);
    w->cur += len;
    return 0;
}

/* Packed string: NUL-terminated, NUL counted in the length.  A NULL or empty
 * string is simply omitted; a string that would not fit the receiver's
 * `cap`-byte buffer (including its NUL) is refused — never truncated. */
static int
sss_tlv_put_str(sss_tlv_writer_t *w, uint8_t type, const char *s, size_t cap)
{
    size_t n;

    if (s == NULL || *s == '\0') {
        return 0;
    }
    n = strnlen(s, cap);
    if (n >= cap) {
        return -1;
    }
    return sss_tlv_put(w, type, (const uint8_t *) s, n + 1);
}

/* 40-byte data header: 32 nonce + gen_time(BE) + 3 spare + option byte. */
static void
sss_data_header(uint8_t *clear, const uint8_t nonce32[32], uint32_t gen_time,
                uint8_t opt)
{
    memset(clear, 0, BRIX_SSS_DATA_HDR_LEN);
    memcpy(clear, nonce32, 32);
    sss_put_u32(clear + 32, gen_time);
    clear[39] = opt;
}

/* 16-byte outer header: magic + version + spare + kn + enc + key_id(8B BE). */
static void
sss_outer_header(uint8_t *out, uint64_t key_id)
{
    out[0] = 's'; out[1] = 's'; out[2] = 's'; out[3] = '\0';
    out[4] = 1;                       /* version */
    out[5] = 0;                       /* spare */
    out[6] = 0;                       /* kn_size: no named key */
    out[7] = BRIX_SSS_ENC_BF32;
    sss_put_u32(out + 8,  (uint32_t) (key_id >> 32));
    sss_put_u32(out + 12, (uint32_t)  key_id);
}

/* Append the entity TLVs after the data header; *clear_len receives the total
 * cleartext length.  Field order mirrors the tag order so a server walking the
 * stream sees NAME first, exactly as the v1 wire did. */
static int
sss_entity_tlvs(uint8_t *clear, size_t clear_max, const brix_sss_entity_t *ent,
                size_t *clear_len)
{
    sss_tlv_writer_t  w = { clear + BRIX_SSS_DATA_HDR_LEN, clear + clear_max };
    const char       *name;

    name = (ent->name != NULL && ent->name[0] != '\0') ? ent->name : "xrd";

    if (sss_tlv_put_str(&w, BRIX_SSS_TYPE_NAME, name,      BRIX_SSS_ENT_NAME_MAX) != 0
        || sss_tlv_put_str(&w, BRIX_SSS_TYPE_VORG, ent->vorg, BRIX_SSS_ENT_VORG_MAX) != 0
        || sss_tlv_put_str(&w, BRIX_SSS_TYPE_ROLE, ent->role, BRIX_SSS_ENT_ROLE_MAX) != 0
        || sss_tlv_put_str(&w, BRIX_SSS_TYPE_GRPS, ent->grps, BRIX_SSS_ENT_GRPS_MAX) != 0
        || sss_tlv_put_str(&w, BRIX_SSS_TYPE_ENDO, ent->endo, BRIX_SSS_ENT_ENDO_MAX) != 0)
    {
        return -1;
    }
    if (ent->creds != NULL && ent->creds_len > 0) {
        if (ent->creds_len > BRIX_SSS_ENT_CREDS_MAX
            || sss_tlv_put(&w, BRIX_SSS_TYPE_CRED, ent->creds, ent->creds_len) != 0)
        {
            return -1;
        }
    }
    *clear_len = (size_t) (w.cur - clear);
    return 0;
}

int
brix_sss_build_entity_credential(const uint8_t *key, size_t key_len,
    uint64_t key_id, const brix_sss_entity_t *ent, const uint8_t nonce32[32],
    uint32_t gen_time, uint8_t *out, size_t out_max, size_t *out_len)
{
    uint8_t   plain[BRIX_SSS_ENTITY_BLOB_MAX];   /* cleartext + CRC32 */
    size_t    clear_len, crypt_out;

    if (key == NULL || key_len == 0 || nonce32 == NULL || out == NULL
        || out_len == NULL
        || out_max < BRIX_SSS_HDR_LEN + BRIX_SSS_DATA_HDR_LEN + 4)
    {
        return -1;
    }

    sss_data_header(plain, nonce32, gen_time,
                    ent == NULL ? BRIX_SSS_OPT_SNDLID : BRIX_SSS_OPT_USEDATA);
    clear_len = BRIX_SSS_DATA_HDR_LEN;
    if (ent != NULL
        && sss_entity_tlvs(plain, sizeof(plain) - 4, ent, &clear_len) != 0)
    {
        return -1;
    }

    /* plain = cleartext + IEEE-CRC32 (big-endian). */
    sss_put_u32(plain + clear_len, brix_crc32_ieee(plain, clear_len));

    if ((size_t) BRIX_SSS_HDR_LEN + clear_len + 4 > out_max) {
        return -1;
    }
    if (brix_sss_bf_crypt(1, key, key_len, plain, clear_len + 4,
                          out + BRIX_SSS_HDR_LEN, out_max - BRIX_SSS_HDR_LEN,
                          &crypt_out) != 0)
    {
        return -1;
    }
    sss_outer_header(out, key_id);
    *out_len = (size_t) BRIX_SSS_HDR_LEN + crypt_out;
    return 0;
}

/* Walk the TLV stream for the LGID field; copy it out as a C string. */
static int
sss_find_lgid(const uint8_t *p, size_t n, char *lgid, size_t lgid_max)
{
    const uint8_t *end = p + n;
    size_t         len, copy;

    while ((size_t) (end - p) >= 3) {
        uint8_t type = p[0];

        len = ((size_t) p[1] << 8) | (size_t) p[2];
        p += 3;
        if ((size_t) (end - p) < len) {
            return -1;
        }
        if (type == BRIX_SSS_TYPE_LGID) {
            copy = (len > 0 && p[len - 1] == '\0') ? len - 1 : len;
            if (copy >= lgid_max) {
                copy = lgid_max - 1;
            }
            memcpy(lgid, p, copy);
            lgid[copy] = '\0';
            return 0;
        }
        p += len;
    }
    return -1;
}

int
brix_sss_challenge_lgid(const uint8_t *key, size_t key_len,
    const uint8_t *body, size_t body_len, char *lgid, size_t lgid_max)
{
    uint8_t  clear[BRIX_SSS_ENTITY_BLOB_MAX];
    size_t   hdr_len, plain_len, clear_len;

    if (key == NULL || key_len == 0 || body == NULL || lgid == NULL
        || lgid_max == 0 || body_len < BRIX_SSS_HDR_LEN)
    {
        return -1;
    }
    if (memcmp(body, "sss", 4) != 0 || body[7] != BRIX_SSS_ENC_BF32) {
        return -1;
    }
    hdr_len = (size_t) BRIX_SSS_HDR_LEN + body[6];
    if (body_len < hdr_len + BRIX_SSS_DATA_HDR_LEN + 4
        || body_len - hdr_len > sizeof(clear))
    {
        return -1;
    }
    if (brix_sss_bf_crypt(0, key, key_len, body + hdr_len, body_len - hdr_len,
                          clear, sizeof(clear), &plain_len) != 0
        || plain_len < BRIX_SSS_DATA_HDR_LEN + 4)
    {
        return -1;
    }
    clear_len = plain_len - 4;
    if (sss_get_u32(clear + clear_len) != brix_crc32_ieee(clear, clear_len)) {
        return -1;
    }
    return sss_find_lgid(clear + BRIX_SSS_DATA_HDR_LEN,
                         clear_len - BRIX_SSS_DATA_HDR_LEN, lgid, lgid_max);
}
