/*
 * sss_entity_unittest.c — standalone unit test for the SSS v2 entity kernel.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/sss_entity_ut \
 *       src/core/compat/sss_entity.c src/core/compat/sss_bf.c \
 *       src/core/compat/crc32_ieee.c src/core/compat/sss_entity_unittest.c \
 *       -lcrypto && /tmp/sss_entity_ut
 *
 * Exit 0 = all checks pass ("all checks passed" on stdout).  Pins: the outer
 * header and option byte, the CRC trailer, every entity TLV round-tripping
 * through the BF32 decrypt, the NAME-only entity being byte-identical to the
 * v1 brix_sss_build_credential() wire, every per-field cap failing closed
 * (never truncating), the SNDLID form being header-only, and the challenge
 * decoder accepting a good LGID reply while refusing a wrong key, a corrupt
 * CRC, a reply without an LGID, a bad magic and a truncated body.
 */
#include "sss_entity.h"
#include "sss_bf.h"
#include "crc32_ieee.h"
#include "protocols/root/protocol/sss.h"

#include <stdio.h>
#include <string.h>

static int fails;

static void
check(const char *what, int ok)
{
    if (!ok) {
        printf("FAIL %s\n", what);
        fails++;
    }
}

static const uint8_t KEY[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
static const uint8_t WRONG_KEY[32] = { 0x42 };
static const uint8_t NONCE[32] = { 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8 };
#define GEN_TIME 0x01020304u
#define KEY_ID   0x0102030405060708ull

/* Decrypt out[] back into clear[] and verify the CRC trailer; returns the
 * cleartext length (without CRC) or 0 on any failure. */
static size_t
decrypt(const uint8_t *out, size_t out_len, uint8_t *clear, size_t clear_max)
{
    size_t   plain_len, clear_len;
    uint32_t crc;

    if (out_len < BRIX_SSS_HDR_LEN + BRIX_SSS_DATA_HDR_LEN + 4
        || brix_sss_bf_crypt(0, KEY, sizeof(KEY), out + BRIX_SSS_HDR_LEN,
                             out_len - BRIX_SSS_HDR_LEN, clear, clear_max,
                             &plain_len) != 0
        || plain_len < BRIX_SSS_DATA_HDR_LEN + 4)
    {
        return 0;
    }
    clear_len = plain_len - 4;
    crc = ((uint32_t) clear[clear_len] << 24) | ((uint32_t) clear[clear_len + 1] << 16)
        | ((uint32_t) clear[clear_len + 2] << 8) | (uint32_t) clear[clear_len + 3];
    return crc == brix_crc32_ieee(clear, clear_len) ? clear_len : 0;
}

/* Find TLV `type` in the cleartext body; returns its value pointer / length. */
static const uint8_t *
find_tlv(const uint8_t *clear, size_t clear_len, uint8_t type, size_t *len)
{
    const uint8_t *p = clear + BRIX_SSS_DATA_HDR_LEN, *end = clear + clear_len;

    while ((size_t) (end - p) >= 3) {
        size_t n = ((size_t) p[1] << 8) | (size_t) p[2];

        if ((size_t) (end - p - 3) < n) {
            return NULL;
        }
        if (p[0] == type) {
            *len = n;
            return p + 3;
        }
        p += 3 + n;
    }
    return NULL;
}

static void
check_str_tlv(const uint8_t *clear, size_t clear_len, uint8_t type,
              const char *want, const char *what)
{
    const uint8_t *v;
    size_t         n = 0;

    v = find_tlv(clear, clear_len, type, &n);
    check(what, v != NULL && n == strlen(want) + 1
                && memcmp(v, want, n) == 0);
}

static void
test_full_entity(void)
{
    static const uint8_t creds[] = { 0x00, 0x01, 0xff, 'X', 0x00, 0x7f };
    brix_sss_entity_t ent = { "alice", "cms", "production", "/cms,/cms/prod",
                              "endorsed-by=broker", creds, sizeof(creds) };
    uint8_t  out[BRIX_SSS_ENTITY_BLOB_MAX], clear[BRIX_SSS_ENTITY_BLOB_MAX];
    size_t   out_len = 0, clear_len, n = 0;
    const uint8_t *v;

    check("full: build", brix_sss_build_entity_credential(KEY, sizeof(KEY), KEY_ID,
          &ent, NONCE, GEN_TIME, out, sizeof(out), &out_len) == 0);
    check("full: magic", memcmp(out, "sss\0", 4) == 0 && out[4] == 1
                         && out[6] == 0 && out[7] == BRIX_SSS_ENC_BF32);
    check("full: key id", out[8] == 0x01 && out[11] == 0x04 && out[15] == 0x08);
    clear_len = decrypt(out, out_len, clear, sizeof(clear));
    check("full: crc", clear_len > BRIX_SSS_DATA_HDR_LEN);
    check("full: nonce", memcmp(clear, NONCE, 32) == 0);
    check("full: gen_time", clear[32] == 0x01 && clear[35] == 0x04);
    check("full: usedata", clear[39] == BRIX_SSS_OPT_USEDATA);
    check_str_tlv(clear, clear_len, BRIX_SSS_TYPE_NAME, "alice", "full: name");
    check_str_tlv(clear, clear_len, BRIX_SSS_TYPE_VORG, "cms", "full: vorg");
    check_str_tlv(clear, clear_len, BRIX_SSS_TYPE_ROLE, "production", "full: role");
    check_str_tlv(clear, clear_len, BRIX_SSS_TYPE_GRPS, "/cms,/cms/prod", "full: grps");
    check_str_tlv(clear, clear_len, BRIX_SSS_TYPE_ENDO, "endorsed-by=broker", "full: endo");
    v = find_tlv(clear, clear_len, BRIX_SSS_TYPE_CRED, &n);
    check("full: cred raw", v != NULL && n == sizeof(creds)
                            && memcmp(v, creds, n) == 0);
    check("full: name first", clear[BRIX_SSS_DATA_HDR_LEN] == BRIX_SSS_TYPE_NAME);
}

static void
test_v1_identical(void)
{
    brix_sss_entity_t ent = { "bob", NULL, "", NULL, NULL, NULL, 0 };
    uint8_t  a[512], b[512];
    size_t   alen = 0, blen = 0;

    check("v1: entity build", brix_sss_build_entity_credential(KEY, sizeof(KEY),
          KEY_ID, &ent, NONCE, GEN_TIME, a, sizeof(a), &alen) == 0);
    check("v1: legacy build", brix_sss_build_credential(KEY, sizeof(KEY), KEY_ID,
          "bob", NONCE, GEN_TIME, b, sizeof(b), &blen) == 0);
    check("v1: byte-identical", alen == blen && memcmp(a, b, alen) == 0);

    memset(&ent, 0, sizeof(ent));
    check("v1: empty entity build", brix_sss_build_entity_credential(KEY,
          sizeof(KEY), KEY_ID, &ent, NONCE, GEN_TIME, a, sizeof(a), &alen) == 0);
    check("v1: legacy xrd build", brix_sss_build_credential(KEY, sizeof(KEY),
          KEY_ID, NULL, NONCE, GEN_TIME, b, sizeof(b), &blen) == 0);
    check("v1: empty → xrd identical", alen == blen && memcmp(a, b, alen) == 0);
}

static void
test_caps_fail_closed(void)
{
    char     big[BRIX_SSS_ENT_CREDS_MAX + 2];
    uint8_t  out[BRIX_SSS_ENTITY_BLOB_MAX];
    size_t   out_len = 0;
    brix_sss_entity_t ent;

    memset(big, 'a', sizeof(big));
    memset(&ent, 0, sizeof(ent));

    big[BRIX_SSS_ENT_NAME_MAX] = '\0';          /* exactly cap chars: no room for NUL */
    ent.name = big;
    check("cap: name", brix_sss_build_entity_credential(KEY, sizeof(KEY), KEY_ID,
          &ent, NONCE, GEN_TIME, out, sizeof(out), &out_len) != 0);
    big[BRIX_SSS_ENT_NAME_MAX - 1] = '\0';      /* cap-1 chars: fits */
    check("cap: name-1 ok", brix_sss_build_entity_credential(KEY, sizeof(KEY),
          KEY_ID, &ent, NONCE, GEN_TIME, out, sizeof(out), &out_len) == 0);

    memset(&ent, 0, sizeof(ent));
    memset(big, 'e', sizeof(big));
    big[BRIX_SSS_ENT_ENDO_MAX] = '\0';
    ent.endo = big;
    check("cap: endo", brix_sss_build_entity_credential(KEY, sizeof(KEY), KEY_ID,
          &ent, NONCE, GEN_TIME, out, sizeof(out), &out_len) != 0);

    memset(&ent, 0, sizeof(ent));
    ent.creds = (const uint8_t *) big;
    ent.creds_len = BRIX_SSS_ENT_CREDS_MAX + 1;
    check("cap: creds", brix_sss_build_entity_credential(KEY, sizeof(KEY), KEY_ID,
          &ent, NONCE, GEN_TIME, out, sizeof(out), &out_len) != 0);
    ent.creds_len = BRIX_SSS_ENT_CREDS_MAX;
    check("cap: creds max ok", brix_sss_build_entity_credential(KEY, sizeof(KEY),
          KEY_ID, &ent, NONCE, GEN_TIME, out, sizeof(out), &out_len) == 0);

    check("cap: small out", brix_sss_build_entity_credential(KEY, sizeof(KEY),
          KEY_ID, &ent, NONCE, GEN_TIME, out, 64, &out_len) != 0);
    check("cap: null key", brix_sss_build_entity_credential(NULL, 0, KEY_ID,
          &ent, NONCE, GEN_TIME, out, sizeof(out), &out_len) != 0);
}

static void
test_sndlid_form(void)
{
    uint8_t  out[256], clear[256];
    size_t   out_len = 0, clear_len;

    check("sndlid: build", brix_sss_build_entity_credential(KEY, sizeof(KEY),
          KEY_ID, NULL, NONCE, GEN_TIME, out, sizeof(out), &out_len) == 0);
    check("sndlid: header only",
          out_len == BRIX_SSS_HDR_LEN + BRIX_SSS_DATA_HDR_LEN + 4);
    clear_len = decrypt(out, out_len, clear, sizeof(clear));
    check("sndlid: crc", clear_len == BRIX_SSS_DATA_HDR_LEN);
    check("sndlid: option byte", clear[39] == BRIX_SSS_OPT_SNDLID);
}

/* Build a server-style challenge: echoed outer header + BF32(header + TLVs + CRC). */
static size_t
make_challenge(const uint8_t *key, size_t key_len, int with_lgid, int corrupt,
               uint8_t *out, size_t out_max)
{
    static const char lgid[] = "nobody";
    uint8_t  plain[128];
    size_t   n = BRIX_SSS_DATA_HDR_LEN, crypt_out = 0;
    uint32_t crc;

    memset(plain, 0, sizeof(plain));
    memcpy(plain, NONCE, 32);
    plain[39] = BRIX_SSS_OPT_USEDATA;
    if (with_lgid) {
        plain[n++] = BRIX_SSS_TYPE_LGID;
        plain[n++] = 0;
        plain[n++] = (uint8_t) sizeof(lgid);
        memcpy(plain + n, lgid, sizeof(lgid));
        n += sizeof(lgid);
    }
    crc = brix_crc32_ieee(plain, n) ^ (corrupt ? 1u : 0u);
    plain[n] = (uint8_t) (crc >> 24); plain[n + 1] = (uint8_t) (crc >> 16);
    plain[n + 2] = (uint8_t) (crc >> 8); plain[n + 3] = (uint8_t) crc;
    memset(out, 0, BRIX_SSS_HDR_LEN);
    memcpy(out, "sss", 4);
    out[4] = 1;
    out[7] = BRIX_SSS_ENC_BF32;
    if (brix_sss_bf_crypt(1, key, key_len, plain, n + 4, out + BRIX_SSS_HDR_LEN,
                          out_max - BRIX_SSS_HDR_LEN, &crypt_out) != 0) {
        return 0;
    }
    return BRIX_SSS_HDR_LEN + crypt_out;
}

static void
test_challenge(void)
{
    uint8_t  body[256];
    char     lgid[64];
    size_t   n;

    n = make_challenge(KEY, sizeof(KEY), 1, 0, body, sizeof(body));
    check("chal: good", n > 0 && brix_sss_challenge_lgid(KEY, sizeof(KEY), body, n,
          lgid, sizeof(lgid)) == 0 && strcmp(lgid, "nobody") == 0);
    check("chal: wrong key", brix_sss_challenge_lgid(WRONG_KEY, sizeof(WRONG_KEY),
          body, n, lgid, sizeof(lgid)) != 0);
    check("chal: truncated", brix_sss_challenge_lgid(KEY, sizeof(KEY), body,
          n - 8, lgid, sizeof(lgid)) != 0);
    check("chal: too short", brix_sss_challenge_lgid(KEY, sizeof(KEY), body,
          BRIX_SSS_HDR_LEN + 8, lgid, sizeof(lgid)) != 0);
    check("chal: tiny lgid buf", brix_sss_challenge_lgid(KEY, sizeof(KEY), body,
          n, lgid, 3) == 0 && strcmp(lgid, "no") == 0);
    body[0] = 'x';
    check("chal: bad magic", brix_sss_challenge_lgid(KEY, sizeof(KEY), body, n,
          lgid, sizeof(lgid)) != 0);
    body[0] = 's';
    body[7] = 'Z';
    check("chal: bad enc", brix_sss_challenge_lgid(KEY, sizeof(KEY), body, n,
          lgid, sizeof(lgid)) != 0);

    n = make_challenge(KEY, sizeof(KEY), 1, 1, body, sizeof(body));
    check("chal: corrupt crc", n > 0 && brix_sss_challenge_lgid(KEY, sizeof(KEY),
          body, n, lgid, sizeof(lgid)) != 0);
    n = make_challenge(KEY, sizeof(KEY), 0, 0, body, sizeof(body));
    check("chal: no lgid", n > 0 && brix_sss_challenge_lgid(KEY, sizeof(KEY),
          body, n, lgid, sizeof(lgid)) != 0);
    check("chal: null args", brix_sss_challenge_lgid(KEY, sizeof(KEY), NULL, n,
          lgid, sizeof(lgid)) != 0);
}

int
main(void)
{
    test_full_entity();
    test_v1_identical();
    test_caps_fail_closed();
    test_sndlid_form();
    test_challenge();
    if (fails) {
        printf("%d failures\n", fails);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
