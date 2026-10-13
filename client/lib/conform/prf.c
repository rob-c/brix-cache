/* Seekable SipHash-2-4 content function for planted conformance objects. */
#include "conform/conform.h"

#include <string.h>

static int
hex_nibble(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Parse the stable 32-hex-character run-key spelling. */
int
brix_conform_key_parse(const char *hex, brix_conform_key *key)
{
    size_t i;

    if (hex == NULL || key == NULL
        || strlen(hex) != BRIX_CONFORM_KEY_SIZE * 2U) return -1;
    for (i = 0; i < BRIX_CONFORM_KEY_SIZE; i++) {
        int high = hex_nibble(hex[i * 2U]);
        int low = hex_nibble(hex[i * 2U + 1U]);

        if (high < 0 || low < 0) return -1;
        key->bytes[i] = (uint8_t) ((high << 4) | low);
    }
    return 0;
}

/* Format a run key without locale or allocation dependencies. */
void
brix_conform_key_format(const brix_conform_key *key,
    char hex[BRIX_CONFORM_KEY_SIZE * 2U + 1U])
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < BRIX_CONFORM_KEY_SIZE; i++) {
        hex[i * 2U] = digits[key->bytes[i] >> 4];
        hex[i * 2U + 1U] = digits[key->bytes[i] & 0x0fU];
    }
    hex[BRIX_CONFORM_KEY_SIZE * 2U] = '\0';
}

static uint64_t
load64_le(const uint8_t *p)
{
    return ((uint64_t) p[0]) | ((uint64_t) p[1] << 8)
        | ((uint64_t) p[2] << 16) | ((uint64_t) p[3] << 24)
        | ((uint64_t) p[4] << 32) | ((uint64_t) p[5] << 40)
        | ((uint64_t) p[6] << 48) | ((uint64_t) p[7] << 56);
}

static uint64_t
rotl64(uint64_t value, unsigned int bits)
{
    return (value << bits) | (value >> (64U - bits));
}

static void
sip_round(uint64_t *v0, uint64_t *v1, uint64_t *v2, uint64_t *v3)
{
    *v0 += *v1;
    *v1 = rotl64(*v1, 13);
    *v1 ^= *v0;
    *v0 = rotl64(*v0, 32);
    *v2 += *v3;
    *v3 = rotl64(*v3, 16);
    *v3 ^= *v2;
    *v0 += *v3;
    *v3 = rotl64(*v3, 21);
    *v3 ^= *v0;
    *v2 += *v1;
    *v1 = rotl64(*v1, 17);
    *v1 ^= *v2;
    *v2 = rotl64(*v2, 32);
}

/* Return SipHash-2-4(key, little-endian counter), the Phase-118 PRF block. */
uint64_t
brix_conform_prf64(const brix_conform_key *key, uint64_t counter)
{
    uint64_t k0 = load64_le(key->bytes);
    uint64_t k1 = load64_le(key->bytes + 8);
    uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ k0;
    uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ k1;
    uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ k0;
    uint64_t v3 = UINT64_C(0x7465646279746573) ^ k1;
    uint64_t tail = UINT64_C(8) << 56;

    v3 ^= counter;
    sip_round(&v0, &v1, &v2, &v3);
    sip_round(&v0, &v1, &v2, &v3);
    v0 ^= counter;
    v3 ^= tail;
    sip_round(&v0, &v1, &v2, &v3);
    sip_round(&v0, &v1, &v2, &v3);
    v0 ^= tail;
    v2 ^= 0xffU;
    sip_round(&v0, &v1, &v2, &v3);
    sip_round(&v0, &v1, &v2, &v3);
    sip_round(&v0, &v1, &v2, &v3);
    sip_round(&v0, &v1, &v2, &v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

/* Return the independently addressable planted byte at offset. */
uint8_t
brix_conform_byte(const brix_conform_key *key, uint64_t offset)
{
    uint64_t block = brix_conform_prf64(key, offset >> 3);

    return (uint8_t) (block >> ((offset & 7U) * 8U));
}

/* Fill one arbitrary object range without generating its preceding bytes. */
void
brix_conform_fill(const brix_conform_key *key, uint64_t offset, uint8_t *out,
    size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        out[i] = brix_conform_byte(key, offset + (uint64_t) i);
    }
}

/* Compare an arbitrary range and report the first divergent absolute offset. */
int
brix_conform_verify(const brix_conform_key *key, uint64_t offset,
    const uint8_t *actual, size_t len, uint64_t *bad_offset)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (actual[i] != brix_conform_byte(key, offset + (uint64_t) i)) {
            if (bad_offset != NULL) {
                *bad_offset = offset + (uint64_t) i;
            }
            return -1;
        }
    }
    return 0;
}
