/*
 * hex.c — hexadecimal encoding and decoding helpers.
 *
 * WHAT: Provides nibble-to-char conversion, char-to-nibble parsing (case-insensitive),
 *      and byte-array to hex string encoding. WHY: XRootD checksums, file metadata, ETag
 *      generation all require hex representation of binary data. Single shared implementation
 *      avoids duplication across compat modules.
 *
 * HOW: nibble lookup via conditional ('0'+v or 'A'+(v-10)), char parsing via range checks
 *      for digits/uppercase/lowercase, encoding via precomputed hex[] array with shift-and-mask. */

#include "hex.h"

/*
 * brix_hex_nibble — convert 4-bit value (0-15) to uppercase hex character.
 *
 * WHAT: Returns '0'-'9' for values 0-9, 'A'-'F' for values 10-15. WHY: Used by encoding
 *      functions to produce hex output characters from individual nibbles. */

uint8_t
brix_hex_nibble(uint8_t v)
{
    return (v < 10) ? (uint8_t) ('0' + v)
                    : (uint8_t) ('A' + (v - 10));
}

/*
 * brix_hex_from_char — parse hex character to nibble value, case-insensitive.
 *
 * WHAT: Returns 0-9 for '0'-'9', 10-15 for 'a'-'f'/'A'-'F', -1 for invalid input. WHY: Used
 *      by checksum parsing functions to convert hex strings back to byte values. */

int
brix_hex_from_char(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return (int) (c - '0');
    }

    if (c >= 'a' && c <= 'f') {
        return (int) (c - 'a' + 10);
    }

    if (c >= 'A' && c <= 'F') {
        return (int) (c - 'A' + 10);
    }

    return -1;
}

/*
 * brix_hex_encode — convert byte array to null-terminated hex string.
 *
 * WHAT: Writes each input byte as two uppercase hex characters into out, null-terminating at
 *      end. WHY: Checksum computation results, ETag generation, metadata display need hex
 *      representation of arbitrary binary data. */

void
brix_hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t            i;

    for (i = 0; i < len; i++) {
        out[i * 2] = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }

    out[len * 2] = '\0';
}
