#ifndef XROOTD_COMPAT_HEX_H
#define XROOTD_COMPAT_HEX_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * xrootd_hex_nibble — convert nibble value to uppercase ASCII hex character.
 *
 * WHAT: Returns '0'-'9' for values 0-9, 'A'-'F' for values 10-15. WHY: Produces individual hex
 *      output characters from 4-bit input during byte-array encoding. */

u_char xrootd_hex_nibble(u_char v);

/*
 * xrootd_hex_from_char — parse ASCII hex character to nibble value, case-insensitive.
 *
 * WHAT: Returns 0-9 for '0'-'9', 10-15 for 'a'-'f'/'A'-'F', -1 for invalid input. WHY: Converts
 *      hex string characters back to byte values during checksum parsing and decoding. */

int xrootd_hex_from_char(unsigned char c);

/*
 * xrootd_hex_encode — convert byte array to null-terminated lowercase ASCII hex string.
 *
 * WHAT: Writes each input byte as two hex characters into out, null-terminating at end. WHY:
 *      Checksum computation results, ETag generation, metadata display need hex representation
 *      of arbitrary binary data. Caller must allocate 2*len+1 bytes for output buffer. */

void xrootd_hex_encode(const u_char *in, size_t len, char *out);

#endif /* XROOTD_COMPAT_HEX_H */
