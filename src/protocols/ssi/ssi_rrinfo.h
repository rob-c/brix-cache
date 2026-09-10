#ifndef BRIX_SSI_RRINFO_H
#define BRIX_SSI_RRINFO_H

/*
 * ssi_rrinfo.h — byte-exact codec for the XrdSsi request/response control words.
 *
 * WHAT: pack/unpack the 8-byte XrdSsiRRInfo carried in the kXR read/write/truncate
 *       offset field, and build the 16-byte XrdSsiRRInfoAttn prefix that heads a
 *       kXR_attn response/alert push.
 * WHY:  byte-exact interop with a real libXrdSsi client. The layouts are fixed by
 *       XrdSsi/XrdSsiRRInfo.hh; this codec is validated against golden values
 *       generated from that very class (see ssi_rrinfo_unittest.c).
 * HOW:  pure C (no nginx headers) so it is unit-testable standalone. The RRInfo
 *       offset, serialized big-endian as the kXR offset, lays out as
 *       [id_lo][id_mid][id_hi][cmd][size little-endian u32]; RRInfoAttn is
 *       [tag][flags][pfxLen BE u16][mdLen BE u32][8 reserved bytes].
 */

#include <stddef.h>
#include <stdint.h>

/* The SSI resource namespace. Lives HERE, not in ssi.h, because ssi.h is
 * ngx-coupled and the native client must build the same path without it —
 * one definition rather than a literal copied across the seam. */
#define BRIX_SSI_PREFIX     "/.ssi/"
#define BRIX_SSI_PREFIX_LEN (sizeof(BRIX_SSI_PREFIX) - 1)

/* XrdSsiRRInfo::Opc command codes. */
#define BRIX_SSI_CMD_RXQ 0   /* request / response data exchange */
#define BRIX_SSI_CMD_RWT 1   /* response wait */
#define BRIX_SSI_CMD_CAN 2   /* cancel */

/* XrdSsiRRInfoAttn tag bytes. */
#define BRIX_SSI_ATTN_ALRT '!'   /* alert */
#define BRIX_SSI_ATTN_FULL ':'   /* full response present */
#define BRIX_SSI_ATTN_PEND '*'   /* response pending */

#define BRIX_SSI_RRINFO_LEN 8
#define BRIX_SSI_ATTN_LEN   16
#define BRIX_SSI_ID_MAX     0x00ffffffu   /* reqId is 24-bit */

/*
 * Decode the 8 raw offset bytes (as received on the wire, big-endian kXR offset)
 * into command, reqId and size. Always succeeds (the field is fixed-width); the
 * caller validates cmd/id semantically.
 */
void brix_ssi_rrinfo_decode(const unsigned char off[BRIX_SSI_RRINFO_LEN],
                              int *cmd, uint32_t *id, uint32_t *size);

/*
 * Encode command/reqId/size into the 8 wire offset bytes. reqId is masked to
 * 24 bits (BRIX_SSI_ID_MAX), matching XrdSsiRRInfo::Id().
 */
void brix_ssi_rrinfo_encode(int cmd, uint32_t id, uint32_t size,
                              unsigned char off[BRIX_SSI_RRINFO_LEN]);

/*
 * Build the 16-byte XrdSsiRRInfoAttn prefix for a kXR_attn push: tag (one of the
 * ATTN_* bytes), flags, pfxLen (prefix length, normally sizeof attn = 16), and
 * mdLen (metadata length). The 8 trailing reserved bytes are zeroed.
 */
void brix_ssi_attn_encode(char tag, unsigned char flags, uint16_t pfx_len,
                            uint32_t md_len, unsigned char out[BRIX_SSI_ATTN_LEN]);

/*
 * Decode a 16-byte XrdSsiRRInfoAttn prefix — the exact inverse of
 * brix_ssi_attn_encode. Always succeeds (the prefix is fixed-width); the caller
 * validates `tag` semantically and must not trust `pfx_len`/`md_len` against its
 * own buffer without checking them. Any out-param may be NULL to decline it.
 *
 * A reader needs this because the reply the server builds is
 * [attn pfx_len][metadata md_len][data], and the data length is only recoverable
 * as total - pfx_len - md_len: nothing on the wire states it. Decoding the
 * prefix by hand at the read site is how the two halves get swapped.
 */
void brix_ssi_attn_decode(const unsigned char in[BRIX_SSI_ATTN_LEN],
                            char *tag, unsigned char *flags,
                            uint16_t *pfx_len, uint32_t *md_len);

#endif /* BRIX_SSI_RRINFO_H */
