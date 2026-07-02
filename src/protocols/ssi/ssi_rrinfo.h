#ifndef XROOTD_SSI_RRINFO_H
#define XROOTD_SSI_RRINFO_H

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

/* XrdSsiRRInfo::Opc command codes. */
#define XROOTD_SSI_CMD_RXQ 0   /* request / response data exchange */
#define XROOTD_SSI_CMD_RWT 1   /* response wait */
#define XROOTD_SSI_CMD_CAN 2   /* cancel */

/* XrdSsiRRInfoAttn tag bytes. */
#define XROOTD_SSI_ATTN_ALRT '!'   /* alert */
#define XROOTD_SSI_ATTN_FULL ':'   /* full response present */
#define XROOTD_SSI_ATTN_PEND '*'   /* response pending */

#define XROOTD_SSI_RRINFO_LEN 8
#define XROOTD_SSI_ATTN_LEN   16
#define XROOTD_SSI_ID_MAX     0x00ffffffu   /* reqId is 24-bit */

/*
 * Decode the 8 raw offset bytes (as received on the wire, big-endian kXR offset)
 * into command, reqId and size. Always succeeds (the field is fixed-width); the
 * caller validates cmd/id semantically.
 */
void xrootd_ssi_rrinfo_decode(const unsigned char off[XROOTD_SSI_RRINFO_LEN],
                              int *cmd, uint32_t *id, uint32_t *size);

/*
 * Encode command/reqId/size into the 8 wire offset bytes. reqId is masked to
 * 24 bits (XROOTD_SSI_ID_MAX), matching XrdSsiRRInfo::Id().
 */
void xrootd_ssi_rrinfo_encode(int cmd, uint32_t id, uint32_t size,
                              unsigned char off[XROOTD_SSI_RRINFO_LEN]);

/*
 * Build the 16-byte XrdSsiRRInfoAttn prefix for a kXR_attn push: tag (one of the
 * ATTN_* bytes), flags, pfxLen (prefix length, normally sizeof attn = 16), and
 * mdLen (metadata length). The 8 trailing reserved bytes are zeroed.
 */
void xrootd_ssi_attn_encode(char tag, unsigned char flags, uint16_t pfx_len,
                            uint32_t md_len, unsigned char out[XROOTD_SSI_ATTN_LEN]);

#endif /* XROOTD_SSI_RRINFO_H */
