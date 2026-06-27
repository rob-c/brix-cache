/*
 * ssi_rrinfo.c — byte-exact codec for XrdSsiRRInfo / XrdSsiRRInfoAttn. See header.
 *
 * Layouts validated against golden values from the real XrdSsi classes
 * (ssi_rrinfo_unittest.c). The kXR offset that carries an XrdSsiRRInfo serializes
 * big-endian as [id_lo][id_mid][id_hi][cmd][size little-endian u32]; the attn
 * prefix is [tag][flags][pfxLen BE u16][mdLen BE u32][8 reserved].
 */

#include "ssi_rrinfo.h"

void
xrootd_ssi_rrinfo_decode(const unsigned char off[XROOTD_SSI_RRINFO_LEN],
                         int *cmd, uint32_t *id, uint32_t *size)
{
    *id = (uint32_t) off[0]
        | ((uint32_t) off[1] << 8)
        | ((uint32_t) off[2] << 16);
    *cmd = off[3];
    *size = (uint32_t) off[4]
          | ((uint32_t) off[5] << 8)
          | ((uint32_t) off[6] << 16)
          | ((uint32_t) off[7] << 24);
}

void
xrootd_ssi_rrinfo_encode(int cmd, uint32_t id, uint32_t size,
                         unsigned char off[XROOTD_SSI_RRINFO_LEN])
{
    id &= XROOTD_SSI_ID_MAX;
    off[0] = (unsigned char) (id & 0xff);
    off[1] = (unsigned char) ((id >> 8) & 0xff);
    off[2] = (unsigned char) ((id >> 16) & 0xff);
    off[3] = (unsigned char) cmd;
    off[4] = (unsigned char) (size & 0xff);
    off[5] = (unsigned char) ((size >> 8) & 0xff);
    off[6] = (unsigned char) ((size >> 16) & 0xff);
    off[7] = (unsigned char) ((size >> 24) & 0xff);
}

void
xrootd_ssi_attn_encode(char tag, unsigned char flags, uint16_t pfx_len,
                       uint32_t md_len, unsigned char out[XROOTD_SSI_ATTN_LEN])
{
    int i;

    out[0] = (unsigned char) tag;
    out[1] = flags;
    out[2] = (unsigned char) ((pfx_len >> 8) & 0xff);   /* big-endian u16 */
    out[3] = (unsigned char) (pfx_len & 0xff);
    out[4] = (unsigned char) ((md_len >> 24) & 0xff);   /* big-endian u32 */
    out[5] = (unsigned char) ((md_len >> 16) & 0xff);
    out[6] = (unsigned char) ((md_len >> 8) & 0xff);
    out[7] = (unsigned char) (md_len & 0xff);
    for (i = 8; i < XROOTD_SSI_ATTN_LEN; i++) {
        out[i] = 0;
    }
}
