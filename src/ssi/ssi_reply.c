/*
 * ssi_reply.c — build the kXR_query response-wait reply. See header.
 *
 * Layout: [XrdSsiRRInfoAttn 16][metadata mdLen][data dbL], matching exactly what
 * XrdSsiTaskReal::GetResp() parses (pfxLen=16, mdLen=ntohl, dbL=total-md-pfx).
 */

#include "ssi_reply.h"
#include "ssi_rrinfo.h"
#include <string.h>

size_t
xrootd_ssi_reply_len(size_t md_len, size_t data_len)
{
    return XROOTD_SSI_ATTN_LEN + md_len + data_len;
}

size_t
xrootd_ssi_reply_build(char tag, const unsigned char *md, size_t md_len,
                       const unsigned char *data, size_t data_len,
                       unsigned char *out)
{
    xrootd_ssi_attn_encode(tag, 0, (uint16_t) XROOTD_SSI_ATTN_LEN,
                           (uint32_t) md_len, out);
    if (md_len > 0 && md != NULL) {
        memcpy(out + XROOTD_SSI_ATTN_LEN, md, md_len);
    }
    if (data_len > 0 && data != NULL) {
        memcpy(out + XROOTD_SSI_ATTN_LEN + md_len, data, data_len);
    }
    return XROOTD_SSI_ATTN_LEN + md_len + data_len;
}
