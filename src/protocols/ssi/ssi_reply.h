#ifndef BRIX_SSI_REPLY_H
#define BRIX_SSI_REPLY_H

/*
 * ssi_reply.h — build the kXR_query (response-wait) reply payload.
 *
 * WHAT: lay out the byte-exact reply a real libXrdSsi client's GetResp() parses:
 *       [XrdSsiRRInfoAttn (16)][metadata (mdLen)][data (dbL)]. The client recovers
 *       dbL = total - mdLen - pfxLen, reads metadata at +pfxLen and data at
 *       +mdLen+pfxLen (XrdSsiTaskReal::GetResp).
 * WHY:  the kXR_query reply that delivers a unary SSI response (tag fullResp), an
 *       alert (alrtResp), or a streaming head.
 * HOW:  pure C; uses the attn encoder from ssi_rrinfo. Unit-tested for the exact
 *       layout + the client's dbL recovery formula.
 */

#include <stddef.h>

/* Total reply length for the given metadata + data sizes (prefix + md + data). */
size_t brix_ssi_reply_len(size_t md_len, size_t data_len);

/*
 * Build the reply into out (must hold brix_ssi_reply_len bytes): the 16-byte
 * XrdSsiRRInfoAttn prefix (tag, pfxLen=16, mdLen), then metadata, then data.
 * md/data may be NULL when their length is 0. Returns the total bytes written.
 */
size_t brix_ssi_reply_build(char tag,
                              const unsigned char *md, size_t md_len,
                              const unsigned char *data, size_t data_len,
                              unsigned char *out);

#endif /* BRIX_SSI_REPLY_H */
