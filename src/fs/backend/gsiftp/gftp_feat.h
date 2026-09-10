/*
 * gftp_feat.h — RFC 2389 FEAT capability probe for the outbound GridFTP driver.
 *
 * WHAT: one lazily-issued FEAT command per session, parsed into a bit mask of
 * the extensions this driver is prepared to USE.
 *
 * WHY: the GridFTP extensions are opt-in on the wire and there is no safe way to
 * discover them by trying.  A command an origin has never heard of comes back
 * 500 or 502 — which is indistinguishable from "the transfer failed" on some
 * doors, and on others is answered with a plain-RETR-shaped reply that would
 * hand the caller the WRONG BYTES (see the fallback note on gftp_feat_eret_get
 * in gftp_data.c).  Asking first is the only way to know.
 *
 * HOW: probed at most once per session, and only from a path that would
 * actually use a capability — a stat, a listing or a whole-file read pays
 * nothing for it, which matters because a session lives for exactly one
 * storage-driver call and an unconditional FEAT would put a round trip on every
 * metadata operation the driver performs.
 */
#ifndef BRIX_GFTP_FEAT_H
#define BRIX_GFTP_FEAT_H

#include "gftp_client.h"

/* Extensions this driver uses.  A bit is set only when the origin ADVERTISED
 * it: an origin that supports one silently gets the RFC 959 path, which is
 * correct, merely less efficient.  Bits are added here as the callers that need
 * them land. */
#define GFTP_FEAT_ERET  0x1u   /* GFD.020 5.3 bounded retrieve  (W5.2) */
#define GFTP_FEAT_SPAS  0x2u   /* GFD.020 5.1 striped passive   (W5.3) */

/* The origin's advertised feature mask, probing on first use.  Never fails:
 * an origin that refuses or mangles FEAT reports NO extensions, which is the
 * RFC 959 floor and exactly what this driver did before W5.2. */
unsigned gftp_feat(gftp_session_t *session);

#endif /* BRIX_GFTP_FEAT_H */
