/*
 * dirlist_fmt.h — kXR_dirlist response envelope grammar (single source of truth).
 *
 * WHAT: the dstat lead-in sentinel that a kXR_dirlist reply carries when the
 *       request set kXR_dstat / kXR_dcksm. The body then begins with this fixed
 *       10-byte sentinel, followed by "<name>\n<statline>\n" pairs (the stat line
 *       itself is owned by protocol/stat_line.h).
 * WHY:  the server EMITS the sentinel (twice — the streaming and buffered dirlist
 *       paths in src/dirlist/handler.c) and the client MATCHES its 9-byte prefix
 *       to decide whether to enter stat-pairing mode (client/lib/ops_meta.c). The
 *       literal was hand-written in all three places; the stock XRootD client keys
 *       on exactly the 9-byte prefix `.\n0 0 0 0`, so a stray byte here silently
 *       drops the whole listing into "every line is a filename" mode. One
 *       definition keeps emit and match in lockstep.
 * HOW:  header-only macros — no ngx, no allocation — so the same constant compiles
 *       into the nginx module and the ngx-free client. The match length is derived
 *       from the emit literal (lead-in minus its trailing newline) so the two can
 *       never drift.
 *
 * Clean-room: sentinel from XProtocol dirlist dstat docs (DirectoryList::dStatPrefix).
 */
#ifndef BRIX_PROTOCOL_DIRLIST_FMT_H
#define BRIX_PROTOCOL_DIRLIST_FMT_H

#include <stddef.h>

/* What the server prepends to a dstat/dcksm listing (10 bytes incl. trailing \n). */
#define BRIX_DSTAT_LEADIN      ".\n0 0 0 0\n"
#define BRIX_DSTAT_LEADIN_LEN  (sizeof(BRIX_DSTAT_LEADIN) - 1)

/* What the client matches at the head of the body to detect stat-pairing mode:
 * the lead-in without its trailing newline (9 bytes). Derived, never re-spelled. */
#define BRIX_DSTAT_PREFIX_LEN  (BRIX_DSTAT_LEADIN_LEN - 1)

#endif /* BRIX_PROTOCOL_DIRLIST_FMT_H */
