/*
 * src/core/compat/host_identity.h — the one name this node advertises.
 *
 * WHAT: the host name a server writes into anything a client may dial back:
 *       the kXR_locate kXR_prefname token and the cms.d registration "<host>:
 *       <port>".  XRDNET_IDENTITY (the stock XRootD short-circuit for the same
 *       value) wins when it is a syntactically valid host name; otherwise
 *       gethostname(2).  Never resolved here (INVARIANT 13: names are only
 *       resolved through brix_dns_*); this is what is *published*.
 * WHY:  a host whose gethostname(2) has no DNS record (a laptop, a container)
 *       would otherwise hand clients a name they cannot connect to, while the
 *       stock server on the same host advertises its configured identity.
 */
#ifndef BRIX_HOST_IDENTITY_H
#define BRIX_HOST_IDENTITY_H

#include <stddef.h>

/** Maximum accepted identity length (RFC 1035 name limit). */
#define BRIX_HOST_IDENTITY_MAX 255

/**
 * The node identity, cached process-wide on first use.
 * @return a NUL-terminated name; "" when neither source yields one.
 */
const char *brix_host_identity(void);

/**
 * 1 when `name` (len bytes) is a host name this node may advertise: 1..255
 * bytes of letters, digits, '.', '-' and (v6 literal) ':' only.  Pure.
 */
int brix_host_identity_valid(const char *name, size_t len);

#endif /* BRIX_HOST_IDENTITY_H */
