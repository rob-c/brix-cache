#ifndef BRIX_OCI_REF_H
#define BRIX_OCI_REF_H
#include <stddef.h>

#include "oci/digest.h"   /* BRIX_OCI_DIGEST_STRLEN — the widest "<alg>:<hex>" */

/* WHAT: image reference parse — `[host[:port]/]name[:tag][@digest]`
 *       (phase-104 D5.1).
 * WHY:  one place turns CLI text into validated registry coordinates; the
 *       name/tag/digest grammars themselves are the shared/oci ones, so a
 *       ref that parses here is a ref the proxy classifier also accepts.
 * HOW:  the podman host rule — the first path component is a registry host
 *       iff it contains '.' or ':' or is "localhost". Neither tag nor
 *       digest ⇒ "latest"; both ⇒ the digest pins content and the tag is
 *       advisory. An IPv6-literal host is written bracketed, as everywhere
 *       else on the wire ("[::1]:5000/lab/app:v1"), and stored UNBRACKETED
 *       in `host` — the one canonical form, which the transport re-brackets
 *       on emit (brix_format_host_port). */

typedef struct {
    char host[256];     /* empty: no registry host; IPv6 WITHOUT brackets */
    int  port;          /* 0: scheme default */
    char name[256];     /* repository name, shared/oci grammar-valid */
    char tag[129];      /* always set ("latest" default) */
    char digest[BRIX_OCI_DIGEST_STRLEN];
                        /* "<alg>:<hex>", empty when by-tag */
    int  has_digest;
} brix_oci_ref_t;

/* 0 ok / -1 with a human-readable reason in err. */
int brix_oci_ref_parse(const char *s, brix_oci_ref_t *out,
                       char *err, size_t errlen);

#endif /* BRIX_OCI_REF_H */
