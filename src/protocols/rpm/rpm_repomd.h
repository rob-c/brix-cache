/* rpm_repomd.h — the freshness root, read for what a dnf client asks next
 * (phase-104 D15.10).
 *
 * WHAT: extract from a repomd.xml the `<location href="...">` of the metadata
 *       files a package client fetches unconditionally right after it, and
 *       compose each one into the mirror's own cache key.
 * WHY:  Appendix X, finding X-3: a stock EL9 dnf fetches repomd.xml and then
 *       primary AND filelists, every time its metadata expires, before it can
 *       answer any question at all. On a cold mirror those two fetches are
 *       the client's whole wait, and they are perfectly predictable — the
 *       repomd the mirror has just pulled names them. Warming them is the one
 *       piece of speculation a repository mirror can do that is never wrong:
 *       the objects are named by the index the client already has, they are
 *       digest-named (so they are verified on arrival like any other fill),
 *       and if the client never asks, the mirror has cached two files the
 *       next client will ask for.
 * HOW:  pure C over the caller's buffer — no nginx types, no allocation,
 *       spans point into the XML. Not an XML parser: a repomd is a fixed
 *       shape written by createrepo, and the only thing read out of it is an
 *       attribute value that must then survive the SAME path grammar the gate
 *       applied to the request (brix_rpm_classify) before it can become a
 *       fetch. An href this file cannot vouch for is dropped, never repaired.
 */
#ifndef BRIX_PROTOCOLS_RPM_REPOMD_H
#define BRIX_PROTOCOLS_RPM_REPOMD_H

#include <stddef.h>

/* The warm set is {primary, filelists} — `other` is never fetched by dnf4 and
 * is optional in dnf5 (finding X-3), so speculating on it would be paying for
 * the one file the client does not want. */
#define BRIX_RPM_REPOMD_WARM_MAX  2

/* The longest href this reader will carry. Repository layouts nest, but a
 * location inside one repository is a short relative path; anything longer is
 * not a file createrepo named. */
#define BRIX_RPM_REPOMD_HREF_MAX  512

/* A repomd.xml larger than this is not a repository index this mirror is
 * willing to speculate on: the biggest real one is a few kilobytes, and the
 * cap is what bounds the read the serving path does inline. */
#define BRIX_RPM_REPOMD_MAX  (256 * 1024)

typedef struct {
    const char *href;   size_t href_len;   /* span into the caller's XML */
} brix_rpm_repomd_ref_t;

/* Fill `out` (capacity `max`) with the warm-set hrefs `xml` names, in the
 * order they appear. Returns how many were written (0 when the document names
 * none it can vouch for). An href that is absolute, escapes its repository,
 * carries a scheme or an XML entity, or is empty is DROPPED — the caller
 * cannot tell a dropped one from an absent one, which is the point. */
size_t brix_rpm_repomd_warm_set(const char *xml, size_t len,
    brix_rpm_repomd_ref_t *out, size_t max);

/* Compose the cache key of a file `href` names relative to the repository
 * root, given the key of the repomd.xml that named it (".../repodata/
 * repomd.xml"). Writes a NUL-terminated key into `out` and returns 0, or -1
 * when the repomd key is not repodata-shaped or the composition would not
 * fit. The result is NOT trusted on the strength of this composition: the
 * caller classifies it, and only a metadata-class key is ever fetched. */
int brix_rpm_repomd_sibling_key(const char *repomd_key, size_t key_len,
    const char *href, size_t href_len, char *out, size_t out_size);

#endif /* BRIX_PROTOCOLS_RPM_REPOMD_H */
