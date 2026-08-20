/* ref.c — image reference parse (see ref.h for the grammar). */
#include "oci/ref.h"

#include "oci/digest.h"
#include "oci/name.h"
#include "oci/url.h"

#include <stdio.h>
#include <string.h>

static int
ref_fail(char *err, size_t errlen, const char *msg)
{
    if (err != NULL && errlen > 0) {
        snprintf(err, errlen, "%s", msg);
    }
    return -1;
}

/* The podman rule: first path component is a host iff it has '.' or ':' or
 * is exactly "localhost". */
static int
looks_like_host(const char *s, size_t n)
{
    return memchr(s, '.', n) != NULL || memchr(s, ':', n) != NULL ||
           (n == 9 && memcmp(s, "localhost", 9) == 0);
}

/* Peel a podman-style registry prefix from *rest when the first component
 * identifies itself as a host. The authority itself is parsed by the shared
 * URL grammar — brackets, port and all — so a host this tool will dial is
 * exactly a host the proxy would have accepted in a base URL, and an IPv6
 * literal keeps the one canonical (unbracketed) spelling everywhere below. */
static int
ref_registry(const char **rest, brix_oci_ref_t *out, char *err,
             size_t errlen)
{
    const char *slash = strchr(*rest, '/');
    size_t      alen;

    if (slash == NULL) {
        /* A bracketed literal with nothing after it is a host and no
         * repository — worth saying so, rather than failing later as a
         * repository name full of colons. */
        return ((*rest)[0] == '[')
               ? ref_fail(err, errlen, "registry host without a repository")
               : 0;
    }
    alen = (size_t) (slash - *rest);
    if (!looks_like_host(*rest, alen)) {
        return 0;
    }
    if (brix_oci_url_authority(*rest, alen, out->host, sizeof(out->host),
                               &out->port) != 0)
    {
        return ref_fail(err, errlen, "invalid registry host or port");
    }
    *rest = slash + 1;
    return 0;
}

/* Validate and retain the optional digest, before tag parsing sees its colon. */
static int
ref_digest(const char *at, brix_oci_ref_t *out, char *err, size_t errlen)
{
    brix_oci_digest_t d;

    if (at == NULL) {
        return 0;
    }
    if (brix_oci_digest_parse(at + 1, strlen(at + 1), &d) != 0) {
        return ref_fail(err, errlen,
                        "invalid digest (want sha256:<64 lowercase hex> "
                        "or sha512:<128 lowercase hex>)");
    }
    /* Re-emit through the formatter rather than the parsed hex alone: the
     * algorithm the ref pinned is part of the identity, and every path and
     * URL built from this ref is keyed by it. */
    if (brix_oci_digest_format(&d, out->digest, sizeof(out->digest)) < 0) {
        return ref_fail(err, errlen, "digest too long");
    }
    out->has_digest = 1;
    return 0;
}

/* Return the final slash in the name span, if it has one. */
static const char
*ref_last_slash(const char *rest, size_t len)
{
    const char *slash = NULL;
    const char *p;

    for (p = rest; p < rest + len; p++) {
        if (*p == '/') {
            slash = p;
        }
    }
    return slash;
}

/* Pull a terminal tag from a name span and update its remaining name length. */
static int
ref_tag(const char *rest, const char *at, brix_oci_ref_t *out,
        size_t *name_len, char *err, size_t errlen)
{
    const char *start;
    const char *colon;
    size_t      tlen;

    *name_len = at != NULL ? (size_t) (at - rest) : strlen(rest);
    start = ref_last_slash(rest, *name_len);
    start = start != NULL ? start : rest;
    colon = memchr(start, ':', (size_t) (rest + *name_len - start));
    if (colon == NULL) {
        memcpy(out->tag, "latest", 7);
        return 0;
    }
    tlen = (size_t) (rest + *name_len - colon - 1);
    if (tlen == 0 || tlen >= sizeof(out->tag) ||
        brix_oci_tag_valid(colon + 1, tlen) != 0) {
        return ref_fail(err, errlen, "invalid tag");
    }
    memcpy(out->tag, colon + 1, tlen);
    out->tag[tlen] = '\0';
    *name_len = (size_t) (colon - rest);
    return 0;
}

/* Store and validate the repository component after host/tag/digest parsing. */
static int
ref_name(const char *rest, size_t len, brix_oci_ref_t *out, char *err,
         size_t errlen)
{
    if (len == 0 || len >= sizeof(out->name)) {
        return ref_fail(err, errlen, "repository name empty or too long");
    }
    memcpy(out->name, rest, len);
    out->name[len] = '\0';
    if (brix_oci_name_valid(out->name, len) != 0) {
        return ref_fail(err, errlen, "invalid repository name");
    }
    return 0;
}

int
brix_oci_ref_parse(const char *s, brix_oci_ref_t *out, char *err,
                   size_t errlen)
{
    const char *at;
    const char *rest = s;
    size_t      n;

    memset(out, 0, sizeof(*out));
    if (s == NULL || s[0] == '\0') {
        return ref_fail(err, errlen, "empty image reference");
    }
    if (ref_registry(&rest, out, err, errlen) != 0) {
        return -1;
    }

    /* [@digest] first — it may contain ':' and must not confuse the tag. */
    at = strchr(rest, '@');
    if (ref_digest(at, out, err, errlen) != 0 ||
        ref_tag(rest, at, out, &n, err, errlen) != 0) {
        return -1;
    }
    return ref_name(rest, n, out, err, errlen);
}
