/* classify.c — CVMFS URL classifier.
 *
 * WHAT: maps a request path onto the five CVMFS traffic classes (immutable CAS
 *       object / mutable signed metadata / geo API / bundle batch-fetch /
 *       reject).
 * WHY:  the whole cache policy — TTL, verification, pass-through, guard — keys
 *       off the class; classifying in one pure function keeps policy testable
 *       without nginx and reusable from both dispatch and the fill verifier.
 * HOW:  hand-rolled prefix walk (no regex, no alloc): "/cvmfs/" + repo token
 *       ([a-z0-9.-]+, dots not leading) + one of the three known shapes.
 */
#include "cvmfs/grammar/classify.h"

#include <string.h>

static int hexlc(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }

static int repo_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-';
}

static int is_cas_suffix(char c) {
    return c == 'C' || c == 'H' || c == 'X' || c == 'M' || c == 'L' || c == 'P';
}

/* A digest's total hex length is standard iff it is one CVMFS ever publishes:
 * 40 (sha1/rmd160), 64 (sha256), 96 (sha384), 128 (sha512). No official hash
 * has any other length, so an in-range odd length (e.g. 41 = 40 hex + a folded
 * lowercase 'c') is not CVMFS traffic and must be rejected. */
static int cas_hexlen_standard(size_t t) {
    return t == 40 || t == 64 || t == 96 || t == 128;
}

/* "<2hex>/<hex...>[suffix]" after ".../data/". Returns 0 on valid CAS. */
static int parse_cas(const char *p, size_t n, cvmfs_url_info_t *out) {
    size_t hexn;

    if (n < 3 || !hexlc(p[0]) || !hexlc(p[1]) || p[2] != '/')
        return -1;
    p += 3; n -= 3;
    for (hexn = 0; hexn < n && hexlc(p[hexn]); hexn++) { /* count hex run */ }
    if (!cas_hexlen_standard(hexn + 2))      /* sha1=40/sha256=64/384/512 */
        return -1;
    if (hexn == n) {
        out->cas_suffix = 0;
    } else if (hexn + 1 == n && is_cas_suffix(p[hexn])) {
        out->cas_suffix = p[hexn];
    } else {
        return -1;
    }
    out->cas_hex[0] = p[-3];                 /* re-join the 2-hex dir     */
    out->cas_hex[1] = p[-2];
    memcpy(out->cas_hex + 2, p, hexn);
    out->cas_hex_len = hexn + 2;
    out->cas_hex[out->cas_hex_len] = '\0';
    out->cls = CVMFS_URL_CAS;
    return 0;
}

/*
 * WHAT: Compare a bounded relative path with one complete literal.
 * WHY:  Metadata classification needs exact names rather than prefix matches.
 * HOW:  Require the same byte length before comparing the literal contents.
 */
static int rel_equals(const char *rel, size_t len, const char *literal) {
    size_t literal_len = strlen(literal);

    return len == literal_len && memcmp(rel, literal, len) == 0;
}

/*
 * WHAT: Classify a validated repository-relative CVMFS path.
 * WHY:  Repository grammar and traffic-class grammar are independent concerns.
 * HOW:  Match the known CAS, metadata, API, bundle, and dictionary shapes.
 */
static void classify_relative(cvmfs_url_info_t *out) {
    const char *rel = out->rel;
    size_t      len = out->rel_len;

    if (len >= 6 && memcmp(rel, "data/", 5) == 0) {
        (void) parse_cas(rel + 5, len - 5, out);
    } else if (rel_equals(rel, len, ".cvmfspublished") ||
               rel_equals(rel, len, ".cvmfswhitelist") ||
               rel_equals(rel, len, ".cvmfsreflog")) {
        out->cls = CVMFS_URL_MANIFEST;
    } else if (len > 13 && memcmp(rel, "api/v1.0/geo/", 13) == 0) {
        out->cls = CVMFS_URL_GEO;
    } else if (rel_equals(rel, len, ".cvmfs-bundle")) {
        out->cls = CVMFS_URL_BUNDLE;
    } else if (len > 12 && memcmp(rel, ".cvmfs-dict/", 12) == 0) {
        out->cls = CVMFS_URL_DICT;
    }
}

/*
 * WHAT: Split a CVMFS path suffix into repository and relative-path spans.
 * WHY:  Every traffic class requires the same strict repository token grammar.
 * HOW:  Consume repository bytes, require its separator, and expose both spans.
 */
static int split_repository(const char *begin, const char *end,
                            cvmfs_url_info_t *out) {
    const char *cursor = begin;
    size_t      repo_len;

    while (cursor < end && repo_char(*cursor))
        cursor++;
    repo_len = (size_t) (cursor - begin);
    if (repo_len == 0 || begin[0] == '.' || cursor >= end || *cursor != '/')
        return -1;
    out->repo = begin;
    out->repo_len = repo_len;
    cursor++;
    out->rel = cursor;
    out->rel_len = (size_t) (end - cursor);
    return 0;
}

int cvmfs_classify_url(const char *path, size_t len, cvmfs_url_info_t *out) {
    static const char pfx[] = "/cvmfs/";
    const char       *begin;
    const char       *end;

    memset(out, 0, sizeof(*out));
    out->cls = CVMFS_URL_REJECT;

    if (len <= sizeof(pfx) - 1 || memcmp(path, pfx, sizeof(pfx) - 1) != 0)
        return 0;
    begin = path + sizeof(pfx) - 1;
    end = path + len;
    if (split_repository(begin, end, out) != 0)
        return 0;
    classify_relative(out);
    return 0;
}
