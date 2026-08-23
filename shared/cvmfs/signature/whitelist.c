/* whitelist.c — parse a CVMFS .cvmfswhitelist. See whitelist.h. */
#include "cvmfs/signature/whitelist.h"

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>

/* "YYYYMMDDhhmmss" (14 digits) → epoch seconds (UTC). Returns 0 on bad input. */
static long parse_expiry(const unsigned char *p, size_t n) {
    if (n < 14) return 0;

    char d[15];
    memcpy(d, p, 14);
    d[14] = '\0';
    for (int i = 0; i < 14; i++)
        if (d[i] < '0' || d[i] > '9') return 0;

    struct tm tm;
    char      f[5];
    memset(&tm, 0, sizeof(tm));
    memcpy(f, d,      4); f[4] = '\0'; tm.tm_year = atoi(f) - 1900;
    memcpy(f, d + 4,  2); f[2] = '\0'; tm.tm_mon  = atoi(f) - 1;
    memcpy(f, d + 6,  2); f[2] = '\0'; tm.tm_mday = atoi(f);
    memcpy(f, d + 8,  2); f[2] = '\0'; tm.tm_hour = atoi(f);
    memcpy(f, d + 10, 2); f[2] = '\0'; tm.tm_min  = atoi(f);
    memcpy(f, d + 12, 2); f[2] = '\0'; tm.tm_sec  = atoi(f);
    return (long) timegm(&tm);
}

/* AA:BB:... — hex pairs separated by ':', length >= 8. */
static int is_fp_line(const unsigned char *p, size_t n) {
    if (n < 8) return 0;
    for (size_t i = 0; i < n; i++) {
        char c   = (char) p[i];
        int  hex = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
        if (!hex && c != ':') return 0;
    }
    return 1;
}

static size_t find_marker(const unsigned char *b, size_t len) {
    for (size_t i = 0; i + 3 < len; i++) {
        if (b[i] == '\n' && b[i + 1] == '-' && b[i + 2] == '-' && b[i + 3] == '\n')
            return i + 1;
    }
    return (size_t) -1;
}

typedef struct {
    size_t lineno;
    long   explicit_expiry;
    long   first_timestamp;
} whitelist_body_state_t;

/*
 * WHAT: Recognize an authoritative E-prefixed whitelist expiry line.
 * WHY:  Certificate fingerprints can also begin with E followed by a digit.
 * HOW:  Require E plus fourteen consecutive decimal digits before accepting it.
 */
static int is_expiry_line(const unsigned char *line, size_t len) {
    size_t i;

    if (len < 15 || line[0] != 'E')
        return 0;
    for (i = 1; i <= 14; i++)
        if (line[i] < '0' || line[i] > '9')
            return 0;
    return 1;
}

/*
 * WHAT: Store the repository binding from an N-prefixed whitelist line.
 * WHY:  The client compares this bounded value with its requested repository.
 * HOW:  Truncate to the destination capacity, copy, and terminate explicitly.
 */
static void store_repo_name(cvmfs_whitelist_t *out,
                            const unsigned char *line, size_t len) {
    size_t copy_len = len - 1;

    if (copy_len >= sizeof(out->repo_name))
        copy_len = sizeof(out->repo_name) - 1;
    memcpy(out->repo_name, line + 1, copy_len);
    out->repo_name[copy_len] = '\0';
}

/*
 * WHAT: Store a valid leading fingerprint token from a whitelist line.
 * WHY:  Fingerprint lines may carry whitespace and trailing comments.
 * HOW:  Bound the first token, validate its grammar, and append within the cap.
 */
static void store_fingerprint(cvmfs_whitelist_t *out,
                              const unsigned char *line, size_t len) {
    size_t token_len = 0;
    size_t copy_len;

    while (token_len < len && line[token_len] != ' ' &&
           line[token_len] != '\t' && line[token_len] != '#')
        token_len++;
    if (!is_fp_line(line, token_len) || out->n_fingerprints >= 16)
        return;
    copy_len = token_len < 59 ? token_len : 59;
    memcpy(out->fingerprints[out->n_fingerprints], line, copy_len);
    out->fingerprints[out->n_fingerprints][copy_len] = '\0';
    out->n_fingerprints++;
}

/*
 * WHAT: Apply one unsigned whitelist body line to parser state.
 * WHY:  Expiry, repository, and fingerprint lines have distinct grammars.
 * HOW:  Dispatch by unambiguous form and preserve line-zero expiry fallback.
 */
static void parse_body_line(cvmfs_whitelist_t *out,
                            whitelist_body_state_t *state,
                            const unsigned char *line, size_t len) {
    if (is_expiry_line(line, len)) {
        long expiry = parse_expiry(line + 1, len - 1);

        if (expiry > 0)
            state->explicit_expiry = expiry;
    } else if (state->lineno == 0) {
        state->first_timestamp = parse_expiry(line, len);
    } else if (len >= 1 && line[0] == 'N') {
        store_repo_name(out, line, len);
    } else {
        store_fingerprint(out, line, len);
    }
    state->lineno++;
}

/*
 * WHAT: Parse all unsigned whitelist body lines before the signature marker.
 * WHY:  Body field extraction must remain separate from signed-tail framing.
 * HOW:  Walk newline-delimited spans and apply each through parse_body_line.
 */
static int parse_body(const unsigned char *buf, size_t marker,
                      cvmfs_whitelist_t *out) {
    whitelist_body_state_t state = {0};
    size_t                 offset = 0;

    while (offset < marker) {
        size_t end = offset;

        while (end < marker && buf[end] != '\n')
            end++;
        parse_body_line(out, &state, buf + offset, end - offset);
        offset = end + 1;
    }
    out->expiry_utc = state.explicit_expiry > 0 ? state.explicit_expiry
                                                 : state.first_timestamp;
    return out->expiry_utc == 0 ? -1 : 0;
}

/*
 * WHAT: Frame the signed hash line and opaque signature after the body marker.
 * WHY:  Signature verification needs both the exact printed hash and raw bytes.
 * HOW:  Locate the newline, parse the bounded hash, and expose remaining bytes.
 */
static int parse_signed_tail(const unsigned char *buf, size_t len,
                             size_t marker, cvmfs_whitelist_t *out) {
    size_t p;
    size_t h;

    out->signed_body = buf;
    out->signed_body_len = marker + 3;
    p = out->signed_body_len;
    h = p;
    while (h < len && buf[h] != '\n')
        h++;
    if (h >= len)
        return -1;
    cvmfs_hash_parse((const char *) buf + p, h - p, &out->signed_hash);
    out->signed_hash_text = buf + p;
    out->signed_hash_text_len = h - p;
    out->signature = buf + h + 1;
    out->signature_len = len - (h + 1);
    return out->signature_len == 0 ? -1 : 0;
}

int cvmfs_whitelist_parse(const unsigned char *buf, size_t len,
                          cvmfs_whitelist_t *out) {
    size_t marker;

    memset(out, 0, sizeof(*out));
    marker = find_marker(buf, len);
    if (marker == (size_t) -1)
        return -1;
    if (parse_body(buf, marker, out) != 0)
        return -1;
    return parse_signed_tail(buf, len, marker, out);
}

int cvmfs_whitelist_lists_fp(const cvmfs_whitelist_t *w, const char *fp_hex) {
    for (size_t i = 0; i < w->n_fingerprints; i++)
        if (strcasecmp(w->fingerprints[i], fp_hex) == 0) return 1;
    return 0;
}

int cvmfs_whitelist_expired(const cvmfs_whitelist_t *w, long now_utc) {
    return now_utc > w->expiry_utc ? 1 : 0;
}
