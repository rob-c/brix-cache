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

int cvmfs_whitelist_parse(const unsigned char *buf, size_t len, cvmfs_whitelist_t *out) {
    memset(out, 0, sizeof(*out));

    size_t marker = find_marker(buf, len);
    if (marker == (size_t) -1) return -1;

    /* Real CVMFS whitelists put the authoritative expiry on the "E<14 digits>"
     * line; line 0 is the *creation* timestamp. Older/synthetic whitelists have
     * only the line-0 timestamp — use it as a fallback. Fingerprint lines may
     * carry a trailing "# comment", so only the leading token is the fingerprint. */
    size_t i = 0, lineno = 0;
    long   e_expiry = 0, first_ts = 0;
    while (i < marker) {
        size_t j = i;
        while (j < marker && buf[j] != '\n') j++;
        size_t n = j - i;
        const unsigned char *L = buf + i;

        /* "E<14 digits>" authoritative-expiry line. Disambiguate from a
         * FINGERPRINT that also starts with 'E' — not just "EA:74:..." (2nd char
         * a hex letter) but ALSO "E8:49:..." whenever the signing cert's SHA-1
         * first byte is 0xE0..0xE9 (~4% of certs). The old test looked at L[1]
         * alone, so an E0..E9 fingerprint was swallowed here and never stored,
         * and a perfectly valid mount then failed the trust gate with -9. A real
         * expiry line is 'E' followed by 14 consecutive DECIMAL digits; a
         * fingerprint breaks that run at its ':' (index 2). */
        int is_e_expiry = (n >= 15 && L[0] == 'E');
        for (size_t k = 1; is_e_expiry && k <= 14; k++) {
            if (L[k] < '0' || L[k] > '9') is_e_expiry = 0;
        }
        if (is_e_expiry) {
            long e = parse_expiry(L + 1, n - 1);
            if (e > 0) e_expiry = e;
        } else if (lineno == 0) {
            first_ts = parse_expiry(L, n);
        } else if (n >= 1 && L[0] == 'N') {
            /* "N<fqrn>" — binds the whitelist to one repository. A fingerprint
             * never starts with 'N' (hex alphabet is 0-9A-F), so this is
             * unambiguous. Last write wins; kept for the client's repo check. */
            size_t c = n - 1 < sizeof(out->repo_name) - 1 ? n - 1 : sizeof(out->repo_name) - 1;
            memcpy(out->repo_name, L + 1, c);
            out->repo_name[c] = '\0';
        } else {
            size_t t = 0;
            while (t < n && L[t] != ' ' && L[t] != '\t' && L[t] != '#') t++;
            if (is_fp_line(L, t) && out->n_fingerprints < 16) {
                size_t c = t < 59 ? t : 59;
                memcpy(out->fingerprints[out->n_fingerprints], L, c);
                out->fingerprints[out->n_fingerprints][c] = '\0';
                out->n_fingerprints++;
            }
        }
        lineno++;
        i = j + 1;
    }
    out->expiry_utc = e_expiry > 0 ? e_expiry : first_ts;
    if (out->expiry_utc == 0) return -1;

    out->signed_body = buf;
    out->signed_body_len = marker + 3;

    size_t p = out->signed_body_len;
    size_t h = p;
    while (h < len && buf[h] != '\n') h++;   /* the hash line is the signed text */
    if (h >= len) return -1;
    cvmfs_hash_parse((const char *) buf + p, h - p, &out->signed_hash);
    out->signed_hash_text = buf + p;
    out->signed_hash_text_len = h - p;
    out->signature = buf + h + 1;
    out->signature_len = len - (h + 1);
    return out->signature_len == 0 ? -1 : 0;
}

int cvmfs_whitelist_lists_fp(const cvmfs_whitelist_t *w, const char *fp_hex) {
    for (size_t i = 0; i < w->n_fingerprints; i++)
        if (strcasecmp(w->fingerprints[i], fp_hex) == 0) return 1;
    return 0;
}

int cvmfs_whitelist_expired(const cvmfs_whitelist_t *w, long now_utc) {
    return now_utc > w->expiry_utc ? 1 : 0;
}
