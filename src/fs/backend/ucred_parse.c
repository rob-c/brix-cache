/*
 * ucred_parse.c — credential-file format parsers for the ucred helper.
 *
 * WHAT: Implements the four credential-file readers declared in
 *       ucred_internal.h — x509 PEM expiry check, bearer .token reader,
 *       .s3 SigV4 triple parser, and CephX .keyring section-header parser —
 *       plus their per-format static line-scanning helpers.
 *
 * WHY:  These format parsers are the bulk of the ucred implementation; keeping
 *       them in their own translation unit keeps both ucred.c and this file
 *       under the file-size guard.  brix_sd_ucred_resolve() (ucred.c) is the
 *       sole caller of the four readers via ucred_internal.h.
 *
 * HOW:  Static pure helpers (line-end/EOL/keyring scanners) keep side effects
 *       at the edges; each reader opens O_RDONLY|O_NOFOLLOW|O_CLOEXEC, reads a
 *       bounded chunk, parses, and cleanses any secret scratch on exit.
 */
#include "ucred.h"
#include "ucred_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

/* ---- Classify one candidate credential file ----
 * WHAT: NGX_OK valid; NGX_DECLINED absent/unreadable/unparseable;
 *       NGX_DECLINED with *expired=1 when parseable but past notAfter.
 * WHY:  Expiry must be checked at the moment of use — a proxy can lapse
 *       between the request open and a deferred flush.
 * HOW:  1. fopen; 2. PEM_read_X509 (first block = the proxy cert);
 *       3. X509_cmp_current_time(notAfter) must be > 0. */
ngx_int_t
ucred_check_pem(const char *path, int *expired)
{
    FILE *f;
    X509 *cert;
    int   cmp;

    *expired = 0;
    f = fopen(path, "r");
    if (f == NULL) {
        return NGX_DECLINED;
    }
    cert = PEM_read_X509(f, NULL, NULL, NULL);
    (void) fclose(f);   /* read-only stream — nothing buffered to lose */
    if (cert == NULL) {
        return NGX_DECLINED;                  /* unparseable = treated missing */
    }
    cmp = X509_cmp_current_time(X509_get0_notAfter(cert));
    X509_free(cert);
    if (cmp <= 0) {
        *expired = 1;
        return NGX_DECLINED;
    }
    return NGX_OK;
}

/* ---- Read a bearer token from a .token file --------------------------------
 * WHAT: Opens `path` (O_RDONLY|O_NOFOLLOW|O_CLOEXEC), reads at most cap-1
 *       bytes, trims at the first CR, LF, space, or NUL, and copies the
 *       result into out_bearer.  Returns NGX_OK on success; NGX_DECLINED when
 *       the file is absent/unreadable or the trimmed value is empty.
 * WHY:  Bearer tokens have no X.509 notAfter field — the token's own exp claim
 *       is enforced by the origin server at authentication time.  Expiry checking
 *       is therefore the origin's responsibility; we only validate that the file
 *       contains a non-empty string.  O_NOFOLLOW prevents a symlink from
 *       escaping the credential directory.
 * HOW:  1. open with O_RDONLY|O_NOFOLLOW|O_CLOEXEC; absent → DECLINED.
 *       2. read up to cap-1 bytes into a stack buffer.
 *       3. Trim at the first whitespace/NUL character.
 *       4. Reject an empty result → DECLINED; copy into out_bearer → OK. */
ngx_int_t
ucred_read_token(const char *path, char *out_bearer, size_t cap)
{
    char    buf[BRIX_UCRED_BEARER_MAX];
    ssize_t n;
    size_t  end;
    int     fd;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return NGX_DECLINED;
    }
    n = read(fd, buf, cap - 1);
    close(fd);
    if (n <= 0) {
        return NGX_DECLINED;
    }
    buf[n] = '\0';

    /* Trim at the first whitespace or embedded NUL — tokens must be a single
     * word with no embedded spaces, CRs, or LFs. */
    for (end = 0; end < (size_t) n; end++) {
        unsigned char c = (unsigned char) buf[end];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t' || c == '\0') {
            break;
        }
    }
    if (end == 0) {
        OPENSSL_cleanse(buf, (size_t) n);   /* scratch held a bearer token */
        return NGX_DECLINED;    /* empty after trimming */
    }
    memcpy(out_bearer, buf, end);
    out_bearer[end] = '\0';
    OPENSSL_cleanse(buf, (size_t) n);       /* wipe the secret from the stack */
    return NGX_OK;
}

/* ---- Trim one line from a read buffer at CR/LF, return its length --------
 * WHAT: Scans buf[start..end) for the first CR or LF and returns the offset
 *       of that terminator (or `end` if none found before the buffer end).
 * WHY:  Shared by ucred_read_s3's 3-line parse; keeps the line-splitting
 *       logic in one place instead of duplicating a scan-for-newline loop
 *       three times.
 * HOW:  Linear scan; no allocation. */
static size_t
ucred_line_end(const char *buf, size_t start, size_t end)
{
    size_t i;

    for (i = start; i < end; i++) {
        if (buf[i] == '\r' || buf[i] == '\n') {
            return i;
        }
    }
    return end;
}

/* ---- Advance past exactly ONE line terminator (\r\n, \n, or \r) ----------
 * WHAT: Given `pos` pointing at a CR/LF (as returned by ucred_line_end) or at
 *       `end` (no terminator found), returns the offset of the next line's
 *       first byte: pos+2 for "\r\n", pos+1 for a lone "\r" or "\n", or `end`
 *       unchanged when pos already equals end.
 * WHY:  A single-terminator skip (as opposed to skipping ALL consecutive
 *       CR/LF bytes) is required so an intentionally blank line — e.g. an
 *       empty secret-key field in a malformed .s3 file — is preserved as a
 *       zero-length field for the caller to reject, instead of being
 *       silently swallowed together with the next line's terminator.
 * HOW:  Bounds-checked lookahead for the 2-byte CRLF case; else advance 1. */
static size_t
ucred_skip_eol(const char *buf, size_t pos, size_t end)
{
    if (pos >= end) {
        return end;
    }
    if (buf[pos] == '\r' && pos + 1 < end && buf[pos + 1] == '\n') {
        return pos + 2;
    }
    return pos + 1;
}

/* ---- Read an S3 access-key/secret-key/region triple from a .s3 file ------
 * WHAT: Opens `path` (O_RDONLY|O_NOFOLLOW|O_CLOEXEC), reads a bounded chunk,
 *       and parses up to 3 CR/LF-terminated lines: line 1 = access key id
 *       (required, non-empty), line 2 = secret key (required, non-empty),
 *       line 3 = region (optional; "us-east-1" when absent or empty).
 *       Fills out_ak/out_sk/out_region.  Returns NGX_OK on a well-formed
 *       file, NGX_DECLINED when the file is absent/unreadable, either
 *       required line is missing/empty, or any field would overflow its
 *       output buffer.
 * WHY:  S3-backed exports need a per-user SigV4 credential (phase-3 T3),
 *       mirroring the .pem/.token precedence chain with a third, simpler
 *       file format (no ASN.1/JWT parsing — just delimited plaintext).
 *       O_NOFOLLOW prevents a symlink from escaping the credential
 *       directory, matching ucred_read_token's hardening.
 * HOW:  1. open + bounded read into a stack buffer.
 *       2. ucred_line_end three times to locate line boundaries.
 *       3. Reject empty ak or sk → DECLINED.
 *       4. memcpy each field with an explicit NUL; overflow → DECLINED.
 *       5. Empty/absent region line → default "us-east-1". */
ngx_int_t
ucred_read_s3(const char *path, char *out_ak, size_t ak_cap,
    char *out_sk, size_t sk_cap, char *out_region, size_t region_cap)
{
    char    buf[BRIX_UCRED_S3_AK_MAX + BRIX_UCRED_S3_SK_MAX
                + BRIX_UCRED_S3_REGION_MAX + 8];
    ssize_t n;
    size_t  ak_start, ak_end, sk_start, sk_end, rg_start, rg_end, rg_len;
    int     fd;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return NGX_DECLINED;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return NGX_DECLINED;
    }
    buf[n] = '\0';

    /* Line 1: access key id. */
    ak_start = 0;
    ak_end   = ucred_line_end(buf, ak_start, (size_t) n);
    if (ak_end == ak_start || (ak_end - ak_start) >= ak_cap) {
        OPENSSL_cleanse(buf, sizeof(buf));  /* scratch held the secret key */
        return NGX_DECLINED;
    }

    /* Line 2: secret key. Skip exactly the ONE line terminator after line 1
     * (not all consecutive CR/LF bytes — a blank line must stay a zero-length
     * field, not be merged into the following line). */
    sk_start = ucred_skip_eol(buf, ak_end, (size_t) n);
    sk_end   = ucred_line_end(buf, sk_start, (size_t) n);
    if (sk_end == sk_start || (sk_end - sk_start) >= sk_cap) {
        OPENSSL_cleanse(buf, sizeof(buf));
        return NGX_DECLINED;
    }

    /* Line 3: region (optional). */
    rg_start = ucred_skip_eol(buf, sk_end, (size_t) n);
    rg_end  = ucred_line_end(buf, rg_start, (size_t) n);
    rg_len  = rg_end - rg_start;
    if (rg_len >= region_cap) {
        OPENSSL_cleanse(buf, sizeof(buf));
        return NGX_DECLINED;
    }

    memcpy(out_ak, buf + ak_start, ak_end - ak_start);
    out_ak[ak_end - ak_start] = '\0';
    memcpy(out_sk, buf + sk_start, sk_end - sk_start);
    out_sk[sk_end - sk_start] = '\0';
    if (rg_len == 0) {
        snprintf(out_region, region_cap, "us-east-1");
    } else {
        memcpy(out_region, buf + rg_start, rg_len);
        out_region[rg_len] = '\0';
    }
    OPENSSL_cleanse(buf, sizeof(buf));   /* wipe the secret key from the stack */
    return NGX_OK;
}

/* ---- Read a CephX user id from a `[client.NAME]` keyring section header --
 * WHAT: Opens `path` (O_RDONLY|O_NOFOLLOW|O_CLOEXEC), reads a bounded chunk,
 *       and scans for the FIRST line of the form "[client.NAME]" (leading/
 *       trailing whitespace around the brackets tolerated).  Fills out_path
 *       with `path` itself (the keyring PATH — librados reads the file, we
 *       never parse the key material) and out_user with the bare id NAME
 *       (no "client." prefix).  Returns NGX_OK on a well-formed keyring,
 *       NGX_DECLINED when the file is absent/unreadable or no
 *       "[client.NAME]" section header is found.
 * WHY:  A `<key>.keyring` credential (ceph-peruser item) lets the driver
 *       authenticate to RADOS as a specific CephX user instead of the export's
 *       static service credential.  librados's rados_create() wants the bare
 *       id (it re-adds "client." itself — see sd_ceph_user_id in sd_ceph.c),
 *       so the bare id is what this parser stores.  O_NOFOLLOW prevents a
 *       symlink from escaping the credential directory, matching
 *       ucred_read_token/ucred_read_s3's hardening.
 * HOW:  1. open + bounded read into a stack buffer.
 *       2. Line-scan for "[client." ... "]"; extract the id between them.
 *       3. Reject an empty id or overflow → DECLINED; else fill out_user and
 *          out_path (verbatim `path`) → OK. */
/* ---- Advance `i` to the start of the next line (past the next '\n') -------
 * WHAT: Returns the offset of the first byte after the next '\n' at or after
 *       `i`, or `end` when no '\n' remains.
 * WHY:  ucred_keyring_parse_line uses this to resume scanning after a line
 *       that is not a usable "[client.NAME]" header; factoring it out removes
 *       the three duplicated scan-to-newline loops that inflated the caller's
 *       cyclomatic complexity.
 * HOW:  Linear scan to the terminator; return terminator+1 (bounded by end). */
static size_t
ucred_keyring_next_line(const char *buf, size_t i, size_t end)
{
    while (i < end && buf[i] != '\n') {
        i++;
    }
    if (i < end) {
        i++;    /* step past the '\n' */
    }
    return i;
}

/* ---- Parse one keyring line for a "[client.NAME]" section header ----------
 * WHAT: Examines the line beginning at `line`.  On a well-formed
 *       "[client.NAME]" header, sets out->id_start/out->id_len to the bare
 *       NAME span and returns NGX_OK.  On any other line returns NGX_DECLINED
 *       and sets out->next to the start of the following line so the caller
 *       keeps scanning.
 * WHY:  Isolates the header-recognition branching (whitespace skip, bracket,
 *       "client." prefix, closing bracket) from ucred_read_keyring's loop,
 *       collapsing that loop to a single dispatch on this helper's result.
 * HOW:  1. skip leading spaces/tabs; 2. require '['; 3. require "client.";
 *       4. locate the closing ']' before EOL; on any miss, compute out->next
 *       via ucred_keyring_next_line and return NGX_DECLINED. */
typedef struct {
    size_t id_start;    /* offset of the bare NAME span (valid iff NGX_OK) */
    size_t id_len;      /* length of the bare NAME span (valid iff NGX_OK) */
    size_t next;        /* start of the next line (valid iff NGX_DECLINED) */
} ucred_keyring_line_t;

static ngx_int_t
ucred_keyring_parse_line(const char *buf, size_t line, size_t end,
    ucred_keyring_line_t *out)
{
    size_t i = line;
    size_t j, start, stop;

    out->id_start = 0;
    out->id_len   = 0;
    out->next     = end;

    while (i < end && (buf[i] == ' ' || buf[i] == '\t')) {
        i++;
    }
    if (i >= end || buf[i] != '[') {
        out->next = ucred_keyring_next_line(buf, i, end);
        return NGX_DECLINED;
    }
    j = i + 1;
    if (j + 7 > end || strncmp(buf + j, "client.", 7) != 0) {
        out->next = ucred_keyring_next_line(buf, i, end);
        return NGX_DECLINED;
    }
    start = j + 7;
    stop  = start;
    while (stop < end && buf[stop] != ']' && buf[stop] != '\n') {
        stop++;
    }
    if (stop >= end || buf[stop] != ']') {
        out->next = ucred_keyring_next_line(buf, i, end);
        return NGX_DECLINED;
    }
    out->id_start = start;
    out->id_len   = stop - start;
    return NGX_OK;
}

ngx_int_t
ucred_read_keyring(const char *path, char *out_path, size_t path_cap,
    char *out_user, size_t user_cap)
{
    char    buf[4096];
    ssize_t n;
    size_t  i, end;
    int     fd;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return NGX_DECLINED;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return NGX_DECLINED;
    }
    buf[n] = '\0';
    end = (size_t) n;

    i = 0;
    while (i < end) {
        ucred_keyring_line_t line = { 0, 0, end };

        if (ucred_keyring_parse_line(buf, i, end, &line) != NGX_OK) {
            i = line.next;
            continue;
        }

        if (line.id_len == 0 || line.id_len >= user_cap) {
            OPENSSL_cleanse(buf, sizeof(buf));  /* scratch held CephX key material */
            return NGX_DECLINED;    /* empty or oversized id: malformed */
        }
        memcpy(out_user, buf + line.id_start, line.id_len);
        out_user[line.id_len] = '\0';

        if (snprintf(out_path, path_cap, "%s", path) >= (int) path_cap) {
            OPENSSL_cleanse(buf, sizeof(buf));
            return NGX_DECLINED;
        }
        OPENSSL_cleanse(buf, sizeof(buf));      /* wipe key material from the stack */
        return NGX_OK;
    }

    OPENSSL_cleanse(buf, sizeof(buf));
    return NGX_DECLINED;    /* no "[client.NAME]" section header found */
}
