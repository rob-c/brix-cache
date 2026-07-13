/*
 * ucred.c — per-user backend-credential selection (phase-1 x509 + phase-2
 * bearer/.token + phase-3 T3 S3/.s3 + ceph-peruser .keyring). See ucred.h.
 *
 * WHAT: Implements the four public functions declared in ucred.h: principal
 *       extraction, filesystem-safe key derivation, single-key resolve, and
 *       identity-to-credential selection with expiry checking.
 *
 * WHY:  Backends acting on behalf of authenticated users need a per-user
 *       credential (x509 proxy, bearer token, S3 SigV4 triple, or CephX
 *       keyring).  Centralising the key-derivation and validation logic
 *       here prevents every backend from reimplementing (and diverging on)
 *       the search and validation semantics.
 *
 * HOW:  Static pure helpers (charset classifier, PEM expiry check, bearer/
 *       S3/keyring file parsers) keep side effects at the edges.  All four
 *       public functions are small and single-purpose; none allocates heap
 *       memory.
 */
#include "ucred.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

/* ---- Is `principal` usable verbatim as a credential filename stem? ----
 * WHAT: 1 iff principal matches [A-Za-z0-9@._][A-Za-z0-9@._-]{0,63}.
 * WHY:  Human-manageable filenames for token subs / S3 access keys; DNs
 *       (which contain '/') always fall through to the hash form.
 * HOW:  1. reject empty/oversized/leading '-'/leading '.'; 2. scan charset.
 *       Leading '.' is rejected for path-traversal / dotfile safety: "." and
 *       ".." would otherwise reach brix_sd_ucred_resolve as valid literals and
 *       produce paths like <dir>/../.pem — reads outside the credential dir. */
/* ---- Is one character allowed in a verbatim credential filename stem? ----
 * WHAT: 1 iff `c` is in [A-Za-z0-9@._-].
 * WHY:  Splitting the per-character charset test out of the scan loop keeps
 *       ucred_principal_fs_safe's cyclomatic complexity within the gate; the
 *       compound OR expression is the sole source of that function's branching.
 * HOW:  Range tests for the alnum classes plus the four literal specials. */
static int
ucred_fs_safe_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9') || c == '@' || c == '.'
        || c == '_' || c == '-';
}

static int
ucred_principal_fs_safe(const char *principal)
{
    size_t i, len = strlen(principal);

    if (len == 0 || len > 64 || principal[0] == '-' || principal[0] == '.') {
        return 0;
    }
    for (i = 0; i < len; i++) {
        if (!ucred_fs_safe_char(principal[i])) {
            return 0;
        }
    }
    return 1;
}

/* ---- Classify one candidate credential file ----
 * WHAT: NGX_OK valid; NGX_DECLINED absent/unreadable/unparseable;
 *       NGX_DECLINED with *expired=1 when parseable but past notAfter.
 * WHY:  Expiry must be checked at the moment of use — a proxy can lapse
 *       between the request open and a deferred flush.
 * HOW:  1. fopen; 2. PEM_read_X509 (first block = the proxy cert);
 *       3. X509_cmp_current_time(notAfter) must be > 0. */
static ngx_int_t
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
static ngx_int_t
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
        return NGX_DECLINED;    /* empty after trimming */
    }
    memcpy(out_bearer, buf, end);
    out_bearer[end] = '\0';
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
static ngx_int_t
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
        return NGX_DECLINED;
    }

    /* Line 2: secret key. Skip exactly the ONE line terminator after line 1
     * (not all consecutive CR/LF bytes — a blank line must stay a zero-length
     * field, not be merged into the following line). */
    sk_start = ucred_skip_eol(buf, ak_end, (size_t) n);
    sk_end   = ucred_line_end(buf, sk_start, (size_t) n);
    if (sk_end == sk_start || (sk_end - sk_start) >= sk_cap) {
        return NGX_DECLINED;
    }

    /* Line 3: region (optional). */
    rg_start = ucred_skip_eol(buf, sk_end, (size_t) n);
    rg_end  = ucred_line_end(buf, rg_start, (size_t) n);
    rg_len  = rg_end - rg_start;
    if (rg_len >= region_cap) {
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

static ngx_int_t
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
            return NGX_DECLINED;    /* empty or oversized id: malformed */
        }
        memcpy(out_user, buf + line.id_start, line.id_len);
        out_user[line.id_len] = '\0';

        if (snprintf(out_path, path_cap, "%s", path) >= (int) path_cap) {
            return NGX_DECLINED;
        }
        return NGX_OK;
    }

    return NGX_DECLINED;    /* no "[client.NAME]" section header found */
}

/*
 * brix_sd_ucred_principal — extract canonical principal string from identity.
 *
 * WHAT: Copies id->dn (if non-empty) else id->subject into buf as a
 *       NUL-terminated C string.
 * WHY:  DN is the richer identifier; subject (JWT sub / S3 key) is the
 *       fallback when no DN is present.
 * HOW:  Reject unauthenticated / both-empty / overflow; memcpy + NUL.
 */
ngx_int_t
brix_sd_ucred_principal(const brix_identity_t *id, char *buf, size_t cap)
{
    ngx_str_t src;

    if (id == NULL || !id->is_authenticated) {
        return NGX_ERROR;
    }
    if (id->dn.len > 0) {
        src = id->dn;
    } else if (id->subject.len > 0) {
        src = id->subject;
    } else {
        return NGX_ERROR;
    }
    if (src.len >= cap) {
        return NGX_ERROR;
    }
    memcpy(buf, src.data, src.len);
    buf[src.len] = '\0';
    return NGX_OK;
}

/*
 * brix_sd_ucred_key — derive a filesystem-safe filename stem from a principal.
 *
 * WHAT: Literal verbatim when fs-safe; "x5h-" + first 32 hex chars of
 *       SHA256(principal) otherwise.
 * WHY:  DNs contain '/' and other shell-hostile chars; the hash form gives
 *       a stable, collision-resistant, admin-provisionable name.
 * HOW:  Classify; literal snprintf or SHA256 + hex-encode first 16 bytes.
 */
ngx_int_t
brix_sd_ucred_key(const char *principal, char *key, size_t cap)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int           n;

    if (principal == NULL || principal[0] == '\0') {
        return NGX_ERROR;
    }
    if (ucred_principal_fs_safe(principal)) {
        n = snprintf(key, cap, "%s", principal);
        if (n < 0 || (size_t) n >= cap) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }
    SHA256((const unsigned char *) principal, strlen(principal), digest);
    n = snprintf(key, cap,
        "x5h-%02x%02x%02x%02x%02x%02x%02x%02x"
            "%02x%02x%02x%02x%02x%02x%02x%02x",
        digest[0],  digest[1],  digest[2],  digest[3],
        digest[4],  digest[5],  digest[6],  digest[7],
        digest[8],  digest[9],  digest[10], digest[11],
        digest[12], digest[13], digest[14], digest[15]);
    if (n < 0 || (size_t) n >= cap) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * brix_sd_ucred_resolve — look up a credential file by its exact key.
 *
 * WHAT: Tries <dir>/<key>.pem (x509, expiry-checked) then, only when the .pem
 *       is ABSENT, <dir>/<key>.token (bearer, no expiry check).  Fills *out on
 *       success (is_bearer=0 for x509, is_bearer=1 for bearer).
 * WHY:  Flush/write paths already know the key and need a fresh expiry check
 *       without re-running principal derivation.  An expired .pem is a hard
 *       DECLINED — the .token file is NOT tried as a fallback (the operator
 *       must fix the proxy; silent promotion to bearer would change identity).
 * HOW:  1. snprintf .pem path; overflow → NGX_ERROR.
 *       2. ucred_check_pem: NGX_OK → x509 path, return OK.
 *          expired (expired=1) → set out->expired, return DECLINED immediately.
 *          absent (expired=0) → fall through to .token probe.
 *       3. ucred_read_token on .token path: NGX_OK → bearer path, return OK;
 *          else → return DECLINED.
 */
ngx_int_t
brix_sd_ucred_resolve(const char *dir, const char *key, brix_sd_ucred_t *out)
{
    char      pem_path[BRIX_UCRED_PATH_MAX];
    char      tok_path[BRIX_UCRED_PATH_MAX];
    char      s3_path[BRIX_UCRED_PATH_MAX];
    char      keyring_path[BRIX_UCRED_PATH_MAX];
    int       n, expired;
    ngx_int_t pem_rc;

    n = snprintf(pem_path, sizeof(pem_path), "%s/%s.pem", dir, key);
    if (n < 0 || (size_t) n >= sizeof(pem_path)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    pem_rc = ucred_check_pem(pem_path, &expired);
    if (pem_rc == NGX_OK) {
        snprintf(out->path, sizeof(out->path), "%s", pem_path);
        snprintf(out->key,  sizeof(out->key),  "%s", key);
        out->expired   = 0;
        out->is_bearer = 0;
        out->is_s3     = 0;
        out->is_ceph   = 0;
        out->bearer[0] = '\0';
        return NGX_OK;
    }

    /* Hard stop on an expired .pem: never fall through to .token or .s3.
     * The operator must renew the proxy; silently promoting to bearer/s3
     * would change the presented identity without the admin's intent. */
    if (expired) {
        out->expired = 1;
        return NGX_DECLINED;
    }

    /* .pem is absent (not expired) — probe the .token file. */
    n = snprintf(tok_path, sizeof(tok_path), "%s/%s.token", dir, key);
    if (n < 0 || (size_t) n >= sizeof(tok_path)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    if (ucred_read_token(tok_path, out->bearer, sizeof(out->bearer)) == NGX_OK) {
        snprintf(out->path, sizeof(out->path), "%s", tok_path);
        snprintf(out->key,  sizeof(out->key),  "%s", key);
        out->expired   = 0;
        out->is_bearer = 1;
        out->is_s3     = 0;
        out->is_ceph   = 0;
        return NGX_OK;
    }

    /* Neither .pem nor .token — probe the .s3 file (phase-3 T3). */
    n = snprintf(s3_path, sizeof(s3_path), "%s/%s.s3", dir, key);
    if (n < 0 || (size_t) n >= sizeof(s3_path)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    if (ucred_read_s3(s3_path, out->s3_ak, sizeof(out->s3_ak),
            out->s3_sk, sizeof(out->s3_sk),
            out->s3_region, sizeof(out->s3_region)) == NGX_OK) {
        snprintf(out->path, sizeof(out->path), "%s", s3_path);
        snprintf(out->key,  sizeof(out->key),  "%s", key);
        out->expired   = 0;
        out->is_bearer = 0;
        out->is_s3     = 1;
        out->is_ceph   = 0;
        return NGX_OK;
    }

    /* Neither .pem, .token, nor .s3 — probe the .keyring file (CephX,
     * ceph-peruser item). */
    n = snprintf(keyring_path, sizeof(keyring_path), "%s/%s.keyring", dir, key);
    if (n < 0 || (size_t) n >= sizeof(keyring_path)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    if (ucred_read_keyring(keyring_path, out->ceph_keyring,
            sizeof(out->ceph_keyring), out->ceph_user,
            sizeof(out->ceph_user)) != NGX_OK) {
        return NGX_DECLINED;
    }
    snprintf(out->path, sizeof(out->path), "%s", keyring_path);
    snprintf(out->key,  sizeof(out->key),  "%s", key);
    out->expired   = 0;
    out->is_bearer = 0;
    out->is_s3     = 0;
    out->is_ceph   = 1;
    return NGX_OK;
}

/*
 * brix_sd_ucred_select — map an identity to its best available credential.
 *
 * WHAT: Tries literal-key then hash-key candidate; first valid+unexpired PEM
 *       wins (NGX_OK).  On all-missed returns NGX_DECLINED with out->key set
 *       to the hash-form key so the caller can log the file to provision.
 * WHY:  Single entry point for all per-user credential lookups; hides the
 *       two-candidate search and expiry-OR logic from callers.
 * HOW:  Zero *out; derive principal; build up to 2 candidates; resolve each;
 *       return first OK or DECLINED with out->key = hash key.
 */
ngx_int_t
brix_sd_ucred_select(const char *dir, const brix_identity_t *id,
    brix_sd_ucred_t *out)
{
    char      principal[BRIX_UCRED_PRINC_MAX];
    char      lit_key[BRIX_UCRED_KEY_MAX];
    char      hash_key[BRIX_UCRED_KEY_MAX];
    int       has_lit;
    int       any_expired;
    ngx_int_t rc;

    memset(out, 0, sizeof(*out));

    if (brix_sd_ucred_principal(id, principal, sizeof(principal)) != NGX_OK) {
        return NGX_DECLINED;
    }
    snprintf(out->principal, sizeof(out->principal), "%s", principal);

    /* Derive the hash key unconditionally (always needed for the fallback). */
    if (brix_sd_ucred_key(principal, hash_key, sizeof(hash_key)) != NGX_OK) {
        return NGX_DECLINED;
    }

    /* Derive the literal key; flag whether it is usable.
     * ucred_principal_fs_safe guarantees len <= 64 < BRIX_UCRED_KEY_MAX; use
     * memcpy+NUL so the compiler sees a bounded copy (avoids -Wformat-truncation
     * from comparing the declared buf sizes rather than the runtime constraint). */
    has_lit = ucred_principal_fs_safe(principal);
    if (has_lit) {
        size_t plen = strlen(principal);
        memcpy(lit_key, principal, plen);
        lit_key[plen] = '\0';
    }

    any_expired = 0;

    /* Try the literal candidate first (only when fs-safe). */
    if (has_lit) {
        rc = brix_sd_ucred_resolve(dir, lit_key, out);
        if (rc == NGX_OK) {
            /* out->principal already set above; no re-copy needed. */
            return NGX_OK;
        }
        any_expired |= out->expired;
    }

    /* Try the hash candidate. */
    rc = brix_sd_ucred_resolve(dir, hash_key, out);
    if (rc == NGX_OK) {
        /* out->principal already set above; no re-copy needed. */
        return NGX_OK;
    }
    any_expired |= out->expired;

    /* No valid credential found — return DECLINED with the hash key for
     * logging so the operator knows which file to provision. */
    snprintf(out->principal, sizeof(out->principal), "%s", principal);
    snprintf(out->key,       sizeof(out->key),       "%s", hash_key);
    out->expired = any_expired;
    return NGX_DECLINED;
}
