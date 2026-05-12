/*
 * Macaroon token validation.
 *
 * Implements HMAC-SHA256 signature chaining and WLCG caveat parsing.
 */

#include "token_internal.h"
#include "macaroon.h"
#include "b64url.h"
#include "scopes.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>
#include <time.h>

#define MACAROON_MAX_BIN 8192

static int
hex_to_int(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int
parse_packet_len(const u_char *p)
{
    int v0, v1, v2, v3;
    v0 = hex_to_int(p[0]);
    v1 = hex_to_int(p[1]);
    v2 = hex_to_int(p[2]);
    v3 = hex_to_int(p[3]);
    if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) return -1;
    return (v0 << 12) | (v1 << 8) | (v2 << 4) | v3;
}

/* 
 * ISO8601 subset parser for "before:2026-05-10T00:00:00Z"
 * Returns (time_t) -1 on failure.
 */
static time_t
parse_iso8601(const char *s, size_t len)
{
    struct tm tm;
    char      buf[32];

    if (len < 20 || len >= sizeof(buf)) return (time_t) -1;
    memcpy(buf, s, len);
    buf[len] = '\0';

    memset(&tm, 0, sizeof(tm));
    /* %Y-%m-%dT%H:%M:%SZ */
    if (sscanf(buf, "%d-%d-%dT%d:%d:%dZ",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6)
    {
        return (time_t) -1;
    }

    tm.tm_year -= 1900;
    tm.tm_mon  -= 1;
    tm.tm_isdst = -1;

    return timegm(&tm);
}

int
xrootd_token_is_macaroon(const char *token, size_t token_len)
{
    /* JWTs always have dots. Macaroons in base64url do not. */
    if (token_len < 4) return 0;
    if (memchr(token, '.', token_len) == NULL) return 1;
    return 0;
}

ssize_t
xrootd_macaroon_secret_parse(const char *hex, size_t hex_len,
    u_char *bin, size_t bin_max)
{
    size_t i;
    int    v1, v2;

    if (hex_len % 2 != 0 || hex_len / 2 > bin_max) return -1;

    for (i = 0; i < hex_len / 2; i++) {
        v1 = hex_to_int(hex[i * 2]);
        v2 = hex_to_int(hex[i * 2 + 1]);
        if (v1 < 0 || v2 < 0) return -1;
        bin[i] = (u_char) ((v1 << 4) | v2);
    }

    return (ssize_t) (hex_len / 2);
}

int
xrootd_macaroon_validate(ngx_log_t *log,
    const char *token, size_t token_len,
    const u_char *root_key, size_t root_key_len,
    xrootd_token_claims_t *claims)
{
    u_char  bin[MACAROON_MAX_BIN];
    ssize_t bin_len;
    u_char  sig[32];
    u_char *p, *end;
    unsigned int sig_out_len;
    int     found_sig = 0;
    int     found_id = 0;
    time_t  now = time(NULL);
    char    scope_buf[2048];
    size_t  scope_off = 0;
    char    path_caveats[8][XROOTD_SCOPE_PATH_MAX];
    int     n_path_caveats = 0;

    ngx_memzero(claims, sizeof(*claims));
    ngx_memzero(scope_buf, sizeof(scope_buf));

    bin_len = b64url_decode(token, token_len, bin, sizeof(bin));
    if (bin_len < 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_macaroon: base64url decode failed");
        return -1;
    }

    p = bin;
    end = bin + bin_len;

    while (p + 4 <= end) {
        int plen = parse_packet_len(p);
        if (plen < 4 || p + plen > end) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_macaroon: malformed packet length: %d", plen);
            return -1;
        }

        u_char *data = p + 4;
        size_t  dlen = plen - 4;
        
        /* Strip trailing newline if present */
        if (dlen > 0 && data[dlen-1] == '\n') dlen--;

        if (dlen >= 11 && memcmp(data, "identifier ", 11) == 0) {
            const u_char *id = data + 11;
            size_t idlen = dlen - 11;
            HMAC(EVP_sha256(), root_key, root_key_len, id, idlen, sig, &sig_out_len);
            ngx_memcpy(claims->sub, id, idlen < sizeof(claims->sub) ? idlen : sizeof(claims->sub)-1);
            found_id = 1;
        } else if (dlen >= 9 && memcmp(data, "location ", 9) == 0) {
            const u_char *loc = data + 9;
            size_t loclen = dlen - 9;
            ngx_memcpy(claims->iss, loc, loclen < sizeof(claims->iss) ? loclen : sizeof(claims->iss)-1);
        } else if (dlen >= 4 && memcmp(data, "cid ", 4) == 0) {
            const u_char *caveat = data + 4;
            size_t clen = dlen - 4;
            u_char next_sig[32];
            
            if (!found_id) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "xrootd_macaroon: caveat before identifier");
                return -1;
            }

            /* Update HMAC chain: sig = HMAC(sig, caveat) */
            HMAC(EVP_sha256(), sig, 32, caveat, clen, next_sig, &sig_out_len);
            ngx_memcpy(sig, next_sig, 32);

            /* Parse WLCG caveats */
            if (clen >= 9 && memcmp(caveat, "activity:", 9) == 0) {
                const char *act = (const char *) caveat + 9;
                size_t alen = clen - 9;
                const char *scope = NULL;
                
                if (alen == 8 && memcmp(act, "DOWNLOAD", 8) == 0) scope = "storage.read";
                else if (alen == 4 && memcmp(act, "LIST", 4) == 0) scope = "storage.read";
                else if (alen == 6 && memcmp(act, "UPLOAD", 6) == 0) scope = "storage.write";
                else if (alen == 6 && memcmp(act, "DELETE", 6) == 0) scope = "storage.write";
                else if (alen == 6 && memcmp(act, "MANAGE", 6) == 0) scope = "storage.modify";

                if (scope && scope_off + strlen(scope) + 2 < sizeof(scope_buf)) {
                    if (scope_off > 0) scope_buf[scope_off++] = ' ';
                    strcpy(scope_buf + scope_off, scope);
                    scope_off += strlen(scope);
                }
            } else if (clen >= 7 && memcmp(caveat, "before:", 7) == 0) {
                time_t exp = parse_iso8601((const char *) caveat + 7, clen - 7);
                if (exp != (time_t) -1) {
                    if (claims->exp == 0 || exp < claims->exp) {
                        claims->exp = exp;
                    }
                }
            } else if (clen >= 5 && memcmp(caveat, "path:", 5) == 0) {
                const char *cp = (const char *) caveat + 5;
                size_t      cplen = clen - 5;
                if (n_path_caveats < 8 && cplen > 0
                    && cplen < XROOTD_SCOPE_PATH_MAX)
                {
                    memcpy(path_caveats[n_path_caveats], cp, cplen);
                    path_caveats[n_path_caveats][cplen] = '\0';
                    n_path_caveats++;
                }
            }
        } else if (dlen >= 10 && memcmp(data, "signature ", 10) == 0) {
            const u_char *provided_sig = data + 10;
            if (dlen < 10 + 32 || memcmp(sig, provided_sig, 32) != 0) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "xrootd_macaroon: signature mismatch");
                return -1;
            }
            found_sig = 1;
        }

        p += plen;
    }

    if (!found_sig) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_macaroon: no valid signature found");
        return -1;
    }

    if (claims->exp > 0 && now > (time_t) claims->exp) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_macaroon: token expired at %L (now=%L)",
                      (long long) claims->exp, (long long) now);
        return -1;
    }

    /* Finalize scopes — parse activity: caveats into structured entries */
    strcpy(claims->scope_raw, scope_buf);
    claims->scope_count = xrootd_token_parse_scopes(
        claims->scope_raw, claims->scopes, XROOTD_MAX_TOKEN_SCOPES);

    /*
     * Enforce path: caveats (WLCG Macaroon restriction).
     *
     * Each path: caveat narrows the allowed paths further (intersection).
     * For every caveat path C and every scope S:
     *   - If C starts with S.path  → C is narrower; use C.
     *   - If S.path starts with C  → S is already narrower; keep S.path.
     *   - Otherwise the paths are disjoint → revoke the scope (clear bits).
     *
     * After all caveats are applied, scope_raw is rebuilt from the
     * (possibly narrowed) scopes[] so that downstream policy checks see
     * the restricted paths.
     */
    if (n_path_caveats > 0) {
        int       ci, si;
        int       narrowed = 0;

        for (ci = 0; ci < n_path_caveats; ci++) {
            const char *cp = path_caveats[ci];
            size_t      cplen = strlen(cp);

            for (si = 0; si < claims->scope_count; si++) {
                xrootd_token_scope_t *sc = &claims->scopes[si];
                size_t slen = strlen(sc->path);

                /* Strip trailing slash from scope path for comparison,
                 * matching the logic in scope_path_matches(). */
                size_t slen_cmp = slen;
                if (slen_cmp > 1 && sc->path[slen_cmp - 1] == '/')
                    slen_cmp--;

                /* Case 1: caveat path is equal to or deeper than scope path
                 * → narrow scope to caveat path. */
                if (strncmp(cp, sc->path, slen_cmp) == 0
                    && (cp[slen_cmp] == '/' || cp[slen_cmp] == '\0'))
                {
                    if (strcmp(sc->path, cp) != 0) {
                        ngx_log_error(NGX_LOG_INFO, log, 0,
                            "xrootd_macaroon: path: caveat \"%s\" narrows "
                            "scope path \"%s\" → \"%s\"",
                            cp, sc->path, cp);
                        memcpy(sc->path, cp, cplen + 1);
                        narrowed = 1;
                    }
                    /* else: already exact — no change needed */
                }
                /* Case 2: scope path is already deeper than caveat path
                 * → scope path stays (it is already more restrictive). */
                else if (strncmp(sc->path, cp, cplen) == 0
                         && (sc->path[cplen] == '/' || sc->path[cplen] == '\0'))
                {
                    /* keep sc->path as-is */
                }
                /* Case 3: paths are disjoint → revoke all permissions */
                else {
                    if (sc->read || sc->write || sc->create || sc->modify) {
                        ngx_log_error(NGX_LOG_INFO, log, 0,
                            "xrootd_macaroon: path: caveat \"%s\" revokes "
                            "scope path \"%s\" (disjoint)",
                            cp, sc->path);
                        narrowed = 1;
                    }
                    sc->read = sc->write = sc->create = sc->modify = 0;
                }
            }
        }

        /* Rebuild scope_raw from the narrowed scopes[] */
        if (narrowed) {
            static const char *perm_names[] = {
                "storage.read", "storage.write",
                "storage.create", "storage.modify"
            };
            size_t off = 0;

            claims->scope_raw[0] = '\0';
            for (si = 0; si < claims->scope_count; si++) {
                xrootd_token_scope_t *sc = &claims->scopes[si];
                unsigned int bits[4] = {
                    sc->read, sc->write, sc->create, sc->modify
                };
                int bi;
                for (bi = 0; bi < 4; bi++) {
                    if (!bits[bi]) continue;
                    size_t plen = strlen(perm_names[bi]);
                    size_t pathlen = strlen(sc->path);
                    /* "perm:path" + space + NUL */
                    if (off + plen + 1 + pathlen + 2 > sizeof(claims->scope_raw))
                        break;
                    if (off > 0)
                        claims->scope_raw[off++] = ' ';
                    memcpy(claims->scope_raw + off, perm_names[bi], plen);
                    off += plen;
                    claims->scope_raw[off++] = ':';
                    memcpy(claims->scope_raw + off, sc->path, pathlen);
                    off += pathlen;
                    claims->scope_raw[off] = '\0';
                }
            }
            /* Re-parse so scopes[] path fields are canonical */
            claims->scope_count = xrootd_token_parse_scopes(
                claims->scope_raw, claims->scopes, XROOTD_MAX_TOKEN_SCOPES);
        }
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "xrootd_macaroon: valid Macaroon sub=\"%s\" iss=\"%s\" "
                  "scope=\"%s\" exp=%L",
                  claims->sub, claims->iss, claims->scope_raw, (long long) claims->exp);

    return 0;
}
