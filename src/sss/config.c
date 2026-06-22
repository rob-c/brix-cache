#include "../config/config.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* WHAT: Hexadecimal nibble value lookup                                */
/* WHY: Converts individual hex characters (0-9, a-f, A-F) to their     */
/*      numeric equivalents for binary key decoding. Used by           */
/*      xrootd_sss_decode_hex() to pair consecutive nibbles into       */
/*      single output bytes.                                           */
/* HOW: Returns 0-15 for valid hex chars, -1 otherwise. Case-insensitive*/
/*      via separate checks for lowercase and uppercase ranges.        */
/* ------------------------------------------------------------------ */
static int
xrootd_sss_hex_value(int ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }

    return -1;
}

/* ---- xrootd_sss_decode_hex — hex string to binary key conversion (SSS master key decoding) ----
 *
 * WHAT: Converts a hexadecimal-encoded string into raw bytes for SSS authentication keys. Validates input length is even and ≤ XROOTD_SSS_KEY_MAX, then pairs consecutive nibbles (high|low) into single output bytes using xrootd_sss_hex_value() lookup. Returns NGX_OK with out_len set to hex_len/2 on success, NGX_ERROR on invalid input (odd-length, non-hex characters, or exceeding key max length). Security invariant: rejects malformed hex strings that could indicate tampered master keys — fails closed on any decode error. Used by SSS authentication flow to convert config-stored hex keys into usable byte arrays for HMAC computation. */
static ngx_int_t
xrootd_sss_decode_hex(const char *hex, u_char *out, size_t *out_len)
{
    size_t hex_len;
    size_t hex_index;

    hex_len = strlen(hex);
    if (hex_len == 0 || (hex_len & 1)
        || hex_len / 2 > XROOTD_SSS_KEY_MAX)
    {
        return NGX_ERROR;
    }

    for (hex_index = 0; hex_index < hex_len; hex_index += 2) {
        int high_nibble;
        int low_nibble;

        high_nibble = xrootd_sss_hex_value((unsigned char) hex[hex_index]);
        low_nibble = xrootd_sss_hex_value(
            (unsigned char) hex[hex_index + 1]);
        if (high_nibble < 0 || low_nibble < 0) {
            return NGX_ERROR;
        }

        out[hex_index / 2] = (u_char) ((high_nibble << 4) | low_nibble);
    }

    *out_len = hex_len / 2;
    return NGX_OK;
}

/* ---- xrootd_sss_parse_i64 — integer parsing with errno validation (keytab expiry/ID field extraction) ----
 *
 * WHAT: Parses a text string into int64_t using strtoll() with strict validation. Checks errno for overflow, parse_end==text for empty input, and *parse_end!='\0' for trailing non-numeric characters. Returns NGX_OK with out populated on successful parse, NGX_ERROR on any invalid input. Used by SSS keytab parser to extract expiry timestamps (e: field) and key entry IDs (N: field). Security invariant: fails closed on malformed integer strings — rejects partial parses or overflow conditions that could indicate corrupted configuration. */
static ngx_int_t
xrootd_sss_parse_i64(const char *text, int64_t *out)
{
    char      *parse_end;
    long long  parsed_value;

    errno = 0;
    parsed_value = strtoll(text, &parse_end, 10);
    if (errno || parse_end == text || *parse_end != '\0') {
        return NGX_ERROR;
    }

    *out = (int64_t) parsed_value;
    return NGX_OK;
}

/* ---- xrootd_sss_copy_string — bounded string copy with length validation (SSS keytab field extraction safety) ----
 *
 * WHAT: Copies src string into dst buffer with strict length check. Validates strlen(src) < dst_len before copying via ngx_memcpy including NUL terminator. Returns NGX_OK on successful bounded copy, NGX_ERROR if src exceeds dst capacity preventing buffer overflow. Used by SSS keytab parser to extract user (u:), group (g:), and name (N:) fields into fixed-size buffers without risking overflow from oversized input values. Security invariant: always validates source length before copying — prevents buffer overflows that could corrupt adjacent configuration state or cause crashes on oversized keytab entries. */
static ngx_int_t
xrootd_sss_copy_string(char *dst, size_t dst_len, const char *src)
{
    size_t len;

    len = strlen(src);
    if (len >= dst_len) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst, src, len + 1);
    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/* WHAT: Keytab file permission validation                              */
/* WHY: Ensures SSS keytab files have restrictive permissions before    */
/*      loading. Plain keytabs require owner-only access (rw); the     */
/*      historical .grp variant permits group-read due to shared       */
/*      config management practices, but world-access is always        */
/*      rejected to prevent unauthorized key exposure.               */
/* HOW: Checks filename suffix ".grp" for legacy variant detection,    */
/*      then compares file mode against allowed permission set.       */
/*      Returns NGX_OK if permissions are within bounds, NGX_ERROR     */
/*      otherwise. Security invariant: fails closed on overly permissive*/
/*      keytab files — prevents accidental exposure of shared secrets.*/
/* ------------------------------------------------------------------ */
static ngx_int_t
xrootd_sss_keytab_mode_ok(const char *path, mode_t mode)
{
    mode_t allowed;
    size_t len;

    /*
     * Plain keytabs must be owner-only.  The historical .grp variant may be
     * group-readable because sites sometimes distribute it via shared config
     * management, but world bits are still rejected.
     */
    len = strlen(path);
    allowed = (len >= 4 && strcmp(path + len - 4, ".grp") == 0)
               ? (S_IRUSR | S_IWUSR | S_IRGRP)
               : (S_IRUSR | S_IWUSR);

    return ((mode & (S_IRWXG | S_IRWXO)) & ~allowed) ? NGX_ERROR : NGX_OK;
}

/* ------------------------------------------------------------------ */
/* WHAT: Keytab parsing error logger                                    */
/* WHY: Provides consistent emergency-level logging for malformed      */
/*      keytab lines during configuration validation. Uses NGX_LOG_    */
/*      EMERG because a corrupted keytab entry could cause incorrect   */
/*      authentication decisions at runtime.                           */
/* HOW: Formats error message as "xrootd_sss_keytab: <reason> on line  */
/*      <N>" with line number for operator troubleshooting. Always     */
/*      returns NGX_ERROR to signal parse failure to caller.          */
/* ------------------------------------------------------------------ */
static ngx_int_t
xrootd_sss_keytab_line_error(ngx_conf_t *cf, ngx_uint_t line_no,
    const char *reason)
{
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "xrootd_sss_keytab: %s on line %ui",
                        reason, line_no);
    return NGX_ERROR;
}

/* ------------------------------------------------------------------ */
/* WHAT: SSS keytab line parser — extracts authentication credentials   */
/* WHY: Parses each line of the server-side SSS keytab file into a      */
/*      xrootd_sss_key_t struct. The keytab format contains fields for  */
/*      entry ID (N), hex-encoded master key (k), user identity (u),    */
/*      group membership (g), name (n), and optional expiry timestamp  */
/*      (e). Unknown fields are ignored for compatibility with         */
/*      reference xrootd keytabs, but malformed required fields        */
/*      fail closed.                                                   */
/* HOW: Uses strtok_r() (thread-safe) to tokenize whitespace-separated  */
/*      fields. Each field is parsed via switch-case on prefix char     */
/*      ("N:", "k:", "u:", etc.). Key validation checks: ID must be    */
/*      positive, key bytes must exist, expiry must not have passed.   */
/*      Special user/group values ("anybody", "allusers") and name     */
/*      suffix "+" set policy options (XROOTD_SSS_OPT_*).             */
/* ------------------------------------------------------------------ */
static ngx_int_t
xrootd_sss_parse_key_line(ngx_conf_t *cf, ngx_array_t *keys,
    char *line, ngx_uint_t line_no)
{
    xrootd_sss_key_t  key, *dst;
    char             *save;
    char             *field;
    char             *field_value;
    int64_t           parsed_integer;
    size_t            name_len;

    /*
     * Keytab lines are whitespace-separated fields:
     *   0 N:<id> k:<hex-key> u:<user> g:<group> n:<name> e:<expiry>
     *
     * Unknown fields are ignored for compatibility with xrootd keytabs, but
     * malformed required fields fail closed.
     */
    field = strtok_r(line, " \t\r\n", &save);
    if (field == NULL || field[0] == '#') {
        return NGX_OK;
    }

    if (strcmp(field, "0") != 0 && strcmp(field, "1") != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_sss_keytab: unsupported key format "
                           "on line %ui", line_no);
        return NGX_ERROR;
    }

    ngx_memzero(&key, sizeof(key));
    key.id = -1;
    ngx_cpystrn((u_char *) key.name, (u_char *) "nowhere", sizeof(key.name));
    ngx_cpystrn((u_char *) key.user, (u_char *) "nobody", sizeof(key.user));
    ngx_cpystrn((u_char *) key.group, (u_char *) "nogroup", sizeof(key.group));

    while ((field = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
        if (field[0] == '#') {
            break;
        }

        if (field[1] != ':') {
            continue;
        }

        field_value = field + 2;

        switch (field[0]) {
        case 'u':
            if (xrootd_sss_copy_string(key.user, sizeof(key.user),
                                       field_value)
                != NGX_OK)
            {
                return xrootd_sss_keytab_line_error(cf, line_no,
                                                    "field too long");
            }
            break;

        case 'g':
            if (xrootd_sss_copy_string(key.group, sizeof(key.group),
                                       field_value)
                != NGX_OK)
            {
                return xrootd_sss_keytab_line_error(cf, line_no,
                                                    "field too long");
            }
            break;

        case 'n':
            if (xrootd_sss_copy_string(key.name, sizeof(key.name),
                                       field_value)
                != NGX_OK)
            {
                return xrootd_sss_keytab_line_error(cf, line_no,
                                                    "field too long");
            }
            break;

        case 'N':
            if (xrootd_sss_parse_i64(field_value, &key.id) != NGX_OK) {
                return xrootd_sss_keytab_line_error(cf, line_no,
                                                    "invalid key entry");
            }
            break;

        case 'e':
            if (xrootd_sss_parse_i64(field_value, &parsed_integer)
                != NGX_OK)
            {
                return xrootd_sss_keytab_line_error(cf, line_no,
                                                    "invalid key entry");
            }
            key.exp = (time_t) parsed_integer;
            break;

        case 'k':
            if (xrootd_sss_decode_hex(field_value, key.key, &key.key_len)
                != NGX_OK)
            {
                return xrootd_sss_keytab_line_error(cf, line_no,
                                                    "invalid key entry");
            }
            break;

        default:
            break;
        }
    }

    if (key.id < 0 || key.key_len == 0) {
        return xrootd_sss_keytab_line_error(cf, line_no,
                                            "invalid key entry");
    }

    if (key.exp && key.exp <= ngx_time()) {
        return NGX_OK;
    }

    if (strcmp(key.user, "anybody") == 0) {
        key.opts |= XROOTD_SSS_OPT_ANYUSR;
    } else if (strcmp(key.user, "allusers") == 0) {
        key.opts |= XROOTD_SSS_OPT_ALLUSR;
    }

    if (strcmp(key.group, "anygroup") == 0) {
        key.opts |= XROOTD_SSS_OPT_ANYGRP;
    } else if (strcmp(key.group, "usrgroup") == 0) {
        key.opts |= XROOTD_SSS_OPT_USRGRP;
    }

    name_len = strlen(key.name);
    if (name_len > 0 && key.name[name_len - 1] == '+') {
        key.opts |= XROOTD_SSS_OPT_NOIPCK;
    }

    dst = ngx_array_push(keys);
    if (dst == NULL) {
        return NGX_ERROR;
    }
    *dst = key;
    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/* WHAT: SSS authentication configuration validator                     */
/* WHY: Validates and loads the server-side SSS keytab file during      */
/*      nginx startup. Ensures the keytab exists, has proper           */
/*      permissions (owner-only), contains parseable entries, and      */
/*      has at least one usable (non-expired) key before enabling      */
/*      SSS auth mode.                                                 */
/* HOW: Checks xcf->auth == XROOTD_AUTH_SSS first for early exit.       */
/*      Validates keytab path exists as regular file with R_OK.        */
/*      Calls stat() to check permissions via xrootd_sss_keytab_mode_ok().*/
/*      Creates ngx_array_t for keys, opens file with FD_CLOEXEC,     */
/*      reads lines one-by-one via fgets(), parses each with           */
/*      xrootd_sss_parse_key_line(). Skips expired entries.            */
/*      Requires at least one non-expired key — logs NOTICE on         */
/*      successful configuration with key count.                     */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/* WHAT: Generic SSS keytab loader (path -> parsed key array)           */
/* WHY:  Shared by the main stream module's SSS auth (kXR_auth) and the */
/*       CMS server module's cluster authentication (kYR_xauth).  Both  */
/*       consume the same on-disk keytab format and the same private-   */
/*       permission policy; keeping a single loader avoids two diverging */
/*       parsers and one accidentally skipping the 0600/0640 check.     */
/* HOW:  Validate path is a readable regular file, open O_NOFOLLOW to    */
/*       defeat symlink/TOCTOU, fstat + permission check, parse each     */
/*       line into a freshly allocated array, require >=1 usable key.    */
/*       On success *out_keys points at the populated array.            */
/* ------------------------------------------------------------------ */
ngx_int_t
xrootd_sss_load_keytab(ngx_conf_t *cf, ngx_str_t *path, ngx_array_t **out_keys)
{
    FILE        *fp;
    struct stat  st;
    char         line[4096];
    ngx_uint_t   line_no;
    ngx_array_t *keys;
    int          keytab_fd;

    *out_keys = NULL;

    if (path == NULL || path->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "SSS keytab path is empty");
        return NGX_ERROR;
    }

    if (xrootd_validate_path(cf, "sss keytab", path,
                             XROOTD_PATH_REGULAR_FILE, R_OK)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Open with O_NOFOLLOW to reject symlinks before any permission check.
     * Using fstat() on the resulting fd eliminates the stat()/open() TOCTOU
     * race where an attacker could swap the keytab for a symlink between
     * the permission check and the actual open. */
    keytab_fd = open((const char *) path->data,
                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (keytab_fd < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd: cannot open SSS keytab \"%V\"", path);
        return NGX_ERROR;
    }

    if (fstat(keytab_fd, &st) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd: cannot stat SSS keytab \"%V\"", path);
        close(keytab_fd);
        return NGX_ERROR;
    }

    if (xrootd_sss_keytab_mode_ok((const char *) path->data, st.st_mode)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd: SSS keytab \"%V\" is not private enough",
                           path);
        close(keytab_fd);
        return NGX_ERROR;
    }

    fp = fdopen(keytab_fd, "r");
    if (fp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd: cannot fdopen SSS keytab \"%V\"", path);
        close(keytab_fd);
        return NGX_ERROR;
    }
    /* O_CLOEXEC was set at open() — no separate fcntl needed */

    keys = ngx_array_create(cf->pool, 4, sizeof(xrootd_sss_key_t));
    if (keys == NULL) {
        fclose(fp);
        return NGX_ERROR;
    }

    line_no = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        line_no++;
        if (xrootd_sss_parse_key_line(cf, keys, line, line_no) != NGX_OK) {
            fclose(fp);
            return NGX_ERROR;
        }
    }

    if (ferror(fp)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd: cannot read SSS keytab \"%V\"", path);
        fclose(fp);
        return NGX_ERROR;
    }

    fclose(fp);

    if (keys->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd: SSS keytab \"%V\" has no usable keys", path);
        return NGX_ERROR;
    }

    *out_keys = keys;
    return NGX_OK;
}

/* Does this server need the SSS keytab loaded for UPSTREAM proxy auth?  A proxy
 * authenticates to an SSS upstream using conf->sss_keys even when its own client
 * auth is not SSS (e.g. xrootd_auth none + xrootd_proxy_auth sss, or a
 * per-upstream "sss" policy).  Without this the keys are never parsed and the
 * upstream SSS handshake silently fails NotAuthorized. */
static int
xrootd_sss_upstream_needed(ngx_stream_xrootd_srv_conf_t *xcf)
{
    ngx_uint_t i;

    if (!xcf->proxy_enable) {
        return 0;
    }
    if (xcf->proxy_auth == XROOTD_PROXY_AUTH_SSS) {
        return 1;
    }
    if (xcf->proxy_upstreams != NULL) {
        xrootd_proxy_upstream_t *ups = xcf->proxy_upstreams->elts;
        for (i = 0; i < xcf->proxy_upstreams->nelts; i++) {
            if (ups[i].auth == (ngx_int_t) XROOTD_PROXY_AUTH_SSS) {
                return 1;
            }
        }
    }
    return 0;
}

ngx_int_t
xrootd_configure_sss_auth(ngx_conf_t *cf, ngx_stream_xrootd_srv_conf_t *xcf)
{
    int need_client   = (xcf->auth == XROOTD_AUTH_SSS);
    int need_upstream = xrootd_sss_upstream_needed(xcf);

    if (!need_client && !need_upstream) {
        return NGX_OK;
    }

    if (xcf->sss_keytab.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            need_client
                ? "xrootd_auth sss requires xrootd_sss_keytab"
                : "SSS proxy upstream auth requires xrootd_sss_keytab");
        return NGX_ERROR;
    }

    if (xrootd_sss_load_keytab(cf, &xcf->sss_keytab, &xcf->sss_keys)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "xrootd: SSS keytab loaded - keytab=%V keys=%ui (%s)",
                       &xcf->sss_keytab, xcf->sss_keys->nelts,
                       need_client ? (need_upstream ? "client+upstream"
                                                    : "client")
                                   : "upstream");

    return NGX_OK;
}
