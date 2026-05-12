#include "../config/config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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


static ngx_int_t
xrootd_sss_keytab_mode_ok(const char *path, mode_t mode)
{
    mode_t allowed;
    size_t len;

    len = strlen(path);
    /*
     * Plain keytabs must be owner-only.  The historical .grp variant may be
     * group-readable because sites sometimes distribute it via shared config
     * management, but world bits are still rejected.
     */
    allowed = (len >= 4 && strcmp(path + len - 4, ".grp") == 0)
              ? (S_IRUSR | S_IWUSR | S_IRGRP)
              : (S_IRUSR | S_IWUSR);

    return ((mode & (S_IRWXG | S_IRWXO)) & ~allowed) ? NGX_ERROR : NGX_OK;
}


static ngx_int_t
xrootd_sss_keytab_line_error(ngx_conf_t *cf, ngx_uint_t line_no,
    const char *reason)
{
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "xrootd_sss_keytab: %s on line %ui",
                       reason, line_no);
    return NGX_ERROR;
}


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


ngx_int_t
xrootd_configure_sss_auth(ngx_conf_t *cf, ngx_stream_xrootd_srv_conf_t *xcf)
{
    FILE       *fp;
    struct stat st;
    char        line[4096];
    ngx_uint_t  line_no;

    if (xcf->auth != XROOTD_AUTH_SSS) {
        return NGX_OK;
    }

    if (xcf->sss_keytab.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_auth sss requires xrootd_sss_keytab");
        return NGX_ERROR;
    }

    if (xrootd_validate_path(cf, "xrootd_sss_keytab", &xcf->sss_keytab,
                             XROOTD_PATH_REGULAR_FILE, R_OK)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (stat((const char *) xcf->sss_keytab.data, &st) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd: cannot stat SSS keytab \"%V\"",
                           &xcf->sss_keytab);
        return NGX_ERROR;
    }

    if (xrootd_sss_keytab_mode_ok((const char *) xcf->sss_keytab.data,
                                  st.st_mode)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd: SSS keytab \"%V\" is not private enough",
                           &xcf->sss_keytab);
        return NGX_ERROR;
    }

    xcf->sss_keys = ngx_array_create(cf->pool, 4, sizeof(xrootd_sss_key_t));
    if (xcf->sss_keys == NULL) {
        return NGX_ERROR;
    }

    fp = fopen((const char *) xcf->sss_keytab.data, "r");
    if (fp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd: cannot open SSS keytab \"%V\"",
                           &xcf->sss_keytab);
        return NGX_ERROR;
    }

    line_no = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        line_no++;
        if (xrootd_sss_parse_key_line(cf, xcf->sss_keys, line, line_no)
            != NGX_OK)
        {
            fclose(fp);
            return NGX_ERROR;
        }
    }

    if (ferror(fp)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd: cannot read SSS keytab \"%V\"",
                           &xcf->sss_keytab);
        fclose(fp);
        return NGX_ERROR;
    }

    fclose(fp);

    if (xcf->sss_keys->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd: SSS keytab \"%V\" has no usable keys",
                           &xcf->sss_keytab);
        return NGX_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "xrootd: SSS auth configured - keytab=%V keys=%ui",
                       &xcf->sss_keytab, xcf->sss_keys->nelts);

    return NGX_OK;
}
