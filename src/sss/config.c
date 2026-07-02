#include "core/config/config.h"
#include "core/compat/log_diag.h"
#include "sss_keytab_kernel.h"   /* shared keytab line grammar + mode check */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The neutral entry caps must match this module's key struct so the copy-out
 * below never truncates a valid field (a drift in either would be a real bug). */
_Static_assert(sizeof(((xrootd_sss_key_t *) 0)->key)   == SSS_K_KEY_MAX,
               "SSS key buffer size drift vs shared kernel");
_Static_assert(sizeof(((xrootd_sss_key_t *) 0)->user)  == SSS_K_USER_MAX,
               "SSS user buffer size drift vs shared kernel");
_Static_assert(sizeof(((xrootd_sss_key_t *) 0)->group) == SSS_K_GROUP_MAX,
               "SSS group buffer size drift vs shared kernel");
_Static_assert(sizeof(((xrootd_sss_key_t *) 0)->name)  == SSS_K_NAME_MAX,
               "SSS name buffer size drift vs shared kernel");

/*
 * WHAT: SSS keytab line parser — wraps the shared grammar and layers on the
 *       server-only authz options (ANYUSR/ALLUSR/ANYGRP/USRGRP/NOIPCK) derived
 *       from the user/group/name fields.
 * HOW:  The shared kernel tokenises and validates the line; this function maps
 *       its tri-state result onto NGX_OK / NGX_ERROR, copies the neutral entry
 *       into an xrootd_sss_key_t, computes the option flags, and pushes the key.
 */
static ngx_int_t
xrootd_sss_parse_key_line(ngx_conf_t *cf, ngx_array_t *keys,
    char *line, ngx_uint_t line_no)
{
    sss_keytab_entry_t  entry;
    xrootd_sss_key_t    key, *dst;
    size_t              name_len;
    int                 rc;

    rc = sss_keytab_parse_line(line, &entry, (int64_t) ngx_time());
    if (rc < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_sss_keytab: invalid key entry on line %ui",
                           line_no);
        return NGX_ERROR;
    }
    if (rc == 0) {
        return NGX_OK;   /* blank / comment / expired — nothing to load */
    }

    ngx_memzero(&key, sizeof(key));
    key.id      = entry.id;
    key.exp     = (time_t) entry.exp;
    key.key_len = entry.key_len;
    ngx_memcpy(key.key, entry.key, entry.key_len);
    ngx_cpystrn((u_char *) key.user,  (u_char *) entry.user,  sizeof(key.user));
    ngx_cpystrn((u_char *) key.group, (u_char *) entry.group, sizeof(key.group));
    ngx_cpystrn((u_char *) key.name,  (u_char *) entry.name,  sizeof(key.name));

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

/* WHAT: SSS authentication configuration validator                     */
/*      Calls stat() to check permissions via xrootd_sss_keytab_mode_ok().*/
/* WHAT: Generic SSS keytab loader (path -> parsed key array)           */
/* WHY:  Shared by the main stream module's SSS auth (kXR_auth) and the */
/*       permission policy; keeping a single loader avoids two diverging */
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
        XROOTD_DIAG_CONF(NGX_LOG_EMERG, cf, 0,
            "xrootd: SSS keytab path is empty",
            "xrootd_sss_keytab was given without a path argument",
            "supply the keytab file path: xrootd_sss_keytab /etc/xrootd/sss.keytab;");
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
        XROOTD_DIAG_CONF(NGX_LOG_EMERG, cf, ngx_errno,
            "xrootd: cannot open SSS keytab \"%V\"",
            "the path is wrong, the file is unreadable by the nginx user, or "
            "it is a symlink (rejected for safety)",
            "generate the keytab with xrdsssadmin and give the nginx user "
            "read access to the real file; the OS reason is appended below",
            path);
        return NGX_ERROR;
    }

    if (fstat(keytab_fd, &st) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd: cannot stat SSS keytab \"%V\"", path);
        close(keytab_fd);
        return NGX_ERROR;
    }

    if (sss_keytab_mode_ok((const char *) path->data, st.st_mode, 1) != 0) {
        XROOTD_DIAG_CONF(NGX_LOG_EMERG, cf, 0,
            "xrootd: SSS keytab \"%V\" has unsafe permissions",
            "the keytab is a shared secret but is group/world readable or not "
            "owned correctly",
            "chmod 0400 (or 0600) the keytab and ensure it is owned by the "
            "nginx user; it must not be readable by anyone else",
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
