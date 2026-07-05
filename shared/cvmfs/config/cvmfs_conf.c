/* cvmfs_conf.c — stock CVMFS_* config-file parsing. See cvmfs_conf.h. */
#include "cvmfs/config/cvmfs_conf.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cvmfs_conf_init(cvmfs_conf_t *c) { c->n = 0; }

static void set_kv(cvmfs_conf_t *c, const char *k, const char *v) {
    for (size_t i = 0; i < c->n; i++) {
        if (strcmp(c->key[i], k) == 0) {
            snprintf(c->val[i], sizeof(c->val[i]), "%s", v);   /* last wins */
            return;
        }
    }
    if (c->n >= CVMFS_CONF_MAX_KEYS) return;
    snprintf(c->key[c->n], sizeof(c->key[c->n]), "%s", k);
    snprintf(c->val[c->n], sizeof(c->val[c->n]), "%s", v);
    c->n++;
}

/* Strip surrounding whitespace in place; returns the trimmed start. */
static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r' || s[n-1] == '\n'))
        s[--n] = '\0';
    return s;
}

/* Drop one layer of matching surrounding quotes. */
static void unquote(char *s) {
    size_t n = strlen(s);
    if (n >= 2 && ((s[0] == '"' && s[n-1] == '"') || (s[0] == '\'' && s[n-1] == '\''))) {
        memmove(s, s + 1, n - 2);
        s[n - 2] = '\0';
    }
}

int cvmfs_conf_parse_text(cvmfs_conf_t *c, const char *text, size_t len) {
    int added = 0;
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && text[j] != '\n') j++;

        char line[600];
        size_t ll = j - i < sizeof(line) - 1 ? j - i : sizeof(line) - 1;
        memcpy(line, text + i, ll);
        line[ll] = '\0';
        i = j + 1;

        char *p = trim(line);
        if (*p == '\0' || *p == '#') continue;
        if (strncmp(p, "export ", 7) == 0) p = trim(p + 7);

        char *eq = strchr(p, '=');
        if (eq == NULL) continue;
        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);
        unquote(val);
        if (*key == '\0') continue;
        set_kv(c, key, val);
        added++;
    }
    return added;
}

int cvmfs_conf_parse_file(cvmfs_conf_t *c, const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return 0;                 /* missing = fine */
    char  buf[8192];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    cvmfs_conf_parse_text(c, buf, n);
    return 0;
}

int cvmfs_conf_load_cascade(cvmfs_conf_t *c, const char *etc_root, const char *fqrn) {
    const char *root = etc_root ? etc_root : "/etc/cvmfs";
    char path[1400];

    snprintf(path, sizeof(path), "%s/default.conf", root);
    cvmfs_conf_parse_file(c, path);

    /* default.d entries ending in .conf, in directory order */
    char dd[600]; snprintf(dd, sizeof(dd), "%s/default.d", root);
    DIR *d = opendir(dd);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            const char *dot = strrchr(e->d_name, '.');
            if (dot && strcmp(dot, ".conf") == 0) {
                snprintf(path, sizeof(path), "%s/%s", dd, e->d_name);
                cvmfs_conf_parse_file(c, path);
            }
        }
        closedir(d);
    }

    const char *domain = strchr(fqrn, '.');
    if (domain && domain[1]) {
        snprintf(path, sizeof(path), "%s/domain.d/%s.conf", root, domain + 1);
        cvmfs_conf_parse_file(c, path);
    }
    snprintf(path, sizeof(path), "%s/config.d/%s.conf", root, fqrn);
    cvmfs_conf_parse_file(c, path);
    snprintf(path, sizeof(path), "%s/default.local", root);
    cvmfs_conf_parse_file(c, path);
    return 0;
}

const char *cvmfs_conf_get(const cvmfs_conf_t *c, const char *key) {
    for (size_t i = 0; i < c->n; i++)
        if (strcmp(c->key[i], key) == 0) return c->val[i];
    return NULL;
}

/* Replace every occurrence of `needle` in `s` with `rep` (bounded). */
static void replace_all(char *s, size_t cap, const char *needle, const char *rep) {
    char tmp[600];
    size_t nl = strlen(needle), rl = strlen(rep), o = 0;
    for (size_t i = 0; s[i] != '\0' && o < cap - 1; ) {
        if (strncmp(s + i, needle, nl) == 0) {
            for (size_t k = 0; k < rl && o < cap - 1; k++) tmp[o++] = rep[k];
            i += nl;
        } else {
            tmp[o++] = s[i++];
        }
    }
    tmp[o] = '\0';
    memcpy(s, tmp, o + 1);
}

int cvmfs_conf_expand(const char *tmpl, const char *fqrn, char *out, size_t outlen) {
    if (strlen(tmpl) >= outlen) return -1;
    snprintf(out, outlen, "%s", tmpl);

    const char *dot = strchr(fqrn, '.');
    char org[128] = {0}, fqdn[256] = {0};
    if (dot) {
        size_t ol = (size_t)(dot - fqrn);
        if (ol < sizeof(org)) { memcpy(org, fqrn, ol); org[ol] = '\0'; }
        snprintf(fqdn, sizeof(fqdn), "%s", dot + 1);
    } else {
        snprintf(org, sizeof(org), "%s", fqrn);
    }
    replace_all(out, outlen, "@fqrn@", fqrn);
    replace_all(out, outlen, "@org@",  org);
    replace_all(out, outlen, "@fqdn@", fqdn);
    return 0;
}

/* split `list` on any char in `seps`, calling cb for each non-empty token. */
static void for_each_token(const char *list, const char *seps,
                           void (*cb)(const char *tok, void *ud), void *ud) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", list);
    char *save = NULL;
    for (char *t = strtok_r(buf, seps, &save); t; t = strtok_r(NULL, seps, &save)) {
        while (*t == ' ') t++;
        if (*t) cb(t, ud);
    }
}

typedef struct { cvmfs_failover_t *fo; const char *fqrn; int hosts; } apply_ctx_t;

static void add_server_cb(const char *tok, void *ud) {
    apply_ctx_t *a = ud;
    char url[512];
    if (cvmfs_conf_expand(tok, a->fqrn, url, sizeof(url)) == 0
        && cvmfs_failover_add_host(a->fo, url) == 0)
        a->hosts++;
}

typedef struct { cvmfs_failover_t *fo; int group; } proxy_grp_ctx_t;
static void add_proxy_cb(const char *tok, void *ud) {
    proxy_grp_ctx_t *g = ud;
    cvmfs_failover_add_proxy(g->fo, tok, g->group);
}

int cvmfs_conf_apply(const cvmfs_conf_t *c, const char *fqrn,
                     cvmfs_repo_config_t *rc, cvmfs_failover_t *fo) {
    /* timeouts */
    const char *t  = cvmfs_conf_get(c, "CVMFS_TIMEOUT");
    const char *td = cvmfs_conf_get(c, "CVMFS_TIMEOUT_DIRECT");
    rc->timeout_s        = t  ? atol(t)  : 5;
    rc->timeout_direct_s = td ? atol(td) : 10;

    /* master key: CVMFS_PUBLIC_KEY wins; else CVMFS_KEYS_DIR/<domain>.pub */
    const char *pk  = cvmfs_conf_get(c, "CVMFS_PUBLIC_KEY");
    const char *kd  = cvmfs_conf_get(c, "CVMFS_KEYS_DIR");
    const char *dom = strchr(fqrn, '.');
    if (pk) {
        snprintf(rc->master_pub_path, sizeof(rc->master_pub_path), "%s", pk);
    } else if (kd && dom) {
        snprintf(rc->master_pub_path, sizeof(rc->master_pub_path), "%s/%s.pub", kd, dom + 1);
    }

    /* proxies: groups by ';', members by '|'; unset ⇒ DIRECT */
    const char *proxy = cvmfs_conf_get(c, "CVMFS_HTTP_PROXY");
    if (proxy && *proxy) {
        char groups[512];
        snprintf(groups, sizeof(groups), "%s", proxy);
        char *save = NULL; int g = 0;
        for (char *grp = strtok_r(groups, ";", &save); grp; grp = strtok_r(NULL, ";", &save)) {
            proxy_grp_ctx_t pc = { fo, g++ };
            for_each_token(grp, "|", add_proxy_cb, &pc);
        }
    } else {
        cvmfs_failover_add_proxy(fo, "DIRECT", 0);
    }

    /* servers */
    apply_ctx_t a = { fo, fqrn, 0 };
    const char *su = cvmfs_conf_get(c, "CVMFS_SERVER_URL");
    if (su && *su)
        for_each_token(su, ";,", add_server_cb, &a);
    return a.hosts;
}
