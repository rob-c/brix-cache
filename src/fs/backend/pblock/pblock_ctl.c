/*
 * pblock_ctl.c — Phase-83 lab control plane (see pblock_ctl.h).
 *
 * Static opts parsing + the runtime ctl table. ngx-free (libc + sqlite3),
 * malloc-owned, gated by BRIX_HAVE_SQLITE. Reaches the catalog connection
 * through the internal cat_exec/cat_prepare primitives.
 */
#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "pblock_ctl.h"
#include "sd_pblock_catalog_internal.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sqlite3.h>

/* ---- capability name → bit --------------------------------------------- */

uint32_t
pblock_cap_bit(const char *name, size_t len)
{
    static const struct { const char *n; uint32_t b; } tab[] = {
        { "fd",           BRIX_SD_CAP_FD },
        { "sendfile",     BRIX_SD_CAP_SENDFILE },
        { "random_write", BRIX_SD_CAP_RANDOM_WRITE },
        { "range_read",   BRIX_SD_CAP_RANGE_READ },
        { "truncate",     BRIX_SD_CAP_TRUNCATE },
        { "server_copy",  BRIX_SD_CAP_SERVER_COPY },
        { "xattr",        BRIX_SD_CAP_XATTR },
        { "hard_rename",  BRIX_SD_CAP_HARD_RENAME },
        { "dirs",         BRIX_SD_CAP_DIRS },
        { "append",       BRIX_SD_CAP_APPEND },
        { "iouring",      BRIX_SD_CAP_IOURING },
        { "nearline",     BRIX_SD_CAP_NEARLINE },
        { "catalog",      BRIX_SD_CAP_CATALOG },
        { "dirs_write",   BRIX_SD_CAP_DIRS_WRITE },
        { "xattr_write",  BRIX_SD_CAP_XATTR_WRITE },
        { "memfile",      BRIX_SD_CAP_MEMFILE },
    };
    size_t i;

    for (i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        if (strlen(tab[i].n) == len && memcmp(tab[i].n, name, len) == 0) {
            return tab[i].b;
        }
    }
    return 0;
}

uint32_t
pblock_caps_apply(uint32_t caps, const pblock_opts_t *o)
{
    if (o == NULL || !o->has_caps) {
        return caps;
    }
    return (caps | o->caps_add) & ~o->caps_drop;
}

/* Parse "caps=" value: a comma list of +name / -name (bare name ⇒ +name). */
static int
opts_parse_caps(const char *v, size_t vlen, pblock_opts_t *out)
{
    const char *p   = v;
    const char *end = v + vlen;

    out->has_caps = 1;
    while (p < end) {
        const char *comma = memchr(p, ',', (size_t) (end - p));
        const char *tok_end = comma ? comma : end;
        int         add = 1;
        uint32_t    bit;

        if (p < tok_end && (*p == '+' || *p == '-')) {
            add = (*p == '+');
            p++;
        }
        bit = pblock_cap_bit(p, (size_t) (tok_end - p));
        if (bit == 0) {
            errno = EINVAL;
            return -1;
        }
        if (add) {
            out->caps_add |= bit;
        } else {
            out->caps_drop |= bit;
        }
        p = comma ? comma + 1 : end;
    }
    return 0;
}

/* pblock_parse_size — "10G"/"512m"/"100k"/"1234" → bytes/count (suffix k/m/g/t,
 * case-insensitive). 0 on empty/garbage (⇒ the quota stays off). Non-static:
 * pblock_quota.c reuses it for `quota.uid.<n>` ctl values. */
int64_t
pblock_parse_size(const char *val, size_t vlen)
{
    int64_t n = 0;
    size_t  i = 0;

    while (i < vlen && val[i] >= '0' && val[i] <= '9') {
        n = n * 10 + (val[i] - '0');
        i++;
    }
    if (i == 0) {
        return 0;
    }
    if (i < vlen) {
        switch (val[i] | 0x20) {
        case 'k': n *= 1024LL; break;
        case 'm': n *= 1024LL * 1024; break;
        case 'g': n *= 1024LL * 1024 * 1024; break;
        case 't': n *= 1024LL * 1024 * 1024 * 1024; break;
        default:  break;
        }
    }
    return n;
}

/* A boolean opts token is true when present with no value, or with a value whose
 * first byte is not a falsey sentinel (0 / n / f — i.e. 0, no, false). The
 * `vlen == 0` short-circuit keeps val[0] out of bounds when there is no value. */
static int
opts_truthy(const char *val, size_t vlen)
{
    return vlen == 0 || (val[0] != '0' && val[0] != 'n' && val[0] != 'f');
}

/* opts_apply_flag — the boolean feature toggles, table-driven: name → the int
 * field it sets.  Returns 1 iff KEY named one of them (and it was applied). */
static int
opts_apply_flag(pblock_opts_t *out, const char *key, size_t klen,
    const char *val, size_t vlen)
{
    static const struct { const char *n; size_t off; } flags[] = {
        { "lab",      offsetof(pblock_opts_t, lab) },        /* master gate */
        { "mem",      offsetof(pblock_opts_t, mem) },        /* F16 */
        { "audit",    offsetof(pblock_opts_t, audit) },      /* F17 */
        { "csi",      offsetof(pblock_opts_t, csi) },        /* F3  */
        { "nearline", offsetof(pblock_opts_t, nearline) },   /* F4  */
        { "locks",    offsetof(pblock_opts_t, locks) },      /* F15 */
        { "dedup",    offsetof(pblock_opts_t, dedup) },      /* F10 */
        { "snap",     offsetof(pblock_opts_t, snapshots) },  /* F6  */
        { "trash",    offsetof(pblock_opts_t, trash) },      /* F11 */
    };
    size_t i;

    for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        if (strlen(flags[i].n) == klen && memcmp(flags[i].n, key, klen) == 0) {
            *(int *) ((char *) out + flags[i].off) = opts_truthy(val, vlen);
            return 1;
        }
    }
    return 0;
}

/* opts_apply_xform — F12/F13 transform spec ("crypt:<keyfile>"/"zstd"); copied
 * into the fixed buffer, EINVAL if it would not fit. */
static int
opts_apply_xform(pblock_opts_t *out, const char *val, size_t vlen)
{
    if (vlen >= sizeof(out->xform)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(out->xform, val, vlen);
    out->xform[vlen] = '\0';
    out->xform_len   = vlen;
    return 0;
}

/* opts_apply_scalar — the non-boolean keys (sizes, counts, caps, xform).
 * Unknown keys are ignored for later-wave forward-compat. */
static int
opts_apply_scalar(pblock_opts_t *out, const char *key, size_t klen,
    const char *val, size_t vlen)
{
    if (klen == 5 && memcmp(key, "quota", 5) == 0) {
        out->quota_bytes = pblock_parse_size(val, vlen);         /* F5  */
    } else if (klen == 12 && memcmp(key, "quota_inodes", 12) == 0) {
        out->quota_inodes = pblock_parse_size(val, vlen);        /* F5  */
    } else if (klen == 8 && memcmp(key, "versions", 8) == 0) {
        out->versions = (int) pblock_parse_size(val, vlen);      /* F11 */
    } else if (klen == 9 && memcmp(key, "trash_ttl", 9) == 0) {
        out->trash_ttl = pblock_parse_size(val, vlen);           /* F11 */
    } else if (klen == 4 && memcmp(key, "caps", 4) == 0) {
        return opts_parse_caps(val, vlen, out);                  /* F2  */
    } else if (klen == 5 && memcmp(key, "xform", 5) == 0) {
        return opts_apply_xform(out, val, vlen);                 /* F12/F13 */
    }
    return 0;
}

int
pblock_opts_parse(const char *query, pblock_opts_t *out)
{
    const char *p;

    memset(out, 0, sizeof(*out));
    if (query == NULL) {
        return 0;
    }
    for (p = query; *p != '\0'; ) {
        const char *amp    = strchr(p, '&');
        const char *kv_end = amp ? amp : p + strlen(p);
        const char *eq     = memchr(p, '=', (size_t) (kv_end - p));
        const char *key    = p;
        size_t      klen   = eq ? (size_t) (eq - p) : (size_t) (kv_end - p);
        const char *val    = eq ? eq + 1 : kv_end;
        size_t      vlen   = eq ? (size_t) (kv_end - (eq + 1)) : 0;

        if (!opts_apply_flag(out, key, klen, val, vlen)
            && opts_apply_scalar(out, key, klen, val, vlen) != 0)
        {
            return -1;
        }
        p = amp ? amp + 1 : kv_end;
    }
    return 0;
}

/* ---- static opts sidecar ----------------------------------------------- */

static void
opts_sidecar_path(const char *root, char *buf, size_t buflen)
{
    snprintf(buf, buflen, "%s/pblock.opts", root);
}

int
pblock_opts_load_sidecar(const char *root, pblock_opts_t *out)
{
    char  path[PATH_MAX];
    char  line[1024];
    FILE *f;
    char *nl;

    memset(out, 0, sizeof(*out));
    opts_sidecar_path(root, path, sizeof(path));
    f = fopen(path, "re");
    if (f == NULL) {
        return (errno == ENOENT) ? 0 : -1;   /* no sidecar ⇒ default (lab off) */
    }
    if (fgets(line, sizeof(line), f) == NULL) {
        fclose(f);
        return 0;
    }
    fclose(f);
    nl = strchr(line, '\n');
    if (nl != NULL) {
        *nl = '\0';
    }
    return pblock_opts_parse(line, out);
}

/* ---- runtime ctl table ------------------------------------------------- */

int
pblock_ctl_init(pblock_catalog *cat)
{
    return cat_exec(cat,
        "CREATE TABLE IF NOT EXISTS ctl("
        "  key TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL DEFAULT '',"
        "  epoch INTEGER NOT NULL DEFAULT 0);");
}

int64_t
pblock_ctl_epoch(pblock_catalog *cat)
{
    sqlite3_stmt *st;
    int64_t       epoch = 0;
    int           rc;

    st = cat_prepare(cat, "SELECT MAX(epoch) FROM ctl;");
    if (st == NULL) {
        return -1;
    }
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) {
        epoch = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        errno = EIO;
        return -1;
    }
    return epoch;
}

int
pblock_ctl_get(pblock_catalog *cat, const char *key, char *buf, size_t buflen)
{
    sqlite3_stmt *st;
    int           rc, found = 0;

    if (buflen > 0) {
        buf[0] = '\0';
    }
    st = cat_prepare(cat, "SELECT value FROM ctl WHERE key = ?1;");
    if (st == NULL) {
        return -1;
    }
    sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(st, 0);

        if (v != NULL && buflen > 0) {
            snprintf(buf, buflen, "%s", (const char *) v);
        }
        found = 1;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        errno = EIO;
        return -1;
    }
    return found;
}

int
pblock_ctl_mem_pragmas(pblock_catalog *cat)
{
    if (cat_exec(cat, "PRAGMA journal_mode=MEMORY;") != 0
        || cat_exec(cat, "PRAGMA synchronous=OFF;") != 0)
    {
        return -1;
    }
    return 0;
}

/* ---- op audit log (F17) ------------------------------------------------- */

int
pblock_audit_init(pblock_catalog *cat)
{
    /* seq is a gap-free AUTOINCREMENT so a test can assert a total order across
     * two workers sharing the export (SQLite serialises the INSERTs). */
    return cat_exec(cat,
        "CREATE TABLE IF NOT EXISTS oplog("
        "  seq INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  ts INTEGER NOT NULL,"
        "  op TEXT NOT NULL,"
        "  path TEXT NOT NULL DEFAULT '',"
        "  aux TEXT NOT NULL DEFAULT '',"
        "  uid INTEGER NOT NULL DEFAULT 0,"
        "  gid INTEGER NOT NULL DEFAULT 0,"
        "  result INTEGER NOT NULL DEFAULT 0,"
        "  errno INTEGER NOT NULL DEFAULT 0);");
}

void
pblock_audit_log(pblock_catalog *cat, const char *op, const char *path,
    const char *aux, uint32_t uid, uint32_t gid, int result, int err)
{
    sqlite3_stmt *st;
    int           saved = errno;   /* audit must not perturb the caller's errno */

    st = cat_prepare(cat,
        "INSERT INTO oplog(ts, op, path, aux, uid, gid, result, errno)"
        " VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);");
    if (st != NULL) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64) time(NULL));
        sqlite3_bind_text(st, 2, op, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 3, path ? path : "", -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 4, aux ? aux : "", -1, SQLITE_STATIC);
        sqlite3_bind_int64(st, 5, (sqlite3_int64) uid);
        sqlite3_bind_int64(st, 6, (sqlite3_int64) gid);
        sqlite3_bind_int(st, 7, result);
        sqlite3_bind_int(st, 8, err);
        (void) sqlite3_step(st);       /* best-effort: swallow any error */
        sqlite3_finalize(st);
    }
    errno = saved;
}

#endif /* BRIX_HAVE_SQLITE */
