/* tar_pax.c — pax extended-header record parsing (phase-104 D6.3).
 *
 * WHAT: parse the body of an 'x' (per-file) or 'g' (global) pax entry —
 *       repeated "<len> <key>=<value>\n" records — onto the reader's
 *       override state, including SCHILY.xattr.* capture for the publish
 *       plane.
 * WHY:  split from tar.c by design (§0.5): the record grammar is fiddly
 *       (the length counts itself) and security-relevant (attacker-authored
 *       lengths), so it gets its own TU and its own fuzz corpus.
 * HOW:  byte-exact walk: decimal length parsed and bounds-checked against
 *       the remaining body BEFORE any field is touched; a malformed length
 *       is -1, never a resync guess. Values are binary-safe (xattr values
 *       may hold NULs); numeric values go through a bounded copy. Record
 *       count is capped (TAR_PAX_REC_MAX) so a stream of zero-length
 *       records is a clean refusal, not a CPU bomb.
 */
#include "oci/tar_internal.h"

#include <stdlib.h>
#include <string.h>

#define PAX_XATTR_PREFIX     "SCHILY.xattr."
#define PAX_XATTR_PREFIX_LEN 13

/* Parse a decimal int64 from a bounded, possibly-unterminated span (numeric
 * pax values: size/mtime/uid/gid; mtime's fractional part truncated). */
static int pax_num(const unsigned char *v, size_t n, int64_t *out) {
    char   tmp[32];
    char  *end = NULL;
    size_t i;

    if (n == 0 || n >= sizeof(tmp))
        return -1;
    for (i = 0; i < n && v[i] != '.'; i++)      /* truncate fraction */
        tmp[i] = (char) v[i];
    tmp[i] = '\0';
    if (tmp[0] == '\0')
        return -1;
    *out = strtoll(tmp, &end, 10);
    return (end != NULL && *end == '\0') ? 0 : -1;
}

/* Stage one SCHILY.xattr pair into the per-file arena. */
static int pax_xattr(brix_tar_t *t, const unsigned char *key, size_t keylen,
                     const unsigned char *val, size_t vallen) {
    size_t name_len = keylen - PAX_XATTR_PREFIX_LEN;
    char  *slot;

    if (name_len == 0 || name_len > 255)
        return brix_tar_fail(t, "pax xattr name length %zu out of bounds",
                             name_len);
    if (t->xcount >= TAR_XATTR_MAX)
        return brix_tar_fail(t, "more than %d xattrs on one entry",
                             TAR_XATTR_MAX);
    if (t->xarena_len + name_len + 1 + vallen > sizeof(t->xarena))
        return brix_tar_fail(t, "xattr set exceeds the %u-byte budget",
                             (unsigned) sizeof(t->xarena));

    slot = t->xarena + t->xarena_len;
    memcpy(slot, key + PAX_XATTR_PREFIX_LEN, name_len);
    slot[name_len] = '\0';
    memcpy(slot + name_len + 1, val, vallen);

    t->xkeys[t->xcount] = slot;
    t->xvals[t->xcount] = (const unsigned char *) slot + name_len + 1;
    t->xlens[t->xcount] = vallen;
    t->xcount++;
    t->xarena_len += name_len + 1 + vallen;
    return 0;
}

/* Apply one key=value onto the target override. An EMPTY value unsets the
 * override (the POSIX pax rule). Unknown keys are skipped. */
static int pax_kv(brix_tar_t *t, tar_override_t *o, int global,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *val, size_t vallen) {
    if (keylen == 4 && memcmp(key, "path", 4) == 0) {
        if (vallen >= sizeof(o->path))
            return brix_tar_fail(t, "pax path exceeds 4095 bytes");
        memcpy(o->path, val, vallen);
        o->path[vallen] = '\0';
        o->have_path = vallen > 0;
        return 0;
    }
    if (keylen == 8 && memcmp(key, "linkpath", 8) == 0) {
        if (vallen >= sizeof(o->linkname))
            return brix_tar_fail(t, "pax linkpath exceeds 4095 bytes");
        memcpy(o->linkname, val, vallen);
        o->linkname[vallen] = '\0';
        o->have_link = vallen > 0;
        return 0;
    }
    if (keylen == 4 && memcmp(key, "size", 4) == 0) {
        o->have_size = vallen > 0 && pax_num(val, vallen, &o->size) == 0;
        if (vallen > 0 && !o->have_size)
            return brix_tar_fail(t, "malformed pax size value");
        return 0;
    }
    if (keylen == 5 && memcmp(key, "mtime", 5) == 0) {
        o->have_mtime = vallen > 0 && pax_num(val, vallen, &o->mtime) == 0;
        if (vallen > 0 && !o->have_mtime)
            return brix_tar_fail(t, "malformed pax mtime value");
        return 0;
    }
    if (keylen == 3 && memcmp(key, "uid", 3) == 0) {
        o->have_uid = vallen > 0 && pax_num(val, vallen, &o->uid) == 0;
        if (vallen > 0 && !o->have_uid)
            return brix_tar_fail(t, "malformed pax uid value");
        return 0;
    }
    if (keylen == 3 && memcmp(key, "gid", 3) == 0) {
        o->have_gid = vallen > 0 && pax_num(val, vallen, &o->gid) == 0;
        if (vallen > 0 && !o->have_gid)
            return brix_tar_fail(t, "malformed pax gid value");
        return 0;
    }
    if (keylen > PAX_XATTR_PREFIX_LEN &&
        memcmp(key, PAX_XATTR_PREFIX, PAX_XATTR_PREFIX_LEN) == 0) {
        /* Global xattrs ("apply to every following file") are a grammar
         * corner no known writer emits; honoring them would smear one
         * attacker-authored record across the whole layer. Skipped. */
        if (global)
            return 0;
        return pax_xattr(t, key, keylen, val, vallen);
    }
    return 0;    /* unknown key: skipped by contract */
}

int brix_tar_pax_apply(brix_tar_t *t, size_t len, int global) {
    tar_override_t *o = global ? &t->glob : &t->next;
    size_t          off = 0;
    size_t          nrec = 0;

    while (off < len) {
        const unsigned char *rec = t->pax + off;
        size_t               remain = len - off;
        size_t               reclen = 0, digits = 0;
        const unsigned char *key, *val, *eq;
        size_t               keylen, vallen;

        if (++nrec > TAR_PAX_REC_MAX)
            return brix_tar_fail(t, "more than %d pax records in one entry",
                                 TAR_PAX_REC_MAX);

        /* "<len> " — decimal, counts the WHOLE record including itself. */
        while (digits < remain && rec[digits] >= '0' && rec[digits] <= '9') {
            if (reclen > len / 10 + 1)
                return brix_tar_fail(t, "pax record length overflows");
            reclen = reclen * 10 + (size_t) (rec[digits] - '0');
            digits++;
        }
        if (digits == 0 || digits >= remain || rec[digits] != ' ')
            return brix_tar_fail(t, "malformed pax record length");
        if (reclen < digits + 2 || reclen > remain)
            return brix_tar_fail(t, "pax record length %zu out of bounds",
                                 reclen);
        if (rec[reclen - 1] != '\n')
            return brix_tar_fail(t, "pax record not newline-terminated");

        /* "<key>=<value>" between the space and the newline. */
        key = rec + digits + 1;
        eq  = memchr(key, '=', reclen - digits - 2);
        if (eq == NULL)
            return brix_tar_fail(t, "pax record without '='");
        keylen = (size_t) (eq - key);
        val    = eq + 1;
        vallen = (size_t) (rec + reclen - 1 - val);
        if (keylen == 0)
            return brix_tar_fail(t, "pax record with empty key");

        if (pax_kv(t, o, global, key, keylen, val, vallen) != 0)
            return -1;
        off += reclen;
    }
    return 0;
}

void brix_tar_pax_reset_next(brix_tar_t *t) {
    memset(&t->next, 0, sizeof(t->next));
    t->xarena_len = 0;
    t->xcount     = 0;
}
