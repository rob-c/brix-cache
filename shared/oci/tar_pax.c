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

typedef struct {
    const unsigned char *key;
    const unsigned char *val;
    size_t               keylen;
    size_t               vallen;
    size_t               reclen;
} pax_record_t;

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

/*
 * WHAT: Compare a bounded pax key with a NUL-terminated expected name.
 * WHY:  Record keys are spans, so plain strcmp could read into the value.
 * HOW:  Require equal lengths before comparing the exact key bytes.
 */
static int pax_key_is(const unsigned char *key, size_t keylen,
                      const char *expected) {
    size_t expected_len = strlen(expected);

    return keylen == expected_len && memcmp(key, expected, keylen) == 0;
}

/*
 * WHAT: Install or unset a bounded pax string override.
 * WHY:  Empty values remove overrides while non-empty values need termination.
 * HOW:  Enforce destination capacity, copy bytes, append NUL, and set presence.
 */
static int pax_text_value(brix_tar_t *t, char *dst, size_t dstlen, int *have,
                          const char *name, const unsigned char *val,
                          size_t vallen) {
    if (vallen >= dstlen)
        return brix_tar_fail(t, "pax %s exceeds 4095 bytes", name);
    memcpy(dst, val, vallen);
    dst[vallen] = '\0';
    *have = vallen > 0;
    return 0;
}

/*
 * WHAT: Install or unset a signed numeric pax override.
 * WHY:  All numeric keys use the same empty-value and malformed-value rules.
 * HOW:  Parse non-empty spans and update the presence bit only on success.
 */
static int pax_number_value(brix_tar_t *t, int64_t *dst, int *have,
                            const char *name, const unsigned char *val,
                            size_t vallen) {
    if (vallen == 0) {
        *have = 0;
        return 0;
    }
    if (pax_num(val, vallen, dst) != 0)
        return brix_tar_fail(t, "malformed pax %s value", name);
    *have = 1;
    return 0;
}

/* Apply one key=value onto the target override. An EMPTY value unsets the
 * override (the POSIX pax rule). Unknown keys are skipped. */
static int pax_kv(brix_tar_t *t, tar_override_t *o, int global,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *val, size_t vallen) {
    if (pax_key_is(key, keylen, "path"))
        return pax_text_value(t, o->path, sizeof(o->path), &o->have_path,
                              "path", val, vallen);
    if (pax_key_is(key, keylen, "linkpath"))
        return pax_text_value(t, o->linkname, sizeof(o->linkname),
                              &o->have_link, "linkpath", val, vallen);
    if (pax_key_is(key, keylen, "size"))
        return pax_number_value(t, &o->size, &o->have_size, "size", val,
                                vallen);
    if (pax_key_is(key, keylen, "mtime"))
        return pax_number_value(t, &o->mtime, &o->have_mtime, "mtime", val,
                                vallen);
    if (pax_key_is(key, keylen, "uid"))
        return pax_number_value(t, &o->uid, &o->have_uid, "uid", val,
                                vallen);
    if (pax_key_is(key, keylen, "gid"))
        return pax_number_value(t, &o->gid, &o->have_gid, "gid", val,
                                vallen);
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

/*
 * WHAT: Parse and validate one length-prefixed pax record view.
 * WHY:  Attacker-controlled lengths must be proven safe before field access.
 * HOW:  Decode the decimal prefix, validate bounds/newline, and split at '='.
 */
static int pax_record_parse(brix_tar_t *t, const unsigned char *rec,
                            size_t remain, size_t body_len,
                            pax_record_t *view) {
    const unsigned char *eq;
    size_t               digits = 0;
    size_t               reclen = 0;

    while (digits < remain && rec[digits] >= '0' && rec[digits] <= '9') {
        if (reclen > body_len / 10 + 1)
            return brix_tar_fail(t, "pax record length overflows");
        reclen = reclen * 10 + (size_t) (rec[digits] - '0');
        digits++;
    }
    if (digits == 0 || digits >= remain || rec[digits] != ' ')
        return brix_tar_fail(t, "malformed pax record length");
    if (reclen < digits + 2 || reclen > remain)
        return brix_tar_fail(t, "pax record length %zu out of bounds", reclen);
    if (rec[reclen - 1] != '\n')
        return brix_tar_fail(t, "pax record not newline-terminated");

    view->key = rec + digits + 1;
    eq = memchr(view->key, '=', reclen - digits - 2);
    if (eq == NULL)
        return brix_tar_fail(t, "pax record without '='");
    view->keylen = (size_t) (eq - view->key);
    if (view->keylen == 0)
        return brix_tar_fail(t, "pax record with empty key");
    view->val    = eq + 1;
    view->vallen = (size_t) (rec + reclen - 1 - view->val);
    view->reclen = reclen;
    return 0;
}

int brix_tar_pax_apply(brix_tar_t *t, size_t len, int global) {
    tar_override_t *o = global ? &t->glob : &t->next;
    size_t          off = 0;
    size_t          nrec = 0;

    while (off < len) {
        const unsigned char *rec = t->pax + off;
        size_t               remain = len - off;
        pax_record_t         view = {0};

        if (++nrec > TAR_PAX_REC_MAX)
            return brix_tar_fail(t, "more than %d pax records in one entry",
                                 TAR_PAX_REC_MAX);
        if (pax_record_parse(t, rec, remain, len, &view) != 0)
            return -1;
        if (pax_kv(t, o, global, view.key, view.keylen, view.val,
                   view.vallen) != 0)
            return -1;
        off += view.reclen;
    }
    return 0;
}

void brix_tar_pax_reset_next(brix_tar_t *t) {
    memset(&t->next, 0, sizeof(t->next));
    t->xarena_len = 0;
    t->xcount     = 0;
}
