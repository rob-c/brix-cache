/*
 * lock_record.c — encode/decode for the persisted resource-lock record
 * (phase-107 C7; format contract in lock_record.h).
 *
 * Moved byte-for-byte from src/protocols/webdav/prop_xattr.c (encode, decode,
 * the per-field dispatcher) and lock_check.c (the ancestor-walk path helper)
 * so the VFS lock gate can read lock records without a protocol dependency.
 * The xattr I/O around the format — who reads/writes it, under which
 * credential, with which confinement — stays with the callers.
 */
#include "lock_record.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ngx_int_t
brix_lock_record_encode(const brix_lock_record_t *e, char *out, size_t outsz)
{
    int n;

    /*
     * Schema v2: `expires` is absolute Unix WALL-CLOCK seconds (not the legacy
     * v1 monotonic-msec value, which was meaningless after a reboot). The leading
     * `v=2` lets the decoder reject/expire any pre-upgrade v1 record. `null=1`
     * marks a lock-null placeholder (RFC 4918 §9.10.1).
     */
    n = snprintf(out, outsz,
                 "v=2|token=%s|owner=%s|expires=%lld|scope=%s|depth=%s|null=%d",
                 e->token, e->owner,
                 (long long) e->expires,
                 e->exclusive ? "exclusive" : "shared",
                 e->depth_infinity ? "infinity" : "0",
                 e->is_null ? 1 : 0);
    return (n > 0 && (size_t) n < outsz) ? NGX_OK : NGX_ERROR;
}

/* ---- Apply one decoded `key`/`val` field pair to the lock record ----
 *
 * WHAT: Dispatches a single `key=val` pair (already split, NUL-terminated) from
 * a lock xattr into the matching field of `*e`, and captures the schema version
 * into `*version` for the `v` key. Unknown keys are ignored (forward-compat).
 *
 * WHY: The per-key branch ladder is the sole source of decode complexity; hoisting
 * it out of brix_lock_record_decode keeps that parser a small loop and makes the
 * field-mapping table reviewable on its own. Field semantics (schema v2 encoding,
 * scope/depth string forms, null placeholder) are preserved byte-for-byte.
 *
 * HOW:
 *   1. Compare `key` against each known field name in turn.
 *   2. On match, parse `val` into the field with the same primitive the inline
 *      ladder used (strtol/strtoll for numerics, ngx_cpystrn for bounded strings,
 *      exact-string equality for the enum-like scope/depth/null fields).
 *   3. Return with no effect when `key` matches nothing.
 */
static void
brix_lock_record_apply_field(const char *key, char *val,
    brix_lock_record_t *e, int *version)
{
    if (strcmp(key, "v") == 0) {
        *version = (int) strtol(val, NULL, 10);
    } else if (strcmp(key, "token") == 0) {
        ngx_cpystrn((u_char *) e->token, (u_char *) val, sizeof(e->token));
    } else if (strcmp(key, "owner") == 0) {
        ngx_cpystrn((u_char *) e->owner, (u_char *) val, sizeof(e->owner));
    } else if (strcmp(key, "expires") == 0) {
        e->expires = (int64_t) strtoll(val, NULL, 10);
    } else if (strcmp(key, "scope") == 0) {
        e->exclusive = (strcmp(val, "exclusive") == 0) ? 1 : 0;
    } else if (strcmp(key, "depth") == 0) {
        e->depth_infinity = (strcmp(val, "infinity") == 0) ? 1 : 0;
    } else if (strcmp(key, "null") == 0) {
        e->is_null = (strcmp(val, "1") == 0) ? 1 : 0;
    }
}

ngx_int_t
brix_lock_record_decode(const char *raw, size_t rawlen, brix_lock_record_t *e)
{
    char   buf[BRIX_LOCK_XATTR_MAXLEN];
    char  *p, *end, *val, *next;
    int    version = 0;

    if (rawlen == 0 || rawlen >= sizeof(buf)) {
        return NGX_DECLINED;
    }

    ngx_memcpy(buf, raw, rawlen);
    buf[rawlen] = '\0';
    ngx_memzero(e, sizeof(*e));

    p   = buf;
    end = buf + rawlen;

    while (p < end) {
        next = strchr(p, '|');
        if (next != NULL) {
            *next = '\0';
        }

        val = strchr(p, '=');
        if (val != NULL) {
            *val++ = '\0';
            brix_lock_record_apply_field(p, val, e, &version);
        }

        p = next ? next + 1 : end;
    }

    if (e->token[0] == '\0') {
        return NGX_DECLINED;
    }

    /*
     * Migration guard: a legacy v1 record (no `v=2`) carries a MONOTONIC `expires`
     * that is meaningless in this process (especially after a reboot). Force it to
     * 0 (already-expired) so every caller's existing expired-lock cleanup path
     * deletes it and proceeds — a downgrade therefore releases stale locks rather
     * than honouring a bogus deadline. Returning NGX_OK (not NGX_DECLINED) is
     * deliberate: NGX_DECLINED would leave the physical xattr in place and a fresh
     * XATTR_CREATE LOCK would then wrongly hit EEXIST -> 423.
     */
    if (version != 2) {
        e->expires = 0;
    }

    return NGX_OK;
}

int
brix_lock_path_ascend(char *check, size_t check_len)
{
    char *slash = check + check_len - 1;

    while (slash > check && *slash == '/') {
        slash--;
    }
    while (slash > check && *slash != '/') {
        slash--;
    }
    if (*slash != '/') {
        return 0;
    }
    *slash = '\0';
    return 1;
}
