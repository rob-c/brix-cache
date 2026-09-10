#include "voms_internal.h"
#include "auth/voms/vo_token.h"

#include <string.h>

/*
 * Helpers for converting VOMS API results into the module's comma-separated
 * VO list format.
 */

/*
 *
 * WHAT: brix_append_vo_token() — deduplicates and appends a VO name to both
 * primary_vo (single VO) and vo_list (comma-separated multi-VO string). Returns
 * ngx_flag_t: 1 on success, 0 when buffer is full. Guards against duplicates via
 * brix_vo_list_contains(). Handles first-entry case separately from append-case
 * to avoid leading commas. Uses ngx_cpystrn for initial write and ngx_memcpy +
 * manual NUL termination for subsequent appends. Caller must ensure vo_list_sz
 * and primary_vo_sz are sufficient (typically 256 bytes). */

/* Thin ngx-typed wrapper over the shared ngx-free predicate (vo_token.h). */
static ngx_flag_t
brix_vo_token_safe(const char *vo, size_t vo_len)
{
    return brix_vo_token_is_safe(vo, vo_len) ? 1 : 0;
}

static ngx_flag_t
brix_append_vo_token(char *primary_vo, size_t primary_vo_sz,
    char *vo_list, size_t vo_list_sz, const char *vo)
{
    size_t list_len;
    size_t vo_len;

    if (vo == NULL || vo[0] == '\0') {
        return 1;
    }

    vo_len = strlen(vo);
    if (!brix_vo_token_safe(vo, vo_len)) {
        return 1;
    }

    if (brix_vo_list_contains(vo_list, vo)) {
        return 1;
    }

    list_len = strlen(vo_list);

    if (list_len == 0) {
        if (vo_len + 1 > vo_list_sz || vo_len + 1 > primary_vo_sz) {
            return 0;
        }

        ngx_cpystrn((u_char *) vo_list, (u_char *) vo, vo_list_sz);
        ngx_cpystrn((u_char *) primary_vo, (u_char *) vo, primary_vo_sz);
        return 1;
    }

    if (list_len + 1 + vo_len + 1 > vo_list_sz) {
        return 0;
    }

    vo_list[list_len++] = ',';
    ngx_memcpy(vo_list + list_len, vo, vo_len);
    vo_list[list_len + vo_len] = '\0';
    return 1;
}

/*
 * WHAT: brix_append_fqan_token() — deduplicate and append ONE raw VOMS FQAN to
 *       the comma-separated `fqan_list` buffer.  No return value: the FQAN CSV
 *       is an enrichment, never a precondition for login.
 * WHY:  2.0 F20 — brix_identity_derive_attrs recovers (vorg, role, group) from
 *       an FQAN, but the VO-name list it used to be handed is '/'-free by
 *       construction (brix_vo_token_is_safe), so the role was always empty and
 *       the authdb `l` selector and the XrdAcc `role` template could never
 *       match anything.  The FQANs need their own channel.
 * HOW:  refuse a token the FQAN predicate rejects, skip a duplicate, and append
 *       ",<fqan>" when it fits.  A full buffer silently stops enriching rather
 *       than failing the handshake: the VO-name authorization the deployment
 *       already relied on must keep working.  Never feeds primary_vo — that
 *       value reaches metric labels and log fields (INVARIANT 8).
 */
static void
brix_append_fqan_token(char *fqan_list, size_t fqan_list_sz, const char *fqan)
{
    size_t list_len;
    size_t fqan_len;

    if (fqan_list == NULL || fqan_list_sz == 0 || fqan == NULL) {
        return;
    }

    fqan_len = strlen(fqan);
    if (!brix_fqan_token_is_safe(fqan, fqan_len)) {
        return;
    }
    if (brix_vo_list_contains(fqan_list, fqan)) {
        return;
    }

    list_len = strlen(fqan_list);

    if (list_len == 0) {
        if (fqan_len + 1 > fqan_list_sz) {
            return;
        }
        ngx_cpystrn((u_char *) fqan_list, (u_char *) fqan, fqan_list_sz);
        return;
    }

    if (list_len + 1 + fqan_len + 1 > fqan_list_sz) {
        return;
    }

    fqan_list[list_len++] = ',';
    ngx_memcpy(fqan_list + list_len, fqan, fqan_len);
    fqan_list[list_len + fqan_len] = '\0';
}

/*
 *
 * WHAT: brix_fqan_to_vo() — extracts the VO name from a Fully-Qualified Attribute
 * Name (FQAN). FQAN format: "/VO/Role=X/Capability=Y" — the VO is the first path
 * component after the leading slash. Returns ngx_flag_t: 1 on success, 0 when fqan
 * is NULL, malformed (no second '/'), or VO name exceeds vo_sz. Uses pointer arithmetic
 * (end - start) for length calculation to avoid strlen on the full string, then
 * ngx_memcpy + manual NUL termination. Caller must provide vo_sz >= 128 bytes
 * (VO names are typically short: "cms", "atlas", "alice"). */

static ngx_flag_t
brix_fqan_to_vo(const char *fqan, char *vo, size_t vo_sz)
{
    const char *start;
    const char *end;
    size_t      len;

    if (fqan == NULL || fqan[0] != '/') {
        return 0;
    }

    start = fqan + 1;
    end = strchr(start, '/');
    if (end == NULL || end == start) {
        return 0;
    }

    len = (size_t) (end - start);
    if (len + 1 > vo_sz || !brix_vo_token_safe(start, len)) {
        return 0;
    }

    ngx_memcpy(vo, start, len);
    vo[len] = '\0';
    return 1;
}

/*
 *
 * WHAT: brix_collect_voms_vos() — iterates over all VOMS attribute certificate
 * entries in vd->data and populates primary_vo (single VO name) and vo_list
 * (comma-separated multi-VO string). Two-pass per entry: first uses voname field
 * directly, then derives additional VOs from each FQAN via brix_fqan_to_vo().
 * Delegates append/dedup to brix_append_vo_token() for both paths. Returns
 * NGX_OK when vo_list is non-empty, NGX_DECLINED when no VO membership found,
 * NGX_ERROR on buffer overflow during append. Caller must ensure primary_vo_sz
 * and vo_list_sz are sufficient (typically 256 bytes). */

ngx_int_t
brix_collect_voms_vos(struct voms_data *vd, const brix_voms_out_t *out)
{
    struct voms_entry **entry;

    if (vd->data == NULL) {
        return NGX_DECLINED;
    }

    for (entry = vd->data; *entry != NULL; entry++) {
        char **fqan;
        char   derived_vo[128];

        if ((*entry)->voname != NULL && (*entry)->voname[0] != '\0') {
            if (!brix_append_vo_token(out->primary_vo, out->primary_vo_sz,
                                        out->vo_list, out->vo_list_sz,
                                        (*entry)->voname)) {
                return NGX_ERROR;
            }
        }

        if ((*entry)->fqan == NULL) {
            continue;
        }

        for (fqan = (*entry)->fqan; *fqan != NULL; fqan++) {
            /* 2.0 F20: the RAW FQAN first — it is the only carrier of the
             * VOMS role, and the VO-name views below deliberately cannot hold
             * one.  Best-effort: an FQAN that does not fit, or that carries a
             * byte the predicate refuses, is dropped without failing a login
             * that VO-name authorization would still have allowed. */
            brix_append_fqan_token(out->fqan_list, out->fqan_list_sz, *fqan);

            if (!brix_fqan_to_vo(*fqan, derived_vo, sizeof(derived_vo))) {
                continue;
            }

            if (!brix_append_vo_token(out->primary_vo, out->primary_vo_sz,
                                        out->vo_list, out->vo_list_sz,
                                        derived_vo)) {
                return NGX_ERROR;
            }
        }
    }

    return (out->vo_list != NULL && out->vo_list[0] != '\0')
           ? NGX_OK : NGX_DECLINED;
}
