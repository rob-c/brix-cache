/*
 * tier_config_args.c — the trailing store-line PARAMS of a tier declaration.
 *
 * WHAT: everything after the URL on a brix_storage_backend / _cache / _stage /
 *       _cold line: `credential=<name>`, `block_size=<n>`, `verify_pages[=…]`,
 *       `mode=e|s`, `prot=p|c`, `streams=<n>`, `permit=<host|.suffix>` (2.0 F5
 *       forward://), and the bare `nearline` flag.
 *
 * WHY:  split out of tier_config.c (phase-115 W4.3) when `verify_pages` pushed
 *       that file past the 600-line cap.  The split axis is real, not
 *       arithmetic: tier_config.c answers "what STORE is this line naming?"
 *       (scheme → driver, authority, path confinement), while this file answers
 *       "what does the operator want done with it?".  Every function here is a
 *       pure params→cfg validator that never touches a path or a socket.
 *
 * HOW:  one dispatch loop (tier_parse_args) over the args array, one refusal
 *       per unrecognised token — an unknown param is an OPERATOR error that
 *       fails nginx -t rather than a silently ignored word.  Error text goes
 *       through tier_fail so both halves speak one vocabulary.
 */
#include "tier.h"
#include "tier_internal.h"
#include "fs/backend/gsiftp/gftp_client.h"   /* GFTP_STREAMS_MAX */

#include <string.h>

/* Parse the `verify_pages[=best-effort|require]` store param (phase-115 W4.3).
 *
 * The bare token means REQUIRE: an operator who writes `verify_pages` is asking
 * for verified bytes, and an origin that cannot deliver them should say so at
 * the first read rather than quietly serving unverified ones.  `=best-effort`
 * is the explicit opt-in to the compat behaviour (verify where the origin can,
 * plain kXR_read where it cannot) for a federation of mixed-vintage origins.
 *
 * Accepted only on a root:// / roots:// BACKEND: the param arms a wire request
 * (kXR_pgread) that only the xroot driver speaks, and only against the ORIGIN
 * the bytes come from — on a posix/s3/http store, or on a cache/stage tier, it
 * would silently do nothing, which is the failure mode this refusal exists to
 * prevent.  Returns NGX_OK / NGX_ERROR (message written through tier_fail). */
static ngx_int_t
tier_parse_verify_pages(ngx_conf_t *cf, ngx_str_t *arg, brix_tier_cfg_t *out,
    char *err, size_t errcap)
{
    static const char  key[] = "verify_pages";
    size_t             vlen = arg->len - (sizeof(key) - 1);
    u_char            *v = arg->data + sizeof(key) - 1;

    if (out->role != BRIX_TIER_BACKEND) {
        return tier_fail(cf, 1, err, errcap,
            "\"verify_pages\" belongs on brix_storage_backend, not on %s "
            "(it verifies bytes ARRIVING from an origin)",
            tier_role_directive(out->role));
    }
    if (ngx_strcmp(out->driver, "xroot") != 0
        && ngx_strcmp(out->driver, "xroot_fwd") != 0)
    {
        return tier_fail(cf, 1, err, errcap,
            "\"verify_pages\" needs a root:// origin (kXR_pgread); "
            "the %s driver has no per-page checksum", out->driver);
    }

    if (vlen == 0) {
        out->verify_pages = BRIX_PGVERIFY_REQUIRE;
        return NGX_OK;
    }
    if (vlen == sizeof("=require") - 1
        && ngx_strncmp(v, "=require", vlen) == 0)
    {
        out->verify_pages = BRIX_PGVERIFY_REQUIRE;
        return NGX_OK;
    }
    if (vlen == sizeof("=best-effort") - 1
        && ngx_strncmp(v, "=best-effort", vlen) == 0)
    {
        out->verify_pages = BRIX_PGVERIFY_BESTEFFORT;
        return NGX_OK;
    }
    return tier_fail(cf, 1, err, errcap,
        "invalid verify_pages value (want \"require\" or \"best-effort\")");
}

/* ---- GridFTP data-channel params (phase-115 W5.1) -------------------------
 *
 * `mode=e|s` and `prot=p|c` say how the DATA connection of an ftp:///gsiftp://
 * origin is framed and protected.  Both are per-store operator policy rather
 * than negotiation: the client asks for exactly what the store line says and
 * fails the transfer if the origin refuses, because the alternative — quietly
 * falling back to MODE S or a cleartext channel — is the failure mode an
 * operator who wrote `prot=p` is paying to avoid. */

/* Both params are GridFTP vocabulary and mean nothing anywhere else; accepting
 * one on another driver would leave the operator believing they had armed a
 * data channel the store does not speak. */
static ngx_int_t
tier_ftp_param_driver_ok(ngx_conf_t *cf, const char *key,
    brix_tier_cfg_t *out, char *err, size_t errcap)
{
    if (ngx_strcmp(out->driver, "gsiftp") != 0) {
        return tier_fail(cf, 1, err, errcap,
            "\"%s\" needs an ftp:// or gsiftp:// store; the %s driver has no "
            "GridFTP data channel", key, out->driver);
    }
    return NGX_OK;
}

/* tier_ftp_param_letter — the prologue `mode=` and `prot=` share.
 *
 * WHAT: Reject the param on a non-GridFTP store, then reduce `key=X` to its
 *       single value letter, folded to lower case.
 * WHY:  Both params are one-letter enumerations guarded by the same driver
 *       check.  Written out twice, the guard drifts: a third one-letter param
 *       would make it three copies.  The letters themselves stay with their
 *       own parser, because their MEANING (and their error text) is not
 *       shared.
 * HOW:  tier_ftp_param_driver_ok() on the key, then require exactly one byte
 *       after the `=`.  Returns the lowercased letter; 0 when the value is not
 *       one byte (the caller reports it with its own list of valid values);
 *       -1 when the driver check failed, with *err already filled.
 */
static int
tier_ftp_param_letter(ngx_conf_t *cf, ngx_str_t *arg, brix_tier_cfg_t *out,
    char *err, size_t errcap)
{
    u_char  *eq;
    char     key[16];
    size_t   klen;

    eq = ngx_strlchr(arg->data, arg->data + arg->len, '=');
    if (eq == NULL) {
        return -1;
    }
    klen = (size_t) (eq - arg->data);
    if (klen >= sizeof(key)) {
        return -1;
    }
    ngx_memcpy(key, arg->data, klen);
    key[klen] = '\0';

    if (tier_ftp_param_driver_ok(cf, key, out, err, errcap) != NGX_OK) {
        return -1;
    }
    if ((size_t) (arg->data + arg->len - eq) != 2) {
        return 0;
    }
    return ngx_tolower(eq[1]);
}

/* `mode=e|s` — GFD.020 §3.4 extended block mode, or RFC 959 stream mode. */
static ngx_int_t
tier_parse_ftp_mode(ngx_conf_t *cf, ngx_str_t *arg, brix_tier_cfg_t *out,
    char *err, size_t errcap)
{
    int  letter = tier_ftp_param_letter(cf, arg, out, err, errcap);

    if (letter < 0) {
        return NGX_ERROR;
    }
    if (letter == 'e') {
        out->ftp_mode_e = 1;
        return NGX_OK;
    }
    if (letter == 's') {
        out->ftp_mode_e = 0;
        return NGX_OK;
    }
    return tier_fail(cf, 1, err, errcap,
        "invalid mode value (want \"e\" or \"s\")");
}

/* `prot=p|c` — TLS on the data socket (with DCAU A), or a cleartext one.
 *
 * `prot=p` is refused on a plain ftp:// store because the protection is only
 * worth anything when the data peer can be PINNED to the control channel's
 * X.509 identity: without GSI on the control channel there is no identity to
 * pin to, and an unpinned TLS data channel authenticates nobody. */
static ngx_int_t
tier_parse_ftp_prot(ngx_conf_t *cf, ngx_str_t *arg, brix_tier_cfg_t *out,
    char *err, size_t errcap)
{
    int  letter = tier_ftp_param_letter(cf, arg, out, err, errcap);

    if (letter < 0) {
        return NGX_ERROR;
    }
    if (letter == 'p') {
        if (!out->tls) {
            return tier_fail(cf, 1, err, errcap,
                "\"prot=p\" needs a gsiftp:// store: a protected data channel "
                "pins its peer to the control channel's X.509 identity, and a "
                "plain ftp:// control channel has none");
        }
        out->ftp_prot_p = 1;
        return NGX_OK;
    }
    if (letter == 'c') {
        out->ftp_prot_p = 0;
        return NGX_OK;
    }
    return tier_fail(cf, 1, err, errcap,
        "invalid prot value (want \"p\" or \"c\")");
}

/* `streams=<n>` — the ceiling on data connections one READ may open, asked for
 * with GFD.020 SPAS (phase-115 W5.3).
 *
 * Unlike its two neighbours this is a budget rather than a demand: an origin
 * that will not stripe still serves the same bytes over one connection.  What
 * it is NOT is free — every stream is a socket held by one blocking VFS worker
 * for the length of a transfer — so the value is bounded here rather than left
 * to whatever the origin's SPAS reply happens to list. */
static ngx_int_t
tier_parse_ftp_streams(ngx_conf_t *cf, ngx_str_t *arg, brix_tier_cfg_t *out,
    char *err, size_t errcap)
{
    ngx_str_t  v;
    ngx_int_t  n;

    if (tier_ftp_param_driver_ok(cf, "streams", out, err, errcap) != NGX_OK) {
        return NGX_ERROR;
    }
    v.data = arg->data + sizeof("streams=") - 1;
    v.len  = arg->len - (sizeof("streams=") - 1);

    n = ngx_atoi(v.data, v.len);
    if (n == NGX_ERROR || n < 1 || n > GFTP_STREAMS_MAX) {
        return tier_fail(cf, 1, err, errcap,
            "invalid streams value (want 1..%d)", GFTP_STREAMS_MAX);
    }
    out->ftp_streams = (unsigned) n;
    return NGX_OK;
}

/* Cross-param check, run once the WHOLE line is parsed.
 *
 * `streams=` and `mode=` can be written in either order, so neither parser can
 * see the other's answer while it runs — a per-param check would accept
 * "streams=4 mode=e" and refuse "mode=e streams=4", which is an operator trap,
 * not a rule.  The rule itself: a striped transfer is reassembled from blocks
 * that carry their own absolute offsets, so it exists only in MODE E.  Asking
 * for it in stream mode would arm nothing at all, silently. */
static ngx_int_t
tier_check_ftp_args(ngx_conf_t *cf, brix_tier_cfg_t *out, char *err,
    size_t errcap)
{
    if (out->ftp_streams > 1 && !out->ftp_mode_e) {
        /* %u, not nginx's %ud: tier_fail formats through C vsnprintf, where
         * the trailing 'd' of an ngx_snprintf width suffix is a literal. */
        return tier_fail(cf, 1, err, errcap,
            "\"streams=%u\" needs \"mode=e\": a striped GridFTP transfer is "
            "reassembled from blocks that carry their own offsets, and stream "
            "mode has none", out->ftp_streams);
    }
    return NGX_OK;
}

/* ---- one parser per param -------------------------------------------------
 *
 * Each takes the raw token and validates it into *out, so the dispatch loop
 * below stays a table of names rather than a nest of branches. */

/* `credential=<name>` — bind the store line to a declared brix_credential. */
static ngx_int_t
tier_parse_credential(ngx_conf_t *cf, ngx_str_t *arg, brix_tier_cfg_t *out,
    char *err, size_t errcap)
{
    static const char        key[] = "credential=";
    const brix_credential_t *c;
    char                     name[256];
    size_t                   nl = arg->len - (sizeof(key) - 1);

    if (nl == 0 || nl >= sizeof(name)) {
        return tier_fail(cf, 1, err, errcap, "invalid credential name");
    }
    ngx_memcpy(name, arg->data + sizeof(key) - 1, nl);
    name[nl] = '\0';

    c = brix_credential_lookup(name);
    if (c == NULL) {
        return tier_fail(cf, 1, err, errcap, "no brix_credential \"%s\"", name);
    }
    out->credential = c;
    return NGX_OK;
}

/* `block_size=<n>` — the origin read/fetch stride, in nginx size syntax. */
static ngx_int_t
tier_parse_block_size(ngx_conf_t *cf, ngx_str_t *arg, brix_tier_cfg_t *out,
    char *err, size_t errcap)
{
    static const char  key[] = "block_size=";
    ngx_str_t          v;
    ssize_t            sz;

    v.len  = arg->len - (sizeof(key) - 1);
    v.data = arg->data + sizeof(key) - 1;

    sz = ngx_parse_size(&v);
    if (sz == NGX_ERROR) {
        return tier_fail(cf, 1, err, errcap, "invalid block_size");
    }
    out->block_size = (size_t) sz;
    return NGX_OK;
}

/* `nearline` — a bare flag, not a key=value: it declares that the store this
 * line names fronts tape/an MSS, so reads must recall asynchronously rather
 * than block.  Accepted on ANY SCHEME — tier_validate's MISS_SLOT(recall)/
 * MISS_CAP(NEARLINE) turns `nearline` on a driver that cannot stage into a
 * clean startup error naming the missing slot, a better operator message than
 * a scheme table with no spelling for "this origin sits in front of tape" —
 * but only in the BACKEND role.  A cache/stage/cold tier is by definition the
 * ONLINE copy that a recall lands in, so `nearline` there is always an
 * operator mistake, and nothing downstream reads t->nearline for those roles:
 * accepting it silently would leave the operator believing they had armed
 * async recall. */
static ngx_int_t
tier_parse_nearline(ngx_conf_t *cf, brix_tier_cfg_t *out, char *err,
    size_t errcap)
{
    if (out->role != BRIX_TIER_BACKEND) {
        return tier_fail(cf, 1, err, errcap,
            "\"nearline\" belongs on brix_storage_backend, not on %s "
            "(a cache/stage tier IS the recall target)",
            tier_role_directive(out->role));
    }
    out->nearline = 1;
    return NGX_OK;
}

/* `permit=<host|.suffix>` (2.0 F5) — one origin-host pattern a forward://
 * backend may relay to; repeat the param for more.  An exact host matches
 * itself (case-insensitively), a leading-dot pattern matches every host in
 * that domain.  Only the forwarding driver reads the list, so the param is
 * refused everywhere else: a `permit=` on a fixed-origin line would name a
 * host that nothing checks, while the operator believes an ACL is in force.
 * One pattern per param — a space (the list joiner) or a slash (a URL, not a
 * host) is refused so a mistyped URL cannot become a permit for its first
 * label. */
static ngx_int_t
tier_parse_permit(ngx_conf_t *cf, ngx_str_t *arg, brix_tier_cfg_t *out,
    char *err, size_t errcap)
{
    static const char  key[] = "permit=";
    size_t             vlen = arg->len - (sizeof(key) - 1);
    u_char            *v = arg->data + sizeof(key) - 1;
    size_t             have = ngx_strlen(out->fwd_permit);

    if (out->role != BRIX_TIER_BACKEND) {
        return tier_fail(cf, 1, err, errcap,
            "\"permit=\" belongs on a brix_storage_backend forward:// line, "
            "not on %s (a store has one fixed origin to reach)",
            tier_role_directive(out->role));
    }
    if (ngx_strcmp(out->driver, "xroot_fwd") != 0) {
        return tier_fail(cf, 1, err, errcap,
            "\"permit=\" belongs on a forward:// backend line; the %s driver "
            "checks no origin permit list", out->driver);
    }
    if (vlen == 0
        || ngx_strlchr(v, v + vlen, ' ') != NULL
        || ngx_strlchr(v, v + vlen, '/') != NULL)
    {
        return tier_fail(cf, 1, err, errcap,
            "\"permit=\" takes one host or .suffix per param, not \"%.*s\"",
            (int) vlen, (const char *) v);
    }
    if (have + (have ? 1 : 0) + vlen >= sizeof(out->fwd_permit)) {
        return tier_fail(cf, 1, err, errcap,
            "\"permit=\" list too long (%zu bytes max, all patterns joined)",
            sizeof(out->fwd_permit) - 1);
    }
    if (have) {
        out->fwd_permit[have++] = ' ';
    }
    ngx_memcpy(out->fwd_permit + have, v, vlen);
    out->fwd_permit[have + vlen] = '\0';
    return NGX_OK;
}

/* The three shapes a store-line param can take.  They differ only in what may
 * FOLLOW the keyword.  The distinction is load-bearing here and was not before
 * the table: `nearline` used to be matched by a hand-written exact-length
 * compare in tier_parse_one_arg, so tier_arg_is()'s loose non-`key=` branch had
 * exactly one caller — `verify_pages`, whose own parser validates the tail and
 * so never needed the matcher to be strict.  Folding the cloned dispatch ifs
 * into this table moves `nearline` onto the shared matcher, and a two-state
 * flag would have silently widened it to accept `nearlinex`. */
typedef enum {
    TIER_ARG_VALUED,      /* `key=value` — strictly longer than "key="       */
    TIER_ARG_OPT_VALUE,   /* `key` or `key=value` — the parser reads the tail */
    TIER_ARG_BARE         /* `key` and nothing else                          */
} tier_arg_shape_e;

/* Does `arg` carry param `key` in shape `shape`?
 *
 * WHY: A BARE keyword matched on a prefix is silently wrong — `nearlinex`
 *      would set out->nearline with no diagnostic, leaving the operator
 *      believing they had armed async recall with a word nothing validated.
 *      `nearline` has no value vocabulary of its own, so there is no second
 *      layer to catch the typo.  An OPT_VALUE keyword still matches long
 *      tokens on purpose: its own parser owns the "=require"/"=best-effort"
 *      vocabulary and refuses `verify_pagesss` there, with a message naming
 *      the param the operator meant.
 */
static int
tier_arg_is(ngx_str_t *arg, const char *key, size_t keylen,
    tier_arg_shape_e shape)
{
    switch (shape) {
    case TIER_ARG_VALUED:
        if (arg->len <= keylen) {
            return 0;
        }
        break;
    case TIER_ARG_BARE:
        if (arg->len != keylen) {
            return 0;
        }
        break;
    default:                                     /* TIER_ARG_OPT_VALUE */
        if (arg->len < keylen) {
            return 0;
        }
        break;
    }
    return ngx_strncmp(arg->data, key, keylen) == 0;
}

/* `nearline` is a bare flag, so its parser has no value to read; the routing
 * table wants one uniform signature. */
static ngx_int_t
tier_parse_nearline_arg(ngx_conf_t *cf, ngx_str_t *arg, brix_tier_cfg_t *out,
    char *err, size_t errcap)
{
    return tier_parse_nearline(cf, out, err, errcap);
}

typedef ngx_int_t (*tier_arg_parser_pt)(ngx_conf_t *cf, ngx_str_t *arg,
    brix_tier_cfg_t *out, char *err, size_t errcap);

typedef struct {
    const char          *kw;
    size_t               len;
    tier_arg_shape_e     shape;
    tier_arg_parser_pt   parse;
} tier_arg_kw_t;

/* The store-line keyword table.  Const data, not state: one row per param, so
 * adding a param is one row rather than another cloned `if`. */
static const tier_arg_kw_t  tier_arg_kws[] = {
    { "credential=",  sizeof("credential=") - 1,  TIER_ARG_VALUED,
      tier_parse_credential },
    { "block_size=",  sizeof("block_size=") - 1,  TIER_ARG_VALUED,
      tier_parse_block_size },
    { "verify_pages", sizeof("verify_pages") - 1, TIER_ARG_OPT_VALUE,
      tier_parse_verify_pages },
    { "mode=",        sizeof("mode=") - 1,        TIER_ARG_VALUED,
      tier_parse_ftp_mode },
    { "prot=",        sizeof("prot=") - 1,        TIER_ARG_VALUED,
      tier_parse_ftp_prot },
    { "streams=",     sizeof("streams=") - 1,     TIER_ARG_VALUED,
      tier_parse_ftp_streams },
    { "nearline",     sizeof("nearline") - 1,     TIER_ARG_BARE,
      tier_parse_nearline_arg },
    { "permit=",      sizeof("permit=") - 1,      TIER_ARG_VALUED,
      tier_parse_permit },
};

/* Route ONE store-line param to its parser.  An unrecognised token is an
 * OPERATOR error, never a silently ignored word: a misspelled `verify_page`
 * must fail nginx -t rather than leave the operator believing the store line
 * says something it does not. */
static ngx_int_t
tier_parse_one_arg(ngx_conf_t *cf, ngx_str_t *arg, brix_tier_cfg_t *out,
    char *err, size_t errcap)
{
    ngx_uint_t  i;

    for (i = 0; i < sizeof(tier_arg_kws) / sizeof(tier_arg_kws[0]); i++) {
        if (tier_arg_is(arg, tier_arg_kws[i].kw, tier_arg_kws[i].len,
                        tier_arg_kws[i].shape))
        {
            return tier_arg_kws[i].parse(cf, arg, out, err, errcap);
        }
    }
    return tier_fail(cf, 1, err, errcap, "unknown store param \"%.*s\"",
                     (int) arg->len, arg->data);
}

/* Parse every trailing param on the store line into *out. */
ngx_int_t
tier_parse_args(ngx_conf_t *cf, ngx_array_t *args, brix_tier_cfg_t *out,
    char *err, size_t errcap)
{
    ngx_str_t  *a;
    ngx_uint_t  i;

    if (args == NULL) {
        return NGX_OK;
    }
    a = args->elts;
    for (i = 0; i < args->nelts; i++) {
        if (tier_parse_one_arg(cf, &a[i], out, err, errcap) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return tier_check_ftp_args(cf, out, err, errcap);
}
