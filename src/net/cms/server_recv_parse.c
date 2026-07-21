/*
 * cms/server_recv_parse.c — CMS server-side wire payload decoders.
 *
 * WHAT: Pure decoders for the CMS frame payloads an accepted data server sends:
 * the XrdOucPup TLV scalar walk, the OucPup string reader, the LOGIN
 * (CmsLoginData) parser that fills ctx->{free_mb,util_pct,port,paths}, and the
 * LOAD / AVAIL / SPACE load-figure extractors.
 *
 * WHY: Split out of the former monolithic server_recv.c (Phase-79 file-size
 * split).  These functions are side-effect-free parsers (no I/O, no socket, no
 * registry) — isolating them keeps the "how the wire bytes decode" concern in
 * one testable place, separate from dispatch and the event loop.  The three
 * entry points invoked by the frame handlers are declared in
 * server_recv_internal.h and are therefore non-static here; the TLV/string/
 * LOGIN-segment helpers stay file-local.
 *
 * HOW: tlv_read_next / cms_srv_read_string advance a (p, end) cursor by one
 * tagged value; cms_srv_parse_login composes the scalar prologue decode with a
 * newline-segment Paths walk; the LOAD/AVAIL parsers read fixed scalar layouts.
 */

#include "server.h"
#include "server_recv_internal.h"

/* TLV walk helpers */

/*
 * The LOGIN/LOAD/AVAIL payloads use a simple type-tagged encoding:
 *   CMS_PT_SHORT (0x80) + big-endian uint16
 *   CMS_PT_INT   (0xa0) + big-endian uint32
 *
 * Walk *p forward by one tagged value, returning the decoded uint32.
 * Advances *p past the tag+value bytes.  Returns 0 and sets *p=end on error.
 */
static uint32_t
tlv_read_next(const u_char **p, const u_char *end)
{
    if (*p >= end) {
        *p = end;
        return 0;
    }

    if (**p == CMS_PT_SHORT) {
        if (end - *p < 3) { *p = end; return 0; }
        uint32_t v = ngx_brix_cms_get16(*p + 1);
        *p += 3;
        return v;
    }

    if (**p == CMS_PT_INT) {
        if (end - *p < 5) { *p = end; return 0; }
        uint32_t v = ngx_brix_cms_get32(*p + 1);
        *p += 5;
        return v;
    }

    /* Unknown tag — treat as end of parseable data. */
    *p = end;
    return 0;
}

/*
 * Read one XrdOucPup string from *p: a 2-byte big-endian length followed by
 * <len> raw bytes (the length includes the trailing NUL).  Sets *out / *out_len
 * to the data span and advances *p.  Returns 1 on success, 0 (and *p=end) on a
 * short/overrun buffer.  Strings carry NO type tag — the high bit of the first
 * length byte is clear for any reasonable length, which is how the real Parser
 * tells a string apart from a PT_short/PT_int scalar.
 */
static int
cms_srv_read_string(const u_char **p, const u_char *end,
    const u_char **out, size_t *out_len)
{
    uint16_t  len;

    if (end - *p < 2) { *p = end; return 0; }
    len = ngx_brix_cms_get16(*p);
    *p += 2;
    if ((size_t) (end - *p) < len) { *p = end; return 0; }
    *out = *p;
    *out_len = len;
    *p += len;
    return 1;
}

/* LOGIN payload parser */

/*
 * Parse the CMS LOGIN frame payload in the real XrdCms CmsLoginData wire format
 * (XrdOucPup), the same one a real cmsd and our own cms/send.c now emit:
 *
 *   PT_SHORT Version    PT_INT Mode      PT_INT HoldTime
 *   PT_INT   tSpace     PT_INT fSpace ←free_mb   PT_INT mSpace
 *   PT_SHORT fsNum      PT_SHORT fsUtil ←util_pct PT_SHORT dPort ←port
 *   PT_SHORT sPort      [Fence]
 *   string SID          string Paths     string ifList   string envCGI
 *
 * The Paths string is a newline-separated list of "<type> <namespace-path>"
 * entries (type 'r'/'w', e.g. "w /\nw /atlas").  We strip the type prefix and
 * store the bare namespace paths colon-delimited ("/:/atlas") — the form the
 * registry's srv_path_matches() expects.
 */

/*
 * cms_srv_login_scalars — decode the fixed PT_SHORT/PT_INT scalar prologue of
 * the LOGIN payload (Version..sPort), capturing free_mb/util_pct/port on ctx.
 * Splitting the scalar block from the string/paths negotiation keeps each
 * piece independently checkable.  Advances *p past the block; tlv_read_next()
 * self-terminates on a short buffer so missing fields decode as 0.
 */
static void
cms_srv_login_scalars(brix_cms_srv_ctx_t *ctx,
    const u_char **p, const u_char *end)
{
    /* version */   (void) tlv_read_next(p, end);
    /* mode    */   (void) tlv_read_next(p, end);
    /* holdtime */  (void) tlv_read_next(p, end);
    /* tSpace  */   (void) tlv_read_next(p, end);
    ctx->free_mb  = tlv_read_next(p, end);     /* fSpace  */
    /* mSpace  */   (void) tlv_read_next(p, end);
    /* fsNum   */   (void) tlv_read_next(p, end);
    ctx->util_pct = tlv_read_next(p, end);     /* fsUtil  */
    ctx->port     = (uint16_t) tlv_read_next(p, end); /* dPort */
    /* sPort   */   (void) tlv_read_next(p, end);
}

/*
 * cms_srv_login_seg_path — reduce one "<type> <path>" Paths segment to the
 * bare path: drop the leading type token up to and including the first run of
 * spaces (a segment without a space is taken verbatim), then trim trailing
 * blanks.  Adjusts *tok / *tok_len in place; *tok_len may become 0.
 */
static void
cms_srv_login_seg_path(const u_char **tok, size_t *tok_len)
{
    size_t  sp = 0;

    /* split off the leading "<type> " prefix, if any */
    while (sp < *tok_len && (*tok)[sp] != ' ') {
        sp++;
    }
    if (sp < *tok_len) {              /* found a space → path follows it */
        sp++;
        while (sp < *tok_len && (*tok)[sp] == ' ') {
            sp++;
        }
        *tok += sp;
        *tok_len -= sp;
    }

    while (*tok_len > 0
           && ((*tok)[*tok_len - 1] == ' ' || (*tok)[*tok_len - 1] == '\t'))
    {
        (*tok_len)--;
    }
}

/*
 * cms_srv_login_next_path — scan the newline-separated Paths string for the
 * next segment starting at *i, skipping blank/NUL padding, and hand back the
 * bare path span via cms_srv_login_seg_path().  Advances *i past the segment.
 * Returns 1 with *tok / *tok_len set (len may be 0), 0 when exhausted.
 */
static int
cms_srv_login_next_path(const u_char *paths, size_t paths_len, size_t *i,
    const u_char **tok, size_t *tok_len)
{
    size_t  seg_end;

    while (*i < paths_len
           && (paths[*i] == '\n' || paths[*i] == ' '
               || paths[*i] == '\t' || paths[*i] == '\0'))
    {
        (*i)++;
    }
    if (*i >= paths_len) {
        return 0;
    }

    /* find end of this segment (newline / NUL terminated) */
    seg_end = *i;
    while (seg_end < paths_len
           && paths[seg_end] != '\n' && paths[seg_end] != '\0')
    {
        seg_end++;
    }

    *tok = paths + *i;
    *tok_len = seg_end - *i;
    cms_srv_login_seg_path(tok, tok_len);

    *i = seg_end;
    return 1;
}

/*
 * cms_srv_login_append_path — append one bare path to the colon-delimited
 * ctx->paths buffer, truncating at the buffer boundary exactly like the
 * original inline copy loop.  Empty tokens (type-only segments) are dropped.
 */
static void
cms_srv_login_append_path(brix_cms_srv_ctx_t *ctx, u_char **dst,
    u_char *dst_end, const u_char *tok, size_t tok_len)
{
    size_t  cp;

    if (tok_len == 0) {
        return;
    }

    if (*dst != (u_char *) ctx->paths && *dst < dst_end) {
        *(*dst)++ = ':';
    }
    cp = (size_t) (dst_end - *dst);
    if (cp > tok_len) {
        cp = tok_len;
    }
    ngx_memcpy(*dst, tok, cp);
    *dst += cp;
}

int
cms_srv_parse_login(brix_cms_srv_ctx_t *ctx,
    const u_char *payload, size_t payload_len)
{
    const u_char  *p   = payload;
    const u_char  *end = payload + payload_len;
    const u_char  *sid;
    const u_char  *paths;
    const u_char  *tok;
    size_t         sid_len;
    size_t         paths_len;
    size_t         tok_len;
    u_char        *dst;
    u_char        *dst_end;
    size_t         i;

    cms_srv_login_scalars(ctx, &p, end);

    /* SID (ignored) then Paths (extracted); ifList ignored, envCGI scanned
     * for the vnid token below. */
    (void) cms_srv_read_string(&p, end, &sid, &sid_len);
    if (!cms_srv_read_string(&p, end, &paths, &paths_len)) {
        paths = NULL;
        paths_len = 0;
    }

    /*
     * Convert "<type> <path>\n<type> <path>..." -> colon-delimited bare paths.
     * Each newline segment is "<type> <path>"; the path follows the first
     * space.  A segment without a space is taken verbatim as the path.
     */
    dst     = (u_char *) ctx->paths;
    dst_end = dst + sizeof(ctx->paths) - 1;
    i = 0;
    while (dst < dst_end
           && cms_srv_login_next_path(paths, paths_len, &i, &tok, &tok_len))
    {
        cms_srv_login_append_path(ctx, &dst, dst_end, tok, tok_len);
    }
    *dst = '\0';

    /*
     * Phase-89 W9: extract the virtual network id from envCGI ("&"-separated
     * CGI tokens; stock cmsd emits "vnid=<id>").  ifList is skipped to reach
     * it in wire order.  Absent/empty → ctx->vnid stays "".
     */
    ctx->vnid[0] = '\0';
    {
        const u_char  *iflist, *env, *tok;
        size_t         iflist_len, env_len, i, vl;

        if (cms_srv_read_string(&p, end, &iflist, &iflist_len)
            && cms_srv_read_string(&p, end, &env, &env_len))
        {
            for (i = 0; i + 5 <= env_len; i++) {
                if ((i == 0 || env[i - 1] == '&')
                    && ngx_strncmp(env + i, "vnid=", 5) == 0)
                {
                    tok = env + i + 5;
                    vl  = 0;
                    while (i + 5 + vl < env_len && tok[vl] != '&'
                           && tok[vl] != '\0' && vl < sizeof(ctx->vnid) - 1)
                    {
                        ctx->vnid[vl] = (char) tok[vl];
                        vl++;
                    }
                    ctx->vnid[vl] = '\0';
                    break;
                }
            }
        }
    }

    /* Default XRootD port if the data server didn't advertise one. */
    if (ctx->port == 0) {
        ctx->port = BRIX_DEFAULT_PORT;
    }

    return 1;
}

/* LOAD/AVAIL payload parsers */

/*
 * LOAD payload (from cms/send.c):
 *   PT_SHORT  count=6      (3 bytes)
 *   <6 raw bytes>          (cpu load values, ignored)
 *   PT_INT    free_mb      (5 bytes)  ← extracted
 */
uint32_t
cms_srv_parse_load_free_mb(const u_char *payload, size_t payload_len)
{
    const u_char  *p   = payload;
    const u_char  *end = payload + payload_len;

    /* count field */
    (void) tlv_read_next(&p, end);

    /* skip 6 raw CPU bytes */
    if (end - p >= 6) {
        p += 6;
    } else {
        return 0;
    }

    return tlv_read_next(&p, end);
}

/*
 * cms_srv_parse_load_machine_pct — extract the machine-load percentage from
 * the LOAD payload's 6 theLoad bytes: the max of cpu/net/xeq/mem/pag (the
 * bottleneck resource; dsk is excluded — disk fill is already tracked as
 * util_pct/free_mb).  Returns 0-100; a short payload reads as 0 (idle),
 * matching the parser's general missing-field-decodes-as-zero posture.
 */
uint32_t
cms_srv_parse_load_machine_pct(const u_char *payload, size_t payload_len)
{
    uint32_t  best = 0;
    size_t    i;

    /* [2-byte blob len][6 load bytes ...] — the 5 machine bytes start at 2. */
    if (payload_len < 2 + 5) {
        return 0;
    }
    for (i = 2; i < 2 + 5; i++) {
        if (payload[i] > best) {
            best = payload[i];
        }
    }
    return best > 100 ? 100 : best;
}

/*
 * AVAIL payload (from cms/send.c):
 *   PT_INT    free_mb      (5 bytes)  ← extracted
 *   PT_INT    util_pct     (5 bytes)  ← extracted
 *
 * Used for both CMS_RR_AVAIL and CMS_RR_SPACE.
 */
void
cms_srv_parse_avail(const u_char *payload, size_t payload_len,
    uint32_t *free_mb, uint32_t *util_pct)
{
    const u_char  *p   = payload;
    const u_char  *end = payload + payload_len;

    *free_mb  = tlv_read_next(&p, end);
    *util_pct = tlv_read_next(&p, end);
}
