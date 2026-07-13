#include "core/ngx_brix_module.h"
#include "observability/metrics/unified.h"
#include "protocols/root/session/registry.h"

#include <string.h>

/*
 * auth.c — XRootD `unix` (client-asserted UNIX-name) authentication handler
 *
 * WHAT: Implements the kXR_auth handler for the XRootD `unix` security
 *       protocol. The client merely *declares* a user name (and optional
 *       group) in the credential blob; there is no cryptographic proof.
 *       brix_handle_unix_auth() parses and character-validates those names,
 *       populates the per-connection identity (ctx->login.dn, ctx->login.vo_list,
 *       ctx->login.primary_vo, and the canonical ctx->identity), registers the
 *       session, emits auth metrics, writes a sanitised audit line, and
 *       replies kXR_ok — or rejects with kXR_NotAuthorized / kXR_NoMemory.
 *
 * WHY:  Grid sites need an unauthenticated path for trusted local clients,
 *       sidecars, and intra-host tooling that should not have to mint a proxy
 *       cert or token. Because `unix` is unverified, this handler is
 *       deliberately fail-closed: by default it is honoured only for loopback
 *       peers (unless conf->unix_trust_remote is set), and it must be
 *       explicitly selected (conf->auth == BRIX_AUTH_UNIX) before the GSI
 *       auth dispatcher (../gsi/auth.c) will ever route a "unix" credtype here.
 *       Isolating it in one file keeps the "the client names itself" attack
 *       surface auditable in a single place.
 *
 * HOW:  This is the stream / root:// path, downstream of kXR_login and inside
 *       the kXR_auth dispatcher. brix_handle_unix_auth() first gates on
 *       brix_unix_peer_is_loopback() (over the connection sockaddr), then
 *       validates the leading "unix\0" tag in ctx->recv.payload, splits the
 *       remaining space/NUL-delimited bytes into user and optional group, runs
 *       each through brix_unix_copy_name() (which enforces an allow-list of
 *       safe bytes via brix_unix_name_byte_ok() and a bounded destination).
 *       Validated names are copied into the identity fields, the session is
 *       registered, and VO/unique-user metrics are bumped via
 *       brix_unix_track_identity(). Every exit path increments the
 *       BRIX_AUTHN_UNIX auth metric (fail=0 / ok=1) and returns through the
 *       BRIX_RETURN_ERR / BRIX_RETURN_OK framing macros.
 */

/*
 * Return non-zero when the peer connection originates from the local host:
 * an IPv4 127.0.0.0/8 address, the IPv6 ::1 loopback, or any AF_UNIX socket.
 * This is the default trust gate for `unix` auth (bypassed only when
 * conf->unix_trust_remote is set), so a NULL connection/sockaddr is treated
 * as untrusted (returns 0).
 */
static ngx_flag_t
brix_unix_peer_is_loopback(ngx_connection_t *c)
{
    if (c == NULL || c->sockaddr == NULL) {
        return 0;
    }

    if (c->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) c->sockaddr;
        return ((ntohl(sin->sin_addr.s_addr) >> 24) == 127);
    }

    if (c->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) c->sockaddr;
        return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr);
    }

    return c->sockaddr->sa_family == AF_UNIX;
}

/*
 * Allow-list predicate for a single byte of an asserted user/group name.
 * Accepts only [A-Za-z0-9] plus a small set of identity-safe punctuation
 * ('_', '-', '.', '@', '+'). Restricting the alphabet up front keeps the
 * unverified, attacker-controlled name out of log lines, metric labels, and
 * downstream ACL comparisons as anything other than plain printable text.
 */
static ngx_flag_t
brix_unix_name_byte_ok(u_char ch)
{
    return ((ch >= 'A' && ch <= 'Z')
            || (ch >= 'a' && ch <= 'z')
            || (ch >= '0' && ch <= '9')
            || ch == '_' || ch == '-' || ch == '.' || ch == '@' || ch == '+');
}

/*
 * Validate and NUL-terminate one wire name into a fixed-size buffer.
 * Rejects (NGX_ERROR) an empty source, a length that would not leave room for
 * the terminator (len >= dst_len), or any byte failing
 * brix_unix_name_byte_ok(); otherwise copies `len` bytes and appends '\0',
 * returning NGX_OK. This is the single choke point that bounds and sanitises
 * both the user and the optional group strings.
 */
static ngx_int_t
brix_unix_copy_name(char *dst, size_t dst_len, const u_char *src,
    size_t len)
{
    size_t i;

    if (dst == NULL || dst_len == 0 || src == NULL || len == 0
        || len >= dst_len)
    {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        if (!brix_unix_name_byte_ok(src[i])) {
            return NGX_ERROR;
        }
    }

    ngx_memcpy(dst, src, len);
    dst[len] = '\0';
    return NGX_OK;
}

/*
 * Record the freshly-authenticated identity in the shared metrics segment:
 * the primary VO (group) as VO activity and the DN (user) as a unique user.
 * Silently no-ops when the metrics SHM is unavailable or the corresponding
 * identity field is empty, so it is safe to call unconditionally on success.
 */
static void
brix_unix_track_identity(brix_ctx_t *ctx)
{
    ngx_brix_metrics_t *shm;

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    if (ctx->login.primary_vo[0] != '\0') {
        brix_track_vo_activity(shm, ctx->login.primary_vo, 0, 0);
    }
    if (ctx->login.dn[0] != '\0') {
        brix_track_unique_user(shm, ctx->login.dn, strlen(ctx->login.dn));
    }
}

/*
 * Parsed result of an asserted `unix` credential: the validated, NUL-terminated
 * user name and the optional group (empty string when the client sent none).
 * Populated by brix_unix_parse_cred(); consumed by brix_unix_apply_identity().
 */
typedef struct {
    char user[BRIX_SSS_USER_MAX];
    char group[BRIX_SSS_GROUP_MAX];
} brix_unix_names_t;

/*
 * WHAT: Confirm the credential blob opens with the expected "unix\0" tag.
 * WHY:  The `unix` scheme is unverified, so the one structural guarantee we
 *       insist on is the leading protocol tag; anything shorter or mistagged is
 *       a malformed credential and must be rejected before we parse names.
 * HOW:  Returns NGX_OK when payload is non-NULL, at least 6 bytes, begins with
 *       "unix", and byte 4 is NUL; otherwise NGX_DECLINED. No side effects.
 */
static ngx_int_t
brix_unix_tag_ok(const brix_ctx_t *ctx)
{
    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen < 6
        || ngx_strncmp(ctx->recv.payload, "unix", 4) != 0
        || ctx->recv.payload[4] != '\0')
    {
        return NGX_DECLINED;
    }
    return NGX_OK;
}

/*
 * WHAT: Advance `*p` over any run of ASCII spaces, then return the extent of the
 *       next space/NUL-delimited token as [start, *p).
 * WHY:  Both the user and the optional group are parsed with identical
 *       skip-spaces-then-take-a-token logic; centralising it keeps the parser
 *       linear and removes duplicated pointer walks.
 * HOW:  Pure cursor arithmetic over the half-open [*p, end) range: skip spaces,
 *       record the token start, advance to the first space/NUL/end, and report
 *       the token start plus its length via the out-params.
 */
static void
brix_unix_next_token(const u_char **p, const u_char *end,
    const u_char **tok_start, size_t *tok_len)
{
    const u_char *cur = *p;

    while (cur < end && *cur == ' ') {
        cur++;
    }
    *tok_start = cur;
    while (cur < end && *cur != '\0' && *cur != ' ') {
        cur++;
    }
    *tok_len = (size_t) (cur - *tok_start);
    *p = cur;
}

/*
 * WHAT: Parse the space/NUL-delimited user (mandatory) and group (optional) out
 *       of the credential payload and character-validate both into `names`.
 * WHY:  Isolating the untrusted-name parse keeps the single choke point for the
 *       safe-byte allow-list (brix_unix_copy_name) in one auditable place and
 *       out of the top-level control flow.
 * HOW:  Skips the "unix\0" tag, reads the user token, then (only if a further
 *       space-separated token follows) the group token. Each non-empty token is
 *       copied through brix_unix_copy_name(); on any validation failure returns
 *       NGX_DECLINED and writes the reject reason to *msg. Returns NGX_OK with
 *       names->group left "" when no group was asserted.
 */
static ngx_int_t
brix_unix_parse_cred(const brix_ctx_t *ctx, brix_unix_names_t *names,
    const char **msg)
{
    const u_char *p, *end, *user_start, *group_start;
    size_t        user_len = 0, group_len = 0;

    names->user[0] = '\0';
    names->group[0] = '\0';

    p = ctx->recv.payload + 5;
    end = ctx->recv.payload + ctx->recv.cur_dlen;

    brix_unix_next_token(&p, end, &user_start, &user_len);

    if (p < end && *p == ' ') {
        brix_unix_next_token(&p, end, &group_start, &group_len);
        if (group_len > 0
            && brix_unix_copy_name(names->group, sizeof(names->group),
                                     group_start, group_len) != NGX_OK)
        {
            *msg = "invalid unix group";
            return NGX_DECLINED;
        }
    }

    if (brix_unix_copy_name(names->user, sizeof(names->user), user_start,
                              user_len) != NGX_OK)
    {
        *msg = "invalid unix user";
        return NGX_DECLINED;
    }

    return NGX_OK;
}

/*
 * WHAT: Stamp the validated user/group onto the per-connection identity and
 *       mark the session authenticated (unverified, non-token).
 * WHY:  Populating ctx->login and the canonical ctx->identity is the load-
 *       bearing state transition; keeping it in one helper preserves the exact
 *       field-fill ordering that downstream ACL/session code depends on.
 * HOW:  Sets auth_done/token flags, copies user→login.dn and (when present)
 *       group→login.vo_list + login.primary_vo via ngx_cpystrn, then mirrors dn
 *       and the VO CSV into ctx->identity. Returns NGX_OK on success, or
 *       NGX_ABORT (with *code = kXR_NoMemory) if identity allocation fails.
 */
static ngx_int_t
brix_unix_apply_identity(brix_ctx_t *ctx, ngx_connection_t *c,
    const brix_unix_names_t *names, int *code)
{
    ctx->login.auth_done = 1;
    ctx->token.auth = 0;
    ngx_cpystrn((u_char *) ctx->login.dn, (u_char *) names->user,
                sizeof(ctx->login.dn));
    if (names->group[0] != '\0') {
        ngx_cpystrn((u_char *) ctx->login.vo_list, (u_char *) names->group,
                    sizeof(ctx->login.vo_list));
        ngx_cpystrn((u_char *) ctx->login.primary_vo, (u_char *) names->group,
                    sizeof(ctx->login.primary_vo));
    }

    if (ctx->identity != NULL) {
        if (brix_identity_set_dn(ctx->identity, c->pool, ctx->login.dn,
                                   BRIX_AUTHN_UNIX) != NGX_OK
            || brix_identity_set_vos_csv(ctx->identity, c->pool,
                                           ctx->login.vo_list) != NGX_OK)
        {
            *code = kXR_NoMemory;
            return NGX_ABORT;
        }
    }

    return NGX_OK;
}

/*
 * WHAT: Finalise a successful `unix` auth: register the session, bump identity
 *       metrics, and emit the sanitised audit line.
 * WHY:  The success epilogue is a fixed, side-effect-only sequence; separating
 *       it keeps the top-level function focused on validation control flow.
 * HOW:  Registers the session under login.sessid, calls brix_unix_track_identity
 *       for VO/unique-user metrics, then logs user/group through
 *       brix_sanitize_log_string (group shown as "-" when empty). No return.
 */
static void
brix_unix_finalize(brix_ctx_t *ctx, ngx_connection_t *c,
    const brix_unix_names_t *names)
{
    char safe_user[BRIX_SSS_USER_MAX * 4];
    char safe_group[BRIX_SSS_GROUP_MAX * 4];

    brix_session_register(ctx->login.sessid, ctx->login.dn,
                            ctx->login.vo_list, 0);
    brix_unix_track_identity(ctx);

    brix_sanitize_log_string(names->user, safe_user, sizeof(safe_user));
    brix_sanitize_log_string(names->group[0] ? names->group : "-", safe_group,
                               sizeof(safe_group));
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "brix: unix auth OK user=\"%s\" group=\"%s\"",
                  safe_user, safe_group);
}

/*
 * Public entry point for the XRootD `unix` auth scheme, called from the GSI
 * auth dispatcher (../gsi/auth.c) once it has matched the "unix" credtype and
 * confirmed conf->auth == BRIX_AUTH_UNIX.
 *
 * Enforces the loopback trust gate (unless conf->unix_trust_remote), validates
 * the "unix\0" tag, parses the space/NUL-delimited user and optional group out
 * of ctx->recv.payload, and character-validates both via brix_unix_copy_name().
 * On success it marks the session authenticated (ctx->login.auth_done = 1,
 * token_auth = 0), fills ctx->login.dn / ctx->login.vo_list / ctx->login.primary_vo and the
 * canonical ctx->identity, registers the session, bumps metrics, logs a
 * sanitised audit line, and returns kXR_ok via BRIX_RETURN_OK. Any failure
 * increments the failed-auth metric and returns kXR_NotAuthorized (bad peer,
 * malformed credential, invalid user/group) or kXR_NoMemory (identity alloc).
 */
ngx_int_t
brix_handle_unix_auth(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    brix_unix_names_t names;
    const char       *reject = NULL;
    int               err_code = kXR_NoMemory;

    if (!conf->unix_trust_remote && !brix_unix_peer_is_loopback(c)) {
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_UNIX, 0);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "unix",
                          kXR_NotAuthorized,
                          "unix auth is restricted to loopback peers");
    }

    if (brix_unix_tag_ok(ctx) != NGX_OK) {
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_UNIX, 0);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "unix",
                          kXR_NotAuthorized, "malformed unix credential");
    }

    if (brix_unix_parse_cred(ctx, &names, &reject) != NGX_OK) {
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_UNIX, 0);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "unix",
                          kXR_NotAuthorized, reject);
    }

    if (brix_unix_apply_identity(ctx, c, &names, &err_code) != NGX_OK) {
        return brix_send_error(ctx, c, err_code,
                                 "identity allocation failed");
    }

    brix_unix_finalize(ctx, c, &names);

    brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_UNIX, 1);
    BRIX_RETURN_OK(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "unix", 0);
}
