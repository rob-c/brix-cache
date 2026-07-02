#include "core/ngx_xrootd_module.h"
#include "observability/metrics/unified.h"
#include "protocols/root/session/registry.h"

#include <string.h>

/*
 * auth.c — XRootD `unix` (client-asserted UNIX-name) authentication handler
 *
 * WHAT: Implements the kXR_auth handler for the XRootD `unix` security
 *       protocol. The client merely *declares* a user name (and optional
 *       group) in the credential blob; there is no cryptographic proof.
 *       xrootd_handle_unix_auth() parses and character-validates those names,
 *       populates the per-connection identity (ctx->dn, ctx->vo_list,
 *       ctx->primary_vo, and the canonical ctx->identity), registers the
 *       session, emits auth metrics, writes a sanitised audit line, and
 *       replies kXR_ok — or rejects with kXR_NotAuthorized / kXR_NoMemory.
 *
 * WHY:  Grid sites need an unauthenticated path for trusted local clients,
 *       sidecars, and intra-host tooling that should not have to mint a proxy
 *       cert or token. Because `unix` is unverified, this handler is
 *       deliberately fail-closed: by default it is honoured only for loopback
 *       peers (unless conf->unix_trust_remote is set), and it must be
 *       explicitly selected (conf->auth == XROOTD_AUTH_UNIX) before the GSI
 *       auth dispatcher (../gsi/auth.c) will ever route a "unix" credtype here.
 *       Isolating it in one file keeps the "the client names itself" attack
 *       surface auditable in a single place.
 *
 * HOW:  This is the stream / root:// path, downstream of kXR_login and inside
 *       the kXR_auth dispatcher. xrootd_handle_unix_auth() first gates on
 *       xrootd_unix_peer_is_loopback() (over the connection sockaddr), then
 *       validates the leading "unix\0" tag in ctx->payload, splits the
 *       remaining space/NUL-delimited bytes into user and optional group, runs
 *       each through xrootd_unix_copy_name() (which enforces an allow-list of
 *       safe bytes via xrootd_unix_name_byte_ok() and a bounded destination).
 *       Validated names are copied into the identity fields, the session is
 *       registered, and VO/unique-user metrics are bumped via
 *       xrootd_unix_track_identity(). Every exit path increments the
 *       XROOTD_AUTHN_UNIX auth metric (fail=0 / ok=1) and returns through the
 *       XROOTD_RETURN_ERR / XROOTD_RETURN_OK framing macros.
 */

/*
 * Return non-zero when the peer connection originates from the local host:
 * an IPv4 127.0.0.0/8 address, the IPv6 ::1 loopback, or any AF_UNIX socket.
 * This is the default trust gate for `unix` auth (bypassed only when
 * conf->unix_trust_remote is set), so a NULL connection/sockaddr is treated
 * as untrusted (returns 0).
 */
static ngx_flag_t
xrootd_unix_peer_is_loopback(ngx_connection_t *c)
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
xrootd_unix_name_byte_ok(u_char ch)
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
 * xrootd_unix_name_byte_ok(); otherwise copies `len` bytes and appends '\0',
 * returning NGX_OK. This is the single choke point that bounds and sanitises
 * both the user and the optional group strings.
 */
static ngx_int_t
xrootd_unix_copy_name(char *dst, size_t dst_len, const u_char *src,
    size_t len)
{
    size_t i;

    if (dst == NULL || dst_len == 0 || src == NULL || len == 0
        || len >= dst_len)
    {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        if (!xrootd_unix_name_byte_ok(src[i])) {
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
xrootd_unix_track_identity(xrootd_ctx_t *ctx)
{
    ngx_xrootd_metrics_t *shm;

    shm = xrootd_metrics_shared();
    if (shm == NULL) {
        return;
    }

    if (ctx->primary_vo[0] != '\0') {
        xrootd_track_vo_activity(shm, ctx->primary_vo, 0, 0);
    }
    if (ctx->dn[0] != '\0') {
        xrootd_track_unique_user(shm, ctx->dn, strlen(ctx->dn));
    }
}

/*
 * Public entry point for the XRootD `unix` auth scheme, called from the GSI
 * auth dispatcher (../gsi/auth.c) once it has matched the "unix" credtype and
 * confirmed conf->auth == XROOTD_AUTH_UNIX.
 *
 * Enforces the loopback trust gate (unless conf->unix_trust_remote), validates
 * the "unix\0" tag, parses the space/NUL-delimited user and optional group out
 * of ctx->payload, and character-validates both via xrootd_unix_copy_name().
 * On success it marks the session authenticated (ctx->auth_done = 1,
 * token_auth = 0), fills ctx->dn / ctx->vo_list / ctx->primary_vo and the
 * canonical ctx->identity, registers the session, bumps metrics, logs a
 * sanitised audit line, and returns kXR_ok via XROOTD_RETURN_OK. Any failure
 * increments the failed-auth metric and returns kXR_NotAuthorized (bad peer,
 * malformed credential, invalid user/group) or kXR_NoMemory (identity alloc).
 */
ngx_int_t
xrootd_handle_unix_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    const u_char *p, *end, *user_start, *group_start;
    size_t        user_len, group_len;
    char          user[XROOTD_SSS_USER_MAX];
    char          group[XROOTD_SSS_GROUP_MAX];
    char          safe_user[XROOTD_SSS_USER_MAX * 4];
    char          safe_group[XROOTD_SSS_GROUP_MAX * 4];

    if (!conf->unix_trust_remote && !xrootd_unix_peer_is_loopback(c)) {
        xrootd_metric_auth(XROOTD_PROTO_ROOT, XROOTD_AUTHN_UNIX, 0);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", "unix",
                          kXR_NotAuthorized,
                          "unix auth is restricted to loopback peers");
    }

    if (ctx->payload == NULL || ctx->cur_dlen < 6
        || ngx_strncmp(ctx->payload, "unix", 4) != 0
        || ctx->payload[4] != '\0')
    {
        xrootd_metric_auth(XROOTD_PROTO_ROOT, XROOTD_AUTHN_UNIX, 0);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", "unix",
                          kXR_NotAuthorized, "malformed unix credential");
    }

    p = ctx->payload + 5;
    end = ctx->payload + ctx->cur_dlen;
    while (p < end && *p == ' ') {
        p++;
    }
    user_start = p;
    while (p < end && *p != '\0' && *p != ' ') {
        p++;
    }
    user_len = (size_t) (p - user_start);

    group[0] = '\0';
    if (p < end && *p == ' ') {
        while (p < end && *p == ' ') {
            p++;
        }
        group_start = p;
        while (p < end && *p != '\0' && *p != ' ') {
            p++;
        }
        group_len = (size_t) (p - group_start);
        if (group_len > 0
            && xrootd_unix_copy_name(group, sizeof(group), group_start,
                                     group_len) != NGX_OK)
        {
            xrootd_metric_auth(XROOTD_PROTO_ROOT, XROOTD_AUTHN_UNIX, 0);
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", "unix",
                              kXR_NotAuthorized, "invalid unix group");
        }
    }

    if (xrootd_unix_copy_name(user, sizeof(user), user_start, user_len)
        != NGX_OK)
    {
        xrootd_metric_auth(XROOTD_PROTO_ROOT, XROOTD_AUTHN_UNIX, 0);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", "unix",
                          kXR_NotAuthorized, "invalid unix user");
    }

    ctx->auth_done = 1;
    ctx->token_auth = 0;
    ngx_cpystrn((u_char *) ctx->dn, (u_char *) user, sizeof(ctx->dn));
    if (group[0] != '\0') {
        ngx_cpystrn((u_char *) ctx->vo_list, (u_char *) group,
                    sizeof(ctx->vo_list));
        ngx_cpystrn((u_char *) ctx->primary_vo, (u_char *) group,
                    sizeof(ctx->primary_vo));
    }

    if (ctx->identity != NULL) {
        if (xrootd_identity_set_dn(ctx->identity, c->pool, ctx->dn,
                                   XROOTD_AUTHN_UNIX) != NGX_OK
            || xrootd_identity_set_vos_csv(ctx->identity, c->pool,
                                           ctx->vo_list) != NGX_OK)
        {
            return xrootd_send_error(ctx, c, kXR_NoMemory,
                                     "identity allocation failed");
        }
    }

    xrootd_session_register(ctx->sessid, ctx->dn, ctx->vo_list, 0);
    xrootd_unix_track_identity(ctx);

    xrootd_sanitize_log_string(user, safe_user, sizeof(safe_user));
    xrootd_sanitize_log_string(group[0] ? group : "-", safe_group,
                               sizeof(safe_group));
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: unix auth OK user=\"%s\" group=\"%s\"",
                  safe_user, safe_group);

    xrootd_metric_auth(XROOTD_PROTO_ROOT, XROOTD_AUTHN_UNIX, 1);
    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", "unix", 0);
}
