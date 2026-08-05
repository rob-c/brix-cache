/*
 * policy.c — protbind rule evaluation: peer → ordered protocol set.
 *
 * WHAT: Owns the decision half of the engine — building a frontend's base set,
 *       picking the first rule whose template matches the peer, and composing
 *       the rule's protocol list with the base set into the ordered result the
 *       caller advertises and enforces.
 *
 * WHY:  Kept apart from match.c (pure lookups) and config.c (parsing) so the
 *       precedence rules — first match wins, `none` short-circuits, `only`
 *       truncates, the default form appends the base — live in one small file
 *       that can be read end-to-end while auditing an access decision.
 *
 * HOW:  Every function here is pure over its arguments: no config lookups, no
 *       DNS, no logging.  Callers supply the already-resolved peer identity,
 *       which is what lets the root:// stream path and the HTTP path share
 *       this code unchanged.
 */

#include "core/ngx_brix_module.h"
#include "protbind.h"

/*
 * brix_protbind_append — add one protocol to a set, ignoring duplicates.
 *
 * WHAT: Appends `proto` unless it is already present or the set is full.
 *
 * WHY:  The default (non-`only`) rule form concatenates the rule's list with
 *       the base set, and the two routinely overlap ("gsi" listed first, base
 *       {ztn,gsi}); silently de-duplicating keeps the advertised sec token from
 *       offering the same scheme twice, which stock clients treat as a
 *       malformed protocol list.
 *
 * HOW:  Linear membership scan (the set holds at most 8 ids), then append.
 */
static void
brix_protbind_append(brix_protbind_set_t *set, ngx_uint_t proto)
{
    ngx_uint_t  index;

    for (index = 0; index < set->count; index++) {
        if (set->protos[index] == proto) {
            return;
        }
    }

    if (set->count < BRIX_PROTBIND_MAX_PROTOS) {
        set->protos[set->count++] = proto;
    }
}

/* ---- Base protocol set implied by a stream listener's brix_auth mode ----
 *
 * WHAT: Fills *out with the protocols `brix_auth <mode>` allows on its own:
 *       none → empty and require_auth 0, both → {ztn, gsi}, anything else →
 *       that single scheme.
 *
 * WHY:  protbind refines an existing listener policy rather than replacing it,
 *       so the pre-protbind behaviour has to be expressible as a set.  Encoding
 *       it here — including `both`'s token-then-GSI order, which is the order
 *       the sec token has always advertised — is what guarantees that a config
 *       with no brix_protbind line behaves exactly as it did before.
 *
 * HOW:  1. Zero the set.  2. Return early for the anonymous mode.  3. Expand
 *       `both` into its two members; otherwise append the mode itself.
 */
void
brix_protbind_base_set(ngx_uint_t base_auth, brix_protbind_set_t *out)
{
    ngx_memzero(out, sizeof(*out));

    if (base_auth == BRIX_AUTH_NONE) {
        return;
    }

    out->require_auth = 1;

    if (base_auth == BRIX_AUTH_BOTH) {
        brix_protbind_append(out, BRIX_AUTH_TOKEN);
        brix_protbind_append(out, BRIX_AUTH_GSI);
        return;
    }

    brix_protbind_append(out, base_auth);
}

/* ---- Base protocol set for an HTTP frontend ----
 *
 * WHAT: Fills *out with {gsi, ztn, pwd} — the three credential sources a
 *       WebDAV/HTTP location can actually run — and stamps `require_auth` from
 *       the location's own auth=none/optional/required decision.
 *
 * WHY:  HTTP has no login negotiation: a request arrives carrying whatever
 *       credentials it has, and the server tries the sources in descending
 *       strength.  That historical order (client cert, then bearer token, then
 *       Basic) IS the base ordering, so a location with no protbind rule keeps
 *       byte-identical behaviour.  The remaining schemes (sss/unix/krb5/host)
 *       have no HTTP transport and are therefore absent by construction.
 *
 * HOW:  Zero, append the three ids in order, record require_auth.
 */
void
brix_protbind_http_base(ngx_flag_t require_auth, brix_protbind_set_t *out)
{
    ngx_memzero(out, sizeof(*out));

    brix_protbind_append(out, BRIX_AUTH_GSI);
    brix_protbind_append(out, BRIX_AUTH_TOKEN);
    brix_protbind_append(out, BRIX_AUTH_PWD);

    out->require_auth = require_auth;
}

/*
 * brix_protbind_rule_matches — does either peer identity satisfy a template?
 *
 * WHAT: Returns 1 when the template matches the peer's hostname or, failing
 *       that, its textual IP address.
 *
 * WHY:  Sites write templates against names ("*.cern.ch") but reverse DNS can
 *       be absent or broken, and admins also legitimately write literal
 *       addresses or address prefixes ("192.168.1.*").  Trying both identities
 *       covers each intent without a separate directive; a bare "*" matches via
 *       the hostname arm even when both identities are unknown.
 *
 * HOW:  Match the hostname first (the intended identity), then the IP.
 */
static ngx_flag_t
brix_protbind_rule_matches(const brix_protbind_rule_t *rule,
    const char *peer_host, const char *peer_ip)
{
    if (brix_protbind_host_match(&rule->host_tpl, peer_host)) {
        return 1;
    }

    return brix_protbind_host_match(&rule->host_tpl, peer_ip);
}

/*
 * brix_protbind_apply — turn the winning rule into the resolved set.
 *
 * WHAT: Fills *out from `rule`, folding in `base` for the default rule form.
 *
 * WHY:  The three rule modes differ only in what surrounds the rule's own
 *       list, so expressing them as one function keeps the precedence in a
 *       single readable place instead of spread across the search loop.
 *
 * HOW:  1. `none` → the empty, auth-less set.  2. Copy the rule's protocols in
 *       written order (that order is the advertisement order).  3. For the
 *       default (non-`only`) form append the base protocols not already named.
 *       4. require_auth follows from the set being non-empty.
 */
static void
brix_protbind_apply(const brix_protbind_rule_t *rule,
    const brix_protbind_set_t *base, brix_protbind_set_t *out)
{
    ngx_uint_t  index;

    ngx_memzero(out, sizeof(*out));

    if (rule->mode == BRIX_PROTBIND_NONE) {
        return;
    }

    for (index = 0; index < rule->count; index++) {
        brix_protbind_append(out, rule->protos[index]);
    }

    if (rule->mode != BRIX_PROTBIND_ONLY) {
        for (index = 0; index < base->count; index++) {
            brix_protbind_append(out, base->protos[index]);
        }
    }

    out->require_auth = (out->count > 0);
}

/* ---- Resolve the effective protocol set for one peer ----
 *
 * WHAT: Fills *out with the ordered protocols this peer may authenticate with;
 *       with no rules, or no rule matching, *out is a copy of *base.
 *
 * WHY:  This is the single entry point every frontend calls, so "first
 *       matching rule wins" is enforced in exactly one place.  First-match (not
 *       most-specific-match) is stock XRootD's rule and the reason admins put
 *       their `*` catch-all last.
 *
 * HOW:  1. Copy the base as the default outcome.  2. Walk the rules in
 *       configuration order.  3. On the first template that matches either
 *       peer identity, apply it and return.
 */
void
brix_protbind_resolve(ngx_array_t *rules, const brix_protbind_set_t *base,
    const char *peer_host, const char *peer_ip, brix_protbind_set_t *out)
{
    brix_protbind_rule_t  *rule;
    ngx_uint_t             index;

    *out = *base;

    if (rules == NULL || rules->nelts == 0) {
        return;
    }

    rule = rules->elts;
    for (index = 0; index < rules->nelts; index++) {
        if (brix_protbind_rule_matches(&rule[index], peer_host, peer_ip)) {
            brix_protbind_apply(&rule[index], base, out);
            return;
        }
    }
}

/* ---- Membership test for an offered credential ----
 *
 * WHAT: Returns 1 when `proto` is in the resolved set.
 *
 * WHY:  Advertising a protocol list is not enforcement: a client can send any
 *       credential type it likes regardless of what the sec token offered, so
 *       the kXR_auth dispatcher must re-check membership before running a
 *       scheme's handler.  One shared predicate keeps the advertised set and
 *       the enforced set from drifting apart.
 *
 * HOW:  Linear scan over at most BRIX_PROTBIND_MAX_PROTOS ids.
 */
ngx_flag_t
brix_protbind_allows(const brix_protbind_set_t *set, ngx_uint_t proto)
{
    ngx_uint_t  index;

    for (index = 0; index < set->count; index++) {
        if (set->protos[index] == proto) {
            return 1;
        }
    }

    return 0;
}
