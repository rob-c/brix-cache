/*
 * protbind_test.c — unit for the per-host auth-protocol binding engine
 * (src/auth/protbind/match.c + policy.c, XRootD `sec.protbind`).
 *
 * WHAT: Drives the pure engine directly: host-template matching, the base sets
 *       both frontends start from, rule resolution (none / only / default),
 *       first-match-wins ordering, and the membership gate that admits a
 *       credential at kXR_auth or picks an HTTP credential source.
 *
 * WHY:  This engine decides who may authenticate and how; every branch of it
 *       is a security decision, and none of them are observable from a config
 *       check.  The real match.o + policy.o are linked (no reimplementation),
 *       so the unit fails if the shipped logic drifts.  Config-grammar
 *       rejection is covered separately by tests/test_protbind_parse.py, which
 *       needs a real ngx_conf_t.
 *
 * HOW:  Rules are built as plain C arrays wrapped in a stack ngx_array_t (the
 *       engine only reads elts/nelts), so no pool or nginx runtime is needed.
 *       Each check prints and counts its own failure; main returns non-zero if
 *       any failed.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "core/types/tunables.h"
#include "auth/protbind/protbind.h"

/* The linked-in ngx_string.o pulls these in for helpers this unit never calls
 * (ngx_pstrdup / ngx_sort); the engine itself allocates nothing. */
volatile ngx_cycle_t  *ngx_cycle;
void *ngx_alloc(size_t size, ngx_log_t *log) { (void) log; return malloc(size); }
void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{ (void) pool; return malloc(size); }

static int failures;

#define CHECK(cond, what)                                                     \
    do {                                                                      \
        if (!(cond)) {                                                        \
            failures++;                                                       \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, (what));   \
        }                                                                     \
    } while (0)

/* Wrap a plain C array of rules in the ngx_array_t view the engine reads. */
static ngx_array_t
rule_array(brix_protbind_rule_t *rules, ngx_uint_t n)
{
    ngx_array_t  a;

    a.elts = rules;
    a.nelts = n;
    a.size = sizeof(brix_protbind_rule_t);
    a.nalloc = n;
    a.pool = NULL;
    return a;
}

static void
set_tpl(brix_protbind_rule_t *rule, const char *tpl)
{
    rule->host_tpl.data = (u_char *) tpl;
    rule->host_tpl.len = ngx_strlen(tpl);
}

/* Exact ordered comparison of a resolved set against an expected list. */
static int
set_equals(const brix_protbind_set_t *set, const ngx_uint_t *want,
    ngx_uint_t n)
{
    ngx_uint_t  i;

    if (set->count != n) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (set->protos[i] != want[i]) {
            return 0;
        }
    }
    return 1;
}

/* ---- host-template matching (XrdOucNList semantics) ---- */
static void
test_host_match(void)
{
    ngx_str_t  star = ngx_string("*");
    ngx_str_t  exact = ngx_string("lxplus701.cern.ch");
    ngx_str_t  suffix = ngx_string("*.cern.ch");
    ngx_str_t  prefix = ngx_string("lxplus*");
    ngx_str_t  both = ngx_string("pps*.gridpp.uk");

    /* success: a bare "*" matches anything, including a peer with no PTR
     * record — that is what keeps the common ruleset free of reverse DNS. */
    CHECK(brix_protbind_host_match(&star, "anything.example"), "* matches");
    CHECK(brix_protbind_host_match(&star, NULL), "* matches NULL host");
    CHECK(brix_protbind_host_match(&star, ""), "* matches empty host");

    /* success: exact templates are case-insensitive, like XrdOucNList. */
    CHECK(brix_protbind_host_match(&exact, "lxplus701.cern.ch"), "exact");
    CHECK(brix_protbind_host_match(&exact, "LXPLUS701.CERN.CH"), "exact ci");

    /* error: a near-miss must not match — no prefix/suffix leniency. */
    CHECK(!brix_protbind_host_match(&exact, "lxplus701.cern.ch.evil.net"),
          "exact rejects suffix extension");
    CHECK(!brix_protbind_host_match(&exact, "lxplus70.cern.ch"),
          "exact rejects short");
    CHECK(!brix_protbind_host_match(&exact, NULL), "exact rejects NULL");

    /* success + security-negative: the wildcard splits into prefix/suffix and
     * BOTH ends must match, so a lookalike domain cannot borrow the suffix. */
    CHECK(brix_protbind_host_match(&suffix, "lxplus.cern.ch"), "*.cern.ch");
    CHECK(brix_protbind_host_match(&suffix, "a.b.CERN.ch"), "*.cern.ch ci");
    CHECK(!brix_protbind_host_match(&suffix, "cern.ch"), "suffix needs a dot");
    CHECK(!brix_protbind_host_match(&suffix, "evil.cern.ch.attacker.net"),
          "*.cern.ch rejects embedded match");

    CHECK(brix_protbind_host_match(&prefix, "lxplus701"), "lxplus*");
    CHECK(!brix_protbind_host_match(&prefix, "xlxplus701"),
          "lxplus* rejects embedded match");

    CHECK(brix_protbind_host_match(&both, "pps01.gridpp.uk"), "pps*.gridpp.uk");
    CHECK(!brix_protbind_host_match(&both, "pps.gridpp.uk.evil"),
          "pps*.gridpp.uk rejects suffix extension");
    /* The prefix and suffix must not be allowed to overlap in a short name. */
    CHECK(!brix_protbind_host_match(&both, "pps.gridpp.u"),
          "overlapping prefix/suffix rejected");
}

/* ---- ruleset predicates the callers use to avoid work ---- */
static void
test_rule_predicates(void)
{
    brix_protbind_rule_t  wildcard_only[2];
    brix_protbind_rule_t  named[1];
    ngx_array_t           a;

    ngx_memzero(wildcard_only, sizeof(wildcard_only));
    set_tpl(&wildcard_only[0], "*");
    wildcard_only[0].mode = BRIX_PROTBIND_ONLY;
    wildcard_only[0].count = 1;
    wildcard_only[0].protos[0] = BRIX_AUTH_TOKEN;
    set_tpl(&wildcard_only[1], "*");
    wildcard_only[1].mode = BRIX_PROTBIND_NONE;

    /* success: a wildcard-only ruleset never needs reverse DNS. */
    a = rule_array(wildcard_only, 2);
    CHECK(!brix_protbind_needs_hostname(&a), "wildcard-only needs no DNS");
    CHECK(!brix_protbind_needs_hostname(NULL), "NULL rules need no DNS");

    /* success: any non-"*" template forces the (cached) lookup. */
    ngx_memzero(named, sizeof(named));
    set_tpl(&named[0], "*.cern.ch");
    a = rule_array(named, 1);
    CHECK(brix_protbind_needs_hostname(&a), "template needs DNS");

    /* success: any_names drives the startup loaders for a scheme brix_auth
     * did not select; a NONE rule lists nothing, so it never claims one. */
    a = rule_array(wildcard_only, 2);
    CHECK(brix_protbind_any_names(&a, BRIX_AUTH_TOKEN), "any_names finds ztn");
    CHECK(!brix_protbind_any_names(&a, BRIX_AUTH_GSI), "any_names misses gsi");
    CHECK(!brix_protbind_any_names(NULL, BRIX_AUTH_GSI), "any_names NULL");
}

/* ---- the base sets each frontend starts from ---- */
static void
test_base_sets(void)
{
    brix_protbind_set_t  set;
    ngx_uint_t           both_order[2] = { BRIX_AUTH_TOKEN, BRIX_AUTH_GSI };
    ngx_uint_t           http_order[3] = { BRIX_AUTH_GSI, BRIX_AUTH_TOKEN,
                                           BRIX_AUTH_PWD };

    /* REGRESSION PIN: `brix_auth both` must stay ztn-then-gsi — that order is
     * the byte order of the sec token every stock client has ever seen. */
    brix_protbind_base_set(BRIX_AUTH_BOTH, &set);
    CHECK(set_equals(&set, both_order, 2), "both = {ztn, gsi}");
    CHECK(set.require_auth, "both requires auth");

    brix_protbind_base_set(BRIX_AUTH_GSI, &set);
    CHECK(set.count == 1 && set.protos[0] == BRIX_AUTH_GSI, "gsi base");

    brix_protbind_base_set(BRIX_AUTH_KRB5, &set);
    CHECK(set.count == 1 && set.protos[0] == BRIX_AUTH_KRB5, "krb5 base");

    /* error/anonymous: auth none authenticates nobody. */
    brix_protbind_base_set(BRIX_AUTH_NONE, &set);
    CHECK(set.count == 0 && !set.require_auth, "none base is anonymous");

    /* REGRESSION PIN: the HTTP gate's historical cert→token→basic order. */
    brix_protbind_http_base(1, &set);
    CHECK(set_equals(&set, http_order, 3), "http base = {gsi, ztn, pwd}");
    CHECK(set.require_auth, "http base requires auth");
    brix_protbind_http_base(0, &set);
    CHECK(!set.require_auth, "http auth=none does not require auth");
}

/* ---- resolution: no rules, none, only, default, first-match-wins ---- */
static void
test_resolve(void)
{
    brix_protbind_rule_t  rules[3];
    brix_protbind_set_t   base, set;
    ngx_array_t           a;
    ngx_uint_t            only_order[2] = { BRIX_AUTH_UNIX, BRIX_AUTH_SSS };
    ngx_uint_t            all_order[3] = { BRIX_AUTH_GSI, BRIX_AUTH_TOKEN,
                                           BRIX_AUTH_GSI };

    brix_protbind_base_set(BRIX_AUTH_BOTH, &base);

    /* REGRESSION PIN: no rules at all → the base set, unchanged.  This is the
     * proof that every existing config keeps its exact sec token. */
    brix_protbind_resolve(NULL, &base, "lxplus.cern.ch", "1.2.3.4", &set);
    CHECK(set.count == base.count && set.protos[0] == base.protos[0]
          && set.protos[1] == base.protos[1] && set.require_auth,
          "no rules = base set");

    ngx_memzero(rules, sizeof(rules));
    set_tpl(&rules[0], "mon.example.org");
    rules[0].mode = BRIX_PROTBIND_NONE;
    set_tpl(&rules[1], "*.farm.local");
    rules[1].mode = BRIX_PROTBIND_ONLY;
    rules[1].count = 2;
    rules[1].protos[0] = BRIX_AUTH_UNIX;
    rules[1].protos[1] = BRIX_AUTH_SSS;
    set_tpl(&rules[2], "*");
    rules[2].mode = BRIX_PROTBIND_ALL;
    rules[2].count = 1;
    rules[2].protos[0] = BRIX_AUTH_GSI;
    a = rule_array(rules, 3);

    /* `none`: the monitoring host authenticates with nothing. */
    brix_protbind_resolve(&a, &base, "mon.example.org", "10.0.0.9", &set);
    CHECK(set.count == 0 && !set.require_auth, "none rule = anonymous");

    /* `only`: exactly the listed protocols, in the written order — the base
     * set contributes nothing, so gsi/ztn are NOT admitted here. */
    brix_protbind_resolve(&a, &base, "node7.farm.local", "10.0.0.7", &set);
    CHECK(set_equals(&set, only_order, 2), "only rule = listed protocols");
    CHECK(set.require_auth, "only rule requires auth");
    CHECK(!brix_protbind_allows(&set, BRIX_AUTH_GSI),
          "only rule excludes base gsi");
    CHECK(!brix_protbind_allows(&set, BRIX_AUTH_TOKEN),
          "only rule excludes base ztn");

    /* default form: listed first, then the base protocols not already named —
     * gsi is promoted ahead of ztn and must NOT appear twice. */
    brix_protbind_resolve(&a, &base, "desktop.example.net", "192.0.2.5", &set);
    CHECK(set.count == 2, "default form dedupes the base");
    CHECK(set.protos[0] == BRIX_AUTH_GSI && set.protos[1] == BRIX_AUTH_TOKEN,
          "default form promotes the listed protocol");
    CHECK(!set_equals(&set, all_order, 3), "no duplicate gsi entry");

    /* first-match-wins: the "*" catch-all must not steal a named host. */
    brix_protbind_resolve(&a, &base, "MON.EXAMPLE.ORG", "10.0.0.9", &set);
    CHECK(set.count == 0, "first match wins (case-insensitively)");

    /* The IP literal is matched when the hostname does not match (or is
     * absent, e.g. a peer with no PTR record). */
    set_tpl(&rules[0], "10.0.0.*");
    brix_protbind_resolve(&a, &base, NULL, "10.0.0.9", &set);
    CHECK(set.count == 0 && !set.require_auth, "IP template matches");
    brix_protbind_resolve(&a, &base, NULL, "10.0.1.9", &set);
    CHECK(set.count == 2, "non-matching IP falls through to catch-all");
}

/* ---- the membership gate (kXR_auth admission / HTTP source selection) ---- */
static void
test_allows(void)
{
    brix_protbind_set_t  set;

    brix_protbind_base_set(BRIX_AUTH_BOTH, &set);
    CHECK(brix_protbind_allows(&set, BRIX_AUTH_TOKEN), "both admits ztn");
    CHECK(brix_protbind_allows(&set, BRIX_AUTH_GSI), "both admits gsi");

    /* security-negative: a scheme outside the set is refused even though the
     * server has a handler for it — the client may offer any credtype. */
    CHECK(!brix_protbind_allows(&set, BRIX_AUTH_SSS), "both refuses sss");
    CHECK(!brix_protbind_allows(&set, BRIX_AUTH_UNIX), "both refuses unix");

    /* security-negative: an anonymous set admits NOTHING, so a `none` binding
     * can never be turned into an authenticated identity by the client. */
    brix_protbind_base_set(BRIX_AUTH_NONE, &set);
    CHECK(!brix_protbind_allows(&set, BRIX_AUTH_GSI), "none refuses gsi");
    CHECK(!brix_protbind_allows(&set, BRIX_AUTH_TOKEN), "none refuses ztn");
}

/* ---- protocol-name mapping (config words ↔ sec-token names) ---- */
static void
test_names(void)
{
    ngx_str_t   gsi = ngx_string("gsi");
    ngx_str_t   ztn = ngx_string("ztn");
    ngx_str_t   token = ngx_string("token");
    ngx_str_t   upper = ngx_string("GSI");
    ngx_str_t   bogus = ngx_string("bogus");
    ngx_str_t   empty = ngx_string("");
    ngx_uint_t  id;

    CHECK(brix_protbind_proto_id(&gsi, &id) == NGX_OK && id == BRIX_AUTH_GSI,
          "gsi id");
    CHECK(brix_protbind_proto_id(&ztn, &id) == NGX_OK && id == BRIX_AUTH_TOKEN,
          "ztn id");
    /* `token` is BriX's own spelling of the ztn protocol; both must parse. */
    CHECK(brix_protbind_proto_id(&token, &id) == NGX_OK
          && id == BRIX_AUTH_TOKEN, "token alias");

    /* error: unknown or malformed protocol words are rejected, and the
     * comparison is case-sensitive like every other BriX config keyword. */
    CHECK(brix_protbind_proto_id(&bogus, &id) != NGX_OK, "bogus rejected");
    CHECK(brix_protbind_proto_id(&empty, &id) != NGX_OK, "empty rejected");
    CHECK(brix_protbind_proto_id(&upper, &id) != NGX_OK, "GSI rejected");
}

int
main(void)
{
    test_host_match();
    test_rule_predicates();
    test_base_sets();
    test_resolve();
    test_allows();
    test_names();

    if (failures == 0) {
        printf("protbind: all checks passed\n");
    }
    return failures == 0 ? 0 : 1;
}
