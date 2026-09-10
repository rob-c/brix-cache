/*
 * identity_matrix_unittest.c — standalone unit suite for the TPC identity
 * matrix's pure half (2.0 F18: `brix_tpc_allow_identity` / `brix_tpc_require` /
 * `brix_tpc_restrict` / `brix_tpc_oids`, BriX's spelling of stock XRootD's
 * `ofs.tpc allow|require|restrict|oids`).
 *
 *   cc -std=c11 -Wall -Wextra -Werror -DXRDPROTO_NO_NGX \
 *      identity_matrix_unittest.c -o /tmp/ut && /tmp/ut
 *   (run from src/tpc/common/)
 *
 * Exit 0 = all checks pass.  Pure C: the ngx half (conf-array adaptation,
 * identity projection, the three directive setters) is excluded by
 * XRDPROTO_NO_NGX and is covered online by
 * tests/test_release20_tpc_identity_matrix.py against a live gateway and
 * `nginx -t`.  egress_guard.c is included too because the matrix deliberately
 * reuses brix_tpc_host_pattern_match so there is ONE host spelling in the
 * server.
 */
#include <stdio.h>
#include <string.h>

#include "egress_guard.c"
#include "identity_matrix.c"

static int g_fail;
#define CHECK(cond) do {                                                   \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
                   g_fail++; }                                             \
} while (0)


/* ---- stage 0: CSV membership ---- */

/* SUCCESS: an element matches exactly, wherever it sits and however padded. */
static void
test_csv_member(void)
{
    CHECK(brix_tpc_csv_member("cms", "cms"));
    CHECK(brix_tpc_csv_member("atlas,cms,lhcb", "cms"));
    CHECK(brix_tpc_csv_member("atlas, cms , lhcb", "cms"));
    CHECK(brix_tpc_csv_member("\tcms\t,atlas", "cms"));
}

/* SECURITY NEGATIVE: membership is element-bounded and case-sensitive, so a
 * rule naming "cms" can never be satisfied by "cmsuser", "xcms" or "CMS". */
static void
test_csv_member_negatives(void)
{
    CHECK(!brix_tpc_csv_member("cmsuser", "cms"));
    CHECK(!brix_tpc_csv_member("xcms", "cms"));
    CHECK(!brix_tpc_csv_member("CMS", "cms"));
    CHECK(!brix_tpc_csv_member("atlas,lhcb", "cms"));
    CHECK(!brix_tpc_csv_member(NULL, "cms"));
    CHECK(!brix_tpc_csv_member("cms", NULL));
    CHECK(!brix_tpc_csv_member("cms", ""));
    CHECK(!brix_tpc_csv_member(",,", ""));
}


/* ---- stage 0: auth-method names ---- */

/* SUCCESS: the label match is case-insensitive, so `require all GSI` and the
 * identity's "gsi" agree. */
static void
test_auth_name_eq(void)
{
    CHECK(brix_tpc_auth_name_eq("gsi", "gsi"));
    CHECK(brix_tpc_auth_name_eq("GSI", "gsi"));
    CHECK(brix_tpc_auth_name_eq("gsi", "GSI"));
    CHECK(brix_tpc_auth_name_eq("token", "TOKEN"));
}

/* SECURITY NEGATIVE: an empty or absent method never satisfies a require. */
static void
test_auth_name_eq_negatives(void)
{
    CHECK(!brix_tpc_auth_name_eq("gsi", "token"));
    CHECK(!brix_tpc_auth_name_eq("", ""));
    CHECK(!brix_tpc_auth_name_eq("gsi", ""));
    CHECK(!brix_tpc_auth_name_eq("", "gsi"));
    CHECK(!brix_tpc_auth_name_eq(NULL, "gsi"));
    CHECK(!brix_tpc_auth_name_eq("gsi", NULL));
}


/* ---- stage 2: allow rules ---- */

/* SUCCESS: each selector admits its own subject. */
static void
test_allow_each_selector(void)
{
    brix_tpc_subject_t s;
    brix_tpc_allow_rule_t r;

    memset(&s, 0, sizeof(s));
    s.dn     = "/DC=org/CN=alice";
    s.groups = "cms,atlas";
    s.vos    = "cms";
    s.host   = "se.example.org";
    s.auth   = "gsi";

    memset(&r, 0, sizeof(r));
    r.dn = "/DC=org/CN=alice";
    CHECK(brix_tpc_allow_rule_match(&r, &s));

    memset(&r, 0, sizeof(r));
    r.group = "atlas";
    CHECK(brix_tpc_allow_rule_match(&r, &s));

    memset(&r, 0, sizeof(r));
    r.vo = "cms";
    CHECK(brix_tpc_allow_rule_match(&r, &s));

    memset(&r, 0, sizeof(r));
    r.host = ".example.org";
    CHECK(brix_tpc_allow_rule_match(&r, &s));
}

/* A multi-selector rule is an AND: every named field must match. */
static void
test_allow_rule_is_an_and(void)
{
    brix_tpc_subject_t s;
    brix_tpc_allow_rule_t r;

    memset(&s, 0, sizeof(s));
    s.dn   = "/DC=org/CN=alice";
    s.vos  = "cms";
    s.host = "se.example.org";

    memset(&r, 0, sizeof(r));
    r.dn = "/DC=org/CN=alice";
    r.vo = "cms";
    CHECK(brix_tpc_allow_rule_match(&r, &s));

    r.vo = "atlas";           /* one field wrong ⇒ the whole rule fails */
    CHECK(!brix_tpc_allow_rule_match(&r, &s));

    r.vo   = "cms";
    r.host = ".elsewhere.org";
    CHECK(!brix_tpc_allow_rule_match(&r, &s));
}

/* SECURITY NEGATIVE: an all-empty rule matches nothing.  A rule whose every
 * selector was dropped must never degrade into "allow everyone". */
static void
test_allow_empty_rule_matches_nothing(void)
{
    brix_tpc_subject_t s;
    brix_tpc_allow_rule_t r;

    memset(&s, 0, sizeof(s));
    s.dn = "/DC=org/CN=alice";
    memset(&r, 0, sizeof(r));
    CHECK(!brix_tpc_allow_rule_match(&r, &s));
    CHECK(!brix_tpc_allow_rule_match(NULL, &s));
}


/* ---- stage 4: restrict prefixes ---- */

/* SUCCESS: a prefix admits itself and anything strictly beneath it. */
static void
test_restrict_match(void)
{
    CHECK(brix_tpc_restrict_match("/data", "/data"));
    CHECK(brix_tpc_restrict_match("/data", "/data/file"));
    CHECK(brix_tpc_restrict_match("/data/", "/data/sub/file"));
    CHECK(brix_tpc_restrict_match("/", "/anything"));
}

/* SECURITY NEGATIVE: the match is component-aware, so `/data` never admits
 * `/database` — a plain string prefix (stock's rule) would. */
static void
test_restrict_component_boundary(void)
{
    CHECK(!brix_tpc_restrict_match("/data", "/database"));
    CHECK(!brix_tpc_restrict_match("/data", "/datax/file"));
    CHECK(!brix_tpc_restrict_match("/data", "/other"));
    CHECK(!brix_tpc_restrict_match("/data", ""));
    CHECK(!brix_tpc_restrict_match("/data", NULL));
    /* a lost argument fails closed rather than degrading into "/" */
    CHECK(!brix_tpc_restrict_match(NULL, "/data"));
    CHECK(!brix_tpc_restrict_match("", "/data"));
}


/* ---- stage 1: object ids ---- */

/* An oid path is stock's '*'-prefixed form; nothing else is. */
static void
test_path_is_oid(void)
{
    CHECK(brix_tpc_path_is_oid("*abc"));
    CHECK(brix_tpc_path_is_oid("*"));
    CHECK(!brix_tpc_path_is_oid("/data/file"));
    CHECK(!brix_tpc_path_is_oid("/data/*"));
    CHECK(!brix_tpc_path_is_oid(""));
    CHECK(!brix_tpc_path_is_oid(NULL));
}


/* ---- the whole evaluation ---- */

static void
subject_alice(brix_tpc_subject_t *s)
{
    memset(s, 0, sizeof(*s));
    s->dn     = "/DC=org/CN=alice";
    s->groups = "cms";
    s->vos    = "cms";
    s->host   = "se.example.org";
    s->auth   = "gsi";
}

/* SUCCESS: an unconfigured matrix is a no-op — every subject, every path, both
 * parties.  This is what lets 2.0 ship the feature without changing behaviour
 * for anyone who does not adopt it. */
static void
test_unconfigured_is_a_noop(void)
{
    brix_tpc_matrix_t m;
    brix_tpc_subject_t s;

    subject_alice(&s);
    memset(&m, 0, sizeof(m));
    m.oids = 1;   /* the one stage that is default-DENY; disable it explicitly */
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/data/f")
          == BRIX_TPC_MATRIX_OK);
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_DEST, &s, "/data/f")
          == BRIX_TPC_MATRIX_OK);
    CHECK(brix_tpc_matrix_evaluate(NULL, BRIX_TPC_PARTY_CLIENT, &s, "/data/f")
          == BRIX_TPC_MATRIX_OK);
}

/* oids default to OFF, and that refusal precedes every other stage — a '*'
 * path is refused even by an otherwise-empty matrix. */
static void
test_oids_default_deny(void)
{
    brix_tpc_matrix_t m;
    brix_tpc_subject_t s;

    subject_alice(&s);
    memset(&m, 0, sizeof(m));
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "*abc")
          == BRIX_TPC_MATRIX_DENY_OID);
    m.oids = 1;
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "*abc")
          == BRIX_TPC_MATRIX_OK);
}

/* SUCCESS + SECURITY NEGATIVE: once ANY allow rule exists, the stage is
 * fail-closed — a subject no rule names is DENIED, never defaulted. */
static void
test_allow_stage_fails_closed(void)
{
    brix_tpc_allow_rule_t rules[2];
    brix_tpc_matrix_t m;
    brix_tpc_subject_t s;

    memset(rules, 0, sizeof(rules));
    rules[0].vo   = "cms";
    rules[1].host = ".trusted.org";

    memset(&m, 0, sizeof(m));
    m.allow  = rules;
    m.nallow = 2;
    m.oids   = 1;

    subject_alice(&s);                       /* vo=cms ⇒ rule 0 admits */
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/data/f")
          == BRIX_TPC_MATRIX_OK);

    s.vos  = "atlas";                        /* neither rule names them */
    s.host = "se.example.org";
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/data/f")
          == BRIX_TPC_MATRIX_DENY_IDENTITY);

    s.host = "se.trusted.org";               /* rule 1 admits (OR across lines) */
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/data/f")
          == BRIX_TPC_MATRIX_OK);
}

/* SECURITY NEGATIVE: an empty subject cannot walk through a configured allow
 * stage.  An unauthenticated or partially-filled identity is a denial. */
static void
test_empty_subject_is_denied(void)
{
    brix_tpc_allow_rule_t rule;
    brix_tpc_matrix_t m;

    memset(&rule, 0, sizeof(rule));
    rule.vo = "cms";
    memset(&m, 0, sizeof(m));
    m.allow  = &rule;
    m.nallow = 1;
    m.oids   = 1;

    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, NULL, "/data/f")
          == BRIX_TPC_MATRIX_DENY_IDENTITY);
}

/* SECURITY NEGATIVE (the load-bearing party fact): `require dest gsi` is a
 * constraint on the DESTINATION party's credential.  A client leg is not
 * constrained by it, and a dest leg presenting a token does not satisfy it. */
static void
test_require_is_party_scoped(void)
{
    brix_tpc_require_rule_t rules[1];
    brix_tpc_matrix_t m;
    brix_tpc_subject_t s;

    memset(rules, 0, sizeof(rules));
    rules[0].party = BRIX_TPC_PARTY_DEST;
    rules[0].auth  = "gsi";

    memset(&m, 0, sizeof(m));
    m.require_rules = rules;
    m.nrequire      = 1;
    m.oids          = 1;

    subject_alice(&s);
    s.auth = "token";
    /* the CLIENT party is named by no rule ⇒ unconstrained */
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/data/f")
          == BRIX_TPC_MATRIX_OK);
    /* the DEST party is named ⇒ its token credential cannot satisfy `gsi` */
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_DEST, &s, "/data/f")
          == BRIX_TPC_MATRIX_DENY_AUTH);
    s.auth = "gsi";
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_DEST, &s, "/data/f")
          == BRIX_TPC_MATRIX_OK);
}

/* `require all <auth>` binds both parties; several rules for one party are an
 * OR (any listed method satisfies it), matching stock's repeatable form. */
static void
test_require_all_and_or_semantics(void)
{
    brix_tpc_require_rule_t rules[2];
    brix_tpc_matrix_t m;
    brix_tpc_subject_t s;

    memset(rules, 0, sizeof(rules));
    rules[0].party = BRIX_TPC_PARTY_ALL;
    rules[0].auth  = "gsi";
    rules[1].party = BRIX_TPC_PARTY_ALL;
    rules[1].auth  = "token";

    memset(&m, 0, sizeof(m));
    m.require_rules = rules;
    m.nrequire      = 2;
    m.oids          = 1;

    subject_alice(&s);
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/d")
          == BRIX_TPC_MATRIX_OK);
    s.auth = "token";
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_DEST, &s, "/d")
          == BRIX_TPC_MATRIX_OK);
    s.auth = "sss";
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/d")
          == BRIX_TPC_MATRIX_DENY_AUTH);
    s.auth = NULL;               /* unauthenticated cannot satisfy a require */
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/d")
          == BRIX_TPC_MATRIX_DENY_AUTH);
}

/* SECURITY NEGATIVE: restrict is fail-closed once configured, and an allow
 * rule cannot buy a path back — the stages are an AND, evaluated in order. */
static void
test_restrict_stage_fails_closed(void)
{
    const char *paths[2];
    brix_tpc_allow_rule_t rule;
    brix_tpc_matrix_t m;
    brix_tpc_subject_t s;

    paths[0] = "/data";
    paths[1] = "/scratch";

    memset(&rule, 0, sizeof(rule));
    rule.vo = "cms";

    memset(&m, 0, sizeof(m));
    m.allow  = &rule;
    m.nallow = 1;
    m.paths  = paths;
    m.npaths = 2;
    m.oids   = 1;

    subject_alice(&s);
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/data/f")
          == BRIX_TPC_MATRIX_OK);
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/scratch")
          == BRIX_TPC_MATRIX_OK);
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/etc/passwd")
          == BRIX_TPC_MATRIX_DENY_PATH);
    /* and `/data` still does not admit `/database` through the whole matrix */
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/database/f")
          == BRIX_TPC_MATRIX_DENY_PATH);
}

/* The order is a security order: identity is decided before auth, and auth
 * before path, so the verdict names the FIRST stage that refused. */
static void
test_stage_order(void)
{
    brix_tpc_allow_rule_t rule;
    brix_tpc_require_rule_t req;
    const char *paths[1];
    brix_tpc_matrix_t m;
    brix_tpc_subject_t s;

    memset(&rule, 0, sizeof(rule));
    rule.vo = "cms";
    memset(&req, 0, sizeof(req));
    req.party = BRIX_TPC_PARTY_ALL;
    req.auth  = "gsi";
    paths[0] = "/data";

    memset(&m, 0, sizeof(m));
    m.allow         = &rule;
    m.nallow        = 1;
    m.require_rules = &req;
    m.nrequire      = 1;
    m.paths         = paths;
    m.npaths        = 1;
    m.oids          = 0;

    subject_alice(&s);
    s.vos  = "atlas";     /* fails every stage at once … */
    s.auth = "sss";
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "*oid")
          == BRIX_TPC_MATRIX_DENY_OID);        /* … oids first */
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/etc/x")
          == BRIX_TPC_MATRIX_DENY_IDENTITY);   /* … then identity */
    s.vos = "cms";
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/etc/x")
          == BRIX_TPC_MATRIX_DENY_AUTH);       /* … then auth */
    s.auth = "gsi";
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "/etc/x")
          == BRIX_TPC_MATRIX_DENY_PATH);       /* … then path */
}

/* A role with no path in hand (the source/push-target legs at gate time) skips
 * the path-shaped stages rather than failing them closed on "". */
static void
test_absent_path_skips_path_stages(void)
{
    const char *paths[1];
    brix_tpc_matrix_t m;
    brix_tpc_subject_t s;

    paths[0] = "/data";
    memset(&m, 0, sizeof(m));
    m.paths  = paths;
    m.npaths = 1;
    m.oids   = 0;

    subject_alice(&s);
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, "")
          == BRIX_TPC_MATRIX_OK);
    CHECK(brix_tpc_matrix_evaluate(&m, BRIX_TPC_PARTY_CLIENT, &s, NULL)
          == BRIX_TPC_MATRIX_OK);
}

/* INVARIANT 8: every refusal text is a fixed, low-cardinality string naming
 * the directive.  No DN, VO, group, host or path may appear in it — these
 * strings reach the access log and the wire error. */
static void
test_verdict_text_is_low_cardinality(void)
{
    static const brix_tpc_matrix_verdict_t all[] = {
        BRIX_TPC_MATRIX_OK, BRIX_TPC_MATRIX_DENY_OID,
        BRIX_TPC_MATRIX_DENY_IDENTITY, BRIX_TPC_MATRIX_DENY_AUTH,
        BRIX_TPC_MATRIX_DENY_PATH,
    };
    size_t i;

    for (i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        const char *t = brix_tpc_matrix_verdict_text(all[i]);
        CHECK(t != NULL);
        CHECK(strchr(t, '%') == NULL);     /* no format escape reaches a label */
        CHECK(strstr(t, "alice") == NULL);
        CHECK(strstr(t, "/DC=") == NULL);
    }
    CHECK(strcmp(brix_tpc_matrix_verdict_text(BRIX_TPC_MATRIX_OK), "") == 0);
    CHECK(strstr(brix_tpc_matrix_verdict_text(BRIX_TPC_MATRIX_DENY_IDENTITY),
                 "brix_tpc_allow_identity") != NULL);
    CHECK(strstr(brix_tpc_matrix_verdict_text(BRIX_TPC_MATRIX_DENY_AUTH),
                 "brix_tpc_require") != NULL);
    CHECK(strstr(brix_tpc_matrix_verdict_text(BRIX_TPC_MATRIX_DENY_PATH),
                 "brix_tpc_restrict") != NULL);
    CHECK(strstr(brix_tpc_matrix_verdict_text(BRIX_TPC_MATRIX_DENY_OID),
                 "brix_tpc_oids") != NULL);
}


int
main(void)
{
    test_csv_member();
    test_csv_member_negatives();
    test_auth_name_eq();
    test_auth_name_eq_negatives();
    test_allow_each_selector();
    test_allow_rule_is_an_and();
    test_allow_empty_rule_matches_nothing();
    test_restrict_match();
    test_restrict_component_boundary();
    test_path_is_oid();
    test_unconfigured_is_a_noop();
    test_oids_default_deny();
    test_allow_stage_fails_closed();
    test_empty_subject_is_denied();
    test_require_is_party_scoped();
    test_require_all_and_or_semantics();
    test_restrict_stage_fails_closed();
    test_stage_order();
    test_absent_path_skips_path_stages();
    test_verdict_text_is_low_cardinality();

    if (g_fail == 0) {
        printf("all checks passed\n");
        return 0;
    }
    printf("%d check(s) FAILED\n", g_fail);
    return 1;
}
