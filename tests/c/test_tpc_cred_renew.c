/*
 * test_tpc_cred_renew.c — unit test for the pure decision half of mid-transfer
 * TPC delegated-credential renewal (src/tpc/common/cred_renew.c).
 *
 * WHAT: Exercises brix_tpc_renew_verdict() across every branch and both of its
 *       boundaries, brix_tpc_renew_mode_can_mint() across all six token_mode
 *       spellings this server actually produces plus the near-miss strings an
 *       attacker or a typo would supply, and brix_tpc_renew_verdict_name().
 * WHY:  The kernel is the security boundary of W8.2: a wrong DUE is an outage,
 *       a wrong NOT_NEEDED on an expired credential streams on a token the
 *       source may stop honouring, and a wrong mint authority would re-present
 *       a forwarded credential the destination never owned. It is pure and
 *       nginx-free, so it can be proved here rather than inferred from a live
 *       transfer.
 * HOW:  Table-driven cases plus a monotonicity sweep: for one fixed expiry the
 *       verdict must move NOT_NEEDED -> DUE -> EXPIRED exactly once each as
 *       `now` advances, with no hole and no going back.
 */

#include "tpc/common/cred_renew.h"

#include <stdio.h>
#include <string.h>

static int  failures;

static void
check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        printf("FAIL %s\n", what);
        return;
    }
    printf("ok   %s\n", what);
}

/* One (expires_at, now, lead) triple and the verdict it must produce. */
struct verdict_case {
    time_t                    expires_at;
    time_t                    now;
    time_t                    lead;
    brix_tpc_renew_verdict_t  want;
    const char               *what;
};

static void
test_verdicts(void)
{
    static const struct verdict_case  cases[] = {
        /* the ordinary three outcomes */
        { 1000, 100, 300, BRIX_TPC_RENEW_NOT_NEEDED, "900s left, 300s lead: not needed" },
        { 1000, 800, 300, BRIX_TPC_RENEW_DUE,        "200s left, 300s lead: due" },
        { 1000, 1500, 300, BRIX_TPC_RENEW_EXPIRED,   "500s past expiry: expired" },

        /* both boundaries, named exactly */
        { 1000, 700, 300, BRIX_TPC_RENEW_DUE,        "remaining == lead: due (inclusive)" },
        { 1000, 699, 300, BRIX_TPC_RENEW_NOT_NEEDED, "remaining == lead+1: not needed" },
        { 1000, 999, 300, BRIX_TPC_RENEW_DUE,        "one second left: due" },
        { 1000, 1000, 300, BRIX_TPC_RENEW_EXPIRED,   "now == expires_at: expired" },

        /* renewal off is inert even on an already-expired credential: enabling
         * the feature is the only thing that may ever change a pull's fate */
        { 1000, 5000, 0,  BRIX_TPC_RENEW_NOT_NEEDED, "lead 0 (off) on expired: not needed" },
        { 1000, 5000, -1, BRIX_TPC_RENEW_NOT_NEEDED, "negative lead on expired: not needed" },

        /* nothing to decide on */
        { 0, 5000, 300,  BRIX_TPC_RENEW_NOT_NEEDED, "no expiry known: not needed" },
        { -1, 5000, 300, BRIX_TPC_RENEW_NOT_NEEDED, "negative expiry: not needed" },
        { 1000, 0, 300,  BRIX_TPC_RENEW_NOT_NEEDED, "no usable clock (now 0): not needed" },
        { 1000, -1, 300, BRIX_TPC_RENEW_NOT_NEEDED, "negative clock: not needed" },

        /* the subtraction must not underflow however far apart the clocks are */
        { 2000000000, 1, 300, BRIX_TPC_RENEW_NOT_NEEDED, "distant expiry, tiny now: not needed" },
        { 2000000000, 1, 2000000000, BRIX_TPC_RENEW_DUE, "lead wider than the lifetime: due" },
    };
    size_t  i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        check(brix_tpc_renew_verdict(cases[i].expires_at, cases[i].now,
                                     cases[i].lead) == cases[i].want,
              cases[i].what);
    }
}

/*
 * The verdict must be monotone in `now`: not-needed while there is slack, due
 * inside the lead window, expired after. A hole or a reversal anywhere in that
 * order would mean a pull could stop renewing and then resume, or renew after
 * it had already been refused.
 */
static void
test_monotone_in_now(void)
{
    const time_t  expires_at = 4000;
    const time_t  lead       = 250;
    int           seen_due = 0, seen_expired = 0, bad = 0;
    time_t        now;

    for (now = 1; now <= 5000; now++) {
        brix_tpc_renew_verdict_t  v = brix_tpc_renew_verdict(expires_at, now, lead);

        switch (v) {
        case BRIX_TPC_RENEW_NOT_NEEDED:
            if (seen_due || seen_expired) { bad = 1; }   /* went backwards */
            break;
        case BRIX_TPC_RENEW_DUE:
            if (seen_expired) { bad = 1; }               /* went backwards */
            seen_due = 1;
            break;
        case BRIX_TPC_RENEW_EXPIRED:
            if (!seen_due) { bad = 1; }                  /* skipped the window */
            seen_expired = 1;
            break;
        default:
            bad = 1;
            break;
        }
    }

    check(!bad && seen_due && seen_expired,
          "verdict is monotone over 5000 clock ticks: not-needed -> due -> expired");
    check(brix_tpc_renew_verdict(expires_at, expires_at - lead, lead)
              == BRIX_TPC_RENEW_DUE
          && brix_tpc_renew_verdict(expires_at, expires_at - lead - 1, lead)
              == BRIX_TPC_RENEW_NOT_NEEDED,
          "the window opens at exactly expires_at - lead");
}

/* One token_mode spelling and whether it may mint a fresh credential. */
struct mode_case {
    const char  *mode;
    int          can_mint;
    const char  *what;
};

static void
test_mint_authority(void)
{
    static const struct mode_case  cases[] = {
        /* the two issuer-facing modes this server implements */
        { "oidc-agent",      1, "oidc-agent mints" },
        { "token-exchange",  1, "token-exchange mints" },

        /* every forwarding / inert mode must NOT: it holds the client's
         * credential, not the authority to re-mint it */
        { "passthrough",     0, "passthrough never mints" },
        { "passthrough-opt", 0, "passthrough-opt never mints" },
        { "none",            0, "none never mints" },
        { "",                0, "empty mode never mints" },

        /* near misses: the match is exact, never a prefix, suffix or fold */
        { "oidc-agentX",     0, "suffixed mode name never mints" },
        { "oidc-agent ",     0, "trailing-space mode name never mints" },
        { " oidc-agent",     0, "leading-space mode name never mints" },
        { "oidc",            0, "truncated mode name never mints" },
        { "OIDC-AGENT",      0, "upper-case mode name never mints" },
        { "Token-Exchange",  0, "mixed-case mode name never mints" },
        { "token-exchange\n", 0, "newline-terminated mode name never mints" },
        { "token_exchange",  0, "underscore spelling never mints" },
    };
    size_t  i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        check(brix_tpc_renew_mode_can_mint(cases[i].mode) == cases[i].can_mint,
              cases[i].what);
    }

    check(brix_tpc_renew_mode_can_mint(NULL) == 0, "NULL mode never mints");
}

static void
test_verdict_names(void)
{
    check(strcmp(brix_tpc_renew_verdict_name(BRIX_TPC_RENEW_NOT_NEEDED),
                 "not-needed") == 0, "name(NOT_NEEDED) == not-needed");
    check(strcmp(brix_tpc_renew_verdict_name(BRIX_TPC_RENEW_DUE),
                 "due") == 0, "name(DUE) == due");
    check(strcmp(brix_tpc_renew_verdict_name(BRIX_TPC_RENEW_EXPIRED),
                 "expired") == 0, "name(EXPIRED) == expired");
    check(strcmp(brix_tpc_renew_verdict_name((brix_tpc_renew_verdict_t) 99),
                 "unknown") == 0, "an unmapped verdict names itself unknown");
}

int
main(void)
{
    test_verdicts();
    test_monotone_in_now();
    test_mint_authority();
    test_verdict_names();

    if (failures != 0) {
        printf("FAILED %d check(s)\n", failures);
        return 1;
    }
    printf("ALL PASSED\n");
    return 0;
}
