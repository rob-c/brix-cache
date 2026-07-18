/*
 * brixautofs_unittest.c — unit tests for the automount umbrella's pure core:
 * the FQRN lookup-name gate, the CVMFS_REPOSITORIES membership test, and the
 * repo-slot table state machine.
 *
 * gcc -Wall -Wextra -Werror -DBRIXAUTOFS_UNIT \
 *     -o /tmp/brixautofs_ut client/apps/fs/brixautofs_unittest.c \
 *     client/apps/fs/brixautofs.c -lpthread && /tmp/brixautofs_ut
 */
#include "brixautofs.h"

#include <stdio.h>
#include <string.h>

static int g_checks, g_failed;
#define CHECK(c,n) do{ g_checks++; if(c){printf("  ok   %s\n",n);} \
    else{printf("  FAIL %s (line %d)\n",n,__LINE__); g_failed++;} }while(0)

static void test_valid_fqrn(void) {
    /* success: real-world repository names */
    CHECK(brixautofs_valid_fqrn("atlas.cern.ch"),        "fqrn: atlas.cern.ch");
    CHECK(brixautofs_valid_fqrn("sft.cern.ch"),          "fqrn: sft.cern.ch");
    CHECK(brixautofs_valid_fqrn("cms-ib.cern.ch"),       "fqrn: hyphenated org");
    CHECK(brixautofs_valid_fqrn("config-osg.opensciencegrid.org"),
          "fqrn: config-osg.opensciencegrid.org");
    CHECK(brixautofs_valid_fqrn("a0.b1"),                "fqrn: minimal two labels");

    /* error: structurally wrong names */
    CHECK(!brixautofs_valid_fqrn("atlas"),               "fqrn: single label rejected");
    CHECK(!brixautofs_valid_fqrn(""),                    "fqrn: empty rejected");
    CHECK(!brixautofs_valid_fqrn(NULL),                  "fqrn: NULL rejected");
    CHECK(!brixautofs_valid_fqrn("a..b"),                "fqrn: empty label rejected");
    CHECK(!brixautofs_valid_fqrn("atlas.cern.ch."),      "fqrn: trailing dot rejected");
    char big[300];
    memset(big, 'a', sizeof(big));
    memcpy(big + 140, ".x.", 3);
    big[sizeof(big) - 1] = '\0';
    CHECK(!brixautofs_valid_fqrn(big),                   "fqrn: >255 chars rejected");
    char longlab[80];
    memset(longlab, 'a', 70);
    memcpy(longlab + 70, ".ch", 4);
    CHECK(!brixautofs_valid_fqrn(longlab),               "fqrn: >63-char label rejected");

    /* security-negative: attacker-chosen /cvmfs lookup names */
    CHECK(!brixautofs_valid_fqrn(".."),                  "sec: .. rejected");
    CHECK(!brixautofs_valid_fqrn("../etc"),              "sec: ../ rejected");
    CHECK(!brixautofs_valid_fqrn("a/b.cern.ch"),         "sec: embedded / rejected");
    CHECK(!brixautofs_valid_fqrn(".hidden.cern.ch"),     "sec: leading dot rejected");
    CHECK(!brixautofs_valid_fqrn(".atlas.cern.ch.swp"),  "sec: editor swap probe rejected");
    CHECK(!brixautofs_valid_fqrn("a;b.cern.ch"),         "sec: shell meta rejected");
    CHECK(!brixautofs_valid_fqrn("a b.cern.ch"),         "sec: space rejected");
    CHECK(!brixautofs_valid_fqrn("Atlas.cern.ch"),       "sec: uppercase rejected");
    CHECK(!brixautofs_valid_fqrn("a_b.cern.ch"),         "sec: underscore rejected");
    CHECK(!brixautofs_valid_fqrn("-a.cern.ch"),          "sec: leading - in label rejected");
    CHECK(!brixautofs_valid_fqrn("a-.cern.ch"),          "sec: trailing - in label rejected");
    CHECK(!brixautofs_valid_fqrn("autorun.inf\n"),       "sec: control char rejected");
}

static void test_repo_listed(void) {
    CHECK(brixautofs_repo_listed("atlas.cern.ch,sft.cern.ch", "sft.cern.ch"),
          "listed: comma list");
    CHECK(brixautofs_repo_listed("atlas.cern.ch:sft.cern.ch", "atlas.cern.ch"),
          "listed: colon list");
    CHECK(brixautofs_repo_listed(" atlas.cern.ch ", "atlas.cern.ch"),
          "listed: whitespace tolerated");
    CHECK(!brixautofs_repo_listed("atlas.cern.ch", "atlas.cern.c"),
          "listed: prefix does not match");
    CHECK(!brixautofs_repo_listed("atlas.cern.ch", "las.cern.ch"),
          "listed: substring does not match");
    CHECK(!brixautofs_repo_listed("", "atlas.cern.ch"),
          "listed: empty list matches nothing");   /* strict-mount deny */
    CHECK(!brixautofs_repo_listed(NULL, "atlas.cern.ch"),
          "listed: NULL list matches nothing");
}

static void test_table(void) {
    static brixautofs_table_t t;
    brixautofs_table_init(&t);

    CHECK(brixautofs_find_locked(&t, "atlas.cern.ch") == -1, "table: empty find → -1");
    int i = brixautofs_claim_locked(&t, "atlas.cern.ch");
    CHECK(i >= 0 && t.slot[i].st == BRIXAUTOFS_MOUNTING, "table: claim → MOUNTING");
    CHECK(brixautofs_find_locked(&t, "atlas.cern.ch") == i, "table: find claimed slot");
    brixautofs_commit_locked(&t, i, 4242);
    CHECK(t.slot[i].st == BRIXAUTOFS_MOUNTED && t.slot[i].pid == 4242,
          "table: commit → MOUNTED with pid");
    CHECK(brixautofs_find_pid_locked(&t, 4242) == i, "table: find by pid");
    CHECK(brixautofs_find_pid_locked(&t, 4243) == -1, "table: unknown pid → -1");
    brixautofs_release_locked(&t, i);
    CHECK(brixautofs_find_locked(&t, "atlas.cern.ch") == -1, "table: release frees slot");

    /* error: table full refuses further claims */
    char name[64];
    int claimed = 0;
    for (int k = 0; k < BRIXAUTOFS_MAX_REPOS; k++) {
        snprintf(name, sizeof(name), "r%d.cern.ch", k);
        if (brixautofs_claim_locked(&t, name) >= 0) claimed++;
    }
    CHECK(claimed == BRIXAUTOFS_MAX_REPOS, "table: fills to capacity");
    CHECK(brixautofs_claim_locked(&t, "overflow.cern.ch") == -1,
          "table: full → claim refused");
}

int main(void) {
    test_valid_fqrn();
    test_repo_listed();
    test_table();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
