/* brixcvmfs_admin.c — `brixcvmfs repo gc` + `brixcvmfs repo tag` front-end
 * (phase-96 S11/S12). Thin arg parsing over shared/cvmfs/publish/admin.c;
 * always linked alongside brixcvmfs_repo.c, which dispatches here. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cvmfs/publish/admin.h"
#include "cvmfs/grammar/hash.h"

static int ad_err(const char *what, const char *detail) {
    fprintf(stderr, "brixcvmfs repo: %s%s%s\n", what,
            detail != NULL ? ": " : "", detail != NULL ? detail : "");
    return 1;
}

static int ad_usage(void) {
    fprintf(stderr,
        "usage: brixcvmfs repo gc  <repo_dir> [keys_dir]"
        " (--keep N | --keep-since T) [--grace S]\n"
        "       brixcvmfs repo tag add      <repo_dir> <name> [keys_dir]"
        " [-m <message>]\n"
        "       brixcvmfs repo tag list     <repo_dir>\n"
        "       brixcvmfs repo tag rollback <repo_dir> <name> [keys_dir]\n");
    return 2;
}

/* argv[idx] is a keys_dir when present and not a flag; NULL → engine default
 * of <repo>/keys. Returns the next unconsumed index via *next. */
static const char *ad_keys(int argc, char **argv, int idx, int *next) {
    if (idx < argc && argv[idx][0] != '-') {
        *next = idx + 1;
        return argv[idx];
    }
    *next = idx;
    return NULL;
}

static int ad_gc_flags(int argc, char **argv, int idx, cvmfs_gc_opts_t *o) {
    while (idx < argc) {
        const char *flag = argv[idx];
        const char *val = idx + 1 < argc ? argv[idx + 1] : NULL;
        if (val == NULL) return -1;
        if (strcmp(flag, "--keep") == 0) o->keep_n = atol(val);
        else if (strcmp(flag, "--keep-since") == 0) o->keep_since = atol(val);
        else if (strcmp(flag, "--grace") == 0) o->grace_seconds = atol(val);
        else return -1;
        idx += 2;
    }
    return 0;
}

static int ad_gc_main(int argc, char **argv) {
    /* argv: repo gc <repo_dir> [keys_dir] flags... */
    if (argc < 3) return ad_usage();
    cvmfs_gc_opts_t o;
    memset(&o, 0, sizeof(o));
    o.repo_dir = argv[2];
    o.grace_seconds = 3600;              /* default: spare in-flight publishes */
    int idx = 0;
    o.keys_dir = ad_keys(argc, argv, 3, &idx);
    if (ad_gc_flags(argc, argv, idx, &o) != 0) return ad_usage();
    cvmfs_gc_stats_t st;
    char err[1024] = "";
    if (cvmfs_gc_run(&o, &st, err, sizeof(err)) != 0)
        return ad_err("gc failed", err[0] ? err : NULL);
    printf("gc: kept %ld revision(s), dropped %ld, swept %ld object(s)\n",
           st.kept_revisions, st.dropped_revisions, st.swept_objects);
    return 0;
}

static void ad_tag_print(const cvmfs_history_tag_t *t, void *ud) {
    (void) ud;
    char hex[64];
    cvmfs_hash_to_hex(&t->root_hash, 0, hex, sizeof(hex));
    printf("%-24s rev %-6ld %s  %lld%s%s\n", t->name, t->revision, hex,
           (long long) t->timestamp,
           t->description[0] ? "  " : "", t->description);
}

static int ad_tag_add(int argc, char **argv) {
    /* argv: repo tag add <repo_dir> <name> [keys_dir] [-m msg] */
    if (argc < 5) return ad_usage();
    int idx = 0;
    const char *keys = ad_keys(argc, argv, 5, &idx);
    const char *msg = NULL;
    if (idx < argc) {
        if (idx + 1 >= argc || strcmp(argv[idx], "-m") != 0) return ad_usage();
        msg = argv[idx + 1];
        if (idx + 2 != argc) return ad_usage();
    }
    char err[1024] = "";
    if (cvmfs_tag_add(argv[3], keys, argv[4], msg, err, sizeof(err)) != 0)
        return ad_err("tag add failed", err[0] ? err : NULL);
    printf("tagged '%s'\n", argv[4]);
    return 0;
}

static int ad_tag_rollback(int argc, char **argv) {
    /* argv: repo tag rollback <repo_dir> <name> [keys_dir] */
    if (argc != 5 && argc != 6) return ad_usage();
    int idx = 0;
    const char *keys = ad_keys(argc, argv, 5, &idx);
    long newrev = 0;
    char err[1024] = "";
    if (cvmfs_tag_rollback(argv[3], keys, argv[4], &newrev,
                           err, sizeof(err)) != 0)
        return ad_err("tag rollback failed", err[0] ? err : NULL);
    printf("rolled back to '%s' as revision %ld\n", argv[4], newrev);
    return 0;
}

static int ad_tag_main(int argc, char **argv) {
    const char *sub = argc >= 3 ? argv[2] : "";
    if (strcmp(sub, "add") == 0) return ad_tag_add(argc, argv);
    if (strcmp(sub, "rollback") == 0) return ad_tag_rollback(argc, argv);
    if (strcmp(sub, "list") == 0 && argc == 4) {
        char err[1024] = "";
        int n = cvmfs_tag_list(argv[3], ad_tag_print, NULL, err, sizeof(err));
        if (n < 0) return ad_err("tag list failed", err[0] ? err : NULL);
        if (n == 0) printf("no tags\n");
        return 0;
    }
    return ad_usage();
}

int brixcvmfs_admin_main(int argc, char **argv) {
    /* argv[0] = "repo" after the front-end shift; argv[1] = gc | tag. */
    const char *cmd = argc >= 2 ? argv[1] : "";
    if (strcmp(cmd, "gc") == 0) return ad_gc_main(argc, argv);
    if (strcmp(cmd, "tag") == 0) return ad_tag_main(argc, argv);
    return ad_usage();
}
