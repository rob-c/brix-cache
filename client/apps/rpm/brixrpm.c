/* brixrpm — clean-room createrepo + RPM inspector (phase-104 D12.1), an
 * argv[0] personality of brixMount (dispatch in apps/fs/brixmount.c).
 *
 * WHAT: `createrepo <dir>` builds dnf-consumable repodata/ from a directory
 *       of .rpm files; `inspect <pkg.rpm>` prints NEVRA + deps + files as a
 *       debug/verify aid (the D12.4 oracle leg diffs it against `rpm -qp`).
 * WHY:  sites publishing RPM repos into CVMFS (D13) need a repo builder with
 *       no createrepo_c/librpm dependency; the parser and emitter live in
 *       shared/rpm/, this file is only the verb surface.
 * HOW:  exit codes follow the brixcvmfs table subset: 0 ok · 1 operation
 *       failed · 2 usage.
 */
#include "brixrpm_internal.h"

#include "core/version.h"
#include "cli/jsonout.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
rpm_usage(FILE *out)
{
    fprintf(out,
        "usage: brixrpm createrepo <dir> [--update] [--paranoid] [--strict]\n"
        "                          [--baseurl-relative] [--compress gz]\n"
        "       brixrpm inspect <pkg.rpm> [--json]\n"
        "\n"
        "  createrepo scans <dir> recursively for *.rpm and writes\n"
        "  repodata/ (primary/filelists/other + repomd.xml, repomd last).\n"
        "  --update reuses the .brixrpm-cache memo for packages whose\n"
        "  (size, mtime) are unchanged; --paranoid re-hashes each memo hit\n"
        "  instead, so a package rewritten in place under an unchanged\n"
        "  (size, mtime) is caught rather than republished stale (without\n"
        "  --update every package is parsed anyway, so it adds nothing).\n"
        "  --strict makes an unreadable .rpm fatal instead of a\n"
        "  skip-with-warning. Hrefs are always emitted repo-relative and\n"
        "  gzip is the only compression, so the last two flags just name\n"
        "  the defaults.\n"
        "%s", BRIX_USAGE_FOOTER("brixrpm"));
}

/* Sense bits → the rpm -qp operator spelling ("" when unversioned). */
static const char *
rpm_sense_op(uint32_t flags)
{
    uint32_t s = flags & (BRIX_RPMSENSE_LT | BRIX_RPMSENSE_GT |
                          BRIX_RPMSENSE_EQ);

    switch (s) {
    case BRIX_RPMSENSE_LT:                     return "<";
    case BRIX_RPMSENSE_GT:                     return ">";
    case BRIX_RPMSENSE_EQ:                     return "=";
    case BRIX_RPMSENSE_LT | BRIX_RPMSENSE_EQ:  return "<=";
    case BRIX_RPMSENSE_GT | BRIX_RPMSENSE_EQ:  return ">=";
    default:                                   return "";
    }
}

/* One dependency block (provides/requires/...) in text or JSON form.
 * inspect shows the whole truth — rpmlib() tracking deps included — so its
 * output diffs cleanly against `rpm -qp --requires`; only primary.xml
 * filters them (repomd_write.c). */
static void
rpm_deps(brix_rpm_pkg_t *p, const char *label, uint32_t names_tag,
         uint32_t flags_tag, uint32_t vers_tag, int json, int *jfirst)
{
    uint32_t n = brix_rpm_count(p, names_tag);
    uint32_t i;

    if (json) {
        printf("%s \"%s\": [", *jfirst ? "" : ",", label);
        *jfirst = 0;
    } else {
        printf("%s:\n", label);
    }
    for (i = 0; i < n; i++) {
        const char *name = brix_rpm_stra(p, names_tag, i);
        const char *ver  = brix_rpm_stra(p, vers_tag, i);
        uint32_t    fl   = 0;
        const char *op;

        if (name == NULL) {
            break;
        }
        (void) brix_rpm_u32(p, flags_tag, i, &fl);
        op = rpm_sense_op(fl);
        if (json) {
            printf("%s{", i > 0 ? "," : "");
            brix_json_kv_str(stdout, "name", name, 0);
            if (op[0] != '\0' && ver != NULL && ver[0] != '\0') {
                printf(",");
                brix_json_kv_str(stdout, "op", op, 0);
                printf(",");
                brix_json_kv_str(stdout, "version", ver, 0);
            }
            printf("}");
        } else if (op[0] != '\0' && ver != NULL && ver[0] != '\0') {
            printf("  %s %s %s\n", name, op, ver);
        } else {
            printf("  %s\n", name);
        }
    }
    if (json) {
        printf("]");
    }
}

/* The package file list; JSON keeps insane (../) paths visible on purpose —
 * inspect reports, only the emitters sanitize. */
static void
rpm_files(brix_rpm_pkg_t *p, int json)
{
    uint32_t nf = brix_rpm_nfiles(p);
    uint32_t i;

    if (json) {
        printf(", \"files\": [");
    } else {
        printf("files:\n");
    }
    for (i = 0; i < nf; i++) {
        char path[4096];

        if (brix_rpm_file(p, i, path, sizeof(path), NULL, NULL) != 0) {
            break;
        }
        if (json) {
            printf("%s", i > 0 ? "," : "");
            brix_json_fputs(stdout, path);
        } else {
            printf("  %s%s\n", path,
                   brix_rpm_path_sane(path) ? "" : "   [insane path]");
        }
    }
    if (json) {
        printf("]");
    }
}

static void
rpm_nevra(brix_rpm_pkg_t *p, uint32_t epoch, char *out, size_t outlen)
{
    if (epoch > 0) {
        snprintf(out, outlen, "%s-%u:%s-%s.%s",
                 brix_rpm_str(p, BRIX_RPMTAG_NAME), epoch,
                 brix_rpm_str(p, BRIX_RPMTAG_VERSION),
                 brix_rpm_str(p, BRIX_RPMTAG_RELEASE),
                 brix_rpm_str(p, BRIX_RPMTAG_ARCH));
    } else {
        snprintf(out, outlen, "%s-%s-%s.%s",
                 brix_rpm_str(p, BRIX_RPMTAG_NAME),
                 brix_rpm_str(p, BRIX_RPMTAG_VERSION),
                 brix_rpm_str(p, BRIX_RPMTAG_RELEASE),
                 brix_rpm_str(p, BRIX_RPMTAG_ARCH));
    }
}

static void
rpm_inspect_json(brix_rpm_pkg_t *p, uint32_t epoch, const char *nevra)
{
    int jfirst = 1;

    printf("{");
    brix_json_kv_str(stdout, "name", brix_rpm_str(p, BRIX_RPMTAG_NAME), 1);
    brix_json_kv_ll(stdout, "epoch", epoch, 1);
    brix_json_kv_str(stdout, "version",
                     brix_rpm_str(p, BRIX_RPMTAG_VERSION), 1);
    brix_json_kv_str(stdout, "release",
                     brix_rpm_str(p, BRIX_RPMTAG_RELEASE), 1);
    brix_json_kv_str(stdout, "arch", brix_rpm_str(p, BRIX_RPMTAG_ARCH), 1);
    brix_json_kv_str(stdout, "nevra", nevra, 1);
    brix_json_kv_str(stdout, "pkgid", brix_rpm_pkgid(p), 1);
    brix_json_kv_ll(stdout, "size_bytes", brix_rpm_size_bytes(p), 1);
    brix_json_kv_ll(stdout, "nfiles", brix_rpm_nfiles(p), 0);
    printf(",");
    rpm_deps(p, "provides", BRIX_RPMTAG_PROVIDENAME, BRIX_RPMTAG_PROVIDEFLAGS,
             BRIX_RPMTAG_PROVIDEVERSION, 1, &jfirst);
    rpm_deps(p, "requires", BRIX_RPMTAG_REQUIRENAME, BRIX_RPMTAG_REQUIREFLAGS,
             BRIX_RPMTAG_REQUIREVERSION, 1, &jfirst);
    rpm_files(p, 1);
    printf("}\n");
}

static void
rpm_inspect_text(brix_rpm_pkg_t *p, uint32_t epoch, const char *nevra)
{
    int jfirst = 1;

    printf("name: %s\n", brix_rpm_str(p, BRIX_RPMTAG_NAME));
    printf("epoch: %u\n", epoch);
    printf("version: %s\n", brix_rpm_str(p, BRIX_RPMTAG_VERSION));
    printf("release: %s\n", brix_rpm_str(p, BRIX_RPMTAG_RELEASE));
    printf("arch: %s\n", brix_rpm_str(p, BRIX_RPMTAG_ARCH));
    printf("nevra: %s\n", nevra);
    printf("pkgid: %s\n", brix_rpm_pkgid(p));
    printf("size: %lld\n", (long long) brix_rpm_size_bytes(p));
    rpm_deps(p, "provides", BRIX_RPMTAG_PROVIDENAME, BRIX_RPMTAG_PROVIDEFLAGS,
             BRIX_RPMTAG_PROVIDEVERSION, 0, &jfirst);
    rpm_deps(p, "requires", BRIX_RPMTAG_REQUIRENAME, BRIX_RPMTAG_REQUIREFLAGS,
             BRIX_RPMTAG_REQUIREVERSION, 0, &jfirst);
    rpm_files(p, 0);
}

static int
rpm_cmd_inspect(const char *path, int json)
{
    char            err[512] = "";
    char            nevra[1024];
    uint32_t        epoch = 0;
    brix_rpm_pkg_t *p = brix_rpm_open(path, err, sizeof(err));

    if (p == NULL) {
        fprintf(stderr, "brixrpm: %s\n", err);
        return 1;
    }
    (void) brix_rpm_u32(p, BRIX_RPMTAG_EPOCH, 0, &epoch);
    rpm_nevra(p, epoch, nevra, sizeof(nevra));
    if (json) {
        rpm_inspect_json(p, epoch, nevra);
    } else {
        rpm_inspect_text(p, epoch, nevra);
    }
    brix_rpm_close(p);
    return 0;
}

/* createrepo flag walk: one positional (the dir). -1 = usage error. */
static int
rpm_createrepo_args(int argc, char **argv, brixrpm_cr_opts_t *o)
{
    int i;

    memset(o, 0, sizeof(*o));
    for (i = 2; i < argc; i++) {
        const char *a = argv[i];

        if (a[0] != '-') {
            if (o->dir != NULL) {
                return -1;
            }
            o->dir = a;
        } else if (strcmp(a, "--update") == 0) {
            o->update = 1;
        } else if (strcmp(a, "--strict") == 0) {
            o->strict = 1;
        } else if (strcmp(a, "--paranoid") == 0) {
            o->paranoid = 1;
        } else if (strcmp(a, "--baseurl-relative") == 0) {
            /* the default (and only) href mode — accepted, nothing to set */
        } else if (strcmp(a, "--compress") == 0) {
            if (i + 1 >= argc || strcmp(argv[++i], "gz") != 0) {
                fprintf(stderr, "brixrpm: --compress supports only gz\n");
                return -1;
            }
        } else {
            fprintf(stderr, "brixrpm: unknown option %s\n", a);
            return -1;
        }
    }
    return o->dir != NULL ? 0 : -1;
}


/* `createrepo <dir> [options]` — parse then run; a bad flag set is a usage
 * error, never a half-built repository. */
static int
rpm_run_createrepo(int argc, char **argv)
{
    brixrpm_cr_opts_t  o;

    if (rpm_createrepo_args(argc, argv, &o) != 0) {
        rpm_usage(stderr);
        return 2;
    }
    return brixrpm_createrepo(&o);
}


/* `inspect <rpm> [--json]` — the only optional argument this tool takes, so
 * its shape is checked here rather than in the dispatch table. */
static int
rpm_run_inspect(int argc, char **argv)
{
    int  json = (argc == 4 && strcmp(argv[3], "--json") == 0);

    if (argc < 3 || argc > 4 || (argc == 4 && !json)) {
        rpm_usage(stderr);
        return 2;
    }
    return rpm_cmd_inspect(argv[2], json);
}


int
brixrpm_main(int argc, char **argv)
{
    if (argc < 2) {
        rpm_usage(stderr);
        return 2;
    }
    if (strcmp(argv[1], "--version") == 0) {
        printf("brixrpm (BriX-Cache client) %s\n", brix_client_version());
        return 0;
    }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        rpm_usage(stdout);
        return 0;
    }
    if (strcmp(argv[1], "createrepo") == 0) {
        return rpm_run_createrepo(argc, argv);
    }
    if (strcmp(argv[1], "inspect") == 0) {
        return rpm_run_inspect(argc, argv);
    }
    fprintf(stderr, "brixrpm: unknown command \"%s\"\n", argv[1]);
    rpm_usage(stderr);
    return 2;
}
