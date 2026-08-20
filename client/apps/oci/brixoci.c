/* brixoci — OCI registry / image-layout tool (phase-104 D5.4), an argv[0]
 * personality of brixMount (dispatch in apps/fs/brixmount.c).
 *
 * WHAT: pull/push/copy between registries and on-disk OCI image layouts,
 *       plus ls/tags/rm/inspect — over lib/oci (reg_client + layout).
 * WHY:  the ingest pipeline (`brixcvmfs ingest image`) and operators need
 *       one CLI that speaks both transports with the same auth, digest-
 *       verify and redirect policy as the proxy planes.
 * HOW:  every verb maps its lib result code onto the brixcvmfs exit table
 *       (0 ok · 2 usage · 3 auth · 4 not-found · 5 verify · 6 transport).
 *       Auth material: --token-file / --cert+--key / netrc-style
 *       ~/.config/brix/oci-auth, refused outright unless mode 0600. */
#include "brixoci_internal.h"

#include "core/version.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OCI_AUTH_FILE_CAP  8192
#define OCI_PEM_CAP        (256 * 1024)

static void
oci_usage(FILE *out)
{
    fprintf(out,
        "usage: brixoci pull  <ref> [--to DIR] [--platform P]\n"
        "       brixoci push  <ref> [--from DIR]\n"
        "       brixoci copy  <src-ref|oci:DIR> <dst-ref|oci:DIR>\n"
        "       brixoci convert --estargz <src-ref|oci:DIR> <dst-ref|oci:DIR>\n"
        "                       [--tag NAME]\n"
        "       brixoci ls    [oci:DIR]\n"
        "       brixoci tags  <host/name>\n"
        "       brixoci rm    <ref>\n"
        "       brixoci inspect <ref> [--raw]\n"
        "       brixoci gc    <store-dir> [--grace S] [--dry-run] [--json]\n"
        "\n"
        "  <ref> = [host[:port]/]name[:tag][@alg:hex]; oci:DIR is an\n"
        "  OCI image-layout directory (pull default: oci:.). convert\n"
        "  re-encodes every layer for lazy pulling; the result is a new\n"
        "  image — different layer digests, different diff_ids.\n"
        "  Auth: --token-file F | --cert PEM [--key PEM] | netrc-style\n"
        "  ~/.config/brix/oci-auth (must be mode 0600). --insecure allows\n"
        "  cleartext http + disables TLS verification (lab fixtures).\n"
        "%s", BRIX_USAGE_FOOTER("brixoci"));
}

/* Result code → the brixcvmfs exit-code table. */
static int
oci_exit(int rc)
{
    switch (rc) {
    case BRIX_OCI_REG_OK:        return 0;
    case BRIXOCI_EUSAGE:         return 2;
    case BRIX_OCI_REG_EAUTH:     return 3;
    case BRIX_OCI_REG_ENOTFOUND: return 4;
    case BRIX_OCI_REG_EVERIFY:   return 5;
    default:                     return 6;   /* ETRANSPORT / EPROTO */
    }
}

/* Whole small file into buf (NUL-terminated). 0 / -1 with errno. */
static int
oci_slurp(const char *path, char *buf, size_t cap, size_t *n)
{
    FILE  *f = fopen(path, "r");
    size_t got;

    if (f == NULL) {
        return -1;
    }
    got = fread(buf, 1, cap - 1, f);
    if (ferror(f) || got == cap - 1) {          /* error or over cap */
        fclose(f);
        errno = got == cap - 1 ? EFBIG : EIO;
        return -1;
    }
    fclose(f);
    buf[got] = '\0';
    if (n != NULL) {
        *n = got;
    }
    return 0;
}

/* ~/.config/brix/oci-auth: netrc-style `machine H login U password P`
 * records. The file is refused whenever it exists with group/other bits
 * set — 0600 is the contract, not a warning. 1 creds found / 0 none /
 * negative result code. Matches the transport host or the ref's host
 * spelling (docker.io vs registry-1.docker.io). */
static int
oci_auth_file(const char *host, const char *ref_host, char *user,
              size_t ulen, char *pass, size_t plen, char *err, size_t errlen)
{
    char        path[1024], buf[OCI_AUTH_FILE_CAP];
    const char *home = getenv("HOME");
    struct stat st;
    char       *tok, *sp = NULL;
    char        cur[256] = "";
    int         matched = 0, have = 0;

    if (home == NULL || home[0] == '\0') {
        return 0;
    }
    snprintf(path, sizeof(path), "%s/.config/brix/oci-auth", home);
    if (stat(path, &st) != 0) {
        return 0;                               /* absent: fine */
    }
    if ((st.st_mode & 077) != 0) {
        snprintf(err, errlen, "%s: mode %04o is not 0600 — refusing to "
                 "read credentials (chmod 600 it)", path,
                 st.st_mode & 07777);
        return BRIX_OCI_REG_EAUTH;
    }
    if (oci_slurp(path, buf, sizeof(buf), NULL) != 0) {
        snprintf(err, errlen, "%s: %s", path, strerror(errno));
        return BRIX_OCI_REG_EAUTH;
    }
    for (tok = strtok_r(buf, " \t\r\n", &sp); tok != NULL;
         tok = strtok_r(NULL, " \t\r\n", &sp)) {
        char *val = strtok_r(NULL, " \t\r\n", &sp);

        if (val == NULL) {
            break;
        }
        if (strcmp(tok, "machine") == 0) {
            snprintf(cur, sizeof(cur), "%s", val);
            matched = strcmp(cur, host) == 0 ||
                      (ref_host[0] != '\0' && strcmp(cur, ref_host) == 0);
        } else if (matched && strcmp(tok, "login") == 0) {
            snprintf(user, ulen, "%s", val);
        } else if (matched && strcmp(tok, "password") == 0) {
            snprintf(pass, plen, "%s", val);
            have = user[0] != '\0';
        }
    }
    return have;
}

/* --token-file: the trimmed file content becomes the static bearer. */
static int
oci_token_file(const char *path, char *bearer, size_t blen, char *err,
               size_t errlen)
{
    size_t n;

    if (oci_slurp(path, bearer, blen, &n) != 0) {
        snprintf(err, errlen, "--token-file %s: %s", path, strerror(errno));
        return BRIX_OCI_REG_EAUTH;
    }
    while (n > 0 && (bearer[n - 1] == '\n' || bearer[n - 1] == '\r' ||
                     bearer[n - 1] == ' ' || bearer[n - 1] == '\t')) {
        bearer[--n] = '\0';
    }
    if (n == 0) {
        snprintf(err, errlen, "--token-file %s: empty", path);
        return BRIX_OCI_REG_EAUTH;
    }
    return BRIX_OCI_REG_OK;
}

/* The TLS layer takes ONE PEM holding chain + key (lib/net/tls.c). A
 * separate --key is combined into a mode-0600 temp; main unlinks it on
 * every exit path. pem_out empty = no client cert. */
static int
oci_client_pem(const brixoci_opts_t *o, char *pem_out, size_t plen,
               int *is_tmp, char *err, size_t errlen)
{
    char  *buf;
    size_t cn = 0, kn = 0;
    int    fd, ok;

    *is_tmp = 0;
    pem_out[0] = '\0';
    if (o->cert == NULL) {
        if (o->key != NULL) {
            snprintf(err, errlen, "--key requires --cert");
            return BRIXOCI_EUSAGE;
        }
        return BRIX_OCI_REG_OK;
    }
    if (o->key == NULL || strcmp(o->key, o->cert) == 0) {
        snprintf(pem_out, plen, "%s", o->cert);
        return BRIX_OCI_REG_OK;
    }
    buf = malloc(2 * OCI_PEM_CAP);
    if (buf == NULL) {
        snprintf(err, errlen, "out of memory");
        return BRIX_OCI_REG_ETRANSPORT;
    }
    if (oci_slurp(o->cert, buf, OCI_PEM_CAP, &cn) != 0 ||
        oci_slurp(o->key, buf + cn, OCI_PEM_CAP, &kn) != 0) {
        snprintf(err, errlen, "--cert/--key: %s", strerror(errno));
        free(buf);
        return BRIX_OCI_REG_EAUTH;
    }
    snprintf(pem_out, plen, "%s/brixoci-pem.XXXXXX",
             getenv("TMPDIR") != NULL ? getenv("TMPDIR") : "/tmp");
    fd = mkstemp(pem_out);
    if (fd < 0) {
        snprintf(err, errlen, "%s: %s", pem_out, strerror(errno));
        free(buf);
        return BRIX_OCI_REG_ETRANSPORT;
    }
    ok = write(fd, buf, cn + kn) == (ssize_t) (cn + kn);
    free(buf);
    close(fd);
    if (!ok) {
        snprintf(err, errlen, "%s: short write", pem_out);
        unlink(pem_out);
        pem_out[0] = '\0';
        return BRIX_OCI_REG_ETRANSPORT;
    }
    *is_tmp = 1;
    return BRIX_OCI_REG_OK;
}

int
brixoci_end_open(brixoci_end_t *e, const char *spec, int create,
                 const brixoci_opts_t *o, const char *client_pem,
                 char *err, size_t errlen)
{
    int rc;

    memset(e, 0, sizeof(*e));
    if (strncmp(spec, "oci:", 4) == 0) {
        e->is_layout = 1;
        return brix_oci_layout_open(&e->lay, spec[4] != '\0' ? spec + 4
                                                             : ".",
                                    create, err, errlen);
    }
    if (brix_oci_ref_parse(spec, &e->ref, err, errlen) != 0) {
        return BRIXOCI_EUSAGE;
    }
    rc = brix_oci_reg_from_ref(&e->reg, &e->ref, o->insecure, e->name,
                               sizeof(e->name), err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (client_pem != NULL && client_pem[0] != '\0') {
        e->reg.client_cert = client_pem;
    }
    if (o->token_file != NULL) {
        return oci_token_file(o->token_file, e->reg.bearer,
                              sizeof(e->reg.bearer), err, errlen);
    }
    rc = oci_auth_file(e->reg.host, e->ref.host, e->reg.user,
                       sizeof(e->reg.user), e->reg.pass,
                       sizeof(e->reg.pass), err, errlen);
    return rc < 0 ? rc : BRIX_OCI_REG_OK;
}

/* pull/push/copy: normalize the verb into (src spec, dst spec) and pump. */
static int
oci_cmd_xfer(const char *verb, const brixoci_opts_t *o, const char **pos,
             int npos, const char *pem, char *err, size_t errlen)
{
    char          src_spec[1100], dst_spec[1100], dig[72];
    brixoci_end_t src, dst;
    int           rc;

    if (strcmp(verb, "pull") == 0 && npos == 1) {
        snprintf(src_spec, sizeof(src_spec), "%s", pos[0]);
        snprintf(dst_spec, sizeof(dst_spec), "oci:%s",
                 o->to_dir != NULL ? o->to_dir : ".");
    } else if (strcmp(verb, "push") == 0 && npos == 1) {
        snprintf(src_spec, sizeof(src_spec), "oci:%s",
                 o->from_dir != NULL ? o->from_dir : ".");
        snprintf(dst_spec, sizeof(dst_spec), "%s", pos[0]);
    } else if (strcmp(verb, "copy") == 0 && npos == 2) {
        snprintf(src_spec, sizeof(src_spec), "%s", pos[0]);
        snprintf(dst_spec, sizeof(dst_spec), "%s", pos[1]);
    } else {
        snprintf(err, errlen, "%s: wrong arguments", verb);
        return BRIXOCI_EUSAGE;
    }
    rc = brixoci_end_open(&src, src_spec, 0, o, pem, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    rc = brixoci_end_open(&dst, dst_spec, 1, o, pem, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    rc = brixoci_copy_run(&src, &dst, o, dig, sizeof(dig), err, errlen);
    if (rc == BRIX_OCI_REG_OK) {
        printf("%s\n", dig);
    }
    return rc;
}

/* convert: the same two endpoints as copy, with the eStargz re-encoder in
 * the middle. The encoding is named explicitly rather than assumed — a
 * second lazy-pull format would be a second flag, not a silent change of
 * what `convert` produces. */
static int
oci_cmd_convert(const brixoci_opts_t *o, const char **pos, int npos,
                const char *pem, char *err, size_t errlen)
{
    brixoci_end_t src, dst;
    char          dig[72];
    int           rc;

    if (npos != 2) {
        snprintf(err, errlen, "convert: expects a source and a destination");
        return BRIXOCI_EUSAGE;
    }
    if (!o->estargz) {
        snprintf(err, errlen, "convert: name the target encoding "
                 "(--estargz)");
        return BRIXOCI_EUSAGE;
    }
    if (o->tag != NULL && strncmp(pos[1], "oci:", 4) != 0) {
        snprintf(err, errlen, "convert: --tag names an entry in a "
                 "destination LAYOUT; a registry destination is named by "
                 "its own reference");
        return BRIXOCI_EUSAGE;
    }
    rc = brixoci_end_open(&src, pos[0], 0, o, pem, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    rc = brixoci_end_open(&dst, pos[1], 1, o, pem, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    rc = brixoci_convert_run(&src, &dst, o, dig, sizeof(dig), err, errlen);
    if (rc == BRIX_OCI_REG_OK) {
        printf("%s\n", dig);
    }
    return rc;
}

static int
oci_cmd_ls(const char **pos, int npos, char *err, size_t errlen)
{
    brix_oci_layout_t l;
    const char       *dir = ".";
    char             *lines;
    int               rc;

    if (npos == 1) {
        dir = strncmp(pos[0], "oci:", 4) == 0 ? pos[0] + 4 : pos[0];
    }
    rc = brix_oci_layout_open(&l, dir, 0, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    rc = brix_oci_layout_ls(&l, &lines, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    fputs(lines, stdout);
    free(lines);
    return BRIX_OCI_REG_OK;
}

/* tags / rm / inspect share one registry-endpoint verb shape. */
static int
oci_cmd_remote(const char *verb, const brixoci_opts_t *o, const char *spec,
               const char *pem, char *err, size_t errlen)
{
    brixoci_end_t e;
    int           rc;

    rc = brixoci_end_open(&e, spec, 0, o, pem, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (e.is_layout) {
        snprintf(err, errlen, "%s needs a registry ref, not oci:", verb);
        return BRIXOCI_EUSAGE;
    }
    if (strcmp(verb, "tags") == 0) {
        char *tags;

        rc = brix_oci_reg_tags(&e.reg, e.name, &tags, err, errlen);
        if (rc == BRIX_OCI_REG_OK) {
            fputs(tags, stdout);
            free(tags);
        }
        return rc;
    }
    if (strcmp(verb, "rm") == 0) {
        return brix_oci_reg_manifest_del(&e.reg, &e.ref, err, errlen);
    }
    /* inspect: --raw = as served (an index stays an index); default =
     * platform-resolved manifest JSON. */
    {
        brix_oci_desc_t d;

        rc = o->raw
                 ? brix_oci_reg_manifest(&e.reg, &e.ref, NULL, &d, err,
                                         errlen)
                 : brix_oci_reg_resolve(&e.reg, &e.ref, o->platform, &d,
                                        err, errlen);
        if (rc != BRIX_OCI_REG_OK) {
            return rc;
        }
        fwrite(d.body, 1, d.body_len, stdout);
        if (d.body_len == 0 || d.body[d.body_len - 1] != '\n') {
            fputc('\n', stdout);
        }
        brix_oci_desc_free(&d);
        return BRIX_OCI_REG_OK;
    }
}

/* A flag whose value is a non-negative count of seconds; advances *i. */
static int
oci_flag_secs(int argc, char **argv, int *i, long *out)
{
    char *end;

    if (*i + 1 >= argc) {
        return -1;
    }
    *out = strtol(argv[++*i], &end, 10);
    return (end == argv[*i] || *end != '\0' || *out < 0) ? -1 : 0;
}


/* One flag with a value; advances *i. 0 ok / -1 missing value. */
static int
oci_flag_val(int argc, char **argv, int *i, const char **out)
{
    if (*i + 1 >= argc) {
        return -1;
    }
    *out = argv[++*i];
    return 0;
}

/* The value-less switches. 1 = consumed. */
static int
oci_bool_flag(const char *a, brixoci_opts_t *o)
{
    if (strcmp(a, "--insecure") == 0) {
        o->insecure = 1;
    } else if (strcmp(a, "--raw") == 0) {
        o->raw = 1;
    } else if (strcmp(a, "--estargz") == 0) {
        o->estargz = 1;
    } else if (strcmp(a, "--dry-run") == 0) {
        o->dry_run = 1;
    } else if (strcmp(a, "--json") == 0) {
        o->json = 1;
    } else {
        return 0;
    }
    return 1;
}


/* The flags that own the next argv slot; *i advances past it. 1 consumed /
 * 0 not one of these / -1 the value is missing or malformed. */
static int
oci_value_flag(int argc, char **argv, int *i, brixoci_opts_t *o)
{
    const char *a = argv[*i];
    int         bad;

    if (strcmp(a, "--grace") == 0) {
        bad = oci_flag_secs(argc, argv, i, &o->grace);
    } else if (strcmp(a, "--to") == 0) {
        bad = oci_flag_val(argc, argv, i, &o->to_dir);
    } else if (strcmp(a, "--from") == 0) {
        bad = oci_flag_val(argc, argv, i, &o->from_dir);
    } else if (strcmp(a, "--tag") == 0) {
        bad = oci_flag_val(argc, argv, i, &o->tag);
    } else if (strcmp(a, "--platform") == 0) {
        bad = oci_flag_val(argc, argv, i, &o->platform);
    } else if (strcmp(a, "--token-file") == 0) {
        bad = oci_flag_val(argc, argv, i, &o->token_file);
    } else if (strcmp(a, "--cert") == 0) {
        bad = oci_flag_val(argc, argv, i, &o->cert);
    } else if (strcmp(a, "--key") == 0) {
        bad = oci_flag_val(argc, argv, i, &o->key);
    } else {
        return 0;
    }
    return bad != 0 ? -1 : 1;
}


static int
oci_parse_args(int argc, char **argv, brixoci_opts_t *o, const char **pos,
               int *npos)
{
    int i, rc;

    for (i = 2; i < argc; i++) {
        const char *a = argv[i];

        if (a[0] != '-' || a[1] == '\0') {
            if (*npos >= 2) {
                return -1;
            }
            pos[(*npos)++] = a;
            continue;
        }
        if (oci_bool_flag(a, o)) {
            continue;
        }
        rc = oci_value_flag(argc, argv, &i, o);
        if (rc == 1) {
            continue;
        }
        if (rc == 0) {
            fprintf(stderr, "brixoci: unknown option %s\n", a);
        } else {
            fprintf(stderr, "brixoci: %s: missing or invalid value\n", a);
        }
        return -1;
    }
    return 0;
}


/* Execute the verb once common authentication and positional parsing finish. */
static int
oci_dispatch(const char *verb, const brixoci_opts_t *o, const char **pos,
             int npos, const char *pem, char *err, size_t errlen)
{
    if (strcmp(verb, "pull") == 0 || strcmp(verb, "push") == 0 ||
        strcmp(verb, "copy") == 0) {
        return oci_cmd_xfer(verb, o, pos, npos, pem, err, errlen);
    }
    if (strcmp(verb, "convert") == 0) {
        return oci_cmd_convert(o, pos, npos, pem, err, errlen);
    }
    if (strcmp(verb, "gc") == 0) {
        return brixoci_gc_run(o, pos, npos, err, errlen);
    }
    if (strcmp(verb, "ls") == 0) {
        return npos <= 1 ? oci_cmd_ls(pos, npos, err, errlen)
                         : BRIXOCI_EUSAGE;
    }
    if (strcmp(verb, "tags") == 0 || strcmp(verb, "rm") == 0 ||
        strcmp(verb, "inspect") == 0) {
        return npos == 1 ? oci_cmd_remote(verb, o, pos[0], pem, err, errlen)
                         : BRIXOCI_EUSAGE;
    }
    fprintf(stderr, "brixoci: unknown command \"%s\"\n", verb);
    return BRIXOCI_EUSAGE;
}

int brixoci_main(int argc, char **argv);

int
brixoci_main(int argc, char **argv)
{
    brixoci_opts_t o;
    const char    *verb, *pos[2] = { NULL, NULL };
    char           err[512] = "", pem[1100] = "";
    int            npos = 0, pem_tmp = 0, rc;

    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        printf("brixoci (BriX-Cache client) %s\n", brix_client_version());
        return 0;
    }
    if (argc < 2 || strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-h") == 0) {
        oci_usage(argc < 2 ? stderr : stdout);
        return argc < 2 ? 2 : 0;
    }
    verb = argv[1];
    memset(&o, 0, sizeof(o));
    o.grace = BRIXOCI_GC_GRACE;
    if (oci_parse_args(argc, argv, &o, pos, &npos) != 0) {
        oci_usage(stderr);
        return 2;
    }
    rc = oci_client_pem(&o, pem, sizeof(pem), &pem_tmp, err, sizeof(err));
    if (rc == BRIX_OCI_REG_OK) {
        rc = oci_dispatch(verb, &o, pos, npos, pem, err, sizeof(err));
    }
    if (pem_tmp) {
        unlink(pem);
    }
    if (rc == BRIXOCI_EUSAGE && err[0] == '\0') {
        oci_usage(stderr);
    } else if (rc != BRIX_OCI_REG_OK && err[0] != '\0') {
        fprintf(stderr, "brixoci: %s\n", err);
    }
    return oci_exit(rc);
}
