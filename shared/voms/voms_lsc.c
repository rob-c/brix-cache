/*
 * shared/voms/voms_lsc.c — vomsdir/<vo>/<host>.lsc and legacy certificate matching
 */

#include "voms_lsc.h"
#include "voms_ac.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define VOMS_LSC_MAX_PAIRS 8
#define VOMS_LSC_MAX_LINE  1024

/* Trim leading/trailing whitespace in place; returns the start. */
static char *
lsc_trim(char *s)
{
    size_t n;

    while (*s == ' ' || *s == '\t') {
        s++;
    }
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '
                     || s[n - 1] == '\t'))
    {
        s[--n] = '\0';
    }
    return s;
}

int
brix_voms_dn_line_matches(const char *line, const X509_NAME *name)
{
    char  oneline[BRIX_VOMS_MAX_DN];
    BIO  *bio;
    char *rfc = NULL;
    long  n;
    int   matched;

    if (line == NULL || name == NULL) {
        return 0;
    }
    brix_voms_dn_oneline(name, oneline, sizeof(oneline));
    if (strcmp(line, oneline) == 0) {
        return 1;
    }
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return 0;
    }
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
    n = BIO_get_mem_data(bio, &rfc);
    matched = (n > 0 && (size_t) n == strlen(line) && memcmp(line, rfc, (size_t) n) == 0);
    BIO_free(bio);
    return matched;
}

/* Read the DN lines of one .lsc file into pairs[]; returns the line count
 * (0 for an unreadable or empty file). */
static int
lsc_read(const char *path, char lines[][VOMS_LSC_MAX_LINE], int cap)
{
    FILE *fp = fopen(path, "r");
    char  buf[VOMS_LSC_MAX_LINE];
    int   n = 0;

    if (fp == NULL) {
        return 0;
    }
    while (n < cap && fgets(buf, sizeof(buf), fp) != NULL) {
        char *s = lsc_trim(buf);

        if (s[0] == '\0' || s[0] == '#') {
            continue;
        }
        memcpy(lines[n], s, strlen(s) + 1);
        n++;
    }
    fclose(fp);
    return n;
}

/* Every (subject, issuer) pair of the file matches the chain from the signer up. */
static int
lsc_file_matches(const char *path, STACK_OF(X509) *chain)
{
    char lines[VOMS_LSC_MAX_PAIRS * 2][VOMS_LSC_MAX_LINE];
    int  n = lsc_read(path, lines, VOMS_LSC_MAX_PAIRS * 2);
    int  pairs = n / 2;
    int  i;

    if (pairs == 0 || pairs > sk_X509_num(chain)) {
        return 0;
    }
    for (i = 0; i < pairs; i++) {
        X509 *cert = sk_X509_value(chain, i);

        if (!brix_voms_dn_line_matches(lines[2 * i], X509_get_subject_name(cert))
            || !brix_voms_dn_line_matches(lines[2 * i + 1], X509_get_issuer_name(cert)))
        {
            return 0;
        }
    }
    return 1;
}

/* A PEM certificate file equal to the signer: the pre-LSC vomsdir layout. */
static int
legacy_cert_matches(const char *path, X509 *signer)
{
    FILE *fp = fopen(path, "r");
    X509 *cert;
    int   same;

    if (fp == NULL) {
        return 0;
    }
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (cert == NULL) {
        return 0;
    }
    same = (X509_cmp(cert, signer) == 0);
    X509_free(cert);
    return same;
}

static int
has_suffix(const char *name, const char *suffix)
{
    size_t n = strlen(name), s = strlen(suffix);

    return n >= s && strcmp(name + n - s, suffix) == 0;
}

/* Scan one directory: .lsc files against the chain when `lsc` is set, other
 * regular files as legacy certificates otherwise. */
static int
scan_dir(const char *dir, STACK_OF(X509) *chain, int lsc)
{
    DIR           *dp = opendir(dir);
    struct dirent *de;
    char           path[PATH_MAX];
    int            found = 0;

    if (dp == NULL) {
        return 0;
    }
    while (!found && (de = readdir(dp)) != NULL) {
        int is_lsc = has_suffix(de->d_name, ".lsc");

        if (de->d_name[0] == '.' || is_lsc != lsc) {
            continue;
        }
        if (snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) >= (int) sizeof(path)) {
            continue;
        }
        found = lsc ? lsc_file_matches(path, chain)
                    : legacy_cert_matches(path, sk_X509_value(chain, 0));
    }
    closedir(dp);
    return found;
}

int
brix_voms_lsc_match(const char *vomsdir, const char *vo, STACK_OF(X509) *signer_chain)
{
    char vodir[PATH_MAX];

    if (vomsdir == NULL || vo == NULL || vo[0] == '\0' || signer_chain == NULL
        || sk_X509_num(signer_chain) == 0 || strchr(vo, '/') != NULL
        || strcmp(vo, "..") == 0)
    {
        return 0;
    }
    if (snprintf(vodir, sizeof(vodir), "%s/%s", vomsdir, vo) >= (int) sizeof(vodir)) {
        return 0;
    }
    if (scan_dir(vodir, signer_chain, 1)) {
        return 1;
    }
    return scan_dir(vodir, signer_chain, 0) || scan_dir(vomsdir, signer_chain, 0);
}
