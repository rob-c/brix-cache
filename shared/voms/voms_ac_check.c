/*
 * shared/voms/voms_ac_check.c — print the verdict of every VOMS AC in a proxy file
 *
 * WHAT: A standalone diagnostic and test harness over the native engine:
 *         voms_ac_check [--certdir DIR] [--vomsdir DIR] [--now EPOCH]
 *                       [--skew SECONDS] PROXY.pem
 *       loads every CERTIFICATE block of PROXY.pem (the first is the leaf,
 *       the rest the chain), runs brix_voms_retrieve and prints one line per
 *       attribute certificate plus its FQANs and generic attributes.
 * WHY:  The corner-case test matrix (tests/test_voms_corner_cases.py) crafts
 *       proxies with utils/voms_proxy_fake.py and asserts these verdicts
 *       without a server; operators get the same answer libvoms's
 *       voms-proxy-info -all used to give, with the reason for a rejection.
 * HOW:  Output contract (stable; the tests parse it):
 *         status: <token>
 *         ac[<i>]: vo=<vo> verdict=<token> uri=<uri> digest=<md> fqans=<n> carrier=<k>
 *           fqan: <fqan>
 *           attr: <name>=<value>:<qualifier>
 *       Exit 0 iff status is ok. --certdir omitted skips the chain check,
 *       --vomsdir omitted skips the LSC check (the client-diagnostic mode).
 *
 *   cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -I shared \
 *      shared/voms/voms_ac_check.c shared/voms/voms_asn1.c shared/voms/voms_decode.c \
 *      shared/voms/voms_verify.c shared/voms/voms_lsc.c -lcrypto -o voms_ac_check
 */

#include "voms/voms_ac.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>

typedef struct {
    const char *certdir;
    const char *vomsdir;
    const char *proxy;
    time_t      now;
    int         skew;
} check_args_t;

static int
usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [--certdir DIR] [--vomsdir DIR] [--now EPOCH] "
                    "[--skew SECONDS] PROXY.pem\n", argv0);
    return 2;
}

static int
parse_args(int argc, char **argv, check_args_t *a)
{
    int i;

    memset(a, 0, sizeof(*a));
    a->skew = 300;
    for (i = 1; i < argc; i++) {
        const char *opt = argv[i];
        const char *val = (i + 1 < argc) ? argv[i + 1] : NULL;

        if (strcmp(opt, "--certdir") == 0 && val != NULL) {
            a->certdir = val;
            i++;
        } else if (strcmp(opt, "--vomsdir") == 0 && val != NULL) {
            a->vomsdir = val;
            i++;
        } else if (strcmp(opt, "--now") == 0 && val != NULL) {
            a->now = (time_t) strtoll(val, NULL, 10);
            i++;
        } else if (strcmp(opt, "--skew") == 0 && val != NULL) {
            a->skew = atoi(val);
            i++;
        } else if (opt[0] == '-' || a->proxy != NULL) {
            return 0;
        } else {
            a->proxy = opt;
        }
    }
    return a->proxy != NULL;
}

/* Every CERTIFICATE block of the file: leaf first, then the chain. */
static X509 *
load_chain(const char *path, STACK_OF(X509) **chain)
{
    FILE *fp = fopen(path, "r");
    X509 *leaf = NULL, *cert;

    *chain = sk_X509_new_null();
    if (fp == NULL || *chain == NULL) {
        if (fp != NULL) {
            fclose(fp);
        }
        return NULL;
    }
    while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
        if (leaf == NULL) {
            leaf = cert;
        } else {
            sk_X509_push(*chain, cert);
        }
    }
    fclose(fp);
    return leaf;
}

/* 1 when `dir` holds at least one "<hash>.r<n>" CRL file. */
static int
dir_has_crl(const char *dir)
{
    DIR           *dp = opendir(dir);
    struct dirent *de;
    int            found = 0;

    if (dp == NULL) {
        return 0;
    }
    while (!found && (de = readdir(dp)) != NULL) {
        const char *dot = strrchr(de->d_name, '.');

        found = (dot != NULL && dot[1] == 'r' && dot[2] >= '0' && dot[2] <= '9');
    }
    closedir(dp);
    return found;
}

static X509_STORE *
load_store(const char *certdir)
{
    X509_STORE *store;

    if (certdir == NULL) {
        return NULL;
    }
    store = X509_STORE_new();
    if (store == NULL || X509_STORE_load_locations(store, NULL, certdir) != 1) {
        X509_STORE_free(store);
        fprintf(stderr, "voms_ac_check: cannot load CA directory %s\n", certdir);
        exit(2);
    }
    /* CRLs are consulted where the directory holds any (<hash>.r0), as the
     * module's try mode does; a directory without CRLs skips the check. */
    if (dir_has_crl(certdir)) {
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    }
    return store;
}

static void
print_entry(const brix_voms_entry_t *e, int index)
{
    int j;

    printf("ac[%d]: vo=%s verdict=%s uri=%s digest=%s fqans=%d carrier=%d\n",
           index, e->vo, brix_voms_status_name(e->verdict), e->uri,
           e->digest[0] ? e->digest : "-", e->nfqans, e->carrier);
    for (j = 0; j < e->nfqans; j++) {
        printf("  fqan: %s\n", e->fqans[j]);
    }
    for (j = 0; j < e->nattrs; j++) {
        printf("  attr: %s=%s:%s\n", e->attrs[j].name, e->attrs[j].value,
               e->attrs[j].qualifier);
    }
}

int
main(int argc, char **argv)
{
    check_args_t        a;
    STACK_OF(X509)     *chain = NULL;
    X509               *leaf;
    brix_voms_trust_t   trust;
    brix_voms_result_t *res = NULL;
    brix_voms_status_t  status;
    int                 i;

    if (!parse_args(argc, argv, &a)) {
        return usage(argv[0]);
    }
    leaf = load_chain(a.proxy, &chain);
    if (leaf == NULL) {
        fprintf(stderr, "voms_ac_check: no certificate in %s: %s\n", a.proxy,
                strerror(errno));
        return 2;
    }
    trust.store = load_store(a.certdir);
    trust.vomsdir = a.vomsdir;
    trust.now = a.now;
    trust.skew_seconds = a.skew;

    status = brix_voms_retrieve(leaf, chain, &trust, &res);
    printf("status: %s\n", brix_voms_status_name(status));
    for (i = 0; res != NULL && i < res->n; i++) {
        print_entry(&res->entries[i], i);
    }
    brix_voms_result_free(res);
    X509_STORE_free(trust.store);
    X509_free(leaf);
    sk_X509_pop_free(chain, X509_free);
    return status == BRIX_VOMS_OK ? 0 : 1;
}
