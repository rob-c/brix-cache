/*
 * proxy.c — X.509 RFC-3820 GSI proxy create / info / destroy (xrdgsiproxy).
 *
 * WHAT: Build a short-lived proxy certificate signed by the user's end-entity
 *       cert/key, carrying the proxyCertInfo extension (OID 1.3.6.1.5.5.7.1.14,
 *       id-ppl-inheritAll) so the GSI verifier accepts it; plus info/destroy.
 * WHY:  Users need a proxy before any GSI xrdcp/xrdfs. This is the one genuinely
 *       new crypto surface in the client; it is pure local OpenSSL (no wire, no
 *       libXrdCl/XrdCrypto).
 * HOW:  Mirror utils/make_proxy.py byte-for-byte on the proxyCertInfo DER and the
 *       subject scheme (userDN + CN=<serial>) so output is identical to the
 *       harness's reference proxy. Output chain = proxycert + usercert + proxykey,
 *       written atomically at mode 0400.
 *
 * Clean-room: the proxy/extension format is RFC 3820 (a published interface);
 * OpenSSL X509 is a public API. No upstream implementation was consulted.
 */
#include "xrdc.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* proxyCertInfo extnValue: SEQUENCE { SEQUENCE { OID id-ppl-inheritAll } }.
 * id-ppl-inheritAll = 1.3.6.1.5.5.7.21.1 → 2b 06 01 05 05 07 15 01. */
static const unsigned char PROXY_CERT_INFO_DER[] = {
    0x30, 0x0c, 0x30, 0x0a, 0x06, 0x08,
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x15, 0x01
};
#define PROXY_CERT_INFO_OID "1.3.6.1.5.5.7.1.14"

/* Open a credential file as a BIO with xrdc_open_credfile's safety checks (no
 * symlink, owned by euid, secret=1 → 0600), so the predictable /tmp/x509up_u<uid>
 * proxy can't be hijacked via a planted symlink/file. BIO_CLOSE makes BIO_free
 * close the underlying fd. Quiet on failure (returns NULL) — callers report. */
struct bio_st *
xrdc_credfile_bio(const char *path, int secret)
{
    int   fd = xrdc_open_credfile(path, secret, NULL);
    FILE *fp;
    BIO  *bio;

    if (fd < 0) {
        return NULL;
    }
    fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        return NULL;
    }
    bio = BIO_new_fp(fp, BIO_CLOSE);
    if (bio == NULL) {
        fclose(fp);
    }
    return bio;
}

void
xrdc_proxy_default_path(char *out, size_t outsz)
{
    const char *p = getenv("X509_USER_PROXY");
    if (p != NULL && p[0] != '\0') {
        snprintf(out, outsz, "%s", p);
    } else {
        snprintf(out, outsz, "/tmp/x509up_u%u", (unsigned) geteuid());
    }
}

static void
default_cred(const char *envname, const char *globus_leaf, char *out, size_t outsz)
{
    const char *v = getenv(envname);
    if (v != NULL && v[0] != '\0') {
        snprintf(out, outsz, "%s", v);
        return;
    }
    {
        struct passwd *pw = getpwuid(geteuid());
        const char    *home = (pw != NULL) ? pw->pw_dir : getenv("HOME");
        snprintf(out, outsz, "%s/.globus/%s", home ? home : ".", globus_leaf);
    }
}

static int
ssl_fail(xrdc_status *st, const char *what)
{
    unsigned long e = ERR_get_error();
    char          buf[160];
    ERR_error_string_n(e, buf, sizeof(buf));
    xrdc_status_set(st, XRDC_EAUTH, 0, "%s: %s", what, buf[0] ? buf : "(no detail)");
    return -1;
}

/* All OpenSSL/OS resources owned by xrdc_proxy_create. Every member starts NULL
 * (fd = -1) so the cleanup helper can free exactly what was acquired so far, in
 * the original single-exit ladder order, regardless of which step failed. */
typedef struct {
    int                fd;
    BIO               *bio;
    X509_EXTENSION    *ext;
    ASN1_OCTET_STRING *octet;
    ASN1_OBJECT       *pci_obj;
    X509_NAME         *subj;
    X509              *proxy;
    EVP_PKEY          *pkey;
    EVP_PKEY          *ukey;
    X509              *user;
} proxy_build_ctx;

/*
 * proxy_build_cleanup — release every resource the build owns and return rc.
 *
 * WHAT: NULL-safe teardown of the proxy_build_ctx in the exact order the former
 *       single `done:` ladder used (fd, bio, ext, octet, pci_obj, subj, proxy,
 *       pkey, ukey, user).
 * WHY:  Lets xrdc_proxy_create become a flat early-return sequence with no goto,
 *       while preserving byte-identical free ordering and partial-init safety.
 * HOW:  Free each non-NULL member once, then return the caller's status code so
 *       callsites can `return proxy_build_cleanup(&c, rc)` on every exit.
 */
static int
proxy_build_cleanup(proxy_build_ctx *c, int rc)
{
    if (c->fd >= 0) { close(c->fd); }
    if (c->bio) { BIO_free(c->bio); }
    if (c->ext) { X509_EXTENSION_free(c->ext); }
    if (c->octet) { ASN1_OCTET_STRING_free(c->octet); }
    if (c->pci_obj) { ASN1_OBJECT_free(c->pci_obj); }
    if (c->subj) { X509_NAME_free(c->subj); }
    if (c->proxy) { X509_free(c->proxy); }
    if (c->pkey) { EVP_PKEY_free(c->pkey); }
    if (c->ukey) { EVP_PKEY_free(c->ukey); }
    if (c->user) { X509_free(c->user); }
    return rc;
}

int
xrdc_proxy_create(const xrdc_proxy_opts *o, xrdc_status *st)
{
    char       cert_path[1024], key_path[1024], out_path[1024], tmp_path[1100];
    proxy_build_ctx c = { .fd = -1 };
    int        valid_hours = (o && o->valid_hours > 0) ? o->valid_hours : 12;
    int        bits = (o && o->bits > 0) ? o->bits : 2048;
    long       serial = (long) time(NULL);   /* arbitrary; verifier keys on PCI+chain */
    char       serial_str[32];

    if (o && o->user_cert) { snprintf(cert_path, sizeof(cert_path), "%s", o->user_cert); }
    else { default_cred("X509_USER_CERT", "usercert.pem", cert_path, sizeof(cert_path)); }
    if (o && o->user_key) { snprintf(key_path, sizeof(key_path), "%s", o->user_key); }
    else { default_cred("X509_USER_KEY", "userkey.pem", key_path, sizeof(key_path)); }
    if (o && o->out_path) { snprintf(out_path, sizeof(out_path), "%s", o->out_path); }
    else { xrdc_proxy_default_path(out_path, sizeof(out_path)); }

    /* Load the user end-entity cert + key (the proxy issuer). */
    c.bio = BIO_new_file(cert_path, "r");
    if (c.bio == NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "cannot open user cert %s", cert_path);
        return proxy_build_cleanup(&c, -1);
    }
    c.user = PEM_read_bio_X509(c.bio, NULL, NULL, NULL);
    BIO_free(c.bio); c.bio = NULL;
    if (c.user == NULL) { ssl_fail(st, "parse user cert"); return proxy_build_cleanup(&c, -1); }

    c.bio = BIO_new_file(key_path, "r");
    if (c.bio == NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "cannot open user key %s", key_path);
        return proxy_build_cleanup(&c, -1);
    }
    c.ukey = PEM_read_bio_PrivateKey(c.bio, NULL, NULL, NULL);
    BIO_free(c.bio); c.bio = NULL;
    if (c.ukey == NULL) { ssl_fail(st, "parse user key"); return proxy_build_cleanup(&c, -1); }

    /* Ephemeral proxy keypair. */
    c.pkey = EVP_RSA_gen((unsigned) bits);
    if (c.pkey == NULL) { ssl_fail(st, "RSA keygen"); return proxy_build_cleanup(&c, -1); }

    c.proxy = X509_new();
    if (c.proxy == NULL) { ssl_fail(st, "X509_new"); return proxy_build_cleanup(&c, -1); }
    X509_set_version(c.proxy, 2);   /* v3 */
    ASN1_INTEGER_set(X509_get_serialNumber(c.proxy), serial);

    /* Subject = user DN + CN=<serial>; issuer = user subject (RFC 3820). */
    c.subj = X509_NAME_dup(X509_get_subject_name(c.user));
    snprintf(serial_str, sizeof(serial_str), "%ld", serial);
    if (c.subj == NULL
        || X509_NAME_add_entry_by_NID(c.subj, NID_commonName, MBSTRING_ASC,
                                      (unsigned char *) serial_str, -1, -1, 0) != 1
        || X509_set_subject_name(c.proxy, c.subj) != 1
        || X509_set_issuer_name(c.proxy, X509_get_subject_name(c.user)) != 1
        || X509_set_pubkey(c.proxy, c.pkey) != 1) {
        ssl_fail(st, "build proxy subject"); return proxy_build_cleanup(&c, -1);
    }
    X509_gmtime_adj(X509_getm_notBefore(c.proxy), -300);
    X509_gmtime_adj(X509_getm_notAfter(c.proxy), (long) valid_hours * 3600);

    /* proxyCertInfo (critical) — exact DER from make_proxy.py. */
    c.octet = ASN1_OCTET_STRING_new();
    c.pci_obj = OBJ_txt2obj(PROXY_CERT_INFO_OID, 1);
    if (c.octet == NULL || c.pci_obj == NULL
        || ASN1_OCTET_STRING_set(c.octet, PROXY_CERT_INFO_DER,
                                 (int) sizeof(PROXY_CERT_INFO_DER)) != 1) {
        ssl_fail(st, "build proxyCertInfo"); return proxy_build_cleanup(&c, -1);
    }
    c.ext = X509_EXTENSION_create_by_OBJ(NULL, c.pci_obj, 1, c.octet);
    if (c.ext == NULL || X509_add_ext(c.proxy, c.ext, -1) != 1) {
        ssl_fail(st, "add proxyCertInfo"); return proxy_build_cleanup(&c, -1);
    }
    X509_EXTENSION_free(c.ext); c.ext = NULL;

    /* KeyUsage critical = digitalSignature. */
    c.ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "critical,digitalSignature");
    if (c.ext == NULL || X509_add_ext(c.proxy, c.ext, -1) != 1) {
        ssl_fail(st, "add KeyUsage"); return proxy_build_cleanup(&c, -1);
    }
    X509_EXTENSION_free(c.ext); c.ext = NULL;

    if (X509_sign(c.proxy, c.ukey, EVP_sha256()) == 0) {
        ssl_fail(st, "sign proxy"); return proxy_build_cleanup(&c, -1);
    }

    /* Write proxycert + usercert + proxykey to a 0600 temp, then atomic rename. */
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%u", out_path, (unsigned) getpid());
    c.fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (c.fd < 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "cannot create %s", tmp_path);
        return proxy_build_cleanup(&c, -1);
    }
    c.bio = BIO_new_fp(fdopen(c.fd, "w"), BIO_CLOSE);
    c.fd = -1;   /* owned by the BIO now */
    if (c.bio == NULL
        || PEM_write_bio_X509(c.bio, c.proxy) != 1
        || PEM_write_bio_X509(c.bio, c.user) != 1
        || PEM_write_bio_PrivateKey(c.bio, c.pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        ssl_fail(st, "write proxy chain");
        BIO_free(c.bio); c.bio = NULL;
        unlink(tmp_path);
        return proxy_build_cleanup(&c, -1);
    }
    BIO_free(c.bio); c.bio = NULL;
    if (chmod(tmp_path, 0400) != 0 || rename(tmp_path, out_path) != 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "cannot finalize %s", out_path);
        unlink(tmp_path);
        return proxy_build_cleanup(&c, -1);
    }

    return proxy_build_cleanup(&c, 0);
}

int
xrdc_proxy_info(const char *path, FILE *out, xrdc_status *st)
{
    char  defp[1024];
    BIO  *bio;
    X509 *cert;
    char  subj[512], issuer[512];

    if (path == NULL) {
        xrdc_proxy_default_path(defp, sizeof(defp));
        path = defp;
    }
    bio = xrdc_credfile_bio(path, 1);
    if (bio == NULL) {
        /* A missing/unreadable proxy is a not-found condition, NOT a CLI
         * usage error: the arguments were well-formed, the file just isn't
         * there. Callers (xrdgsiproxy info) lean on XRDC_ENOENT to stay
         * tolerant of an absent proxy the way stock xrdgsiproxy does. */
        xrdc_status_set(st, XRDC_ENOENT, 0, "proxy file: %s not found", path);
        return -1;
    }
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (cert == NULL) {
        return ssl_fail(st, "parse proxy");
    }

    X509_NAME_oneline(X509_get_subject_name(cert), subj, sizeof(subj));
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
    fprintf(out, "path     : %s\n", path);
    fprintf(out, "subject  : %s\n", subj);
    fprintf(out, "issuer   : %s\n", issuer);
    {
        int days = 0, secs = 0;
        const ASN1_TIME *na = X509_get0_notAfter(cert);
        if (ASN1_TIME_diff(&days, &secs, NULL, na)) {
            long left = (long) days * 86400 + secs;
            fprintf(out, "validity : %s (%ld:%02ld:%02ld remaining)\n",
                    left > 0 ? "valid" : "EXPIRED",
                    left > 0 ? left / 3600 : 0,
                    left > 0 ? (left % 3600) / 60 : 0,
                    left > 0 ? left % 60 : 0);
        }
    }
    X509_free(cert);
    return 0;
}

/*
 * Phase 40 (c): programmatic GSI-proxy lifetime — store the seconds of validity
 * remaining (negative if already expired) in *secs_left.  Returns 0 on success,
 * -1 if there is no proxy at `path` (default path when NULL) or it cannot be
 * parsed.  Pure local inspection (no network); used by the client-side pre-flight
 * / auth-failure diagnostics so the user instantly sees an expired proxy.
 */
int
xrdc_proxy_remaining(const char *path, long *secs_left)
{
    char  defp[1024];
    BIO  *bio;
    X509 *cert;
    int   days = 0, secs = 0;

    if (secs_left == NULL) {
        return -1;
    }
    if (path == NULL) {
        xrdc_proxy_default_path(defp, sizeof(defp));
        path = defp;
    }
    bio = xrdc_credfile_bio(path, 1);
    if (bio == NULL) {
        return -1;
    }
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (cert == NULL) {
        return -1;
    }
    if (!ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(cert))) {
        X509_free(cert);
        return -1;
    }
    X509_free(cert);
    *secs_left = (long) days * 86400 + secs;
    return 0;
}

int
xrdc_proxy_destroy(const char *path, xrdc_status *st)
{
    char        defp[1024];
    struct stat sb;
    int         fd;

    if (path == NULL) {
        xrdc_proxy_default_path(defp, sizeof(defp));
        path = defp;
    }
    if (stat(path, &sb) != 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "no proxy at %s", path);
        return -1;
    }
    /* Best-effort shred: overwrite the bytes before unlinking. */
    fd = open(path, O_WRONLY);
    if (fd >= 0) {
        char    zero[4096];
        off_t   left = sb.st_size;
        memset(zero, 0, sizeof(zero));
        while (left > 0) {
            size_t  n = (left < (off_t) sizeof(zero)) ? (size_t) left : sizeof(zero);
            ssize_t w = write(fd, zero, n);
            if (w <= 0) { break; }
            left -= w;
        }
        (void) fsync(fd);
        close(fd);
    }
    if (unlink(path) != 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "cannot remove %s", path);
        return -1;
    }
    return 0;
}
