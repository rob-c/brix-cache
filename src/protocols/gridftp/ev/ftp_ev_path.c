#include "ftp_ev.h"

#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_ops.h"
#include "core/compat/path.h"

#include <string.h>    /* strchr */

#include <openssl/pem.h>
#include <openssl/x509.h>

/*
 * ftp_ev_path.c — command tokenising, path confinement, and VFS context setup.
 *
 * WHAT: split a command line into verb + argument, resolve a (possibly relative)
 * command argument into a canonical filesystem path confined under the export
 * root, and build the per-operation brix_vfs_ctx_t.
 *
 * WHY: every namespace/transfer verb needs the same two things — a path that
 * cannot escape the export (INVARIANT 4: resolve_path before open) and a VFS
 * context carrying the caller's identity + write permission.  Centralising them
 * keeps the per-verb handlers to their own logic.  Ported verbatim from the sync
 * engine so both share identical confinement semantics during the transition.
 *
 * HOW: brix_ftp_ev_resolve() joins the session CWD with the argument, then hands
 * the logical path to brix_http_resolve_path() for canonicalisation + confinement
 * against conf->root_canon; brix_ftp_ev_vfs_ctx() threads the GSI identity and
 * TLS state into brix_vfs_ctx_init().
 */


/* Split `line` in place: NUL-terminate the verb, return the argument tail (an
 * empty string when the line is a bare verb). */
char *
brix_ftp_ev_split(char *line, char **verb_out)
{
    char *sp;

    *verb_out = line;
    sp = strchr(line, ' ');
    if (sp == NULL) {
        return (char *) "";
    }
    *sp = '\0';
    return sp + 1;
}


/* Combine the session CWD with `arg` into a logical path and confine it under the
 * export root.  On success `abs` holds the canonical filesystem path and the
 * return is 0; otherwise an FTP failure code (550 not-found/denied, 553 malformed). */
int
brix_ftp_ev_resolve(ftp_ev_t *fc, const char *arg, char *abs, size_t abssz)
{
    char logical[PATH_MAX];
    int  rc;

    if (arg == NULL || arg[0] == '\0') {
        ngx_memcpy(logical, fc->cwd, ngx_strlen(fc->cwd) + 1);
    } else if (arg[0] == '/') {
        if (ngx_strlen(arg) >= sizeof(logical)) {
            return 553;
        }
        ngx_memcpy(logical, arg, ngx_strlen(arg) + 1);
    } else {
        int n = snprintf(logical, sizeof(logical), "%s%s%s",
                         fc->cwd,
                         (fc->cwd[1] == '\0') ? "" : "/",   /* cwd == "/" ? */
                         arg);
        if (n <= 0 || (size_t) n >= sizeof(logical)) {
            return 553;
        }
    }

    rc = brix_http_resolve_path(fc->conf->root_canon, logical, abs, abssz);
    if (rc != 0) {
        return 550;                     /* 400/403/404/414/500 → FTP 550       */
    }
    return 0;
}


/* Read every PEM certificate in `pem` onto `sink`, de-duplicating by identity so
 * a cert already present (e.g. the spliced issuer) is not added twice. */
static void
fwd_collect_certs(ngx_str_t *pem, STACK_OF(X509) *sink)
{
    BIO  *bio;
    X509 *x;

    if (pem == NULL || pem->len == 0) {
        return;
    }
    bio = BIO_new_mem_buf(pem->data, (int) pem->len);
    if (bio == NULL) {
        return;
    }
    while ((x = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        int i, dup = 0;
        for (i = 0; i < sk_X509_num(sink); i++) {
            if (X509_cmp(sk_X509_value(sink, i), x) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup) {
            X509_free(x);
        } else if (sk_X509_push(sink, x) == 0) {
            X509_free(x);
        }
    }
    BIO_free(bio);
}


/* Assemble the RFC 3820 proxy chain to forward to the storage backend.
 *
 * The credential captured on the control channel (fc->deleg_proxy) is what the
 * server-side GSSAPI layer could see of the client's chain — leaf + whatever
 * SSL_get_peer_cert_chain() exposed — which (a) omits the delegated leaf's DIRECT
 * issuer (the peer's own control leaf, excluded by OpenSSL server-side), (b) may
 * carry the certs OUT OF ISSUER ORDER, and (c) includes the self-signed CA.  A
 * GSI upstream (XrdSecgsi) walks the presented chain strictly and rejects any of
 * those as "chain is inconsistent".
 *
 * Rebuild a clean chain: parse every cert (from the capture and the separately
 * captured control leaf, fc->ctrl_leaf_pem), find the leaf by matching the
 * private key, then walk issuer→subject links emitting leaf → … → end-entity,
 * STOPPING before the self-signed trust anchor (the upstream verifies the CA from
 * its own trust store; a forwarded CA breaks the walk).  Serialize the ordered
 * certs followed by the private key — the layout every GSI consumer expects.
 *
 * Returns *deleg verbatim on any parse/alloc failure (defensive: never worse than
 * forwarding the raw capture).  All OpenSSL temporaries are freed before return;
 * the result bytes are owned by `pool`. */
static ngx_str_t
brix_ftp_ev_forward_pem(ngx_pool_t *pool, ngx_str_t *deleg, ngx_str_t *issuer)
{
    ngx_str_t       out = *deleg;                 /* default: forward verbatim */
    STACK_OF(X509) *certs;
    EVP_PKEY       *key = NULL;
    X509           *leaf = NULL, *cur;
    BIO            *kbio, *obio = NULL;
    int             i;

    if (deleg->len == 0) {
        return out;
    }

    certs = sk_X509_new_null();
    if (certs == NULL) {
        return out;
    }
    fwd_collect_certs(deleg, certs);
    fwd_collect_certs(issuer, certs);

    /* the private key identifies the leaf (the cert we can actually sign with). */
    kbio = BIO_new_mem_buf(deleg->data, (int) deleg->len);
    if (kbio != NULL) {
        key = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
        BIO_free(kbio);
    }
    if (key != NULL) {
        for (i = 0; i < sk_X509_num(certs); i++) {
            X509     *c = sk_X509_value(certs, i);
            EVP_PKEY *pk = X509_get_pubkey(c);
            int       hit = (pk != NULL && EVP_PKEY_eq(pk, key) == 1);
            EVP_PKEY_free(pk);
            if (hit) {
                leaf = c;
                break;
            }
        }
    }

    obio = (leaf != NULL) ? BIO_new(BIO_s_mem()) : NULL;
    if (obio != NULL) {
        int ok = 1;
        int steps = 0;
        int ncerts = sk_X509_num(certs);

        /* Emit leaf → issuer → … stopping before the self-signed trust anchor.
         * Bound the walk by the cert count: a hostile client could delegate a
         * cross-signed cert pair (A issues B, B issues A) with no self-signed
         * terminus, which would otherwise spin the worker. */
        cur = leaf;
        while (cur != NULL && steps++ <= ncerts) {
            X509 *next = NULL;

            if (!PEM_write_bio_X509(obio, cur)) {
                ok = 0;
                break;
            }
            if (X509_NAME_cmp(X509_get_subject_name(cur),
                              X509_get_issuer_name(cur)) == 0)
            {
                break;                 /* reached a self-issued cert — stop */
            }
            for (i = 0; i < sk_X509_num(certs); i++) {
                X509 *c = sk_X509_value(certs, i);
                if (c == cur) {
                    continue;
                }
                if (X509_NAME_cmp(X509_get_subject_name(c),
                                  X509_get_issuer_name(cur)) == 0)
                {
                    next = c;
                    break;
                }
            }
            /* drop the trust anchor: if the only remaining issuer is self-signed
             * (the CA), do not forward it — the upstream trusts it out of band. */
            if (next != NULL
                && X509_NAME_cmp(X509_get_subject_name(next),
                                 X509_get_issuer_name(next)) == 0)
            {
                next = NULL;
            }
            cur = next;
        }

        if (ok && key != NULL
            && PEM_write_bio_PrivateKey(obio, key, NULL, NULL, 0, NULL, NULL))
        {
            u_char *data;
            long    len = BIO_get_mem_data(obio, &data);
            if (len > 0) {
                u_char *copy = ngx_pnalloc(pool, (size_t) len);
                if (copy != NULL) {
                    ngx_memcpy(copy, data, (size_t) len);
                    out.data = copy;
                    out.len  = (size_t) len;
                }
            }
        }
        BIO_free(obio);
    }

    if (key != NULL) {
        EVP_PKEY_free(key);
    }
    sk_X509_pop_free(certs, X509_free);
    return out;
}


/* Build the per-operation VFS context: export root, write permission, TLS flag,
 * and the verified GSI principal (NULL for a cleartext session).
 *
 * When the client delegated an X.509 proxy on the control channel, forward it to
 * the storage backend so the upstream authenticates AS the gsiftp user (the
 * legacy gsiftp → xrootd gateway).  A full proxy is a PASSTHROUGH credential —
 * presented to the upstream unmodified, exactly as the root:// and WebDAV
 * backends treat a captured proxy.  Gated three ways so it never disturbs the
 * existing paths: only when a proxy was actually delegated, only when the
 * resolved mode forwards it (not SELECT), and only when the leaf backend consumes
 * a proxy PEM (xroot/s3) — a posix/pblock export accepts no forwarded proxy, so
 * the bind is skipped and the request serves with the session's own identity as
 * before.  The bag is bound before any open (INVARIANT 4 ordering unchanged). */
void
brix_ftp_ev_vfs_ctx(ftp_ev_t *fc, const char *abs, void *vctx)
{
    brix_vfs_ctx_t *ctx = vctx;

    brix_vfs_ctx_init(ctx, fc->c->pool, fc->c->log,
                      BRIX_PROTO_ROOT, fc->conf->root_canon, "",
                      fc->conf->allow_write ? 1 : 0,
                      fc->sec_active ? 1 : 0 /* is_tls */,
                      fc->identity, abs);

    if (fc->deleg_proxy.len > 0
        && fc->conf->deleg_mode != BRIX_CRED_SELECT
        && brix_vfs_backend_accepts_proxy(ctx))
    {
        ngx_str_t fwd = brix_ftp_ev_forward_pem(fc->c->pool, &fc->deleg_proxy,
                                                &fc->ctrl_leaf_pem);
        (void) brix_vfs_deleg_bind(fc->c->pool, ctx, fc->conf->deleg_mode,
                                   NULL, &fwd);
    }
}
