[← PKI overview](index.md)

## VO Authorization: From Cert to Path Decision

After authentication the module has extracted an identity (a DN string) and,
for VOMS proxies, a VO list.  The VO list flows through the session context:

```
Proxy cert received and verified
          │
          ▼
VOMS AC extraction (src/voms/collect.c)
    libvomsapi parses the AC extension from the proxy cert
    For each VOMS AC entry:
        voName           → "cms"
        fqan[0]          → "/cms/Role=NULL/Capability=NULL" → extract "cms"
        fqan[1]          → "/cms/Role=production/..."       → extract "cms" (already present)
    Result: ctx->primary_vo = "cms"
            ctx->vo_list    = "cms"

          │
          ▼
Path ACL check (src/path/ and xrootd_require_vo directives)
    For each xrootd_require_vo rule:
        rule: path="/cms"  required_vo="cms"
        request path: "/cms/mc/file.root"
              → path starts with "/cms"  ✓
              → vo_list contains "cms"   ✓
              → ALLOW

        rule: path="/atlas"  required_vo="atlas"
        request path: "/cms/mc/file.root"
              → path starts with "/atlas"  ✗
              → skip rule

    Path "/public/..." has no xrootd_require_vo rule
              → ALLOW (any authenticated user)

    Path "/atlas/..." with "cms" proxy
              → rule matches path prefix
              → vo_list does not contain "atlas"
              → DENY (kXR_NotAuthorized)
```

Bearer tokens with `wlcg.groups` claims follow the same path.  The module
maps `wlcg.groups` array entries as synthetic VO names into the same
`ctx->vo_list` field, so `xrootd_require_vo` applies equally to both
authentication methods.

---

## CRL Checking

Certificate Revocation Lists are checked after chain verification succeeds.
The check is performed separately by the stream (GSI) and WebDAV (HTTPS) code
paths, but both use the same logic:

```
Stream GSI path:
  On startup:  load CRL PEM from xrootd_crl directive
               xrootd_pki_verify_crls() checks CRL signature against CA
               CRL reloaded periodically (xrootd_crl_reload seconds)

  Per-session: after X509_verify_cert() succeeds:
               for each cert in proxy chain:
                   search CRL for matching serial + issuer
                   if found → reject with kXR_NotAuthorized

WebDAV HTTPS path:
  On startup:  load CRL PEM from xrootd_webdav_crl directive
               same signature check

  Per-request: after webdav_verify_proxy_cert() would succeed:
               same serial search against loaded CRL
```

CRLs from Grid CAs typically have a 7-day validity period.  The
`xrootd_crl_reload` timer (stream) and the CA store rebuild (WebDAV) must run
more frequently than the CRL validity window or revoked certificates will
eventually be accepted.

---

## The CA Bundle and Hash Symlinks

OpenSSL locates trusted CAs in a directory by hashing the subject name of each
certificate and looking for a file named `<hash>.0`.  Grid installations must
provide symlinks for **both** the new-style (OpenSSL 1.0+) and old-style
(legacy) subject hash formats because XRootD builds on different OpenSSL
versions:

```
ca/
├── ca.pem              ← actual CA certificate
├── 03628dcb.0 ──>  ca.pem   ← new-style hash (openssl x509 -subject_hash)
├── 03628dcb.signing_policy  ← required by XRootD's GSI library
├── f79132b2.0 ──>  ca.pem   ← old-style hash (openssl x509 -subject_hash_old)
└── f79132b2.signing_policy
```

The `.signing_policy` files are only read by the XRootD C++ `XrdSecGSI`
library on the client side — nginx-xrootd's server-side verification does not
read them.  They must still be present in the CA directory if your test clients
use the XRootD library for GSI, because the client validates the server cert
against its own CA bundle.

---

## TLS vs. GSI: What Encrypts What

A common point of confusion is the relationship between TLS transport
encryption and GSI credential exchange:

```
Connection mode       Encrypted by      GSI proxy delivered by
──────────────────    ──────────────    ──────────────────────────────────────
root://  no TLS       nothing           DH session key (AES-CBC, inside XRootD)
root://  xrootd_tls   TLS (after        DH session key INSIDE the TLS tunnel
                      kXR_protocol)
roots://              TLS (from         DH session key INSIDE the TLS tunnel
                      TCP connect)
davs://               TLS (TLS          TLS client cert (not a separate layer;
                      handshake)         the proxy cert IS the TLS client cert)
```

For `root://` without `xrootd_tls`, the proxy certificate is protected only
by the DH session key established in the GSI exchange itself.  The DH exchange
provides forward secrecy for the credential exchange but does not encrypt
subsequent file traffic.

---

## Code Map

| Concern | Source |
|---|---|
| GSI DH key exchange | `src/handshake/` (GSI auth state machine) |
| Proxy chain verification (stream) | `src/handshake/policy.c`, OpenSSL `X509_verify_cert` |
| Proxy chain verification (WebDAV) | `src/webdav/auth_cert.c:webdav_verify_proxy_cert()` |
| TLS auth cache (WebDAV) | `src/webdav/auth_cert.c`, `SSL_get_ex_data` / `SSL_SESSION_get_ex_data` |
| `X509_V_FLAG_ALLOW_PROXY_CERTS` patch | `src/webdav/postconfig.c:xrootd_webdav_patch_ssl_ctx()` |
| VOMS AC parsing | `src/voms/loader.c` (dlopen of libvomsapi) |
| VOMS VO extraction | `src/voms/collect.c:xrootd_collect_voms_vos()` |
| vomsdir LSC lookup | delegated to libvomsapi |
| VO path ACL enforcement | `src/path/find_rule.c`, `src/config/policy.c` |
| CA bundle load | `src/crypto/pki_load.c` |
| CRL signature verification | `src/crypto/pki_check.c:xrootd_pki_verify_crls()` |
| kXR_login challenge string | `src/session/login.c:xrootd_handle_login()` |
| Token (JWT/WLCG) validation | `src/token/` |
| Request signing (kXR_sigver) | `src/session/signing.c`, `src/handshake/sigver.c` |

---

## Common Failure Modes

| Symptom | Probable cause | Check |
|---|---|---|
| `"proxy certificate lacks proxyCertInfo"` | Proxy was generated without RFC 3820 extension | Use `voms-proxy-init` or `utils/make_proxy.py`, not plain `openssl req -new -x509` |
| `"unable to get local issuer certificate"` | CA hash symlinks missing or wrong format | `ls $CA_DIR/*.0` — both old-style and new-style hashes must be present |
| `"No protocols left to try"` (client message) | Login challenge string is malformed | Check that the challenge is plain text `&P=gsi,v:10000,c:ssl,ca:<hash>`, not a binary buffer |
| `"could not instantiate session cipher"` | DH public key in wrong format | Key must be hex bignum prefixed with `---BPUB---`, not RSA PEM |
| Proxy decryption produces garbage | DH padding not disabled | `EVP_PKEY_CTX_set_dh_pad(ctx, 0)` is required |
| WebDAV returns 403 for valid proxy | Proxy rejected because `ssl_verify_client on` | Change to `ssl_verify_client optional_no_ca` — nginx's own verification does not accept RFC 3820 proxies |
| `"cannot verify VOMS signature"` | vomsdir LSC DNs don't match VOMS signing cert | `openssl x509 -in vomscert.pem -noout -subject -nameopt compat` must match the LSC file exactly |
| CRL checks always pass even for revoked certs | CRL not loaded or path wrong | Check `xrootd_crl` / `xrootd_webdav_crl` directives; verify the CRL's issuer matches the CA |
