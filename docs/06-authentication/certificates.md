[← PKI overview](pki-config.md)

## The certificate hierarchy

Grid deployments use a four-level certificate hierarchy. Each level is a
distinct X.509 entity with a distinct trust role.

```
┌───────────────────────────────────────────────────────────┐
│  Root CA Certificate  (self-signed, long-lived, offline)  │
│  /DC=org/DC=example/CN=Example Grid CA                    │
│  BasicConstraints: CA:TRUE                                 │
│  KeyUsage: keyCertSign, cRLSign                            │
└──────────────────────────────┬────────────────────────────┘
                               │ signs
                    ┌──────────┴──────────┐
                    │                     │
     ┌──────────────▼──────────┐   ┌──────▼─────────────────────┐
     │  Host Certificate       │   │  User Certificate           │
     │  /…/CN=storage.cern.ch  │   │  /…/CN=Alice/CN=98765       │
     │  (nginx presents this   │   │  (long-lived, kept offline, │
     │   during TLS handshake) │   │   5-year lifetime typical)  │
     └─────────────────────────┘   └──────┬──────────────────────┘
                                          │ signs (user's private key)
                                   ┌──────▼──────────────────────────────────┐
                                   │  GSI Proxy Certificate  (RFC 3820)       │
                                   │  /…/CN=Alice/CN=98765/CN=12346           │
                                   │  proxyCertInfo extension (critical)       │
                                   │  Lifetime: 12–24 hours                   │
                                   │  ┌────────────────────────────────────┐  │
                                   │  │  [optional] VOMS Attribute Cert    │  │
                                   │  │  embedded as X.509 extension       │  │
                                   │  │  OID 1.3.6.1.4.1.8005.2.1         │  │
                                   │  │  Signed by the VOMS signing cert   │  │
                                   │  └────────────────────────────────────┘  │
                                   └──────────────────────────────────────────┘
```

The **host certificate** proves the server's identity to clients.  The **user
certificate** is the long-term personal credential that lives in the user's
`~/.globus/` directory.  The **proxy certificate** is a short-lived delegate
credential generated each morning — this is what clients actually present to
servers.

---

## Proxy Certificates (RFC 3820)

### What Makes a Certificate a Proxy

A GSI proxy certificate is a normal X.509 end-entity certificate with one
additional critical extension:

```
OID 1.3.6.1.5.5.7.1.14  (id-pe-proxyCertInfo)

ProxyCertInfo ::= SEQUENCE {
    pCPathLenConstraint  INTEGER OPTIONAL,   -- delegation depth limit
    proxyPolicy          ProxyPolicy
}

ProxyPolicy ::= SEQUENCE {
    policyLanguage  OBJECT IDENTIFIER,       -- 1.3.6.1.5.5.7.21.1 = inheritAll
    policy          OCTET STRING OPTIONAL
}
```

The `inheritAll` policy language means the proxy inherits all rights of its
issuer (the user certificate), with no further restriction.

The proxy's subject name is the issuer's DN with an extra `CN` component
appended:

```
Issuer  (user cert): /DC=org/DC=example/CN=Alice/CN=98765
Subject (proxy):     /DC=org/DC=example/CN=Alice/CN=98765/CN=12346
```

Standard OpenSSL rejects proxy certificates by default because they violate the
normal rule that only CAs may issue certificates.  Two flags must be set to
allow them:

```c
/* at CA store creation time */
X509_STORE_set_flags(store, X509_V_FLAG_ALLOW_PROXY_CERTS);

/* at each verification call */
X509_STORE_CTX_set_flags(vctx, X509_V_FLAG_ALLOW_PROXY_CERTS);
```

Setting only the store flag is not sufficient — both must be set.  This is
documented in `protocol-notes.md` §8 and enforced in `src/auth/crypto/` and
`src/webdav/auth_cert.c`.

### Proxy File Layout (PEM Stack)

A GSI proxy credential file contains three PEM blocks in order:

```
┌────────────────────────────────────────────────────────┐
│  -----BEGIN CERTIFICATE-----                           │
│  [proxy certificate — signed by user's private key]    │  ← servers read this
│  -----END CERTIFICATE-----                             │    as the leaf cert
├────────────────────────────────────────────────────────┤
│  -----BEGIN RSA PRIVATE KEY-----                       │
│  [proxy private key — ephemeral, generated at proxy    │  ← clients sign
│   creation time]                                       │    requests with this
│  -----END RSA PRIVATE KEY-----                         │
├────────────────────────────────────────────────────────┤
│  -----BEGIN CERTIFICATE-----                           │
│  [user certificate — the issuer of the proxy,         │  ← completes the chain
│   needed by the server to verify the proxy's sig]     │    proxy → user → CA
│  -----END CERTIFICATE-----                             │
└────────────────────────────────────────────────────────┘
```

The proxy private key travels with the proxy cert in the same file.  This is
intentional in the GSI model: the proxy is a short-lived credential meant to be
copied to remote sites (e.g. a grid batch job worker node) without exposing the
long-lived user key.

---

## VOMS Attribute Certificates

VOMS (Virtual Organization Membership Service) extends a GSI proxy with VO
membership assertions.  This adds a **second**, independent trust chain
alongside the X.509 certificate chain.

### Two Parallel Trust Chains

```
X.509 IDENTITY CHAIN                  VOMS MEMBERSHIP CHAIN
────────────────────                  ─────────────────────

Root CA                               Root CA
    │ signs                               │ signs
Host / User Cert                     VOMS Signing Cert
    │ signs                               │ signs
Proxy Cert                           Attribute Certificate (AC)
(subject DN = who you are)           (AC embedded inside proxy cert
                                      as X.509 extension)

Verified by:                         Verified by:
  X509_verify_cert()                   libvomsapi: checks AC signature
  against CA bundle                    against vomsdir LSC files
```

The VOMS signing certificate is **not** the same as the CA.  It is a separate
end-entity certificate signed by the CA, whose sole purpose is signing ACs.  It
has no `BasicConstraints: CA:TRUE`.  Its identity is registered in the
`vomsdir` on every server that wants to accept VOMS memberships from that VO.

### The vomsdir and LSC Files

Each VO gets a directory under `vomsdir`:

```
vomsdir/
├── cms/
│   └── voms.cern.ch.lsc          ← one file per VOMS server hostname
└── atlas/
    └── voms.cern.ch.lsc
```

An LSC file contains exactly two lines — the VOMS signing cert's subject DN,
then its issuer DN (the CA that signed the VOMS signing cert):

```
/DC=ch/DC=cern/OU=computers/CN=voms.cern.ch
/DC=ch/DC=cern/CN=CERN Grid Certification Authority
```

When the module calls `libvomsapi` to verify a VOMS proxy, the library:

1. Locates the AC extension inside the proxy certificate
2. Finds the matching LSC file using the VO name from the AC
3. Verifies that the AC was signed by a VOMS signing cert whose
   `(subject, issuer)` DN pair matches the LSC file

This two-step lookup is why the LSC file must contain the DNs in exactly the
format produced by `openssl x509 -noout -subject -nameopt compat`.

### VOMS Attribute Certificate Contents

The AC embedded in a VOMS proxy expresses VO membership as Fully Qualified
Attribute Names (FQANs):

```
VOMS Attribute Certificate
├── holder         (DN of the proxy certificate)
├── issuer         (DN of the VOMS signing cert)
├── validity       (notBefore / notAfter — typically 24h)
├── voName         "cms"
└── fqan[]
    ├── "/cms/Role=NULL/Capability=NULL"          ← generic membership
    ├── "/cms/Role=production/Capability=NULL"    ← role-based
    └── "/cms/local/tier2/Role=NULL/..."          ← sub-VO group
```

The module extracts VO names from FQANs in `src/auth/voms/collect.c`:

```c
/* FQAN "/cms/Role=..." → VO name "cms" (text before the second '/') */
static ngx_flag_t
xrootd_fqan_to_vo(const char *fqan, char *vo, size_t vo_sz)
{
    const char *start = fqan + 1;            /* skip leading '/' */
    const char *end   = strchr(start, '/');  /* find next '/' */
    size_t      len   = end - start;         /* that's the VO name */
    ...
}
```

The extracted VO list (e.g. `"cms,atlas"`) is stored in the session context
and matched against `xrootd_require_vo` path rules.

---
