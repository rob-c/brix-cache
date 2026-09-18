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
`src/protocols/webdav/auth_cert.c`.

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

## Legacy (GT2) proxy certificates

Before RFC 3820 a Globus proxy was recognised by shape alone: subject = the
issuer's subject plus one CN (`CN=proxy`, `CN=limited proxy`, or a number) and
no proxyCertInfo extension. OpenSSL only recognises RFC 3820 proxies, so the
verifier marks GT2-shaped certificates for OpenSSL itself (`X509_set_proxy_flag`)
before chain validation; the same proxy rules then apply to them (the issuer
must be the end-entity certificate or another proxy, the subject must be the
issuer plus one CN, path lengths are accounted). VOMS attribute certificates
inside a GT2 proxy are read exactly as inside an RFC one.

`brix_gsi_legacy_proxy off|on|full-only` (http and stream; default `on`)
controls acceptance: `on` accepts full and limited GT2 proxies, `full-only`
refuses a chain containing a `limited proxy` (a credential meant for data access
by a job, not for a login that may re-delegate), `off` accepts RFC 3820 proxies
only. The gsiftp control channel accepts GT2 proxies unconditionally, as
GridFTP clients have always presented them. Every accepted legacy proxy logs one
NOTICE line so the client's move to RFC 3820 can be planned; a full RFC proxy
issued beneath a limited GT2 proxy is refused as before (delegation escalation).

## VOMS Attribute Certificates

VOMS (Virtual Organization Membership Service) extends a GSI proxy with VO
membership assertions.  This adds a **second**, independent trust chain
alongside the X.509 certificate chain.  The module verifies it natively —
`shared/voms/` is plain C over OpenSSL, shared with the client — so no VOMS
library is installed, linked or loaded at runtime.

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
  X509_verify_cert()                   shared/voms/ (brix_voms_retrieve):
  against brix_trusted_ca              AC signature by the embedded VOMS
                                       signing cert, that cert's chain
                                       against brix_voms_cert_dir, and the
                                       vomsdir LSC match
```

The VOMS signing certificate is **not** the same as the CA.  It is a separate
end-entity certificate signed by the CA, whose sole purpose is signing ACs.  It
has no `BasicConstraints: CA:TRUE`.  Its identity is registered in the
`vomsdir` on every server that wants to accept VOMS memberships from that VO.

### What the verifier checks

`brix_voms_retrieve()` runs only **after** the GSI proxy chain has verified
(`src/auth/gsi/auth.c` for `root://`, `src/protocols/webdav/auth_cert.c` for
`davs://`).  It locates the VOMS extension (OID `1.3.6.1.4.1.8005.100.100.5`)
on the proxy leaf or any certificate of its chain, decodes the `AC_SEQ` with a
strict DER template (RFC 5755), and then checks every attribute certificate in
this order — each entry keeps its own verdict, and a proxy is accepted when at
least one entry passes:

1. **AC version** is 2.
2. **Holder binding** — the AC's `baseCertificateID` names the end-entity
   certificate (its subject or issuer DN plus its serial number); an AC lifted
   from another user's proxy is rejected.
3. **Validity window** — `notBefore ≤ now ≤ notAfter`, with the configured
   clock-skew tolerance applied to `notBefore` only (an expired AC is never
   tolerated).
4. **Embedded VOMS server certificate** — the AC carries the signing
   certificate (extension `…100.100.10`); without one there is nothing to
   verify against.
5. **Signature algorithm** — the inner and outer algorithm identifiers must
   agree and MD5-class digests are refused.
6. **Signature** — verified over the original TBS bytes with the embedded
   certificate's public key.
7. **Issuer** — the AC issuer name must equal the signing certificate's
   subject.
8. **Targets** — when the AC carries a targeting extension, this host must be
   among the targets.
9. **Server certificate chain** — the embedded VOMS signing certificate is
   chained against `brix_voms_cert_dir`, the hashed CA directory, with the
   same CRL and `signing_policy` handling as the GSI identity chain.
10. **vomsdir match** — `brix_vomsdir/<vo>/` must name the signer (next
    section).

Only after all ten checks pass are the FQANs of that entry turned into the VO
list used by `brix_require_vo` and the authdb.  A proxy with no VOMS extension
at all is still a valid GSI credential: it simply carries no VO.

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
then its issuer DN (the CA that signed the VOMS signing cert).  Blank lines
and `#` comments are ignored:

```
/DC=ch/DC=cern/OU=computers/CN=voms.cern.ch
/DC=ch/DC=cern/CN=CERN Grid Certification Authority
```

The verifier looks up `vomsdir/<vo>/` using the VO name from the AC (a VO
name containing a path separator or `..` never matches), then reads every
`*.lsc` file in it; the entry passes when some file's `(subject, issuer)` pair
equals the embedded signing certificate's subject DN and issuer DN.  Legacy
vomsdir layouts are also honoured: a PEM certificate placed in the VO
directory (the pre-LSC convention) matches when it is byte-for-byte the
embedded signing certificate.

The DNs are compared in the format produced by
`openssl x509 -noout -subject -nameopt compat` (`/DC=…/CN=…`), so the LSC
file must be written in exactly that form.

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
brix_fqan_to_vo(const char *fqan, char *vo, size_t vo_sz)
{
    const char *start = fqan + 1;            /* skip leading '/' */
    const char *end   = strchr(start, '/');  /* find next '/' */
    size_t      len   = end - start;         /* that's the VO name */
    ...
}
```

The extracted VO list (e.g. `"cms,atlas"`) is stored in the session context
and matched against `brix_require_vo` path rules.

---
