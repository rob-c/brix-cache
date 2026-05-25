# PKI, Proxy Certificates, and VOMS

The complete X.509 certificate stack used by nginx-xrootd, and how it's consumed during authentication over `root://` (XRootD native) and `https://` (WebDAV). If you already know Grid PKI and just want directives, jump to the configuration section.
step-by-step commands for creating test certificates, see
[test-pki.md](test-pki-setup.md).  If you want the quick-reference config
directives, see [authentication.md](auth-overview.md).

---

## Security Model In One Page

Grid security has a lot of names because it separates several concerns that are
often bundled together in smaller systems:

| Concern | Grid/WLCG/OSG term | What nginx-xrootd uses |
|---|---|---|
| Who is this user? | X.509 identity, DN, proxy certificate | GSI proxy chain or token `sub` |
| Which collaboration are they in? | VO, VOMS, FQAN, WLCG group | `ctx->primary_vo`, `ctx->vo_list`, `xrootd_require_vo` |
| Is this server trusted? | Host certificate | `xrootd_certificate`, `ssl_certificate` |
| Which CAs are trusted? | IGTF/grid CA bundle, trust anchors | `xrootd_trusted_ca`, `xrootd_webdav_cadir` |
| Has a cert been revoked? | CRL | `xrootd_crl`, WebDAV CA store CRLs |
| Can this request read/write this path? | Authorization, ACL, storage scope | VO ACLs, token scopes, filesystem permissions |
| Is the transport encrypted? | TLS, HTTPS, `roots://` | nginx SSL or XRootD TLS upgrade |

The module treats identity, authorization, and transport security as distinct
layers:

1. **Identity** says who the client claims to be.
2. **Credential verification** proves that identity using a CA chain, proxy
   extension, token signature, and validity time checks.
3. **Group or VO extraction** turns the credential into authorization facts.
4. **Path authorization** checks those facts against configured ACLs.
5. **Transport encryption** protects bytes on the wire, but does not by itself
   grant access to files.

That separation explains a common surprise: `root://` + GSI can authenticate a
user without encrypting all file data. Native XRootD GSI proves identity at the
application protocol layer. If you also want encrypted file data, use
`roots://`, `xrootd_tls on`, or `davs://`.

```text
credential presented by client
        |
        +-- X.509 / GSI proxy chain
        |       |
        |       +-- verify CA trust anchor and CRL
        |       +-- allow RFC 3820 proxy certificates
        |       +-- extract subject DN
        |       +-- extract optional VOMS attributes
        |               |
        |               v
        |          VO/FQAN facts
        |
        +-- WLCG bearer token
                |
                +-- verify JWT signature with local JWKS
                +-- check issuer, audience, exp, nbf
                +-- extract sub
                +-- extract scopes and wlcg.groups
                        |
                        v
                   scope/group facts

identity facts + authorization facts
        |
        v
path policy: token scopes, xrootd_require_vo, xrootd_allow_write, filesystem mode
        |
        v
allow or reject this request
```

---

## Vocabulary For New Grid Operators

| Term | Short explanation |
|---|---|
| CA | Certificate Authority. A trusted signer for host and user certificates. |
| Trust anchor | A CA certificate installed locally so the server can verify chains. |
| DN | Distinguished Name, the canonical X.509 name for a user or host. |
| Host cert | The server certificate, usually in `/etc/grid-security/hostcert.pem`. |
| Host key | The server private key, usually in `/etc/grid-security/hostkey.pem`. |
| User cert | A long-lived personal certificate, usually not copied to worker nodes. |
| Proxy cert | A short-lived delegated credential derived from the user cert. |
| GSI | Grid Security Infrastructure, the XRootD-era x509/proxy auth model. |
| VO | Virtual Organization, such as `cms` or `atlas`. |
| VOMS | Service that signs VO membership attributes and embeds them in proxies. |
| FQAN | Fully Qualified Attribute Name, e.g. `/cms/Role=production/...`. |
| LSC file | Local trust record naming which VOMS server certificate may sign a VO. |
| CRL | Certificate Revocation List, used to reject revoked certificates. |
| JWKS | JSON Web Key Set, public keys used to verify JWT bearer tokens. |
| WLCG token | A JWT profile used by WLCG storage and compute services. |
| OSG/OSPool | US grid ecosystem that commonly uses the same proxy, VO, and token patterns. |

Site policy decides which CAs, VOs, token issuers, and paths are trusted. This
module provides the protocol machinery; it does not decide that `cms`,
`atlas`, or any other VO should be trusted by default.

---

## Native XRootD vs WebDAV Auth Placement

The same user credential can reach the server through two different protocol
layers:

| Path | Where the credential appears | Main verifier |
|---|---|---|
| `root://` + GSI | Inside `kXR_auth` payload after XRootD login | `src/gsi/auth.c` |
| `roots://` + GSI | Same XRootD `kXR_auth` payload, after TLS decrypt | `src/gsi/auth.c` |
| `davs://` + x509 | TLS client certificate chain during HTTPS handshake | `src/webdav/auth_cert.c` |
| `root://` + token | `kXR_auth` credential type `ztn` with JWT payload | `src/token/validate.c` |
| `davs://` + token | `Authorization: Bearer <jwt>` HTTP header | `src/webdav/auth_token.c` |

For native `root://`, nginx sees raw TCP bytes and the module implements the
XRootD login/auth exchange. For WebDAV, nginx performs the TLS handshake first,
then the WebDAV module verifies the proxy chain or bearer token for the HTTP
request.

The practical debugging consequence is simple: if `root://` GSI works but
`davs://` x509 fails, the user's proxy may be fine and the issue may be in the
HTTP SSL/client-certificate configuration. If `davs://` works but native GSI
fails, inspect the XRootD GSI exchange, `kXR_auth` logs, and native listener
CA/CRL settings.

---

## Common Files And Directories

| Path or variable | Used by | Purpose |
|---|---|---|
| `/etc/grid-security/hostcert.pem` | server | Host certificate sent to clients |
| `/etc/grid-security/hostkey.pem` | server | Private key matching the host certificate |
| `/etc/grid-security/certificates/` | server and clients | Hashed CA trust directory, often with CRLs |
| `/etc/grid-security/vomsdir/<vo>/*.lsc` | server | Names the VOMS signing cert trusted for a VO |
| `~/.globus/usercert.pem` | client | Long-lived user certificate |
| `~/.globus/userkey.pem` | client | Long-lived user private key |
| `X509_USER_PROXY` | client | Path to the short-lived proxy credential |
| `BEARER_TOKEN` | client | JWT token consumed by XRootD clients |
| `Authorization: Bearer ...` | WebDAV client | JWT token consumed by HTTP clients |

In production, host keys should be readable only by the service account that
runs nginx workers. CA certificates and public `.lsc` files can usually be
world-readable. Proxy files contain private keys and should be treated as
secrets even though they are short-lived.

---

## Sub-pages

- [Certificates](certificates.md) — certificate hierarchy, proxy certs (RFC 3820), VOMS attribute certificates
- [GSI authentication](gsi-auth.md) — GSI over root://, proxy cert auth over https://
- [Authorization and CRL](authorization.md) — VO authorization, CRL checking, CA bundle, TLS vs GSI, code map, failure modes
