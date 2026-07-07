# auth — identity and authorization

Everything that establishes *who* a client is (GSI/x509, WLCG tokens, SSS,
Kerberos, password, unix, host) and *what they may do* (the authz gate:
authdb + VO ACLs + token scope), plus the crypto plumbing those mechanisms
share and the impersonation broker that performs storage operations as the
mapped user.

Identity establishment runs during the protocol handshake; authorization
runs per-operation through the auth gate ([authz/](authz/)) — the sole
checkpoint on cached-serve paths.

| Dir | What |
|---|---|
| [authz/](authz/) | path-level authorization: auth gate, authdb, VO ACLs, verdict caches |
| [gsi/](gsi/) | GSI/x509: proxy certs (RFC 3820), delegation, DH, signing policy, CRL |
| [token/](token/) | WLCG/SciTokens JWT validation, JWKS, scopes, issuer registry |
| [sss/](sss/) | Simple Shared Secret credentials (cluster-internal auth) |
| [krb5/](krb5/) | Kerberos 5 authentication |
| [pwd/](pwd/) | password authentication |
| [unix/](unix/) | unix identity mapping |
| [host/](host/) | host-based trust |
| [voms/](voms/) | VOMS attribute-certificate extraction (VO/groups/roles) |
| [crypto/](crypto/) | shared crypto helpers: OCSP, cert stores, policy |
| [impersonate/](impersonate/) | per-user impersonation broker (setfsuid workers, idmap) |

**Invariant:** S3 SigV4 is NOT here — it is request signing, not identity,
and lives in `src/protocols/s3/` (CLAUDE.md INVARIANT 6: never share auth
logic between SigV4 and WLCG tokens).
