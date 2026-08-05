# GSI CRL revocation conformance — BriX vs stock XRootD

**Status:** verified 2026-08-04 (xrd1). **Scope:** BriX front (root:// stream plane,
`brix_auth gsi`) vs stock XRootD `sec.protocol gsi`, both fronting X.509-proxy clients.
**One-line:** stock XRootD v5.9.6 loads a CRL that revokes a proxy's End-Entity Certificate,
records the revocation, then authenticates the delegated proxy anyway; BriX (matching
openssl, the reference verifier) rejects it. See also
[gsi-benchmark-rig](gsi-benchmark-rig-2026-08-04.md) context and
[xrdsecgsi-handshake](xrdsecgsi-handshake.md), [wlcg-ca-conformance](wlcg-ca-conformance.md).

This came out of the Phase-2 authenticated conformance benchmark (5 clients — PyXRootD,
go-hep, XrdRust, stock xrdcp/xrdfs, brix CLI — each BriX-vs-stock). The matrix itself is
**full parity: PASS 68 · FAIL 0 · N/A 1** (the lone N/A is `vector_read`, which has no CLI
primitive in either CLI). The only defect-grade *divergence* is the CRL case below.

## The finding

Given a CRL that revokes a user's EEC, stock XRootD authenticates a proxy delegated from
that revoked EEC. Its own GSI debug (`sec.protocol gsi -d:2`) shows exactly why:

```
cryptossl_X509Crl::Init: CRL successfully loaded from …/03628dcb.r0
cryptossl_LoadCache: 2 certificates have been revoked      ← CRL loaded, revocations known
…
crypto_X509Chain::EECname: EEC not found in chain          ← EEC not located in the proxy chain
crypto_X509Chain::EEChash: EEC not found in chain          ← so the revocation is never applied
XrootdXeq: … pvt IPv4 login as testuser                    ← revoked user authenticated
```

The EEC **is** present in the chain the client transmits — a standard grid proxy carries
`[proxy-cert][EEC]` (confirmed: the presented proxy contains the revoked EEC as cert `[1]`,
serial `6E8E…F53A`). BriX finds and checks that same cert and rejects it; stock's chain
walker fails to identify it as the EEC and skips the revocation check. So this is not a
missing-CRL or missing-EEC condition — it is stock failing to apply a *loaded* revocation
to the one CA-issued cert in a proxy chain.

## Why it matters

WLCG / grid authentication is *always* proxy-based — delegation is the entire point of GSI.
The EEC is the only CA-issued (and thus CA-CRL-revocable) certificate in a proxy chain.
A verifier that cannot apply EEC revocation to a proxy therefore fails to honour revocation
in the normal operating case. BriX matches the reference verifier (openssl `-crl_check`);
stock does not.

## Common misconfiguration ruled out (do not repeat)

An earlier pass wrongly concluded "stock `-crl:1` accepts revoked certs." That was a
**CRL-directory misconfiguration**, not the defect. XRootD GSI reads CRLs from a *separate*
`-crldir:` directory — debug line `Secgsi CRL dir:` — that **defaults to
`/etc/grid-security/certificates/`**, independent of `-certdir:`. A revoking CRL placed only
in `-certdir` is never loaded. The finding above is established only *after* setting
`-crldir:` to the trust dir that actually holds the revoking CRL and confirming from the log
that stock loaded it (`N certificates have been revoked`). Always verify CRL load before
drawing any conclusion about enforcement.

## Reproduction

PKI: test CA (hash `03628dcb`), user EECs signed by it, combined CRL revoking their serials,
delegated proxies via `voms-proxy-init`. Rig ports: stock origin `:21199`
(`-crl:3 -crldir:<revoking-dir> -d:2`), BriX gateway `:21296`
(`brix_crl <revoking-dir>; brix_crl_mode require;`). Trust dir carries the CA cert
(`<hash>.0`), signing policy, and the revoking CRL (`<hash>.r0`).

Ground truth per credential:

```
cat <hash>.0 combined.crl.pem > ca_plus_crl.pem
openssl verify -crl_check -CAfile ca_plus_crl.pem <eec>.pem
#   revoked EEC → "error 23 … certificate revoked"
#   valid  EEC → "OK"
```

Per credential, present the proxy and compare:

```
X509_USER_PROXY=<proxy> xrdfs root://localhost:21199/ ls /   # stock
X509_USER_PROXY=<proxy> xrdfs root://localhost:21296/ ls /   # BriX
```

### Exact rig artifacts (xrd1)

- CA hash `03628dcb`; second EEC's CA hash `f79132b2`. Revoked user1 EEC
  `/DC=test/DC=xrootd/CN=Test User/CN=12345`, serial
  `6E8E67D548DA1B2FF5F628C9DB38882B801AF53A`; user2 fresh keypair signed by the CA, serial `2001`.
- Combined CRL `pki/ca/combined.crl.pem` (revokes `6E8E…` + `2001`), built via
  `openssl ca -revoke` + `openssl ca -gencrl` with `pki/ca/ca-full.cnf`, installed as
  `certdir-revoked/{03628dcb,f79132b2}.r0` (both servers restarted to clear the CRL cache).
- Stock origin `:21199`:
  `sec.protocol /usr/lib64 gsi -certdir:certdir-revoked -crl:3
  -crldir:/tmp/xrd-test/certdir-revoked -gridmap:… -gmapopt:1` (`-crl:3` = require-not-expired).
- BriX gateway `:21296`, config `configs/nginx-brix-gsi-revoked.conf`
  (`brix_crl /tmp/xrd-test/certdir-revoked; brix_crl_mode require;`).
- Proxies under `/tmp/xrd-test/proxies/` (revoked-user 12 h proxy also at `/tmp/xrd-test/x509up`,
  `voms-proxy-init -rfc` → 2-cert chain); the format/EEC sweep is `/tmp/xrd-test/sweep.sh`.

## Verification matrix (breadth)

Held to a controlled standard — two independent EECs, four proxy formats, and a
non-revoked positive control:

| credential                                   | openssl (ref) | stock  | BriX   |
|----------------------------------------------|:-------------:|:------:|:------:|
| user1 — RFC 3820 proxy (revoked)             | REVOKED       | ACCEPT | reject |
| user1 — legacy GT2 proxy                     | REVOKED       | ACCEPT | reject |
| user1 — limited proxy                        | REVOKED       | ACCEPT | reject |
| user1 — proxy-of-proxy (2-level delegation)  | REVOKED       | ACCEPT | reject |
| user2 — RFC proxy (independent keypair+serial, revoked) | REVOKED | ACCEPT | reject |
| **user3 — RFC proxy (valid, NOT revoked)**   | OK            | ACCEPT | ACCEPT |

The positive control (user3) is essential: BriX **accepts** the valid proxy, so its
rejections are revocation-specific, not a blanket GSI deny. BriX rejects with
`GSI client cert rejected: certificate revoked`. BriX tracks openssl on every row; stock
accepts every revoked proxy regardless of format or which EEC it derives from.

## Honest scope / caveats

Reproduced against xrootd **v5.9.6** (`libXrdSecgsi-5`) with one test CA. Breadth covers two
distinct EECs and four proxy formats, plus a positive control — so it is not an artifact of a
single credential or proxy structure. The `EEC not found in chain` log pinpoints the failing
step as stock's proxy-chain EEC identification. Not yet cross-checked across other xrootd
versions; it is a real, mechanism-pinned, reproducible observation suitable for an upstream
report, not (yet) a proven-universal CVE.

## Not defects (recorded so the report is not inflated)

- **XrdRust checksum "brix-only"** in the matrix: the stock origin computes the checksum
  asynchronously and returns `kXR_wait`; XrdRust accumulates the waits past its 300 s cap
  (`limit exceeded: server asked this client to wait past its 300s cap`). BriX answers
  synchronously. A timing/behavioral difference, not a stock bug.
- **Phase-1 `kXR_protocol` sec-block layout and `mkdir -p` ENOTEMPTY**: those were *BriX*
  being wrong versus stock (both since fixed) — the opposite direction of defect.
