# shared/voms — native VOMS attribute-certificate decoder and verifier

## Overview

`shared/voms/` decodes the VOMS extension (OID `1.3.6.1.4.1.8005.100.100.5`)
of an X.509 proxy into per-VO entries — VO name, VOMS server URI, FQANs,
generic attributes, validity window, issuer DNs — and verifies every entry
the way the HEP `libvomsapi` did, without that library.  It is plain C over
OpenSSL >= 3.0 with no nginx types, no logging and no global state, so the
same objects are linked into the nginx module (`src/auth/voms/extract.c`)
and into the native client.  Nothing here allocates from nginx pools; every
function is safe to call from any thread with distinct arguments.

The wire formats are RFC 5755 attribute certificates and the VOMS extension
exactly as `voms-proxy-init` / `libvoms` encode it:
`AC_SEQ ::= SEQUENCE { SEQUENCE OF AttributeCertificate }`.

## Files

| File | Responsibility |
|------|----------------|
| `voms_ac.h` | **Public API** — read it first.  `brix_voms_retrieve()` (decode + verify, the entry point for the module and the client), `brix_voms_find_extension()`, `brix_voms_decode()`, `brix_voms_verify()`, `brix_voms_result_free()`, `brix_voms_find_eec()`, `brix_voms_strerror()`, `brix_voms_dn_oneline()`; the types `brix_voms_entry_t`, `brix_voms_result_t`, `brix_voms_trust_t` and the `brix_voms_status_t` error codes. |
| `voms_asn1.h` / `voms_asn1.c` | OpenSSL ASN.1 templates for the AC, its holder / issuer / attribute structures and the VOMS-specific extensions (server certificate chain `…100.100.10`, generic attributes `…100.100.11`).  Private: a strict DER decoder that rejects anything the templates do not describe. |
| `voms_decode.c` | `brix_voms_decode()` — AC_SEQ DER → `brix_voms_result_t` with one entry per AC: VO and URI from the FQAN policy authority, FQANs, generic attributes, validity, holder / issuer / issuer-CA DNs in OpenSSL one-line form.  No verification; every entry's `verdict` starts non-OK. |
| `voms_verify.c` | `brix_voms_verify()` — the ordered checks below, one typed error per failure, recorded per entry. |
| `voms_lsc.h` / `voms_lsc.c` | `brix_voms_lsc_match()` — does `vomsdir/<vo>/` name the signer chain? `.lsc` files and the legacy certificate layout; `brix_voms_dn_line_matches()` accepts both the OpenSSL one-line and the RFC 2253 DN forms. |
| `voms_ac_fixture.h` | A **genuine** LHCb VOMS extension (DER, two FQANs) captured from a real `voms-proxy-init` against `lhcb-auth.cern.ch`; the signing server certificate is embedded, so the unit suite verifies a real VOMS signature. |
| `voms_ac_unittest.c` | The C unit suite: success, error and security-negative pins over the fixture. |

## Verification order

`brix_voms_retrieve(leaf, chain, trust, &out)` first locates the extension
(the leaf, then each certificate of the chain, leaf-first) and the
end-entity certificate (`brix_voms_find_eec`: the first non-proxy
certificate walking up from the leaf), decodes the AC_SEQ, then runs the
checks below on **every** entry.  Each entry keeps its own `verdict`; the
call returns `BRIX_VOMS_OK` when at least one entry verified, else the first
failure.

| # | Check | Failure |
|---|-------|---------|
| 1 | AC version is 2 | `BRIX_VOMS_ERR_VERSION` |
| 2 | Holder binding: `baseCertificateID` names the end-entity certificate (subject-or-issuer name + serial) | `BRIX_VOMS_ERR_HOLDER` |
| 3 | Validity window at `trust->now` (0 = wall clock); `skew_seconds` tolerates a `notBefore` in the near future only — an expired AC is never tolerated | `BRIX_VOMS_ERR_NOTYET` / `BRIX_VOMS_ERR_EXPIRED` |
| 4 | An embedded VOMS server certificate is present | `BRIX_VOMS_ERR_NOSIGNER` |
| 5 | Signature algorithm: inner (TBS) equals outer, and no MD5-class digest | `BRIX_VOMS_ERR_SIGALG` |
| 6 | Signature verifies over the original TBS bytes with the server certificate's key | `BRIX_VOMS_ERR_SIGNATURE` |
| 7 | AC issuer name equals the server certificate's subject | `BRIX_VOMS_ERR_ISSUER` |
| 8 | AC targets (if any) include this host | `BRIX_VOMS_ERR_TARGET` |
| 9 | Server certificate chain against `trust->store` — skipped when `store` is NULL (client diagnostics only; the module always supplies the `brix_voms_cert_dir` store) | `BRIX_VOMS_ERR_UNTRUSTED` |
| 10 | `vomsdir/<vo>/` names the signer (next section) — skipped when `trust->vomsdir` is NULL | `BRIX_VOMS_ERR_LSC` |

Other codes: `BRIX_VOMS_ERR_NOEXT` (no extension anywhere in the chain — a
plain grid proxy, not an error for callers), `BRIX_VOMS_ERR_DECODE` (the
extension is not a valid AC_SEQ), `BRIX_VOMS_ERR_ATTRS` (no usable FQAN),
`BRIX_VOMS_ERR_NOMEM`, `BRIX_VOMS_ERR_ARGS`.  `brix_voms_strerror()` renders
any of them.

## vomsdir semantics (`.lsc` and legacy layouts)

`brix_voms_lsc_match(vomsdir, vo, signer_chain)` looks in `vomsdir/<vo>/`:

- **LSC files** — every `vomsdir/<vo>/<host>.lsc` holds DN lines, subject
  then issuer, describing the server chain from the signer upwards; blank
  lines and `#` comments are ignored.  The entry matches when each pair
  equals the corresponding chain certificate (for the usual one-certificate
  chain: the signer's subject DN and its issuer DN).  Lines may be in
  OpenSSL one-line form (`/DC=ch/DC=cern/OU=computers/CN=voms.cern.ch`) or
  RFC 2253 form.
- **Legacy certificates** — failing every LSC, a PEM certificate in
  `vomsdir/<vo>/` or in `vomsdir/` itself that is byte-for-byte the signer
  certificate also matches (the pre-LSC vomsdir convention).
- A VO name that could escape the directory (`../lhcb`, `lhcb/../lhcb`,
  any `/` or `\`) never matches; an unreadable vomsdir never matches.

## Corner cases the engine handles

Every shape below is pinned by `tests/test_voms_corner_cases.py` (crafted with
`utils/voms_proxy_fake.py` and checked through the harness described next)
or by the C unit suite.

| Shape | Behaviour |
| --- | --- |
| AC on a parent proxy (a plain `grid-proxy-init` over a `voms-proxy-init` proxy) | Every certificate in the chain that carries the extension is read; `carrier` on each entry says which. |
| Legacy GT2 proxies (`CN=proxy` / `CN=limited proxy`, no proxyCertInfo) | Recognised as proxies by shape (subject = issuer + one CN), so the end-entity certificate is still found and the holder still binds. |
| Chain handed over CA-first or leaf-first | The end-entity walk follows issuer links; order is irrelevant. |
| Holder named with a different string encoding (UTF8String vs PrintableString) | `X509_NAME_cmp` compares canonical forms, so they match. |
| Holder naming the proxy instead of the end-entity certificate | Accepted: any certificate on the carrier-to-EEC path may be named, never a CA. |
| `entityName` or `objectDigestInfo` holders | Rejected (`holder`): VOMS only ever issues `baseCertificateID`. |
| Multi-VO proxy with one bad AC | Each AC has its own verdict; the proxy verifies if any AC does, and only verified ACs grant a VO. |
| Signer not first in the certs extension, or intermediate CAs embedded | The signer is the embedded certificate whose subject is the AC issuer name; the rest are untrusted intermediates for the chain check and the LSC pairs. |
| AC issuer names a certificate that is not embedded | `issuer`. No certs extension at all: `nosigner`. |
| authorityKeyIdentifier on the AC | Must equal the signer's subjectKeyIdentifier when both exist (`issuer` otherwise). |
| RSA PKCS#1 v1.5 (SHA-1 through SHA-512), RSA-PSS, ECDSA, Ed25519 signers | All verify; the digest or scheme is reported per AC. MD2/MD4/MD5: `sigalg`. Inner and outer algorithm identifiers must agree: `sigalg`. |
| Unknown critical AC extension | `extension`. Unknown non-critical extensions are ignored. |
| policyAuthority absent, or `vo://host` without a port | The VO comes from the first FQAN component; the URI is whatever was given. |
| FQAN values as UTF8String | Accepted like OCTET STRING. |
| Malformed FQAN (no leading `/`, control or non-ASCII bytes, `,`) | Dropped; an AC left with no FQAN is `attrs`. Dotted VO names and hyphenated roles are fine. |
| Empty AC sequence, or more than 32 ACs | `decode` (a hard cap against inflated proxies). |
| Targets extension | Present and naming this host (dNSName or URI, case-insensitive): ok; present and not: `target`. |
| Expired or revoked VOMS server certificate inside the AC's validity | `untrusted` (the chain is checked at the current time, CRLs in try mode). |
| LSC variants | Several `.lsc` per VO directory; 4-line files for chained signers; CRLF, trailing spaces, `#` comments; OpenSSL one-line or RFC 2253 DNs; legacy PEM copies of the signer. |
| VO name with `/` or `..` | Never touches the filesystem (`lsc`). |

## The verdict harness

`voms_ac_check.c` is a standalone program over the engine — the tool behind the
corner-case matrix and a useful operator diagnostic:

```
voms_ac_check [--certdir DIR] [--vomsdir DIR] [--now EPOCH] [--skew SECONDS] proxy.pem
```

It prints `status: <token>` and, per AC, `ac[i]: vo=… verdict=… uri=… digest=…
fqans=… carrier=…` followed by `fqan:` and `attr:` lines, and exits 0 only when
the proxy verified. Without `--certdir` the chain check is skipped and without
`--vomsdir` the LSC check is skipped (what `xrddiag` prints for a credential
when no trust directories are configured). Build it with the same line as the
unit suite, substituting `voms_ac_check.c` for `voms_ac_unittest.c`.

## Running the unit suite

From the repository root (the header of `voms_ac_unittest.c` carries the
same line):

```bash
cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -I shared \
   shared/voms/voms_ac_unittest.c shared/voms/voms_asn1.c \
   shared/voms/voms_decode.c shared/voms/voms_verify.c shared/voms/voms_lsc.c \
   -lcrypto -o /tmp/voms_ut && /tmp/voms_ut
```

On macOS with Homebrew OpenSSL add
`-I/usr/local/opt/openssl@3/include -L/usr/local/opt/openssl@3/lib`.
Exit 0 and the line `all checks passed` mean every pin holds.  The Python
tier wraps the same build in `tests/test_voms_native_ac_unit.py`, and
`tests/test_voms_native_ac.py` drives a live `brix_require_vo` server with
good and deliberately bad proxies (`utils/voms_proxy_fake.py -ac-hours`,
`-holder-serial`, a signer not named in any LSC).

What the suite pins over the LHCb fixture: decode (VO `lhcb`, the two
FQANs, issuer `CN=lhcb-auth.cern.ch`), the **genuine signature verifying**
inside the AC's validity window, expired / not-yet-valid windows, the holder
binding with a wrong serial, a tampered signature byte, an empty trust store
(`ERR_UNTRUSTED`), the LSC states (none, wrong server, the real pair) and the
path-escape guard, truncated and junk DER, and retrieval from a certificate
that carries the extension but is not the holder (decodes, then fails the
binding — never silently accepted).

## Fixture provenance

`voms_ac_fixture.h` is real VOMS output — the extension bytes of an LHCb
proxy issued by `lhcb-auth.cern.ch` (AC valid 2026-08-03 .. 2026-08-10, so
the suite pins its clock inside that window with `trust->now`).  The user's
end-entity certificate is not part of the fixture; the suite rebuilds a
stand-in with the AC's own holder name and serial.  Do not regenerate the
fixture with the fake tool: its value is that the signature was produced by
the production VOMS server code.
