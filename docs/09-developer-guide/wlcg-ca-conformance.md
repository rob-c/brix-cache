# WLCG X.509 / CA-Directory Conformance

This module implements the WLCG/IGTF CA-directory trust model on top of the
OpenSSL `X509_STORE`, adding the enforcement that plain PKIX validation does not
provide: Globus `signing_policy` namespace restriction, RFC 3820 limited-proxy
monotonicity, and an explicit CRL-strictness knob. This page documents the
directive semantics and how to run the conformance suite.

## Trust model as implemented

`brix_trusted_ca` (root://) / `brix_webdav_cadir` (davs://) point at a hashed CA
directory — the `/etc/grid-security/certificates` layout: `<hash>.0` CA certs,
`<hash>.r0` CRLs, `<hash>.signing_policy` EACL files. OpenSSL looks CAs up by the
**new** (SHA-1 canonical) subject hash; the legacy MD5 hash alone is not
sufficient for lookup (WLCG distributions ship both links).

The single shared verifier `brix_gsi_verify_chain()` (`src/auth/crypto/gsi_verify.c`)
runs after `X509_verify_cert()` succeeds and enforces two extra WLCG rules over
the verified chain:

1. **signing_policy** — for every non-proxy cert whose issuer is a trust-anchor
   CA, the subject DN must match that CA's `cond_subjects` globs. Proxy `CN=`
   suffixes are exempt (the policy binds the EEC and sub-CAs, never proxies).
2. **Proxy monotonicity** — a full proxy may not be issued beneath a limited
   proxy (RFC 3820 §3.8).

Both root:// GSI and davs:// client-cert auth share this verifier and the same
`X509_STORE`, so a fix or policy applies to both uniformly. The signing_policy
table and both modes travel on the store via `ex_data`, so the stream
CRL-reload timer and the WebDAV build-once path inherit enforcement without
extra plumbing.

## Directives

### `brix_signing_policy` / `brix_webdav_signing_policy` — `on` | `off` | `require`

Default **`on`**.

| Mode | `<hash>.signing_policy` present | absent |
|---|---|---|
| `on` | enforced | chain validation only (pass-through) |
| `require` | enforced | CA rejected |
| `off` | ignored | ignored |

Fail-closed cases (rejected in `on` and `require`): a malformed/unreadable
policy file, or a policy file that names a different CA than the one presenting.
`require` with a bundle *file* trust store (no directory to search) is a
configuration error — `nginx -t` fails.

Supported EACL grammar (the IGTF subset):

```
# comment
access_id_CA    X509    '/DC=.../CN=Some CA'
pos_rights      globus  CA:sign
cond_subjects   globus  '"/DC=.../*" "/DC=.../CN=host/*"'
```

`*` matches any run of characters including `/`; `?` matches one; matching is
case-insensitive on the OpenSSL oneline slash DN. `neg_rights` blocks grant
nothing. Both single-quoted glob lists and a lone bare/double-quoted glob are
accepted.

### `brix_crl_mode` / `brix_webdav_crl_mode` — `off` | `try` | `require`

Default **`try`**.

| Mode | Behaviour |
|---|---|
| `off` | CRL verify flags never set (CRLs still load for `/healthz` audit) |
| `try` | revocation enforced where a CRL exists; a CA with none passes; an **expired** CRL is still fatal (staleness is evidence, not absence) |
| `require` | a missing / expired / unverifiable CRL is fatal |

> **Migration note.** `try` is a deliberate change from the earlier implicit
> rule ("any CRL loaded ⇒ required for all CAs"). Sites that want the old
> effective strictness should set `brix_crl_mode require`. A CRL path
> (`brix_crl` / `brix_webdav_crl`) must be configured for `require` to have
> anything to check.

## Running the suite

Three layers, all driven by the same fixture forge (`tests/x509forge.py`) whose
`manifest.json` is the single source of truth for expected verdicts:

```bash
# C unit — ngx-free grammar/matcher (SP-*)
bash tests/c/run_signing_policy_tests.sh          # 17 checks

# C conformance — decisions, chain building, CRL, proxy monotonicity
bash tests/c/run_x509_conformance_tests.sh        # 21 checks

# C unit — VO-name sanitization (VMS-*)
bash tests/c/run_vo_token_tests.sh                # 13 checks

# pytest e2e on the davs:// wire (marker: x509conf, also slow)
TEST_OWN_FLEET=1 pytest tests/test_wlcg_conformance_*.py -p no:xdist
#   SP (7) · CRL (5) · CAD (6) · PX (2) · RT (3)

# Differential vs stock XRootD (opt-in; skip-clean without the flag)
TEST_X509_DIFF=1 tests/run_x509_differential.sh
```

The differential runner asserts our verdict equals the spec verdict for every
scenario and *records* stock-XRootD divergences — without failing on them —
into [`../10-reference/wlcg-x509-differential-findings.md`](../10-reference/wlcg-x509-differential-findings.md).
Regenerate that report by re-running the differential; review it like a golden
file.

## The scaled clause-indexed suite (500+ cases)

A second, much larger suite indexes every case to a specific normative clause
(RFC 5280 / RFC 3820 / RFC 5755 / IGTF / Globus EACL).  It is driven by the
same forge, now table-driven: each `tests/clauses/<family>.py` registers
`Clause` rows (families CHN/PXY/SPL/CRL/CAD/DNE ≈ 530 rows), aggregated in
`tests/clauses/__init__.py` as `ALL_CLAUSES` and materialised by
`x509forge.build_all()` into one big multi-CA directory + a manifest.

```bash
# C oracle — replays the whole manifest through the REAL trust cores
# (signing_policy.c + store_policy.c via brix_store_configure), fast bulk check
bash tests/c/run_x509_oracle.sh                    # ~558 checks, 0 failures

# Live davs wire — every davs case against the fixed ConformanceFleet
# (one server per config-group on the shared CA dir, stood up once)
BRIX_X509_MATRIX=/tmp/x509matrix \
  PYTHONPATH=tests python3 -c "import clauses,x509forge,pathlib; \
  x509forge.build_all(pathlib.Path('/tmp/x509matrix'), clauses.ALL_CLAUSES)"
BRIX_X509_MATRIX=/tmp/x509matrix pytest tests/test_wlcg_conformance_matrix.py

# Matrix differential vs stock XRootD (XrdHttp) — records divergences
TEST_X509_DIFF=1 tests/run_x509_matrix_differential.sh
```

The oracle replicates the exact store configuration production uses (including
nginx's TLS-layer `SSL_CLIENT` purpose), so **oracle verdict == live wire
verdict == manifest** for every case.  Deliberate verdict corrections (places
our behaviour is stricter, more conservative, or a documented limitation) live
in one auditable register, `tests/clauses/_decisions.py`, which is cited by the
[source-level conformance write-up](../10-reference/conformance/README.md).

## Scope notes

- **davs:// is the e2e surface.** WebDAV x509 auth exercises the exact shared
  verifier where signing_policy/CRL enforcement lives, and is driven with
  `curl -k --cert`. It refuses proxy chains by design, so limited-proxy
  monotonicity is proven at the C level (`brix_proxy_chain_ok`, PX-C01..05)
  against the same forged proxy chains the wire would see.
- **VOMS AC** extraction/validation stays with `libvomsapi` on the root:// GSI
  path (`tests/test_webdav_voms.py`); this effort adds hostile-VO-name
  sanitization coverage (`vo_token.h`, VMS-01..13).
