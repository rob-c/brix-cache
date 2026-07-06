# signing_policy / EACL namespace enforcement — conformance

## Normative basis

The Globus/IGTF **signing_policy** (EACL, "Extended Access Control List") file is
the mechanism by which a WLCG/EGI trust anchor is confined to a *namespace*: a
trusted CA is permitted to sign end-entity subject DNs only inside its delegated
subtree. This closes a gap that plain PKIX chain validation (RFC 5280 §6) leaves
open — a technically-valid signature from a trusted-but-misbehaving (or
compromised) CA over a DN outside its remit is accepted by OpenSSL yet must be
rejected under the grid trust model. The governing artefacts:

- **Globus EACL grammar** — the `.signing_policy` file: one or more
  `access_id_CA X509 '<DN>'` blocks, each carrying `pos_rights`/`neg_rights`
  (`globus CA:sign`) and a `cond_subjects globus <glob-list>` clause. The glob
  list constrains which subject DNs the named CA may sign.
- **IGTF hashed-store discovery** — the policy file for a CA is found in the CA
  directory as `<subject-hash>.signing_policy`, keyed by the OpenSSL subject
  name hash (new SHA-1 form, and legacy MD5 form for back-compat), the same
  discovery scheme as `<hash>.0` CA certs and `<hash>.r0` CRLs.
- **IGTF authentication profile** — trust must fail *closed*: an unreadable,
  malformed, or wrong-CA policy file is a rejection, not a silent pass.
- **RFC 5280 §4.1.2.6 / OpenSSL `X509_NAME_oneline`** — the subject DN match
  surface: the slash-form rendering (`/DC=a/DC=b/CN=c`) with `\/` and `\xNN`
  escaping. Encoding-independent DN equality (RFC 5280 §7.1) is *not* part of
  this match surface (see the DN-encoding limitation below).

**Headline finding.** The official XRootD v6.1.0 GSI stack does **not parse or
enforce signing_policy at all** — there is zero support for the EACL grammar,
zero namespace confinement, anywhere in the tree. Our module implements the
feature end-to-end (parser → per-CA table → chain-walk enforcement) and is
therefore categorically stricter on every requirement in this component. This is
verifiable: `grep -rln 'signing_policy\|cond_subjects\|access_id_CA\|EACL' src/`
over `/tmp/xrootd-src` returns **no matches**. XRootD's `GetCA()`
(`/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc:4661`) loads only
`<cahash>.0` (via `GetCApath`, `:4473`) and the matching CRL — it never opens a
`.signing_policy` file. Its only DN-driven policy is the gridmap
(`XrdSecgsiGMAPFunDN.cc`), which is a DN→username *mapping*, not an
authorization namespace.

---

### EACL grammar parsing (Globus `access_id_CA` / `pos_rights` / `neg_rights` / `cond_subjects`)

- **Requirement:** A `.signing_policy` file is a sequence of `access_id_CA X509
  '<CA-DN>'` blocks; each block's granting is asserted by `pos_rights globus
  CA:sign` (and revoked by `neg_rights`); the permitted subject DNs are the
  glob list in `cond_subjects globus <list>`. Comments (`#`), blank lines,
  indentation, tabs, and CRLF must be tolerated; rights/conditions appearing
  before any `access_id_CA` are a grammar error.
- **Ours:** Full recursive-descent line parser. `access_id_CA` opens a block and
  captures the quoted DN (`src/auth/crypto/signing_policy.c:299`,
  `sp_handle_access_id` at `:252`); `pos_rights`/`neg_rights` set the block
  `granted`/`denied` flags (`:303`, `:312`) and are rejected with a
  "before access_id_CA" error when no block is open (`:304`, `:313`);
  `cond_subjects` skips the auth-scope token (`globus`) and parses the glob
  region (`:321`). Comments/blank lines are skipped (`:292`), CRLF is normalized
  per line (`signing_policy.c:365`), leading whitespace/tabs are consumed by
  `sp_skip_space` (`:58`), and any unknown directive is a hard parse failure
  (`:337`). `neg_rights` blocks are skipped at match time so a denied block
  never grants (`brix_sp_subject_allowed`, `:429`).
- **XRootD v6.1.0:** No grammar exists to conform to — the EACL file is never
  read. Its nearest analogue, the gridmap parser
  (`/tmp/xrootd-src/src/XrdSecgsi/XrdSecgsiGMAPFunDN.cc:90`, `FindMatchingCondition`),
  matches a DN against `contains/begins/ends/full` conditions to select a
  *username*, with no CA-scoping and no `CA:sign` concept.
- **Verdict:** Stricter-than-XRootD (feature absent upstream). Pinned by
  SPL-025..SPL-042 (grammar/quoting/block structure: bare/single/double quotes,
  rights-before-id, cond-before-id, unknown directive, comments/CRLF/indent/tabs,
  multi-block OR semantics).

### Glob semantics (`*` crosses `/`, `?` = one char, case-insensitive, both-ends anchored)

- **Requirement:** Globus cond_subjects globs are *not* fnmatch/PATHNAME:
  `*` matches any run of characters **including `/`**, `?` matches exactly one
  character (including `/`), matching is case-insensitive, and the pattern is
  anchored at both ends (a prefix without a trailing `*` does not match a longer
  DN).
- **Ours:** `brix_sp_glob_match` (`src/auth/crypto/signing_policy.c:95`) is a
  backtracking matcher: `*` (`:107`) sets a resume point and greedily absorbs
  any byte including `/`; `?` (`:102`) consumes exactly one byte with no `/`
  exclusion; comparison folds case via `tolower()` on both sides (`:103`); the
  tail loop requires the whole pattern be consumed (`:117`), enforcing the
  right-anchor, and the left-anchor is implicit (matching starts at index 0).
- **XRootD v6.1.0:** No glob engine for signing namespaces. (The gridmap
  `matches()` at `XrdSecgsiGMAPFunDN.cc:106` is `XrdOucString::matches`, used for
  username selection, not CA-namespace authorization.)
- **Verdict:** Stricter-than-XRootD (feature absent upstream). Pinned by
  SPL-001..SPL-024 and SPL-082..SPL-100 — notably SPL-002/SPL-088 (`*` crossing
  `/`), SPL-013/SPL-092 (`?` matching `/`), SPL-006/SPL-081 (both-ends anchor),
  SPL-014/SPL-015/SPL-086 (case-fold), SPL-100 (a bare `*` is an all-permit —
  documented deployment foot-gun, matched honestly).

### Hashed-store discovery (`<hash>.signing_policy`, new + legacy hash, DN fallback)

- **Requirement:** The policy for a CA is located in the CA directory as
  `<subject-hash>.signing_policy`, using the OpenSSL new (SHA-1) subject hash,
  with the legacy (MD5) hash accepted for older trust bundles.
- **Ours:** `brix_sp_table_build` (`src/auth/crypto/store_policy.c:142`) scans
  the CA dir for `*.signing_policy` files (`:175`), parses each, and records the
  hex stem as the entry hash (`:185`). At check time `sp_find_by_hash`
  (`:235`) matches a CA against both `X509_subject_name_hash` (new) and
  `X509_subject_name_hash_old` (legacy) (`:238`). A DN fallback,
  `sp_find_by_dn` (`:255`), binds an oddly-named file whose `access_id_CA` block
  nonetheless names this CA's DN.
- **XRootD v6.1.0:** Discovers `<cahash>.0` (CA cert) and CRLs by hash in
  `GetCApath` (`/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc:4473`) but
  never a `.signing_policy` file — `GetCA` (`:4661`) reads only the cert +
  CRL.
- **Verdict:** Stricter-than-XRootD (feature absent upstream). Pinned by
  SPL-053..SPL-056 (new-hash-only, old-hash-only, both-hash, DN fallback).

### Fail-closed on malformed / unreadable / wrong-CA policy

- **Requirement (IGTF profile):** A policy file that is present but unusable —
  malformed grammar, unreadable, or naming a different CA than the one whose
  hash it is filed under — must cause the CA to be *rejected*, never silently
  treated as unconstrained.
- **Ours:** `brix_sp_parse` returns `NULL` on any malformed input
  (`signing_policy.c:370`, fail-closed by contract, header `:11`); the table
  build records that as `malformed` (`store_policy.c:196`) and also marks an
  unreadable file malformed (`:189`). `brix_sp_table_check` returns 0 (reject)
  when the entry is malformed (`store_policy.c:292`) and when the discovered
  file does not actually name this CA's DN (`:296`). An empty/whitespace-only
  `cond_subjects` yields zero globs, so the subject can never match (grants
  nothing — `sp_parse_cond_subjects` `:247`).
- **XRootD v6.1.0:** N/A — no policy file is read, so there is nothing to fail
  closed on. A CA that signs outside any namespace is silently accepted once its
  cert chain and CRL verify.
- **Verdict:** Stricter-than-XRootD (feature absent upstream). Pinned by
  SPL-029..SPL-035 (empty/no-value/unknown-directive/truncated/mis-ordered
  → reject), SPL-057/SPL-064 (wrong-CA block rejected under ON and REQUIRE),
  SPL-071/SPL-075/SPL-103 (malformed and whitespace-only → reject).

### Enforcement modes (off / on / require)

- **Requirement:** Deployments need a graduated policy: ignore signing_policy
  entirely; enforce it where a file is present but tolerate CAs without one; or
  mandate that *every* trust anchor carry a granting policy (strict IGTF).
- **Ours:** `brix_sp_mode_t { OFF, ON, REQUIRE }`
  (`src/auth/crypto/signing_policy.h:20`). `brix_sp_table_check`
  (`store_policy.c:268`) short-circuits to accept under OFF (`:276`); with no
  policy file for the CA it accepts under ON but rejects under REQUIRE
  (`:289`); a present policy is always matched (`:301`). REQUIRE additionally
  demands a hashed CA directory (not a flat bundle) at configure time
  (`brix_store_configure`, `:623`). The mode is carried on the `X509_STORE`
  ex_data (`brix_store_policy_attach`, `:672`) and read back during the chain
  walk (`brix_store_policy_mode`, `:720`).
- **XRootD v6.1.0:** No equivalent axis. Its GSI strictness knobs
  (`XrdSecgsiOpts.hh`) govern *CRL* handling (crlIgnore/crlTry/crlUse/crlRequire)
  and CA verification, never a signing namespace.
- **Verdict:** Stricter-than-XRootD (feature absent upstream). Pinned by the
  mode matrix SPL-058..SPL-076 (present/absent/malformed × off/on/require) —
  e.g. SPL-059/SPL-076 (REQUIRE rejects absent), SPL-065..SPL-068 (OFF ignores
  even out-of-namespace and malformed policy).

### Chain-walk placement (per-link CA check, proxies exempt)

- **Requirement:** Namespace confinement applies to each *CA→subject* signing
  link in the verified chain; a proxy certificate's issuer is its EEC/parent
  proxy (not a trust anchor), so proxy links are outside signing_policy's scope.
- **Ours:** Enforcement runs only *after* `X509_verify_cert` succeeds, over the
  built chain. `brix_gsi_enforce_signing_policy`
  (`src/auth/crypto/gsi_verify.c:63`) walks `leaf..root` and for each non-proxy
  subject (`EXFLAG_PROXY` skipped, `:85`) asks `brix_sp_table_check(table, mode,
  issuer, subject)` whether the issuer may sign it (`:89`), rejecting on the
  first violation. It is wired into the single shared verifier alongside proxy
  monotonicity and per-cert policy (`brix_gsi_verify_chain`, `:217`), so both the
  `root://` GSI path and the `davs://` WebDAV client-cert path
  (`src/protocols/webdav/auth_cert.c`) enforce it identically.
- **XRootD v6.1.0:** `XrdCryptogsiX509Chain::Verify`
  (`/tmp/xrootd-src/src/XrdCrypto/XrdCryptogsiX509Chain.cc:45`) walks
  CA→sub-CA→EEC→proxy validating signatures, validity, and proxyCertInfo, but
  performs **no namespace check** at any link — there is no policy table to
  consult.
- **Verdict:** Stricter-than-XRootD (feature absent upstream). Exercised across
  the whole SPL family (every clause drives a real chain through
  `brix_gsi_verify_chain` on the `davs` surface).

### DN match surface + encoding-normalization limitation

- **Requirement:** cond_subjects globs are matched against the subject DN. The
  IGTF/Globus tooling matches the `X509_NAME_oneline` slash rendering; RFC 5280
  §7.1 additionally defines encoding-independent name equality (a UTF8String and
  a BMPString of the same characters are the *same* name).
- **Ours:** The match surface is the OpenSSL oneline slash form via
  `brix_x509_oneline` → `X509_NAME_oneline` (`store_policy.c:48`, called for CA
  and subject at `:280`/`:300`), compared case-insensitively by the glob
  matcher. This means `\/` and `\xNN` escaping is part of the surface (an
  embedded `/` renders `\/`; non-ASCII bytes render `\xNN`) and a glob must be
  written against the *rendered* bytes. Encoding-independent DN equality
  (RFC 5280 §7.1) and RFC 4518 insignificant-space folding are **not**
  implemented — the match is against the literal rendering.
- **XRootD v6.1.0:** Uses the same raw-string philosophy — DN comparison is a
  byte `strcmp` with no encoding normalization
  (`/tmp/xrootd-src/src/XrdCrypto/XrdCryptoX509Chain.cc`, DN rendered via
  `X509_NAME_print_ex`/oneline in `XrdCryptosslAux.cc`). Neither implementation
  canonicalizes across ASN.1 string types.
- **Verdict:** Documented-limitation (shared with XRootD). The escaping surface
  is pinned positively by SPL-043..SPL-052 (UTF8String/PrintableString ASCII
  match, `\xNN` under `*`, `\/` and `\+` escaping, literal `*` in a value) and
  RDN-order sensitivity by SPL-050/SPL-051. The normalization gap is registered
  in `tests/clauses/_decisions.py` under DNE-003 / DNE-005 / DNE-006 (BMPString /
  UniversalString / VisibleString vs UTF8String → reject, category **LIMITATION**,
  "Shared with XRootD (raw match)") and DNE-028 (RFC 4518 space folding). The
  operational guidance is to use a consistent DN encoding across the trust store.

---

## Divergence summary

| Aspect | Ours | XRootD v6.1.0 | Verdict | Tests |
|---|---|---|---|---|
| signing_policy / EACL enforcement at all | Full parser + per-CA table + chain-walk enforcement (`signing_policy.c`, `store_policy.c`, `gsi_verify.c:63`) | **Not implemented** — zero grep matches; `GetCA` loads only `<hash>.0`+CRL (`XrdSecProtocolgsi.cc:4661`) | Stricter-than-XRootD | SPL-001..SPL-104 |
| EACL grammar (blocks/rights/cond_subjects, comments/CRLF/tabs/order) | Parsed, mis-ordered directives = fail-closed (`signing_policy.c:299,304,337`) | Absent | Stricter-than-XRootD | SPL-025..SPL-042 |
| Glob semantics (`*` crosses `/`, `?`=1 char incl `/`, case-fold, both-ends anchored) | `brix_sp_glob_match` (`signing_policy.c:95`) | Absent | Stricter-than-XRootD | SPL-001..SPL-024, SPL-082..SPL-100 |
| Hashed discovery (new+legacy subject hash, DN fallback) | `sp_find_by_hash`/`sp_find_by_dn` (`store_policy.c:235,255`) | Only `<hash>.0`+CRL (`:4473`) | Stricter-than-XRootD | SPL-053..SPL-056 |
| Fail-closed (malformed / unreadable / wrong-CA / empty cond) | Reject (`store_policy.c:292,296`; `signing_policy.c:247,370`) | N/A — CA accepted with no namespace | Stricter-than-XRootD | SPL-029..SPL-035, SPL-057, SPL-064, SPL-071, SPL-075, SPL-103 |
| Modes off/on/require | `brix_sp_mode_t`; REQUIRE mandates policy per CA (`store_policy.c:289,623`) | No namespace-strictness axis (only CRL levels) | Stricter-than-XRootD | SPL-058..SPL-076 |
| Proxy links exempt, per-link CA check post-verify | Chain walk skips `EXFLAG_PROXY` (`gsi_verify.c:85`) | Chain verify has no namespace step (`XrdCryptogsiX509Chain.cc:45`) | Stricter-than-XRootD | SPL-* (whole family) |
| DN match surface + encoding normalization | oneline slash form, case-insensitive; no cross-encoding equality (`store_policy.c:48,300`) | Raw byte `strcmp`, no normalization | Documented-limitation (shared) | SPL-043..SPL-052; DNE-003/005/006/028 |
