# DN handling & string encoding — conformance

Scope: how the module renders an X.509 `Name` to a canonical string, how it
compares that string against a Globus `signing_policy` namespace, and how it
handles the ASN.1 string-CHOICE and byte-level content of RDN attribute values.
The DN matcher is exercised on both surfaces that run the GSI chain verifier:
`root://` GSI (stream) and `davs://` client certificates
(`src/protocols/webdav/auth_cert.c:478` → `brix_gsi_verify_chain`). The
per-cert byte sanitation gate runs for every certificate in the chain
(`src/auth/crypto/gsi_verify.c:124`).

All test IDs below carry the `DNE-` prefix and live in
`tests/clauses/dn_encoding.py`; deliberate verdict corrections are recorded in
`tests/clauses/_decisions.py` (the `OVERRIDES` table).

## Normative basis

- **RFC 5280 §4.1.2.4 / §4.1.2.6** — the `Name`/`RDNSequence` structure; an
  empty subject is legal only when a critical `subjectAltName` carries the
  identity; DirectoryString values are one of
  `{PrintableString, UTF8String, BMPString, UniversalString, TeletexString, …}`.
- **RFC 5280 §7.1** — **name matching is encoding independent**: two names are
  equal when their attribute values compare equal under the attribute's matching
  rule, *regardless of the ASN.1 string CHOICE used on the wire*.
- **RFC 4514** — the string form of a DN. `/`, `*`, `+`, `=`, `,` embedded in an
  attribute *value* are literal payload, not RDN/AVA delimiters and not
  wildcards.
- **RFC 4517 / RFC 4519** — `caseIgnoreMatch` (DirectoryString) and
  `caseIgnoreIA5Match` (`domainComponent`): matching is case-insensitive.
- **RFC 4518** — LDAP string-prep: insignificant-whitespace folding before
  comparison.
- **Globus EACL / `signing_policy`** — a CA namespace is expressed as an OpenSSL
  oneline glob (`/DC=a/DC=b/CN=...` with `*`) matched against the leaf subject.

## DN rendering / canonicalization (RFC 5280 §4.1.2.4)

- **Requirement:** a DN must be reduced to a stable canonical string for policy
  matching and logging; the rendering must not itself become a security seam
  (no injection of delimiters, no truncation).
- **Ours:** `brix_x509_oneline()` wraps `X509_NAME_oneline(name, NULL, 0)` into a
  bounded caller buffer (`src/auth/crypto/store_policy.c:49`, call
  `store_policy.c:60`). Every policy comparison and log line renders through this
  one function — CA DN and subject DN at `store_policy.c:280` and
  `store_policy.c:300`, leaf DN for the authenticated identity at
  `gsi_verify.c:228`. Output is the classic slash form
  `/DC=test/DC=x509conf/CN=Alice`, with non-ASCII/control octets escaped as
  `\xNN` by OpenSSL.
- **XRootD v6.1.0:** `XrdCryptosslNameOneLine()`
  (`/tmp/xrootd-src/src/XrdCrypto/XrdCryptosslAux.cc:736`). By **default**
  (no `USEX509NAMEONELINE`) it uses `X509_NAME_print_ex(mbio, nm, 0,
  XN_FLAG_SEP_MULTILINE)` and then rewrites the line separators to `/`
  (`XrdCryptosslAux.cc:742,748`); only when built with `USEX509NAMEONELINE` does
  it fall back to `X509_NAME_oneline` (`XrdCryptosslAux.cc:750`). The rendered
  string is cached on the cert as `Subject()`
  (`/tmp/xrootd-src/src/XrdCrypto/XrdCryptosslX509.cc:505`).
- **Verdict:** Conformant. Both reduce to a single canonical slash string; the
  renderers differ (our `X509_NAME_oneline` vs XRootD's default
  `X509_NAME_print_ex` multiline form), which is why byte-for-byte equivalence
  across implementations is *not* guaranteed — but each is internally consistent.
  DNE-001, DNE-002, DNE-004 (UTF8/Printable/T61 render to the identical
  `/DC=test/DC=x509conf/CN=Alice` and match the namespace).

## Encoding-independent equality (RFC 5280 §7.1) — documented limitation

- **Requirement:** the *same logical DN* encoded in a different ASN.1 string
  CHOICE (BMPString, UniversalString, VisibleString, …) must still compare equal
  to its `UTF8String`/`PrintableString` form.
- **Ours:** we do **not** implement §7.1 matching-rule equality. Comparison is a
  case-insensitive glob over the `X509_NAME_oneline` byte rendering
  (`brix_sp_glob_match`, `src/auth/crypto/signing_policy.c:96`;
  `brix_sp_subject_allowed`, `signing_policy.c:433`). Empirically, the same
  `CN=Alice` renders differently per CHOICE and is therefore not recognized as
  the same identity:
  - `UTF8String` / `PrintableString` / `T61String` → `.../CN=Alice` — match.
  - `BMPString` → `.../CN=\x00A\x00l\x00i\x00c\x00e`; the raw ASN.1 value
    contains inter-character NUL octets, so the byte-sanitation gate
    (`brix_dn_has_control_bytes`, `store_policy.c:385,395`) rejects the
    credential outright before any name comparison.
  - `UniversalString` (UTF-32) → `.../CN=\x00\x00\x00A...`; likewise rejected by
    the control-byte gate.
  - `VisibleString` → the certificate fails to load in OpenSSL at all
    (unusable credential → reject).
- **XRootD v6.1.0:** also does **not** implement §7.1 equality. Name linkage and
  gridmap lookup compare the rendered `Subject()`/`Issuer()` strings with raw
  `strcmp` (issuer↔subject chaining at
  `/tmp/xrootd-src/src/XrdCrypto/XrdCryptoX509Chain.cc:622`; subject search at
  `XrdCryptoX509Chain.cc:499`). No matching-rule normalization of the ASN.1
  CHOICE occurs. (XRootD's default `print_ex` renderer may decode some wide
  encodings to UTF-8, but the comparison is still string-vs-string, not
  value-matching-rule, and its GSI path performs no `signing_policy` namespace
  check at all — see `signing-policy.md`.)
- **Verdict:** Documented-limitation, shared with XRootD. Both compare rendered
  strings, not decoded values under the attribute matching rule. The failure
  mode is fail-safe (reject / non-match, never a false accept). Deployments must
  use a consistent DN encoding across `signing_policy` / gridmap and the issued
  certificates. Pinned: DNE-003 (BMPString), DNE-005 (UniversalString),
  DNE-006 (VisibleString) — all corrected to `reject` with the `LIMITATION`
  rationale in `_decisions.py:82-91`.

## RFC 4518 insignificant-space folding — documented limitation

- **Requirement:** DirectoryString matching folds insignificant whitespace
  (e.g. a trailing space) before comparison, so `CN=Alice ` equals `CN=Alice`.
- **Ours:** not implemented. `brix_sp_glob_match` compares character-for-
  character (case-folded but not space-folded), so a trailing space in the
  subject value defeats an exact policy glob
  (`signing_policy.c:96`). The parser only trims whitespace at token boundaries
  of the *policy file* (`sp_is_space`, `signing_policy.c:52`), never inside a DN
  value.
- **XRootD v6.1.0:** not implemented either — `strcmp` on the rendered subject
  (`XrdCryptoX509Chain.cc:622`) is byte-exact; no LDAP string-prep step exists.
- **Verdict:** Documented-limitation, shared with XRootD. Pinned: DNE-028
  (`_decisions.py:92`, corrected to `reject`, `LIMITATION`).

## Case-insensitive matching (RFC 4517 / RFC 4519)

- **Requirement:** `caseIgnoreMatch` (DirectoryString) and `caseIgnoreIA5Match`
  (`domainComponent`) make matching case-insensitive.
- **Ours:** the glob matcher lower-cases both pattern and subject byte-by-byte
  (`tolower((unsigned char)...)`, `signing_policy.c:103`), and CA-DN lookup uses
  `strcasecmp` (`signing_policy.c:409`, `signing_policy.c:426`). A
  `/DC=TEST/DC=X509CONF/...` subject therefore folds into a `/DC=test/...`
  namespace, and `CN=ALICE` matches a granted `CN=Alice`.
- **XRootD v6.1.0:** `strcmp` (`XrdCryptoX509Chain.cc:622`) is case-*sensitive*.
- **Verdict:** Conformant (and stricter-adherent than XRootD's byte compare for
  the ASCII case-fold rules). Pinned: DNE-026 (DC case fold), DNE-029 (CN case
  fold) — both `accept`, and *not* overridden in `_decisions.py` because our
  case-insensitive glob already satisfies them. A genuinely different domain is
  still rejected (DNE-027), and RDN order remains significant (DNE-030).

## Literal metacharacters, RDN structure (RFC 4514, RFC 5280 §4.1.2.6)

- **Requirement:** `/`, `*`, `+` inside an attribute *value* are literal payload;
  a subject `*` must never act as a wildcard against an exact policy; multivalued
  RDNs, duplicate RDNs and long DNs are legal; an empty subject requires a
  critical SAN.
- **Ours:** matching is anchored — `brix_sp_glob_match` consumes the entire
  subject string and only the policy-side `*` is a wildcard
  (`signing_policy.c:101-120`). An out-of-namespace leaf whose CN value literally
  spells `/DC=test/...` cannot smuggle in, because the anchored compare diverges
  at the first RDN (`/DC=evil` ≠ `/DC=test`). A subject value of the single
  character `*` is compared as data, never re-interpreted. RDN shape is whatever
  `X509_NAME_oneline` renders; the empty-subject / critical-SAN rule is enforced
  upstream in chain verification.
- **XRootD v6.1.0:** the subject value is likewise opaque payload inside the
  rendered `Subject()` string; XRootD performs no glob interpretation of subject
  values (its gridmap match is a straight `strcmp`,
  `XrdCryptoX509Chain.cc:499`), so metacharacters are inert there too.
- **Verdict:** Conformant. Pinned: DNE-011..DNE-015 (metacharacters),
  DNE-016..DNE-021 (RDN structure), DNE-022..DNE-025 (uncommon attribute types).

## DN control-byte / embedded-NUL rejection (RFC 5280 §4.1.2.6) — stricter than XRootD

- **Requirement:** RFC 5280 constrains DirectoryString content; an embedded NUL
  or raw control byte in a name value is a name-truncation / log-injection
  smuggling vector and must not be honored as a legitimate identity.
- **Ours:** `brix_dn_has_control_bytes()` walks every RDN's raw `ASN1_STRING`
  and rejects any octet `< 0x20` or `== 0x7f`
  (`src/auth/crypto/store_policy.c:385-401`). It is invoked over both the subject
  and issuer names inside `brix_cert_policy_violation()`
  (`store_policy.c:451-454`), which the chain verifier runs against **every**
  certificate in the chain (`gsi_verify.c:124`). This gate is what rejects an
  embedded NUL (`Al\x00ice`), a raw control byte (`Al\x07ice`), and — as a side
  effect — the NUL-laden BMPString/UniversalString wide encodings above.
- **XRootD v6.1.0:** has **no** such gate. A grep of `XrdCrypto/` and
  `XrdSecgsi/` finds no `iscntrl`/control-byte rejection over DN values; the one
  embedded-NUL guard in the codebase is on the SAN dNSName only
  (`/tmp/xrootd-src/src/XrdCrypto/XrdCryptosslX509.cc:1166`), not on RDN values.
  A control byte survives into `Subject()` (OpenSSL escapes it in the rendered
  string) and into the gridmap/name comparison.
- **Verdict:** Stricter-than-XRootD. We reject a control-byte or NUL-bearing DN
  that XRootD would carry through its name pipeline. Pinned: DNE-031 (embedded
  NUL), DNE-032 (embedded control byte).

## Divergence summary

| Aspect | Ours | XRootD v6.1.0 | Verdict | Tests |
|---|---|---|---|---|
| DN render | `X509_NAME_oneline` slash form (`store_policy.c:49`) | default `X509_NAME_print_ex` multiline → `/` (`XrdCryptosslAux.cc:742`) | Conformant (different renderer) | DNE-001,002,004 |
| §7.1 encoding-independent equality | not implemented; oneline-byte glob, wide encodings rejected by control gate (`signing_policy.c:433`, `store_policy.c:385`) | not implemented; `strcmp` on rendered `Subject()` (`XrdCryptoX509Chain.cc:622`) | Documented-limitation (shared) | DNE-003,005,006 |
| RFC 4518 space folding | not implemented (`signing_policy.c:96`) | not implemented (`strcmp`) | Documented-limitation (shared) | DNE-028 |
| caseIgnore (CN / DC) | case-insensitive glob + `strcasecmp` (`signing_policy.c:103,409`) | case-sensitive `strcmp` | Conformant (stricter-adherent) | DNE-026,027,029,030 |
| Literal `/ * +` in value; anchored match | anchored, policy-side `*` only (`signing_policy.c:101`) | opaque payload, straight `strcmp` (`XrdCryptoX509Chain.cc:499`) | Conformant | DNE-011..021 |
| Embedded NUL / control byte in DN | rejected for every cert (`store_policy.c:385`, `gsi_verify.c:124`) | not checked (only SAN dNSName, `XrdCryptosslX509.cc:1166`) | Stricter-than-XRootD | DNE-031,032 |
