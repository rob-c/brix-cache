# WLCG JWT Bearer Token — Normative Conformance Rule Catalog

Testable `MUST`/`MUST NOT`/`SHOULD` rules extracted from the authoritative
specs. Each maps to one or more conformance cases (a conforming token + a
violating token). `[SEC]` = security-critical. Cited by section. This is the
**oracle** for the RFC-conformance suite: where the module diverges from a
rule, the test asserts the rule.

Sources: RFC 7519 (JWT), RFC 7515 (JWS), RFC 7517/7518 (JWK/JWA), RFC 8725
(JWT BCP), RFC 9068 (`at+jwt`), RFC 6749 §3.3 (scope), RFC 6750 (Bearer),
[WLCG Common JWT Profile v1.0](https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md),
[SciTokens v2.0](https://scitokens.org/technical_docs/Claims).

## RFC 7519 — JWT
1. `[§2]` `exp`/`nbf`/`iat` MUST be a JSON **number**; a string value MUST be rejected.
2. `[§2]` NumericDate MAY be fractional (`1300819380.5`) — MUST accept.
3. `[§2]` NumericDate MAY be negative/large — parsing MUST NOT overflow/wrap.
4. `[§2]` `iss`/`sub`/`aud`-elements/`jti` are StringOrURI → MUST be JSON strings; non-string MUST reject.
5. `[§4.1.1]` `[SEC]` missing/`iss`-mismatch → reject when issuer required.
6. `[§4.1.2]` `sub` type MUST be validated as string.
7. `[§4.1.3]` `aud` MUST accept both a single string AND an array of strings.
8. `[§4.1.3]` `[SEC]` if `aud` present and our id not among values → reject.
9. `[§4.1.3]` `[SEC]` `aud` comparison MUST be case-sensitive equality (no substring/prefix).
10. `[§4.1.4]` `[SEC]` reject once now ≥ `exp` (small skew allowed).
11. `[§4.1.4]` `exp` in the future MUST NOT reject for expiry.
12. `[§4.1.5]` `[SEC]` MUST NOT accept before now ≥ `nbf`.
13. `[§4.1.6]` `iat` type MUST be validated.
14. `[§4.1.7]` `[SEC]` `jti` string; with replay protection, duplicate MUST reject.
15. `[§4]` optional-claim absence alone MUST NOT reject.
16. `[§4]` unknown/custom claims MUST be ignored (token still valid).
17. `[§5.1]` `typ` advisory unless a profile requires it.
18. `[§5.2]` `cty` for nested payloads; a bare JWT SHOULD NOT set `cty`.
19. `[§6.1/§7.2]` `[SEC]` `alg:"none"` empty-sig MUST be rejected by an integrity-requiring validator.
20. `[§7.2]` header & payload MUST each be valid UTF-8 JSON objects; malformed → reject.
21. `[§7.2]` `[SEC]` duplicate member names SHOULD reject.
22. `[§7.2-7]` `[SEC]` header `alg` MUST be among accepted algs for the key.
23. `[§7.1]` a signed JWT MUST have JWS compact structure.

## RFC 7515 — JWS
24. `[§7.1]` exactly three base64url segments (two dots); other counts → reject.
25. `[§2/§7]` `[SEC]` segments MUST be base64url **without padding**; `=`/`+`/`/` → reject.
26. `[§4.1.1]` `[SEC]` `alg` MUST be present; missing → reject.
27. `[§4.1.1]` `[SEC]` unrecognized/unexpected `alg` → reject (no auto-select).
28. `[§4.1.2]` `[SEC]` MUST NOT fetch/trust a key from `jku` unless pre-trusted (SSRF/key-injection).
29. `[§4.1.3]` `[SEC]` MUST NOT trust an embedded `jwk` unless it matches a pre-configured key.
30. `[§4.1.4]` `[SEC]` `kid` is untrusted input; unknown `kid` → reject (no key-guessing/traversal).
31. `[§4.1.5]` `[SEC]` MUST NOT fetch/trust `x5u` unless pre-trusted.
32. `[§4.1.6]` `[SEC]` `x5c` MUST validate to a trusted root; untrusted `x5c` alone MUST NOT be trusted.
33. `[§4.1.7/8]` `x5t`/`x5t#S256` thumbprints, if used for selection, MUST match.
34. `[§4.1.9]` `typ`, if present, MAY be profile-validated.
35. `[§4.1.10]` `cty` SHOULD be absent for non-nested JWS.
36. `[§4.1.11]` `[SEC]` unknown param listed in `crit` → MUST reject.
37. `[§4.1.11]` `[SEC]` `crit` MUST be a non-empty array of strings present in the header; empty/non-array/absent-name → reject.
38. `[§4.1.11]` `crit` MUST NOT list an RFC-defined param (e.g. `alg`) → reject.
39. `[§5.2]` `[SEC]` signature recomputed over `ASCII(b64u(hdr).b64u(pay))`; non-verifying → reject.
40. `[§5.2-6]` `[SEC]` key selected by recipient trust config, NOT header-embedded material.
41. `[§5.2]` `[SEC]` full-length/constant-time compare; truncated/empty sig → reject.
42. `[§10.6/10.10]` `[SEC]` alg allowlist bound to key type; no downgrade to `none`/weaker.

## RFC 7518 — JWA
43. `[§3.1]` `HS256` Required-to-implement.
44. `[§3.1]` `RS256` Recommended; `RS384`/`RS512` Optional.
45. `[§3.1]` `ES256` Recommended+; `ES384`/`ES512` Optional.
46. `[§3.1]` `PS256/384/512` Optional.
47. `[§3.1/3.6]` `[SEC]` `none` MUST be treated as forbidden for bearer verification.
48. `[§3.4]` `[SEC]` `ES256`↔P-256, `ES384`↔P-384, `ES512`↔P-521; curve/alg mismatch → reject.
49. `[§3.4]` `[SEC]` ECDSA sig is fixed-size R‖S (64/96/132B); DER/wrong-length → reject.
50. `[§3.3]` `[SEC]` RS*/PS* key MUST be ≥ 2048 bits; smaller → reject.
51. `[§3.2]` `[SEC]` HMAC key ≥ hash size.
52. `[§3.2]` `[SEC]` full constant-time MAC compare.
53. `[§3.5]` `PS*` binds MGF1/hash to the named alg.
54. `[§3.1]` `[SEC]` `alg` is case-sensitive; `rs256`≠`RS256`.
55. `[§3.6]` `[SEC]` `none` sig part MUST be empty; non-empty → reject.
56. `[§6.3.1]` RSA JWK MUST give `n`,`e`; EC JWK `crv`,`x`,`y` consistent with alg.

## RFC 8725 — JWT BCP (+ RFC 9068)
57. `[§2.1]` `[SEC]` signature MUST be verified before any claim is trusted.
58. `[§2.2/3.1]` `[SEC]` MUST NOT trust header `alg` blindly — algs from config/key metadata.
59. `[§3.2]` `[SEC]` `alg:none` MUST be rejected.
60. `[§2.2]` `[SEC]` RS↔HS key-confusion MUST be prevented (key type bound to alg family).
61. `[§3.1]` `[SEC]` alg allowlist; reject any off-list.
62. `[§3.2]` deprecated/weak algs SHOULD be disabled.
63. `[§3.3]` `[SEC]` no partial validation (header-only / skip-sig-when-key-absent).
64. `[§3.4]` `[SEC]` validate crypto inputs (invalid-curve points rejected).
65. `[§3.5]` `[SEC]` sufficient key entropy; no low-entropy HMAC secrets.
66. `[§3.7]` `[SEC]` process as UTF-8; conflicting encodings → reject.
67. `[§3.8]` `[SEC]` validate `iss` against expected; unexpected issuer → reject.
68. `[§3.9]` `[SEC]` validate audience; our id must be in `aud`.
69. `[§3.10]` `[SEC]` every relied-upon claim validated for presence+type.
70. `[§3.11]` `[SEC]` SHOULD require a distinguishing `typ` (e.g. `at+jwt`).
71. `[§3.12]` `[SEC]` different JWT kinds have mutually-exclusive validation.
72. `[§2.6]` `[SEC]` bind tokens to recipient/use via `aud`+`typ`.
73. `[§2.8]` `[SEC]` no dereference of header URLs (`jku`/`x5u`) — SSRF/DoS.
74. `[§3.1]` `[SEC]` validate `crit` per 7515 §4.1.11.
75. `[9068 §2.1]` `[SEC]` OAuth2 access-token `typ` MUST be `at+jwt`; else reject.
76. `[9068 §2.2]` access token MUST carry `iss`/`exp`/`aud`/`sub`/`client_id`/`iat`/`jti`.
77. `[9068 §4]` `[SEC]` RS validates sig/`iss`/`aud`/`exp` before access.
78. `[9068 §2.1]` `[SEC]` `alg` MUST be asymmetric; no `none`.

## RFC 6750 — Bearer Token Usage
79. `[§2]` `[SEC]` exactly one transport per request; multiple → `400 invalid_request`.
80. `[§2.1]` `Authorization: Bearer <token>` is RECOMMENDED.
81. `[§2.1]` `Bearer` scheme matched case-insensitively.
82. `[§2.1]` `b64token` charset `1*(ALPHA/DIGIT/-/./_/~/+//) *"="`; outside-set → malformed reject.
83. `[§2.2]` form-body `access_token` needs `x-www-form-urlencoded`, MUST NOT be `GET`.
84. `[§2.3]` `[SEC]` query method is NOT RECOMMENDED (leakage).
85. `[§2.3]` `[SEC]` query-method responses MUST include `Cache-Control: no-store`.
86. `[§2]` no credential on a protected resource → `401` + `WWW-Authenticate: Bearer`.
87. `[§3]` failed/absent token → `WWW-Authenticate: Bearer` (MAY add realm/error/error_description/scope).
88. `[§3]` `error`/`error_description`/`scope` are quoted-strings with a restricted charset.
89. `[§3.1]` `invalid_request` → HTTP **400**.
90. `[§3.1]` `[SEC]` `invalid_token` → HTTP **401** + `WWW-Authenticate`.
91. `[§3.1]` `[SEC]` `insufficient_scope` → HTTP **403** (SHOULD add `scope`).
92. `[§3]` no auth info → challenge SHOULD NOT include `error`.
93. `[§3.1]` `error` MUST be a registered value.
94. `[§4/5.3]` `[SEC]` bearer tokens only over TLS.
95. `[§5.2]` `[SEC]` avoid tokens in logged URLs.

## RFC 6749 §3.3 — Scope
96. `[§3.3]` `scope` = space-delimited, case-sensitive strings.
97. `[§3.3]` scope-token `1*(%x21/%x23-5B/%x5D-7E)` — excludes space/`"`/`\`; forbidden byte → reject.
98. `[§3.3]` scope order does not matter (set equivalence).
99. `[§3.3]` empty scope = empty set; extra spaces MUST NOT create empty tokens.
100. `[§3.3]` `[SEC]` resource authorizes only against granted scopes.

## WLCG Common JWT Profile v1.0
101. `wlcg.ver` MUST be present = `"1.0"`; missing/unknown → reject.
102. REQUIRED: `sub`,`iss`,`exp`,`nbf`,`iat`,`aud`,`jti`,`wlcg.ver`; any missing → reject.
103. `[SEC]` `iss` MUST be an `https://` trusted issuer; unconfigured → reject.
104. `aud` MUST identify the resource OR the wildcard `https://wlcg.cern.ch/jwt/v1/any`.
105. `[SEC]` accept if `aud` == our id OR == the wildcard; else reject.
106. `aud` may be string or array; match every element case-sensitively.
107. `[SEC]` MUST be signed asymmetric (RS256/ES256) via issuer `jwks_uri`; `none`/HMAC → reject.
108. `[SEC]` access-token lifetime `< 6h` (SHOULD ~20 min); MAY reject over-long.
109. capability (scope) vs attribute (`wlcg.groups`) models handled distinctly.
110. `scope` value space-delimited, case-sensitive (RFC 6749 §3.3).
111. storage scopes `storage.{read,create,modify,stage}:<PATH>`.
112. `[SEC]` `storage.*` PATH REQUIRED (MAY be `/`); path-less → reject.
113. `[SEC]` PATH absolute, RFC 3986 §6 normalized, components URL-escaped.
114. `[SEC]` `storage.read:<PATH>` covers PATH+sub; uncovered sibling/parent → deny.
115. `[SEC]` `storage.create` = new writes only; NOT `storage.modify`.
116. `storage.modify` = modify/delete existing; `storage.stage` = bring-online. Distinct ops.
117. `[SEC]` path authz on segment boundaries (`/foo` ≠ `/foobar`).
118. compute scopes `compute.{read,modify,create,cancel}`.
119. `wlcg.groups` = array of `/`-rooted group strings.
120. group order: first MAY be primary; no implicit capability.
121. `wlcg.groups` only when requested; MUST NOT assume all VO groups.
122. `[SEC]` distinguish capability / group / identity token shapes.
123. `[SEC]` `sub` unique+persistent per issuer; key on `(iss,sub)`.
124. `[SEC]` validate sig/`iss`/`aud`/`exp`/`nbf`/`wlcg.ver` before scope/group.
125. `[SEC]` unrecognized scope MUST NOT grant (fail-closed).

## SciTokens v2.0
126. `ver` = `<profile>:<version>` = `"scitokens:2.0"`; mandatory in 2.0, missing → reject.
127. `[SEC]` reject unknown `ver` (no permissive default).
128. REQUIRED `iss`,`sub`,`exp`,`iat`,`nbf`; `iss` `https://` discoverable.
129. `[SEC]` issuer trust via `<iss>/.well-known/openid-configuration`→`jwks_uri`.
130. `[SEC]` `iss` exact match to configured trusted issuer (scheme/host/path).
131. `aud` mandatory in v2.0; missing → reject.
132. `[SEC]` `aud` may be a site name; special value `ANY` matches any audience.
133. `[SEC]` `aud` present but neither matches nor `ANY` → reject.
134. `scope` space-separated per RFC 6749 §3.3 (`scp` deprecated).
135. authz scopes `$AUTHZ:$PATH` with `read`/`write`/`queue`/`execute`.
136. `[SEC]` `read:<PATH>` covers PATH+sub only; `/foo` ≠ `/bar`.
137. `write`/`queue`/`execute` distinct; not conflated with storage r/w.
138. `[SEC]` omitted PATH defaults to `/` — MUST be explicit, MUST NOT silently widen.
139. `[SEC]` `$PATH` normalized per RFC 3986 (`///foo/../baz`≡`/baz`) before compare.
140. `[SEC]` segment-boundary prefix (the sibling-path CVE class).
141. `[SEC]` `..` traversal resolved in normalization; MUST NOT broaden.
142. `[SEC]` reject now ≥ `exp` or now < `nbf`.
143. `[SEC]` fail-closed on unknown authz verbs; no over-authorization.
144. `[SEC]` asymmetric signing (ES256/RS256) vs issuer JWKS; `none` → reject.
145. `jti` MAY be used for replay; repeated → reject when enforced.
146. `[SEC]` v1↔v2 differences enforced (`ver`/`aud`/`scope` mandatory-ness).

## Cross-cutting security families (fan out into many cases)
147. alg=none bypass · 148. RS→HS confusion · 149. alg downgrade/unexpected ·
150. key injection via `jwk`/`jku`/`x5u`/`x5c` · 151. `crit` abuse ·
152. undersized RSA · 153. curve mismatch/invalid-curve ·
154. aud redirection / cross-JWT confusion · 155. expiry/nbf/NumericDate edges ·
156. path prefix/traversal/missing-path · 157. signature tamper/truncate/segment-swap/padded-b64 ·
158. transport: multiple methods→400, query without no-store, lowercase `bearer`, wrong status codes.

> Note: SciTokens' real sibling-path and path-traversal authz-bypass CVEs
> (scitokens-cpp advisories) justify the segment-boundary cases 117/140/156.
