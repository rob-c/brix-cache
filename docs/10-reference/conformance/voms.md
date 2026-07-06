# VOMS attribute certificates — conformance

Scope: extraction of Virtual Organisation (VO) membership from a VOMS Attribute
Certificate (AC) embedded in an RFC 3820 proxy, the derivation of VO names from
Fully-Qualified Attribute Names (FQANs), and the sanitization applied before a VO
name is placed into the module's VO list, ACL engine, metric labels, and access
log. Both our module and XRootD v6.1.0 delegate the cryptographic validation of
the AC itself (signature, AC validity window, VOMS-server trust) to the VOMS
library; this document is about the extraction/handling layer that sits on top of
that library, which is where the two implementations differ.

## Normative basis

- **RFC 5755 / RFC 3281 — An Internet Attribute Certificate Profile for
  Authorization.** Defines the AC structure carried inside a VOMS proxy. Signature
  and validity verification of the AC is performed by the VOMS library in both
  implementations and is therefore out of scope for the extraction layer.
- **GFD-C.182 — "The VOMS Attribute Certificate Format" (OGF).** Defines the FQAN
  grammar `/VO[/group]*[/Role=role][/Capability=cap]`; the VO name is the first
  path component. Our FQAN→VO derivation implements this grammar directly.
- **EACL / VO-membership authorization** (the `authdb`/`.lcas`-style rules the
  module's ACL engine evaluates). Requires that a VO name be usable as an opaque
  matching token — which is what motivates a canonical, injection-free encoding.
- **No RFC mandates VO-name sanitization.** A forged or self-signed AC is
  attacker-influenced input, so treating the extracted VO/FQAN strings as untrusted
  before they cross into the list encoding, log, and metric-label planes is a
  defense-in-depth requirement local to this module (module INVARIANT #8:
  low-cardinality, injection-free metric labels). XRootD applies no such
  sanitization; this is the one place our layer is deliberately stricter.

---

### AC extraction is delegated to the VOMS library (RFC 5755 AC validation)

- **Requirement:** VO membership must be extracted from the AC embedded in the
  proxy chain, and the AC's own signature/validity must be checked by trusted VOMS
  code — not re-implemented in the server.
- **Ours:** We `dlopen("libvomsapi.so.1", RTLD_NOW | RTLD_LOCAL)` at startup and
  resolve `VOMS_Init`/`VOMS_Retrieve`/`VOMS_Destroy`/`VOMS_ErrorMessage`
  (`src/auth/voms/loader.c:38`, `src/auth/voms/loader.c:63`). Extraction duplicates
  the verified proxy chain, strips the leaf (VOMS needs the parent EEC for the AC
  holder lookup), and calls `VOMS_Retrieve(leaf, chain, VOMS_RECURSE_CHAIN, …)`
  (`src/auth/voms/extract.c:84`, `src/auth/voms/extract.c:91`). AC validation
  (signature, `vomsdir` trust, validity window) happens entirely inside
  `libvomsapi`; we consume only the resulting `voms_data`
  (`src/auth/voms/voms_internal.h:41`). Extraction runs **only after** the GSI proxy
  chain is verified — root:// at `src/auth/gsi/auth.c:352`, davs:// at
  `src/protocols/webdav/auth_cert.c:396`.
- **XRootD v6.1.0:** VOMS extraction is a pluggable server-side callback. The GSI
  protocol loads a `XrdSecgsiVOMSFun` plug-in via `LoadVOMSFun()`
  (`/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc:5459`) — the default plug-in
  `libXrdVoms.so` (`/tmp/xrootd-src/src/XrdSecgsi/XrdSecgsiOpts.hh:42`) is itself a
  thin wrapper over `libvomsapi`. The callback is invoked on the verified chain at
  `/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc:2003`, filling
  `Entity.vorg`/`grps`/`role`/`endorsements`
  (`/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc:2013`). For HTTP, XrdHttp uses
  a separate `XrdHttpSecXtractor` plug-in
  (`/tmp/xrootd-src/src/XrdHttp/XrdHttpProtocol.cc:107`,
  `/tmp/xrootd-src/src/XrdHttp/XrdHttpProtocol.cc:3141`) rather than the GSI VOMSFun.
- **Verdict:** Conformant (architecturally aligned). Both delegate AC validation to
  `libvomsapi`; the difference is dlopen-a-known-symbol (ours) vs.
  dlopen-a-configurable-plugin (XRootD). Extraction correctness is exercised at the
  integration level; the string-handling surface is pinned by VMS-01..VMS-03,
  VMS-32 (valid VO/FQAN tokens accepted end-to-end).

---

### FQAN → VO-name derivation (GFD-C.182 FQAN grammar)

- **Requirement:** The VO name is the first path component of an FQAN
  `/VO/group/Role=…`; deriving it must not mis-parse a leading slash, an empty
  component, or an over-long name.
- **Ours:** `brix_fqan_to_vo()` requires a leading `/`, takes the substring up to
  the next `/`, rejects an empty first component, and bounds-checks the length
  before copying (`src/auth/voms/collect.c:80`–`src/auth/voms/collect.c:105`). VO
  names are collected from both the AC's `voname` field and every FQAN, deduplicated
  into a comma-separated list by `brix_collect_voms_vos()`
  (`src/auth/voms/collect.c:118`, dedup via `brix_vo_list_contains` at
  `src/auth/voms/collect.c:44`).
- **XRootD v6.1.0:** FQAN parsing lives inside the VOMS plug-in
  (`libXrdVoms`/`libvomsapi`); the GSI core consumes the already-split
  `Entity.vorg` (VO) and `Entity.grps` (groups) strings and does not itself walk the
  FQAN grammar (`/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc:2013`). The
  bundled VO authz helper treats `vorg` as an opaque token against a configured
  comma-separated VO list (`/tmp/xrootd-src/src/XrdSecgsi/XrdSecgsiAuthzFunVO.cc:51`).
- **Verdict:** Conformant. Same first-component-is-VO semantics; we additionally
  derive the VO from FQANs ourselves (rather than trusting only the library's
  `voname`), which is a superset of the required behavior. Pinned by VMS-06 (a raw
  FQAN string `/cms/Role=X` is rejected as a *VO token* — the slash is stripped by
  the FQAN parser, not accepted verbatim).

---

### VO-name sanitization before list/log/label use (defense-in-depth; INVARIANT #8)

- **Requirement:** A VO/FQAN string extracted from an attacker-influenced AC must
  not be able to break the comma-separated VO-list encoding, inject into the access
  log, or create a high-cardinality/hostile metric label.
- **Ours:** `brix_vo_token_is_safe()` rejects an empty token and any byte `<= ' '`
  (control/space), any byte `>= 0x7f` (DEL/non-ASCII), and the structural
  separators `,` `/` `\` (`src/auth/voms/vo_token.h:32`). It gates **every** VO name
  before it enters the list — both the AC `voname` (`src/auth/voms/collect.c:40`)
  and each FQAN-derived VO (`src/auth/voms/collect.c:98`). A rejected token is
  silently dropped, not fatal, so a single hostile AC entry cannot deny a legitimate
  VO. The same predicate is header-only so the collector and its unit test share the
  exact bytes.
- **XRootD v6.1.0:** None. The VOMS plug-in output (`Entity.vorg`/`grps`/`role`) is
  `strdup`'d verbatim into the `XrdSecEntity`
  (`/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc:2231`,
  `/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc:2237`); for HTTP the values are
  taken from request opaque data (`xrdhttpvorg`/`xrdhttprole`/`xrdhttpgrps`) and only
  URL-decoded, not sanitized
  (`/tmp/xrootd-src/src/XrdHttp/XrdHttpProtocol.cc:705`–745). A grep of `XrdSecgsi`
  finds no control-byte/comma/`isprint` filtering of VO names.
- **Verdict:** Stricter-than-XRootD. We reject VO names XRootD would accept
  verbatim. Pinned by VMS-04..VMS-31: comma (VMS-05/26/31), slash (VMS-06/27),
  backslash (VMS-07/28), space (VMS-08/15), tab/newline/CR (VMS-09/10/25),
  control bytes (VMS-11/14/29/30), non-ASCII/DEL/high-bit (VMS-12/13/19/20), with the
  printable-boundary accept cases VMS-16/17/18/21/22/23/24 confirming legitimate
  FQAN structural characters (`!` `+` `~` `:` `=` `_` `-` `.`) are preserved.

---

### Graceful degradation when the VOMS library is absent

- **Requirement:** VOMS is optional grid infrastructure; a server without it must
  still authenticate GSI users, simply without VO attributes.
- **Ours:** No link-time VOMS dependency. If `libvomsapi.so.1` is not present,
  `brix_voms_init()` logs a NOTICE and returns `NGX_DECLINED`
  (`src/auth/voms/loader.c:39`); `brix_voms_available()` then reports unavailable
  and every callsite skips extraction (`src/auth/gsi/auth.c:349`,
  `src/protocols/webdav/auth_cert.c:389`). Extraction that finds no AC returns
  `NGX_DECLINED` on `VOMS_VERR_NOEXT`/`VOMS_VERR_NODATA`, never a hard failure
  (`src/auth/voms/extract.c:94`).
- **XRootD v6.1.0:** Default `-vomsat` is `vatIgnore`
  (`/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc:174`); with no VOMSFun
  configured the extraction block at
  `/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc:1989` is skipped and GSI auth
  proceeds without VO attributes.
- **Verdict:** Conformant (aligned). Both make VOMS best-effort by default.

---

### VOMS-required (`vomsat=require`) enforcement mode

- **Requirement:** Not mandated by any RFC. XRootD offers an operator policy where a
  missing/failed VOMS extraction *fails* authentication.
- **Ours:** No equivalent "require" mode. `brix_extract_voms_info()` returns
  `NGX_DECLINED`/`NGX_ERROR` but callers treat VO membership as advisory (root://
  registers whatever VO list was produced; davs:// sets identity VOs only if
  non-empty — `src/protocols/webdav/auth_cert.c:400`). Authentication never fails
  solely because VOMS attributes are absent; VO-based authorization is enforced
  downstream by the ACL engine only when a rule demands a VO.
- **XRootD v6.1.0:** `-vomsat:require` (`vatRequire`) makes a VOMSFun failure fatal —
  `kS_rc = kgST_error` and the handshake breaks
  (`/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc:2005`–2010).
- **Verdict:** Documented-limitation. We do not implement a global
  "authentication requires a valid VOMS AC" switch; the equivalent effect is
  achieved by an ACL rule that requires VO membership (deny-by-default at the
  authorization layer rather than the authentication layer). No pinning test —
  this is an absent optional feature, recorded here for completeness.

---

## Divergence summary

| Aspect | Ours | XRootD v6.1.0 | Verdict | Tests |
|---|---|---|---|---|
| AC validation | `dlopen libvomsapi.so.1` → `VOMS_Retrieve` (`src/auth/voms/extract.c:91`) | pluggable `XrdSecgsiVOMSFun` / `XrdHttpSecXtractor` over `libvomsapi` (`XrdSecProtocolgsi.cc:2003`) | Conformant (aligned) | VMS-01..03, VMS-32 |
| FQAN → VO name | first-component parse + dedup (`src/auth/voms/collect.c:80`) | inside VOMS plug-in; core consumes `Entity.vorg` (`XrdSecProtocolgsi.cc:2013`) | Conformant | VMS-06 |
| VO-name sanitization | reject ctrl/space/`,`/`/`/`\`/non-ASCII (`src/auth/voms/vo_token.h:32`) | none — `strdup` verbatim (`XrdSecProtocolgsi.cc:2231`) | Stricter-than-XRootD | VMS-04..31 |
| No-library degradation | dlopen-optional, best-effort (`src/auth/voms/loader.c:39`) | `vatIgnore` default, skipped (`XrdSecProtocolgsi.cc:174`) | Conformant (aligned) | — |
| VOMS-required mode | not implemented (advisory only) | `-vomsat:require` fatal (`XrdSecProtocolgsi.cc:2005`) | Documented-limitation | — |

Notes for grid-security engineers: the one behavioral divergence that changes what
is *accepted* is VO-name sanitization — we drop a VO/FQAN token that XRootD would
propagate verbatim into `Entity.vorg`/`grps`, the access log, and (in our case)
metric labels. Because rejection is per-token and non-fatal, a proxy carrying one
legitimate VO plus one hostile AC entry still authenticates with the legitimate VO;
the hostile string is simply never materialized. All heavy lifting for AC trust
(signature, VOMS-server certificate, AC validity window) remains inside
`libvomsapi` in both implementations and is not re-verified here.
