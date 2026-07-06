"""proxy — RFC 3820 proxy-certificate conformance family (id prefix PXY).

Every row exercises the proxy-verification path that root:// GSI (and the C
oracle with ALLOW_PROXY_CERTS) runs — WebDAV refuses proxies outright — so all
rows use surface='c-oracle' and group='sp_off_crl_off' (signing_policy + CRL
disabled, to isolate pure chain/proxy semantics).

Chains are minted leaf-first: [proxy(…leaf), …, proxy1, eec, ca].  The EEC is a
plain make_eec (keyUsage digitalSignature asserted by default) so it may legally
sign a proxy per RFC 3820 §3.1.

expected is SPEC-FIRST (RFC 3820 / Globus GT2 legacy convention / RFC 5280 path
validation).  Where our current code is likely to diverge (path-length and
limited→full monotonicity enforcement are commonly unimplemented) the row still
asserts the standard's verdict; a later phase fixes the code, never the test.

Validity note: the forge epoch is 2026-01-01 but path validation runs at real
wall-clock time, so every "valid-now" cert is minted with a multi-year
not_after; the expiry rows set a deliberately short/late window.
"""

from __future__ import annotations

from cryptography.x509 import Name, NameAttribute
from cryptography.x509.oid import NameOID

import x509forge
from x509forge import make_eec, make_proxy, make_proxy_from, proxy_cert_info_der
from clauses._helpers import clause, leaf_dn

# --- shared constants ------------------------------------------------------
S = "c-oracle"
G = "sp_off_crl_off"
VALID = 3650          # ~10y past the epoch → valid at real "now"
LONG = 4200           # strictly beyond an EEC minted with not_after=VALID
NEAR = 300            # ~2026-10-28: still valid now but earlier than VALID
FUTURE_NB = 3650      # notBefore far in the future → "not yet valid"
FUTURE_NA = 3660

OID_PCI = x509forge.OID_PROXY_CERT_INFO           # 1.3.6.1.5.5.7.1.14
OID_INHERIT = x509forge.OID_PPL_INHERIT_ALL       # impersonation / full
OID_INDEPENDENT = x509forge.OID_PPL_INDEPENDENT
OID_LIMITED = x509forge.OID_GLOBUS_LIMITED
OID_DRAFT_PCI = "1.3.6.1.4.1.3536.1.222"          # pre-standard Globus PCI OID
OID_BOGUS_A = "1.2.3.4.5.6.7.8.9.10"
OID_BOGUS_B = "1.3.6.1.4.1.99999.1.1"


# --- low-level helpers -----------------------------------------------------

def _proxy_subject(parent, cn: str) -> Name:
    """issuer-subject + one CN RDN — the RFC 3820 §3.4 proxy naming rule."""
    return Name(list(parent.cert.subject) + [NameAttribute(NameOID.COMMON_NAME, cn)])


def _proxy_like(parent, cn, extra_ext, *, subject=None, not_after=VALID):
    """A proxy-ish EEC-signed cert with hand-supplied extensions (raw-DER PCI
    variants cryptography's builder cannot express through make_proxy)."""
    subj = subject if subject is not None else _proxy_subject(parent, cn)
    return make_eec(parent, subject_name=subj, not_after_days=not_after,
                    key_usage={"key_encipherment": False}, extra_ext=extra_ext)


# --- credential factories --------------------------------------------------

def _single(kind="rfc3820", **pk):
    """One proxy directly off a fresh EEC."""
    def build(ctx):
        ca = ctx.ca()
        eec = make_eec(ca, leaf_dn(ctx), not_after_days=VALID)
        kw = dict(kind=kind, not_after_days=VALID, serial=100001)
        kw.update(pk)
        proxy = make_proxy(eec, **kw)
        return ctx.cred([proxy, eec, ca], proxy)
    return build


def _single_eec(kind="rfc3820", *, eec_kw=None, **pk):
    """One proxy off an EEC whose validity/keyUsage we control."""
    def build(ctx):
        ca = ctx.ca()
        ekw = dict(not_after_days=VALID)
        ekw.update(eec_kw or {})
        eec = make_eec(ca, leaf_dn(ctx), **ekw)
        kw = dict(kind=kind, not_after_days=VALID, serial=100001)
        kw.update(pk)
        proxy = make_proxy(eec, **kw)
        return ctx.cred([proxy, eec, ca], proxy)
    return build


def _chain(specs, *, eec_kw=None):
    """Multi-level delegation.  specs is top-first (closest to the EEC); each
    entry is a make_proxy kwargs dict."""
    def build(ctx):
        ca = ctx.ca()
        ekw = dict(not_after_days=VALID)
        ekw.update(eec_kw or {})
        eec = make_eec(ca, leaf_dn(ctx), **ekw)
        parent = eec
        certs = []
        serial = 200001
        for sp in specs:
            kw = dict(not_after_days=VALID, serial=serial)
            kw.update(sp)
            p = make_proxy(parent, **kw)
            certs.append(p)
            parent = p
            serial += 1
        chain = list(reversed(certs)) + [eec, ca]
        return ctx.cred(chain, certs[-1])
    return build


def _proxy_off_ca(ctx):
    """A 'proxy' whose issuer is the trust anchor itself (no EEC in between)."""
    ca = ctx.ca()
    proxy = make_proxy(ca, kind="rfc3820", not_after_days=VALID, serial=100001)
    return ctx.cred([proxy, ca], proxy)


def _dup_pci(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx), not_after_days=VALID)
    der = proxy_cert_info_der(OID_INHERIT, None)
    proxy = _proxy_like(eec, "100001",
                        [(OID_PCI, der, True), (OID_DRAFT_PCI, der, True)])
    return ctx.cred([proxy, eec, ca], proxy)


def _empty_policy_pci(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx), not_after_days=VALID)
    # PCI ::= SEQUENCE { ProxyPolicy ::= SEQUENCE { } } — policyLanguage absent.
    malformed = x509forge._der_seq(x509forge._der_seq(b""))
    proxy = _proxy_like(eec, "100001", [(OID_PCI, malformed, True)])
    return ctx.cred([proxy, eec, ca], proxy)


def _draft_only_pci(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx), not_after_days=VALID)
    der = proxy_cert_info_der(OID_INHERIT, None)
    proxy = _proxy_like(eec, "100001", [(OID_DRAFT_PCI, der, True)])
    return ctx.cred([proxy, eec, ca], proxy)


def _subject_unrelated(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx), not_after_days=VALID)
    der = proxy_cert_info_der(OID_INHERIT, None)
    subj = x509forge._name("/DC=test/DC=x509conf/CN=unrelated-name")
    proxy = _proxy_like(eec, "100001", [(OID_PCI, der, True)], subject=subj)
    return ctx.cred([proxy, eec, ca], proxy)


def _subject_missing_cn(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx), not_after_days=VALID)
    der = proxy_cert_info_der(OID_INHERIT, None)
    proxy = _proxy_like(eec, "100001", [(OID_PCI, der, True)],
                        subject=eec.cert.subject)   # no added CN
    return ctx.cred([proxy, eec, ca], proxy)


def _eec_no_digsig(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx), not_after_days=VALID,
                   key_usage={"digital_signature": False})
    proxy = make_proxy(eec, kind="rfc3820", not_after_days=VALID, serial=100001)
    return ctx.cred([proxy, eec, ca], proxy)


def _eec_only_keyenc(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx), not_after_days=VALID,
                   key_usage={"digital_signature": False,
                              "key_encipherment": True})
    proxy = make_proxy(eec, kind="rfc3820", not_after_days=VALID, serial=100001)
    return ctx.cred([proxy, eec, ca], proxy)


def _wrong_signer(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx, "real"), not_after_days=VALID)
    other = make_eec(ca, leaf_dn(ctx, "other"), not_after_days=VALID)
    der = proxy_cert_info_der(OID_INHERIT, None)
    subj = _proxy_subject(eec, "100001")
    # signed by `other`, but we present `eec` above it → issuer/sig mismatch.
    proxy = make_eec(other, subject_name=subj, not_after_days=VALID,
                     key_usage={"key_encipherment": False},
                     extra_ext=[(OID_PCI, der, True)])
    return ctx.cred([proxy, eec, ca], proxy)


def _escalate_via_proxy_from(ctx):
    """Full proxy minted (make_proxy_from) beneath a limited proxy."""
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx), not_after_days=VALID)
    limited = make_proxy(eec, kind="limited", not_after_days=VALID, serial=1)
    full = make_proxy_from(limited, eec, kind="rfc3820", serial=2)
    return ctx.cred([full.cert_obj, limited, eec, ca], full.cert_obj)


# --- clause registry -------------------------------------------------------
CLAUSES = []
_n = [0]


def add(ref, title, expected, build, reason=""):
    _n[0] += 1
    CLAUSES.append(clause(f"PXY-{_n[0]:03d}", ref, title, expected, build,
                          surface=S, group=G, reason=reason))


# 1. Policy language / kind acceptance -------------------------------------
add("RFC3820 §3.2", "impersonation proxy (id-ppl-inheritAll) authenticates",
    "accept", _single("rfc3820"), "full/impersonation proxy is the common case")
add("RFC3820 §3.2", "independent proxy (id-ppl-independent) authenticates",
    "accept", _single("independent"), "independent policy still authenticates EEC")
add("Globus EACL", "Globus limited proxy authenticates for authn",
    "accept", _single("limited"), "limited proxy is valid for authentication")
add("Globus GT2", "legacy GT2 proxy (CN=proxy) authenticates",
    "accept", _single("legacy"), "pre-RFC full legacy proxy")
add("Globus GT2", "legacy GT2 limited proxy (CN=limited proxy) authenticates",
    "accept", _single("legacy-limited"), "pre-RFC limited legacy proxy")
add("RFC3820 §3.1", "critical proxyCertInfo is recognised as a proxy",
    "accept", _single("rfc3820", pci_critical=True), "PCI MUST be critical")

# 2. proxyCertInfo criticality --------------------------------------------
add("RFC3820 §3.1", "non-critical proxyCertInfo (impersonation) rejected",
    "reject", _single("rfc3820", pci_critical=False),
    "non-critical PCI is not treated as a proxy → issuer/subject mismatch")
add("RFC3820 §3.1", "non-critical proxyCertInfo (independent) rejected",
    "reject", _single("independent", pci_critical=False), "PCI MUST be critical")
add("RFC3820 §3.1", "non-critical proxyCertInfo (limited) rejected",
    "reject", _single("limited", pci_critical=False), "PCI MUST be critical")
add("RFC3820 §3.1", "non-critical PCI at chain leaf rejected",
    "reject", _chain([{"kind": "rfc3820"}, {"kind": "rfc3820", "pci_critical": False}]),
    "leaf proxy not recognised → chain breaks")

# 3. Unknown / malformed policy language -----------------------------------
add("RFC3820 §3.2", "bogus proxy policy OID rejected (A)",
    "reject", _single("rfc3820", policy_oid=OID_BOGUS_A),
    "unrecognised policy language MUST be rejected")
add("RFC3820 §3.2", "bogus proxy policy OID rejected (B)",
    "reject", _single("rfc3820", policy_oid=OID_BOGUS_B),
    "unrecognised policy language MUST be rejected")
add("RFC3820 §3.1", "duplicate proxyCertInfo (RFC + draft OID) rejected",
    "reject", _dup_pci, "two conflicting PCI extensions = malformed proxy")
add("RFC3820 §3.1", "empty ProxyPolicy (no policyLanguage) rejected",
    "reject", _empty_policy_pci, "policyLanguage is mandatory in ProxyPolicy")
add("RFC3820 §3.1", "pre-standard draft-only PCI OID rejected",
    "reject", _draft_only_pci,
    "cert carries only 1.3.6.1.4.1.3536.1.222, not the RFC OID → not a proxy")

# 4. kind x depth acceptance grid ------------------------------------------
for _kind in ("rfc3820", "independent", "limited", "legacy", "legacy-limited"):
    for _depth in (2, 3, 4):
        add("RFC3820 §3.4", f"{_kind} delegation depth {_depth} authenticates",
            "accept", _chain([{"kind": _kind}] * _depth),
            "well-formed homogeneous delegation chain")

# 5. pcPathLenConstraint grid ----------------------------------------------
for _top in (0, 1, 2, 3):
    for _extra in (0, 1, 2, 3, 4):
        specs = [{"kind": "rfc3820", "path_len": _top}] + \
                [{"kind": "rfc3820"}] * _extra
        exp = "accept" if _extra <= _top else "reject"
        add("RFC3820 §4.2",
            f"pCPathLenConstraint={_top} with {_extra} following proxies",
            exp, _chain(specs),
            "at most pCPathLenConstraint proxies may follow")

# 5b. proper monotone decrement chains -------------------------------------
add("RFC3820 §4.2", "decrementing path-len 2->1 chain authenticates",
    "accept", _chain([{"kind": "rfc3820", "path_len": 2},
                      {"kind": "rfc3820", "path_len": 1}]),
    "each level stays within the constraint above it")
add("RFC3820 §4.2", "decrementing path-len 3->2->1 chain authenticates",
    "accept", _chain([{"kind": "rfc3820", "path_len": 3},
                      {"kind": "rfc3820", "path_len": 2},
                      {"kind": "rfc3820", "path_len": 1}]),
    "monotone decrement is legal")
add("RFC3820 §4.2", "top path-len 3 with 3 following authenticates",
    "accept", _chain([{"kind": "rfc3820", "path_len": 3}] +
                     [{"kind": "rfc3820"}] * 3),
    "exactly at the constraint")

# 6. Forbidden extensions on a proxy ---------------------------------------
add("RFC3820 §3.7", "proxy asserting BasicConstraints CA:TRUE rejected",
    "reject", _single("rfc3820", ca_true=True),
    "a proxy MUST NOT be a CA / assert keyCertSign")
add("RFC3820 §3.7", "independent proxy asserting CA:TRUE rejected",
    "reject", _single("independent", ca_true=True), "proxy MUST NOT be a CA")
add("RFC3820 §3.7", "limited proxy asserting CA:TRUE rejected",
    "reject", _single("limited", ca_true=True), "proxy MUST NOT be a CA")
add("RFC3820 §3.7", "CA:TRUE + keyCertSign at chain leaf rejected",
    "reject", _chain([{"kind": "rfc3820"}, {"kind": "rfc3820", "ca_true": True}]),
    "keyCertSign on a proxy is forbidden")
add("RFC3820 §3.7", "proxy carrying subjectAltName rejected",
    "reject", _single("rfc3820", with_san=True),
    "a proxy MUST NOT carry a subjectAltName")
add("RFC3820 §3.7", "independent proxy carrying subjectAltName rejected",
    "reject", _single("independent", with_san=True), "SAN forbidden on proxy")
add("RFC3820 §3.7", "limited proxy carrying subjectAltName rejected",
    "reject", _single("limited", with_san=True), "SAN forbidden on proxy")
add("RFC3820 §3.7", "subjectAltName at chain leaf rejected",
    "reject", _chain([{"kind": "rfc3820"}, {"kind": "rfc3820", "with_san": True}]),
    "SAN forbidden anywhere in a proxy chain")
add("RFC3820 §3.7", "CA:TRUE + SAN combined on a proxy rejected",
    "reject", _single("rfc3820", ca_true=True, with_san=True),
    "both forbidden markers present")

# 7. RFC 3820 §3.4 subject / issuer naming ---------------------------------
add("RFC3820 §3.4", "proxy subject not (issuer + one CN) rejected",
    "reject", _subject_unrelated, "proxy subject must extend issuer with one CN")
add("RFC3820 §3.4", "proxy subject equal to issuer (missing CN) rejected",
    "reject", _subject_missing_cn, "a proxy MUST add exactly one CN RDN")
add("RFC3820 §3.1", "proxy signed by a key other than its issuer rejected",
    "reject", _wrong_signer, "signature does not verify against presented issuer")

# 8. Proxy issuer must be an EEC/proxy with digitalSignature ---------------
add("RFC3820 §3.1", "proxy signed directly by the CA rejected",
    "reject", _proxy_off_ca,
    "issuer is the trust anchor (no digitalSignature keyUsage)")
add("RFC3820 §3.1", "proxy signed by EEC lacking digitalSignature rejected",
    "reject", _eec_no_digsig, "issuer keyUsage must assert digitalSignature")
add("RFC3820 §3.1", "proxy signed by keyEncipherment-only EEC rejected",
    "reject", _eec_only_keyenc, "digitalSignature bit required to sign a proxy")
add("RFC3820 §3.1", "proxy signed by digitalSignature EEC authenticates",
    "accept", _single("rfc3820"), "control: EEC with correct keyUsage")

# 9. Legacy GT2 interactions -----------------------------------------------
add("Globus GT2", "legacy proxy beneath an RFC 3820 proxy rejected",
    "reject", _chain([{"kind": "rfc3820"}, {"kind": "legacy"}]),
    "GT2 legacy under an RFC proxy is an invalid mix")
add("Globus GT2", "RFC 3820 proxy beneath a legacy proxy rejected",
    "reject", _chain([{"kind": "legacy"}, {"kind": "rfc3820"}]),
    "RFC proxy under a GT2 legacy proxy is an invalid mix")
add("Globus GT2", "legacy proxy beneath a legacy proxy authenticates",
    "accept", _chain([{"kind": "legacy"}, {"kind": "legacy"}]),
    "homogeneous GT2 delegation")
add("Globus GT2", "legacy limited beneath legacy full authenticates",
    "accept", _chain([{"kind": "legacy"}, {"kind": "legacy-limited"}]),
    "restricting a legacy proxy is allowed")
add("Globus GT2", "legacy full beneath legacy limited rejected",
    "reject", _chain([{"kind": "legacy-limited"}, {"kind": "legacy"}]),
    "escalating out of a limited legacy proxy is forbidden")
add("Globus GT2", "legacy limited beneath an RFC 3820 proxy rejected",
    "reject", _chain([{"kind": "rfc3820"}, {"kind": "legacy-limited"}]),
    "GT2/RFC mixing rejected")

# 10. Limited-proxy monotonicity (RFC 3820 §3.8) ---------------------------
add("RFC3820 §3.8", "limited then full proxy beneath it rejected",
    "reject", _chain([{"kind": "limited"}, {"kind": "rfc3820"}]),
    "cannot escalate a limited proxy to full")
add("RFC3820 §3.8", "limited then limited authenticates",
    "accept", _chain([{"kind": "limited"}, {"kind": "limited"}]),
    "restriction is monotone")
add("RFC3820 §3.8", "full then limited authenticates",
    "accept", _chain([{"kind": "rfc3820"}, {"kind": "limited"}]),
    "restricting a full proxy is allowed")
add("RFC3820 §3.8", "full then full authenticates",
    "accept", _chain([{"kind": "rfc3820"}, {"kind": "rfc3820"}]),
    "homogeneous full delegation")
add("RFC3820 §3.8", "limited then limited then limited authenticates",
    "accept", _chain([{"kind": "limited"}] * 3), "deep limited chain")
add("RFC3820 §3.8", "limited then limited then full (leaf escalation) rejected",
    "reject", _chain([{"kind": "limited"}, {"kind": "limited"},
                      {"kind": "rfc3820"}]),
    "escalation anywhere below a limited proxy is forbidden")
add("RFC3820 §3.8", "full then limited then full (re-escalation) rejected",
    "reject", _chain([{"kind": "rfc3820"}, {"kind": "limited"},
                      {"kind": "rfc3820"}]),
    "once restricted, cannot regain full rights")
add("RFC3820 §3.8", "full then limited then limited authenticates",
    "accept", _chain([{"kind": "rfc3820"}, {"kind": "limited"},
                      {"kind": "limited"}]),
    "monotone restriction preserved")
add("RFC3820 §3.8", "limited-to-full via make_proxy_from rejected",
    "reject", _escalate_via_proxy_from,
    "full proxy issued beneath a limited proxy")

# 11. Validity windows (RFC 5280 §6.1) -------------------------------------
add("RFC5280 §6.1.3", "proxy notAfter beyond EEC notAfter authenticates",
    "accept", _single_eec(eec_kw={"not_after_days": NEAR}, not_after_days=LONG),
    "path validation checks each cert at present time, not nested windows")
add("RFC5280 §6.1.3", "proxy notAfter equal to EEC notAfter authenticates",
    "accept", _single_eec(eec_kw={"not_after_days": NEAR}, not_after_days=NEAR),
    "both valid at present time")
add("RFC5280 §6.1.3", "expired proxy on a valid EEC rejected",
    "reject", _single("rfc3820", not_after_days=1),
    "proxy validity window has passed")
add("RFC5280 §6.1.3", "valid proxy on an expired EEC rejected",
    "reject", _single_eec(eec_kw={"not_after_days": 1}),
    "an intermediate cert is expired")
add("RFC5280 §6.1.3", "not-yet-valid proxy rejected",
    "reject", _single("rfc3820", not_before_days=FUTURE_NB,
                      not_after_days=FUTURE_NA),
    "proxy notBefore is in the future")
add("RFC5280 §6.1.3", "not-yet-valid EEC rejected",
    "reject", _single_eec(eec_kw={"not_before_days": FUTURE_NB,
                                  "not_after_days": FUTURE_NA}),
    "EEC notBefore is in the future")
add("RFC5280 §6.1.3", "deep chain, every cert valid, authenticates",
    "accept", _chain([{"kind": "rfc3820"}] * 4), "control for expiry rows")
add("RFC5280 §6.1.3", "expired intermediate proxy in depth-3 chain rejected",
    "reject", _chain([{"kind": "rfc3820"},
                      {"kind": "rfc3820", "not_after_days": 1},
                      {"kind": "rfc3820"}]),
    "middle proxy expired")
add("RFC5280 §6.1.3", "expired leaf proxy in depth-2 chain rejected",
    "reject", _chain([{"kind": "rfc3820"},
                      {"kind": "rfc3820", "not_after_days": 1}]),
    "leaf proxy expired")
add("RFC5280 §6.1.3", "expired top proxy in depth-2 chain rejected",
    "reject", _chain([{"kind": "rfc3820", "not_after_days": 1},
                      {"kind": "rfc3820"}]),
    "first-delegated proxy expired")

# 12. Delegation depth within limits ---------------------------------------
for _d in (1, 2, 3, 4, 5, 6):
    add("RFC3820 §3.4", f"unconstrained delegation depth {_d} authenticates",
        "accept", _chain([{"kind": "rfc3820"}] * _d),
        "no pCPathLenConstraint → unlimited delegation")
add("RFC3820 §4.2", "top path-len 3 followed by exactly 3 proxies (depth 4)",
    "accept", _chain([{"kind": "rfc3820", "path_len": 3}] +
                     [{"kind": "rfc3820"}] * 3),
    "delegation exactly fills the constraint")
add("RFC3820 §3.8", "full->full->limited->limited depth-4 authenticates",
    "accept", _chain([{"kind": "rfc3820"}, {"kind": "rfc3820"},
                      {"kind": "limited"}, {"kind": "limited"}]),
    "monotone mixed-kind delegation")

# 13. Assorted accept/reject pairs to round out coverage -------------------
add("RFC3820 §3.2", "independent proxy at depth 3 authenticates",
    "accept", _chain([{"kind": "independent"}] * 3), "independent chain")
add("RFC3820 §4.2", "limited proxy with path-len 1 plus one sub authenticates",
    "accept", _chain([{"kind": "limited", "path_len": 1}, {"kind": "limited"}]),
    "constraint honoured on a limited chain")
add("RFC3820 §4.2", "limited proxy with path-len 0 plus one sub rejected",
    "reject", _chain([{"kind": "limited", "path_len": 0}, {"kind": "limited"}]),
    "delegation forbidden by pCPathLenConstraint 0")
add("RFC3820 §3.1", "single limited proxy with path-len 0 authenticates",
    "accept", _single("limited", path_len=0),
    "path-len 0 only forbids further delegation, not the proxy itself")
add("RFC3820 §3.1", "single independent proxy with path-len 0 authenticates",
    "accept", _single("independent", path_len=0), "no delegation attempted")
add("RFC3820 §3.7", "limited proxy asserting CA:TRUE + SAN rejected",
    "reject", _single("limited", ca_true=True, with_san=True),
    "multiple forbidden markers on a limited proxy")
add("RFC3820 §3.2", "impersonation proxy with explicit path-len 5 authenticates",
    "accept", _single("rfc3820", path_len=5), "generous constraint, single proxy")

# 14. Extended kind x depth (depth 5) --------------------------------------
for _kind in ("rfc3820", "independent", "limited", "legacy", "legacy-limited"):
    add("RFC3820 §3.4", f"{_kind} delegation depth 5 authenticates",
        "accept", _chain([{"kind": _kind}] * 5),
        "deep homogeneous delegation chain")

# 15. pcPathLenConstraint grid for limited proxies -------------------------
for _top in (0, 1, 2):
    for _extra in (0, 1, 2):
        specs = [{"kind": "limited", "path_len": _top}] + \
                [{"kind": "limited"}] * _extra
        exp = "accept" if _extra <= _top else "reject"
        add("RFC3820 §4.2",
            f"limited pCPathLenConstraint={_top} with {_extra} following",
            exp, _chain(specs),
            "constraint applies to limited proxies too")

# 16. Further monotonicity / mixed chains ----------------------------------
add("RFC3820 §3.8", "full->full->full authenticates",
    "accept", _chain([{"kind": "rfc3820"}] * 3), "homogeneous full depth-3")
add("RFC3820 §3.8", "limited->full at leaf of depth-3 rejected",
    "reject", _chain([{"kind": "rfc3820"}, {"kind": "limited"},
                      {"kind": "rfc3820"}]),
    "escalation below a limited proxy")
add("RFC3820 §3.8", "full->limited->limited->limited authenticates",
    "accept", _chain([{"kind": "rfc3820"}] + [{"kind": "limited"}] * 3),
    "monotone restriction to depth 4")
add("RFC3820 §3.2", "independent->independent->independent authenticates",
    "accept", _chain([{"kind": "independent"}] * 3), "independent depth-3")

# 17. Forbidden extensions deeper in the chain -----------------------------
add("RFC3820 §3.7", "independent proxy CA:TRUE at chain leaf rejected",
    "reject", _chain([{"kind": "independent"},
                      {"kind": "independent", "ca_true": True}]),
    "keyCertSign/CA:TRUE forbidden anywhere in the chain")
add("RFC3820 §3.7", "limited proxy SAN at chain leaf rejected",
    "reject", _chain([{"kind": "limited"},
                      {"kind": "limited", "with_san": True}]),
    "SAN forbidden anywhere in the chain")
add("RFC3820 §3.7", "CA:TRUE on the first-delegated proxy rejected",
    "reject", _chain([{"kind": "rfc3820", "ca_true": True},
                      {"kind": "rfc3820"}]),
    "top proxy asserts CA capability")

# 18. More criticality / policy at depth -----------------------------------
add("RFC3820 §3.1", "non-critical PCI (independent) at chain leaf rejected",
    "reject", _chain([{"kind": "independent"},
                      {"kind": "independent", "pci_critical": False}]),
    "leaf PCI must be critical")
add("RFC3820 §3.2", "bogus policy OID at chain leaf rejected",
    "reject", _chain([{"kind": "rfc3820"},
                      {"kind": "rfc3820", "policy_oid": OID_BOGUS_A}]),
    "unrecognised policy language at any depth")

# 19. More validity combinations -------------------------------------------
add("RFC5280 §6.1.3", "limited depth-3 chain, all valid, authenticates",
    "accept", _chain([{"kind": "limited"}] * 3), "control: valid limited chain")
add("RFC5280 §6.1.3", "EEC valid only briefly but currently valid authenticates",
    "accept", _single_eec(eec_kw={"not_after_days": NEAR}),
    "EEC still inside its (short) validity window at present time")
add("RFC5280 §6.1.3", "not-yet-valid intermediate proxy in chain rejected",
    "reject", _chain([{"kind": "rfc3820", "not_before_days": FUTURE_NB,
                       "not_after_days": FUTURE_NA},
                      {"kind": "rfc3820"}]),
    "top proxy notBefore in the future")

# 20. Naming / issuer edge cases -------------------------------------------
add("Globus GT2", "legacy proxy signed directly by the CA rejected",
    "reject", lambda ctx: ctx.cred(
        [make_proxy((_ca := ctx.ca()), kind="legacy", not_after_days=VALID,
                    serial=100001),
         _ca],
        None),
    "GT2 proxy off a trust anchor (no EEC) is invalid")
