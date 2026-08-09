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

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "proxy_part2.py")
