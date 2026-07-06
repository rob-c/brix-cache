"""smoke — a tiny cross-family clause set proving the forge v2 registry works.

The real families (chain/proxy/signing_policy/crl/cadir/voms/dn_encoding) land
in P1; this module exists so P0's fleet + oracle have something to run.
"""

from clauses._helpers import clause, ns_globs, leaf_dn
import x509forge


def _in_ns(ctx):
    ca = ctx.ca(policy_globs=ns_globs())
    eec = x509forge.make_eec(ca, leaf_dn(ctx, "alice"))
    return ctx.cred([eec, ca], eec)


def _out_of_ns(ctx):
    ca = ctx.ca(policy_globs=ns_globs())
    eec = x509forge.make_eec(ca, "/DC=evil/CN=mallory")
    return ctx.cred([eec, ca], eec)


def _expired_ca(ctx):
    ca = ctx.ca(not_after_days=-1)
    eec = x509forge.make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


def _revoked(ctx):
    # Mint CA + two EECs; place the CA with a CRL revoking one of them.
    ca = x509forge.make_ca(ctx.dn())
    good = x509forge.make_eec(ca, leaf_dn(ctx, "good"))
    bad = x509forge.make_eec(ca, leaf_dn(ctx, "revoked"))
    x509forge._place_ca_in_dir(ctx.shared_ca, ca, name=f"{ctx.clause.id}-ca",
                               crls={"r0": x509forge.make_crl(ca, revoked=[bad])})
    return ctx.cred([good, ca], good)  # good is not revoked → accept


def _bundle_ok(ctx):
    ca = ctx.ca(to_bundle=True)
    eec = x509forge.make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


def _require_bundle_configerr(ctx):
    ctx.ca(to_bundle=True)
    return None  # surface=config: nginx -t must fail


CLAUSES = [
    clause("SMK-001", "signing_policy §3.1", "in-namespace EEC accepted",
           "accept", _in_ns, group="sp_on_crl_off"),
    clause("SMK-002", "signing_policy §3.1", "out-of-namespace EEC rejected",
           "reject", _out_of_ns, group="sp_on_crl_off"),
    clause("SMK-003", "RFC5280 §4.1.2.5", "expired trust anchor rejected",
           "reject", _expired_ca, group="sp_off_crl_off"),
    clause("SMK-004", "RFC5280 §5", "non-revoked EEC accepted under CRL try",
           "accept", _revoked, group="sp_off_crl_try"),
    clause("SMK-005", "IGTF store", "bundle-file CA verifies EEC",
           "accept", _bundle_ok, group="bundle"),
    clause("SMK-006", "signing_policy §3.1", "require+bundle is a config error",
           "reject", _require_bundle_configerr, surface="config",
           group="sp_require_crl_off"),
]
