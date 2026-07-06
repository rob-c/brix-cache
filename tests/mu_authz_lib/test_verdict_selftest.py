"""Self-test for Verdict + tier inference (unprivileged, pure logic)."""
from mu_authz_lib.verdict import Verdict, infer_tier


def test_tier_inference_from_real_server_strings():
    assert infer_tier("VO not authorized") == "vo_acl"
    assert infer_tier("token scope denied") == "token_scope"
    assert infer_tier("not authorized") == "authdb"
    assert infer_tier("file not found") == "none"
    assert infer_tier("AccessDenied") == "authdb"


def test_equality_is_decision_plus_tier_not_reason_text():
    a = Verdict("DENY", "VO not authorized", "vo_acl")
    b = Verdict("DENY", "vo denied for /cms/secret.dat", "vo_acl")
    assert a == b, "same decision+tier compare equal regardless of reason text"


def test_different_tier_is_a_different_verdict():
    # The core of leak detection: a hit that DENIES for a WEAKER tier than the cold
    # verdict is still a transparency violation.
    vo_deny = Verdict.deny("VO not authorized")
    authdb_deny = Verdict.deny("not authorized")
    assert vo_deny != authdb_deny, "vo_acl DENY != authdb DENY (weaker gate is a leak)"


def test_allow_never_equals_deny():
    assert Verdict.allow() != Verdict.deny("not authorized")


def test_deny_classmethod_infers_tier():
    v = Verdict.deny("token scope denied")
    assert v.decision == "DENY" and v.tier == "token_scope"
