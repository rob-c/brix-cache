"""Verdict — the unit of the cache-transparency invariant.

A Verdict is (decision, reason, deciding-tier). Equality is defined over (decision, tier)
so cache-transparency is decidable without brittle string matching: the cached-serve verdict
must ALLOW/DENY for the same *reason tier* as the authoritative (cold) verdict.

The tier is inferred from the server's denial-reason string. The known strings come from the
enforcing code paths, e.g.:
  - "VO not authorized"   -> vo_acl      (open_cache.c:26, prepare.c:216)
  - "token scope denied"  -> token_scope (prepare.c:221)
  - "not authorized"      -> authdb      (auth_gate / prepare.c:210)
  - read-only / write     -> allow_write (policy.c global pre-gate)
"""
from dataclasses import dataclass

# Order matters: earlier, more-specific needles win.
REASON_TIER = [
    ("vo not authorized", "vo_acl"),
    ("vo denied", "vo_acl"),
    ("token scope", "token_scope"),
    ("scope denied", "token_scope"),
    ("scope", "token_scope"),
    ("read-only", "allow_write"),
    ("write not allowed", "allow_write"),
    ("not authorized", "authdb"),
    ("permission denied", "authdb"),
    ("access denied", "authdb"),
    ("accessdenied", "authdb"),          # S3 XML <Code>AccessDenied</Code>
    ("signaturedoesnotmatch", "authn"),  # S3 auth (not authz)
    ("invalidaccesskeyid", "authn"),
    ("not found", "none"),
    ("nosuchkey", "none"),
]


def infer_tier(reason: str) -> str:
    r = (reason or "").lower()
    for needle, tier in REASON_TIER:
        if needle in r:
            return tier
    return "unknown"


@dataclass(frozen=True)
class Verdict:
    decision: str            # "ALLOW" | "DENY"
    reason: str = ""
    tier: str = "none"

    def __eq__(self, other) -> bool:
        return (isinstance(other, Verdict)
                and self.decision == other.decision
                and self.tier == other.tier)

    def __hash__(self) -> int:
        return hash((self.decision, self.tier))

    def __repr__(self) -> str:
        if self.decision == "ALLOW":
            return "ALLOW"
        return f"DENY(tier={self.tier}, reason={self.reason!r})"

    @classmethod
    def allow(cls) -> "Verdict":
        return cls("ALLOW", "", "none")

    @classmethod
    def deny(cls, reason: str) -> "Verdict":
        return cls("DENY", reason, infer_tier(reason))
