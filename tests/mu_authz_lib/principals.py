"""The fixed principal cast (spec §8.2). Each principal carries matched credentials across
protocols (GSI proxy, WLCG token, S3 key) plus a real uid for impersonation, so the same
identity can be presented over root://, WebDAV, and S3.

Key relationships the tests exploit:
  - carol: same VO (cms) as the privileged filler but NO authdb grant — the sharpest probe
    for the read-cache leak (weaker VO-only hit gate vs full-gate cold path).
  - collide: a distinct principal (GSI DN + Kerberos) mapping to alice's uid (threat T6).
  - squashed: below-floor / squash target (threat T6).
"""
from dataclasses import dataclass

from . import creds


@dataclass
class Principal:
    name: str
    uid: int
    dn: str
    sub: str
    scope: str
    vo: str
    proxy: str = ""
    token: str = ""
    s3_key: str = ""
    s3_secret: str = ""
    krb_princ: "str | None" = None
    has_voms: bool = False


# (name, uid, dn, sub, scope, vo, krb_princ)
_SPEC = [
    ("svc",      1700, "/DC=test/CN=brix-service", "brix-service",
     "storage.read:/ storage.write:/", "cms",   None),
    ("alice",    1701, "/DC=test/CN=alice",   "alice",   "storage.read:/cms",   "cms",   None),
    ("bob",      1702, "/DC=test/CN=bob",     "bob",     "storage.read:/atlas", "atlas", None),
    ("carol",    1703, "/DC=test/CN=carol",   "carol",   "storage.read:/cms",   "cms",   None),
    ("mallory",  1704, "/DC=test/CN=mallory", "mallory", "storage.read:/cms",   "cms",   None),
    ("collide",  1701, "/DC=test/CN=alice",   "alice",   "storage.read:/cms",   "cms",
     "alice@TEST.REALM"),
    ("squashed", 65534, "/DC=test/CN=root-ish", "root-ish", "", "", None),
]


def build_cast() -> "dict[str, Principal]":
    """Build the cast, generating all credentials under the MU PKI/token dirs. Idempotent."""
    cast: "dict[str, Principal]" = {}
    for name, uid, dn, sub, scope, vo, krb in _SPEC:
        p = Principal(name=name, uid=uid, dn=dn, sub=sub, scope=scope, vo=vo, krb_princ=krb)
        if name != "squashed":
            cert, key = creds.gen_user_cert(dn, name)
            if vo:
                p.proxy = creds.gen_voms_proxy(cert, key, name, vo)
                p.has_voms = True
            else:
                p.proxy = creds.gen_gsi_proxy(cert, key, name)
            p.token = creds.mint_token(sub, scope, name)
            p.s3_key, p.s3_secret = creds.s3_key_for(name)
        cast[name] = p
    return cast
