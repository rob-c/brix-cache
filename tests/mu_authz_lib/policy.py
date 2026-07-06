"""Render one high-level Policy into consistent backends (spec §8.4): a single declaration
("alice allowed, bob+carol denied on /cms/secret.dat") emits gridmap + authdb + VO rules +
S3 keys that all agree, so a test failure is a real inconsistency, not a misconfiguration.

The exact on-disk formats mirror what the server parses:
  - gridmap  : `"<DN>" <username>` per line (src/auth/impersonate/idmap.c).
  - authdb   : one XrdAcc-style `id <user> <path> rl` grant per allowed principal
               (tests/configs/nginx_authdb.conf references such a file).
Verify both against the running server via nginx -t + a live smoke before trusting them.
"""
import os
from dataclasses import dataclass

from . import ports


@dataclass
class Policy:
    path: str
    allow: list
    deny: list
    vo: "str | None" = None
    scope_prefix: "str | None" = None


def write_gridmap(cast) -> str:
    os.makedirs(ports.MU.MU_ROOT, exist_ok=True)
    lines = []
    for p in cast.values():
        if p.name == "squashed":
            continue
        lines.append(f'"{p.dn}" brixtest_{p.name}')
        if p.krb_princ:
            lines.append(f'"{p.krb_princ}" brixtest_{p.name}')
    with open(ports.MU.GRIDMAP, "w") as f:
        f.write("\n".join(lines) + "\n")
    return ports.MU.GRIDMAP


def _write_authdb(policy: Policy) -> str:
    lines = [f"# MU authdb for {policy.path}"]
    for who in policy.allow:
        lines.append(f"id brixtest_{who} {policy.path} rl")
    with open(ports.MU.AUTHDB, "w") as f:
        f.write("\n".join(lines) + "\n")
    return ports.MU.AUTHDB


def render_policy(policy: Policy, cast) -> dict:
    grid = write_gridmap(cast)
    authdb = _write_authdb(policy)
    vo = os.path.join(ports.MU.MU_ROOT, "vo.rules")
    with open(vo, "w") as f:
        f.write(f"{os.path.dirname(policy.path)} {policy.vo}\n" if policy.vo else "")
    s3 = os.path.join(ports.MU.MU_ROOT, "s3keys")
    with open(s3, "w") as f:
        for who in list(policy.allow) + list(policy.deny):
            p = cast.get(who)
            if p is not None and p.s3_key:
                f.write(f"{p.s3_key} {p.s3_secret} brixtest_{who}\n")
    return {"gridmap": grid, "authdb": authdb, "vo": vo, "s3keys": s3}
