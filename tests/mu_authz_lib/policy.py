"""Render one high-level Policy into consistent backends (spec §8.4): a single declaration
("alice allowed, bob+carol denied on /cms/secret.dat") emits gridmap + authdb + VO rules +
S3 keys that all agree, so a test failure is a real inconsistency, not a misconfiguration.

The exact on-disk formats mirror what the server parses:
  - gridmap  : `"<DN>" <username>` per line (src/auth/impersonate/idmap.c).
  - authdb   : one XrdAcc `u <identity> <path> rl` grant per allowed principal,
               for the `brix_authdb_engine xrdacc` servers in configs/multiuser/
               (src/auth/authz/acc/authfile.c; the same shape test_acc.py pins
               with `u * /sub rl`).
Verify both against the running server via nginx -t + a live smoke before trusting them.

Two things about the authdb are easy to get wrong and both are fatal rather than
partial, so they are stated once here:

* The record TYPE is a single letter in column 1 — `= x s g h n o r t u` — and
  `u` is the per-identity one, carrying ALL of that identity's `<path> <priv>`
  pairs on its single line.  Anything else — a type the loader does not know
  (this file used to write `id`), or a second record for a name already seen —
  is refused, which is an `[emerg]` at worker start: the master keeps the
  listener open and the worker never comes up, so every probe connects and then
  waits forever.  That failure reads as a client hang, never as a config error,
  and it takes the whole MU oracle down with it.

* The IDENTITY in field 2 is whatever `brix_authz_mapped_name()` resolves to,
  which is the identity's own name unless a gridmap has been loaded
  (`brix_idmap_gate_enabled` — src/auth/authz/auth_gate_identity.c).  Every MU
  template that names this engine also sets `brix_idmap off` and no
  `brix_gridmap`, so that name is the one to grant — the `brixtest_<who>`
  gridmap name matches nothing there.  It is NOT always the DN: the name is read
  out of the identity's DN field, and a token puts its `sub` there, so a
  principal who holds both credentials needs both records (see _acc_names).  The
  gridmap is still written: the impersonating postures and the S3 key file use
  it, and the two must keep agreeing about who a DN is.
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


def _acc_names(p) -> list:
    """Every name the XrdAcc engine can see principal `p` under, in order.

    The engine keys a `u` record on ONE string and reads it out of the identity's
    DN field (brix_identity_dn_cstr — src/auth/authz/auth_gate.c for the stream
    planes, src/protocols/webdav/access.c and s3/handler.c for the HTTP ones).
    Which string lands in that field depends on how the principal authenticated:
    an X.509 proxy leaves the EEC DN there, while a verified WLCG token mirrors
    its `sub` into the same field (brix_identity_set_token_claims,
    src/core/types/identity.c).  One principal, two names, one authority.

    Granting only the DN therefore authorized the GSI planes and denied every
    token-authenticated request, and the MU oracle could not see it: it compares
    a cache node against a direct node built from the SAME authdb, so both denied
    and every cell read as agreement.  The one family it did break is the one
    that needs an ALLOW to set itself up — F8 fills the cache as an authorized
    principal before revoking them, and its WebDAV arms present Bearer tokens
    (mu_authz_lib/adapters._webdav_options prefers a token over a proxy), so the
    fill silently did nothing and every cell died on its own precondition.
    """
    names = [p.dn]
    if getattr(p, "sub", "") and p.sub not in names:
        names.append(p.sub)
    return names


def _grant_lines(cast, grants) -> list:
    """Render `grants` — an iterable of (principal, path) — as XrdAcc `u` records.

    ONE record per identity, carrying every `<path> <priv>` pair that identity
    is granted: XrdAcc's table is keyed by name, so a second `u` line for a name
    already seen is `duplicate rule for id "<name>"` — again an `[emerg]` that
    kills the worker at start, not a line skipped.  So the (principal, path)
    grants the corpus thinks in have to be regrouped here, principal-major.
    Note this is per NAME, not per principal: a principal contributes a record
    for each name it can authenticate under (see _acc_names), and two principals
    that share a name — `collide` shares alice's — share the one record.

    Insertion order is preserved on both axes so the file diffs cleanly against
    the corpus it came from.  A principal the cast does not hold raises: writing
    a name nobody authenticates as would make the policy read "allowed" while
    the server denies, which is a broken test, not a denial under test.
    """
    by_id: dict = {}
    for who, path in grants:
        p = cast.get(who)
        if p is None:
            raise KeyError(f"authdb grant for unknown principal {who!r}")
        for name in _acc_names(p):
            paths = by_id.setdefault(name, [])
            if path not in paths:
                paths.append(path)
    return [f"u {name} " + " ".join(f"{path} rl" for path in paths)
            for name, paths in by_id.items()]


def _write_authdb(policy: Policy, cast) -> str:
    lines = [f"# MU authdb for {policy.path}"]
    lines += _grant_lines(cast, ((who, policy.path) for who in policy.allow))
    with open(ports.MU.AUTHDB, "w") as f:
        f.write("\n".join(lines) + "\n")
    return ports.MU.AUTHDB


def render_corpus_policy(cast) -> dict:
    """Render backends for the whole CORPUS: one authdb grant per (allowed principal, object),
    VO rules for each subtree, and the full gridmap. A single consistent policy for every
    object the families exercise."""
    from . import corpus
    grid = write_gridmap(cast)
    lines = ["# MU authdb — corpus grants"]
    lines += _grant_lines(cast, ((who, obj.path)
                                 for obj in corpus.CORPUS for who in obj.allow))
    with open(ports.MU.AUTHDB, "w") as f:
        f.write("\n".join(lines) + "\n")
    vo = os.path.join(ports.MU.MU_ROOT, "vo.rules")
    with open(vo, "w") as f:
        f.write("/cms cms\n/atlas atlas\n")
    s3 = os.path.join(ports.MU.MU_ROOT, "s3keys")
    with open(s3, "w") as f:
        for p in cast.values():
            if p.name != "squashed" and p.s3_key:
                f.write(f"{p.s3_key} {p.s3_secret} brixtest_{p.name}\n")
    return {"gridmap": grid, "authdb": ports.MU.AUTHDB, "vo": vo, "s3keys": s3}


def render_policy(policy: Policy, cast) -> dict:
    grid = write_gridmap(cast)
    authdb = _write_authdb(policy, cast)
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
