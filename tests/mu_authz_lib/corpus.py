"""The test-file CORPUS — the single source of truth for the conformance object set.

Each Obj declares a path, the VO subtree that owns it, the uid-owner, the unix mode, and the
principals authorized by authdb. The seed fixture creates these files, the policy renderer
grants exactly `allow` on each path, and the family tests parametrize over them. Keeping one
declaration means the seeded bytes, the rendered authz backends, and the test expectations
can never drift apart.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Obj:
    path: str
    vo: str            # subtree VO: "cms" | "atlas"
    owner: str         # principal whose uid owns the on-disk file
    mode: int          # unix mode of the on-disk file
    allow: tuple       # principals granted read by authdb (everyone else is denied)


# svc is the privileged filler and is authorized everywhere. The interesting denials:
#   - carol: VO cms, never authdb-granted except on shared.dat  -> authdb-tier probe
#   - bob:   VO atlas, denied on all /cms/*                      -> vo_acl-tier probe
#   - mallory: VO cms, granted nowhere                           -> authdb-tier + revocation
CORPUS = (
    Obj("/cms/secret.dat",        "cms",   "svc", 0o640, ("alice", "svc")),
    Obj("/cms/service-only.dat",  "cms",   "svc", 0o600, ("svc",)),
    Obj("/cms/nested/deep.dat",   "cms",   "svc", 0o640, ("alice", "svc")),
    Obj("/cms/shared.dat",        "cms",   "svc", 0o644, ("alice", "carol", "svc")),
    Obj("/atlas/data.bin",        "atlas", "svc", 0o640, ("bob", "svc")),
    Obj("/atlas/private.bin",     "atlas", "svc", 0o600, ("bob", "svc")),
)

# All non-service cast members, for computing the denied set per object.
_ALL_SUBJECTS = ("alice", "bob", "carol", "mallory")


def denied_for(obj: Obj) -> "list[str]":
    """Principals that must be DENIED read on `obj` (present in the cast, not in allow)."""
    return [s for s in _ALL_SUBJECTS if s not in obj.allow]


def allowed_for(obj: Obj) -> "list[str]":
    """Non-service principals authorized on `obj` (control cells)."""
    return [s for s in _ALL_SUBJECTS if s in obj.allow]


def by_path(path: str) -> Obj:
    for o in CORPUS:
        if o.path == path:
            return o
    raise KeyError(path)
