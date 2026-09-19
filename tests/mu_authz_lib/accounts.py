"""Real system-account provisioning for privileged impersonation tests (spec §8.3, D4).

Crash-safe: sweep leftovers first, reap is idempotent and guarded, reap runs strictly after
the fleet is stopped. Account names are `brixtest_<principal>`; uids come from the cast so a
GSI DN and a Kerberos principal that map to the same account share one uid (threat T6).
"""
import grp
import os
import pwd
import subprocess

PREFIX = "brixtest_"


def require_privileged() -> None:
    if os.geteuid() != 0:
        raise PermissionError(
            "MU conformance suite requires root (real accounts + setfsuid). "
            "Run tests/run_multiuser_authz.sh under sudo, or grant "
            "CAP_SETUID+CAP_SETGID+CAP_DAC_OVERRIDE.")


def _existing() -> "list[str]":
    return [u.pw_name for u in pwd.getpwall() if u.pw_name.startswith(PREFIX)]


def _existing_groups() -> "list[str]":
    return [g.gr_name for g in grp.getgrall() if g.gr_name.startswith(PREFIX)]


def reap() -> None:
    """Remove every brixtest_* account AND its group. Idempotent; ignores failures.

    The group half matters because provision() now lets useradd create each
    principal's own group (see there): a group left behind by a crashed run makes
    the next useradd fail with "group brixtest_alice exists", and provision()
    would then raise mid-session with half a cast on the box.
    """
    for name in _existing():
        subprocess.run(["userdel", "-r", name], capture_output=True)
    for name in _existing_groups():
        subprocess.run(["groupdel", name], capture_output=True)


def sweep_leftover() -> None:
    """Pre-session cleanup so a crashed prior run cannot poison the box."""
    reap()


def provision(cast) -> None:
    """Create brixtest_<name> system users at each principal's uid. Distinct principals that
    share a uid (collide/alice) collapse onto one account by design."""
    require_privileged()
    seen_uids: "dict[int, str]" = {}
    for p in cast.values():
        uname = PREFIX + p.name
        if p.uid in seen_uids and seen_uids[p.uid] != uname:
            # Two principals mapping to one uid share the FIRST account created for it.
            continue
        seen_uids.setdefault(p.uid, uname)
        try:
            if pwd.getpwnam(uname).pw_uid == p.uid:
                continue
            subprocess.run(["userdel", "-r", uname], capture_output=True)
        except KeyError:
            pass
        # Each principal gets its OWN group, which is why -N (share the system
        # `users` group) is gone.  `users` is gid 100, and the impersonation
        # floor refuses any target whose primary gid is below brix_idmap_min_uid
        # — correctly: a system gid must never be an impersonation target
        # (brix_imp_creds_privileged, auth/impersonate/idmap_denylist.c).  So
        # every account this provisioned was mapped, found, and then REFUSED at
        # the gid check, and the broker logged "no UNIX mapping for principal"
        # — which reads as a missing account, not a policy floor.  The write
        # plane's whole attribution property (F6/F9) was unreachable because of
        # one useradd flag.  Without -N, useradd creates brixtest_<name> at the
        # first free gid >= GID_MIN, which clears the floor by construction.
        subprocess.run(["useradd", "-M", "-o", "-u", str(p.uid),
                        "-s", "/usr/sbin/nologin", uname], check=True, capture_output=True)
