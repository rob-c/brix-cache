"""Real system-account provisioning for privileged impersonation tests (spec §8.3, D4).

Crash-safe: sweep leftovers first, reap is idempotent and guarded, reap runs strictly after
the fleet is stopped. Account names are `brixtest_<principal>`; uids come from the cast so a
GSI DN and a Kerberos principal that map to the same account share one uid (threat T6).
"""
import grp
import os
import pwd
import subprocess

from lib_py.util import nologin_shell
from lib_py import account_host

PREFIX = "brixtest_"
BROKER_UID = 1699


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
        subprocess.run(account_host.user_delete(name), capture_output=True)
    for name in _existing_groups():
        subprocess.run(account_host.group_delete(name), capture_output=True)


def sweep_leftover() -> None:
    """Pre-session cleanup so a crashed prior run cannot poison the box."""
    reap()


def _remove_mismatched_user(uname: str, uid: int) -> bool:
    """Return true when the requested account already has the requested uid."""
    try:
        if pwd.getpwnam(uname).pw_uid == uid:
            return True
        subprocess.run(account_host.user_delete(uname), capture_output=True)
    except KeyError:
        pass
    return False


def _group_gid(uname: str) -> "int | None":
    try:
        return grp.getgrnam(uname).gr_gid
    except KeyError:
        return None


def _remove_group(uname: str, old_gid: int, new_gid: int) -> None:
    removed = subprocess.run(account_host.group_delete(uname), capture_output=True)
    if removed.returncode == 0:
        return
    detail = removed.stderr.decode("utf-8", "replace")
    raise RuntimeError(
        f"cannot replace group {uname} at gid {old_gid} "
        f"with gid {new_gid}: {detail.strip()}")


def _create_group(uname: str, uid: int) -> None:
    old_gid = _group_gid(uname)
    if old_gid == uid:
        return
    if old_gid is not None:
        _remove_group(uname, old_gid, uid)
    created = subprocess.run(
        account_host.group_add(uname, uid), capture_output=True,
    )
    if created.returncode == 0:
        return
    detail = created.stderr.decode("utf-8", "replace")
    raise RuntimeError(
        f"cannot provision group {uname} at gid {uid}: {detail.strip()}")


def _create_user(uname: str, uid: int) -> None:
    created = subprocess.run(
        account_host.user_add(uname, uid, uname, nologin_shell(), system=True),
        capture_output=True,
    )
    if created.returncode == 0:
        return
    detail = created.stderr.decode("utf-8", "replace")
    raise RuntimeError(
        f"cannot provision {uname} at uid {uid}: {detail.strip()}")


def canonical_account_names(cast):
    """One exact account per active uid, shared by provisioning and gridmap."""
    first, result = {}, {}
    for principal in cast.values():
        if principal.name != 'squashed':
            result[principal.name] = first.setdefault(
                principal.uid, PREFIX + principal.name)
    return result


def provision(cast) -> None:
    """Create brixtest_<name> system users at each principal's uid. Distinct principals that
    share a uid (collide/alice) collapse onto one account by design."""
    require_privileged()
    names = canonical_account_names(cast)
    seen = set()
    for p in cast.values():
        if p.name == 'squashed':
            # This negative-control principal has no credentials or gridmap
            # entry. Its logical nobody uid must never alias a real account.
            continue
        uname = names[p.name]
        if uname in seen:
            # Two principals mapping to one uid share the FIRST account created for it.
            continue
        seen.add(uname)
        if _remove_mismatched_user(uname, p.uid):
            continue
        # A killed run can leave the user absent but its private group behind.
        # shadow-utils then rejects useradd with exit 16 while trying to create
        # that same group.  The session-wide sweep normally removes it, but do
        # this again immediately before creation so cleanup is idempotent even
        # after a partially successful userdel.
        _create_group(uname, p.uid)
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
        _create_user(uname, p.uid)
    broker = PREFIX + 'broker'
    if not _remove_mismatched_user(broker, BROKER_UID):
        _create_group(broker, BROKER_UID)
        _create_user(broker, BROKER_UID)
