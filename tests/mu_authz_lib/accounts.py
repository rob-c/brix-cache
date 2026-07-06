"""Real system-account provisioning for privileged impersonation tests (spec §8.3, D4).

Crash-safe: sweep leftovers first, reap is idempotent and guarded, reap runs strictly after
the fleet is stopped. Account names are `brixtest_<principal>`; uids come from the cast so a
GSI DN and a Kerberos principal that map to the same account share one uid (threat T6).
"""
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


def reap() -> None:
    """Remove every brixtest_* account. Idempotent; ignores userdel failures."""
    for name in _existing():
        subprocess.run(["userdel", "-r", name], capture_output=True)


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
        subprocess.run(["useradd", "-M", "-N", "-o", "-u", str(p.uid),
                        "-s", "/usr/sbin/nologin", uname], check=True, capture_output=True)
