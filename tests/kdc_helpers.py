"""kdc_helpers.py — provision a self-contained MIT Kerberos KDC for the krb5 tier.

WHAT: stands up an isolated test realm under ``TEST_ROOT/krb5`` — a freshly
  created KDC database, a service principal + exported keytab for the nginx
  ``xrootd_auth krb5`` server, a client principal, a generated ``krb5.conf`` /
  ``kdc.conf``, a running ``krb5kdc`` daemon, and a kinit'd client credential
  cache.  This is the Kerberos analogue of ``pki_helpers.blitz_test_pki()``.

WHY: the nginx-xrootd krb5 acceptor (``src/auth/krb5/auth.c``) validates a client
  AP-REQ against a keytab and maps the principal via ``auth_to_local`` — none of
  which exists without a realm.  The suite ships no KDC, so this module creates a
  throwaway one, fully isolated from any host ``/etc/krb5.conf`` (every krb5 tool
  is invoked with ``KRB5_CONFIG`` / ``KRB5_KDC_PROFILE`` pointing into TEST_ROOT).

HOW: driven by ``manage_test_servers.sh`` as a tiny CLI — ``up`` (provision +
  start KDC + kinit) and ``down`` (stop KDC).  Fail-open: ``up`` returns a
  non-zero exit only on an unexpected error; when the MIT KDC tooling is simply
  not installed it reports "skipped" and exits 0 so the rest of the suite keeps
  running.  The shell gates the whole tier on tool + binary availability before
  ever calling this; the conftest ``requires_krb5`` fixture skips the tests.

Mirrors ``pki_helpers.py``: a side-effecting "blitz" provisioner (wipe + rebuild)
that communicates state purely through files under TEST_ROOT, with a ``_run``
wrapper that raises ``RuntimeError`` (stdout+stderr embedded) on a non-zero exit.
"""

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

# Self-locate so ``from settings import ...`` works regardless of the caller's
# cwd (the shell invokes us by absolute path, not via PYTHONPATH=tests).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from settings import (  # noqa: E402  (path insert must precede the import)
    HOST,
    KRB5_CCACHE,
    KRB5_CLIENT_KEYTAB,
    KRB5_CLIENT_PRINCIPAL,
    KRB5_CONF,
    KRB5_DIR,
    KRB5_KDC_PORT,
    KRB5_KEYTAB,
    KRB5_REALM,
    KRB5_SERVICE_PRINCIPAL,
)

# ---------------------------------------------------------------------------
# Derived paths + constants
# ---------------------------------------------------------------------------

_DB_DIR = os.path.join(KRB5_DIR, "db")
_KDC_CONF = os.path.join(KRB5_DIR, "kdc.conf")
_ACL_FILE = os.path.join(KRB5_DIR, "kadm5.acl")
_KDC_PID = os.path.join(KRB5_DIR, "krb5kdc.pid")
_KDC_LOG = os.path.join(KRB5_DIR, "krb5kdc.log")
_MASTER_PASSWORD = "masterpw"  # noqa: S105 — throwaway test-realm master key

# MIT KDC binaries usually live in sbin dirs that are not on a non-root PATH.
_TOOL_SEARCH_DIRS = ("/usr/sbin", "/sbin", "/usr/lib/krb5/bin", "/usr/lib64/krb5/bin")
_REQUIRED_TOOLS = ("kdb5_util", "kadmin.local", "krb5kdc", "kinit")


def _find_tool(name):
    """Resolve a krb5 tool to an absolute path, also scanning common sbin dirs."""
    found = shutil.which(name)
    if found:
        return found
    for d in _TOOL_SEARCH_DIRS:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def krb5_tools_available():
    """True only if every binary needed to build + run the test realm is present."""
    return all(_find_tool(t) for t in _REQUIRED_TOOLS)


# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------

def _env():
    """A child environment pinned to the test realm's config (never the host's)."""
    e = os.environ.copy()
    e["KRB5_CONFIG"] = KRB5_CONF
    e["KRB5_KDC_PROFILE"] = _KDC_CONF
    return e


def _run(cmd, stdin=None):
    """Run a command (list argv), raising RuntimeError with full output on failure."""
    result = subprocess.run(
        cmd, input=stdin, capture_output=True, text=True, env=_env()
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result.stdout.strip()


def _kadmin(query):
    """Run a kadmin.local query against the local KDC database (no kadmind needed)."""
    return _run([_find_tool("kadmin.local"), "-r", KRB5_REALM, "-q", query])


def _port_open(host, port, timeout=0.5):
    """True if a TCP connect to host:port succeeds (KDC readiness probe)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Config materialisation
# ---------------------------------------------------------------------------

def _write_configs():
    """Write the realm-isolated krb5.conf + kdc.conf into TEST_ROOT/krb5."""
    # krb5.conf — consumed by BOTH the client (kinit) and the nginx acceptor
    # (krb5_init_context reads default_realm + the auth_to_local default that
    # maps ``alice@REALM`` -> ``alice`` because REALM is the default realm).
    krb5_conf = f"""[libdefaults]
    default_realm = {KRB5_REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    ticket_lifetime = 1h

[realms]
    {KRB5_REALM} = {{
        kdc = {HOST}:{KRB5_KDC_PORT}
        admin_server = {HOST}:{KRB5_KDC_PORT}
    }}

[domain_realm]
    localhost = {KRB5_REALM}
    .localhost = {KRB5_REALM}
"""
    # kdc.conf — consumed by kdb5_util / krb5kdc only.  Both UDP and TCP listen
    # on the same port so the client's UDP-first AS-REQ (and any TCP fallback)
    # both reach the daemon.
    kdc_conf = f"""[kdcdefaults]
    kdc_ports = {KRB5_KDC_PORT}
    kdc_tcp_ports = {KRB5_KDC_PORT}

[realms]
    {KRB5_REALM} = {{
        database_name = {_DB_DIR}/principal
        key_stash_file = {_DB_DIR}/.k5.{KRB5_REALM}
        acl_file = {_ACL_FILE}
        max_life = 1h
        max_renewable_life = 1d
    }}
"""
    Path(KRB5_CONF).write_text(krb5_conf, encoding="utf-8")
    Path(_KDC_CONF).write_text(kdc_conf, encoding="utf-8")
    Path(_ACL_FILE).write_text(f"*/admin@{KRB5_REALM} *\n", encoding="utf-8")


def _service_principals():
    """The service principals to register + export into the keytab.

    The advertised principal (``KRB5_SERVICE_PRINCIPAL``) is what the XRootD krb5
    client requests a ticket for, but some client builds canonicalise the host to
    an FQDN.  Registering both ``xrootd/localhost`` and ``xrootd/<fqdn>`` (when the
    FQDN differs) makes the tier robust to that without changing the advert.
    """
    principals = [KRB5_SERVICE_PRINCIPAL]
    fqdn = socket.getfqdn()
    if fqdn and fqdn not in ("localhost", "localhost.localdomain"):
        fqdn_principal = f"xrootd/{fqdn}@{KRB5_REALM}"
        if fqdn_principal not in principals:
            principals.append(fqdn_principal)
    return principals


# ---------------------------------------------------------------------------
# Lifecycle: provision / start / stop / kinit
# ---------------------------------------------------------------------------

def provision():
    """Blitz the realm: wipe TEST_ROOT/krb5, create the DB, principals, keytab."""
    if os.path.exists(KRB5_DIR):
        shutil.rmtree(KRB5_DIR)
    os.makedirs(_DB_DIR, exist_ok=True)

    _write_configs()

    # Create the KDC database with a stashed master key so krb5kdc starts unattended.
    _run([_find_tool("kdb5_util"), "create", "-r", KRB5_REALM, "-s",
          "-P", _MASTER_PASSWORD])

    # Service principal(s): random key, exported into the keytab the nginx server reads.
    for principal in _service_principals():
        _kadmin(f"addprinc -randkey {principal}")
        _kadmin(f"ktadd -k {KRB5_KEYTAB} {principal}")
    os.chmod(KRB5_KEYTAB, 0o600)

    # Client principal (random key) exported to a client keytab, so the test
    # driver can kinit fully non-interactively (``kinit -k -t``) — no password
    # prompt, no stdin handling, deterministic in CI.
    _kadmin(f"addprinc -randkey {KRB5_CLIENT_PRINCIPAL}")
    _kadmin(f"ktadd -k {KRB5_CLIENT_KEYTAB} {KRB5_CLIENT_PRINCIPAL}")
    os.chmod(KRB5_CLIENT_KEYTAB, 0o600)


def start_kdc(wait_seconds=10.0):
    """Launch krb5kdc (self-daemonising) and block until its port accepts."""
    # Remove a stale pidfile so a crashed prior run can't mask a failed start.
    for stale in (_KDC_PID, _KDC_LOG):
        try:
            os.remove(stale)
        except FileNotFoundError:
            pass
    _run([_find_tool("krb5kdc"), "-r", KRB5_REALM, "-P", _KDC_PID])

    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if _port_open(HOST, KRB5_KDC_PORT):
            return
        time.sleep(0.1)
    raise RuntimeError(
        f"krb5kdc did not open {HOST}:{KRB5_KDC_PORT} within {wait_seconds}s "
        f"(see {_KDC_LOG})"
    )


def stop_kdc():
    """Stop the KDC via its pidfile (best-effort; never raises)."""
    try:
        pid = int(Path(_KDC_PID).read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        return
    try:
        os.kill(pid, 15)  # SIGTERM
    except ProcessLookupError:
        pass
    finally:
        try:
            os.remove(_KDC_PID)
        except FileNotFoundError:
            pass


def kinit_client():
    """Obtain a client TGT into KRB5_CCACHE from the client keytab (no prompt)."""
    _run([_find_tool("kinit"), "-k", "-t", KRB5_CLIENT_KEYTAB,
          "-c", KRB5_CCACHE, KRB5_CLIENT_PRINCIPAL])


def up():
    """Provision + start the KDC + kinit the client.  Returns True on success."""
    if not krb5_tools_available():
        missing = [t for t in _REQUIRED_TOOLS if not _find_tool(t)]
        print(f"krb5 tier: skipped (missing MIT KDC tooling: {', '.join(missing)}; "
              f"install krb5-server)")
        return False
    provision()
    start_kdc()
    kinit_client()
    print(f"krb5 tier: realm {KRB5_REALM} up (kdc :{KRB5_KDC_PORT}, "
          f"keytab {KRB5_KEYTAB})")
    return True


def down():
    """Stop the KDC (files are reclaimed by the session-wide TEST_ROOT wipe)."""
    stop_kdc()


# ---------------------------------------------------------------------------
# CLI entry point (driven by manage_test_servers.sh)
# ---------------------------------------------------------------------------

def main(argv):
    if len(argv) != 1 or argv[0] not in ("up", "down", "provision", "kinit"):
        print("usage: kdc_helpers.py {up|down|provision|kinit}", file=sys.stderr)
        return 2
    cmd = argv[0]
    if cmd == "up":
        # Exit 0 = realm is up; exit 3 = cleanly skipped (no KDC tooling) so the
        # caller knows not to start the nginx krb5 instance.  A real provisioning
        # error propagates as an uncaught exception (non-zero, non-3 exit).
        return 0 if up() else 3
    if cmd == "down":
        down()
        return 0
    if cmd == "provision":
        provision()
        return 0
    if cmd == "kinit":
        kinit_client()
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
