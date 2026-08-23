"""MIT Kerberos test-realm creation, KDC lifecycle, keytab, and ticket issuance."""

from __future__ import annotations

import os
import shutil
import socket
import stat
import subprocess
import time
from pathlib import Path
from typing import Dict, Mapping, Optional, TextIO, Tuple

from brixtest.auth.models import KerberosAuth
from brixtest.errors import SpecError

__all__ = ["KerberosRealm", "create_realm"]


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise SpecError("Kerberos recipe", name, "is not installed or not on PATH")
    return path


def _free_port(requested: int) -> Tuple[int, socket.socket]:
    handle = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    handle.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    handle.bind(("127.0.0.1", requested or 0))
    handle.listen(1)
    return int(handle.getsockname()[1]), handle


def _run(argv, env: Mapping[str, str], *, input_text: str = "", timeout: float = 30.0) -> str:
    try:
        result = subprocess.run(
            argv, env={**os.environ, **env}, input=input_text or None,
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SpecError("Kerberos command", " ".join(argv), str(exc)) from exc
    if result.returncode:
        raise SpecError(
            "Kerberos command", " ".join(argv),
            (result.stderr or result.stdout or "command failed").strip(),
        )
    return result.stdout.strip()


def _stop_process(process: Optional[subprocess.Popen]) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2.0)


class KerberosRealm:
    def __init__(
        self, root: Path, files: Mapping[str, Path], env: Mapping[str, str],
        metadata: Mapping[str, object], process: Optional[subprocess.Popen], log,
    ) -> None:
        self.root = root
        self.files = dict(files)
        self.env = dict(env)
        self.metadata = dict(metadata)
        self.process = process
        self._log = log

    def close(self) -> None:
        try:
            _stop_process(self.process)
        finally:
            if self._log is not None:
                self._log.close()


def _configs(root: Path, recipe: KerberosAuth, port: int) -> Tuple[str, str]:
    krb5 = """[libdefaults]
 default_realm = {realm}
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = true
 ticket_lifetime = 1h
[realms]
 {realm} = {{
  kdc = 127.0.0.1:{port}
 }}
[domain_realm]
 .{domain} = {realm}
 {domain} = {realm}
""".format(realm=recipe.realm, domain=recipe.domain, port=port)
    kdc = """[kdcdefaults]
 kdc_listen = 127.0.0.1:{port}
 kdc_tcp_listen = 127.0.0.1:{port}
[realms]
 {realm} = {{
  database_name = {root}/principal
  key_stash_file = {root}/.k5.{realm}
  acl_file = {root}/kadm5.acl
  max_life = 1h
  max_renewable_life = 2h
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
 }}
[logging]
 kdc = FILE:{root}/kdc.log
 default = FILE:{root}/krb5lib.log
""".format(realm=recipe.realm, root=root, port=port)
    return krb5, kdc


def _provision_principals(
    root: Path, recipe: KerberosAuth, env: Mapping[str, str],
) -> tuple[str, str, Path]:
    _run([
        _tool("kdb5_util"), "create", "-s", "-r", recipe.realm,
        "-P", recipe.master_password,
    ], env)
    user_principal = "%s@%s" % (recipe.user, recipe.realm)
    service_principal = "%s@%s" % (recipe.service, recipe.realm)
    admin = _tool("kadmin.local")
    _run([admin, "-r", recipe.realm, "-q", "addprinc -pw %s %s" % (recipe.password, user_principal)], env)
    _run([admin, "-r", recipe.realm, "-q", "addprinc -randkey %s" % service_principal], env)
    keytab = root / "service.keytab"
    _run([admin, "-r", recipe.realm, "-q", "ktadd -k %s %s" % (keytab, service_principal)], env)
    keytab.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return user_principal, service_principal, keytab


def _wait_for_kdc(process: subprocess.Popen, recipe: KerberosAuth, port: int) -> None:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SpecError(
                "Kerberos KDC", recipe.realm,
                "exited before accepting connections",
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise SpecError("Kerberos KDC", recipe.realm, "did not become ready")


def _start_kdc(
    root: Path,
    recipe: KerberosAuth,
    port: int,
    env: Mapping[str, str],
    user_principal: str,
    reservation: socket.socket,
) -> tuple[subprocess.Popen, TextIO, Path]:
    reservation.close()
    log_handle = (root / "kdc-process.log").open("w")
    try:
        process = subprocess.Popen(
            [_tool("krb5kdc"), "-n", "-r", recipe.realm],
            env={**os.environ, **env}, stdout=log_handle, stderr=subprocess.STDOUT,
            text=True, start_new_session=True,
        )
    except OSError as exc:
        log_handle.close()
        raise SpecError("Kerberos KDC", recipe.realm, str(exc)) from exc
    cache = root / "user.ccache"
    try:
        _wait_for_kdc(process, recipe, port)
        _run(
            [_tool("kinit"), "-c", str(cache), user_principal], env,
            input_text=recipe.password + "\n",
        )
        cache.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        _stop_process(process)
        log_handle.close()
        raise
    return process, log_handle, cache


def _empty_cache(root: Path, reservation: socket.socket) -> Path:
    reservation.close()
    cache = root / "user.ccache"
    cache.write_bytes(b"")
    cache.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return cache


def create_realm(root: Path, recipe: KerberosAuth) -> KerberosRealm:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    port, reservation = _free_port(recipe.port)
    krb5_path, kdc_path = root / "krb5.conf", root / "kdc.conf"
    krb5_text, kdc_text = _configs(root, recipe, port)
    krb5_path.write_text(krb5_text)
    kdc_path.write_text(kdc_text)
    (root / "kadm5.acl").write_text("*/admin@%s *\n" % recipe.realm)
    env = {"KRB5_CONFIG": str(krb5_path), "KRB5_KDC_PROFILE": str(kdc_path)}
    try:
        user_principal, service_principal, keytab = _provision_principals(
            root, recipe, env,
        )
    except Exception:
        reservation.close()
        raise
    process: Optional[subprocess.Popen] = None
    log_handle: Optional[TextIO] = None
    if recipe.start_kdc:
        process, log_handle, cache = _start_kdc(
            root, recipe, port, env, user_principal, reservation,
        )
    else:
        cache = _empty_cache(root, reservation)
    files: Dict[str, Path] = {
        "config": krb5_path, "kdc_config": kdc_path, "keytab": keytab,
        "cache": cache, "database": root / "principal",
    }
    metadata = {
        "realm": recipe.realm, "domain": recipe.domain, "hostname": recipe.hostname,
        "port": port, "user_principal": user_principal,
        "service_principal": service_principal,
    }
    return KerberosRealm(root, files, env, metadata, process, log_handle)
