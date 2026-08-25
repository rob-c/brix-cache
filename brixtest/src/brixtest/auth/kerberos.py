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

__all__ = ["KerberosRealm", "create_realm", "kdc_projection"]


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
        self.recipe: Optional[KerberosAuth] = None

    def bind(self, recipe: KerberosAuth) -> "KerberosRealm":
        """Retain the immutable recipe required for later KDC restarts."""
        self.recipe = recipe
        return self

    def available(self) -> bool:
        """Return whether the managed KDC process and TCP endpoint are live."""
        if self.process is None or self.process.poll() is not None:
            return False
        try:
            with socket.create_connection(
                ("127.0.0.1", int(self.metadata["port"])), timeout=0.2,
            ):
                return True
        except OSError:
            return False

    def stop(self) -> None:
        """Stop the KDC promptly while retaining its database and credentials."""
        _stop_process(self.process)
        self.process = None
        if self._log is not None:
            self._log.close()
            self._log = None

    def start(self) -> None:
        """Restart a stopped KDC from the retained realm database."""
        if self.available():
            return
        if self.recipe is None:
            raise SpecError("Kerberos KDC", self.root, "has no restart recipe")
        process, log_handle = _restart_kdc(
            self.root, self.recipe, self.env, int(self.metadata["port"]),
        )
        self.process = process
        self._log = log_handle

    def close(self) -> None:
        self.stop()


def _configs(root: Path, recipe: KerberosAuth, port: int) -> Tuple[str, str]:
    return (
        _client_config(recipe, port, "127.0.0.1"),
        _kdc_config(root, recipe, port, "127.0.0.1"),
    )


def _client_config(recipe: KerberosAuth, port: int, host: str) -> str:
    return """[libdefaults]
 default_realm = {realm}
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = true
 ticket_lifetime = 1h
[realms]
 {realm} = {{
  kdc = {host}:{port}
 }}
[domain_realm]
 .{domain} = {realm}
 {domain} = {realm}
""".format(realm=recipe.realm, domain=recipe.domain, host=host, port=port)


def _kdc_config(
    root: Path, recipe: KerberosAuth, port: int, listen: str, *, stream_logs: bool = False,
) -> str:
    logging = "STDERR" if stream_logs else "FILE:%s/kdc.log" % root
    default_log = "STDERR" if stream_logs else "FILE:%s/krb5lib.log" % root
    return """[kdcdefaults]
 kdc_listen = {listen}:{port}
 kdc_tcp_listen = {listen}:{port}
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
 kdc = {logging}
 default = {default_log}
""".format(
        realm=recipe.realm, root=root, listen=listen, port=port,
        logging=logging, default_log=default_log,
    )


def _kubernetes_configs(root: Path, recipe: KerberosAuth, port: int) -> tuple[Path, Path]:
    service = "kdc-%s" % recipe.name.replace("_", "-")
    client = root / "krb5-kubernetes.conf"
    kdc = root / "kdc-kubernetes.conf"
    client.write_text(_client_config(recipe, port, service))
    kdc.write_text(_kdc_config(
        Path("/realm"), recipe, port, "0.0.0.0", stream_logs=True,
    ))
    return client, kdc


def _database_files(root: Path) -> Dict[str, Path]:
    paths = sorted({*root.glob("principal*"), *root.glob(".k5.*")})
    return {
        "kdc_data_%04d" % index: path
        for index, path in enumerate(paths) if path.is_file()
    }


def kdc_projection(realm: KerberosRealm) -> Mapping[str, Path]:
    """Return only the files needed by a remote KDC, never client credentials."""
    selected = {
        "krb5-kubernetes.conf": realm.files["kubernetes_config"],
        "kdc-kubernetes.conf": realm.files["kubernetes_kdc_config"],
        "kadm5.acl": realm.root / "kadm5.acl",
    }
    selected.update({path.name: path for path in _database_files(realm.root).values()})
    return selected


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
        process = _launch_kdc(root, recipe, env, log_handle)
    except Exception:
        log_handle.close()
        raise
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


def _launch_kdc(root, recipe, env, log_handle) -> subprocess.Popen:
    try:
        return subprocess.Popen(
            [_tool("krb5kdc"), "-n", "-r", recipe.realm],
            cwd=root, env={**os.environ, **env}, stdout=log_handle,
            stderr=subprocess.STDOUT, text=True, start_new_session=True,
        )
    except OSError as exc:
        raise SpecError("Kerberos KDC", recipe.realm, str(exc)) from exc


def _restart_kdc(root, recipe, env, port) -> tuple[subprocess.Popen, TextIO]:
    log_handle = (root / "kdc-process.log").open("a")
    process = None
    try:
        process = _launch_kdc(root, recipe, env, log_handle)
        _wait_for_kdc(process, recipe, port)
    except Exception:
        _stop_process(process)
        log_handle.close()
        raise
    return process, log_handle


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
    kubernetes_config, kubernetes_kdc_config = _kubernetes_configs(
        root, recipe, port,
    )
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
        "kubernetes_config": kubernetes_config,
        "kubernetes_kdc_config": kubernetes_kdc_config,
    }
    files.update(_database_files(root))
    metadata = {
        "realm": recipe.realm, "domain": recipe.domain, "hostname": recipe.hostname,
        "port": port, "user_principal": user_principal,
        "service_principal": service_principal,
    }
    return KerberosRealm(root, files, env, metadata, process, log_handle).bind(recipe)
