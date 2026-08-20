"""Kerberos realm configuration, issuance, and lifecycle tests (061-070)."""

import io
import subprocess
from pathlib import Path

import pytest

from brixtest import kerberos_auth
from brixtest.auth.kerberos import KerberosRealm, _configs, _run, create_realm
from brixtest.auth.store import AuthStore
from brixtest.errors import SpecError


class Reservation:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _fake_realm_tools(monkeypatch):
    monkeypatch.setattr("brixtest.auth.kerberos._tool", lambda name: name)
    monkeypatch.setattr("brixtest.auth.kerberos._free_port", lambda requested: (12345, Reservation()))

    def fake_run(argv, env, **kwargs):
        query = argv[-1]
        if isinstance(query, str) and query.startswith("ktadd -k "):
            Path(query.split()[2]).write_bytes(b"keytab")
        return ""

    monkeypatch.setattr("brixtest.auth.kerberos._run", fake_run)


def test_061_krb5_config_defines_realm_domain_and_dynamic_port(tmp_path):
    recipe = kerberos_auth(realm="AUTH.TEST", domain="auth.test")
    krb5, _ = _configs(tmp_path, recipe, 12345)
    assert "default_realm = AUTH.TEST" in krb5
    assert "kdc = 127.0.0.1:12345" in krb5
    assert ".auth.test = AUTH.TEST" in krb5


def test_062_kdc_config_confines_database_and_logs(tmp_path):
    _, kdc = _configs(tmp_path, kerberos_auth(realm="AUTH.TEST"), 12345)
    assert "database_name = %s/principal" % tmp_path in kdc
    assert "kdc = FILE:%s/kdc.log" % tmp_path in kdc


def test_063_offline_realm_creates_config_keytab_and_cache(tmp_path, monkeypatch):
    _fake_realm_tools(monkeypatch)
    realm = create_realm(tmp_path / "realm", kerberos_auth(start_kdc=False))
    assert realm.files["config"].is_file()
    assert realm.files["keytab"].read_bytes() == b"keytab"
    assert realm.files["cache"].read_bytes() == b""


def test_064_realm_metadata_names_principals(tmp_path, monkeypatch):
    _fake_realm_tools(monkeypatch)
    realm = create_realm(
        tmp_path / "realm",
        kerberos_auth(realm="AUTH.TEST", user="alice", service="host/server.auth.test", start_kdc=False),
    )
    assert realm.metadata["user_principal"] == "alice@AUTH.TEST"
    assert realm.metadata["service_principal"] == "host/server.auth.test@AUTH.TEST"


def test_065_auth_store_hands_keytab_only_to_server(tmp_path, monkeypatch):
    _fake_realm_tools(monkeypatch)
    item = AuthStore(tmp_path / "auth").materialize(kerberos_auth(start_kdc=False))
    assert "KRB5_KTNAME" in item.server_env
    assert "KRB5_KTNAME" not in item.client_env
    assert "KRB5CCNAME" in item.client_env


def test_066_missing_kerberos_tool_is_actionable(monkeypatch):
    monkeypatch.setattr("brixtest.auth.kerberos.shutil.which", lambda name: None)
    with pytest.raises(SpecError, match="not installed"):
        from brixtest.auth.kerberos import _tool
        _tool("kdb5_util")


def test_067_kerberos_command_error_includes_stderr(monkeypatch):
    monkeypatch.setattr(
        "brixtest.auth.kerberos.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 1, stdout="", stderr="database error"),
    )
    with pytest.raises(SpecError, match="database error"):
        _run(["kdb5_util", "create"], {})


def test_068_kerberos_command_timeout_is_wrapped(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("kinit", 30)

    monkeypatch.setattr("brixtest.auth.kerberos.subprocess.run", timeout)
    with pytest.raises(SpecError, match="timed out"):
        _run(["kinit"], {})


def test_069_realm_close_terminates_running_kdc(tmp_path):
    class Process:
        def __init__(self):
            self.terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            return 0

    process = Process()
    realm = KerberosRealm(tmp_path, {}, {}, {}, process, io.StringIO())
    realm.close()
    assert process.terminated


def test_070_realm_close_kills_kdc_after_termination_timeout(tmp_path):
    class Process:
        def __init__(self):
            self.waits = 0
            self.killed = False

        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, timeout):
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired("krb5kdc", timeout)
            return 0

        def kill(self):
            self.killed = True

    process = Process()
    KerberosRealm(tmp_path, {}, {}, {}, process, io.StringIO()).close()
    assert process.killed and process.waits == 2
