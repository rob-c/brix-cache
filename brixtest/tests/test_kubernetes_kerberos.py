"""First-class Kubernetes Kerberos authority contracts."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from brixtest import kerberos_auth, server
from brixtest.auth.kerberos import _configs, kdc_projection
from brixtest.auth.store import AuthStore
from brixtest.runtime.kubernetes_auth import KubernetesKDC, _documents
from brixtest.runtime.kubernetes_network import network_policy_resources


class _Reservation:
    def close(self):
        pass


def _fake_realm(monkeypatch, tmp_path):
    monkeypatch.setattr("brixtest.auth.kerberos._tool", lambda name: name)
    monkeypatch.setattr(
        "brixtest.auth.kerberos._free_port", lambda requested: (18488, _Reservation()),
    )

    def run(argv, env, **options):
        root = Path(env["KRB5_KDC_PROFILE"]).parent
        if argv[1:2] == ["create"]:
            (root / "principal").write_bytes(b"realm-database")
            (root / ".k5.BRIXTEST.TEST").write_bytes(b"stash")
        query = str(argv[-1])
        if query.startswith("ktadd -k "):
            Path(query.split()[2]).write_bytes(b"service-keytab")
        return ""

    monkeypatch.setattr("brixtest.auth.kerberos._run", run)
    store = AuthStore(tmp_path / "auth")
    item = store.materialize(kerberos_auth(start_kdc=False))
    return store, item


def test_kubernetes_configs_use_service_dns_and_dual_transport_listener(tmp_path):
    recipe = kerberos_auth(name="realm", realm="AUTH.TEST")
    local, _ = _configs(tmp_path, recipe, 18488)
    store_root = Path("/realm")
    from brixtest.auth.kerberos import _client_config, _kdc_config

    remote = _client_config(recipe, 18488, "kdc-realm")
    kdc = _kdc_config(store_root, recipe, 18488, "0.0.0.0")

    assert "kdc = 127.0.0.1:18488" in local
    assert "kdc = kdc-realm:18488" in remote
    assert "kdc_listen = 0.0.0.0:18488" in kdc
    assert "kdc_tcp_listen = 0.0.0.0:18488" in kdc


def test_remote_role_environment_selects_remote_config_only(tmp_path, monkeypatch):
    store, item = _fake_realm(monkeypatch, tmp_path)
    remote = Path("/brixtest/secure/auth")

    assert store.environment("test")["KRB5_CONFIG"] == str(item.files["config"])
    assert store.environment("server", remote)["KRB5_CONFIG"].endswith(
        "/kerberos/krb5-kubernetes.conf"
    )
    server_files = store.files_for("server")
    assert "kerberos/krb5-kubernetes.conf" in server_files
    assert all("user.ccache" not in name for name in server_files)


def test_kdc_projection_excludes_client_cache_and_service_keytab(tmp_path, monkeypatch):
    _, item = _fake_realm(monkeypatch, tmp_path)
    realm = getattr(item, "_authority_controller")

    projected = kdc_projection(realm)

    assert {"principal", ".k5.BRIXTEST.TEST", "kdc-kubernetes.conf"} <= set(projected)
    assert "user.ccache" not in projected
    assert "service.keytab" not in projected


@pytest.fixture
def kdc_documents(tmp_path, monkeypatch):
    _, item = _fake_realm(monkeypatch, tmp_path)
    realm = getattr(item, "_authority_controller")
    backend = SimpleNamespace(namespace="case")
    recipe = kerberos_auth(start_kdc=False)
    return _documents(
        backend, recipe, realm, "brixtest.local/kdc:sha256-" + "a" * 64,
        "/opt/brixtest/bin/kdc", "/opt/brixtest/bin/cp",
    )


def test_kdc_manifest_has_tcp_and_udp_service(kdc_documents):
    name, documents = kdc_documents
    secret, deployment, service = documents
    protocols = {item["protocol"] for item in service["spec"]["ports"]}

    assert name == "kdc-kerberos"
    assert deployment["spec"]["replicas"] == 0
    assert protocols == {"TCP", "UDP"}
    assert secret["metadata"]["namespace"] == "case"


def test_kdc_seed_is_writable_after_copy(kdc_documents):
    _, documents = kdc_documents
    deployment = documents[1]
    for entry in deployment["spec"]["template"]["spec"]["volumes"][0]["secret"]["items"]:
        assert entry["mode"] == 0o600


def test_kdc_seed_has_no_client_or_server_identity(kdc_documents):
    _, documents = kdc_documents
    deployment = documents[1]
    paths = {
        item["path"]
        for item in deployment["spec"]["template"]["spec"]["volumes"][0]["secret"]["items"]
    }
    assert "user.ccache" not in paths
    assert "service.keytab" not in paths


def test_declared_network_policy_allows_only_named_kdc_tcp_and_udp():
    declaration = server("origin", command=("server",), ports={"http": 8080})
    policy = network_policy_resources(
        declaration, "case", {"http": 8080}, {}, {"kerberos": 18488},
    )[0]
    authority = policy["spec"]["egress"][0]

    assert authority["to"][0]["podSelector"]["matchLabels"] == {
        "brixtest.io/authority": "kerberos",
    }
    assert authority["ports"] == [
        {"port": 18488, "protocol": "TCP"},
        {"port": 18488, "protocol": "UDP"},
    ]


class _Local:
    def __init__(self):
        self.running = True
        self.metadata = {"port": 18488}

    def available(self):
        return self.running

    def stop(self):
        self.running = False

    def start(self):
        self.running = True


class _Backend:
    namespace = "case"

    def __init__(self, tmp_path):
        self.calls = []
        self.owner = SimpleNamespace(root=tmp_path, evidence=SimpleNamespace(
            attach=lambda *args, **kwargs: None,
            attach_json=lambda *args, **kwargs: None,
        ))

    def _run(self, *args, **options):
        self.calls.append(args)
        if "get" in args:
            return SimpleNamespace(stdout=json.dumps({"status": {"readyReplicas": 1}}))
        return SimpleNamespace(stdout="kdc-log\n")


def test_kubernetes_kdc_control_scales_remote_and_local_authority(tmp_path):
    backend = _Backend(tmp_path)
    local = _Local()
    controller = KubernetesKDC(
        backend, SimpleNamespace(name="kerberos"), local, "kdc-kerberos", {},
    )

    assert controller.available()
    controller.stop()
    assert not local.running
    controller.start()
    assert local.running
    assert any("--replicas=0" in call for call in backend.calls)
    assert any("--replicas=1" in call for call in backend.calls)
