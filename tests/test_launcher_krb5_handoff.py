"""The launcher hands over only the worker-consumed shared Kerberos keytab."""

from brix_suite import settings
from brix_suite.launcher.start_operations import _config_paths


def _paths(tmp_path, monkeypatch, body):
    realm = tmp_path / "krb5"
    realm.mkdir()
    service = realm / "service.keytab"
    client = realm / "client.keytab"
    service.write_bytes(b"service")
    client.write_bytes(b"client")
    config = tmp_path / "nginx.conf"
    config.write_text(body.format(service=service, client=client), encoding="utf-8")
    monkeypatch.setattr(settings, "TEST_ROOT", str(tmp_path))
    monkeypatch.setattr(settings, "KRB5_DIR", str(realm))
    return list(_config_paths(str(config))), service, client


def test_service_keytab_crosses_session_artifact_boundary(tmp_path, monkeypatch):
    paths, service, _client = _paths(
        tmp_path, monkeypatch, "brix_krb5_keytab {service};\n"
    )

    assert paths == [("brix_krb5_keytab", str(service))]


def test_client_keytab_remains_excluded_from_worker_handoff(tmp_path, monkeypatch):
    paths, _service, _client = _paths(
        tmp_path, monkeypatch, "unrelated_client_credential {client};\n"
    )

    assert paths == []


def test_comments_cannot_smuggle_session_credential_into_handoff(tmp_path, monkeypatch):
    paths, _service, _client = _paths(
        tmp_path, monkeypatch, "# brix_krb5_keytab {client};\nevents {{}}\n"
    )

    assert paths == []
