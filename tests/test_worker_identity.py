"""Per-config nginx worker identity resolution tests."""

from types import SimpleNamespace

from brix_suite import worker_identity


def test_omitted_user_uses_packaged_nginx_build_identity(tmp_path, monkeypatch):
    config = tmp_path / "nginx.conf"
    config.write_text("events {}\n", encoding="utf-8")
    probe = SimpleNamespace(stdout="", stderr="configure --user=nginx --group=nginx")
    monkeypatch.setattr(worker_identity.subprocess, "run", lambda *a, **k: probe)

    assert worker_identity.nginx_worker_user(str(config), "/usr/sbin/nginx") == "nginx"


def test_default_worker_identity_falls_back_when_binary_has_no_build_user(monkeypatch):
    probe = SimpleNamespace(stdout="", stderr="configure arguments: --with-debug")
    monkeypatch.setattr(worker_identity.subprocess, "run", lambda *a, **k: probe)
    monkeypatch.setenv("BRIX_WORKER_USER", "service-fallback")

    assert worker_identity.nginx_default_worker_user("nginx") == "service-fallback"


def test_default_worker_group_uses_accounts_primary_group(monkeypatch):
    monkeypatch.setattr(worker_identity, "nginx_default_worker_user",
                        lambda binary: "nobody")
    monkeypatch.setattr(worker_identity.pwd, "getpwnam",
                        lambda user: SimpleNamespace(pw_gid=65534))
    monkeypatch.setattr(worker_identity.grp, "getgrgid",
                        lambda gid: SimpleNamespace(gr_name="nogroup"))

    assert worker_identity.nginx_default_worker_group("nginx") == "nogroup"


def test_default_worker_group_fails_closed_to_named_fallback(monkeypatch):
    monkeypatch.setattr(worker_identity, "nginx_default_worker_user",
                        lambda binary: "missing-user")
    monkeypatch.setattr(worker_identity.pwd, "getpwnam",
                        lambda user: (_ for _ in ()).throw(KeyError(user)))
    monkeypatch.setenv("BRIX_WORKER_GROUP", "safe-workers")

    assert worker_identity.nginx_default_worker_group("nginx") == "safe-workers"


def test_explicit_safe_user_overrides_binary_default(tmp_path, monkeypatch):
    config = tmp_path / "nginx.conf"
    config.write_text("user service;\nevents {}\n", encoding="utf-8")
    monkeypatch.setattr(
        worker_identity, "_compiled_user", lambda binary: "should-not-be-read"
    )

    assert worker_identity.nginx_worker_user(str(config), "nginx") == "service"


def test_explicit_root_fails_closed_to_module_fallback(tmp_path, monkeypatch):
    config = tmp_path / "nginx.conf"
    config.write_text("# user attacker;\nuser root;\nevents {}\n", encoding="utf-8")
    monkeypatch.setenv("BRIX_WORKER_USER", "nobody")
    monkeypatch.setattr(
        worker_identity, "_compiled_user", lambda binary: "should-not-be-read"
    )

    assert worker_identity.nginx_worker_user(str(config), "nginx") == "nobody"
