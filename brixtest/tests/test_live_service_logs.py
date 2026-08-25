"""Backend-neutral live service-log access."""

import subprocess

from brixtest.runtime.kubernetes import KubernetesCaseManager
from brixtest.runtime.service import Service


class _LogController:
    def _service_read_log(self, name, *, encoding, errors):
        assert (name, encoding, errors) == ("origin", "utf-8", "replace")
        return "remote-ready\n"


def test_service_reads_live_backend_log_before_archive_exists(tmp_path):
    value = Service(
        "origin", "127.0.0.1", {"primary": 12345}, tmp_path / "config",
        tmp_path / "not-archived.log", tmp_path,
    )
    object.__setattr__(value, "_controller", _LogController())
    assert value.read_log() == "remote-ready\n"


def test_kubernetes_live_log_selects_server_container_and_all_replicas():
    backend = object.__new__(KubernetesCaseManager)
    backend.namespace = "case"
    observed = []

    def execute(*argv, **options):
        observed.append((argv, options))
        return subprocess.CompletedProcess(argv, 0, "pod/origin ready\n", "")

    backend._run = execute
    assert backend.read_log("origin") == "pod/origin ready\n"
    argv, options = observed[0]
    assert ("-l", "app.kubernetes.io/name=origin", "-c", "server") == argv[3:7]
    assert "--prefix=true" in argv and options["timeout"] == 15.0
