"""Native role spelling never substitutes for listener and lane ownership."""
import pytest

from brix_suite.launcher import control_operations as control
from lib_py.process_host import nginx_worker_title


@pytest.mark.parametrize("title", [
    b"nginx: worker process", b"nginx: worker process is shutting down",
    b"nginx-80fda96b: worker process",
    b"nginx-80fda96b: worker process (nginx-80fda96b)",
    b"nginx-80fda96b: worker process is shutting down (nginx-80fda96b)\n",
])
def test_native_worker_titles_are_recognized(title):
    assert nginx_worker_title(title)


@pytest.mark.parametrize("title", [
    b"", b"nginx: cache manager process", b"nginx: master process",
    b"python -c 'nginx: worker process'", b"nginx: worker process helper",
    b"notnginx: worker process", b"nginx-malicious: worker process",
    b"nginx-80fda96b: worker process (another-program)",
])
def test_unrelated_and_malformed_titles_are_not_workers(title):
    assert not nginx_worker_title(title)


def test_reaper_does_not_signal_a_foreign_native_worker(monkeypatch):
    """A valid BSD worker title cannot bypass either ownership intersection."""
    monkeypatch.setattr(control, "_candidate_pids", lambda *args: {101})
    queried, killed = [], []

    def title(pid):
        queried.append(pid)
        return b"nginx-80fda96b: worker process (nginx-80fda96b)"

    monkeypatch.setattr(control, "_process_title", title)
    monkeypatch.setattr("lib_py.util.kill_pid_list", lambda pids: killed.extend(pids))
    control.reap_orphan_nginx_workers(object(), lambda spec: [12345])
    assert queried == killed == [101]
    monkeypatch.setattr(control, "_candidate_pids", lambda *args: set())
    queried.clear()
    control.reap_orphan_nginx_workers(object(), lambda spec: [12345])
    assert queried == [] and killed == [101]
