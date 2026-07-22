"""LiveRun teardown must reap leftover FUSE mounts before removing its tree.

A scenario killed mid-mount (pytest-timeout, crash) leaves a daemonized
cvmfs2/brixcvmfs mount whose dead FUSE connection wedges the first rmtree to
walk into it — including the whole session teardown sweeping /tmp/xrd-test.
These tests pin the reaper hermetically: no real mount, daemon, or kill.
"""

import os
from pathlib import Path

import pytest

from cmdscripts import fake_nginx, fake_nginx_broken, live_common

_TR = os.environ.get("TEST_ROOT", "/tmp/xrd-test")


@pytest.fixture
def reaper_probe(monkeypatch):
    """Record every external action the reaper takes against a fake world."""
    actions = {"run": [], "killed": []}

    def fake_run(argv, **kwargs):
        actions["run"].append([str(a) for a in argv])
        if argv[0] == "pgrep":
            import subprocess
            return subprocess.CompletedProcess(argv, 0, stdout=actions.get("pgrep_out", ""))
        import subprocess
        return subprocess.CompletedProcess(argv, 0, stdout="")

    monkeypatch.setattr(live_common.subprocess, "run", fake_run)
    monkeypatch.setattr(live_common.os, "kill",
                        lambda pid, sig: actions["killed"].append(pid))
    monkeypatch.setattr(live_common.shutil, "which", lambda name: "/bin/" + name)
    return actions


def _mock_mounts(monkeypatch, sequence):
    """_fuse_mounts_under returns each list in sequence, then the last forever."""
    calls = {"n": 0}

    def fake(prefix):
        idx = min(calls["n"], len(sequence) - 1)
        calls["n"] += 1
        return sequence[idx]

    monkeypatch.setattr(live_common, "_fuse_mounts_under", fake)


def test_reaper_unmounts_and_kills_the_orphan_daemon(monkeypatch, reaper_probe):
    root = Path(_TR + "/tmp/cvmfs_bench.fake")
    _mock_mounts(monkeypatch, [[f"{root}/sm15"], []])
    reaper_probe["pgrep_out"] = "4242\n"

    live_common._reap_fuse_mounts(root)

    assert ["/bin/fusermount3", "-uz", f"{root}/sm15"] in reaper_probe["run"]
    assert any(argv[0] == "pgrep" for argv in reaper_probe["run"])
    assert reaper_probe["killed"] == [4242]


def test_reaper_is_a_noop_without_leftover_mounts(monkeypatch, reaper_probe):
    _mock_mounts(monkeypatch, [[]])
    live_common._reap_fuse_mounts(Path(_TR + "/tmp/clean.fake"))
    assert reaper_probe["run"] == []
    assert reaper_probe["killed"] == []


def test_reaper_never_kills_its_own_process_or_garbage_pids(monkeypatch, reaper_probe):
    """The pgrep sweep must skip the running interpreter and unparseable rows."""
    import os as real_os
    root = Path(_TR + "/tmp/cvmfs_bench.fake2")
    _mock_mounts(monkeypatch, [[f"{root}/sm0"], []])
    reaper_probe["pgrep_out"] = f"{real_os.getpid()}\nnot-a-pid\n5151\n"

    live_common._reap_fuse_mounts(root)

    assert reaper_probe["killed"] == [5151]


def test_close_reaps_before_removing_the_tree(monkeypatch, tmp_path):
    """The sweep must happen before rmtree — a dead mount wedges the walk."""
    order = []
    monkeypatch.setattr(live_common, "_reap_fuse_mounts",
                        lambda root: order.append("reap"))
    monkeypatch.setattr(live_common.shutil, "rmtree",
                        lambda *a, **k: order.append("rmtree"))
    monkeypatch.setattr(live_common, "freeze_nginx", lambda src: Path("/bin/true"))
    monkeypatch.delenv("BRIX_LIVE_KEEP_TREE", raising=False)

    with live_common.LiveRun("reaper_order", nginx="/bin/true"):
        pass

    assert order == ["reap", "rmtree"]


def test_fuse_mounts_under_parses_proc_mounts(monkeypatch):
    fake = (
        f"/dev/fuse {_TR}/tmp/cvmfs_bench.x/sm15 fuse ro 0 0\n"
        "portal /run/user/1000/doc fuse.portal rw 0 0\n"
        f"/dev/sda1 {_TR}/tmp/cvmfs_bench.x/other ext4 rw 0 0\n"
        "garbage-line\n"
    )
    monkeypatch.setattr(live_common.Path, "read_text",
                        lambda self, *a, **k: fake)
    points = live_common._fuse_mounts_under(_TR + "/tmp/cvmfs_bench.x/")
    assert points == [_TR + "/tmp/cvmfs_bench.x/sm15"]


# --------------------------------------------------------------------------- #
# freeze_nginx — the launcher-wide relink shield (round-7 EACCES storm).
# --------------------------------------------------------------------------- #
@pytest.fixture
def fresh_freeze(monkeypatch, tmp_path):
    """Reset the per-process freeze cache and drop retry sleeps.

    Also point ``_FREEZE_ROOT`` at a private dir: this pytest process has a
    REAL frozen nginx at the default root (the conftest fleet machinery froze
    it), and copying a fake binary onto a path being exec'd fails ETXTBSY —
    and would clobber the session's live binary if it succeeded.
    """
    monkeypatch.setattr(live_common, "_FROZEN_NGINX", None)
    monkeypatch.setattr(live_common, "_FREEZE_ROOT", tmp_path / "freeze-root")
    monkeypatch.setattr(live_common.time, "sleep", lambda s: None)


def test_freeze_nginx_returns_validated_private_copy(fresh_freeze, tmp_path):
    src = Path(fake_nginx.install(tmp_path))
    frozen = live_common.freeze_nginx(src)
    assert frozen != src, "must exec a private copy, not the relinkable source"
    assert frozen.read_bytes() == src.read_bytes()
    assert live_common.freeze_nginx(src) == frozen, "second call must hit the cache"


def test_freeze_nginx_is_session_shared_not_per_process(fresh_freeze, tmp_path):
    # Every process of a session must resolve to ONE shared copy: the path is
    # deterministic (no pid), and a second process (cache reset) reuses the
    # first's frozen binary instead of making its own — the single-binary model.
    src = Path(fake_nginx.install(tmp_path))
    first = live_common.freeze_nginx(src)
    assert f"-{os.getpid()}" not in first.name, "frozen path must not be per-process"
    live_common._FROZEN_NGINX = None  # simulate a fresh xdist worker process
    second = live_common.freeze_nginx(src)
    assert second == first, "a second process must reuse the shared frozen copy"


def test_freeze_nginx_missing_source_falls_back_to_live_path(fresh_freeze, tmp_path):
    src = tmp_path / "no-such-nginx"
    assert live_common.freeze_nginx(src) == src
    assert live_common._FROZEN_NGINX is None


def test_freeze_nginx_never_caches_a_broken_binary(fresh_freeze, tmp_path):
    # A source caught mid-relink copies fine but fails validation (-v != 0);
    # the freeze must refuse to pin it and fall back rather than serve a
    # half-written binary for the rest of the session.
    src = Path(fake_nginx_broken.install(tmp_path))
    assert live_common.freeze_nginx(src) == src
    assert live_common._FROZEN_NGINX is None


def test_launcher_nginx_bin_routes_through_freeze(monkeypatch):
    import server_launcher
    monkeypatch.setattr(live_common, "freeze_nginx",
                        lambda src: Path("/tmp/frozen-sentinel/nginx"))
    assert server_launcher._nginx_bin() == "/tmp/frozen-sentinel/nginx"

def test_freeze_root_default_ignores_tmpdir():
    # Round-8 regression: the freeze target used tempfile.gettempdir(), which
    # honours the lane's TMPDIR=/tmp/xrd-test/tmp — inside pytest's basetemp
    # garbage-rotation blast radius, so the frozen copy was rm -rf'd under a
    # running lane (every subsequent nginx exec failed rc=1). The default
    # root must be literal /tmp, never derived from TMPDIR.
    assert live_common._FREEZE_ROOT == Path("/tmp")


def test_freeze_nginx_honours_freeze_root_not_tmpdir(fresh_freeze, tmp_path,
                                                     monkeypatch):
    # The copy must land under _FREEZE_ROOT even when TMPDIR points elsewhere.
    monkeypatch.setenv("TMPDIR", str(tmp_path / "rotated-tmpdir"))
    src = Path(fake_nginx.install(tmp_path))
    frozen = live_common.freeze_nginx(src)
    assert frozen != src
    assert not str(frozen).startswith(str(tmp_path / "rotated-tmpdir"))
    assert str(frozen).startswith(str(tmp_path / "freeze-root"))


def test_registry_command_failure_survives_reraise():
    # Round-8 regression: the exception was a frozen dataclass, so Python's
    # own `exc.__traceback__ = tb` on re-raise (contextlib __exit__, `raise
    # ... from`) blew up with FrozenInstanceError and MASKED the real launch
    # failure. The exception must round-trip through a context manager intact.
    import contextlib

    from server_launcher import RegistryCommandFailure

    err = RegistryCommandFailure(
        config_path="c", logs_dir="l", command=("nginx", "-t"),
        returncode=1, stdout_tail="", stderr_tail="boom",
    )

    @contextlib.contextmanager
    def passthrough():
        yield

    with pytest.raises(RegistryCommandFailure) as excinfo:
        with passthrough():
            raise err
    assert excinfo.value is err
    assert "boom" in str(excinfo.value)
