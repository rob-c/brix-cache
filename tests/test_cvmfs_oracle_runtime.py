"""CVMFS oracle containers use explicit commands and isolated runtime state."""

import io
import subprocess
import tarfile

import pytest

import test_cvmfs_ingest_oracle as oracle


def test_rootfs_uses_a_private_runtime_and_resolves_tag_symlinks(tmp_path, monkeypatch):
    """Tag syntax cannot become Podman options or select shared runtime state."""
    rootfs = tmp_path / "content"
    rootfs.mkdir()
    tag = tmp_path / "tiny:1"
    tag.symlink_to(rootfs, target_is_directory=True)
    calls = []
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/not-this-runtime")
    monkeypatch.setattr(oracle, "_pod", lambda *args, **kw: calls.append((args, kw)))
    oracle._rootfs_run_in("podman", tag, tmp_path)
    args, kwargs = calls[0]
    assert args[-3:] == ("--rootfs", f"{rootfs}:O", "/bin/ok")
    assert "migrate" not in args
    for flag, name in (("--root", "graph"), ("--runroot", "run"), ("--tmpdir", "tmp")):
        assert args[args.index(flag) + 1] == tmp_path / name
    assert kwargs["env"]["XDG_RUNTIME_DIR"] == str(tmp_path / "xdg")
    assert all((tmp_path / name).stat().st_mode & 0o777 == 0o700
               for name in ("graph", "run", "tmp", "xdg"))
    assert calls[1][0] == (*args[:-5], "system", "migrate")
    assert calls[1][1]["env"] == kwargs["env"]


def test_rootfs_runtime_is_short_and_removed_after_execution(tmp_path, monkeypatch):
    """The actual runtime allocator respects Podman's socket path limit."""
    from pathlib import Path
    roots = []

    def run_in(_rt, _rootfs, private):
        assert len(str(private / "run")) <= 50
        assert private.is_dir()
        roots.append(private)
        return 23

    monkeypatch.setattr(oracle, "_rootfs_run_in", run_in)
    assert oracle._rootfs_run("podman", tmp_path) == 23
    assert len(roots) == 1 and not Path(roots[0]).exists()


def test_rootfs_preserves_the_runtime_failure(tmp_path, monkeypatch):
    """A failing container remains a failure after private-runtime cleanup."""
    failed = subprocess.CompletedProcess([], 125, b"", b"mount failed")
    monkeypatch.setattr(oracle, "_pod", lambda *args, **kw: failed)
    assert oracle._rootfs_run_in("podman", tmp_path, tmp_path) is failed


def test_rootfs_rejects_preexisting_runtime_symlink(tmp_path, monkeypatch):
    """Untrusted existing state cannot redirect the oracle's storage."""
    victim = tmp_path / "victim"
    victim.mkdir()
    (tmp_path / "graph").symlink_to(victim, target_is_directory=True)
    calls = []
    monkeypatch.setattr(oracle, "_pod", lambda *args, **kw: calls.append(args))
    with pytest.raises(FileExistsError):
        oracle._rootfs_run_in("podman", tmp_path, tmp_path)
    assert calls == [] and list(victim.iterdir()) == []


def _truth_runtime(monkeypatch, create):
    """Record a synthetic pull/create/export transaction without a daemon."""
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as tf:
        member = tarfile.TarInfo("share/extra")
        member.size = 2
        tf.addfile(member, io.BytesIO(b"ok"))
    calls = []

    def pod(_rt, *args, **kwargs):
        calls.append(args)
        if args[0] == "create":
            return create
        return subprocess.CompletedProcess([], 0, payload.getvalue(), b"")

    monkeypatch.setattr(oracle, "_pod", pod)
    return calls


def test_flatten_oracle_supports_images_without_a_default_command(monkeypatch):
    """The flatten-only container supplies its own explicit command."""
    calls = _truth_runtime(monkeypatch, subprocess.CompletedProcess([], 0, b"cid\n", b""))
    truth = oracle._podman_truth("podman")
    assert truth["share/extra"][0] == "file"
    assert calls[1] == ("create", f"{oracle.HOST}:{oracle.MOCK_PORT}/lab/app:v2", "/bin/true")
    assert calls[-1] == ("rm", "cid")


def test_flatten_oracle_reports_create_errors_instead_of_an_empty_id(monkeypatch):
    """The original runtime diagnostic survives an unsuccessful create."""
    calls = _truth_runtime(monkeypatch, subprocess.CompletedProcess([], 125, b"", b"create denied"))
    with pytest.raises(AssertionError, match="create denied"):
        oracle._podman_truth("podman")
    assert [args[0] for args in calls] == ["pull", "create"]


def test_flatten_oracle_does_not_export_an_id_from_a_failed_create(monkeypatch):
    """Output from a failed create is not trusted as a container identifier."""
    calls = _truth_runtime(monkeypatch, subprocess.CompletedProcess([], 125, b"untrusted-id", b"denied"))
    with pytest.raises(AssertionError, match="denied"):
        oracle._podman_truth("podman")
    assert [args[0] for args in calls] == ["pull", "create"]
