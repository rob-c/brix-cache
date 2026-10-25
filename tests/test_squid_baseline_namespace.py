"""Squid baseline instances use short, private, consistent SHM namespaces."""
from types import SimpleNamespace

from cmdscripts import cvmfs_matrix
from settings import HOST, url_host


def _startup(tmp_path, monkeypatch, port):
    commands = []
    root = tmp_path / str(port)
    work = root / "work"
    work.mkdir(parents=True)
    def write(path, content):
        path.write_text(content)
        return path
    run = SimpleNamespace(root=root, write=write,
                          call=lambda argv, **kwargs: commands.append(argv))
    monkeypatch.setattr(cvmfs_matrix.shutil, "which", lambda name: "/tools/" + name)
    runtime = cvmfs_matrix._start_squid(run, port, HOST, f"{url_host(HOST)}:9000", work)
    return commands, runtime[0]


def test_squid_namespace_fits_darwin_shm_limit(tmp_path, monkeypatch):
    commands, _ = _startup(tmp_path, monkeypatch, 65535)
    service = commands[0][commands[0].index("-n") + 1]
    assert len(f"/{service}-GG5U-cf__metadata.shm") <= 31


def test_initialization_start_and_shutdown_use_the_same_namespace(tmp_path, monkeypatch):
    commands, shutdown = _startup(tmp_path, monkeypatch, 11094)
    names = [argv[argv.index("-n") + 1] for argv in [*commands, shutdown]]
    assert len(set(names)) == 1


def test_parallel_instances_cannot_share_system_or_sibling_namespace(tmp_path, monkeypatch):
    first, _ = _startup(tmp_path, monkeypatch, 11094)
    second, _ = _startup(tmp_path, monkeypatch, 11095)
    names = [argv[0][argv[0].index("-n") + 1] for argv in (first, second)]
    assert names[0] != names[1]
    assert "squid" not in names
