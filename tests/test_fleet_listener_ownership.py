"""Hermetic checks for stale fleet-listener ownership recovery."""

from brix_suite import orphans


def test_listener_owned_when_exact_root_process_holds_socket(monkeypatch):
    monkeypatch.setattr(orphans, "_listening_socket_inodes",
                        lambda port: {"41001"})
    monkeypatch.setattr(orphans, "find_orphans",
                        lambda root, exes: [(101, "nginx -p /lane/main")])
    monkeypatch.setattr(orphans, "_process_socket_inodes",
                        lambda pid: {"41001", "41002"})

    assert orphans.listener_owned_by_test_root("/lane", 10005)


def test_listener_without_kernel_socket_is_not_owned(monkeypatch):
    monkeypatch.setattr(orphans, "_listening_socket_inodes", lambda port: set())
    monkeypatch.setattr(orphans, "find_orphans",
                        lambda root, exes: [(101, "nginx -p /lane/main")])

    assert not orphans.listener_owned_by_test_root("/lane", 10005)


def test_foreign_listener_cannot_borrow_stale_owned_process(monkeypatch):
    """Security-negative: argv ownership must intersect the listener inode."""
    monkeypatch.setattr(orphans, "_listening_socket_inodes",
                        lambda port: {"foreign"})
    monkeypatch.setattr(orphans, "find_orphans",
                        lambda root, exes: [(101, "nginx -p /lane/main")])
    monkeypatch.setattr(orphans, "_process_socket_inodes",
                        lambda pid: {"owned-but-not-listening"})

    assert not orphans.listener_owned_by_test_root("/lane", 10005)
