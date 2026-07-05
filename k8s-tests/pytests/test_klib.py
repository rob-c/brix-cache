"""klib svc_* logic against an in-memory backend (no cluster). The ``svc`` fixture
binds the service + data dir, so each test is a round-trip in one or two lines.
"""
import base64

import klib
import pytest


def test_write_read_round_trips_binary(svc):
    blob = bytes(range(256)) * 4
    svc.write("b.bin", blob)
    assert svc.read("b.bin") == blob


def test_write_accepts_str(svc):
    svc.write("t.txt", "hello\n")
    assert svc.read("t.txt") == b"hello\n"


def test_read_missing_raises(svc):
    with pytest.raises(FileNotFoundError):
        svc.read("nope")


def test_exists_isfile_isdir(svc):
    svc.write("f", b"x"); svc.mkdir("d")
    assert svc.isfile("f") and not svc.isdir("f")
    assert svc.isdir("d") and not svc.exists("missing")


def test_listdir(svc):
    svc.write("one", b"1"); svc.write("two", b"2")
    assert {"one", "two"} <= set(svc.listdir())


def test_rm_and_rmtree(svc):
    svc.write("f", b"x"); svc.mkdir("d"); svc.write("d/child", b"y")
    svc.rm("f"); svc.rmtree("d")
    assert not (svc.exists("f") or svc.exists("d") or svc.exists("d/child"))


def test_chmod_mode(svc):
    svc.write("f", b"x"); svc.chmod("f", 0o640)
    assert svc.mode("f") == 0o640


def test_setxattr_getxattr(svc):
    svc.write("f", b"x"); svc.setxattr("f", "user.color", b"blue")
    assert svc.getxattr("f", "user.color") == b"blue"


def test_symlink(svc):
    svc.symlink("/tmp/outside", "link")
    assert svc.exists("link") and svc.fake.links["/data/xrootd/link"] == "/tmp/outside"


def test_write_is_binary_safe_via_bounded_base64(svc, monkeypatch):
    """White-box: writes go out as base64 with a bounded `head -c` read (the WS
    has no clean stdin-close)."""
    seen = {}
    def spy(service, ns, argv, stdin=None):
        seen.update(argv=argv, stdin=stdin); return klib._Result(0, "", "")
    monkeypatch.setattr(klib, "_exec", spy)
    svc.write("/p", b"\x00\xff\x10")
    assert seen["argv"] == ["sh", "-c", "head -c 4 | base64 -d > '/p'"]
    assert base64.b64decode(seen["stdin"]) == b"\x00\xff\x10"
