"""
Focused wire-level coverage for XRootD option flags that do not have their
own request opcode numbers.

Covered flags:
  - kXR_dstat on kXR_dirlist
  - kXR_dcksm on kXR_dirlist
  - kXR_mkdirpath on kXR_mkdir
  - kXR_posc on kXR_open
"""

import os
import shutil
import socket
import struct
import zlib

import pytest


kXR_ok = 0
kXR_error = 4003

kXR_close = 3003
kXR_dirlist = 3004
kXR_login = 3007
kXR_mkdir = 3008
kXR_open = 3010
kXR_write = 3019

kXR_dstat = 0x02
kXR_dcksm = 0x04
kXR_mkdirpath = 0x01

kXR_new = 0x0008
kXR_open_updt = 0x0020
kXR_posc = 0x1000


ANON_HOST = "127.0.0.1"
ANON_PORT = 11094
DATA_DIR = ""
PREFIX = "_opcode_flag_"


@pytest.fixture(scope="module", autouse=True)
def _configure(test_env):
    global ANON_PORT, DATA_DIR
    ANON_PORT = test_env["anon_port"]
    DATA_DIR = test_env["data_dir"]


@pytest.fixture(autouse=True)
def _clean_prefix():
    _cleanup()
    yield
    _cleanup()


def _cleanup():
    if not DATA_DIR:
        return

    for name in os.listdir(DATA_DIR):
        if not name.startswith(PREFIX):
            continue

        path = os.path.join(DATA_DIR, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


def _disk(path):
    return os.path.join(DATA_DIR, path.lstrip("/"))


def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise AssertionError("socket closed early")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    _streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _request(streamid, reqid, body=b"\x00" * 16, payload=b""):
    assert len(streamid) == 2
    assert len(body) == 16
    return struct.pack("!2sH16sI", streamid, reqid, body, len(payload)) + payload


def _login_session():
    sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
    sock.settimeout(5)

    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, body = _read_response(sock)
    assert status == kXR_ok
    assert len(body) == 8

    username = b"pytest".ljust(8, b"\x00")
    login_body = (
        struct.pack("!I", os.getpid() & 0xFFFFFFFF)
        + username
        + b"\x00\x00\x05\x00"
    )
    sock.sendall(_request(b"\x00\x01", kXR_login, login_body))
    status, _body = _read_response(sock)
    assert status == kXR_ok

    return sock


def _dirlist(sock, path, options, streamid=b"\x00\x10"):
    body = b"\x00" * 15 + bytes([options])
    sock.sendall(_request(streamid, kXR_dirlist, body, path.encode("utf-8")))
    return _read_response(sock)


def _mkdir(sock, path, options, streamid=b"\x00\x20"):
    body = bytes([options]) + b"\x00" * 13 + struct.pack("!H", 0o755)
    sock.sendall(_request(streamid, kXR_mkdir, body, path.encode("utf-8")))
    return _read_response(sock)


def _open(sock, path, options, streamid=b"\x00\x30"):
    body = (
        struct.pack("!H", 0o644)
        + struct.pack("!H", options)
        + b"\x00\x00"
        + b"\x00" * 6
        + b"\x00" * 4
    )
    sock.sendall(_request(streamid, kXR_open, body, path.encode("utf-8")))
    return _read_response(sock)


def _write(sock, fhandle, data, offset=0, streamid=b"\x00\x31"):
    body = fhandle[:4] + struct.pack("!q", offset) + b"\x00" + b"\x00" * 3
    sock.sendall(_request(streamid, kXR_write, body, data))
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x32"):
    body = fhandle[:4] + b"\x00" * 12
    sock.sendall(_request(streamid, kXR_close, body))
    return _read_response(sock)


def _body_lines(body):
    return body.rstrip(b"\x00").split(b"\n")


def test_kXR_dstat_dirlist_emits_leadin_and_entry_stat():
    root = _disk(f"{PREFIX}dstat")
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "alpha.txt"), "wb") as fh:
        fh.write(b"alpha")

    with _login_session() as sock:
        status, body = _dirlist(sock, f"/{PREFIX}dstat", kXR_dstat)

    assert status == kXR_ok
    assert body.startswith(b".\n0 0 0 0\n")

    lines = _body_lines(body)
    entry_index = lines.index(b"alpha.txt")
    stat_fields = lines[entry_index + 1].split()
    assert len(stat_fields) >= 4
    assert int(stat_fields[1]) == len(b"alpha")


def test_kXR_dcksm_dirlist_emits_extended_stat_and_checksum_token():
    root = _disk(f"{PREFIX}dcksm")
    os.makedirs(root, exist_ok=True)
    payload = b"checksum me\n"
    with open(os.path.join(root, "checksum.txt"), "wb") as fh:
        fh.write(payload)

    expected = zlib.adler32(payload) & 0xFFFFFFFF

    with _login_session() as sock:
        status, body = _dirlist(
            sock,
            f"/{PREFIX}dcksm?cks.type=adler32",
            kXR_dcksm,
        )

    assert status == kXR_ok
    assert body.startswith(b".\n0 0 0 0\n")

    lines = _body_lines(body)
    entry_index = lines.index(b"checksum.txt")
    stat_line = lines[entry_index + 1]
    stat_part, checksum_part = stat_line.split(b" [ ", 1)
    assert len(stat_part.split()) >= 9
    assert checksum_part.rstrip(b" ]") == f"adler32:{expected:08x}".encode()


def test_kXR_mkdirpath_creates_missing_parent_directories():
    target = f"/{PREFIX}mkdirpath/a/b/c"

    with _login_session() as sock:
        status_without_flag, _ = _mkdir(sock, target, 0, streamid=b"\x00\x21")
        assert status_without_flag == kXR_error
        assert not os.path.exists(_disk(target))

        status, _ = _mkdir(sock, target, kXR_mkdirpath, streamid=b"\x00\x22")

    assert status == kXR_ok
    assert os.path.isdir(_disk(target))


def test_kXR_posc_write_persists_after_successful_close():
    target = f"/{PREFIX}posc/persisted.bin"
    os.makedirs(os.path.dirname(_disk(target)), exist_ok=True)
    payload = b"persist on successful close\n"

    with _login_session() as sock:
        status, body = _open(
            sock,
            target,
            kXR_new | kXR_open_updt | kXR_posc,
            streamid=b"\x00\x33",
        )
        assert status == kXR_ok
        fhandle = body[:4]

        status, _ = _write(sock, fhandle, payload)
        assert status == kXR_ok

        status, _ = _close(sock, fhandle)
        assert status == kXR_ok

    with open(_disk(target), "rb") as fh:
        assert fh.read() == payload
