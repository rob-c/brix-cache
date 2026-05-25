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

from settings import SERVER_HOST


def _crc32c(data: bytes) -> int:
    """Pure-Python CRC32c (Castagnoli) — avoids requiring the crc32c package."""
    POLY = 0x82F63B78
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ POLY if crc & 1 else crc >> 1
    return crc ^ 0xFFFFFFFF


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


ANON_HOST = SERVER_HOST
ANON_PORT = 11094
DATA_DIR = ""
PREFIX = "_opcode_flag_"


@pytest.fixture(scope="module", autouse=True)
def _configure(test_env):
    global ANON_HOST, ANON_PORT, DATA_DIR
    ANON_HOST = test_env["server_host"]
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


def _dcksm_checksum_token(body, filename):
    """Extract the 'algo:hexvalue' token from a dcksm dirlist response."""
    lines = _body_lines(body)
    entry_index = lines.index(filename.encode())
    stat_line = lines[entry_index + 1]
    stat_part, checksum_part = stat_line.split(b" [ ", 1)
    assert len(stat_part.split()) >= 9
    return checksum_part.rstrip(b" ]")


def test_kXR_dcksm_dirlist_crc32():
    """dcksm with cks.type=crc32 returns the ISO-3309 CRC32 (zlib) digest."""
    import zlib

    root = _disk(f"{PREFIX}dcksm_crc32")
    os.makedirs(root, exist_ok=True)
    payload = b"crc32 test payload\n"
    with open(os.path.join(root, "f.txt"), "wb") as fh:
        fh.write(payload)

    expected = zlib.crc32(payload) & 0xFFFFFFFF

    with _login_session() as sock:
        status, body = _dirlist(
            sock,
            f"/{PREFIX}dcksm_crc32?cks.type=crc32",
            kXR_dcksm,
        )

    assert status == kXR_ok
    token = _dcksm_checksum_token(body, "f.txt")
    assert token == f"crc32:{expected:08x}".encode()


def test_kXR_dcksm_dirlist_crc32c():
    """dcksm with cks.type=crc32c returns the correct CRC32c digest."""
    root = _disk(f"{PREFIX}dcksm_crc32c")
    os.makedirs(root, exist_ok=True)
    payload = b"crc32c test payload\n"
    with open(os.path.join(root, "f.txt"), "wb") as fh:
        fh.write(payload)

    expected = _crc32c(payload)

    with _login_session() as sock:
        status, body = _dirlist(
            sock,
            f"/{PREFIX}dcksm_crc32c?cks.type=crc32c",
            kXR_dcksm,
        )

    assert status == kXR_ok
    token = _dcksm_checksum_token(body, "f.txt")
    assert token == f"crc32c:{expected:08x}".encode()


@pytest.mark.parametrize("algo,hashfn", [
    ("md5",    lambda d: __import__("hashlib").md5(d).hexdigest()),
    ("sha1",   lambda d: __import__("hashlib").sha1(d).hexdigest()),
    ("sha256", lambda d: __import__("hashlib").sha256(d).hexdigest()),
])
def test_kXR_dcksm_dirlist_evp_algorithms(algo, hashfn):
    """dcksm returns the correct EVP (md5/sha1/sha256) digest for each file."""
    root = _disk(f"{PREFIX}dcksm_{algo}")
    os.makedirs(root, exist_ok=True)
    payload = f"evp test payload for {algo}\n".encode()
    with open(os.path.join(root, "f.txt"), "wb") as fh:
        fh.write(payload)

    expected = hashfn(payload)

    with _login_session() as sock:
        status, body = _dirlist(
            sock,
            f"/{PREFIX}dcksm_{algo}?cks.type={algo}",
            kXR_dcksm,
        )

    assert status == kXR_ok
    token = _dcksm_checksum_token(body, "f.txt")
    assert token == f"{algo}:{expected}".encode()


def test_kXR_dcksm_dirlist_unsupported_algo_returns_error():
    """Requesting an unknown cks.type is rejected with an error status."""
    root = _disk(f"{PREFIX}dcksm_bad")
    os.makedirs(root, exist_ok=True)

    with _login_session() as sock:
        status, _body = _dirlist(
            sock,
            f"/{PREFIX}dcksm_bad?cks.type=notanalgo",
            kXR_dcksm,
        )

    assert status == kXR_error


@pytest.mark.parametrize("algo,hashfn", [
    ("adler32", lambda d: __import__("zlib").adler32(d) & 0xFFFFFFFF),
    ("crc32",   lambda d: __import__("zlib").crc32(d) & 0xFFFFFFFF),
    ("md5",     lambda d: __import__("hashlib").md5(d).hexdigest()),
    ("sha256",  lambda d: __import__("hashlib").sha256(d).hexdigest()),
])
def test_kXR_dcksm_xattr_cache_populated_and_reused(algo, hashfn):
    """After the first dcksm listing the xattr cache key is set; the second
    listing returns the same token without recomputing (cache hit path)."""
    import os as _os
    try:
        import xattr as _xattr_mod  # optional; skip if not installed
        _has_xattr = True
    except ImportError:
        _has_xattr = False

    root = _disk(f"{PREFIX}dcksm_xattr_{algo}")
    _os.makedirs(root, exist_ok=True)
    payload = f"xattr cache payload for {algo}\n".encode()
    filepath = _os.path.join(root, "f.txt")
    with open(filepath, "wb") as fh:
        fh.write(payload)

    expected_raw = hashfn(payload)
    if isinstance(expected_raw, int):
        expected_hex = f"{expected_raw:08x}"
    else:
        expected_hex = expected_raw

    # First listing — computes and caches.
    with _login_session() as sock:
        status1, body1 = _dirlist(
            sock,
            f"/{PREFIX}dcksm_xattr_{algo}?cks.type={algo}",
            kXR_dcksm,
        )
    assert status1 == kXR_ok
    token1 = _dcksm_checksum_token(body1, "f.txt")
    assert token1 == f"{algo}:{expected_hex}".encode()

    # Verify xattr was written if the xattr module is available.
    if _has_xattr:
        xattr_key = f"user.XrdCks.{algo}"
        xattr_val = _xattr_mod.getxattr(filepath, xattr_key).decode("ascii")
        # New format is "<hex> <mtime_sec> <mtime_nsec> <size>"
        assert xattr_val.startswith(expected_hex)
        assert len(xattr_val.split()) == 4

    # Second listing — should return the same token (cache hit).
    with _login_session() as sock:
        status2, body2 = _dirlist(
            sock,
            f"/{PREFIX}dcksm_xattr_{algo}?cks.type={algo}",
            kXR_dcksm,
        )
    assert status2 == kXR_ok
    token2 = _dcksm_checksum_token(body2, "f.txt")
    assert token1 == token2


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
