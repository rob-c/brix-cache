"""Session filesystem and credential preparation for the pytest harness."""

from __future__ import annotations

import hashlib
import os
import random
import shutil


def setup_remote_session(check_reachable, host, port):
    from settings import CA_DIR, LOG_DIR, PROXY_STD, TMP_DIR

    if not check_reachable(host, port):
        return False
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(TMP_DIR, exist_ok=True)
    os.environ.setdefault("X509_CERT_DIR", CA_DIR)
    os.environ.setdefault("X509_USER_PROXY", PROXY_STD)
    return True


def setup_local_session(chdir, reset_tree, chdir_scratch):
    from settings import (
        CA_DIR, DATA_ROOT, LOG_DIR, NGINX_BIN, PKI_DIR, PROXY_STD,
        TEST_ROOT, TMP_DIR,
    )

    reset_tree()
    os.makedirs(TEST_ROOT, exist_ok=True)
    if chdir:
        chdir_scratch()
    _replace_directory(DATA_ROOT)
    _replace_directory(PKI_DIR)
    _create_pki_directories(PKI_DIR)
    _create_session_directories(TEST_ROOT, LOG_DIR, TMP_DIR)
    _seed_data(DATA_ROOT)
    os.environ["X509_CERT_DIR"] = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_STD
    _prepare_fleet(NGINX_BIN)


def _replace_directory(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)


def _create_pki_directories(pki_dir):
    for subdirectory in ("ca", "server", "user", "voms", "vomsdir"):
        os.makedirs(os.path.join(pki_dir, subdirectory), exist_ok=True)


def _create_session_directories(test_root, log_dir, tmp_dir):
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(tmp_dir, exist_ok=True)
    os.makedirs(os.path.join(test_root, "artifacts"), exist_ok=True)
    _replace_directory(os.path.join(test_root, "data-gsi-bridge"))


def _seed_data(data_root):
    with open(os.path.join(data_root, "test.txt"), "wb") as output:
        output.write(b"hello from nginx-xrootd\n")
    with open(os.path.join(data_root, "random.bin"), "wb") as output:
        output.write(random.randbytes(5 * 1024 * 1024))
    _seed_large_file(data_root)


def _seed_large_file(data_root):
    size = 200 * 1024 * 1024
    path = os.path.join(data_root, "large200.bin")
    digest = hashlib.md5()
    if _large_file_needs_writing(path, size):
        _write_large_file(path, size, digest)
    else:
        _hash_file(path, digest)
    os.environ["LARGE_FILE_MD5"] = digest.hexdigest()


def _large_file_needs_writing(path, size):
    if not os.path.exists(path):
        return True
    return os.path.getsize(path) != size


def _write_large_file(path, size, digest):
    rng = random.Random(int(os.environ.get("LARGE_FILE_SEED", "42")))
    with open(path, "wb") as output:
        remaining = size
        while remaining > 0:
            chunk = rng.randbytes(min(16 * 1024 * 1024, remaining))
            output.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)


def _hash_file(path, digest):
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)


def _prepare_fleet(nginx_binary):
    import fleet_prep
    from cmdscripts.live_common import freeze_nginx

    fleet_prep.prepare()
    freeze_nginx(nginx_binary)
