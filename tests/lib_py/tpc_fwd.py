"""TPC forwarding helpers replacing tests/lib/tpc_fwd.sh."""

from __future__ import annotations

from pathlib import Path
import os

from .fwd_matrix import ForwardMatrix
from .util import run


def drive_tpc_webdav(source: str, dest: str, source_header: str, token: Path | None = None) -> bool:
    argv = ["curl", "-sk", "-X", "COPY", "-H", f"Source: {source_header}", dest]
    if token is not None:
        argv[4:4] = ["-H", f"Authorization: Bearer {token.read_text().strip()}"]
    return run(argv).returncode == 0


def drive_tpc_root(src: str, dst: str, proxy: Path | None = None, token: Path | None = None) -> bool:
    env = {}
    if proxy is not None:
        env["X509_USER_PROXY"] = str(proxy)
    if token is not None:
        env["BEARER_TOKEN_FILE"] = str(token)
    return run(["xrdcp", "--tpc", "delegate", src, dst], env=env).returncode == 0


def run_tpc_cell(matrix: ForwardMatrix, key: str, src: str, dst: str, *, root: bool = True) -> None:
    ok = drive_tpc_root(src, dst) if root else drive_tpc_webdav(src, dst, src)
    matrix.record(key, "PASS" if ok else "FAIL", "TPC transfer completed" if ok else "TPC transfer failed")

