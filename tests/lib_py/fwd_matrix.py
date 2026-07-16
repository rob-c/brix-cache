"""Credential-forwarding matrix helpers replacing tests/lib/fwd_matrix.sh."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
import shutil
import tempfile

from .util import kill_pid_list, run


REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class ForwardMatrix:
    name: str
    need_xrootd: bool = False
    port_base: int = int(os.environ.get("FWD_PORT_BASE", "21960"))
    prefix: Path = field(init=False)
    node_pidfiles: list[Path] = field(default_factory=list)
    results: list[tuple[str, str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.prefix = Path(tempfile.mkdtemp(prefix=f"fwd_{self.name}."))

    def port(self) -> int:
        port = self.port_base
        self.port_base += 1
        return port

    @property
    def nginx_bin(self) -> Path:
        return Path(os.environ.get("NGINX_BIN", os.environ.get("NGINX", "/tmp/nginx-1.28.3/objs/nginx")))

    @property
    def xrootd_bin(self) -> Path:
        return Path(os.environ.get("XROOTD_BIN", os.environ.get("BRIX_BIN", "/usr/bin/xrootd")))

    def preflight(self) -> bool:
        needed = [self.nginx_bin, REPO_ROOT / "client/bin/xrdcp", REPO_ROOT / "client/bin/xrdfs"]
        if self.need_xrootd:
            needed.append(self.xrootd_bin)
        return all(path.exists() and os.access(path, os.X_OK) for path in needed)

    def record(self, key: str, outcome: str, detail: str = "") -> None:
        self.results.append((key, outcome, detail))

    def cleanup(self) -> None:
        pids = []
        for pidfile in self.node_pidfiles:
            try:
                pids.append(int(pidfile.read_text().strip()))
            except (OSError, ValueError):
                pass
        kill_pid_list(pids)
        shutil.rmtree(self.prefix, ignore_errors=True)


def mint_token(prefix: Path, sub: str, output: Path) -> bool:
    token_dir = prefix / "tokens"
    token_dir.mkdir(parents=True, exist_ok=True)
    run(["python3", str(REPO_ROOT / "utils/make_token.py"), "init", str(token_dir)], cwd=REPO_ROOT)
    proc = run(
        [
            "python3",
            str(REPO_ROOT / "utils/make_token.py"),
            "gen",
            str(token_dir),
            "--sub",
            sub,
            "--scope",
            "storage.read:/ storage.modify:/",
            "--lifetime",
            "3600",
            "--output",
            str(output),
        ],
        cwd=REPO_ROOT,
    )
    return proc.returncode == 0

