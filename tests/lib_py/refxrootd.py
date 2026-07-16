"""Reference xrootd helpers replacing tests/lib/refxrootd.sh."""

from __future__ import annotations

from pathlib import Path
import os

from .util import find_xrd_sec_lib, kill_pid_list, pids_on_port, render_cfg, run, wait_ready_xrdfs


def ref_runas_user() -> str | None:
    return os.environ.get("REF_RUNAS_USER", "nobody") if os.geteuid() == 0 else None


def ref_launch(cfg: Path, log: Path) -> bool:
    ref_bin = os.environ.get("REF_BIN", os.environ.get("BRIX_BIN", "/usr/bin/xrootd"))
    user = ref_runas_user()
    log.parent.mkdir(parents=True, exist_ok=True)
    argv = [ref_bin, "-c", str(cfg), "-l", str(log)]
    if user:
        for line in cfg.read_text(errors="ignore").splitlines():
            words = line.split()
            if len(words) >= 2 and words[0] in {"all.adminpath", "all.pidpath"}:
                Path(words[1]).mkdir(parents=True, exist_ok=True)
            if len(words) >= 2 and words[0] == "oss.localroot":
                Path(words[1]).mkdir(parents=True, exist_ok=True)
        argv += ["-R", user]
    argv.append("-b")
    return run(argv).returncode == 0


def write_ref_cfg(cfg: Path, port: int, data_dir: Path, admin_dir: Path, run_dir: Path, configs_dir: Path) -> None:
    render_cfg(configs_dir / "xrootd_ref.conf", cfg, PORT=str(port), DATA_DIR=str(data_dir), ADMIN_DIR=str(admin_dir), RUN_DIR=str(run_dir))


def write_gsi_ref_cfg(cfg: Path, port: int, data_dir: Path, admin_dir: Path, run_dir: Path, configs_dir: Path, pki_dir: Path) -> bool:
    sec = find_xrd_sec_lib()
    if sec is None:
        return False
    render_cfg(
        configs_dir / "xrootd_ref_gsi.conf",
        cfg,
        PORT=str(port),
        DATA_DIR=str(data_dir),
        ADMIN_DIR=str(admin_dir),
        RUN_DIR=str(run_dir),
        SECLIB=str(sec),
        CA_DIR=str(pki_dir / "ca"),
        SERVER_CERT=str(pki_dir / "server/hostcert.pem"),
        SERVER_KEY=str(pki_dir / "server/hostkey.pem"),
    )
    return True


def start_ref_instance(label: str, port: int, data_dir: Path, *, gsi: bool = False) -> bool:
    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))
    ref_dir = Path(os.environ.get("REF_DIR", str(test_root / "ref")))
    configs_dir = Path(os.environ.get("CONFIGS_DIR", str(Path(__file__).resolve().parents[1] / "configs")))
    pki_dir = Path(os.environ.get("PKI_DIR", str(test_root / "pki")))
    admin_dir = ref_dir / f"{label}-admin-conf"
    run_dir = ref_dir / f"{label}-run-conf"
    cfg = ref_dir / f"{label}-conformance.cfg"
    log = ref_dir / f"{label}-conformance.log"
    if pids_on_port(port):
        return True
    data_dir.mkdir(parents=True, exist_ok=True)
    if gsi and not write_gsi_ref_cfg(cfg, port, data_dir, admin_dir, run_dir, configs_dir, pki_dir):
        write_ref_cfg(cfg, port, data_dir, admin_dir, run_dir, configs_dir)
    elif not gsi:
        write_ref_cfg(cfg, port, data_dir, admin_dir, run_dir, configs_dir)
    ref_launch(cfg, log)
    return wait_ready_xrdfs(f"root://localhost:{port}") or bool(pids_on_port(port))


def stop_ref_ports(*ports: int) -> None:
    pids = []
    for port in ports:
        pids.extend(pids_on_port(port))
    kill_pid_list(sorted(set(pids)))

