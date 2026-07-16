"""Python port of tests/userns/run.sh."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess
import sys

from cmdscripts.compile_run import REPO_ROOT


def main(argv: list[str] | None = None) -> int:
    nginx_src = Path(os.environ.get("TEST_NGINX_SRC", "/tmp/nginx-1.28.3"))
    cc = os.environ.get("CC", "cc")
    out = Path(os.environ.get("OUT", "/tmp/userns_broker_test.bin"))
    imp = REPO_ROOT / "src/auth/impersonate"
    here = REPO_ROOT / "tests/userns"

    if shutil.which(cc) is None:
        print(f"SKIP: no C compiler ({cc})")
        return 0
    if not (nginx_src / "src/core/ngx_config.h").is_file():
        print(f"SKIP: nginx source not at {nginx_src} (set TEST_NGINX_SRC)")
        return 0
    if shutil.which("newuidmap") is None or shutil.which("newgidmap") is None:
        print("SKIP: newuidmap/newgidmap not installed (uidmap package)")
        return 0

    includes = [
        f"-I{nginx_src / 'src/core'}",
        f"-I{nginx_src / 'src/event'}",
        f"-I{nginx_src / 'src/event/modules'}",
        f"-I{nginx_src / 'src/os/unix'}",
        f"-I{nginx_src / 'objs'}",
        f"-I{nginx_src / 'src/stream'}",
        f"-I{imp}",
        f"-I{REPO_ROOT / 'src'}",
    ]
    cmd = [
        cc,
        "-O2",
        "-D_GNU_SOURCE",
        "-Wall",
        *includes,
        "-o",
        str(out),
        str(here / "c/userns_broker_test.c"),
        str(imp / "broker.c"),
        str(imp / "client.c"),
        str(imp / "idmap.c"),
    ]
    print(f"==> building {out}")
    proc = subprocess.Popen(cmd, cwd=REPO_ROOT)
    if proc.wait() != 0:
        return proc.returncode
    print("==> running")
    return subprocess.Popen([str(out)], cwd=REPO_ROOT).wait()


if __name__ == "__main__":
    raise SystemExit(main())
