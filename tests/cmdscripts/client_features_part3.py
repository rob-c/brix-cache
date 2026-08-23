"""Direct Python port of tests/run_client_features.sh.

E2e checks for the 2026-07-05 client feature set, driven through the repo's own
client binaries (client/bin/xrdcp, xrdfs, xrdcksum, xrddiag). Local-only checks
always run; fleet checks auto-skip when no server answers on
${XRD_TEST_URL:-root://localhost:11094} (probed via wait41-brix, like the shell
`have_fleet`).

Routing note (inherited): brix_copy -r requires one remote + one local endpoint;
local->local recursive is rejected. Dry-run on a single non-recursive file works
local->local because transfer_one short-circuits before calling brix_copy. All
recursive filter tests are therefore fleet-gated.
"""

from __future__ import annotations

import argparse
import calendar
import json
import os
from pathlib import Path
import random
import re
import struct
import subprocess
import time

from cmdscripts.compile_run import REPO_ROOT
from cmdscripts.live_common import LiveRun
from settings import NGINX_ANON_PORT, SERVER_HOST

def _exit_code(failed):
    return (
        0 if failed == 0 else 1
    )


def _guard_section_xrdfs_uring_1(dl_on):
    if dl_on.exists():
        dl_on.unlink()

def _guard_section_xrdfs_uring_2(on_rc, s, dl_on, seed):
    if on_rc == 0:
        s.check("download --io-uring on: success -> byte-exact",
                dl_on.exists() and dl_on.read_bytes() == seed.read_bytes())
    else:
        s.check("download --io-uring on: clean fail -> no partial output", not dl_on.exists())

def _guard_run_sections_3(ok, label):
    if not ok:
        print(f"  FAIL: {label}")


BIN = REPO_ROOT / "client/bin"
USAGE_ERROR = 50


def section_xrdfs_uring(s: Session) -> None:
    print("== xrdfs download/upload --io-uring (fleet) ==")
    if not s.have_fleet():
        s.skip(f"xrdfs uring tests (no fleet at {s.url})")
        return

    tag = f"cfeat-uring-{os.getpid()}"
    seed = s.work / "uring_seed.dat"
    seed.write_text("xrdfs-uring-test-data-1234567890\n")
    s.fs("upload", seed, f"/tmp/{tag}")

    dl_off = s.work / "dl_off.dat"
    rc = s.fs("download", "--io-uring", "off", f"/tmp/{tag}", dl_off).returncode
    s.check("download --io-uring off: exit 0", rc == 0)
    s.check("download --io-uring off: byte-exact",
            dl_off.exists() and dl_off.read_bytes() == seed.read_bytes())

    dl_auto = s.work / "dl_auto.dat"
    rc = s.fs("download", "--io-uring", "auto", f"/tmp/{tag}", dl_auto).returncode
    s.check("download --io-uring auto: exit 0", rc == 0)
    s.check("download --io-uring auto: byte-exact",
            dl_off.exists() and dl_auto.exists() and dl_auto.read_bytes() == dl_off.read_bytes())

    rc = s.fs("download", "--io-uring", "bogus", f"/tmp/{tag}", s.work / "dl_bogus.dat").returncode
    s.check("download --io-uring bogus: exits 50", rc == USAGE_ERROR)

    # --io-uring on: either succeeds byte-exact, or fails cleanly with no
    # partial/corrupt output file left at the final path.
    dl_on = s.work / "dl_on.dat"
    _guard_section_xrdfs_uring_1(dl_on)
    on_rc = s.fs("download", "--io-uring", "on", f"/tmp/{tag}", dl_on).returncode
    _guard_section_xrdfs_uring_2(on_rc, s, dl_on, seed)

    rc = s.fs("upload", "--io-uring", "off", seed, f"/tmp/{tag}-up").returncode
    s.check("upload --io-uring off: exit 0", rc == 0)
    up_rt = s.work / "up_rt.dat"
    s.fs("download", f"/tmp/{tag}-up", up_rt)
    s.check("upload --io-uring off: round-trip byte-exact",
            up_rt.exists() and up_rt.read_bytes() == seed.read_bytes())

    s.rm_remote(f"/tmp/{tag}")
    s.rm_remote(f"/tmp/{tag}-up")


# --------------------------------------------------------------------------- #
SECTIONS = {
    "dryrun-filters": section_dryrun_filters,
    "sync-modes": section_sync_modes,
    "mirror-delete": section_mirror_delete,
    "remove-source": section_remove_source,
    "journal": section_journal,
    "xrdfs-rm": section_xrdfs_rm,
    "xrdfs-json": section_xrdfs_json,
    "tail-follow": section_tail_follow,
    "cat-compress": section_cat_compress,
    "cksum-tree": section_cksum_tree,
    "diag-json": section_diag_json,
    "xrdfs-uring": section_xrdfs_uring,
}


def missing_binaries() -> list[str]:
    return [str(BIN / name) for name in ("xrdcp", "xrdfs", "xrdcksum", "xrddiag")
            if not (BIN / name).exists()]


def run_sections(names: list[str], url: str | None = None) -> int:
    missing = missing_binaries()
    if missing:
        print(f"SKIP: client binaries missing: {', '.join(missing)}")
        return 0
    with LiveRun("client-features") as run:
        session = Session(run, url)
        for name in names:
            SECTIONS[name](session)
        passed = sum(1 for ok, _ in session.results if ok)
        failed = len(session.results) - passed
        print(f"client-features: {passed} pass, {failed} fail")
        for ok, label in session.results:
            _guard_run_sections_3(ok, label)
        return _exit_code(failed)


def _scenario(name: str):
    return lambda url=None: run_sections([name], url)


SCENARIOS = {name: _scenario(name) for name in SECTIONS}
SCENARIOS["all"] = lambda url=None: run_sections(list(SECTIONS), url)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", nargs="?", default="all", choices=SCENARIOS)
    parser.add_argument("--url", default=None, help="fleet endpoint (default $XRD_TEST_URL or root://localhost:11094)")  # net-literal-allow: argparse help text describing default endpoint
    ns = parser.parse_args(argv)
    return SCENARIOS[ns.scenario](ns.url)


if __name__ == "__main__":
    raise SystemExit(main())
