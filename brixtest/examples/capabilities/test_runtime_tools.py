"""Minimal PTY, filesystem, task, replica, and lifecycle examples."""

import sys

from brixtest import (
    Lifecycle,
    binary,
    case,
    mount,
    probe,
    server,
    task,
    tool,
    volume,
)

PYTHON = binary(
    "runtime_python", path=sys.executable,
    image="python@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a",
    image_path="/usr/local/bin/python3",
)
DATA = volume("data", kind="shared", access="read-write-many")
SEED = task(
    "seed", command=(PYTHON, "-c", "print('seeded')"), phase="init",
)
ORIGIN = server(
    "stateful_origin",
    command=(PYTHON, "-u", "-c", "import time;time.sleep(300)"),
    mounts=(mount(DATA, "data", read_only=False),), probe=probe("none"),
    replicas=1,
    lifecycle=Lifecycle(
        shutdown_command=(PYTHON, "-c", "print('orderly shutdown')"),
    ),
)
TERMINAL = tool(
    "terminal",
    command=(PYTHON, "-c", "import os,sys;print(os.isatty(0));print(input())"),
    input="hello from a PTY\n", mode="pty",
)


@case(DATA, SEED, ORIGIN, TERMINAL, PYTHON, backend="auto", keep="never")
def test_resources_and_tools_share_one_pythonic_run_surface(run):
    service = run.server(ORIGIN)
    service.fs.write_bytes("payload", b"\x00\xffBriX")
    assert service.fs.read_bytes("payload") == b"\x00\xffBriX"
    assert service.replicas[0].ready
    result = run.tool(TERMINAL).run()
    assert "True" in result.stdout and "hello from a PTY" in result.stdout
    assert run.task(SEED).ok and "seeded" in run.task(SEED).stdout
