"""Shared helpers for Python ports of small compile-and-run shell tests."""

from __future__ import annotations

from pathlib import Path
import os
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[2]


def run(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd or REPO_ROOT),
        env={**os.environ, **(env or {})},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


def compile_binary(output: Path, args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return run(["gcc", *args, "-o", str(output)], cwd=cwd)


def result(ok: bool, message: str) -> tuple[bool, str]:
    return ok, message
