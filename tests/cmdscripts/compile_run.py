"""Shared helpers for Python ports of small compile-and-run shell tests."""

from __future__ import annotations

from pathlib import Path
import os
import subprocess


def _expression_1(args):
    return (
        [a for a in args if str(a).endswith(".o")
                    and Path(a if os.path.isabs(str(a)) else REPO_ROOT / a).exists()]
    )

def _expression_2(objs):
    return (
        run(["nm", *[str(o) for o in objs]])
    )

def _expression_3(proc):
    return (
        proc.stdout if proc.returncode == 0 else ""
    )


def _guard_sanitizer_link_flags_1(syms, flags):
    if "__asan_" in syms:
        flags.append("-fsanitize=address")

def _guard_sanitizer_link_flags_2(syms, flags):
    if "__ubsan_" in syms or "__ubsan" in syms:
        flags.append("-fsanitize=undefined")

def _guard_sanitizer_link_flags_3(syms, flags):
    if "__tsan_" in syms:
        flags.append("-fsanitize=thread")


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


def sanitizer_link_flags(args: list[str]) -> list[str]:
    """`-fsanitize=...` when a linked-in .o was built under a sanitizer.

    An object compiled with -fsanitize=address/undefined/thread carries
    __asan_*/__ubsan_*/__tsan_* references, so linking it without the matching
    runtime dies at LD time with `undefined reference to __asan_*` — exactly the
    contaminated-nginx-object case (a tree built with -fsanitize whose objs/ the
    object-linked units reuse).  One nm pass picks the right flags."""
    objs = _expression_1(args)
    if not objs:
        return []
    proc = _expression_2(objs)
    syms = _expression_3(proc)
    flags = []
    _guard_sanitizer_link_flags_1(syms, flags)
    _guard_sanitizer_link_flags_2(syms, flags)
    _guard_sanitizer_link_flags_3(syms, flags)
    return flags


def compile_binary(output: Path, args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return run(["gcc", *args, *sanitizer_link_flags(args), "-o", str(output)], cwd=cwd)


def result(ok: bool, message: str) -> tuple[bool, str]:
    return ok, message
