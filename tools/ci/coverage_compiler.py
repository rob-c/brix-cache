#!/usr/bin/env python3
"""Keep GCC coverage from standalone C tests outside disposable test roots.

The coverage runner installs these launchers only for its test command. Native
compiler queries and synthetic fixtures without repository inputs retain their
normal compilation mode. Each production compile owns a separate counter
directory, so parallel tests cannot replace the main build's coverage notes.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile


def install(root: Path, output: Path, environment: dict[str, str]) -> dict[str, str]:
    """Return a child environment with launchers for the available GCC drivers."""
    directory = output / "bin"
    directory.mkdir(parents=True, exist_ok=True)
    launcher = Path(__file__).resolve()
    search_path = _compiler_search_path(environment)
    for name in ("gcc", "cc", "g++", "c++"):
        compiler = shutil.which(name, path=search_path)
        if compiler is None:
            continue
        command = [sys.executable, str(launcher), "--compiler", compiler,
                   "--root", str(root.resolve()), "--output", str(output.resolve()), "--"]
        script = directory / name
        script.write_text("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n')
        script.chmod(0o755)
    return {**environment, "PATH": str(directory.resolve()) + os.pathsep
            + search_path,
            "BRIX_COVERAGE_COUNTERS": str(output.resolve()),
            "GCOV_PREFIX": "", "GCOV_PREFIX_STRIP": "0"}


def _compiler_search_path(environment):
    """A nested collector must select real drivers, not its parent's launcher."""
    search_path = environment.get("PATH", os.defpath)
    parent = environment.get("BRIX_COVERAGE_COUNTERS")
    if not parent:
        return search_path
    launchers = (Path(parent) / "bin").resolve()
    return os.pathsep.join(part for part in search_path.split(os.pathsep)
                           if Path(part).resolve() != launchers)


def _repository_input(argument: str, root: Path, cwd: Path) -> bool:
    """Recognize source/include paths without treating a preprocessor value as one."""
    if argument.startswith("-I"):
        argument = argument[2:]
    if not argument or argument.startswith("-"):
        return False
    path = Path(argument)
    path = path if path.is_absolute() else cwd / path
    return path.resolve().is_relative_to(root.resolve())


def _compiles_source(arguments: list[str]) -> bool:
    """Preprocessor, assembly-inspection and compiler-query calls stay unchanged."""
    if {"-E", "-M", "-MM", "-S", "-fsyntax-only", "-###"}.intersection(arguments):
        return False
    return any(not arg.startswith("-") and Path(arg).suffix in
               (".c", ".cc", ".cpp", ".cxx", ".C") for arg in arguments)


def instrument_arguments(arguments: list[str], root: Path, output: Path,
                         cwd: Path) -> list[str]:
    """Instrument repository compilations and link the runtime for object inputs."""
    if _repository_compile(arguments, root, cwd):
        output.mkdir(parents=True, exist_ok=True)
        counters = tempfile.mkdtemp(prefix="compile-", dir=output)
        return [*arguments, "--coverage", "-g", "-fprofile-abs-path",
                "-fprofile-update=atomic", "-dumpdir", counters + os.sep]
    if _links_objects(arguments):
        return [*arguments, "--coverage"]
    return list(arguments)


def _repository_compile(arguments, root, cwd):
    return _compiles_source(arguments) and any(
        _repository_input(arg, root, cwd) for arg in arguments)


def _links_objects(arguments):
    if {"-c", "-E", "-M", "-MM", "-S", "-fsyntax-only", "-###"}.intersection(arguments):
        return False
    return any(not arg.startswith("-") and Path(arg).suffix in (".o", ".a")
               for arg in arguments)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    arguments = options.arguments
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    selected = instrument_arguments(arguments, options.root, options.output, Path.cwd())
    os.execv(options.compiler, [options.compiler, *selected])


if __name__ == "__main__":
    main()
