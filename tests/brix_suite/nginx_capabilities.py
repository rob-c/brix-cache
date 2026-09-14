"""Inspect capabilities in the exact executable/modules selected by the runner."""

from pathlib import Path
import re
import subprocess


def _defined_name(line):
    fields = line.split()
    if len(fields) < 3:
        return None
    if len(fields[1]) != 1 or fields[1] not in "ABCDGINRSTVWabcdginrstu":
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", fields[2]) is None:
        return None
    return fields[0]


def _symbol_layout(path, symbol):
    try:
        with path.open("rb") as stream:
            magic = stream.read(4)
    except OSError as error:
        raise RuntimeError(f"Cannot inspect selected nginx object {path}: {error}") from error
    modes = [[], ["-D"]] if magic == b"\x7fELF" else [[]]
    names = {symbol}
    if magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                 b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                 b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                 b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        names.add("_" + symbol)  # Mach-O's C symbol prefix, not ELF aliases.
    return modes, names


def _run_nm(path, mode):
    try:
        return subprocess.run(["nm", "-P", *mode, str(path)],
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError(f"Cannot inspect selected nginx object {path}: {error}") from error


def _object_has_symbol(path, symbol):
    modes, names = _symbol_layout(path, symbol)
    failures = []
    for mode in modes:
        probe = _run_nm(path, mode)
        if probe.returncode != 0:
            failures.append(probe.stderr.strip() or f"nm exited {probe.returncode}")
            continue
        if any(_defined_name(line) in names for line in probe.stdout.splitlines()):
            return True
    if failures:
        raise RuntimeError(f"Cannot inspect selected nginx object {path}: {'; '.join(failures)}")
    return False


def nginx_has_symbol(symbol):
    """False means absent; an unusable selected-object probe raises a diagnostic.

    Reuse the launcher's frozen executable and authoritative configured modules.
    A different build elsewhere on disk cannot enable a capability in this lane.
    """
    from brix_suite.nginx_tools import _nginx_bin
    from cmdscripts.live_common import _configured_nginx_modules

    binary = Path(_nginx_bin())
    if not binary.is_file():
        return False
    candidates = dict.fromkeys([str(binary), *_configured_nginx_modules()])
    return any(_object_has_symbol(Path(path).absolute(), symbol) for path in candidates)
