#!/usr/bin/env python3
#
# run_fanalyzer.py — zero-findings static-analysis gate over the addon sources.
#
# WHAT: compiles every module source under GCC's symbolic-execution static
#       analyzer (-fanalyzer) and FAILS (exit 1) on ANY finding —
#       use-after-free, double-free, memory/fd leak, NULL dereference, etc.
#
# WHY: -fanalyzer reasons about error / early-return branches the test suite may
#       never hit, where leaks and double-frees hide. The tree is analyzer-clean
#       (the 2026-08 burn-down restructured the last idioms the analyzer could
#       not follow — post-increment array-store indexes, the queue drain loop,
#       the exec'd child's dup2'd stdout), so the gate is a straight "no
#       findings" check: any hit is either a real bug or code written in a shape
#       the analyzer cannot prove safe — both get fixed in code, never waived in
#       a baseline.
#
# HOW: reuse the EXACT $(CFLAGS) and $(ALL_INCS) from a configured nginx build
#       tree (so the analyzer sees the real defines/includes), minus -Werror* (we
#       collect findings across all files instead of aborting on the first), and
#       run `gcc -fanalyzer -c -o /dev/null` on each source in parallel. Each
#       [-Wanalyzer-...] line is normalised to "path│kind│message" (line/column
#       stripped, sorted, de-duped) for a stable report.
#
# USAGE:
#   tools/ci/run_fanalyzer.py                 # gate: exit 1 on any finding
#   NGX_BUILD=/path/to/nginx tools/ci/run_fanalyzer.py
#   tools/ci/run_fanalyzer.py --filter src/auth/gsi   # restrict to a path prefix (faster, no gate)

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# REPO = script dir/../.. ; matches the bash BASH_SOURCE resolution.
REPO = Path(__file__).resolve().parents[2]
NGX_BUILD = os.environ.get("NGX_BUILD", "/tmp/nginx-1.28.3")
MK = f"{NGX_BUILD}/objs/Makefile"
JOBS = int(os.environ.get("JOBS") or os.cpu_count() or 1)

# Files exempted from the gate (basename match). Keep empty — add only with a
# written rationale next to the entry.
ANALYZER_SKIP: list[str] = [
    # e.g. "third_party_blob.c   # vendored, analyzed upstream"
]


def fail(msg: str) -> None:
    print(f"run_fanalyzer: {msg}", file=sys.stderr)
    sys.exit(2)


def read_var(name: str) -> str:
    """Pull a fully-expanded make variable straight from the build's Makefile.

    CFLAGS / ALL_INCS live in objs/Makefile (the top-level Makefile only
    delegates), so read them from there. -s + --no-print-directory keep make's
    own chatter off stdout so only the printf payload survives."""
    try:
        out = subprocess.run(
            ["make", "-s", "--no-print-directory", "-C", NGX_BUILD, "-f", "objs/Makefile",
             f"--eval=__pf: ; @printf '%s' \"$({name})\"", "__pf"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        return out.stdout
    except FileNotFoundError:
        return ""


def collect_sources() -> list[str]:
    """Addon sources actually compiled into this build: grep -oE the absolute
    src/*.c paths out of objs/Makefile, sorted + de-duped."""
    text = Path(MK).read_text()
    pat = re.compile(re.escape(str(REPO)) + r"/src/[^ \n]+\.c")
    return sorted(set(pat.findall(text)))


def skip_match(src: str) -> bool:
    base = os.path.basename(src)
    for entry in ANALYZER_SKIP:
        # entry up to the first whitespace run == basename.
        if re.split(r"[ \t]", entry, maxsplit=1)[0] == base:
            return True
    return False


def analyze_one(src: str, cflags: list[str], all_incs: list[str],
                raw_path: str | None) -> tuple[list[str], str | None]:
    """Run `gcc -fanalyzer` on one source. Returns (analyzer_finding_lines,
    compile_error_block_or_None).

    ALL_INCS carries build-relative -I paths (-I src/core, -I objs), so run from
    the build tree exactly as the Makefile recipe does. The source path is absolute."""
    proc = subprocess.run(
        ["gcc", "-fanalyzer", "-fanalyzer-verbosity=1", "-fno-diagnostics-color",
         "-c", *cflags, *all_incs, src, "-o", "/dev/null"],
        cwd=NGX_BUILD, stderr=subprocess.PIPE, text=True,
    )
    error_text = proc.stderr
    findings = _finding_lines(error_text)
    has_analyzer = "[-Wanalyzer-" in error_text
    _write_raw_trace(raw_path, src, error_text, has_analyzer)
    compile_error = _compile_error(src, error_text, proc.returncode, has_analyzer)
    return findings, compile_error


def _finding_lines(error_text):
    return [
        line for line in error_text.splitlines()
        if re.search(r"\[-Wanalyzer-[a-z-]+\]", line)
    ]


def _write_raw_trace(path, source, error_text, has_analyzer):
    if not path or not has_analyzer:
        return
    try:
        with open(path, "a") as stream:
            stream.write(f"==== {source} ====\n{error_text}")
    except OSError:
        pass


def _compile_error(source, error_text, returncode, has_analyzer):
    if returncode == 0 or has_analyzer:
        return None
    errors = [
        line for line in error_text.splitlines()
        if re.search(r": (error|fatal error):", line)
    ][:3]
    return "\n".join([f"COMPILE-ERROR: {source}", *errors])


def normalise(lines: list[str]) -> list[str]:
    """Normalise findings to a churn-stable key: drop the build-tree and repo
    prefixes, strip ":line:col:", collapse to "path│kind│message". Sorted +
    de-duped.

    Codepoint (LC_ALL=C-equivalent) sort keeps Python deterministic; for these
    ASCII-path-prefixed keys it coincides with the shell's `sort -u`."""
    out = set()
    for ln in lines:
        ln = ln.replace(f"{NGX_BUILD}/", "")
        ln = ln.replace(f"{REPO}/", "")
        ln = re.sub(r":[0-9]+:[0-9]+:\s*warning:\s*", " │ ", ln, count=1)
        ln = re.sub(r"\s*\[(-Wanalyzer-[a-z-]+)\].*", "  │ \\1", ln, count=1)
        out.add(ln)
    return sorted(out)


def parse_args(argv: list[str]) -> str:
    """Returns the path-prefix filter ('' = full tree, gated)."""
    filt = ""
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--filter":
            i += 1
            filt = argv[i] if i < len(argv) else ""
        else:
            filt = arg  # bare path-prefix arg, back-compat
        i += 1
    return filt


def main(argv: list[str]) -> int:
    filt = parse_args(argv)
    _validate_environment()
    cflags, all_incs = _compiler_flags()
    todo = _selected_sources(filt)
    raw_path = os.environ.get("FANALYZER_RAW") or None
    findings, compile_errors = _analyze(todo, cflags, all_incs, raw_path)
    print(f"== analyzed {len(todo)} source file(s) under -fanalyzer ==")
    _fail_compile_errors(compile_errors)
    current = normalise(findings)
    print(f"== {len(current)} analyzer finding(s) ==")
    if filt:
        return _report_filter(current, filt)
    return _gate_current(current)


def _validate_environment():
    if shutil.which("gcc") is None:
        fail("gcc not found")
    if not os.path.isfile(MK):
        fail(f"no configured build at {NGX_BUILD} (need objs/Makefile; run ./configure first)")


def _compiler_flags():
    cflags = read_var("CFLAGS")
    includes = read_var("ALL_INCS")
    if not cflags:
        fail(f"could not read CFLAGS from {MK}")
    cflags = re.sub(r"-Werror(=[a-z-]+)?", "", cflags)
    return cflags.split(), includes.split()


def _selected_sources(filt):
    sources = collect_sources()
    if not sources:
        fail(f"no addon sources found in {MK}")
    selected = [source for source in sources if _selected(source, filt)]
    if not selected:
        fail(f"no sources selected (filter='{filt}')")
    return selected


def _selected(source, filt):
    if filt and not source.startswith(f"{REPO}/{filt}"):
        return False
    return not skip_match(source)


def _analyze(todo, cflags, all_incs, raw_path):
    findings = []
    compile_errors = []
    worker = lambda source: analyze_one(source, cflags, all_incs, raw_path)
    with ThreadPoolExecutor(max_workers=JOBS) as pool:
        results = pool.map(worker, todo)
        for found, error in results:
            findings.extend(found)
            if error is not None:
                compile_errors.append(error)
    return findings, compile_errors


def _fail_compile_errors(errors):
    if not errors:
        return
    text = "\n".join(errors) + "\n"
    count = sum(
        1 for line in text.splitlines() if line.startswith("COMPILE-ERROR:")
    )
    print(f"---- compile errors ({count}) — analysis did NOT run on these ----")
    print("\n".join(text.splitlines()[:20]))
    fail(f"{count} file(s) failed to compile under the analyzer flags "
         "(bad NGX_BUILD / flag extraction?)")


def _report_filter(current, filt):
    print(f"run_fanalyzer: filter run (no gate). Findings under '{filt}':")
    if current:
        print("\n".join(current))
    return 0


def _gate_current(current):
    if current:
        print(f"---- analyzer findings ({len(current)}) ----")
        print("\n".join(current))
        print(f"run_fanalyzer: FAIL — {len(current)} finding(s). Fix them in code "
              "(restructure until the analyzer can prove the path safe);",
              file=sys.stderr)
        print("               set FANALYZER_RAW=<file> to capture the full traces.",
              file=sys.stderr)
        return 1
    print("run_fanalyzer: OK — zero analyzer findings")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
