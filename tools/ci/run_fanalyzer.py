#!/usr/bin/env python3
#
# run_fanalyzer.py — static-analysis regression ratchet over the addon sources.
#
# WHAT: compiles every module source under GCC's symbolic-execution static
#       analyzer (-fanalyzer) and FAILS (exit 1) when a NEW finding appears that
#       is not in the recorded baseline (tools/ci/fanalyzer_baseline.txt) —
#       use-after-free, double-free, memory/fd leak, NULL dereference, etc.
#
# WHY: -fanalyzer reasons about error / early-return branches the test suite may
#       never hit, where leaks and double-frees hide. But GCC's analyzer is also
#       interprocedurally limited: it raises FALSE positives where ownership is
#       transferred into a container that a separate function frees (the cache /
#       catalog "leaks"), on nginx's ngx_queue iteration idiom (a "use-after-free"
#       that is not one), and on SHM pointers it cannot model. So a "zero findings"
#       gate is not workable here. Instead we freeze today's findings as a baseline
#       and gate only on NEW ones — the same backlog-ratchet model as
#       check_vfs_seam.sh. A genuinely new leak/UAF in changed code still fails.
#
# HOW: reuse the EXACT $(CFLAGS) and $(ALL_INCS) from a configured nginx build
#       tree (so the analyzer sees the real defines/includes), minus -Werror* (we
#       collect findings across all files instead of aborting on the first), and
#       run `gcc -fanalyzer -c -o /dev/null` on each source in parallel. Each
#       [-Wanalyzer-...] line is normalised to "path│kind│message" (line/column
#       stripped so unrelated edits do not churn the baseline) and diffed against
#       the baseline. --regen rewrites the baseline after a deliberate review.
#
# USAGE:
#   tools/ci/run_fanalyzer.py                 # gate: exit 1 on findings not in baseline
#   tools/ci/run_fanalyzer.py --regen         # rewrite the baseline (review the diff!)
#   NGX_BUILD=/path/to/nginx tools/ci/run_fanalyzer.py
#   tools/ci/run_fanalyzer.py --filter src/auth/gsi   # restrict to a path prefix (faster, no gate)
#
# Faithful port of run_fanalyzer.sh — same flags, commands, baseline format,
# messages, and exit codes.

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
BASELINE = REPO / "tools/ci/fanalyzer_baseline.txt"

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


def read_baseline(path: Path) -> list[str]:
    """Strip comment lines (first non-space char '#') and blank lines, sort -u."""
    out = set()
    for ln in path.read_text().splitlines():
        if re.match(r"^\s*#", ln):
            continue
        if re.match(r"^\s*$", ln):
            continue
        out.add(ln)
    return sorted(out)


def gate(current: list[str], baseline: list[str]) -> tuple[bool, list[str]]:
    """Verdict helper: New = current minus baseline (comm -23 over sorted sets).
    Returns (ok, new_findings)."""
    bset = set(baseline)
    new = [ln for ln in current if ln not in bset]
    return (len(new) == 0, new)


def parse_args(argv: list[str]) -> tuple[bool, str]:
    regen = False
    filt = ""
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--regen":
            regen = True
        elif arg == "--filter":
            i += 1
            filt = argv[i] if i < len(argv) else ""
        else:
            filt = arg  # bare path-prefix arg, back-compat
        i += 1
    return regen, filt


def main(argv: list[str]) -> int:
    regen, filt = parse_args(argv)
    _validate_environment()
    cflags, all_incs = _compiler_flags()
    todo = _selected_sources(filt)
    raw_path = os.environ.get("FANALYZER_RAW") or None
    findings, compile_errors = _analyze(todo, cflags, all_incs, raw_path)
    print(f"== analyzed {len(todo)} source file(s) under -fanalyzer ==")
    _fail_compile_errors(compile_errors)
    current = normalise(findings)
    cur = len(current)
    print(f"== {cur} analyzer finding(s) (baseline + new) ==")
    if regen:
        return _regenerate(current, filt)
    if filt:
        return _report_filter(current, filt)
    return _gate_current(current, cur)


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


def _regenerate(current, filt):
    if filt:
        fail("--regen must run over the FULL tree (drop --filter)")
    header = [
        "# fanalyzer baseline — known/false-positive findings, line:col stripped.",
        "# Regenerate with: tools/ci/run_fanalyzer.py --regen   (review the diff!)",
    ]
    BASELINE.write_text("".join(f"{line}\n" for line in [*header, *current]))
    print(f"run_fanalyzer: baseline rewritten ({len(current)} findings) → {BASELINE}")
    return 0


def _report_filter(current, filt):
    print(f"run_fanalyzer: filter run (no gate). Findings under '{filt}':")
    if current:
        print("\n".join(current))
    return 0


def _gate_current(current, count):
    if not BASELINE.is_file():
        fail(f"no baseline at {BASELINE} — create it with --regen")
    baseline = read_baseline(BASELINE)
    ok, new = gate(current, baseline)
    if not ok:
        print(f"---- NEW analyzer findings not in baseline ({len(new)}) ----")
        print("\n".join(new))
        print(f"run_fanalyzer: FAIL — {len(new)} new finding(s). Fix them, or if false-positive,",
              file=sys.stderr)
        print("               review and re-baseline with: tools/ci/run_fanalyzer.py --regen",
              file=sys.stderr)
        return 1
    print(f"run_fanalyzer: OK — no new findings beyond the {count}-entry baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
