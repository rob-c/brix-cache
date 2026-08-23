#!/usr/bin/env python3
#
# run_codechecker.py — Clang Static Analyzer + clang-tidy regression ratchet.
#
# WHAT: runs Ericsson CodeChecker (clangsa + clang-tidy) over every addon source
#       compiled into the configured nginx build, and FAILS (exit 1) when a NEW
#       finding appears that is not in the recorded baseline
#       (tools/ci/codechecker_baseline.txt). Complements run_fanalyzer.sh: GCC
#       -fanalyzer reasons about ownership/leak/UAF along error branches; clangsa
#       + clang-tidy add a large, orthogonal checker set (dead stores, logic
#       errors, API misuse, security, bugprone-* etc.). Two engines, one model.
#
# WHY:  Same reasoning as the -fanalyzer ratchet: a "zero findings" gate is not
#       workable over a large C base (clang-tidy's default profile is opinionated
#       and raises stylistic/false-positive findings on nginx idioms). So we freeze
#       today's findings and gate only on NEW ones — the backlog-ratchet model used
#       by check_vfs_seam.sh / run_fanalyzer.sh / check_file_size.sh. A genuinely new
#       bug in changed code still fails CI.
#
# HOW:  1. Reuse the EXACT $(CFLAGS)/$(ALL_INCS) from the configured build tree
#          (same extraction as run_fanalyzer.sh) so the analyzer sees the real
#          defines/includes; strip -Werror so findings are collected, not aborted.
#       2. Synthesize a compile_commands.json (one clang entry per addon .c) — no
#          build interception / bear / ld-logger needed.
#       3. CodeChecker analyze (clangsa + clang-tidy), skipping the nginx build tree
#          and system headers so only OUR code is gated.
#       4. CodeChecker parse -e json → normalise each finding to a churn-stable key
#          "relpath │ checker │ report_hash". report_hash is CONTENT-based (stable
#          across unrelated line moves), so the baseline does not churn on edits.
#       5. Diff current vs baseline; NEW findings fail. --regen rewrites the baseline.
#
# USAGE:
#   tools/ci/run_codechecker.py                 # gate: exit 1 on findings not in baseline
#   tools/ci/run_codechecker.py --regen         # rewrite the baseline (review the diff!)
#   NGX_BUILD=/path/to/nginx tools/ci/run_codechecker.py
#   tools/ci/run_codechecker.py --filter src/auth/gsi   # restrict to a prefix (report-only, no gate)
#   ANALYZERS="clangsa" tools/ci/run_codechecker.py     # override analyzer set
#
# Faithful port of tools/ci/run_codechecker.py (same CLI, commands, wording, exits).

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO
NGX_BUILD = os.environ.get("NGX_BUILD") or "/tmp/nginx-1.28.3"
MK = f"{NGX_BUILD}/objs/Makefile"
JOBS = os.environ.get("JOBS") or str(os.cpu_count() or 1)
BASELINE = f"{REPO}/tools/ci/codechecker_baseline.txt"
ANALYZERS = os.environ.get("ANALYZERS") or "clangsa clang-tidy"

# Checks disabled by policy — each MUST have a reason. These contradict the build's
# own warning config or are pure noise for an nginx module; the ratchet handles the
# rest. Override with CC_DISABLE="" to see the full default profile.
CC_DISABLE_DEFAULT = [
    "clang-diagnostic-unused-parameter",   # the build sets -Wno-unused-parameter (deliberate)
    "misc-header-include-cycle",           # structural noise: nginx module include graph is legitimately cyclic
]
# read -r -a: whitespace word-split of CC_DISABLE (default = the policy list joined by space).
_cc_disable_raw = os.environ.get("CC_DISABLE")
if _cc_disable_raw is None:
    _cc_disable_raw = " ".join(CC_DISABLE_DEFAULT)
CC_DISABLE = _cc_disable_raw.split()


def resolve_cc() -> str:
    """CC=${CODECHECKER:-CodeChecker}; fall back to ~/.local/bin/CodeChecker if not on PATH."""
    cc = os.environ.get("CODECHECKER") or "CodeChecker"
    if shutil.which(cc) is None:
        cc = f"{os.path.expanduser('~')}/.local/bin/CodeChecker"
    return cc


def fail(msg: str) -> None:
    print(f"run_codechecker: {msg}", file=sys.stderr)
    sys.exit(2)


def parse_args(argv: list[str]) -> tuple[int, str]:
    """Faithful reproduction of the bash while/case arg loop."""
    regen = 0
    flt = ""
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--regen":
            regen = 1
        elif arg == "--filter":
            i += 1                          # shift
            flt = argv[i] if i < len(argv) else ""   # "${1:-}"
        else:
            flt = arg                       # bare path-prefix arg, back-compat with run_fanalyzer.sh
        i += 1                              # shift
    return regen, flt


def read_var(name: str) -> str:
    """Read a make variable from the build Makefile exactly as the bash read_var() does."""
    try:
        cp = subprocess.run(
            ["make", "-s", "--no-print-directory", "-C", NGX_BUILD, "-f", "objs/Makefile",
             f"--eval=__pf: ; @printf '%s' \"$({name})\"", "__pf"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        return ""
    return cp.stdout


def main() -> int:
    cc = resolve_cc()
    regen, flt = parse_args(sys.argv[1:])
    _validate_environment(cc)
    cflags, all_incs = _compiler_flags()
    selected = _selected_sources(flt)
    work = tempfile.mkdtemp()
    try:
        return run(cc, regen, flt, cflags, all_incs, selected, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _validate_environment(cc):
    if not _codechecker_available(cc):
        fail("CodeChecker not found (pip install --user codechecker); also needs clang + clang-tidy")
    _validate_clang()
    _validate_makefile()


def _codechecker_available(cc):
    return shutil.which(cc) is not None or (
        os.path.isfile(cc) and os.access(cc, os.X_OK)
    )


def _validate_clang():
    if shutil.which("clang") is None:
        fail("clang not found (clangsa backend)")


def _validate_makefile():
    if not os.path.isfile(MK):
        fail(f"no configured build at {NGX_BUILD} (need objs/Makefile; run ./configure first)")


def _compiler_flags():
    cflags = read_var("CFLAGS")
    all_incs = read_var("ALL_INCS")
    if not cflags:
        fail(f"could not read CFLAGS from {MK}")
    cflags = re.sub(r"-Werror(=[a-z-]+)?", "", cflags)
    return cflags, all_incs


def _selected_sources(flt):
    mk_text = Path(MK).read_text()
    srcs = sorted(set(re.findall(rf"{re.escape(str(REPO))}/src/[^ \n]+\.c", mk_text)))
    if not srcs:
        fail(f"no addon sources found in {MK}")
    selected = [source for source in srcs if _selected(source, flt)]
    if not selected:
        fail(f"no sources selected (filter='{flt}')")
    return selected


def _selected(source, flt):
    return not flt or source.startswith(f"{REPO}/{flt}")


def run(cc: str, regen: int, flt: str, cflags: str, all_incs: str,
        selected: list[str], work: str) -> int:
    ccj = _write_compile_database(work, cflags, all_incs, selected)
    skip = _write_skip_file(work)
    disable_args = _disable_args()
    reports, analyze_log = _analyze(cc, ccj, skip, disable_args, selected, work)
    _check_failed_reports(reports, analyze_log)
    current, current_txt = _parse_current(cc, reports, work)
    print(f"== {len(current)} finding(s) (baseline + new) ==")
    if regen == 1:
        return _regenerate(current, flt)
    if flt:
        return _report_filter(cc, reports, current_txt, flt)
    return _gate_current(current)


def _write_compile_database(work, cflags, all_incs, selected):
    path = f"{work}/compile_commands.json"
    db = [{"directory": NGX_BUILD,
           "command": f"clang -c {cflags} {all_incs} {s} -o /dev/null",
           "file": s} for s in selected]
    with open(path, "w") as fh:
        json.dump(db, fh)
    print(f"compile_commands.json: {len(db)} entrie(s)")
    return path


def _write_skip_file(work):
    path = f"{work}/skip.txt"
    Path(path).write_text(
        f"-{NGX_BUILD}/*\n"
        "-/usr/*\n"
        f"+{REPO}/src/*\n"
        "-*\n"
    )
    return path


def _disable_args():
    disable_args = []
    for checker in CC_DISABLE:
        if checker:
            disable_args += ["--disable", checker]
    return disable_args


def _analyze(cc, compile_db, skip, disable_args, selected, work):
    print(f"== analyzing {len(selected)} source file(s) with: {ANALYZERS} (-j {JOBS}) ==")
    if disable_args:
        print(f"   disabled by policy: {' '.join(CC_DISABLE)}")
    analyze_log = f"{work}/analyze.log"
    reports = f"{work}/reports"
    with open(analyze_log, "wb") as log:
        subprocess.run(
            [cc, "analyze", compile_db,
             "--analyzers", *ANALYZERS.split(),
             *disable_args,
             "-i", skip,
             "-j", JOBS,
             "-o", reports],
            stdout=log, stderr=subprocess.STDOUT,
        )
    return reports, analyze_log


def _check_failed_reports(reports, analyze_log):
    failed_dir = f"{reports}/failed"
    entries = sorted(os.listdir(failed_dir)) if os.path.isdir(failed_dir) else []
    if not entries:
        return
    count = len(entries)
    print(f"---- {count} translation unit(s) FAILED to compile — analysis did NOT run on them ----")
    for name in entries[:20]:
        print(name)
    print(f"(see {analyze_log}; likely a clang-incompatible flag or missing header / bad NGX_BUILD)",
          file=sys.stderr)
    fail(f"{count} TU(s) failed under the analyzer flags — fix flag extraction before trusting a clean gate")


def _parse_current(cc, reports, work):
    parse_json = f"{work}/parse.json"
    with open(parse_json, "wb") as out:
        subprocess.run([cc, "parse", reports, "-e", "json"],
                       stdout=out, stderr=subprocess.DEVNULL)
    current = collect_current(parse_json)
    current_txt = f"{work}/current.txt"
    Path(current_txt).write_text("".join(k + "\n" for k in current))
    return current, current_txt


def _regenerate(current, flt):
    if flt:
        fail("--regen must run over the FULL tree (drop --filter)")
    with open(BASELINE, "w") as stream:
        stream.write("# codechecker baseline — clangsa + clang-tidy findings, keyed by content hash.\n")
        stream.write("# Format: <repo-relative path> │ <checker> │ <report_hash>\n")
        stream.write("# Regenerate with: tools/ci/run_codechecker.py --regen   (review the diff!)\n")
        stream.write("".join(key + "\n" for key in current))
    print(f"run_codechecker: baseline rewritten ({len(current)} findings) → {BASELINE}")
    return 0


def _report_filter(cc, reports, current_txt, flt):
    print(f"run_codechecker: filter run (no gate). Findings under '{flt}':")
    result = subprocess.run([cc, "parse", reports], stderr=subprocess.DEVNULL)
    if result.returncode != 0:
        sys.stdout.write(Path(current_txt).read_text())
    return 0


def _gate_current(current):
    baseline = _baseline()
    new = _new_findings(current, baseline)
    if new:
        return _report_new_findings(new)
    print(f"run_codechecker: OK — no new findings beyond the {len(current)}-entry baseline")
    return 0


def _baseline():
    if not os.path.isfile(BASELINE):
        fail(f"no baseline at {BASELINE} — create it with --regen")
    return load_baseline(BASELINE)


def _new_findings(current, baseline):
    return [key for key in current if key not in baseline]


def _report_new_findings(new):
    print(f"---- NEW findings not in baseline ({len(new)}) ----")
    for key in new:
        print(key)
    print(f"run_codechecker: FAIL — {len(new)} new finding(s). For a human view of one file, run:",
          file=sys.stderr)
    print("               tools/ci/run_codechecker.py --filter <path-prefix>", file=sys.stderr)
    print("               Fix them, or if false-positive, review and re-baseline with --regen",
          file=sys.stderr)
    return 1


def collect_current(parse_json: str) -> list[str]:
    """Normalise the CodeChecker JSON report dump to sorted churn-stable keys."""
    repo = str(REPO).rstrip("/") + "/"
    doc = _load_report(parse_json)
    reports = _report_list(doc)
    keys = filter(None, (_report_key(report, repo) for report in reports))
    return sorted(set(keys))


def _load_report(path):
    try:
        with open(path) as stream:
            return json.load(stream)
    except Exception:
        return {}


def _report_list(document):
    if isinstance(document, dict):
        return document.get("reports", [])
    return document if isinstance(document, list) else []


def _report_key(report, repo):
    file_value = report.get("file")
    path = file_value.get("path") if isinstance(file_value, dict) else file_value
    path = (path or "").replace(repo, "")
    if not path.startswith("src/"):
        return None
    return f"{path} │ {report.get('checker_name', '?')} │ {report.get('report_hash', '')}"


def load_baseline(path: str) -> set[str]:
    """grep -vE '^[[:space:]]*#' | sed '/^[[:space:]]*$/d' | sort -u — as a set for membership."""
    out = set()
    for line in Path(path).read_text().splitlines():
        if re.match(r"^[ \t]*#", line):
            continue
        if re.match(r"^[ \t]*$", line):
            continue
        out.add(line)
    return out


if __name__ == "__main__":
    sys.exit(main())
