#!/usr/bin/env python3
#
# check_metric_names.py — every Prometheus metric the operator-facing docs cite
# must actually exist in the exposition, with the labels it really carries.
#
# WHAT: Extracts the ground-truth metric surface from the C exporters
#       (family name -> label keys), then scans the documentation, the website
#       and contrib/ for `brix_*` metric references and fails on
#         - a family that no exporter emits            -> "unknown family"
#         - a label key that family never carries      -> "unknown label"
#
# WHY:  A metric name in a doc is executable: operators paste it into an alert
#       rule or a Grafana panel. A name that does not exist does not error —
#       it silently matches nothing, so the alert never fires and the panel
#       stays flat, which reads exactly like "the system is healthy". The
#       2026-08-09 doc sweep found five invented families (brix_bytes_sent_total,
#       brix_errors_total, brix_fd_cache_hits_total, brix_write_through_syncs_total,
#       brix_session_bind_total) plus brix_requests_total{proto} (no such label)
#       and brix_auth_total{method,result} (it is {proto,method,status}). Every
#       one of them had been sitting in the docs long enough to be copied. Prose
#       drifts away from the C for free; this makes it cost a red build.
#
# HOW:  Ground truth comes from the exposition writers under
#       src/observability/metrics/, parsed the way the C preprocessor sees them —
#       adjacent string literals are concatenated first, because the row
#       templates are routinely split across lines:
#           "brix_io_latency_usec_bucket" "{proto=\"%s\",op=\"%s\",le=\"%llu\"}\n"
#       Four emission shapes are recognised:
#         1. `# HELP <name>` / `# TYPE <name>`        -> family declared
#         2. `<name>{key="…",…}`                      -> family + exact labels
#         3. mw_emit_labeled(mw, "<name>", help, "<key>", …) / mw_emit_scalar()
#         4. a bare "brix_…" literal inside the exposition tree (descriptor
#            tables and name-by-variable macros), minus the config directives
#            declared with ngx_string(), which share the brix_ prefix
#       Families whose rows are emitted through a "%s{…}" or "{…}" template
#       inherit the union of that file's templates: permissive on purpose — the
#       guard only ever fails on a label no exporter in the declaring file
#       emits. `# TYPE … histogram` also declares the _bucket/_count/_sum
#       series and the `le` label.
#
#       A doc token is treated as a metric reference when it (a) carries a
#       `{key="…"}` selector, (b) ends in a Prometheus-conventional suffix
#       (_total, _seconds, _ratio, _usec, _megabytes, _percent), (c) appears on
#       a line using a PromQL function, or (d) appears on a line that is a raw
#       exposition sample. Anything else — C symbols, config directives, prose —
#       is left alone: this guard is deliberately narrow, and a fabricated
#       *gauge* mentioned in bare prose is the one drift shape it cannot see.
#
#       Escape hatch: put `metric-names-allow: <reason>` anywhere on the line —
#       in an HTML comment, a PromQL `#` comment, whatever the surrounding
#       syntax allows. Deliberately-invalid examples (high-cardinality
#       anti-patterns) and metrics a design doc is proposing but has not built
#       yet are legitimate; they just have to say so. Everything grandfathered
#       lives in the shrink-only backlog, guarded by check_ratchet_monotonic.py.
#
# USAGE:
#   tools/ci/check_metric_names.py              # verify (CI)
#   tools/ci/check_metric_names.py --regen      # re-freeze the backlog
#   tools/ci/check_metric_names.py --dump       # print the exposition surface

from __future__ import annotations

import re
import sys
from bisect import bisect_left
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKLOG = ROOT / "tools/ci/metric_names_backlog.txt"

#: Where the exposition is written. Bare "brix_…" literals are only trusted as
#: family names inside this tree — elsewhere they are directives and log tags.
EXPOSITION = "src/observability/metrics"

#: Historical records and forward-looking plans: dated by construction, so
#: holding them to today's exposition would mean rewriting the past. The guard
#: protects the surface an operator would copy a query from.
EXCLUDED = (
    "docs/_archive/",
    "docs/doxygen/",
    "docs/superpowers/",
    "docs/refactor/",
    "docs/09-developer-guide/history-",
)

#: Suffixes that mark a token as a metric name rather than a C symbol. Kept
#: conservative: "_bytes"/"_count"/"_read" also end plenty of function names.
METRIC_SUFFIX = ("_total", "_seconds", "_ratio", "_usec", "_megabytes", "_percent")

#: Labels Prometheus itself attaches or that are part of the query language.
UNIVERSAL_LABELS = frozenset({"le", "quantile", "job", "instance"})

#: A PromQL call whose argument list opens immediately before the reference —
#: `rate(brix_…`, `histogram_quantile(0.99, rate(brix_…`. Adjacency is what
#: makes this safe: `min(exp-now, 5min)` in a prose table opens no metric.
PROMQL = re.compile(
    r"\b(?:rate|irate|increase|delta|idelta|sum|avg|min|max|count|group|"
    r"topk|bottomk|stddev|quantile|histogram_quantile|absent|clamp_max|"
    r"clamp_min|predict_linear)\s*\(\s*$"
)
#: A raw exposition sample line: `brix_foo{bar="baz"} 42`.
SAMPLE = re.compile(r"^brix_[a-z0-9_]+(?:\{[^}]*\})?\s+[-+0-9.eE]+$")

ALLOW = "metric-names-allow:"

_NAME = r"brix_[a-z0-9]+(?:_[a-z0-9]+)*"
_LITERAL = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_HELP = re.compile(r"#\s*(?:HELP|TYPE)\s+(" + _NAME + r")\b")
_TYPE = re.compile(r"#\s*TYPE\s+(" + _NAME + r")\s+([a-z]+)")
_ROW = re.compile(r"(" + _NAME + r")\{([^}]*)\}")
_TEMPLATE = re.compile(r"(?:^|%s)\{([^}]*)\}")
_BARE = re.compile(r"^" + _NAME + r"$")
_EMITTED_KEY = re.compile(r'([a-z_]+)=\\"')
_DIRECTIVE = re.compile(r'ngx_string\("(brix_[a-z0-9_]+)"\)')
_EMIT_CALL = re.compile(r"\bmw_emit_(labeled|scalar)\s*\(")

_REFERENCE = re.compile(r"\b(" + _NAME + r")(\{[^}\n]*=[^}\n]*\})?")
_CITED_KEY = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=~?|!=|!~)")
_MARKUP = re.compile(r"</?[a-zA-Z][^>]*>")


# --- ground truth -------------------------------------------------------------


def literals(text: str) -> list[tuple[str, int]]:
    """C string literals, with adjacent-literal concatenation applied.

    WHAT: returns (contents, offset) per logical literal.
    WHY: the exporters split every row template across source lines, so a
    per-literal scan sees "brix_io_ops_total" and "{proto=…}" as unrelated.
    HOW: merge a literal into its predecessor when only whitespace separates
    them — exactly the translation-phase-6 rule.
    """
    out: list[tuple[str, int]] = []
    current: str | None = None
    start = end = 0
    for match in _LITERAL.finditer(text):
        if current is not None and not text[end:match.start()].strip():
            current += match.group(1)
        else:
            if current is not None:
                out.append((current, start))
            current, start = match.group(1), match.start()
        end = match.end()
    if current is not None:
        out.append((current, start))
    return out


@lru_cache(maxsize=None)
def directives(root: Path) -> frozenset[str]:
    """Config directive names — brix_-prefixed, but never metrics.

    Cached, and frozen so a caller cannot poison the cache: both the ground
    truth and the doc scan need this set, and re-walking src/ for the second
    one doubles the guard's runtime for an identical answer.
    """
    found: set[str] = set()
    for path in sorted((root / "src").rglob("*.[ch]")):
        found |= set(_DIRECTIVE.findall(path.read_text(errors="ignore")))
    return frozenset(found)


def _emit_calls(text: str, lits: list[tuple[str, int]]) -> Iterator[tuple[str, str | None]]:
    """Yield (family, label_key) for mw_emit_labeled/mw_emit_scalar calls.

    The writer helpers take (mw, name, help[, label_key]) — all string
    literals, in that order — so the family and its single label key are the
    first and third literals after the call's opening paren.
    """
    offsets = [off for _, off in lits]
    for call in _EMIT_CALL.finditer(text):
        first = bisect_left(offsets, call.end())
        args = [lit for lit, _ in lits[first:first + 3]]
        if not args or not args[0].startswith("brix_"):
            continue
        labelled = call.group(1) == "labeled" and len(args) >= 3
        yield args[0], args[2] if labelled else None


def exposition(root: Path) -> dict[str, set[str]]:
    """Map every emitted family to the label keys it can carry."""
    directive_names = directives(root)
    expo_dir = root / EXPOSITION
    families: dict[str, set[str]] = {}
    kinds: dict[str, str] = {}
    home: dict[str, str] = {}
    templates: dict[str, set[str]] = {}

    for path in sorted((root / "src").rglob("*.[ch]")):
        key = str(path)
        in_exposition = expo_dir in path.parents
        text = path.read_text(errors="ignore")
        lits = literals(text)

        for lit, _ in lits:
            for match in _HELP.finditer(lit):
                families.setdefault(match.group(1), set())
                home.setdefault(match.group(1), key)
            for match in _TYPE.finditer(lit):
                kinds[match.group(1)] = match.group(2)
            for match in _ROW.finditer(lit):
                families.setdefault(match.group(1), set()).update(
                    _EMITTED_KEY.findall(match.group(2)))
                home.setdefault(match.group(1), key)
            if not in_exposition:
                continue
            for match in _TEMPLATE.finditer(lit):
                templates.setdefault(key, set()).update(
                    _EMITTED_KEY.findall(match.group(1)))
            if _BARE.match(lit) and lit not in directive_names:
                families.setdefault(lit, set())
                home.setdefault(lit, key)

        for name, label in _emit_calls(text, lits):
            families.setdefault(name, set())
            home.setdefault(name, key)
            if label:
                families[name].add(label)

    for name, kind in kinds.items():
        if kind != "histogram":
            continue
        for suffix in ("_bucket", "_count", "_sum"):
            families.setdefault(name + suffix, set(families.get(name, ())))
            home.setdefault(name + suffix, home.get(name, ""))
        families[name + "_bucket"].add("le")
        families[name] |= families[name + "_count"]

    # Rows emitted through a name-by-variable template carry that file's labels.
    return {
        name: labels or templates.get(home.get(name, ""), set())
        for name, labels in families.items()
    }


# --- documentation surface ----------------------------------------------------


def doc_files(root: Path) -> Iterator[Path]:
    """Every file whose metric references an operator could act on."""
    yield root / "README.md"
    for pattern in ("docs/**/*.md", "src/**/README.md", "client/**/README.md",
                    "site/src/**/*.astro", "contrib/*.yml", "contrib/*.json"):
        for path in sorted(root.glob(pattern)):
            rel = path.relative_to(root).as_posix()
            if not rel.startswith(EXCLUDED):
                yield path


def normalize(line: str, suffix: str) -> str:
    """Undo the markup that separates a metric name from its selector.

    The site writes `<span class="k">brix_io_bytes_read</span>{'{proto="s3"}'}`
    — a JSX-quoted selector, because a bare `{}` in Astro markup is an empty
    expression that renders as nothing. Strip the tags and the JSX quoting so
    the reference reads as it will on screen.
    """
    if suffix != ".astro":
        return line
    return _MARKUP.sub("", line).replace("{'", "").replace("'}", "")


def references(path: Path) -> Iterator[tuple[int, str, set[str] | None, bool]]:
    """Yield (line, family, cited labels or None, is_metric_context)."""
    suffix = path.suffix
    for number, raw in enumerate(path.read_text(errors="ignore").splitlines(), 1):
        if ALLOW in raw:
            continue
        line = normalize(raw, suffix)
        sample = bool(SAMPLE.match(line.strip()))
        for match in _REFERENCE.finditer(line):
            selector = match.group(2)
            labels = set(_CITED_KEY.findall(selector)) if selector else None
            strict = (labels is not None or sample
                      or match.group(1).endswith(METRIC_SUFFIX)
                      or bool(PROMQL.search(line[:match.start()])))
            yield number, match.group(1), labels, strict


# --- ratchet ------------------------------------------------------------------


def read_backlog() -> set[str]:
    if not BACKLOG.exists():
        return set()
    return {
        line.strip()
        for line in BACKLOG.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }


def findings(root: Path) -> list[tuple[str, str, int]]:
    """Every unproven metric reference: (entry, human message, line)."""
    families = exposition(root)
    known = directives(root)
    out: list[tuple[str, str, int]] = []

    for path in doc_files(root):
        if not path.exists():
            continue
        rel = path.relative_to(root).as_posix()
        for number, name, labels, strict in references(path):
            if name not in families:
                if strict and name not in known:
                    out.append((f"{rel}\t{name}",
                                f"unknown metric family {name}", number))
                continue
            if labels is None:
                continue
            unknown = labels - families[name] - UNIVERSAL_LABELS
            for label in sorted(unknown):
                out.append((f"{rel}\t{name}{{{label}}}",
                            f"{name} carries no label {label!r} "
                            f"(it has {sorted(families[name]) or 'none'})",
                            number))
    return out


def run(root: Path) -> tuple[bool, list[str]]:
    backlog = read_backlog()
    lines: list[str] = []
    new = [f for f in findings(root) if f[0] not in backlog]
    for entry, message, number in new:
        source = entry.split("\t", 1)[0]
        lines.append(f"FAIL {source}:{number}: {message}")
    if new:
        lines.append("")
        lines.append(f"{len(new)} unproven metric reference(s). Fix the doc, or —")
        lines.append("  if the example is deliberately invalid or the metric is")
        lines.append(f"  proposed, not built — add `{ALLOW} <reason>` to the line.")
        return False, lines
    lines.append(f"OK metric names: every cited brix_* family exists "
                 f"({len(backlog)} grandfathered)")
    return True, lines


def regen(root: Path) -> None:
    entries = sorted({entry for entry, _, _ in findings(root)})
    BACKLOG.write_text(
        "# check_metric_names.py backlog — metric references that predate the\n"
        "# guard. Shrink-only (check_ratchet_monotonic.py): fix the doc and\n"
        "# delete the line. Never add here to silence new drift — use the\n"
        f"# `{ALLOW} <reason>` marker, which says why on the spot.\n"
        "#\n"
        "# <file><TAB><family>            unknown family\n"
        "# <file><TAB><family>{<label>}   family exists, label does not\n"
        + "".join(f"{entry}\n" for entry in entries))
    print(f"wrote {BACKLOG.relative_to(root)} ({len(entries)} entries)")


def main() -> int:
    if "--dump" in sys.argv[1:]:
        for name, labels in sorted(exposition(ROOT).items()):
            print(f"{name}\t{','.join(sorted(labels))}")
        return 0
    if "--regen" in sys.argv[1:]:
        regen(ROOT)
        return 0
    passed, lines = run(ROOT)
    print("\n".join(lines))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
