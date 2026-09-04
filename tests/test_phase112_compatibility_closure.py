"""Phase-112 closure: every compatibility, feature and security discovery made
while removing the deprecated observability surface, pinned as an assertion.

Phase 112 deleted eleven metric families, three plane-local `$*_cache`
variables (and their handlers) and the seven `$brix_session_*` aliases. The
removals themselves are asserted elsewhere: nginx rejects a removed name at
config-parse time (`test_phase_112_removed_variable_is_now_unknown`), the JSON
record carries each fact exactly once (W3's
`test_phase_112_access_json_carries_each_fact_exactly_once`),
`test_check_directive_registry.py` (the R14/R15 pins from both sides of the
IMPLEMENTED trigger), `test_check_metric_naming.py` (M1/M2) and
`test_cachemx_exposition.py` (one latency histogram).

What this file pins is the set of things the removal WORK discovered — facts
that were true only by accident until they were checked, and that no other
assertion holds:

  * compatibility — no tracked config or `log_format` names a brix-owned
                    variable the module does not register (a removed name in a
                    shipped config is not a degraded log line, it is a server
                    that refuses to start), and the lowercase `hit`/`fill`/`neg`
                    disposition survives ONLY in the cvmfs error-log trace,
                    which two live consumers still grep
  * feature      — the per-plane cache-status maps are total over their source
                    enums (cvmfs FILL→MISS, NEG→NEGHIT; oci/rpm LOCAL→HIT,
                    refused/error→"-"), the byte fold is client-perspective
                    (tx→`_read`, rx→`_written`) and cannot double-count, the
                    latency unit is seconds, and the families that merely LOOK
                    like the removed set are still emitted
  * security     — no removed alias resolves anywhere in the tree, the fidelity
                    loss the phase accepted is genuinely mitigated
                    (`{port,auth}` attribution survives on the request and wire
                    ledgers), and the guard carrying the deprecation pin is
                    invoked by CI with `--fail` (wired is not the same as
                    gating)

Run:
    PYTHONPATH=tests pytest tests/test_phase112_compatibility_closure.py -v
"""

from __future__ import annotations

import importlib.util as _ilu
import re
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.xdist_group("phase112-closure")]

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
REGISTRY_GUARD = ROOT / "tools" / "ci" / "check_directive_registry.py"


def _text(rel):
    return (SRC / rel).read_text()


def _strip(text):
    """C source with comments removed — a comment naming a removed symbol is
    documentation, not a live reference."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def _registered_variables():
    """The names the modules actually register, straight from the guard that
    owns that extraction — reimplementing it here would let the two drift."""
    spec = _ilu.spec_from_file_location("cdr", REGISTRY_GUARD)
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return {name for name, _ in mod._collect_variables()}


def _tracked_files():
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files"],
                         capture_output=True, text=True, check=True)
    return out.stdout.split()


# ---------------------------------------------------------------------------
# compatibility — a config naming a removed variable is a startup failure
# ---------------------------------------------------------------------------

# Variables in these namespaces are ours to register; anything else in a config
# belongs to nginx or to a third-party module and is not ours to police.
OWNED_PREFIX = ("brix_", "cvmfs_", "oci_", "rpm_")
_VAR = re.compile(r"\$\{?([a-z][a-z0-9_]*)\}?")
# Only in a non-.conf artifact, where the span has to be carved out of a file
# that is mostly NOT nginx config.  A bare `\blog_format\b.*?;` reads PROSE
# as a directive: every docstring and comment that says "log_format" starts a
# span running to the next `;` anywhere below, sweeping unrelated `$names`
# in with it.  That is how a docstring saying ``log_format`` still names
# ``$cvmfs_cache`` was reported as a config artifact nginx would reject.
# Two bounds keep prose out and cost no real directive: nginx spells the
# directive `log_format <name> ...;` — whitespace then a bare format name,
# never a backtick or quote — and never puts a blank line inside one.
_LOGFMT = re.compile(r"\blog_format[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t\r\n]"
                     r"(?:(?!\n[ \t]*\n).)*?;", re.S)
# A config may mint its own variables; those are as real as a registered one.
_LOCAL_DEF = re.compile(
    r"\b(?:map|geo|split_clients)\b[^;{]*\$([a-z][a-z0-9_]*)\s*\{"
    r"|\bset\s+\$([a-z][a-z0-9_]*)\s")
CONF_SUFFIX = (".conf", ".conf.in", ".conf.example", ".conf.tmpl")
# Prose, C sources and the release-note migration table quote removed spellings
# on purpose; only artifacts nginx will parse are in scope.
SCAN_SKIP = ("docs/", "CHANGELOG.md", "src/", "client/", "shared/")


def _owned(name):
    # a trailing underscore is a metric/glob stub, never a variable name
    return name.startswith(OWNED_PREFIX) and not name.endswith("_")


def _scannable(root, rel):
    """The text of a tracked file nginx may parse, or None."""
    if rel.startswith(SCAN_SKIP) or "_archive/" in rel:
        return None
    try:
        return (Path(root) / rel).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _parsed_spans(rel, text):
    """The regions of one file nginx resolves variables in: a whole config, and
    any `log_format` directive wherever it is embedded (a test, a shell
    script, a chart template)."""
    spans = [text] if rel.endswith(CONF_SUFFIX) else []
    return spans + _LOGFMT.findall(text)


def _span_names(span):
    """Variable names one span references. '#' starts a comment in an nginx
    config, so the rest of such a line is not a directive."""
    body = "\n".join(ln.split("#", 1)[0] for ln in span.splitlines())
    return _VAR.findall(body)


def _excused(name, text, registered, local):
    """A name is excused only if it is registered, minted by this same file
    (`map`/`geo`/`split_clients`/`set`), or accompanied by an
    `unknown "<name>" variable` expectation — a deliberate negative fixture
    proving nginx REJECTS it. Nothing else silences a hit."""
    return (name in registered or name in local
            or f'unknown "{name}" variable' in text)


def _locally_minted(text):
    """Variables this artifact defines for itself — `map`, `geo`,
    `split_clients` and `set` are as real a definition as a registration."""
    return {g for m in _LOCAL_DEF.finditer(text) for g in m.groups() if g}


def _referenced_names(rel, text):
    return [n for span in _parsed_spans(rel, text) for n in _span_names(span)]


def _unregistered_in_file(rel, text, registered):
    """Names one file references that nginx would refuse to resolve."""
    local = _locally_minted(text)
    return [n for n in _referenced_names(rel, text)
            if _owned(n) and not _excused(n, text, registered, local)]


def _unregistered_variable_uses(root, registered, files):
    """(file, name) for every brix-owned variable an nginx-parsed artifact
    names that the modules do not register."""
    texts = ((rel, _scannable(root, rel)) for rel in files)
    return sorted({(rel, name)
                   for rel, text in texts if text is not None
                   for name in _unregistered_in_file(rel, text, registered)})


def test_no_tracked_config_names_an_unregistered_variable():
    """(success) Every brix-owned $variable a tracked config or log_format
    names is one a module registers.

    This is the compatibility class the removal created: nginx resolves
    variables at config-parse time, so a shipped artifact still naming
    $cvmfs_cache does not log '-' — it aborts startup. The sweep found one
    live case, the reverse-proxy log_format the cvmfs live extension writes
    (tests/cmdscripts/cvmfs_live_ext_part2.py), which would have failed at
    `nginx -t` in a lane no PR tier runs. Nothing in the suite would have
    caught it; this scan is what does."""
    stale = _unregistered_variable_uses(ROOT, _registered_variables(),
                                        _tracked_files())
    assert stale == [], "config artifacts name variables nginx will reject: " \
        + ", ".join(f"{f}:${n}" for f, n in stale)


def test_unregistered_variable_scan_is_not_vacuous(tmp_path):
    """(error) The scan really detects a removed spelling — a config naming
    $cvmfs_cache is a finding, and the same config is clean once the name is
    the canonical one.

    The synthetic config below names a variable nginx must refuse: loading it
    for real aborts with `unknown "cvmfs_cache" variable`. That sentence is
    also what excuses this file from its own scan, which reads every tracked
    artifact including this one — a negative fixture has to declare itself."""
    conf = tmp_path / "site.conf"
    conf.write_text(
        "log_format cvmfs 'class=$cvmfs_class cache=$cvmfs_cache';\n")
    registered = {"cvmfs_class", "brix_cache_status"}
    assert _unregistered_variable_uses(tmp_path, registered, ["site.conf"]) \
        == [("site.conf", "cvmfs_cache")]

    conf.write_text(
        "log_format cvmfs 'class=$cvmfs_class cache=$brix_cache_status';\n")
    assert _unregistered_variable_uses(tmp_path, registered,
                                       ["site.conf"]) == []


def test_local_and_negative_fixture_names_are_excused(tmp_path):
    """(error) The two legitimate excuses work and are the only ones: a
    variable the config mints itself, and a name a test asserts nginx
    REJECTS. Neither may be reported; an unexcused third name still is.

    The unexcused name here is one nginx must refuse for real —
    `unknown "brix_session_dn" variable` — which is what keeps this fixture
    from being a finding when the scan reads this file."""
    (tmp_path / "map.conf").write_text(
        "map $status $brix_upstream_ok { default 1; }\n"
        "log_format m 'ok=$brix_upstream_ok gone=$brix_session_dn';\n")
    (tmp_path / "neg.py").write_text(
        'CONF = "log_format n \'$brix_session_vo\';"\n'
        '# nginx must refuse: unknown "brix_session_vo" variable\n')
    found = _unregistered_variable_uses(tmp_path, {"brix_cache_status"},
                                        ["map.conf", "neg.py"])
    assert found == [("map.conf", "brix_session_dn")]


# The config scan above skips docs/ on purpose — prose quotes removed names to
# explain the removal. But a fenced code block in a CURRENT operator doc is not
# prose: it is the copy-paste source an operator migrates from, and a removed
# variable in one is the same startup abort a shipped config would be. Frozen
# docs (the refactor tree, archives, the CHANGELOG migration table) quote the
# old names by design and are not operator copy sources.
_FENCE = re.compile(r"```.*?\n(.*?)```", re.S)
DOC_FREEZE = ("docs/refactor/", "docs/_archive/", "docs/superpowers/",
              "history-", "brix-rename-migration")


def _operator_docs(files):
    return [f for f in files if f.endswith(".md") and f != "CHANGELOG.md"
            and not any(s in f for s in DOC_FREEZE)]


def _removed_vars_in_fences(text):
    """Removed variable spellings referenced inside a doc's ``` code fences —
    the same 13 names the security section pins as unregistered."""
    removed = set(REMOVED_VARIABLES)
    return {(block_i, n)
            for block_i, block in enumerate(_FENCE.findall(text))
            for n in set(_VAR.findall(block)) if n in removed}


def _doc_fence_offenders(root, files):
    out = []
    for rel in _operator_docs(files):
        try:
            text = (Path(root) / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        out += [f"{rel}:${n}" for _i, n in sorted(_removed_vars_in_fences(text))]
    return sorted(set(out))


def test_no_operator_doc_example_names_a_removed_variable():
    """(compatibility) W5 removed the compatibility-era examples, not just the
    variables. An operator does not read the source registrations — they copy a
    `log_format` out of a protocol or configuration doc, and nginx resolves
    variables at parse time, so a fenced example still naming `$cvmfs_cache`
    hands them a config that aborts startup. The config scan cannot catch this
    because it skips docs/ (prose legitimately quotes the dead names); this
    checks the one part of a doc that is executable — its code fences — over the
    current operator docs only, leaving the frozen refactor/archive tree and the
    CHANGELOG migration table their historical spellings."""
    offenders = _doc_fence_offenders(ROOT, _tracked_files())
    assert offenders == [], (
        "operator docs carry copy-pasteable examples naming removed variables — "
        "an operator migrating from them writes a config nginx rejects: "
        + ", ".join(offenders))


def test_doc_fence_scan_distinguishes_an_example_from_prose(tmp_path):
    """(error) The scan fires on a removed name inside a code fence and ignores
    the same name in prose and in a canonical fence — the distinction the whole
    check rests on. A doc that merely says the word `$cvmfs_cache` while
    explaining the removal is not a finding; a fenced `log_format` using it is."""
    (tmp_path / "docs").mkdir()
    prose = tmp_path / "docs" / "note.md"
    prose.write_text("Phase 112 removed `$cvmfs_cache`; use `$brix_cache_status`.\n")
    assert _doc_fence_offenders(tmp_path, ["docs/note.md"]) == []

    stale = tmp_path / "docs" / "guide.md"
    stale.write_text("```nginx\nlog_format c 'cache=$cvmfs_cache';\n```\n")
    assert _doc_fence_offenders(tmp_path, ["docs/guide.md"]) == \
        ["docs/guide.md:$cvmfs_cache"]

    stale.write_text("```nginx\nlog_format c 'cache=$brix_cache_status';\n```\n")
    assert _doc_fence_offenders(tmp_path, ["docs/guide.md"]) == []


LOWERCASE_DISPOSITION = re.compile(r"cache=(?:hit|fill|neg)\b")


def _lowercase_disposition_readers():
    """Tracked artifacts reading a lowercase cache disposition somewhere other
    than the cvmfs-trace error-log line that legitimately still emits one."""
    out = []
    for rel in _tracked_files():
        text = _scannable(ROOT, rel)
        lines = text.splitlines() if text is not None else []
        out += [f"{rel}: {ln.strip()[:80]}" for ln in lines
                if LOWERCASE_DISPOSITION.search(ln) and "cvmfs-trace" not in ln]
    return out


def test_lowercase_disposition_survives_only_in_the_error_log_trace():
    """(compatibility) Phase 112 removed $cvmfs_cache from the ACCESS log, so
    every access-log consumer now reads HIT/MISS. It did not touch
    handler_finalize.c's `cvmfs-trace:` ERROR-log line, which still prints
    hit/fill/neg — and two live consumers still grep exactly that.

    The two halves must not be confused in either direction: 'finishing' the
    rename in the C trace breaks those consumers, and an access-log consumer
    regressing to lowercase silently never matches again."""
    trace = _strip(_text("protocols/cvmfs/handler_finalize.c"))
    assert '{ "-", "hit", "fill", "neg" }' in trace, (
        "the cvmfs-trace error-log line no longer spells the plane-local "
        "disposition — run_cvmfs_upstream_metrics.sh and cvmfs_live_ext_part3 "
        "grep it")
    offenders = _lowercase_disposition_readers()
    assert offenders == [], (
        "lowercase cache disposition read outside the cvmfs-trace error-log "
        "line — the access log emits $brix_cache_status (HIT/MISS/NEGHIT):\n"
        + "\n".join(offenders))


def test_the_error_log_trace_consumers_are_still_there():
    """(success) The check above is only meaningful while consumers of the
    trace exist — if both went away, 'no lowercase reader outside the trace'
    would be vacuously true and the split it protects would be untested."""
    for rel in ("k8s-tests/remote-suite/tests/run_cvmfs_upstream_metrics.sh",
                "tests/cmdscripts/cvmfs_live_ext_part3.py"):
        text = (ROOT / rel).read_text()
        assert "cvmfs-trace" in text and LOWERCASE_DISPOSITION.search(text), (
            f"{rel} no longer greps the cvmfs-trace disposition")


# ---------------------------------------------------------------------------
# feature — the vocabulary, the fold and the unit
# ---------------------------------------------------------------------------

def test_cvmfs_plane_map_is_total_over_its_own_enum():
    """(feature) $brix_cache_status is now the ONLY reader of the cvmfs
    plane's disposition, so cvmfs_cache_status() must translate every value
    cvmfs.h defines. FILL is nginx's MISS (went to the origin and populated)
    and NEG is NEGHIT; a new plane enum value with no arm here silently
    renders NONE."""
    header = _text("protocols/cvmfs/cvmfs.h")
    defined = set(re.findall(r"#define\s+(BRIX_CVMFS_CACHE_\w+)", header))
    assert defined == {"BRIX_CVMFS_CACHE_NONE", "BRIX_CVMFS_CACHE_HIT",
                       "BRIX_CVMFS_CACHE_FILL", "BRIX_CVMFS_CACHE_NEG"}
    body = _strip(_text("core/http/http_variables.c"))
    fn = body.split("cvmfs_cache_status(ngx_uint_t", 1)[1].split("}", 1)[0]
    for value, want in (("BRIX_CVMFS_CACHE_HIT", "BRIX_CACHE_STATUS_HIT"),
                        ("BRIX_CVMFS_CACHE_FILL", "BRIX_CACHE_STATUS_MISS"),
                        ("BRIX_CVMFS_CACHE_NEG", "BRIX_CACHE_STATUS_NEGHIT")):
        assert re.search(rf"case\s+{value}\s*:\s*return\s+{want}\s*;", fn), (
            f"cvmfs_cache_status lost the {value} -> {want} arm")
    assert re.search(r"default\s*:\s*return\s+BRIX_CACHE_STATUS_NONE\s*;", fn)


def test_oci_rpm_plane_map_records_the_accepted_fidelity_loss():
    """(feature) The removed $oci_cache/$rpm_cache rendered five words; the
    cross-plane vocabulary has no word for 'local', 'refused' or 'error', so
    LOCAL folds onto HIT (served with no origin contact) and refused/error
    report the '-' sentinel rather than pretending to be a cache decision.

    That is the phase's accepted loss IN A LOG LINE; the finer disposition
    stays a label on brix_{oci,rpm}_requests_total{outcome}, which this test
    also requires to still exist."""
    body = _strip(_text("core/http/http_variables.c"))
    fn = body.split("oci_rpm_cache_status(ngx_uint_t", 1)[1].split("}", 1)[0]
    assert re.search(r"case\s+0\s*:.*return\s+BRIX_CACHE_STATUS_HIT", fn)
    assert re.search(r"case\s+1\s*:.*return\s+BRIX_CACHE_STATUS_MISS", fn)
    assert re.search(r"case\s+2\s*:.*return\s+BRIX_CACHE_STATUS_HIT", fn), (
        "LOCAL must fold onto HIT — it is a serve with no origin contact")
    assert re.search(r"default\s*:.*return\s+BRIX_CACHE_STATUS_NONE", fn), (
        "refused/error are not cache dispositions; they must report '-'")
    for family in ("brix_oci_requests_total", "brix_rpm_requests_total"):
        hits = subprocess.run(["git", "-C", str(ROOT), "grep", "-l", family,
                               "--", "src/"], capture_output=True, text=True)
        assert hits.stdout.strip(), (
            f"{family} is gone — the outcome detail the log line gave up has "
            "nowhere left to live")


def test_byte_fold_direction_is_client_perspective():
    """(feature) brix_io_bytes_read is named from the CLIENT's side — a client
    read is a server transmit — so the removed *_bytes_tx_total families fold
    into _read and *_bytes_rx_total into _written. Reversing this swaps every
    byte assertion in the suite while leaving the totals plausible."""
    rec = _strip((SRC / "observability/metrics/unified_record.c").read_text())
    fold = rec.split("brix_metric_op_done(brix_proto_t", 1)[1]
    fold = fold.split("brix_metric_op_latency", 1)[0]
    assert re.search(r"BRIX_METRIC_OP_READ.*io_bytes_read", fold, re.S)
    assert re.search(r"BRIX_METRIC_OP_WRITE.*io_bytes_written", fold, re.S)
    exp = (SRC / "observability/metrics/unified_export_io.c").read_text()
    body = exp.split("unified_emit_io_bytes(metrics_writer_t", 1)[1]
    body = body.split("\n}\n", 1)[0]
    read_half, written_half = body.split("# HELP brix_io_bytes_written", 1)
    for half, side, legacy in ((read_half, "tx", "shm, 0"),
                               (written_half, "rx", "shm, 1")):
        for shm_field in ("webdav.bytes_%s_total", "s3.bytes_%s_total"):
            assert shm_field % side in half, (
                f"brix_io_bytes_{'read' if side == 'tx' else 'written'} no "
                f"longer folds the {side} counters — the removed families "
                "reported exactly those SHM words")
        assert f"brix_unified_legacy_stream_bytes({legacy})" in half
        wrong = "rx" if side == "tx" else "tx"
        assert f"webdav.bytes_{wrong}_total" not in half, (
            "the byte fold is reversed: read is the client's read, i.e. the "
            "server's TRANSMIT")


# Four callsites, not three: the VFS post-op observer is the fourth, and its
# opt-out is what keeps the export-time fold from double counting.
OP_DONE_CALLERS = {"src/protocols/s3/metrics.c",
                   "src/protocols/webdav/metrics.c",
                   "src/protocols/gridftp/ev/ftp_ev_metrics.c",
                   "src/fs/vfs/vfs_observe_internal.h"}


def _op_done_callsites():
    hits = subprocess.run(
        ["git", "-C", str(ROOT), "grep", "-n", "brix_metric_op_done(", "--",
         "src/"], capture_output=True, text=True, check=True).stdout
    return [ln for ln in hits.splitlines()
            if not ln.split(":", 1)[0].endswith(".md")
            and "brix_metric_op_done(brix_proto_t" not in ln
            and not re.search(r":\d+:\s*\*", ln)]


def test_op_done_has_four_callsites_not_three():
    """(feature) The fold is lossless only because unified.io_bytes_*[proto]
    holds no data-plane bytes, and the census that establishes it must be the
    real one: the phase doc's first draft said 'exactly three callsites',
    counting the protocol emitters a grep of src/protocols shows. The fourth
    is the VFS post-op observer, which passes REAL bytes — the one callsite
    that could double-count against the export-time fold, and therefore the
    one that had to be checked. A fifth appearing anywhere is a re-audit."""
    calls = _op_done_callsites()
    assert {ln.split(":", 1)[0] for ln in calls} == OP_DONE_CALLERS, calls


def test_http_emitters_pass_no_bytes_to_op_done():
    """(feature, condition 1 of 3) The webdav and s3 emitters pass bytes = 0,
    so their protocol's unified byte counter stays zero and the export-time
    fold of shm->{webdav,s3}.bytes_* supplies the whole value instead of a
    second copy of part of it."""
    for rel in ("protocols/s3/metrics.c", "protocols/webdav/metrics.c"):
        body = _strip(_text(rel))
        call = body.split("brix_metric_op_done(", 1)[1].split(";", 1)[0]
        assert re.search(r"[,(]\s*0\s*,", call), (
            f"{rel} now passes bytes to brix_metric_op_done — it would be "
            "counted twice, once here and once in the export-time fold")


def test_staged_commit_opts_out_of_io_metering():
    """(feature, condition 2 of 3) The three staged-commit observations pass
    meter_io = 0 because the owning protocol books those bytes itself. Flipping
    one to 1 doubles every PUT's contribution to brix_io_bytes_written."""
    staged = _strip((SRC / "fs/vfs/vfs_staged.c").read_text())
    commits = staged.count("brix_vfs_observe_ctx_op_ex(")
    assert commits == 3 and staged.count("start, 0)") == commits, (
        "a staged-commit observation no longer opts out of io metering "
        "(meter_io = 0) — the plane books those bytes too")


def test_the_data_path_never_reaches_the_vfs_observer():
    """(feature, condition 3 of 3) vfs_read.c and vfs_write.c contain no
    observe call at all: a served byte is zero-copy and is booked once, at the
    plane's serve site. Adding an observation there would land data-plane
    bytes in unified.io_bytes_*[proto] AND in the fold, doubling every
    canonical byte total while leaving it entirely plausible."""
    for rel in ("fs/vfs/vfs_read.c", "fs/vfs/vfs_write.c"):
        assert "brix_vfs_observe" not in _text(rel), (
            f"{rel} now observes: data-path bytes would land in "
            "unified.io_bytes_*[proto] AND in the export-time fold")


def test_latency_is_exposed_in_seconds_only():
    """(feature, breaking) The unit change is real, not a rename: _sum is
    %.6f seconds (sum_usec / 1000000.0) and every bucket `le` is a second
    boundary. A recording rule dividing _sum by _count against a microsecond
    threshold is now wrong by 10^6, which is why the release note calls it
    out. No _usec latency histogram may survive to be mistaken for it."""
    exp = (SRC / "observability/metrics/unified_export_io.c").read_text()
    assert 'brix_io_latency_seconds_sum{proto=\\"%s\\",op=\\"%s\\"} %.6f' in exp
    assert "(double) sum_usec / 1000000.0" in exp
    assert '"{proto=\\"%s\\",op=\\"%s\\",le=\\"%.6f\\"} %llu\\n"' in exp
    assert "(double) bound_usec / 1000000.0" in exp
    emitted = subprocess.run(
        ["git", "-C", str(ROOT), "grep", "-n", "brix_io_latency_usec", "--",
         "src/"], capture_output=True, text=True).stdout
    live = [ln for ln in emitted.splitlines()
            if not re.search(r":\s*\*|/\*|//", ln)]
    assert live == [], "a brix_io_latency_usec spelling survives: " + str(live)


# The full IP-version cross-product: they look like members of the removed set
# and are not — each carries a label the unified families do not have, so
# deleting one deletes a fact rather than a spelling.
KEPT_FAMILIES = {
    "brix_%sbytes_%s_%s_total" % (prefix, direction, version): rel
    for prefix, rel in (("webdav_", "observability/metrics/webdav.c"),
                        ("s3_", "observability/metrics/s3.c"),
                        ("", "observability/metrics/stream_family.c"))
    for direction in ("rx", "tx")
    for version in ("ipv4", "ipv6")
}


def test_families_that_only_look_removable_are_still_emitted():
    """(feature, anti-over-removal) Twelve ipv4/ipv6 twins share a prefix with
    the removed families and are NOT duplicates — the unified families carry
    no IP-version label. A later sweep pattern-matching on the removed names
    would take these with it and lose the only per-address-family byte
    breakdown the server has."""
    assert len(KEPT_FAMILIES) == 12
    for family, rel in KEPT_FAMILIES.items():
        assert family in _text(rel), (
            f"{family} was removed with the deprecated set — it carries an "
            "IP-version fact no unified family has")
    for family, rel in (
            ("brix_cache_bytes_evicted_total", "observability/metrics"),
            ("brix_cvmfs_bytes_served", "observability/metrics"),
            ("brix_tpc_bytes_total", "observability/metrics")):
        hits = subprocess.run(["git", "-C", str(ROOT), "grep", "-l", family,
                               "--", f"src/{rel}"],
                              capture_output=True, text=True)
        assert hits.stdout.strip(), f"{family} is a complementary measurement"


# ---------------------------------------------------------------------------
# security / operations negatives
# ---------------------------------------------------------------------------

REMOVED_VARIABLES = ("brix_session_dn", "brix_session_vo", "brix_session_user",
                     "brix_session_auth", "brix_session_tls",
                     "brix_session_bytes_out", "brix_session_bytes_in",
                     "cvmfs_cache", "brix_cvmfs_cache", "oci_cache",
                     "brix_oci_cache", "rpm_cache", "brix_rpm_cache")
REMOVED_HANDLERS = ("cvmfs_var_cache", "oci_var_cache", "rpm_var_cache")


def _live_references(symbol):
    """Source lines naming a symbol, excluding the phase-112 comments left at
    the point of removal to say why it is gone."""
    hits = subprocess.run(["git", "-C", str(ROOT), "grep", "-n", symbol, "--",
                           "src/"], capture_output=True, text=True).stdout
    return [ln for ln in hits.splitlines() if "phase-112" not in ln]


def test_no_removed_alias_is_registered_again():
    """(security-neg) A removed identity alias must not come back through a
    surviving registration. $brix_session_dn/_user carried the authenticated
    subject; a second name for it can drift from $brix_dn/$brix_sub under
    exactly the auth-failure paths where the value matters."""
    registered = _registered_variables()
    back = [n for n in REMOVED_VARIABLES if n in registered]
    assert back == [], f"removed variables are registered again: {back}"


@pytest.mark.parametrize("handler", REMOVED_HANDLERS)
def test_no_orphaned_cache_variable_handler_survives(handler):
    """(security-neg) The handlers went with the registrations. One left
    compiled in is a second implementation of a disposition
    $brix_cache_status already owns — the duplication this phase exists to
    end, and the shape that lets two readers of one ctx field disagree."""
    assert _live_references(handler) == [], f"{handler}() survives the removal"


CANONICAL_CARRIERS = ("brix_dn", "brix_sub", "brix_vo", "brix_auth_method",
                      "brix_tls", "brix_bytes_served", "brix_bytes_received",
                      "brix_cache_status")


def test_every_removed_fact_still_has_a_canonical_carrier():
    """(success) Removing an alias is only lossless while the canonical name
    is registered. If one of these disappeared the phase would have deleted a
    FACT — an operator's DN, VO or byte totals — not a spelling of one."""
    registered = _registered_variables()
    missing = [n for n in CANONICAL_CARRIERS if n not in registered]
    assert missing == [], f"the removed facts have no carrier: {missing}"


# The removal's positive boundary. Phase 112 deleted the three `$*_cache`
# variables and their `*_var_cache` handlers ONLY; the `$*_class`/`$*_origin`
# plane aliases that share the very same module files are the survivors
# config-reference.md's "Deprecated names" section promises still resolve. The
# cull and the survivors sit two `ngx_string(...)` rows apart.
SURVIVING_ALIASES = ("cvmfs_class", "cvmfs_origin", "oci_class", "rpm_class")
SURVIVING_HANDLERS = ("cvmfs_var_class", "cvmfs_var_origin",
                      "oci_var_class", "rpm_var_class")
CONFIG_REFERENCE = ROOT / "docs" / "03-configuration" / "config-reference.md"


def test_the_cull_stopped_at_cache_class_and_origin_aliases_survive():
    """(security-neg / boundary) Phase 112 removed the `$*_cache` variables and
    their `*_var_cache` handlers ONLY. The `$*_class`/`$*_origin` aliases that
    live in the same three module files — `cvmfs_var_class` sits two rows below
    the deleted `cvmfs_var_cache` — are the survivors, and every removal test
    only asserts the cache names are GONE, so a sweep that took a `*_var_class`
    with the `*_var_cache` beside it would delete the class/origin FACT and stay
    green. This pins the positive boundary: each survivor registers under both
    spellings and its handler still exists."""
    registered = _registered_variables()
    for alias in SURVIVING_ALIASES:
        for name in (alias, "brix_" + alias):
            assert name in registered, (
                f"${name} no longer registers — the cache-variable cull "
                "over-reached into the class/origin aliases it was to keep")
    for handler in SURVIVING_HANDLERS:
        assert _live_references(handler), (
            f"{handler}() is gone — swept out with the *_var_cache handlers, "
            "taking its plane's class/origin fact with it")


def _deprecated_names_section():
    """The body of config-reference.md's `### Deprecated names` section."""
    text = CONFIG_REFERENCE.read_text()
    m = re.search(r"\n### Deprecated names\n(.*?)(?=\n#{2,3} )", text, re.S)
    return m.group(1) if m else ""


def _resolve_paragraph(section):
    """The paragraph promising some aliases still resolve."""
    for para in section.split("\n\n"):
        if "still resolve" in para:
            return para
    return ""


def _promised_resolvers(resolve):
    """Alias names a 'still resolve' paragraph lists, dropping the `$brix_`
    prefix stub (a trailing underscore is never a real variable name)."""
    return {n for n in re.findall(r"\$([a-z][a-z0-9_]*)", resolve)
            if not n.endswith("_")}


def _unregistered(names, registered):
    return sorted(n for n in names if n not in registered)


def test_config_reference_promises_exactly_the_surviving_aliases_resolve():
    """(compatibility / doc-vs-code) config-reference.md tells operators which
    unprefixed aliases "still resolve" after the cull. That promise is a
    startup-abort waiting to happen if it drifts: a name it lists that no module
    registers makes an operator write a `log_format` nginx then refuses. This
    pins the promise to the registry from both ends — it names EXACTLY the four
    surviving aliases (no removed `$*_cache`, no over-claim), and every name it
    lists is one a module actually registers."""
    section = _deprecated_names_section()
    assert section, "config-reference.md lost its 'Deprecated names' section"
    named = _promised_resolvers(_resolve_paragraph(section))
    assert named == set(SURVIVING_ALIASES), (
        f"the 'still resolve' promise names {sorted(named)}, not exactly the "
        f"four survivors {sorted(SURVIVING_ALIASES)}")
    unresolvable = _unregistered(named, _registered_variables())
    assert unresolvable == [], (
        f"config-reference promises {unresolvable} resolve, but no module "
        "registers them — the reference is a false promise nginx aborts on")


def test_port_auth_attribution_survives_the_recorded_fidelity_loss():
    """(security-neg / operations) The removed stream byte families were keyed
    {port,auth} — a per-listener, per-security-plane split. The unified family
    sums every slot, so that breakdown IS gone from byte exposition. The loss
    is only acceptable because an operator can still attribute traffic to a
    listener and a security plane through the request and wire ledgers; if
    those lost their labels too, the removal would have blinded the audit."""
    stream = _text("observability/metrics/stream.c")
    assert 'brix_requests_total{port,auth,op,status}' in stream \
        or re.search(r'brix_requests_total\{[^}]*port[^}]*auth', stream), (
        "brix_requests_total lost its {port,auth} keying")
    family = _text("observability/metrics/stream_family.c")
    for direction in ("rx", "tx"):
        assert re.search(
            r'SRV_FAMILY\(SRV_COUNTER_HDR\("brix_wire_bytes_%s_total"'
            % direction, family), (
            f"brix_wire_bytes_{direction}_total is no longer emitted through "
            "the per-server slot scan — its {port,auth} keying is gone")
    assert '"%s{port=\\"%s\\",auth=\\"%s\\"} %lu\\n"' in family, (
        "metrics_emit_srv_family no longer labels its slot lines {port,auth} "
        "— every per-listener attribution in the exporter dies with it")


def test_the_deprecation_pin_is_gating_not_merely_wired():
    """(security-neg / guard) Arming M2 exposed that check_metric_naming.py had
    never been referenced by guards.yml at all and shipped without its mode
    bit, so the guard carrying the pin could not run in CI. Wiring it is not
    enough: without --fail it reports and exits 0, and a pin that cannot fail
    the build is not a pin."""
    guard = ROOT / "tools" / "ci" / "check_metric_naming.py"
    assert guard.stat().st_mode & 0o111, (
        "check_metric_naming.py is not executable; guards.yml invokes guards "
        "as bare paths")
    workflow = (ROOT / ".github" / "workflows" / "guards.yml").read_text()
    assert re.search(r"tools/ci/check_metric_naming\.py\s+--fail", workflow), (
        "guards.yml must run check_metric_naming.py WITH --fail")
