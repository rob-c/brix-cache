"""phase-110 W5 uniform-vocabulary registry rules (R11/R12/R13), plus the two
self-deleting removal pins they grew (R14 aliases, R15 JSON keys).

Split out of check_directive_registry.py to keep that file under the 600-line
focus cap (coding-standards §1). Self-contained: computes its own ROOT and
inlines the plane test, so it imports nothing from the main checker. The main
checker imports the rule functions and re-exports the detector helpers the
tests unit-call.
"""
import glob
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# W5.4 — the deprecated-alias removal registry lives in the allowlist reasons:
# a `removal: phase-<N>` annotation. R14 is the SELF-DELETING PIN: once that
# phase's refactor doc is marked IMPLEMENTED, the alias MUST be gone, so a
# forgotten deprecated name fails CI at exactly the moment its removal is due
# (the same idea as the DEFECT-CANDIDATE self-deleting tests). Dormant until
# then. The refactor-docs dir is env-overridable so the rule's own tests can
# point it at a fixture.
_REFACTOR_DOCS = os.environ.get("BRIX_REGISTRY_REFACTOR_DOCS") or \
    os.path.join(ROOT, "docs", "refactor")
_REMOVAL_RE = re.compile(r"removal:\s*(phase-\d+)")
# ANCHORED at line start (and kept identical in check_metric_naming.py, which
# owns the M2 twin of this pin). Unanchored it also matched a doc that merely
# QUOTES the trigger while explaining the mechanism — phase-112's own §W6 does
# exactly that — so a still-PLANNED doc documenting the pin would arm it on its
# first draft and fail CI on the very commit that opens the deprecation window.
_IMPLEMENTED_RE = re.compile(r"^\*\*Status:\*\*\s*IMPLEMENTED",
                             re.IGNORECASE | re.MULTILINE)


def _w5_plane(rel):
    """Which nginx subsystem a variable registration belongs to."""
    return "stream" if "stream" in rel else "http"


# phase-110 W5: the uniform-vocabulary rules.
#
# PARITY_FACTS — one fact, one name, on BOTH planes (rule 1). Adding one of
# these on a single plane, or with a different spelling per plane, is the
# switching this whole phase exists to remove.
_PARITY_FACTS = frozenset({
    "brix_protocol", "brix_cache_status", "brix_tls",
    "brix_dn", "brix_vo", "brix_fqan", "brix_sub", "brix_issuer",
    "brix_auth_method", "brix_user", "brix_tier", "brix_origin",
    "brix_bytes_served", "brix_bytes_received", "brix_backend_time",
    "brix_checksum", "brix_op", "brix_ops", "brix_path", "brix_status",
    "brix_duration",
})

# VOCAB_FACTS — facts whose VALUE strings must come from the shared
# brix_metric_*_name() functions (rule 2), so the variable, the JSON key and
# the Prometheus label render the identical word. Each maps to (source files
# that implement its handlers, the name function they must call, forbidden
# inline value literals that would mean a hand-spelled vocabulary).
_VOCAB_SOURCE_GROUPS = (
    (
        "src/core/http/http_variables.c",
        "src/core/http/http_variable_identity.c",
        "src/core/http/http_variable_monitor.c",
    ),
    ("src/protocols/root/stream/stream_variables.c",),
)
_VOCAB_REQUIRED_FNS = (
    "brix_metric_cache_status_name",
    "brix_metric_op_name",
    "brix_metric_err_name",
    "brix_metric_auth_method_name",
)
# A value handler that renders one of these words inline has re-invented a
# vocabulary the name function owns. (Config directive VALUES like "on"/"off"
# are fine; these are the metric-vocabulary words.)
_VOCAB_FORBIDDEN_LITERALS = ('"HIT"', '"MISS"', '"BYPASS"', '"NEGHIT"')

# R13 — the JSON access-log keys and the Prometheus labels for the uniform
# facts must equal the variable name minus "brix_". A presence check on the
# canonical spellings; R15 below owns the absence of the superseded ones.
_R13_JSON_SOURCE = "src/observability/metrics/access_log.c"
# The keys as they appear in the C format string (escaped quotes + colon), so
# "sub" is not matched inside "subject".
_R13_REQUIRED_JSON_KEYS = (r'\"cache_status\":', r'\"sub\":',
                           r'\"bytes_served\":', r'\"backend_time_us\":')
_R13_METRIC_SOURCE = "src/observability/metrics/unified_export.c"
_R13_REQUIRED_METRIC = ("brix_cache_requests_total", 'cache_status=')

# R15 — the JSON counterpart of R14's self-deleting pin. Before phase 110 the
# same four facts were spelled twice per record; phase 112 deletes the older
# spelling. Written as key + colon exactly as they appear in the C format
# string, so \"bytes\": cannot match inside \"bytes_served\": and \"subject\":
# cannot match inside a comment mentioning the word. Dormant until
# docs/refactor/phase-112-*.md is IMPLEMENTED — the deprecation window stays
# open on its own terms — and permanent after: re-adding one of these keys
# means one fact is spelled two ways on the same surface again.
_R15_REMOVAL_PHASE = "phase-112"
_R15_REMOVED_JSON_KEYS = (r'\"from_cache\":', r'\"subject\":',
                          r'\"bytes\":', r'\"latency_us\":')


def _plane_names(variables, plane):
    """Set of variable names registered on `plane`."""
    return {n for n, rel in variables if _w5_plane(rel) == plane}


def _parity_gap(fact, http, stream):
    """Where `fact` is missing when it is on EXACTLY ONE plane, else None.

    A fact on BOTH planes is correct. A fact on NEITHER plane is simply not
    implemented in this tree (a minimal test fixture, or a not-yet-built fact)
    — that is a different concern (the variable's own presence tests), not a
    PARITY violation, so R11 stays silent. R11 fires only for the specific
    defect it owns: a $brix_* fact registered on one plane and not the other,
    which is exactly the switching-between-planes bug the phase removes."""
    on_http, on_stream = fact in http, fact in stream
    if on_http == on_stream:            # both, or neither → not a parity gap
        return None
    return "http only" if on_http else "stream only"


def _rule_r11(variables):
    """R11 — parity: every PARITY_FACT is registered on BOTH planes."""
    http = _plane_names(variables, "http")
    stream = _plane_names(variables, "stream")
    gaps = ((fact, _parity_gap(fact, http, stream))
            for fact in sorted(_PARITY_FACTS))
    return [("R11", fact,
             f"uniform fact registered on {where}; a $brix_* fact must be on "
             "BOTH the http and stream planes so one log_format serves both "
             "(phase-110 rule 1)")
            for fact, where in gaps if where is not None]


def _vocab_findings_for(rel):
    """R12 findings for one variable-handler source file."""
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        return []
    text = open(path, errors="replace").read()
    out = [("R12", rel,
            f"does not call {fn}() — a $brix_* handler that renders a shared "
            "fact must use the metric name function so the variable, JSON and "
            "label agree")
           for fn in _VOCAB_REQUIRED_FNS if fn not in text]
    out += [("R12", rel,
             f"contains the inline cache-vocabulary literal {lit} — render it "
             "via brix_metric_cache_status_name() so no surface spells the "
             "vocabulary by hand")
            for lit in _VOCAB_FORBIDDEN_LITERALS if lit in text]
    return out


def _read_vocab_group(rels):
    """Return the present source names and their combined text."""
    texts = []
    present = []
    for rel in rels:
        path = os.path.join(ROOT, rel)
        if os.path.exists(path):
            present.append(rel)
            texts.append(open(path, errors="replace").read())
    return present, "\n".join(texts)


def _vocab_missing_function_findings(label, text):
    """Report shared name functions absent from one logical surface."""
    return [("R12", label,
             f"does not call {fn}() — a $brix_* handler that renders a shared "
             "fact must use the metric name function so the variable, JSON and "
             "label agree")
            for fn in _VOCAB_REQUIRED_FNS if fn not in text]


def _vocab_literal_findings(label, text):
    """Report shared vocabulary values hand-spelled on one surface."""
    return [("R12", label,
             f"contains the inline cache-vocabulary literal {lit} — render it "
             "via brix_metric_cache_status_name() so no surface spells the "
             "vocabulary by hand")
            for lit in _VOCAB_FORBIDDEN_LITERALS if lit in text]


def _vocab_findings_for_group(rels):
    """R12 findings for one split logical variable-handler implementation."""
    present, text = _read_vocab_group(rels)
    if not present:
        return []
    label = ", ".join(present)
    return (_vocab_missing_function_findings(label, text)
            + _vocab_literal_findings(label, text))


def _rule_r12():
    """R12 — shared vocabulary: the variable-handler files render the uniform
    facts through the brix_metric_*_name() functions, never a hand-spelled
    literal."""
    out = []
    for rels in _VOCAB_SOURCE_GROUPS:
        out += _vocab_findings_for_group(rels)
    return out


def _missing_tokens(rel, tokens):
    """Tokens absent from ROOT/rel (empty when the file is missing — a missing
    surface is a different rule's concern, not R13's)."""
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        return []
    text = open(path, errors="replace").read()
    return [t for t in tokens if t not in text]


def _rule_r13():
    """R13 — cross-surface key parity: the JSON keys and metric labels for the
    uniform facts carry the canonical (variable-name) spelling."""
    out = [("R13", _R13_JSON_SOURCE,
            f"JSON access-log key {key} missing — a fact's JSON key must equal "
            "its $brix_ variable name minus the prefix")
           for key in _missing_tokens(_R13_JSON_SOURCE, _R13_REQUIRED_JSON_KEYS)]
    out += [("R13", _R13_METRIC_SOURCE,
             f"metric surface missing '{token}' — the cache vocabulary must be "
             "a label value, matching $brix_cache_status")
            for token in _missing_tokens(_R13_METRIC_SOURCE, _R13_REQUIRED_METRIC)]
    return out




def _phase_is_implemented(phase_tag):
    """True if docs/refactor/<phase_tag>-*.md exists and is marked IMPLEMENTED.

    A missing doc, or one still marked PLANNED, keeps the pin dormant — the
    deprecation window is open until the removal phase actually lands."""
    for path in glob.glob(os.path.join(_REFACTOR_DOCS, phase_tag + "-*.md")):
        try:
            if _IMPLEMENTED_RE.search(open(path, errors="replace").read()):
                return True
        except OSError:
            continue
    return False


def _overdue_removal_phase(name, reason, registered):
    """The removal phase of `name` if its window has closed (still registered
    AND the phase is IMPLEMENTED), else None."""
    m = _REMOVAL_RE.search(reason or "")
    if m is None or name not in registered:
        return None
    phase = m.group(1)
    return phase if _phase_is_implemented(phase) else None


def _rule_r15():
    """R15 — self-deleting pin on the JSON access-log record: once the removal
    phase is IMPLEMENTED, no deprecated key may be emitted alongside the
    canonical one R13 requires.

    R13 says the canonical key is PRESENT; R15 says the superseded one is
    GONE. Together they hold the record to exactly one spelling per fact."""
    path = os.path.join(ROOT, _R13_JSON_SOURCE)
    if not _phase_is_implemented(_R15_REMOVAL_PHASE) \
            or not os.path.exists(path):
        return []                       # no emitter, nothing deprecated to find
    text = open(path, errors="replace").read()
    present = [k for k in _R15_REMOVED_JSON_KEYS if k in text]
    return [("R15", _R13_JSON_SOURCE,
             f"deprecated JSON access-log key {key} is still emitted but its "
             f"removal phase ({_R15_REMOVAL_PHASE}) is marked IMPLEMENTED — "
             "delete the key; the canonical spelling already carries the fact")
            for key in present]


def _rule_r14(variables, allow):
    """R14 — self-deleting pin: a deprecated alias whose `removal: phase-N`
    window has closed (that phase is IMPLEMENTED) must no longer be registered.

    `allow` is {name: reason}; the removal phase is parsed from the reason.
    Dormant while the phase is unwritten or still PLANNED, so it never blocks
    the deprecation window — it fires precisely when cleanup is due."""
    registered = {name for name, _rel in variables}
    overdue = ((name, _overdue_removal_phase(name, reason, registered))
               for name, reason in sorted(allow.items()))
    return [("R14", name,
             f"deprecated alias is still registered but its removal phase "
             f"({phase}) is marked IMPLEMENTED — delete the alias registration; "
             "the deprecation window has closed")
            for name, phase in overdue if phase is not None]
