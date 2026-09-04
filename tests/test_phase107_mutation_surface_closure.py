"""Phase-107 closure: every compatibility, feature and security discovery made
while completing the VFS mutation surface, pinned as an assertion.

Phase 107 added nine items (C1 writer spill, C2 prestage/evict, C3 durable
publish, C4 bulk namespace delete, C5 space reservation, C6 conditional publish
and atomic exchange, C7 cross-protocol locks, C8 the dedup/CAS plane, C9 the
typed service-storage domain) and took the mutation vocabulary from eleven
members to fifteen (phase-108's C11 made it sixteen). The behaviour of each is
asserted where it lives: the live lanes in `tests/test_vfs_writer_spill.py`,
`tests/test_vfs_reserve.py`, `tests/test_conditional_publish.py`,
`tests/test_cross_protocol_locks.py` and friends, and the hermetic object units
registered in `tests/cmdscripts/c_object_units.py` (`vfs_writer_spill`,
`publish_dirsync`, `vfs_bulk_chunker`, `sd_precond`, `vfs_lock_gate`,
`vfs_service_domain`, `vfs_new_mutator_gate`).

What THIS file pins is the set of things the completion WORK discovered — facts
that were true only by accident until they were checked, and that no other
assertion in the tree holds:

  * compatibility — the C6 evaluator formats its OWN entity tag instead of
                    calling the generator, so two literals in two files must
                    stay in lockstep or a conditional publish silently stops
                    matching what the same server just handed the client; every
                    one of the evaluator's seven callsites maps a missing target
                    to ECANCELED (a failed match, 412) and never to ENOENT
                    (404); and the doc's own test matrix names files that exist
                    — three rows named files that never shipped; and the `nginx
                    -t` diagnostics the doc quotes are the ones the chosen
                    setter can actually emit (only `ngx_conf_set_flag_slot`
                    names the offending directive)
  * feature      — the mutation vocabulary is closed, mirrored and named
                    exactly once, and every member is actually passed by some
                    caller (a vocabulary member no code hands to the kernel is
                    an ungated mutation surface, not a spare label); the bulk-
                    delete window and its capability bit are singular, with no
                    capability sharing a bit with another
  * security     — the policy kernel answers EROFS and never EACCES; every one
                    of the eighteen `_maybe_cred` forwarding wrappers refuses a
                    deny-mode credential rather than silently running the
                    operation as the export (the confused-deputy class the slot
                    wave found three times); the precondition evaluator fails
                    closed on a kind nobody taught it; and the three enums that
                    decide refusals all read "safest" at zero, so a zeroed
                    struct or a forgotten field cannot open a surface

Run:
    PYTHONPATH=tests pytest tests/test_phase107_mutation_surface_closure.py -v
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
DOC = ROOT / "docs" / "refactor" / "phase-107-vfs-mutation-surface-completion.md"

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.xdist_group("phase107-closure")]


def _text(rel: str) -> str:
    return (SRC / rel).read_text()


def _strip(text: str) -> str:
    """C source with comments removed — a comment naming a symbol is
    documentation, not a live reference."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def _function_body(text: str, signature_start: str) -> str:
    """The brace-matched body of the function whose signature begins with
    `signature_start`."""
    at = text.index(signature_start)
    open_brace = text.index("{", at)
    depth, i = 0, open_brace
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace:i + 1]
        i += 1
    raise AssertionError(f"unbalanced braces after {signature_start!r}")


def _enum_body(text: str, member: str) -> str:
    """The comment-free brace body of the enum that declares `member`."""
    at = text.index(member)
    return _strip(text[text.rindex("{", 0, at):text.index("}", at)])


def _enum_members(text: str, first_member: str) -> list[str]:
    """The member names of the enum whose first member is `first_member`."""
    body = _enum_body(text, first_member)
    return re.findall(r"\b([A-Z][A-Z0-9_]+)\b\s*(?:=[^,\n]*)?", body)


def _mutation_enum() -> list[str]:
    """The mutation vocabulary as declared, terminator included."""
    members = _enum_members(_text("fs/vfs/vfs_policy.h"), "BRIX_VFS_MUTATE_OPEN")
    return [m for m in members if m.startswith("BRIX_VFS_MUTATE_")]


def _mutation_ops() -> list[str]:
    """The vocabulary's real operations — the enum minus its count terminator."""
    return [m for m in _mutation_enum() if m != "BRIX_VFS_MUTATE_OP_COUNT"]


def _mutation_labels() -> list[str]:
    """The kernel's one name table, minus the out-of-range fallback."""
    body = _function_body(_text("fs/vfs/vfs_policy.c"),
                          "brix_vfs_mutation_op_name(brix_vfs_mutation_op_t")
    return [lab for lab in re.findall(r'"([a-z]+)"', body) if lab != "unknown"]


def _c_sources_outside_the_kernel() -> dict[Path, str]:
    """Every `src/**.c` but the policy kernel itself, comments removed."""
    return {path: _strip(path.read_text())
            for path in SRC.rglob("*.c") if path.name != "vfs_policy.c"}


def _users_of(symbol: str, bodies: dict[Path, str]) -> list[Path]:
    """The files that name `symbol` as code."""
    pattern = re.compile(rf"\b{symbol}\b")
    return [path for path, text in bodies.items() if pattern.search(text)]


def _precond_callsites() -> list[tuple[Path, int]]:
    """Every `(file, line index)` in `src/` that evaluates a precondition."""
    out: list[tuple[Path, int]] = []
    for path in sorted(SRC.rglob("*.c")):
        for idx, line in enumerate(path.read_text().splitlines()):
            if "brix_sd_precond_eval_stat(" in line:
                out.append((path, idx))
    return out


def _decision_window(path: Path, idx: int) -> str:
    """The text a callsite's missing-target answer can live in.

    Either shape counts: an existence branch ABOVE that answers ECANCELED
    (posix/pblock/frm/vfs), or the folded `stat(...) != 0 || eval(...)`
    condition whose single error arm answers it BELOW (namespace_ops_copy.c,
    which also preserves ENOTSUP through the fold)."""
    lines = path.read_text().splitlines()
    return "\n".join(lines[max(0, idx - 14):idx + 8])


UNIFIED_C = "observability/metrics/unified.c"
_TABLE_RE = re.compile(r"static const char \*(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*\{")


def _braced_block(text: str, at: int) -> str:
    """The brace-matched block that opens at or after `at`."""
    open_brace = text.index("{", at)
    depth, i = 0, open_brace
    while i < len(text):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[open_brace:i + 1]
        i += 1
    raise AssertionError("unbalanced braces in a label table")


def _label_tables() -> list[tuple[str, str, str]]:
    """The exporter's bounded label tables as (name, bound token, body)."""
    text = (SRC / UNIFIED_C).read_text()
    return [(m.group(1), m.group(2), _braced_block(text, m.end() - 1))
            for m in _TABLE_RE.finditer(text)]


def _labels_of(table: str) -> list[str]:
    """One exporter table's labels, in declaration order."""
    found = [body for name, _, body in _label_tables() if name == table]
    assert found, f"the exporter no longer declares {table}"
    return re.findall(r'"([^"]*)"', _strip(found[0]))


def _positional_count(text: str, token: str) -> int | None:
    """`token`'s index in its own enum, when the enum is purely positional."""
    if not re.search(rf"^\s*{token}\b", text, re.M):
        return None
    body = _enum_body(text, token)
    if "#define" in body or re.search(r"=\s*[1-9]", body):
        return None          # explicit values, or an X-macro expansion
    members = _enum_members(text, token)
    return members.index(token) if token in members else None


def _count_constant(token: str) -> int | None:
    """A `..._COUNT` bound's value: a `#define`, an explicit enum value, or the
    member's position in an enum whose members are all implicit.

    `None` when none of the three resolves it — `BRIX_PROTO_COUNT` terminates an
    X-macro expansion and has no countable members in the source at all."""
    for header in sorted(SRC.rglob("*.h")):
        text = _strip(header.read_text())
        literal = re.search(rf"(?:#define\s+{token}\s+|{token}\s*=\s*)(\d+)",
                            text)
        if literal:
            return int(literal.group(1))
        positional = _positional_count(text, token)
        if positional is not None:
            return positional
    return None


ERRMAP = "core/compat/error_mapping.c"


def _mapping_pairs(anchor: str) -> dict[str, str]:
    """One error-mapping table as `{left: right}`, first row winning — the
    order the C lookup scans in."""
    text = _strip(_text(ERRMAP))
    block = _braced_block(text, text.index(anchor))
    out: dict[str, str] = {}
    for left, right in re.findall(r"\{\s*(\w+)\s*,\s*(\w+)\s*\}", block):
        out.setdefault(left, right)
    return out


def _tier_directive_setters() -> dict[str, str]:
    """`{directive suffix: setter}` for every row of the tier X-macros.  The
    rows spell their names as `pfx "suffix"`, which is why grepping the tree for
    a directive's full name finds only comments."""
    text = _strip(_text("core/config/tier_directives.h"))
    rows = re.findall(r'ngx_string\(pfx "(\w+)"\)(.*?)(?=ngx_string\(pfx "|\Z)',
                      text, re.S)
    out: dict[str, str] = {}
    for name, body in rows:
        setter = re.search(r"\b(\w*conf_set_\w+)", body)
        out[name] = setter.group(1) if setter else ""
    return out


def _emerg_quotes_naming_a_directive() -> set[str]:
    """Directives the phase doc quotes an `[emerg]` message BY NAME for."""
    quoted = re.findall(r'\[emerg\] invalid value "[^"]*" in "(\w+)" directive',
                        DOC.read_text())
    return set(quoted)


def _root_plane_files_naming(symbol: str) -> list[Path]:
    """Root-plane sources that name `symbol` as code."""
    return [path for path in sorted((SRC / "protocols/root").rglob("*.c"))
            if symbol in _strip(path.read_text())]


def _suffix_labels(members: list[str], prefix: str) -> list[str]:
    """Each enum member's own suffix, lowercased — the label it must carry."""
    return [m[len(prefix):].lower() for m in members if m.startswith(prefix)]


def _promised_units() -> set[str]:
    """The object-unit names §9.2's "New specs:" block promises."""
    block = DOC.read_text().split("New specs:", 1)[1].split("```")[1]
    return {line.split()[0] for line in block.strip().splitlines() if line.strip()}


def _spec_sources(spec) -> list[str]:
    """A spec's test sources, taken from its own compile args.

    Not from its binary name: `pelican_ad` builds `pelican_ad_test.c`, so
    deriving the path by convention would false-red."""
    return [arg for arg in spec.args
            if arg.endswith(".c") and "stub" not in arg]


# --------------------------------------------------------------------------
# compatibility
# --------------------------------------------------------------------------
def test_the_precondition_evaluator_and_the_etag_generator_emit_one_grammar():
    """C6's evaluator promises in its own header that "the etag comparison
    never forks", then formats the tag itself with a second copy of the
    generator's format string rather than calling `brix_http_etag_str`.  The
    two literals are the fork: change the generator's grammar and every
    If-Match against a stat-grammar backend starts failing 412 against a tag
    the same server minted seconds earlier.  Pin them equal, and pin the
    evaluator's private buffer at least as large as the generator's documented
    minimum (`etag.h`: "buf >= 48 bytes") so the two cannot disagree on width
    either.  `tests/c/test_sd_precond.c` links the REAL `http/etag.o` and
    compares the two at runtime; this is the static half."""
    batch = _text("fs/backend/sd_batch_types.h")
    etag_c = _text("core/http/etag.c")

    strong = r'"\"%lx-%llx\""'
    assert etag_c.count(strong) == 1, "the generator's strong form moved"
    assert batch.count(strong) == 1, "the evaluator's copy of it moved"

    body = _function_body(batch, "brix_sd_precond_eval_stat(const")
    width = int(re.search(r"char\s+tag\[(\d+)\]", body).group(1))
    documented = int(re.search(r"buf >= (\d+) bytes",
                               _text("core/http/etag.h")).group(1))
    assert width >= documented, (
        f"the evaluator's tag[{width}] is narrower than the {documented} bytes "
        "etag.h documents for the same grammar")


def test_every_precondition_callsite_maps_a_missing_target_to_ecanceled():
    """The evaluator answers a FAILED COMPARE (ECANCELED -> 412); it is never
    asked "does the target exist".  Every callsite therefore has to establish
    existence first, and each one has to decide what a missing target means.
    All seven independently chose ECANCELED — a failed match, not ENOENT —
    because a conditional PUT against a vanished object is a precondition
    failure (412), and answering 404 both breaks the RFC 7232 contract and
    discloses absence to a caller who only asked whether a tag matched.  A
    later callsite that forgets is a real behaviour split across backends."""
    callsites = _precond_callsites()
    assert len(callsites) >= 7, (
        f"expected the seven shared callsites, found {len(callsites)}")

    for path, idx in callsites:
        assert "ECANCELED" in _decision_window(path, idx), (
            f"{path.relative_to(ROOT)}:{idx + 1} evaluates a precondition "
            "with no ECANCELED answer for a missing target anywhere around it "
            "— a missing target must be a failed match (412), never ENOENT "
            "(404)")


def test_the_new_directive_diagnostics_are_quoted_as_their_setter_emits_them():
    """Of nginx's config setters only `ngx_conf_set_flag_slot` puts the
    directive's name in its complaint (`ngx_conf_file.c:1050`, "invalid value
    \\"%s\\" in \\"%s\\" directive"); `ngx_conf_set_enum_slot` (`:1382`) logs
    the bad value alone, leaving the file and line as the only clue to WHICH
    directive was wrong.  Phase 107 added one of each — `brix_durable_publish`
    (flag) and `brix_lock_enforcement` (enum, joined by phase-108's
    `brix_authz_backstop`) — and §4 originally quoted a named diagnostic for
    both, promising an operator with two enum directives in one server block a
    message that would tell them apart.  `objs/nginx -t` on 2026-09-03 emitted
    `invalid value "yes" in <conf>:115` for `brix_lock_enforcement yes`; the doc
    now says so.  This pins the rule rather than the two strings: the doc may
    quote a directive-naming diagnostic only for a directive whose row uses the
    flag slot."""
    setters = _tier_directive_setters()
    assert setters.get("durable_publish") == "ngx_conf_set_flag_slot", (
        f"brix_durable_publish now uses {setters.get('durable_publish')}")
    assert setters.get("lock_enforcement") == "ngx_conf_set_enum_slot", (
        f"brix_lock_enforcement now uses {setters.get('lock_enforcement')}")

    for named in _emerg_quotes_naming_a_directive():
        setter = setters.get(named.removeprefix("brix_"))
        assert setter == "ngx_conf_set_flag_slot", (
            f"the doc quotes an [emerg] naming \"{named}\", but its row uses "
            f"{setter}, which logs the bad value alone — the operator would "
            "get a message that never mentions the directive")


def test_the_three_refusals_render_as_three_distinct_codes_on_every_plane():
    """Phase 107 gave the errno tables two new rows, and the three refusals a
    client can now meet must stay tellable apart: `EROFS` "this export takes no
    writes from anyone" -> 403, `EBUSY` "someone holds a lock" -> 423
    (RFC 4918 §11.3), `ECANCELED` "your precondition failed" -> 412
    (RFC 7232).  Collapse any two and the C7 ordering guarantee stops being
    observable — `EROFS` precedes `EBUSY` precisely so a read-only endpoint
    never discloses that a lock exists, which only works while the two render
    differently.  On the wire, `EROFS` round-trips (`kXR_fsReadOnly` back to
    `EROFS`, as the phase-105 comment in the table says it must); `EBUSY`
    deliberately does NOT — `kXR_FileLocked` comes back as `EAGAIN`, the fcntl
    spelling of "held, retry later", while the reverse table reserves `EBUSY`
    for `kXR_Overloaded`, which is server load and not a resource lock.  That
    asymmetry is the one thing here a reader would "fix" by symmetry, so it is
    pinned with its reason rather than left to look like an oversight."""
    http = _mapping_pairs("brix_http_errno_table[] =")
    rendered = {err: http.get(err) for err in ("EROFS", "EBUSY", "ECANCELED")}
    assert rendered == {"EROFS": "403", "EBUSY": "423", "ECANCELED": "412"}, (
        f"the three refusals no longer render distinctly: {rendered}")

    forward = _mapping_pairs("} table[] =")
    reverse = _mapping_pairs("brix_kxr_errno_table[] =")
    assert forward.get("EROFS") == "kXR_fsReadOnly", (
        f"EROFS no longer answers kXR_fsReadOnly: {forward.get('EROFS')}")
    assert reverse.get("kXR_fsReadOnly") == "EROFS", (
        "the EROFS round trip broke, against the comment beside the forward "
        f"row: kXR_fsReadOnly now comes back as {reverse.get('kXR_fsReadOnly')}")
    assert forward.get("EBUSY") == "kXR_FileLocked", (
        f"EBUSY no longer answers kXR_FileLocked: {forward.get('EBUSY')}")
    assert reverse.get("kXR_FileLocked") == "EAGAIN", (
        "the lock refusal no longer comes back as EAGAIN (now "
        f"{reverse.get('kXR_FileLocked')}) — decide deliberately: a POSIX "
        "caller is told EAGAIN, fcntl's 'held, retry', and EBUSY is the "
        "reverse spelling of kXR_Overloaded, which means server load")
    assert reverse.get("kXR_Overloaded") == "EBUSY", (
        "EBUSY is no longer reserved for server load on the reverse side: "
        f"kXR_Overloaded now maps to {reverse.get('kXR_Overloaded')}")


def test_a_precondition_failure_never_reaches_the_root_plane_as_an_io_error():
    """The errno->kXR table has no `ECANCELED` row, so a precondition failure
    that reached it would answer `kXR_IOError` — a server fault, which a client
    retries, for a condition retrying cannot fix.  Nothing defends that today
    except a design fact: the root plane constructs only ABSENT preconditions
    (`kXR_new`), whose refusal is `EEXIST` -> `kXR_ItExists`.
    `tests/test_conditional_publish.py` asserts the live half; this is the
    implication that must hold in either future — the root plane may name
    `ECANCELED` only once the forward table can spell it."""
    forward = _mapping_pairs("} table[] =")
    users = _root_plane_files_naming("ECANCELED")
    assert "ECANCELED" in forward or not users, (
        "the root plane now carries ECANCELED but errno->kXR has no row for "
        f"it, so it renders as kXR_IOError: {[str(p) for p in users]}")


def test_the_doc_test_matrix_names_files_that_exist():
    """The phase doc closed with every item ticked, yet its own §9.1 matrix
    named three files that never shipped under those names — `test_durable_
    publish.py` (C3 landed as the `publish_dirsync` object unit) and
    `test_gcas_gate.py` (shipped as `test_gcas_store_gate.py`).  A ledger that
    names a nonexistent test reads as coverage and is the exact way a promised
    test goes missing while the phase reports done."""
    doc = DOC.read_text()
    # Scope to §9, the ledger. Elsewhere the doc names PLANNED artifacts it
    # then annotates "(as landed: ...)" — `tests/c/test_sd_spy_driver.c` and
    # `tests/brixtest/ordering.py` are two, deliberately never written.
    section = doc.split("## 9. Test matrix", 1)[1].split("\n## 10", 1)[0]
    named = set(re.findall(r"`(tests/[A-Za-z0-9_./-]+\.(?:py|c))`", section))
    assert len(named) >= 12, "the §9 test matrix stopped naming test files"

    missing = sorted(n for n in named if not (ROOT / n).is_file())
    assert not missing, (
        f"the §9 test matrix names test files that do not exist: {missing}")


def test_every_promised_c_unit_is_registered_in_the_parametrized_table():
    """§9.2's own trap, turned on §9.2: "a unit present in RUNNERS but absent
    from the parametrized table never runs, and the suite still reports green".
    Two of the six new units — `vfs_bulk_chunker` and `sd_precond` — were
    still missing from `SPECS` after the phase reported IMPLEMENTED AND
    VERIFIED, so the C4 chunker and the C6 evaluator had no hermetic coverage
    at all while the ledger said they did.  This asserts the doc's list and the
    parametrized table agree, and that every registered spec's source exists."""
    sys.path.insert(0, str(ROOT / "tests"))
    from cmdscripts.c_object_units import SPECS   # noqa: E402

    missing = sorted(_promised_units() - set(SPECS))
    assert not missing, (
        f"§9.2 promises object units that SPECS does not carry: {missing} — "
        "a unit outside the parametrized table never runs")

    # Every spec must also name a source that exists.
    for name, spec in SPECS.items():
        sources = _spec_sources(spec)
        assert sources, f"spec {name} compiles no test source"
        for source in sources:
            assert (ROOT / source).is_file(), (
                f"spec {name} names a missing source {source}")


# --------------------------------------------------------------------------
# feature
# --------------------------------------------------------------------------
def test_the_mutation_vocabulary_is_closed_and_named_exactly_once():
    """The vocabulary is the low-cardinality label set every refusal metric and
    structured log keys on (INVARIANT #8).  Phase 107 took it from eleven
    members to fifteen and phase-108 to sixteen; a member added to the enum but
    not to the name table indexes past a `static const char *[OP_COUNT]`, and a
    metric mirror that drifts silently breaks the two-table equality the kernel
    depends on.  Pin: enum members == OP_COUNT == the metric mirror, and the
    single name table carries one unique lowercase label per member."""
    members = _mutation_enum()
    real = _mutation_ops()
    assert members[-1] == "BRIX_VFS_MUTATE_OP_COUNT", (
        "OP_COUNT must stay last or it stops counting the vocabulary")

    mirror = int(re.search(r"#define BRIX_VFS_MUTATE_OP_METRIC_COUNT\s+(\d+)",
                           _text("observability/metrics/unified.h")).group(1))
    assert len(real) == mirror == 16, (
        f"{len(real)} enum members vs metric mirror {mirror}")

    labels = _mutation_labels()
    assert len(labels) == len(real) == len(set(labels)), (
        f"{len(labels)} labels for {len(real)} operations, "
        f"{len(set(labels))} distinct")


def test_every_mutation_op_is_actually_passed_somewhere_outside_the_kernel():
    """A vocabulary member no caller ever hands to the kernel is not a spare
    label — it is a mutation the phase named and then left ungated, and the
    census reads identically either way.  Every one of the sixteen must appear
    at a real callsite outside `vfs_policy.c` itself."""
    bodies = _c_sources_outside_the_kernel()
    for op in _mutation_ops():
        assert _users_of(op, bodies), (
            f"{op} is in the vocabulary but no caller outside the policy "
            "kernel ever passes it — an unreferenced member is an ungated "
            "mutation surface, not a spare metric label")


def test_the_bulk_delete_window_and_its_capability_bit_are_singular():
    """C4 gates the windowed walk on `BRIX_SD_CAP_BULK_DELETE`.  Two
    capabilities sharing a bit would hand bulk delete to a driver that only
    ever advertised something else — a batch dispatch into a slot that is a
    loop, or worse a NULL — so the bitmap's injectivity is a safety property,
    not tidiness.  The window itself is the number `sd_batch_types.h` promises
    the slot ("n <= the driver's window; the VFS chunker guarantees it") and
    `tests/c/test_vfs_bulk_chunker.c` asserts the split lands ON."""
    sd_h = _text("fs/backend/sd.h")
    bits: dict[int, str] = {}
    for name, shift in re.findall(
            r"\b(BRIX_SD_CAP_[A-Z0-9_]+)\s*=\s*1u\s*<<\s*(\d+)", sd_h):
        shift = int(shift)
        assert shift not in bits, (
            f"{name} shares bit {shift} with {bits[shift]}")
        bits[shift] = name

    assert bits[17] == "BRIX_SD_CAP_BULK_DELETE"
    window = int(re.search(r"#define BRIX_SD_BULK_DELETE_WINDOW\s+(\d+)",
                           _text("fs/backend/sd_batch_types.h")).group(1))
    assert window == 1000


def test_the_three_refusal_enums_all_read_safest_at_zero():
    """Three independent enums decide whether a mutation happens, and all three
    were deliberately arranged so that ZERO is the closed answer: an unset
    mutation policy is READ_ONLY (a forgotten field fails closed), a zeroed
    precondition is NONE (a caller who forgets gets the OLD unconditional
    semantics, never an accidental refusal), and a zero-allocated storage
    instance is DOMAIN_EXPORT (the strict, client-named domain — so a factory
    that forgets to set a domain gets the phase-105 gate, not a service-storage
    bypass).  The three point in different directions and each is right for its
    own question; that is the discovery, and it is easy to break by reordering
    an enum for readability."""
    assert re.search(r"BRIX_VFS_MUTATION_READ_ONLY\s*=\s*0\b",
                     _text("fs/vfs/vfs_policy.h")), \
        "an unset mutation policy must be READ_ONLY"
    assert re.search(r"BRIX_SD_PRECOND_NONE\s*=\s*0\b",
                     _text("fs/backend/sd_batch_types.h")), \
        "a zeroed precondition must be NONE"
    assert re.search(r"BRIX_VFS_DOMAIN_EXPORT\s*=\s*0\b",
                     _text("fs/backend/sd_domain.h")), \
        "a zero-allocated instance must land in the strict EXPORT domain"


def test_the_two_mutation_label_tables_agree_word_for_word():
    """`vfs_policy.c`'s own WHY comment says "a second table would let the two
    drift and would risk an unbounded label (INVARIANT #8)" — and a second table
    exists by design: the exporter mirrors the vocabulary in
    `unified.c` so the metrics layer needs no fs-layer include.  Nothing
    compares them.  The `_Static_assert` next to them pins the two COUNTS, so a
    label spelled differently in the two tables compiles clean and ships a
    structured log naming an operation one way and a metric series naming the
    same operation another — the fork the comment forbids, in the one place it
    is not defended."""
    kernel = _mutation_labels()
    exporter = _labels_of("brix_unified_vfs_mutate_op_names")
    assert kernel == exporter, (
        "the policy kernel's label table and the metrics mirror disagree: "
        f"{[a for a, b in zip(kernel, exporter) if a != b]} — a log line and a "
        "metric series would name the same operation differently")


def test_every_bounded_label_is_its_enum_member_lowercased_in_order():
    """What the length assert cannot see.  Both `_Static_assert`s compare a
    COUNT to a COUNT, so INSERTING a member in the middle of either vocabulary
    — the natural edit, since the enums group related verbs — keeps both
    asserts green while every label after the insertion point shifts by one.
    Every metric series and every structured log from that point on silently
    renames: `evict` starts reporting as `lock`.  The defence is positional:
    each label is its own member's suffix, lowercased, in enum order, for the
    mutation vocabulary (C1-C8) and the storage-domain vocabulary (C9) alike."""
    ops = _suffix_labels(_mutation_ops(), "BRIX_VFS_MUTATE_")
    assert _labels_of("brix_unified_vfs_mutate_op_names") == ops, (
        "the metrics mirror's labels no longer sit at their own member's "
        "index — every series from the drift point on is renamed")
    assert _mutation_labels() == ops, (
        "the policy kernel's labels no longer sit at their own member's "
        "index — every structured log from the drift point on is renamed")

    members = _enum_members(_text("fs/backend/sd_domain.h"),
                            "BRIX_VFS_DOMAIN_EXPORT")
    domains = _suffix_labels(
        [m for m in members if m != "BRIX_VFS_DOMAIN_COUNT"],
        "BRIX_VFS_DOMAIN_")
    assert _labels_of("brix_unified_vfs_domain_names") == domains, (
        "a storage-domain label no longer matches its own enum member — the "
        "C9 domain a refusal reports is not the domain it was refused in")


def test_no_bounded_label_table_carries_a_hole():
    """A `static const char *t[N] = { ... }` with fewer than N initialisers is
    legal C: the tail is NULL.  Every accessor here range-checks against N and
    returns the entry, so `"unknown"` is reached only for an out-of-range
    index, never for a hole — a short table hands the exporter a NULL to
    format.  The protocol table is immune because it is expanded from
    `BRIX_PROTO_LIST`, one list written once; the phase-107 vocabularies are
    hand-written twice and are not.  Every table that resolves its bound must
    fill it exactly."""
    checked = 0
    for name, bound, body in _label_tables():
        declared = _count_constant(bound)
        if declared is None or "#define X(" in body:
            continue                      # X-macro expansion: hole-free by shape
        labels = re.findall(r'"[^"]*"', _strip(body))
        assert len(labels) == declared, (
            f"{name}[{bound}] declares {declared} slots and initialises "
            f"{len(labels)} — the tail is NULL and the range check cannot "
            "see it")
        checked += 1
    assert checked >= 8, f"only {checked} bounded label tables examined"


# --------------------------------------------------------------------------
# security
# --------------------------------------------------------------------------
def test_the_policy_kernel_answers_erofs_and_never_eaccess():
    """Phase 105's finding, which phase 107 had to keep true across four new
    verbs: a read-only endpoint answers EROFS, never EACCES.  EACCES is the
    identity answer, and an identity answer invites a caller to retry with a
    different credential against a surface that is closed to everyone — and it
    is inheritable by a new mutator that copies the wrong neighbour.  The
    kernel's executable text must contain no EACCES at all."""
    body = _strip(_text("fs/vfs/vfs_policy.c"))
    assert "EROFS" in body
    assert "EACCES" not in body, (
        "the policy kernel reached for the identity answer; a read-only "
        "endpoint is EROFS on every plane")


def test_every_credential_forwarding_wrapper_refuses_deny_mode():
    """The confused-deputy class the storage-driver slot wave found three
    times, generalised.  Each `*_maybe_cred` wrapper routes to a `_cred` twin
    when the caller has a credential; when the driver has no twin, a credential
    carrying `fallback_deny` must make the wrapper REFUSE (EACCES) rather than
    fall through to the plain slot, which would run the operation as the export
    identity — precisely the escalation the flag exists to prevent.  C4 added
    `unlink_many` to this set, where the blast radius is a whole batch.  A new
    wrapper added without the clause is invisible until someone audits it."""
    header = _text("fs/backend/sd_cred_forward.h")
    wrappers = re.findall(
        r"\n(brix_sd_\w+_maybe_cred)\(.*?\n\{(.*?)\n\}\n", header, re.S)
    assert len(wrappers) >= 18, (
        f"expected at least the eighteen forwarding wrappers, "
        f"found {len(wrappers)}")

    for name, body in wrappers:
        assert "fallback_deny" in body and "EACCES" in body, (
            f"{name} falls back to the plain slot for a deny-mode credential "
            "— the operation would run as the export identity")

    names = [name for name, _ in wrappers]
    assert "brix_sd_unlink_many_maybe_cred" in names, \
        "C4's batch slot must be inside the forwarding rule, not beside it"


def test_the_precondition_evaluator_fails_closed_on_an_untaught_kind():
    """`brix_sd_precond_kind_t` is an open enum in an ABI-stable header; the
    evaluator teaches exactly MATCH_META and MATCH_ETAG.  Its fall-through must
    be a refusal (ENOTSUP), because a `return 0` default would turn a
    precondition nobody implemented into an unconditional overwrite — a
    conditional PUT that silently stops being conditional is indistinguishable
    from success at every layer above it.  `tests/c/test_sd_precond.c` drives
    NONE, ABSENT and two out-of-range values through it; this pins the shape so
    a future kind cannot be added by widening a branch."""
    body = _function_body(_text("fs/backend/sd_batch_types.h"),
                          "brix_sd_precond_eval_stat(const")
    tail = _strip(body).rstrip().rstrip("}").rstrip()
    assert tail.endswith("return -1;"), \
        "the evaluator's fall-through is not a refusal"
    assert re.search(r"errno\s*=\s*ENOTSUP;\s*return\s+-1;\s*$", tail), \
        "the fall-through must be ENOTSUP, distinguishable from a failed match"

    kinds = _enum_members(_text("fs/backend/sd_batch_types.h"),
                          "BRIX_SD_PRECOND_NONE")
    taught = {k for k in kinds if k in body}
    assert taught == {"BRIX_SD_PRECOND_MATCH_META", "BRIX_SD_PRECOND_MATCH_ETAG"}, (
        f"the evaluator's taught kinds drifted: {sorted(taught)} — NONE and "
        "ABSENT are the caller's job by contract")


def test_the_vocabulary_metric_mirror_keeps_its_compile_time_equality_check():
    """The metrics layer keeps its own copy of the vocabulary's size so it
    carries no dependency on the fs layer, and `vfs_policy.c` holds the one
    `_Static_assert` that makes the duplication safe.  Deleting that assert
    costs nothing at build time and silently re-opens the drift — which for a
    metric mirror means indexing a per-op array out of bounds.  It is the kind
    of line a cleanup removes because "nothing references it"."""
    body = _text("fs/vfs/vfs_policy.c")
    assert re.search(
        r"_Static_assert\(\s*\(int\)\s*BRIX_VFS_MUTATE_OP_COUNT\s*"
        r"==\s*BRIX_VFS_MUTATE_OP_METRIC_COUNT", body), \
        "the enum/metric-mirror equality check is gone"
