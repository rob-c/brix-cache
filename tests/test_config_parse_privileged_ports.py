"""Guard: an accepting `nginx -t` case may not be rendered on a privileged port.

`config_parse.nginx_t` is a parse-only helper, which invites call sites to pass
`PORT=1` — the port is never dialled, so any number looks as good as another.
It is not: **`nginx -t` BINDS every listen socket.**  Run as an ordinary uid
with `net.ipv4.ip_unprivileged_port_start=1024`, a privileged port makes the
ACCEPTING case fail:

    nginx: the configuration file .../nginx.conf syntax is ok
    nginx: [emerg] bind() to 127.0.0.1:1 failed (13: Permission denied)
    nginx: configuration file .../nginx.conf test failed

The syntax is reported OK on the line above, and the failure is a bind — so the
row reads like a directive that was never registered, and the obvious next move
is to go looking in the C for a directive that is in fact fine.

The refusing cases in the same file hide it completely: their parse error fires
before any bind, so they pass on port 1 forever.  A file therefore shows exactly
ONE red row, its negatives all green, which is the least informative shape this
failure could have taken.  Found the hard way when it halted a fail-fast tier
run at 46% on `test_phase115_upstream_gsi.py::test_upstream_x509_directives_parse`
(2026-09-07); a second, identical site in `test_phase115_cms_select_proxy.py`
had not been reached yet.

The rule is therefore scoped to what actually breaks: a function that asserts a
parse ACCEPTS must render unprivileged ports.  A function that only asserts
refusals is left alone — its ports are never bound, and widening the rule to
those would be a churn with no failure behind it.
"""

import ast
from pathlib import Path

TESTS = Path(__file__).resolve().parent
FIRST_UNPRIVILEGED = 1024


def _calls_named(tree, name: str):
    """Every Call in `tree` whose callee is `name`, bare or attribute."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        if isinstance(callee, ast.Attribute) and callee.attr == name:
            found.append(node)
        elif isinstance(callee, ast.Name) and callee.id == name:
            found.append(node)
    return found


def _is_returncode_zero(node) -> bool:
    """Is `node` the comparison `<something>.returncode == 0`?

    Only equality counts.  `!= 0` is a refusal, and a refusal never reaches the
    bind, so those call sites are outside the rule.
    """
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return False
    if not isinstance(node.ops[0], ast.Eq):
        return False
    left, right = node.left, node.comparators[0]
    if not (isinstance(left, ast.Attribute) and left.attr == "returncode"):
        return False
    return isinstance(right, ast.Constant) and right.value == 0


def _asserts_acceptance(tree) -> bool:
    """Does this function assert that some `.returncode` EQUALS zero?"""
    return any(_is_returncode_zero(node) for node in ast.walk(tree))


def _privileged_ports(call) -> list[str]:
    """`NAME=<literal>` keywords of `call` that name a privileged port."""
    bad = []
    for keyword in call.keywords:
        if keyword.arg is None or not keyword.arg.endswith("PORT"):
            continue
        value = keyword.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, int):
            continue
        if 0 < value.value < FIRST_UNPRIVILEGED:
            bad.append(f"{keyword.arg}={value.value}")
    return bad


def _offenders_in_function(node, name: str) -> list[str]:
    """Privileged ports rendered by one function that asserts acceptance."""
    calls = _calls_named(node, "nginx_t")
    if not calls or not _asserts_acceptance(node):
        return []
    return [f"{name}:{call.lineno} {node.name} {port}"
            for call in calls for port in _privileged_ports(call)]


def _offenders_in(path: Path) -> list[str]:
    """Accepting parse cases in `path` that render a privileged port."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return []
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            offenders += _offenders_in_function(node, path.name)
    return offenders


def test_no_accepting_parse_case_binds_a_privileged_port():
    """The whole guard: one row, because one rule.

    Reported as a list rather than failing on the first hit — the failure mode
    this exists for produces several sites at once (one per suite that copied
    the idiom), and finding them one fail-fast run at a time is what it cost
    the first time.
    """
    offenders = []
    for path in sorted(TESTS.glob("test_*.py")):
        offenders += _offenders_in(path)
    assert not offenders, (
        "`nginx -t` binds every listen socket, so these accepting parse cases "
        "fail with `bind() ... (13: Permission denied)` as an ordinary uid — "
        "render them with free_port() instead:\n  " + "\n  ".join(offenders))


def test_the_guard_sees_a_privileged_accepting_case():
    """The guard must fail on the shape it exists for.

    Without this the suite above is indistinguishable from one whose matcher
    silently stopped matching — and it would then stay green through exactly
    the regression it was written for.
    """
    source = (
        "def test_x(tmp_path):\n"
        "    good = config_parse.nginx_t(T, tmp_path, PORT=1, UP_PORT=2)\n"
        "    assert good.returncode == 0\n")
    tree = ast.parse(source)
    function = tree.body[0]
    assert _asserts_acceptance(function)
    call = _calls_named(function, "nginx_t")[0]
    assert _privileged_ports(call) == ["PORT=1", "UP_PORT=2"]


def test_the_guard_leaves_refusing_cases_alone(tmp_path):
    """A refusal never reaches the bind, so port 1 is fine there.

    Pinned because the tempting "just ban privileged ports everywhere" version
    of this guard would red a dozen healthy negatives and teach people to
    silence it.  Driven through `_offenders_in` on a real file rather than
    through its parts, so the whole scanner is what gets exercised.
    """
    refusing = tmp_path / "test_refusing.py"
    refusing.write_text(
        "def test_x(tmp_path):\n"
        "    bad = nginx_t(T, tmp_path, PORT=1)\n"
        "    assert bad.returncode != 0\n", encoding="utf-8")
    assert _offenders_in(refusing) == []

    accepting = tmp_path / "test_accepting.py"
    accepting.write_text(
        "def test_x(tmp_path):\n"
        "    good = nginx_t(T, tmp_path, PORT=1)\n"
        "    assert good.returncode == 0\n", encoding="utf-8")
    assert [row.split(" ", 1)[1] for row in _offenders_in(accepting)] \
        == ["test_x PORT=1"]
