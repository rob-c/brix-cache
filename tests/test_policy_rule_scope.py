"""A policy rule must keep its PATH when the export root is "/".

Every `brix_require_vo` / `brix_authdb` / group rule is canonicalised once at
startup by ``brix_finalize_path_rules`` (src/fs/path/helpers.c) against the
export root, and the canonical form is the prefix the request-time gate matches
on.  On a remote-backed export that root is "/", which sends the resolution down
``brix_resolve_missing_parents``'s "the walk reached the filesystem root" branch
(src/fs/path/unified_resolve.c) — and that branch used to select its snprintf
FORMAT with a ternary while passing a fixed two-argument list, so the one-
argument form ``"/%s"`` consumed the ancestor and silently discarded the suffix.
Every rule on such an export resolved to the literal "//".

Nothing reported it: "//" is a valid absolute path, and it ends in '/', which
``brix_path_prefix_match`` treats as "matches everything beneath".  So a rule
naming one subtree quietly became a rule over the whole namespace, two rules
with different paths became indistinguishable, and the longest-prefix scan —
tie at two characters — handed every request to whichever was declared last.

It was found as a cache-transparency divergence, not as a path bug: the
multi-user oracle's WebDAV pair is one export-rooted node and one remote-backed
one, so the same request, the same rules and the same identity produced ALLOW on
the direct server and a VO denial on the cache.  These cells pin it where it
lives instead, on one unauthenticated server, so the next regression is a status
code and not a two-node disagreement.

  * success          — a path NO rule covers is not subject to any of them
  * error            — a path a rule DOES cover is refused (the rule still works)
  * security negative— the deeper rule's VO is not the one demanded elsewhere,
                       and a prefix that is not a path-component boundary does
                       not inherit the rule next to it
"""
import os

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

pytestmark = [
    pytest.mark.timeout(120),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-policy-rule-scope"),
]

# Nothing listens on port 1: a rule-free path has to get PAST the access phase,
# and a refused connect proves that in milliseconds where a black-holed one
# would take the proxy read timeout.
_DEAD_ORIGIN_PORT = 1

_FORBIDDEN = 403


_VO_RULES = ("            brix_require_vo      /alpha vo-alpha;\n"
             "            brix_require_vo      /beta/gamma vo-beta;")


# Function-scoped, because `lifecycle` is: the harness tears every instance it
# started down with the test that asked for it, so a module-scoped wrapper would
# outlive its own server.  Each cell therefore starts its own nginx; each is a
# single worker with one location and no backend to reach, so the cost is the
# fork, not the fleet.  Every cell reuses ONE instance name — and so one ledger
# port — because the policy block is a template value: two ports for one
# condition would be two ledger rows and a port-ladder shift for nothing.
@pytest.fixture()
def start_server(lifecycle):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    def _start(policy_block):
        return lifecycle.start(NginxInstanceSpec(
            name="lc-policy-rule-scope",
            template="nginx_policy_rule_scope_lc.conf",
            protocol="http",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_PORT": _DEAD_ORIGIN_PORT,
                "POLICY_BLOCK": policy_block,
            },
            reason="policy-rule path scope on a remote-backed ('/'-rooted) "
                   "export"))
    return _start


@pytest.fixture()
def server(start_server):
    return start_server(_VO_RULES)


@pytest.fixture()
def authdb_server(start_server, tmp_path):
    """The same export, with a NATIVE authdb whose one rule names the root.

    `a * / rl` is the most ordinary grant an operator can write for a cache in
    front of a remote origin — "anyone may read this export" — and on such an
    export the resolved rule prefix IS "/", the one prefix that already ends in
    the separator.  The authdb carried its own private copy of the
    boundary-aware prefix test, without the carve-out its sibling in
    find_rule.c has, so the rule covered the literal "/" and nothing under it
    and every authorized read was refused.  It stayed invisible while the
    request path arrived with a doubled slash, whose second '/' satisfied the
    boundary test by accident.
    """
    def _start(rules):
        authdb = tmp_path / "authdb"
        authdb.write_text(rules)
        return start_server(f"            brix_authdb          {authdb};")
    return _start


def _status(server, path):
    """The status of a GET, with the connection failure to the dead origin read
    as 'the gate let it through' rather than as an error of its own."""
    return requests.get(f"http://{HOST}:{server.port}{path}", timeout=30).status_code


def test_a_path_no_rule_covers_is_not_subject_to_any(server):
    """/delta is named by neither rule, so neither may decide it.

    This is the whole failure, in one call: with the rules collapsed to "//",
    /delta matched both and was refused for want of a VO it was never asked to
    hold.  Any non-403 answer means the access phase declined to rule on it —
    including the 502 from the closed origin, which is the expected one here."""
    assert _status(server, "/delta/object.dat") != _FORBIDDEN, (
        "a path outside every brix_require_vo prefix was refused by one of "
        "them: the rules are matching beyond their configured subtree")


def test_the_rule_still_applies_inside_its_own_subtree(server):
    """/alpha IS the first rule's subtree, and this request carries no VO."""
    assert _status(server, "/alpha/object.dat") == _FORBIDDEN, (
        "brix_require_vo /alpha vo-alpha did not apply inside /alpha")


def test_the_deeper_rule_applies_only_to_its_own_subtree(server):
    """/beta is the deeper rule's PARENT, not its subtree.

    The two rules differ in depth on purpose.  A collapse makes them the same
    length, so the longest-prefix scan cannot tell them apart and its tie-break
    (last declared wins) silently hands every request to /beta/gamma's rule.
    Asking about /beta — covered by neither — separates the two cases: refused
    means the deeper rule reached a path above itself."""
    assert _status(server, "/beta/object.dat") != _FORBIDDEN, (
        "brix_require_vo /beta/gamma vo-beta applied to /beta, which is its "
        "parent and not its subtree")


def test_a_non_boundary_prefix_does_not_inherit_the_rule(server):
    """(security negative) /alphaz starts with the rule's bytes and is not it.

    brix_path_prefix_match is boundary-aware for exactly this reason — "/alpha"
    must not reach "/alphaz" — and a rule that has lost its path passes that
    test for the wrong reason, by matching on a prefix that is no longer there.
    A collapse therefore shows up here as a refusal of an unrelated namespace."""
    assert _status(server, "/alphaz/object.dat") != _FORBIDDEN, (
        "a path sharing the rule's leading bytes but not its component boundary "
        "was refused: the prefix match is not anchored to the configured path")


# --------------------------------------------------------------------------- #
# The same question asked of the NATIVE authdb, whose rule prefix can be "/".   #
# --------------------------------------------------------------------------- #

def test_an_authdb_rule_on_the_root_covers_what_is_under_it(authdb_server):
    """(success) `a * / rl` grants a read of /alpha/object.dat.

    The root is the one rule prefix that already ends in the separator, so the
    component-boundary test has to treat it as satisfied — otherwise it covers
    the literal "/" alone.  A 403 here is the whole defect: the operator's
    export-wide grant was loaded, logged as live, and refused every reader."""
    assert _status(authdb_server("a * / rl\n"), "/alpha/object.dat") != _FORBIDDEN, (
        "an authdb rule on \"/\" did not cover a path beneath it: the root "
        "prefix is not being treated as ending on a component boundary")


def test_an_authdb_rule_still_bounds_itself_to_its_own_subtree(authdb_server):
    """(error) a rule on /alpha does not reach /beta — the grant is still scoped.

    The carve-out is for a prefix that ENDS in '/', and "/alpha" does not, so
    widening the root must not widen anything else.  With the export's only
    grant naming /alpha, a read of /beta has no rule and is refused."""
    assert _status(authdb_server("a * /alpha rl\n"), "/beta/object.dat") == _FORBIDDEN, (
        "an authdb rule on /alpha admitted a read of /beta: the root carve-out "
        "has widened a prefix that does not end in the separator")


def test_an_authdb_rule_does_not_reach_a_non_boundary_sibling(authdb_server):
    """(security negative) /alpha's grant must not admit /alphaz.

    Same bytes, no boundary.  This is the assertion that distinguishes "the
    root ends in a separator" from "any prefix match is good enough" — the
    second reading grants a whole neighbouring namespace to a rule that never
    named it."""
    assert _status(authdb_server("a * /alpha rl\n"), "/alphaz/object.dat") == _FORBIDDEN, (
        "an authdb rule on /alpha admitted a read of /alphaz: the prefix match "
        "is no longer anchored to a path-component boundary")
