"""
runner — expand case tables into tests and execute them.

WHAT
    Turns a per-tool list of ``Case`` objects into parametrize tuples and runs
    each one: stock-vs-ours differential parity for the base/knob-off case, and
    (for knob cases) a knob-on behavioural test with a bytes invariant.

WHY
    One execution path for every tool means the parity/knob/skip semantics are
    defined exactly once.  The test shims stay a two-line parametrize.

HOW
    ``expand(cases)`` → list of ``(kind, case, endpoint_key)`` params.
    ``run_param(tool, param, tmp_path, env)`` dispatches to ``run_case`` (parity)
    or ``run_knob`` (behavioural).  Health/availability are SKIPS, never fails.
"""

import os

import pytest

from . import corpus, diffcore
from . import endpoints as E
from .diffcore import OURS, STOCK


class Ctx:
    """Per-test working context: scratch dir + unique path allocation."""

    def __init__(self, endpoint, tmp_dir, worker):
        self.endpoint = endpoint
        self.tmp_dir = tmp_dir
        self.worker = worker or "main"

    @staticmethod
    def _safe(name):
        return name.replace("/", "_").replace(" ", "_")

    def local(self, name, which):
        """A unique local path (download sink / scratch), distinct per binary."""
        return os.path.join(self.tmp_dir, "%s.%s" % (which, self._safe(name)))

    def remote(self, name, which):
        """A unique remote path for an upload/mkdir, namespaced by worker+binary.

        Lives under a SCRATCH prefix (not the read-only corpus dir) so write
        cases never pollute the corpus a recursive/ls case fans out over.
        """
        return "/%s_scratch/%s_%s_%s" % (
            corpus.PREFIX, self.worker, which, self._safe(name))

    def url(self, path=""):
        return self.endpoint.url(path)


# --------------------------------------------------------------------------- #
# Parametrization                                                              #
# --------------------------------------------------------------------------- #
def expand(cases):
    """Flatten cases to ``(kind, case, endpoint_key)`` params.

    Each (case, endpoint) yields a parity param; knob cases add a knob-on param
    on the knob's applicable endpoints.
    """
    params = []
    for c in cases:
        for ek in sorted(c.endpoints):
            params.append(("off", c, ek))
            if c.knob and (c.knob.endpoints is None or ek in c.knob.endpoints):
                params.append(("on", c, ek))
    return params


def idfn(param):
    kind, case, ek = param
    return "%s-%s%s" % (case.id, ek, "+knob" if kind == "on" else "")


def ids(params):
    return [idfn(p) for p in params]


# --------------------------------------------------------------------------- #
# Execution                                                                    #
# --------------------------------------------------------------------------- #
def _require(tool, which):
    path = diffcore.binary(which, tool)
    if path is None:
        pytest.skip("%s %s binary not available" % (which, tool))
    return path


def run_case(tool, case, endpoint, ctx):
    """Differential parity: run stock + ours with identical argv, compare."""
    _require(tool, OURS)
    _require(tool, STOCK)

    results = {which: _run_case_client(which, tool, case, endpoint, ctx)
               for which in (STOCK, OURS)}
    _skip_unreachable(results[STOCK], results[OURS])
    diffcore.assert_parity(results[STOCK], results[OURS], case.parity,
                           tool=tool, case_id=case.id)
    _assert_case_bytes(case, results)
    _run_case_post(case, endpoint, ctx, results)


def _run_case_client(which, tool, case, endpoint, ctx):
    argv = case.argv(endpoint, ctx, which)
    produces = case.produces(ctx, which) if case.produces else None
    return diffcore.run_client(which, tool, argv, endpoint, stdin=case.stdin,
                               produces=produces, timeout=case.timeout)


def _skip_unreachable(*results):
    if any(result.unreachable for result in results):
        pytest.skip("server unreachable mid-run (infra)")


def _assert_case_bytes(case, results):
    if "bytes" in case.parity:
        diffcore.assert_bytes_identical(
            results[STOCK].produced, results[OURS].produced,
            what="%s bytes" % case.id)


def _run_case_post(case, endpoint, ctx, results):
    if case.post:
        case.post(endpoint, ctx, results)


def run_knob(tool, case, endpoint, ctx):
    """Knob ON: run only ours, assert the knob's effect + bytes invariant."""
    _require(tool, OURS)
    knob = case.knob

    # Knob-off baseline (ours), for the bytes invariant.
    base = _run_knob_client(tool, case, endpoint, ctx, "ours")

    # Knob on: prepend the global flag (+ any extra args) to a fresh argv whose
    # produces path is distinct so the two artefacts can be compared.
    on = _run_knob_client(tool, case, endpoint, ctx, "ours_knob", knob)
    _skip_unreachable(base, on)
    knob.behavioral(on, base, ctx)
    _assert_knob_bytes(case, knob, base, on)


def _run_knob_client(tool, case, endpoint, ctx, variant, knob=None):
    argv = case.argv(endpoint, ctx, variant)
    if knob is not None:
        argv = [knob.flag] + list(knob.extra_args) + argv
    produces = case.produces(ctx, variant) if case.produces else None
    return diffcore.run_client(OURS, tool, argv, endpoint, stdin=case.stdin,
                               produces=produces, timeout=case.timeout)


def _assert_knob_bytes(case, knob, base, on):
    if knob.invariant_bytes and base.produced and on.produced:
        diffcore.assert_bytes_identical(
            base.produced, on.produced,
            what="%s knob=%s bytes-invariant" % (case.id, knob.flag))


def run_param(tool, param, tmp_path, env):
    """Top-level dispatch used by the test shims."""
    kind, case, ek = param
    if ek not in env["healthy"]:
        pytest.skip("endpoint %s not healthy" % ek)
    if ek in case.xfail:
        pytest.skip("%s unsupported on endpoint %s" % (case.id, ek))
    endpoint = E.BY_KEY[ek]
    ctx = Ctx(endpoint, str(tmp_path), env["worker"])
    if kind == "on":
        run_knob(tool, case, endpoint, ctx)
    else:
        run_case(tool, case, endpoint, ctx)
