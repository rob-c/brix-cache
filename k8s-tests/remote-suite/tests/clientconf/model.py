"""
model — the case data types shared by every per-tool case table.

A ``Case`` is one differential scenario expressed as data + small callables.
The per-tool modules under ``cases/`` build lists of these; the runner expands
each ``Case`` across its applicable endpoints (and, for knob cases, into a
knob-off parity test plus a knob-on behavioural test).

Design rule encoded here: *knob-off ⇒ parity with stock; knob-on ⇒ behavioural*
(``KnobSpec``).  Keeping these as plain data keeps the tables auditable and the
runner the single place that knows how to execute them.
"""


class Case:
    """One differential scenario.

    Parameters
    ----------
    id : str
        Stable, unique-per-tool identifier (used in the pytest test id).
    argv : callable(endpoint, ctx, which) -> list[str]
        Builds the argument vector for a binary run.  ``which`` is "stock" or
        "ours" so upload/download targets can be made per-binary-unique.
    endpoints : frozenset[str]
        Endpoint keys this case applies to (the runner fans out over these).
    parity : frozenset[str]
        Comparison dimensions that must match stock: subset of
        {"rc","stdout","stderr","bytes"}.
    produces : callable(ctx, which) -> str | None
        Local artefact path to fingerprint after the run (transfer sink), or
        None for metadata-only cases.
    stdin : str | None
        Text fed to the process stdin (e.g. stdin-source uploads).
    knob : KnobSpec | None
        When set, the case auto-expands into knob-off + knob-on tests.
    xfail : frozenset[str]
        Endpoint keys where the operation is known-unsupported; the runner
        SKIPS those rather than failing (e.g. write op on a read-only tier).
    post : callable(endpoint, ctx, results) -> None
        Optional extra verification after both runs (e.g. read-back an upload).
    timeout : int
        Per-run timeout in seconds.
    needs_write : bool
        Marks a case that mutates server state (helps endpoint filtering).
    """

    def __init__(self, id, argv, *, endpoints, parity, produces=None,
                 stdin=None, knob=None, xfail=frozenset(), post=None,
                 timeout=90, needs_write=False):
        self.id = id
        self.argv = argv
        self.endpoints = frozenset(endpoints)
        self.parity = frozenset(parity)
        self.produces = produces
        self.stdin = stdin
        self.knob = knob
        self.xfail = frozenset(xfail)
        self.post = post
        self.timeout = timeout
        self.needs_write = needs_write

    def applies_to(self, endpoint_key):
        return endpoint_key in self.endpoints

    def __repr__(self):
        return "<Case %s eps=%s parity=%s%s>" % (
            self.id, ",".join(sorted(self.endpoints)),
            ",".join(sorted(self.parity)), " +knob" if self.knob else "")


class KnobSpec:
    """A project-only flag (no stock equivalent) attached to a base case.

    The base case (knob OFF) must hold full stock parity.  With the knob ON we
    run ONLY our client and assert:
      * ``behavioral(result, base_result, ctx)`` — the knob's documented effect
        (a counter/log line/return value/produced artefact), and
      * the invariant that engaging the knob does not change the transferred
        bytes/checksum versus the knob-off baseline (when both produce bytes).
    """

    def __init__(self, flag, behavioral, *, extra_args=(), invariant_bytes=True,
                 endpoints=None):
        self.flag = flag
        self.behavioral = behavioral
        self.extra_args = list(extra_args)
        self.invariant_bytes = invariant_bytes
        self.endpoints = None if endpoints is None else frozenset(endpoints)
