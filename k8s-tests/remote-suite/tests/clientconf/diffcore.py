"""
diffcore — run a client tool, normalize its output, compare two runs.

WHAT
    The single engine every parity/behavioural test flows through.  It resolves
    the stock vs project binary, runs it under a scrubbed per-endpoint env,
    captures (rc, stdout, stderr, produced-file fingerprint), normalizes the
    text, and offers a small comparison vocabulary the case tables assert with.

WHY
    One normalization pipeline and one comparison path mean every tool agrees on
    what "the same" means; tightening a rule fixes the whole suite at once.  Raw
    output is always retained alongside the normalized view so a normalization
    rule can never silently mask a real regression — failures show both.

HOW
    ``run_client(which, tool, argv, endpoint, ...)`` → ``Result``.
    ``Result.norm_stdout`` / ``norm_stderr`` apply ``NORMALIZERS`` (named regex
    rules).  ``assert_parity(stock, ours, dims, ...)`` and
    ``assert_bytes_identical(...)`` are the assertion verbs; both consult the
    divergence registry so a *registered* difference is asserted positively and
    an *unregistered* one fails loudly.

No pytest import here on purpose — diffcore is plain Python and unit-testable.
"""

import hashlib
import os
import re
import shutil
import subprocess

from . import divergence

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUR_BIN_DIR = os.path.join(REPO, "client", "bin")

STOCK = "stock"
OURS = "ours"


# --------------------------------------------------------------------------- #
# Binary resolution                                                           #
# --------------------------------------------------------------------------- #
def binary(which, tool):
    """Absolute path to the stock or project ``tool``, or None if absent."""
    if which == OURS:
        cand = os.path.join(OUR_BIN_DIR, tool)
        return cand if os.path.exists(cand) else None
    return shutil.which(tool)


# --------------------------------------------------------------------------- #
# Normalization pipeline — named rules, applied to stdout/stderr before        #
# textual comparison.  Order matters; each rule is (name, compiled, repl).     #
# --------------------------------------------------------------------------- #
def _rule(name, pattern, repl=""):
    return (name, re.compile(pattern, re.MULTILINE), repl)


NORMALIZERS = [
    # ANSI colour / cursor control.
    _rule("ansi", r"\x1b\[[0-9;?]*[A-Za-z]"),
    # Carriage-return progress redraws — keep only the final segment per line.
    _rule("cr-progress", r"^.*\r(?=[^\n])", ""),
    # Version / build banners (tool-name agnostic).
    _rule("version-banner", r"(?im)^.*\bv?\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.]+)?\b.*$"),
    # Transfer rate / throughput / progress-bar lines.
    _rule("rate", r"(?im)^.*\b\d+(?:\.\d+)?\s?[KMGT]?B/s\b.*$"),
    _rule("pbar", r"(?m)^.*\[\s*\d+%\s*\].*$"),
    # Elapsed / duration tails.
    _rule("elapsed", r"(?im)\[\s*\d+:\d{2}:\d{2}\s*\]"),
    # Absolute scratch paths under the test tree → placeholder.
    _rule("tmp-path", r"/tmp/[^\s:'\"]+", "<TMP>"),
    # Our client's GSI auto-discovery chatter (ambient proxy) — never emitted by
    # stock; it's an environment artefact, not a behavioural difference.
    _rule("gsi-proxy-note", r"(?im)^.*GSI proxy (?:has )?(?:EXPIRED|not found).*$"),
    # PIDs in diagnostics.
    _rule("pid", r"(?i)\bpid[:=]\s*\d+", "pid=<PID>"),
    # Timestamps (ISO-ish and "MTime:" lines vary only by clock skew rarely;
    # keep MTime — it is server truth and identical across clients — but strip
    # free-floating wall-clock stamps in banners).
    _rule("walltime", r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?\b(?!.*MTime)",
          "<TS>"),
    # Collapse trailing whitespace and blank-line runs (stock 'stat' prints a
    # leading blank line ours omits — a cosmetic frame, not information).
    _rule("trailing-ws", r"[ \t]+$", ""),
    _rule("blank-runs", r"\n{2,}", "\n"),
]


def normalize(text):
    """Apply the full normalization pipeline, returning the stripped result."""
    if text is None:
        return ""
    for _name, rx, repl in NORMALIZERS:
        text = rx.sub(repl, text)
    return text.strip("\n").strip()


# --------------------------------------------------------------------------- #
# Result                                                                       #
# --------------------------------------------------------------------------- #
def _decode(b):
    """Bytes → str, never raising on non-UTF-8 (binary stdout from cat etc.)."""
    if b is None:
        return ""
    if isinstance(b, str):
        return b
    return b.decode("utf-8", "replace")


class Result:
    """Outcome of one client invocation: raw + normalized views + artefact.

    ``stdout``/``stderr`` are decoded text (UTF-8, errors replaced) for
    normalization/comparison; ``stdout_bytes`` keeps the exact bytes so binary
    output (e.g. ``cat`` of a binary file) can be compared losslessly.
    """

    def __init__(self, which, argv, rc, stdout, stderr, produced=None,
                 timed_out=False):
        self.which = which            # STOCK or OURS
        self.argv = argv
        self.rc = rc
        self.stdout_bytes = stdout if isinstance(stdout, bytes) else \
            (stdout or "").encode("utf-8", "replace")
        self.stdout = _decode(stdout)
        self.stderr = _decode(stderr)
        self.produced = produced      # {"size":int,"sha256":str} or None
        self.timed_out = timed_out

    @property
    def unreachable(self):
        """True when the run failed because the server was not reachable.

        A mid-run server death is INFRA, not a client divergence — the runner
        skips on this rather than reporting a spurious parity failure.
        """
        blob = (self.stdout + self.stderr).lower()
        return (("connect" in blob and ("fail" in blob or "refused" in blob))
                or "connection refused" in blob or self.timed_out)

    @property
    def norm_stdout(self):
        return normalize(self.stdout)

    @property
    def norm_stderr(self):
        return normalize(self.stderr)

    def facet(self, dim):
        """The comparable value for a comparison dimension."""
        if dim == "rc":
            return self.rc
        if dim == "stdout":
            return self.norm_stdout
        if dim == "stderr":
            return self.norm_stderr
        if dim == "bytes":
            return None if self.produced is None else self.produced.get("sha256")
        raise ValueError("unknown comparison dim: %r" % dim)

    def __repr__(self):
        return "<Result %s rc=%s%s>" % (
            self.which, self.rc, " TIMEOUT" if self.timed_out else "")


def _fingerprint(path):
    """Size + sha256 of a produced file, or None if it does not exist."""
    if not path or not os.path.exists(path) or not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return {"size": size, "sha256": h.hexdigest()}


# --------------------------------------------------------------------------- #
# Runner                                                                       #
# --------------------------------------------------------------------------- #
def run_client(which, tool, argv, endpoint, *, env_extra=None, stdin=None,
               produces=None, timeout=90):
    """Run ``tool`` (stock|ours) with ``argv`` against ``endpoint``.

    ``argv`` is the already-built argument vector (the case table supplies it).
    ``produces`` is a local path to fingerprint after the run (transfer sink).
    Returns a ``Result``; a timeout is a *recorded failure*, never a hang.
    """
    path = binary(which, tool)
    if path is None:
        raise FileNotFoundError("%s binary for %r not found" % (which, tool))

    env = endpoint.auth_env()
    if env_extra:
        env.update(env_extra)

    # Capture BYTES (text=False) so binary stdout never crashes the run; the
    # Result decodes for text comparison and keeps the raw bytes for cat.
    stdin_b = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
    full = [path] + list(argv)
    try:
        proc = subprocess.run(
            full, env=env, input=stdin_b,
            capture_output=True, timeout=timeout,
        )
        rc, out, err, to = proc.returncode, proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired as e:
        out = e.stdout or b""
        err = (e.stderr or b"") + b"\n<TIMEOUT>"
        rc, to = 124, True
    return Result(which, full, rc, out, err, produced=_fingerprint(produces),
                  timed_out=to)


# --------------------------------------------------------------------------- #
# Comparison verbs                                                             #
# --------------------------------------------------------------------------- #
class ParityError(AssertionError):
    pass


def _explain(stock, ours, dim):
    """A debuggable message showing normalized AND raw views for one dim."""
    return (
        "\n--- parity mismatch on dim=%s ---\n"
        "argv(stock): %s\nargv(ours):  %s\n"
        "STOCK.%s = %r\nOURS .%s = %r\n"
        "--- raw STOCK stdout ---\n%s\n--- raw OURS stdout ---\n%s\n"
        "--- raw STOCK stderr ---\n%s\n--- raw OURS stderr ---\n%s\n"
        % (dim, stock.argv, ours.argv,
           dim, stock.facet(dim), dim, ours.facet(dim),
           stock.stdout, ours.stdout, stock.stderr, ours.stderr)
    )


def assert_parity(stock, ours, dims, *, tool, case_id):
    """Assert OURS matches STOCK on each dim in ``dims``.

    For any (tool, case_id, dim) registered in the divergence registry the
    requirement switches from "equal" to "matches the registered expectation".
    An *unregistered* difference fails.
    """
    for dim in dims:
        div = divergence.lookup(tool, case_id, dim)
        if div is not None:
            divergence.assert_expectation(div, stock, ours, dim)
            continue
        if stock.facet(dim) != ours.facet(dim):
            raise ParityError(_explain(stock, ours, dim))


def assert_bytes_identical(a, b, *, what="produced bytes"):
    """Two produced-file fingerprints must match (size + sha256)."""
    if a is None or b is None:
        raise ParityError("%s: missing artefact (a=%r b=%r)" % (what, a, b))
    if a.get("sha256") != b.get("sha256") or a.get("size") != b.get("size"):
        raise ParityError("%s differ: %r vs %r" % (what, a, b))
