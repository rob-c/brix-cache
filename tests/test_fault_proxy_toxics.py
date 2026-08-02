"""
test_fault_proxy_toxics.py — behaviour tests for the brix-fault-proxy named-toxic
table (docs/refactor/brix-fault-proxy-feature-expansion.md, Track U · C1).

C1 restores the Toxiproxy "list of named toxics per direction" model on top of
the flat g_up/g_down levers: operators `toxic add <name> <type> <params> [dir]`,
`toxic remove <name>` and `toxic list [json]` at runtime.  Named toxics stack
(two of a kind now compose, where the flat model held exactly one field) and are
individually removable; when the table is empty the relay takes the pre-C1 flat
fast path with zero overhead (no lock, no compose).

House 3-test ritual, exercised across the class:

* SUCCESS  — add/list/remove drive the control-plane oracle; a latency toxic
             actually delays the relayed stream; two latency toxics *stack*
             (additive), which the flat single-field lever could not express.
* ERROR    — duplicate name, unknown type, unknown subcommand and removing a
             non-existent toxic are all rejected with an `err` reply and leave
             the table unchanged.
* SECURITY / NEG — the fixed-capacity table refuses the (FP_MAX_TOXICS+1)th add
             rather than overrunning (no unbounded growth / overflow), and
             `clear` empties the table so the relay returns to the flat fast path.

Self-contained: reuses the echo upstreams + spawn/ctl helpers from
test_brix_fault_proxy on ephemeral ports. No fleet server, so no registry
declaration is required.
"""

import json
import socket
import time

from settings import HOST
from test_brix_fault_proxy import (  # noqa: F401  (bfp is a re-exported fixture)
    _StreamEcho,
    _ctl,
    _free_port,
    _spawn,
    bfp,
)

FP_MAX_TOXICS = 16   # keep in step with brix_fault_proxy_internal.h


def _drive(listen, n):
    """Send `n` bytes up; the stream echo bounces them down (where a down-facing
    toxic applies); return (bytes_drained, seconds) for the round trip.  Timed on
    time.monotonic() to match the relay's CLOCK_MONOTONIC pacing."""
    payload = b"x" * n
    t0 = time.monotonic()
    with socket.create_connection((HOST, listen), timeout=5) as s:
        s.sendall(payload)
        s.settimeout(5.0)
        got = 0
        while got < n:
            d = s.recv(65536)
            if not d:
                break
            got += len(d)
    return got, time.monotonic() - t0


def _toxic_count(ctl):
    """Parse `toxics=N` off the human `toxic list` reply."""
    head = _ctl(ctl, "toxic list").splitlines()[0].strip()
    assert head.startswith("toxics="), head
    return int(head.split("=", 1)[1])


class TestNamedToxics:

    # ---- SUCCESS ---------------------------------------------------------- #

    def test_add_list_remove_lifecycle(self, bfp):
        """SUCCESS: add two toxics, list (text + json) reflects them, remove one
        and clear empties the table — the full control-plane lifecycle."""
        echo = _StreamEcho()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert "added slowdl" in _ctl(ctl, "toxic add slowdl latency 40 down")
            assert "added garble" in _ctl(ctl, "toxic add garble corrupt 5 down")
            assert _toxic_count(ctl) == 2

            doc = json.loads(_ctl(ctl, "toxic list json").strip())
            names = {t["name"]: t for t in doc["toxics"]}
            assert set(names) == {"slowdl", "garble"}
            assert names["slowdl"]["type"] == "latency"
            assert names["garble"]["type"] == "corrupt"
            assert names["garble"]["dir"] == "down"

            assert "removed slowdl" in _ctl(ctl, "toxic remove slowdl")
            assert _toxic_count(ctl) == 1
            assert _ctl(ctl, "clear").strip() == "ok"
            assert _toxic_count(ctl) == 0
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_toxic_composes_into_relay(self, bfp):
        """SUCCESS: a latency toxic folded onto the (empty) flat levers actually
        delays the relayed stream — proving compose reaches the data plane — and
        removing it restores the fast path."""
        echo = _StreamEcho()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            n = 4096
            _, base = _drive(listen, n)
            assert base < 0.15, f"baseline unexpectedly slow ({base:.3f}s)"

            assert "added" in _ctl(ctl, "toxic add lag latency 250 down")
            _, slow = _drive(listen, n)
            assert slow >= 0.20, f"toxic latency not applied ({slow:.3f}s)"

            assert "removed" in _ctl(ctl, "toxic remove lag")
            _, fast = _drive(listen, n)
            assert fast < 0.15, f"fast path not restored after remove ({fast:.3f}s)"
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_stacked_latency_is_additive(self, bfp):
        """SUCCESS (the C1 headline): two latency toxics on the same direction
        STACK — the flat lever holds exactly one latency field, so ~0.30 s of
        delay from two 150 ms toxics can only come from composing both."""
        echo = _StreamEcho()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            n = 4096
            assert "added" in _ctl(ctl, "toxic add a latency 150 down")
            assert "added" in _ctl(ctl, "toxic add b latency 150 down")
            _, dt = _drive(listen, n)
            # A single flat latency lever could contribute at most one 150 ms hit;
            # >= 0.25 s proves both toxics folded in.
            assert dt >= 0.25, f"latency toxics did not stack ({dt:.3f}s)"
        finally:
            proc.terminate(); proc.wait(); echo.close()

    # ---- ERROR ------------------------------------------------------------ #

    def test_bad_inputs_rejected(self, bfp):
        """ERROR: duplicate name, unknown type, unknown subcommand and removing a
        missing toxic are refused, and none of them mutate the table."""
        echo = _StreamEcho()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert "added" in _ctl(ctl, "toxic add dup latency 10 down")
            assert _toxic_count(ctl) == 1

            assert "err: exists" in _ctl(ctl, "toxic add dup latency 99 up")
            assert "err: unknown toxic type" in _ctl(ctl, "toxic add x bogus 1")
            assert "err: unknown toxic subcommand" in _ctl(ctl, "toxic frobnicate y")
            assert "err: no such toxic" in _ctl(ctl, "toxic remove ghost")

            # every rejection left the single valid toxic in place, unchanged
            assert _toxic_count(ctl) == 1
            doc = json.loads(_ctl(ctl, "toxic list json").strip())
            assert doc["toxics"][0] == {"name": "dup", "type": "latency", "dir": "down"}
        finally:
            proc.terminate(); proc.wait(); echo.close()

    # ---- SECURITY / NEG --------------------------------------------------- #

    def test_capacity_capped_and_clear_suppresses(self, bfp):
        """SECURITY/NEG: the fixed-capacity table refuses the overflowing add
        (no unbounded growth), and `clear` drops every toxic so the relay falls
        back to the flat fast path."""
        echo = _StreamEcho()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            for i in range(FP_MAX_TOXICS):
                assert "added" in _ctl(ctl, f"toxic add t{i} latency 1 down")
            assert _toxic_count(ctl) == FP_MAX_TOXICS

            # the (max+1)th is refused, and the table stays exactly full
            assert "err: too many toxics" in _ctl(ctl, "toxic add overflow latency 1 down")
            assert _toxic_count(ctl) == FP_MAX_TOXICS

            assert _ctl(ctl, "clear").strip() == "ok"
            assert _toxic_count(ctl) == 0
            _, fast = _drive(listen, 4096)
            assert fast < 0.15, f"fast path not restored after clear ({fast:.3f}s)"
        finally:
            proc.terminate(); proc.wait(); echo.close()
