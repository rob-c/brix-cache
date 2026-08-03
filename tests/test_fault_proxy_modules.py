"""
test_fault_proxy_modules.py — the JSON control-input front-end bolted onto the
v1.3.0 brix-fault-proxy core (brix_fault_proxy_json.c).

The core sees a leading '{' on a control line and reprojects the object
({"cmd":<verb>,"args":<rest>}) onto the ONE verb grammar, then re-runs it — so
JSON input can never define a command the bare parser doesn't, nor drift from it.
The named-toxic (C1) and named-route (C2) modules have their own behaviour suites
(test_fault_proxy_toxics.py / test_fault_proxy_routes.py); this file covers only
the JSON dialect, which those do not.

House 3-test ritual:

* SUCCESS  — {"cmd":"latency","args":"25 down"} mutates exactly the lever the bare
             verb would; {"cmd":"status"} returns the status line — one grammar,
             two dialects.
* ERROR    — a malformed object and one missing the required "cmd" each draw a
             structured `err: bad json command` and execute nothing.
* SECURITY — an escaped newline inside "args" cannot smuggle a second command: the
             reprojected verb line is honoured only up to the newline, so the
             injected tail stays inert.

Self-contained: reuses the echo upstream + spawn/ctl helpers from
test_brix_fault_proxy on ephemeral ports.  No fleet server, so no registry
declaration is required.
"""

from test_brix_fault_proxy import (  # noqa: F401  (bfp is a re-exported fixture)
    _StreamEcho,
    _ctl,
    _spawn,
    bfp,
)


# --------------------------------------------------------------------------- #
# SUCCESS                                                                      #
# --------------------------------------------------------------------------- #

def test_json_command_mutates_lever(bfp):
    """A JSON command object reaches the exact same lever the bare verb would,
    and {"cmd":"status"} returns the status line — one grammar, two dialects."""
    echo = _StreamEcho()
    proc, _listen, ctl = _spawn(bfp, echo.port)
    try:
        assert _ctl(ctl, '{"cmd":"latency","args":"25 down"}').strip() == "ok"
        status = _ctl(ctl, "status")
        assert "down[lat=25" in status and "up[lat=0" in status   # only down moved
        # a JSON status request yields the same aggregate line
        assert "blocked=0" in _ctl(ctl, '{"cmd":"status"}')
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


# --------------------------------------------------------------------------- #
# ERROR                                                                        #
# --------------------------------------------------------------------------- #

def test_json_malformed_is_rejected(bfp):
    """A malformed object and one missing the required "cmd" both draw a
    structured error and execute nothing."""
    echo = _StreamEcho()
    proc, _listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "err: bad json command" in _ctl(ctl, '{"cmd":}')
        assert "err: bad json command" in _ctl(ctl, '{"args":"25"}')
        # the rejected input left the levers untouched
        assert "down[lat=0" in _ctl(ctl, "status")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


# --------------------------------------------------------------------------- #
# SECURITY / NEG                                                               #
# --------------------------------------------------------------------------- #

def test_json_escaped_newline_cannot_inject_second_command(bfp):
    """An escaped newline in "args" must not smuggle a second verb: the verb line
    is parsed only up to the newline, so the tail ("block") never runs."""
    echo = _StreamEcho()
    proc, _listen, ctl = _spawn(bfp, echo.port)
    try:
        # args decodes to "5 down\nblock" — only "latency 5 down" is honoured
        _ctl(ctl, '{"cmd":"latency","args":"5 down\\nblock"}')
        status = _ctl(ctl, "status")
        assert "down[lat=5" in status       # first verb applied
        assert "blocked=0" in status         # injected "block" did NOT run
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()
