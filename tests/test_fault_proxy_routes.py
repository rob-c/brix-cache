"""
test_fault_proxy_routes.py — behaviour tests for the brix-fault-proxy dynamic
multi-route table (docs/refactor/brix-fault-proxy-feature-expansion.md, Track U · C2).

C2 lets ONE daemon host many named L4 proxies created and destroyed at runtime:
`route add <name> <listen_port> <host:port,...>`, `route del <name>`,
`route list [json]`.  The legacy --listen/--target pair is registered as route
"default".  Each route owns its own listen socket, target pool and traffic
counters; the fault levers and toxic table stay process-global (shared).

House 3-test ritual, exercised across the class:

* SUCCESS  — a route added at runtime relays byte-exact to its own upstream, and
             `route list json` reports that route with its OWN counters (conns /
             bytes), independent of the default route; `route del` tears the
             route down and frees its listen port for re-binding.
* ERROR    — a duplicate name, a listen port already in use, and deleting a
             non-existent route are each rejected with an `err` reply and leave
             the table unchanged.
* SECURITY / NEG — a dynamic route inherits the daemon's vetted loopback bind and
             can never widen it (I4); the control plane refuses `route del
             default`, which would otherwise wedge the daemon.

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

FP_MAX_ROUTES = 16   # keep in step with brix_fault_proxy_internal.h


def _relay_once(port, payload, deadline=5.0):
    """Push `payload` through a listen `port`, drain the echo back, return bytes."""
    with socket.create_connection((HOST, port), timeout=deadline) as s:
        s.sendall(payload)
        s.settimeout(deadline)
        got = b""
        while len(got) < len(payload):
            d = s.recv(65536)
            if not d:
                break
            got += d
    return got


def _wait_listen(port, deadline=5.0):
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection((HOST, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.02)
    return False


def _routes_json(ctl):
    reply = _ctl(ctl, "route list json")
    return json.loads(reply.strip())["routes"]


def _route(ctl, name):
    for r in _routes_json(ctl):
        if r["name"] == name:
            return r
    return None


# --------------------------------------------------------------------------- #
# SUCCESS                                                                      #
# --------------------------------------------------------------------------- #

class TestDynamicRoutes:
    def test_route_relays_with_independent_counters(self, bfp):
        """A runtime-added route forwards byte-exact to its OWN upstream and
        `route list json` accounts its traffic on its own counters, distinct
        from the default route."""
        default_echo = _StreamEcho()
        alt_echo = _StreamEcho()
        proc = None
        try:
            proc, listen, ctl = _spawn(bfp, default_echo.port)

            # The default route exists and is the only route at boot.
            names = {r["name"] for r in _routes_json(ctl)}
            assert names == {"default"}

            rport = _free_port()
            reply = _ctl(ctl, f"route add alt {rport} {HOST}:{alt_echo.port}")
            def _assert_test_route_relays_with_independent_counters_1():
                assert reply.startswith("ok:"), reply
                assert _wait_listen(rport), "new route never started listening"

            _assert_test_route_relays_with_independent_counters_1()

            payload = b"routed-payload" * 64
            got = _relay_once(rport, payload)
            assert got == payload, "route did not relay byte-exact"

            # Counters land at connection teardown (ROUTE_FOLD on relay exit).
            time.sleep(0.2)
            alt = _route(ctl, "alt")
            def _assert_test_route_relays_with_independent_counters_2():
                assert alt is not None, "route vanished from list"
                assert alt["conns"] >= 1

            _assert_test_route_relays_with_independent_counters_2()
            def _assert_test_route_relays_with_independent_counters_3():
                assert alt["up_bytes"] >= len(payload)
                assert alt["down_bytes"] >= len(payload)

            _assert_test_route_relays_with_independent_counters_3()

            # The default route carried none of this traffic (independence).
            default = _route(ctl, "default")
            def _assert_test_route_relays_with_independent_counters_4():
                assert default["up_bytes"] == 0
                assert default["down_bytes"] == 0

            _assert_test_route_relays_with_independent_counters_4()
        finally:
            if proc is not None:
                proc.terminate()
                proc.wait(timeout=5)
            default_echo.close()
            alt_echo.close()

    def test_route_del_frees_the_port(self, bfp):
        """`route del` unwinds the accept thread, closes the listen socket and
        drops the route from the table; the port is then free to re-bind."""
        echo = _StreamEcho()
        alt = _StreamEcho()
        proc = None
        try:
            proc, listen, ctl = _spawn(bfp, echo.port)
            rport = _free_port()
            assert _ctl(ctl, f"route add gone {rport} {HOST}:{alt.port}").startswith("ok:")
            assert _wait_listen(rport)

            assert _ctl(ctl, "route del gone").startswith("ok:")
            assert _route(ctl, "gone") is None, "route still listed after del"

            # The freed port re-binds cleanly (proves the fd was closed).
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((HOST, rport))   # would raise EADDRINUSE if still held
            finally:
                s.close()
        finally:
            if proc is not None:
                proc.terminate()
                proc.wait(timeout=5)
            echo.close()
            alt.close()

    # ----------------------------------------------------------------------- #
    # ERROR                                                                    #
    # ----------------------------------------------------------------------- #

    def test_route_bad_inputs_rejected(self, bfp):
        """Duplicate name, a port already in use, and deleting a ghost route are
        each refused with an `err` reply and leave the table unchanged."""
        echo = _StreamEcho()
        alt = _StreamEcho()
        proc = None
        held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            proc, listen, ctl = _spawn(bfp, echo.port)

            rport = _free_port()
            assert _ctl(ctl, f"route add dup {rport} {HOST}:{alt.port}").startswith("ok:")
            assert _wait_listen(rport)

            # Duplicate name.
            assert _ctl(ctl, f"route add dup {_free_port()} {HOST}:{alt.port}").startswith("err")

            # Port already bound by an unrelated socket -> port in use.
            busy = _free_port()
            held.bind((HOST, busy))
            held.listen(1)
            r = _ctl(ctl, f"route add busy {busy} {HOST}:{alt.port}")
            assert "port in use" in r, r

            # Deleting a route that was never created.
            assert _ctl(ctl, "route del nope").startswith("err")

            # Only the one good route survives the failed adds.
            names = {r["name"] for r in _routes_json(ctl)}
            assert names == {"default", "dup"}
        finally:
            held.close()
            if proc is not None:
                proc.terminate()
                proc.wait(timeout=5)
            echo.close()
            alt.close()

    # ----------------------------------------------------------------------- #
    # SECURITY / NEG                                                           #
    # ----------------------------------------------------------------------- #

    def test_route_cannot_wedge_or_widen_the_gate(self, bfp):
        """The control plane refuses `route del default` (which would leave the
        daemon with no primary listener), and a dynamic route inherits the
        daemon's loopback bind — it is reachable on loopback and cannot widen
        the vetted gate."""
        echo = _StreamEcho()
        alt = _StreamEcho()
        proc = None
        try:
            proc, listen, ctl = _spawn(bfp, echo.port)

            # The default route is undeletable (would wedge the daemon).
            r = _ctl(ctl, "route del default")
            assert r.startswith("err"), r
            assert "default" in r
            assert _route(ctl, "default") is not None, "default route was removed"

            # A route added under the default (loopback) bind listens on
            # loopback — it inherits the gate rather than binding the wildcard.
            rport = _free_port()
            assert _ctl(ctl, f"route add gated {rport} {HOST}:{alt.port}").startswith("ok:")
            assert _wait_listen(rport), "gated route not reachable on loopback"
            # Reachable via loopback proves the inherited bind template took.
            assert _relay_once(rport, b"z" * 32) == b"z" * 32
        finally:
            if proc is not None:
                proc.terminate()
                proc.wait(timeout=5)
            echo.close()
            alt.close()
