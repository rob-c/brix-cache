#!/usr/bin/env bash
#
# run_suite.sh — the canonical, reliable full-suite runner ("source of truth").
#
# WHY a runner (not bare `pytest -n12`):
#   * The suite mixes ~6900 fast parallel-safe tests with a few dozen heavyweight
#     ones that are NOT safe in the parallel pool — timing/throughput ratios,
#     multi-node CMS meshes, the topology tests that spawn nested conformance runs,
#     and the tests that drive a shared real XrdHttp daemon. Those are marked
#     `@pytest.mark.serial` and run in their own serial lane where they are stable.
#   * The destructive suites (chaos/evil/*_resilience/netfault) self-start
#     dedicated FIXED-port instances and cannot run in parallel (port collisions);
#     they get their own serial lane. clientconf forks many xrdcp subprocesses, so
#     it runs at low parallelism. tests/userns/ needs privileges and is excluded.
#   * Even parallel-safe tests occasionally hit a *transient* flake under sustained
#     pool load (a ConnectionReset / a reference-xrootd dirlist framing hiccup) —
#     environmental, not a product bug. These are LOAD-CORRELATED: they fail for
#     the whole loaded run, so immediate in-process retries don't escape them.
#     The robust fix is to re-run ONLY the failed tests AFTER the main run, on a
#     now-quiet box, at progressively lower parallelism (`--lf -n2`, then serial).
#     A real bug fails even quiet → still reported red; a flake passes. This keeps
#     the suite a trustworthy pass/fail signal with no human flake-triage.
#
# Usage:  tests/run_suite.sh [-n PARALLEL] [-- extra pytest args]
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
export PYTHONPATH="tests${PYTHONPATH:+:$PYTHONPATH}"
# Every lane AND every --lf rerun must OWN a fresh fleet, never attach.  Without
# this, a lane's sessionfinish rmtree's TEST_ROOT (deleting the PKI) but nginx
# workers outlive the 30s stop window, so the next invocation (a rerun, or the
# next lane) probes port 11094, finds the zombie fleet, and enters attach mode —
# skipping _setup_session, which is where X509_CERT_DIR/X509_USER_PROXY get set
# and the PKI regenerated.  GSI clients then have no proxy and every GSI open
# fails "No protocols left to try" (the entire lane-2 concurrent/throughput/
# gsi_handshake cluster).  Forcing own-fleet reaps the zombie (resilient
# start-all) and regenerates the PKI for each invocation.
export TEST_OWN_FLEET=1

NPROC="$(nproc 2>/dev/null || echo 8)"
NPAR=$(( NPROC - 2 )); [ "$NPAR" -gt 12 ] && NPAR=12; [ "$NPAR" -lt 2 ] && NPAR=2
FAST=0
PR=0
NIGHTLY=0
EXTRA=()
while [ $# -gt 0 ]; do
    case "$1" in
        --fast)    FAST=1; shift ;;
        --pr)      PR=1; shift ;;
        --nightly) NIGHTLY=1; shift ;;
        -n) NPAR="$2"; shift 2 ;;
        --) shift; EXTRA=("$@"); break ;;
        *)  EXTRA+=("$1"); shift ;;
    esac
done

DESTRUCTIVE=(
    tests/test_chaos_mesh.py tests/test_chaos_mixed_auth.py
    tests/test_cms_resilience.py tests/test_compression_fuse_resilience.py
    tests/test_evil_actor.py tests/test_evil_actor_v2.py
    tests/test_evil_actor_v3.py tests/test_evil_actor_v3_b.py
    tests/test_evil_paths.py tests/test_netfault_stream.py
    tests/test_net_resilience.py tests/test_official_xrootd_resilience.py
    tests/test_phase51_resilience.py tests/test_xrootdfs_resilience.py
    tests/resilience
)
# A stale path here (e.g. a renamed file) makes pytest abort collection with
# "file or directory not found" and run ZERO tests for the whole lane — silently
# disabling the entire destructive/chaos/resilience suite.  Drop any path that no
# longer exists, loudly, so one rename can never zero the lane again.
_dexist=()
for _p in "${DESTRUCTIVE[@]}"; do
    if [ -e "$REPO/$_p" ]; then _dexist+=("$_p")
    else echo "WARNING: DESTRUCTIVE path missing, skipping: $_p" >&2; fi
done
DESTRUCTIVE=("${_dexist[@]}")
CLIENTCONF=( tests/test_clientconf_cksum.py tests/test_clientconf_narrative.py
    tests/test_clientconf_surface.py tests/test_clientconf_xrdcp.py
    tests/test_clientconf_xrdfs.py tests/test_clientconf_xrdgsiproxy.py
    tests/test_clientconf_xrdmapc.py )

IGNORE=( "--ignore=$REPO/tests/userns" )
for p in "${DESTRUCTIVE[@]}" "${CLIENTCONF[@]}"; do IGNORE+=( "--ignore=$REPO/$p" ); done

COMMON=(-ra -q -p no:randomly --color=no "${EXTRA[@]}")

# run_lane <main-dist-args...> -- <selection-args...>
# Runs the main pass, then (if anything failed) re-runs ONLY the failures on a
# now-quiet box at -n2 and finally serially. Returns 0 iff the failures clear.
run_lane() {
    local main=(); while [ "$1" != "--" ]; do main+=("$1"); shift; done; shift
    local sel=("$@")
    python -m pytest "${sel[@]}" "${main[@]}" "${COMMON[@]}" && return 0
    echo "   ↻ re-running just the failures on a now-quiet box (--lf -n2)…"
    python -m pytest "${sel[@]}" --lf -n 2 --dist load "${COMMON[@]}" && return 0
    echo "   ↻ re-running the remaining failures serially…"
    python -m pytest "${sel[@]}" --lf -p no:xdist "${COMMON[@]}" && return 0
    return 1
}

# run_lane_pr — like run_lane but with a SINGLE serial flake-filter re-run (not
# the 3-attempt ladder). The PR gate optimises for wall time: one quiet serial
# re-run clears the load-correlated flakes; a real bug still fails and stays red.
run_lane_pr() {
    local main=(); while [ "$1" != "--" ]; do main+=("$1"); shift; done; shift
    local sel=("$@")
    python -m pytest "${sel[@]}" "${main[@]}" "${COMMON[@]}" && return 0
    echo "   ↻ re-running just the failures serially (flake filter)…"
    python -m pytest "${sel[@]}" --lf -p no:xdist "${COMMON[@]}" && return 0
    return 1
}

echo "== clean fleet =="
tests/manage_test_servers.sh stop-all >/dev/null 2>&1
tests/brutal_teardown.sh >/dev/null 2>&1
for _ in 1 2 3; do pgrep -x nginx >/dev/null && pkill -x nginx 2>/dev/null; done

rc=0; t0=$(date +%s)

# --fast: a single parallel lane over the quick tests only (drops the slow
# families auto-marked `slow` in conftest.py: resilience/chaos/conformance/
# clientconf/mesh/throughput/…). No flake-rerun, no dedicated serial/destructive
# lanes — a ~minutes iteration signal, NOT a substitute for the full run.
if [ "$FAST" -eq 1 ]; then
    echo "== FAST: parallel quick lane (-n $NPAR, -m 'not slow and not serial') =="
    python -m pytest "$REPO/tests/" "${IGNORE[@]}" \
        -m "not slow and not serial" -n "$NPAR" --dist load "${COMMON[@]}"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        # Clear LOAD-CORRELATED flakes (the parallel pool occasionally trips a
        # ConnectionReset / GSI-handshake hiccup): re-run ONLY the failures once,
        # serially on a now-quiet box.  A real bug fails again → stays red.
        echo "   ↻ re-running just the failures serially (flake filter)…"
        python -m pytest "$REPO/tests/" "${IGNORE[@]}" \
            -m "not slow and not serial" --lf -p no:xdist "${COMMON[@]}"
        rc=$?
    fi
    t1=$(date +%s)
    echo "== FAST wall: $((t1-t0))s  ==  $([ $rc -eq 0 ] && echo PASS || echo FAIL) =="
    echo "   (run the full suite before merging: tests/run_suite.sh)"
    exit $rc
fi

# --nightly: the deferred `slow` set — the fault-injection / perf / mesh /
# conformance / clientconf / interop families that carry 15-59s-per-test
# timeouts and cannot fit the <5min gate. Reuses the full lane structure but
# selects only `-m slow`. Run this pre-release; --pr + --nightly == full coverage.
if [ "$NIGHTLY" -eq 1 ]; then
    echo "== NIGHTLY: the deferred slow set (-m slow) =="
    echo "== lane 1: slow parallel-safe (-m 'slow and not serial') =="
    run_lane -n "$NPAR" --dist load -- "$REPO/tests/" "${IGNORE[@]}" \
        -m "slow and not serial" || rc=1
    echo "== lane 2: slow serial-marked =="
    run_lane -p no:xdist -- "$REPO/tests/" --ignore="$REPO/tests/userns" \
        -m "slow and serial" || rc=1
    echo "== lane 3: destructive suites =="
    run_lane -p no:xdist -- "${DESTRUCTIVE[@]/#/$REPO/}" || rc=1
    echo "== lane 4: clientconf differential (-n2) =="
    run_lane -n 2 --dist load -- "${CLIENTCONF[@]/#/$REPO/}" || rc=1
    t1=$(date +%s)
    echo "== NIGHTLY wall: $((t1-t0))s  ==  $([ $rc -eq 0 ] && echo PASS || echo FAIL) =="
    exit $rc
fi

# --pr: the <5min gate — the `not slow` set (bulk parallel + serial lane) with a
# single serial flake-filter re-run per lane (no 3-attempt ladder). The medium/
# heavy families (clientconf, conformance, interop, resilience, chaos, perf, …)
# are auto-marked `slow` and deferred to --nightly, because the shared test fleet
# caps useful parallelism at -n12 and those families cannot fit under 5 minutes.
# --pr + --nightly == the full run_suite.sh coverage.
if [ "$PR" -eq 1 ]; then
    echo "== PR GATE (<5min): the 'not slow' set (-n $NPAR) =="
    echo "== lane A: parallel bulk (-m 'not slow and not serial') =="
    run_lane_pr -n "$NPAR" --dist load -- "$REPO/tests/" "${IGNORE[@]}" \
        -m "not slow and not serial" || rc=1
    echo "== lane B: serial-marked, non-slow =="
    run_lane_pr -p no:xdist -- "$REPO/tests/" --ignore="$REPO/tests/userns" \
        -m "serial and not slow" || rc=1
    t1=$(date +%s)
    echo "== PR wall: $((t1-t0))s  ==  $([ $rc -eq 0 ] && echo PASS || echo FAIL) =="
    echo "   (run the deferred slow suites before release: tests/run_suite.sh --nightly)"
    exit $rc
fi

echo "== LANE 1: parallel bulk (-n $NPAR, not serial) =="
run_lane -n "$NPAR" --dist load -- "$REPO/tests/" "${IGNORE[@]}" -m "not serial" || rc=1

echo "== LANE 2: serial-marked (timing / mesh / topology / xrdhttp daemon) =="
run_lane -p no:xdist -- "$REPO/tests/" --ignore="$REPO/tests/userns" -m serial || rc=1

echo "== LANE 3: destructive suites (serial — fixed-port self-started instances) =="
# No marker filter: this lane already runs -p no:xdist (serial), and the
# destructive files are --ignore'd from lanes 1-2, so this is their only home.
# The old -m "not serial" deselected the serial-marked destructive tests
# (chaos_mesh, netfault, …), which then ran in NO lane at all.
run_lane -p no:xdist -- "${DESTRUCTIVE[@]/#/$REPO/}" || rc=1

echo "== LANE 4: clientconf differential (-n2) =="
run_lane -n 2 --dist load -- "${CLIENTCONF[@]/#/$REPO/}" || rc=1

t1=$(date +%s)
echo "== TOTAL wall: $((t1-t0))s  ==  overall: $([ $rc -eq 0 ] && echo PASS || echo FAIL) =="
exit $rc
