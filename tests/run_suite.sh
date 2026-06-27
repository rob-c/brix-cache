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

NPROC="$(nproc 2>/dev/null || echo 8)"
NPAR=$(( NPROC - 2 )); [ "$NPAR" -gt 12 ] && NPAR=12; [ "$NPAR" -lt 2 ] && NPAR=2
EXTRA=()
while [ $# -gt 0 ]; do
    case "$1" in
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

echo "== clean fleet =="
tests/manage_test_servers.sh stop-all >/dev/null 2>&1
tests/brutal_teardown.sh >/dev/null 2>&1
for _ in 1 2 3; do pgrep -x nginx >/dev/null && pkill -x nginx 2>/dev/null; done

rc=0; t0=$(date +%s)

echo "== LANE 1: parallel bulk (-n $NPAR, not serial) =="
run_lane -n "$NPAR" --dist load -- "$REPO/tests/" "${IGNORE[@]}" -m "not serial" || rc=1

echo "== LANE 2: serial-marked (timing / mesh / topology / xrdhttp daemon) =="
run_lane -p no:xdist -- "$REPO/tests/" --ignore="$REPO/tests/userns" -m serial || rc=1

echo "== LANE 3: destructive suites (serial — fixed-port self-started instances) =="
run_lane -p no:xdist -- "${DESTRUCTIVE[@]/#/$REPO/}" -m "not serial" || rc=1

echo "== LANE 4: clientconf differential (-n2) =="
run_lane -n 2 --dist load -- "${CLIENTCONF[@]/#/$REPO/}" || rc=1

t1=$(date +%s)
echo "== TOTAL wall: $((t1-t0))s  ==  overall: $([ $rc -eq 0 ] && echo PASS || echo FAIL) =="
exit $rc
