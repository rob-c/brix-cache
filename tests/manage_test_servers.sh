#!/usr/bin/env bash
#
# Helper launcher for the local nginx+xrootd test environment.
#
# Manages:
#   - Multiple nginx instances (ports 11094-11123, 8443, 8444, 9100, 18444-18456)
#   - Reference xrootd instances (ports 11098-11113)
#   - PKI regeneration (CA, certs, proxies, VOMS)
#
# Usage:
#   tests/manage_test_servers.sh start-all
#   tests/manage_test_servers.sh stop-all
#   tests/manage_test_servers.sh force-stop
#   tests/manage_test_servers.sh restart
#   tests/manage_test_servers.sh status
#
# Optional subcommands:
#   tests/manage_test_servers.sh start nginx
#   tests/manage_test_servers.sh start ref
#
# Environment variables:
#   TEST_ROOT - Base directory for test files (default: /tmp/xrd-test)
#   NGINX_BIN - Path to nginx binary (default: /tmp/nginx-1.28.3/objs/nginx)
#   REF_BIN   - Path to xrootd binary (default: xrootd)

set -euo pipefail

TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
NGINX_PREFIX="${NGINX_PREFIX:-$TEST_ROOT}"
NGINX_CONF_REL="${NGINX_CONF_REL:-conf/nginx.conf}"
NGINX_PORT="${NGINX_PORT:-11094}"

REF_BIN="${REF_BIN:-xrootd}"
REF_DIR="${REF_DIR:-$TEST_ROOT/ref}"
REF_CFG="${REF_CFG:-${REF_DIR}/conformance.cfg}"
REF_LOG="${REF_LOG:-${REF_DIR}/conformance.log}"
REF_PID_FILE="${REF_PID_FILE:-${REF_DIR}/run-conf/xrootd.pid}"
REF_PORT="${REF_PORT:-11098}"

DATA_DIR="${DATA_DIR:-$TEST_ROOT/data}"
PKI_DIR="${PKI_DIR:-$TEST_ROOT/pki}"
LOG_DIR="${LOG_DIR:-$TEST_ROOT/logs}"
TMP_DIR="${TMP_DIR:-$TEST_ROOT/tmp}"

NGINX_BIN="${NGINX_BIN:-/tmp/nginx-1.28.3/objs/nginx}"

# Config templates directory
CONFIGS_DIR="$(cd "$(dirname "$0")" && pwd)/configs"
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Phase 27 W6 — sanitizer mode.  When SANITIZE=1, every nginx this script
# launches inherits ASan/UBSan/LSan options via the environment (the binary
# must have been built with -fsanitize=address,undefined; see build-guide.md).
# LeakSanitizer reports leaks when each process exits (i.e. at `stop`), so the
# workflow is:  SANITIZE=1 restart  →  run the suite  →  SANITIZE=1 stop  →
# inspect ${SANITIZE_LOG_DIR}/asan.* for frames in src/.
# ---------------------------------------------------------------------------
if [[ "${SANITIZE:-0}" == "1" ]]; then
    SANITIZE_LOG_DIR="${SANITIZE_LOG_DIR:-$TEST_ROOT/sanitize}"
    mkdir -p "$SANITIZE_LOG_DIR"
    # halt_on_error=0 so one finding does not abort a whole worker mid-suite;
    # detect_leaks=1 turns on LSan at exit; log_path gives one file per pid.
    export ASAN_OPTIONS="detect_leaks=1:halt_on_error=0:abort_on_error=0:exitcode=0:log_path=${SANITIZE_LOG_DIR}/asan:print_legend=0:${ASAN_OPTIONS:-}"
    export UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1:${UBSAN_OPTIONS:-}"
    export LSAN_OPTIONS="suppressions=${TESTS_DIR}/lsan.supp:report_objects=0:${LSAN_OPTIONS:-}"
    echo "SANITIZE=1: leak/UBSan logs → ${SANITIZE_LOG_DIR}/asan.<pid>" >&2
fi

# ---------------------------------------------------------------------------
# Phase 27 W6c — Valgrind mode.  When VALGRIND=1, the MAIN nginx instance is
# launched under Valgrind Memcheck (LSan does not fire for nginx under WSL2 —
# see docs/07-security/valgrind-findings.md, so Memcheck is the leak tool here).
# Memcheck emits a report when each traced process exits, so the workflow is:
#   VALGRIND=1 restart  →  run the suite  →  VALGRIND=1 stop  →
#   inspect ${VALGRIND_LOG_DIR}/vg.<workerpid>.log (the worker is the signal; the
#   master log may carry benign nginx-core shutdown noise).
# The standalone tests/valgrind/run_valgrind.sh is the primary harness; this mode
# is for exercising the real generated fleet config under Memcheck.
# ---------------------------------------------------------------------------
if [[ "${VALGRIND:-0}" == "1" ]]; then
    VALGRIND_LOG_DIR="${VALGRIND_LOG_DIR:-$TEST_ROOT/valgrind}"
    mkdir -p "$VALGRIND_LOG_DIR"
    VALGRIND_SUPP="${VALGRIND_SUPP:-${TESTS_DIR}/valgrind/valgrind.supp}"
    : "${VALGRIND_OPTS:=--leak-check=full --show-leak-kinds=definite,indirect --track-fds=yes --trace-children=yes --child-silent-after-fork=no --error-exitcode=0 --num-callers=30}"
    echo "VALGRIND=1: memcheck logs → ${VALGRIND_LOG_DIR}/vg.<pid>.log" >&2
fi

# Phase-38: function definitions live in sourced concern libs.
XRD_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib"
source "$XRD_LIB_DIR/util.sh"
source "$XRD_LIB_DIR/pki.sh"
source "$XRD_LIB_DIR/nginx.sh"
source "$XRD_LIB_DIR/refxrootd.sh"
source "$XRD_LIB_DIR/xrdhttp.sh"
source "$XRD_LIB_DIR/dedicated.sh"

ACTION="${1:-}"
TARGET="${2:-all}"

if [[ -z "$ACTION" ]]; then
    usage
    exit 1
fi

case "$ACTION" in
    start-all)
        start_all_dedicated
        ;;
    stop-all)
        stop_all_dedicated
        ;;
    start-dedicated)
        # Restart a single named dedicated nginx instance without a full start-all.
        case "$TARGET" in
            cluster-redir)
                CMS_PORT="${CLUSTER_REDIR_CMS_PORT:-11161}" \
                    start_dedicated_nginx "cluster-redir" "nginx_cluster_redir.conf" \
                    "${CLUSTER_REDIR_PORT:-11160}"
                ;;
            cluster-ds)
                CMS_PORT="${CLUSTER_REDIR_CMS_PORT:-11161}" CMS_PATHS="/" \
                    start_dedicated_nginx "cluster-ds" "nginx_cluster_ds.conf" \
                    "${CLUSTER_DS_PORT:-11162}"
                ;;
            manager)
                start_dedicated_nginx "manager" "nginx_manager.conf" \
                    "${MANAGER_PORT:-11101}"
                ;;
            cluster-3t-meta)
                CMS_PORT="${CLUSTER_3T_META_CMS_PORT:-11186}" \
                    start_dedicated_nginx "cluster-3t-meta" "nginx_cluster_redir.conf" \
                    "${CLUSTER_3T_META_PORT:-11185}"
                ;;
            cluster-3t-sub)
                CMS_PORT="${CLUSTER_3T_SUB_CMS_PORT:-11188}" \
                META_CMS_PORT="${CLUSTER_3T_META_CMS_PORT:-11186}" \
                SELF_REGISTER_PORT="${CLUSTER_3T_SELF_PORT:-11189}" \
                    start_dedicated_nginx "cluster-3t-sub" "nginx_cluster_sub_manager.conf" \
                    "${CLUSTER_3T_SUB_PORT:-11187}"
                ;;
            cluster-3t-leaf)
                CMS_PORT="${CLUSTER_3T_SUB_CMS_PORT:-11188}" CMS_PATHS="/" \
                    start_dedicated_nginx "cluster-3t-leaf" "nginx_cluster_ds.conf" \
                    "${CLUSTER_3T_LEAF_PORT:-11190}"
                ;;
            *) echo "start-dedicated: unknown target '${TARGET}'" >&2; exit 1 ;;
        esac
        ;;
    start)
        case "$TARGET" in
            all) start_all_dedicated ;;
            nginx)
                if [[ "${SKIP_NGINX_FORCE_STOP_ON_START:-0}" == "1" ]]; then
                    start_nginx
                else
                    force_stop_nginx
                    start_nginx
                fi
                ;;
            ref) force_stop_ref; start_ref ;;
            xrdhttp) stop_xrdhttp; start_xrdhttp ;;
            *) usage; exit 1 ;;
        esac
        ;;
    stop)
        case "$TARGET" in
            all) stop_all_dedicated ;;
            nginx) stop_nginx ;;
            ref) stop_ref ;;
            xrdhttp) stop_xrdhttp ;;
            *) usage; exit 1 ;;
        esac
        ;;
    force-stop)
        case "$TARGET" in
            all) force_stop_ref; force_stop_nginx ;;
            nginx) force_stop_nginx ;;
            ref) force_stop_ref ;;
            xrdhttp) force_stop_xrdhttp ;;
            *) usage; exit 1 ;;
        esac
        ;;
    restart)
        case "$TARGET" in
            all) stop_all_dedicated; start_all_dedicated ;;
            nginx) stop_nginx; start_nginx ;;
            ref) stop_ref; start_ref ;;
            xrdhttp) stop_xrdhttp; start_xrdhttp ;;
            *) usage; exit 1 ;;
        esac
        ;;
    status)
        case "$TARGET" in
            all) status_nginx; status_ref ;;
            nginx) status_nginx ;;
            ref) status_ref ;;
            xrdhttp) status_xrdhttp ;;
            *) usage; exit 1 ;;
        esac
        ;;
    *)
        usage
        exit 1
        ;;
esac
