#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# Native XRootD protocol cross-backend tests (root://)
TESTS=(
    tests/test_file_api.py
    tests/test_query.py
    tests/test_protocol_edge_cases.py
    tests/test_privilege_escalation.py
)

# HTTP-TPC / WebDAV over HTTPS cross-backend tests (davs:// vs XrdHttp)
XRDHTTP_TESTS=(
    tests/test_xrdhttp_webdav.py
    tests/test_xrdhttp_conformance.py
)

run_backend() {
    local backend="$1"
    shift

    echo
    echo "== Running cross-compatible tests against ${backend} =="
    TEST_CROSS_BACKEND="${backend}" pytest "${TESTS[@]}" "$@"
}

# Run native XRootD conformance tests (root:// protocol)
run_backend nginx "$@"
run_backend xrootd "$@"

# Run XrdHttp/WebDAV conformance tests against both backends
if [[ -n "${XRDHTTP_TESTS[*]:-}" ]]; then
    echo
    echo "== Running XrdHttp/WebDAV cross-compatible tests =="
    for test_file in "${XRDHTTP_TESTS[@]}"; do
        if [[ ! -f "$test_file" ]]; then
            echo "SKIP: $test_file not found"
            continue
        fi

        run_backend nginx -- "$test_file" || true
        run_backend xrootd -- "$test_file" || true
    done
fi
