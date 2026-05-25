#!/usr/bin/env bash
# Verify that all expected XRootD client tools are present and executable.
# Exit 0 if everything is found; exit 1 if anything is missing.
set -euo pipefail

REQUIRED_TOOLS=(
    xrdcp
    xrdfs
    xrdgsiproxy
    xrdmapc
    davix-ls
    davix-get
    davix-put
    s3cmd
    gfal-copy
    gfal-ls
    curl
    openssl
    jq
    python3
)

MISSING=()
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING+=("$tool")
    fi
done

if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "MISSING tools: ${MISSING[*]}" >&2
    exit 1
fi

echo "All XRootD client tools present:"
for tool in "${REQUIRED_TOOLS[@]}"; do
    printf "  %-20s %s\n" "$tool" "$(command -v "$tool")"
done
echo "OK"
