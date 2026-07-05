#!/usr/bin/env bash
# tests/cvmfs/run_baselines.sh — run the harness against a squid or varnish
# baseline. Produces baseline_<name>.json for the comparison matrix. Skips
# cleanly when the proxy binary is not installed.
set -eu
NAME="${1:?squid|varnish}"; PORT="${2:?listen port}"; ORIGIN="${3:?host:port}"
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
OHOST="${ORIGIN%%:*}"; OPORT="${ORIGIN##*:}"
WORK="$(mktemp -d /tmp/cvmfs_baseline.XXXXXX)"; trap 'rm -rf "$WORK"' EXIT

case "$NAME" in
squid)
    command -v squid >/dev/null || { echo "SKIP: squid not installed"; exit 0; }
    sed -e "s/@PORT@/$PORT/" -e "s#@CACHEDIR@#$WORK/cache#" \
        -e "s/@ORIGINHOST@/$OHOST/" \
        "$REPO/deploy/cvmfs/baselines/squid.conf" > "$WORK/squid.conf"
    mkdir -p "$WORK/cache"
    squid -f "$WORK/squid.conf" -z 2>/dev/null; squid -f "$WORK/squid.conf"
    STOP="squid -f $WORK/squid.conf -k shutdown"
    # squid is a forward proxy: harness must use proxy-style URLs
    export http_proxy="http://127.0.0.1:$PORT"
    CACHEBASE="http://$ORIGIN"
    ;;
varnish)
    command -v varnishd >/dev/null || { echo "SKIP: varnishd not installed"; exit 0; }
    sed -e "s/@ORIGINHOST@/$OHOST/" -e "s/@ORIGINPORT@/$OPORT/" \
        "$REPO/deploy/cvmfs/baselines/varnish.vcl" > "$WORK/default.vcl"
    varnishd -a "127.0.0.1:$PORT" -f "$WORK/default.vcl" -n "$WORK/vn" -s malloc,256m
    STOP="pkill -f 'varnishd .*$WORK/vn'"
    CACHEBASE="http://127.0.0.1:$PORT"
    ;;
*) echo "unknown: $NAME" >&2; exit 2 ;;
esac

sleep 1
python3 "$HERE/harness.py" --cache "$CACHEBASE" \
    --mock "http://$ORIGIN" --out "baseline_${NAME}.json"
eval "$STOP" || true
echo "wrote baseline_${NAME}.json"
