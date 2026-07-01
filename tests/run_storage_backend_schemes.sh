#!/usr/bin/env bash
#
# run_storage_backend_schemes.sh — phase-64: the xrootd_storage_backend scheme
# vocabulary. The primary-export backend selector (xrootd_vfs_backend_config_str)
# must recognise the SAME generic scheme set the composable cache/stage tier parser
# does: posix(:|://), pblock://, root(s)://, http(s)://, s3://, rados://, ceph:,
# tape://, frm:// (and cephfsro:). Each scheme extracts protocol + authority + path.
#
# Coverage (success + error + security-neg, per CLAUDE.md):
#   * positive: every scheme parses (nginx -t accepts it)
#   * negative: a bare/empty-authority scheme is rejected, not silently treated as a
#               POSIX directory literally named "s3://" / "rados://"
#   * data plane: posix:// serves byte-exact (helper rewrites common->root); frm://
#               (the tape:// alias) faults a recall through sd_frm + sd_cache
#
# Usage: tests/run_storage_backend_schemes.sh [nginx-binary]
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDCP="$HERE/client/bin/xrdcp"; XRDFS="$HERE/client/bin/xrdfs"
PORT=11754; OPORT=11755
PFX="$(mktemp -d /tmp/sbschemes.XXXXXX)"; fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() { for p in "$PFX"/*/nginx.pid "$PFX"/nginx.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/logs" "$PFX/cache" "$PFX/data"   # posix: export root must exist to parse

# ---- parse matrix (nginx -t only; remote endpoints need no live peer to parse) ----
mkconf() { cat > "$PFX/t.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/t.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${PORT}; xrootd on; xrootd_auth none; $1 } }
EOF
}
parse_ok() {  # desc, directives
    mkconf "$2"
    if "$NGINX" -p "$PFX" -c "$PFX/t.conf" -t >"$PFX/out" 2>&1; then ok "parse: $1"
    else bad "parse: $1 (expected accept)"; sed 's/^/      /' "$PFX/out"; fi
}
parse_no() {  # desc, directives, expect-pattern
    mkconf "$2"
    if "$NGINX" -p "$PFX" -c "$PFX/t.conf" -t >"$PFX/out" 2>&1; then
        bad "reject: $1 (expected reject)"; sed 's/^/      /' "$PFX/out"
    elif grep -qiE "$3" "$PFX/out"; then ok "reject: $1"
    else bad "reject: $1 (wrong error)"; sed 's/^/      /' "$PFX/out"; fi
}

echo "== positive: every storage_backend scheme parses =="
parse_ok "posix:<path>"          "xrootd_storage_backend posix:$PFX/data;"
parse_ok "posix://<path>"        "xrootd_storage_backend posix://$PFX/data;"
parse_ok "pblock://<path>"       "xrootd_storage_backend pblock://$PFX/pb;"
parse_ok "root://host:port"      "xrootd_storage_backend root://127.0.0.1:${OPORT};"
parse_ok "roots://host:port"     "xrootd_storage_backend roots://127.0.0.1:${OPORT};"
parse_ok "http://host/base"      "xrootd_storage_backend http://origin.example:8080/d;"
parse_ok "https://host/base"     "xrootd_storage_backend https://origin.example/d;"
parse_ok "s3://host:port/bucket" "xrootd_storage_backend s3://127.0.0.1:9000/mybucket;"
parse_ok "s3://host/bucket"      "xrootd_storage_backend s3://s3.example.com/data;"
parse_ok "rados://pool/ns"       "xrootd_storage_backend rados://mypool/myns;"
parse_ok "rados://pool"          "xrootd_storage_backend rados://mypool;"
parse_ok "frm://+cache (tape alias)" "xrootd_storage_backend frm://stub/$PFX/tape; xrootd_cache_store posix:$PFX/cache; xrootd_cache_root /;"

echo "== negative: malformed / bare scheme is an error, not a POSIX fallback =="
parse_no "bare s3://"            "xrootd_storage_backend s3://;"            "needs|host|bucket"
parse_no "s3:// no bucket"       "xrootd_storage_backend s3://127.0.0.1:9000;" "needs|bucket"
parse_no "bare rados://"         "xrootd_storage_backend rados://;"         "needs|pool"
parse_no "rados:/// empty pool"  "xrootd_storage_backend rados:///ns;"      "needs|pool"
parse_no "frm:// without cache"  "xrootd_storage_backend frm://stub/$PFX/tape;" "nearline|cache_store|recall"

# ---- data plane: posix:// serves bytes (no xrootd_root; helper rewrites root) ----
echo "== data plane: posix:// storage_backend serves byte-exact =="
mkdir -p "$PFX/data"
head -c 200000 /dev/urandom > "$PFX/data/blob.bin"
cat > "$PFX/p.conf" <<EOF
daemon on; error_log $PFX/logs/p.log info; pid $PFX/p.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${PORT}; xrootd on; xrootd_auth none; xrootd_storage_backend posix://$PFX/data; } }
EOF
if [ -x "$XRDCP" ]; then
    "$NGINX" -p "$PFX" -c "$PFX/p.conf" 2>"$PFX/p.err" || { bad "posix:// node start"; cat "$PFX/p.err"; }
    sleep 1
    "$XRDCP" "root://127.0.0.1:${PORT}//blob.bin" "$PFX/got.bin" -f >"$PFX/cp.err" 2>&1 \
        && cmp -s "$PFX/data/blob.bin" "$PFX/got.bin" && ok "posix:// GET byte-exact (no xrootd_root)" \
        || { bad "posix:// GET"; tail -4 "$PFX/cp.err"; tail -6 "$PFX/logs/p.log"; }
    [ -f "$PFX/p.pid" ] && kill "$(cat "$PFX/p.pid")" 2>/dev/null; sleep 1
else
    echo "  SKIP posix:// data plane (native xrdcp not built)"
fi

# ---- data plane: frm:// alias faults a recall through sd_frm + sd_cache ----
echo "== data plane: frm:// (tape alias) offline → recall → byte-exact =="
if [ -x "$XRDFS" ]; then
    mkdir -p "$PFX/tape" "$PFX/fcache" "$PFX/fexport" "$PFX/flogs"
    cat > "$PFX/f.conf" <<EOF
daemon on; error_log $PFX/flogs/e.log info; pid $PFX/f.pid;
env XROOTD_FRM_STUB_RECALL_DELAY_MS=800;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${PORT}; xrootd on; xrootd_root $PFX/fexport; xrootd_auth none;
    xrootd_storage_backend frm://stub${PFX}/tape;
    xrootd_cache_store posix:${PFX}/fcache; } }
EOF
    head -c 400000 /dev/urandom > "$PFX/tape/f.bin"; SHA=$(sha256sum "$PFX/tape/f.bin"|cut -d' ' -f1)
    "$NGINX" -p "$PFX" -c "$PFX/f.conf" 2>"$PFX/f.err" || { bad "frm:// node start"; cat "$PFX/f.err"; cat "$PFX/flogs/e.log"; }
    sleep 1
    "$XRDFS" "root://127.0.0.1:${PORT}" stat /f.bin 2>/dev/null | grep -q "Offline" \
        && ok "frm:// nearline object reports Offline" || bad "frm:// stat not Offline"
    "$XRDFS" "root://127.0.0.1:${PORT}" cat /f.bin > "$PFX/f.got" 2>"$PFX/fcat.err"
    [ "$(sha256sum "$PFX/f.got" 2>/dev/null|cut -d' ' -f1)" = "$SHA" ] \
        && ok "frm:// cat byte-exact (recall via sd_frm+sd_cache)" \
        || { bad "frm:// cat"; cat "$PFX/fcat.err"; grep -iE "frm|tape|recall|error" "$PFX/flogs/e.log"|grep -v access_json|tail -6; }
    [ -f "$PFX/f.pid" ] && kill "$(cat "$PFX/f.pid")" 2>/dev/null
else
    echo "  SKIP frm:// data plane (native xrdfs not built)"
fi

[ "$fail" = 0 ] && echo "run_storage_backend_schemes: ALL PASS" || echo "run_storage_backend_schemes: FAILURES"
exit "$fail"
