#!/usr/bin/env bash
#
# run_csi_trust.sh — xrootd_csi_trust_fs end-to-end: on a self-checksumming
# filesystem the flag skips CSI read-verify (stale tags no longer fail reads)
# while the write side keeps tagging and the pgwrite wire-CRC check stays on.
# Stands up one stream-only nginx with four server blocks on a shared export:
# verify (csi on), trust (csi+trust_fs), require+trust, require-only.
#
# Usage: tests/run_csi_trust.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDCP="$HERE/client/bin/xrdcp"
P_VER=11498   # csi on, trust off  (default verify behavior)
P_TRU=11499   # csi on, trust_fs on
P_RQT=11500   # csi + require + trust_fs (untagged read must pass)
P_RQO=11501   # csi + require only       (untagged read must be refused)
P_DEF=11502   # no csi directives: CSI must be ON by default
P_OFF=11503   # xrootd_csi off: opt-out must not tag
PFX="$(mktemp -d /tmp/csi_trust.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
chk() { [ "$2" = "$3" ] && ok "$1 ($2)" || bad "$1: got '$2' want '$3'"; }

mkdir -p "$PFX/root" "$PFX/logs"
srv() { cat <<EOF
    server {
        listen 127.0.0.1:${1};
        xrootd on;
        xrootd_root $PFX/root;
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_upload_resume off;
        ${2}
        xrootd_access_log $PFX/logs/access_${1}.log;
    }
EOF
}
{
    echo "daemon on;"
    echo "error_log $PFX/logs/error.log info;"
    echo "pid $PFX/nginx.pid;"
    echo "events { worker_connections 64; }"
    echo "stream {"
    srv "$P_VER" "xrootd_csi on;"
    srv "$P_TRU" "xrootd_csi on; xrootd_csi_trust_fs on;"
    srv "$P_RQT" "xrootd_csi on; xrootd_csi_require on; xrootd_csi_trust_fs on;"
    srv "$P_RQO" "xrootd_csi on; xrootd_csi_require on;"
    srv "$P_DEF" ""
    srv "$P_OFF" "xrootd_csi off;"
    echo "}"
} > "$PFX/nginx.conf"

cleanup() { [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX" /tmp/csitrust_*.bin; }
trap cleanup EXIT

"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/logs/start.err" || { echo "nginx failed to start"; cat "$PFX/logs/start.err"; exit 2; }
sleep 1

cp_up()   { "$XRDCP" -f "$2" "root://127.0.0.1:${1}//$3" >/dev/null 2>&1 && echo 0 || echo $?; }
cp_down() { "$XRDCP" -f "root://127.0.0.1:${1}//$2" "$3" >/dev/null 2>&1 && echo 0 || echo $?; }

echo "== trusted write still tags =="
head -c 12288 /dev/urandom > /tmp/csitrust_src.bin              # 3 full CSI pages
chk "PUT via trust_fs server"       "$(cp_up "$P_TRU" /tmp/csitrust_src.bin f.bin)" 0
getfattr -n user.xrd.cinfo "$PFX/root/f.bin" >/dev/null 2>&1 \
  && ok "xmeta record (user.xrd.cinfo) created at close" || bad "no xmeta record on f.bin"
[ ! -e "$PFX/root/.xrdt" ] && ok "no .xrdt tag tree (retired)" || bad ".xrdt tree still created"
chk "GET via verify server passes"  "$(cp_down "$P_VER" f.bin /tmp/csitrust_v.bin)" 0
cmp -s /tmp/csitrust_src.bin /tmp/csitrust_v.bin && ok "verify GET byte-exact" || bad "verify GET differs"

echo "== stale tags: verify fails, trust serves =="
python3 -c "
p='$PFX/root/f.bin'
b=bytearray(open(p,'rb').read()); b[5000]^=0xFF                 # flip a byte in page 1
open(p,'wb').write(bytes(b))"
GOT=$(cp_down "$P_VER" f.bin /tmp/csitrust_c.bin)
[ "$GOT" != 0 ] && ok "verify server rejects corrupt page (rc=$GOT)" || bad "verify server served corrupt bytes"
chk "trust server serves it"        "$(cp_down "$P_TRU" f.bin /tmp/csitrust_t.bin)" 0
cmp -s "$PFX/root/f.bin" /tmp/csitrust_t.bin && ok "trust GET matches on-disk bytes" || bad "trust GET differs from disk"

echo "== csi_require vs trust_fs on an untagged file =="
head -c 8192 /dev/urandom > "$PFX/root/untagged.bin"
chk "require+trust reads untagged"  "$(cp_down "$P_RQT" untagged.bin /tmp/csitrust_u.bin)" 0
GOT=$(cp_down "$P_RQO" untagged.bin /tmp/csitrust_u2.bin)
[ "$GOT" != 0 ] && ok "require-only refuses untagged (rc=$GOT)" || bad "require-only served an untagged file"

echo "== default on / explicit off =="
chk "PUT via default server"        "$(cp_up "$P_DEF" /tmp/csitrust_src.bin defon.bin)" 0
getfattr -n user.xrd.cinfo "$PFX/root/defon.bin" >/dev/null 2>&1 \
  && ok "CSI records by default" || bad "default server did not record"
chk "PUT via csi-off server"        "$(cp_up "$P_OFF" /tmp/csitrust_src.bin defoff.bin)" 0
getfattr -n user.xrd.cinfo "$PFX/root/defoff.bin" >/dev/null 2>&1 \
  && bad "csi-off server recorded anyway" || ok "xrootd_csi off opts out"

echo "== security-neg: bad pgwrite wire-CRC still rejected under trust_fs =="
PYTHONPATH="$HERE/tests" python3 - "$P_TRU" <<'EOF'
import struct, sys
from test_pgwrite_checksum import (_handshake_login, _open_for_write,
    _build_pgwrite_payload, _send_pgwrite, _read_response, _recv_exact,
    kXR_status, kXR_error, kXR_close, kXR_ChkSumErr)

port = int(sys.argv[1])
sock = _handshake_login("127.0.0.1", port)
try:
    fh = _open_for_write(sock, b"/_trust_badcrc.bin")
    payload = _build_pgwrite_payload(b"trust does not cover the wire " * 10,
                                     offset=0, corrupt_page=0)
    status, sbody = _send_pgwrite(sock, fh, 0, payload)
    assert status == kXR_status, f"bad page must be CSE-reported, got {status}"
    cse_len = struct.unpack("!i", sbody[12:16])[0]
    if cse_len > 0:
        _recv_exact(sock, cse_len)
    sock.sendall(struct.pack("!2sH4s12sI", b"\x00\x09", kXR_close, fh,
                             b"\x00" * 12, 0))
    cstatus, cbody = _read_response(sock)
    assert cstatus == kXR_error, "close must stay gated on uncorrected pages"
    assert struct.unpack("!I", cbody[:4])[0] == kXR_ChkSumErr
finally:
    sock.close()
print("pgwrite-bad-crc-gated")
EOF
[ $? = 0 ] && ok "pgwrite wire-CRC verify + close gate intact" || bad "pgwrite wire-CRC path regressed under trust_fs"

[ "$fail" = 0 ] && echo "run_csi_trust: ALL PASS" || echo "run_csi_trust: FAILURES"
exit "$fail"
