#!/usr/bin/env bash
# Terminating tap proxy: client authenticates to the proxy (anon), the proxy
# re-logs-in to the origin and forwards opcodes; passthrough is byte-exact and
# the tap logs the forwarded opcodes (open/read) to error.log.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"
OP=11960; PP=11961
PFX="$(mktemp -d /tmp/tapproxy.XXXXXX)"
fail=0
ok(){ printf '  ok   %s\n' "$1"; }
bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o n; do [ -f "$PFX/$r/pid" ] && kill "$(cat "$PFX/$r/pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/tapproxy_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/n/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OP}; xrootd on; xrootd_root $PFX/o/root; xrootd_auth none;
                  xrootd_allow_write on; xrootd_upload_resume off; } }
EOF
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${PP}; xrootd on; xrootd_auth none;
    xrootd_allow_write on;
    xrootd_tap_proxy on;
    xrootd_tap_proxy_upstream 127.0.0.1:${OP};
    xrootd_tap_proxy_auth anonymous;
} }
EOF

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo origin-fail; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo proxy-fail; cat "$PFX/n/err"; exit 2; }
sleep 1
head -c 400000 /dev/urandom > "$PFX/o/root/f.bin"

"$XRDFS" root://127.0.0.1:${PP} cat /f.bin > /tmp/tapproxy_a.got 2>/dev/null
cmp -s "$PFX/o/root/f.bin" /tmp/tapproxy_a.got && ok "terminating proxy passthrough byte-exact" || bad "passthrough mismatch"
"$XRDFS" root://127.0.0.1:${PP} stat /f.bin >/dev/null 2>&1 && ok "stat via tap proxy" || bad "stat failed"

# ckpXeq through the proxy: stock framing (chkpoint dlen = 24, embedded write
# sub-header carries the outer streamid, data streamed after the frame).  The
# proxy must forward the trailing sub-body verbatim AND translate the file
# handle in BOTH the outer chkpoint body and the embedded sub-header
# (forward_request.c), or the upstream rejects the handle / desyncs.
python3 - "$PP" "$PFX/o/root/ckp.bin" <<'PYEOF'
import socket, struct, sys
port, origin_file = int(sys.argv[1]), sys.argv[2]

def recvall(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        assert c, "connection closed"
        b += c
    return b

def resp(s):
    h = recvall(s, 8)
    st = struct.unpack(">H", h[2:4])[0]
    dl = struct.unpack(">I", h[4:8])[0]
    return st, (recvall(s, dl) if dl else b"")

s = socket.socket(); s.settimeout(10); s.connect(("127.0.0.1", port))
s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
recvall(s, 16)
s.sendall(b"\x00\x01" + struct.pack(">H", 3006) + b"\x00"*16 + struct.pack(">I", 0))
assert resp(s)[0] == 0
s.sendall(b"\x00\x01" + struct.pack(">H", 3007) + b"\x00"*16
          + struct.pack(">I", 10) + b"anonymous\x00")
assert resp(s)[0] == 0, "login via proxy failed"

path = b"/ckp.bin\x00"
req = b"\x00\x02" + struct.pack(">HHH", 3010, 0o644, 0x0020 | 0x0008 | 0x0002) \
    + b"\x00"*12 + struct.pack(">I", len(path))
s.sendall(req + path)
st, body = resp(s)
assert st == 0, f"open via proxy failed: {st} {body!r}"
fh = body[:4]

def chkpoint(sid, opcode, dlen=0):
    return sid + struct.pack(">H", 3012) + fh + b"\x00"*11 \
        + bytes([opcode]) + struct.pack(">I", dlen)

s.sendall(chkpoint(b"\x00\x03", 0))                       # ckpBegin
assert resp(s)[0] == 0, "ckpBegin via proxy failed"

data = b"PROXIED-CKPXEQ"
sub = b"\x00\x04" + struct.pack(">H", 3019) + fh + struct.pack(">q", 0) \
    + b"\x00"*4 + struct.pack(">I", len(data))
s.sendall(chkpoint(b"\x00\x04", 4, 24) + sub)             # ckpXeq, dlen=24
s.sendall(data)                                           # streamed sub-body
st, _ = resp(s)
assert st == 0, f"ckpXeq write via proxy failed: {st}"

s.sendall(chkpoint(b"\x00\x05", 1))                       # ckpCommit
assert resp(s)[0] == 0, "ckpCommit via proxy failed"

# alignment: ping then close must still work on the same connection
s.sendall(b"\x00\x06" + struct.pack(">H", 3011) + b"\x00"*16 + struct.pack(">I", 0))
assert resp(s)[0] == 0, "connection desynced after ckpXeq via proxy"
s.sendall(b"\x00\x07" + struct.pack(">H", 3003) + fh + b"\x00"*12 + struct.pack(">I", 0))
assert resp(s)[0] == 0

with open(origin_file, "rb") as f:
    assert f.read() == data, "ckpXeq bytes did not land at the origin"
PYEOF
[ $? -eq 0 ] && ok "ckpXeq stock framing via tap proxy (embedded fh + streamed sub-body)" \
             || bad "ckpXeq via tap proxy failed"

sleep 0.5
grep -q '"op":"open"' "$PFX/n/logs/e.log" && ok "tap logged open" || bad "tap did not log open"
grep -q '"dir":"u2c"' "$PFX/n/logs/e.log" && ok "tap logged a response" || bad "tap did not log response"
exit $fail
