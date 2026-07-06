#!/usr/bin/env bash
# tests/run_scvmfs.sh — EXPERIMENTAL scvmfs:// secure protocol:
#   1 TLS parity: GET over https serves byte-exact (same core as cvmfs://)
#   2 transport-neg: plain HTTP to the TLS listener → 400, never served
#   3 authz-neg (bearer): missing token → 401; garbage token → 401
#   4 layering: brix_scvmfs without brix_cvmfs → nginx -t error
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MPORT=12901; SPORT=12902
PFX="$(mktemp -d /tmp/scvmfs.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

# throwaway TLS identity for the listener
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
    -keyout "$PFX/key.pem" -out "$PFX/crt.pem" 2>/dev/null

# minimal issuer registry for the bearer negatives: one REAL (freshly
# generated) RSA key that simply never signed our test tokens — the loader
# demands a usable key set, and every presented token fails validation
openssl genrsa -out "$PFX/reg.pem" 2048 2>/dev/null
MOD="$(openssl rsa -in "$PFX/reg.pem" -noout -modulus | cut -d= -f2)"
python3 - "$MOD" > "$PFX/jwks.json" <<'PYEOF'
import base64, json, sys
n = base64.urlsafe_b64encode(bytes.fromhex(sys.argv[1])).rstrip(b"=").decode()
print(json.dumps({"keys": [{"kty": "RSA", "kid": "t1", "alg": "RS256",
                            "use": "sig", "n": n, "e": "AQAB"}]}))
PYEOF
cat > "$PFX/scitokens.cfg" <<EOF
[Global]
audience = https://wlcg.cern.ch/jwt/v1/any

[Issuer test]
issuer = https://tokens.example
base_path = /cvmfs
jwks_file = $PFX/jwks.json
EOF

python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 4 --seed 55 &
MOCK=$!; sleep 0.5
OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[0])')"

mkconf() {  # $1 = authz mode, $2 = extra location lines
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$SPORT ssl;
    ssl_certificate     $PFX/crt.pem;
    ssl_certificate_key $PFX/key.pem;
    location /cvmfs/ {
        brix_storage_backend http://127.0.0.1:$MPORT;
        brix_cache_store posix:$PFX/cache;
        brix_cvmfs on;
        brix_scvmfs on;
        brix_scvmfs_authz $1;
$2
    }
} }
EOF
}

# 1: TLS parity (authz none)
mkconf none ""
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.3
curl -sk "https://127.0.0.1:$SPORT$OBJ" -o "$PFX/tls.bin"
curl -s  "http://127.0.0.1:$MPORT$OBJ" -o "$PFX/ref.bin"
cmp -s "$PFX/tls.bin" "$PFX/ref.bin" && ok "scvmfs TLS parity byte-exact" \
    || bad "TLS parity"

# 2: plain HTTP to the TLS port is refused, not served
C="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$SPORT$OBJ")"
[ "$C" = 400 ] && ok "plain HTTP on scvmfs listener refused" || bad "plain: $C"

# 3: bearer authz-negs
kill "$(cat "$PFX/nginx.pid")"; sleep 0.2
mkconf bearer "        brix_scvmfs_token_issuers $PFX/scitokens.cfg;"
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.3
C1="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$SPORT$OBJ")"
C2="$(curl -sk -o /dev/null -w '%{http_code}' \
      -H 'Authorization: Bearer not.a.token' "https://127.0.0.1:$SPORT$OBJ")"
[ "$C1" = 401 ] && [ "$C2" = 401 ] && ok "bearer: missing/garbage token → 401" \
    || bad "bearer negs: $C1/$C2"
# positive bearer acceptance: exercised via the repo's existing token
# fixtures (same infrastructure as the WebDAV auth tests) — added as a
# pytest alongside when the fleet PKI is up, not in this script.

# 4: layering enforced at config time
cat > "$PFX/bad.conf" <<EOF
events { worker_connections 32; }
http { server { listen 127.0.0.1:$SPORT ssl;
    ssl_certificate $PFX/crt.pem; ssl_certificate_key $PFX/key.pem;
    location / { brix_scvmfs on; } } }
EOF
"$NGINX" -t -c "$PFX/bad.conf" -p "$PFX" 2>/dev/null \
    && bad "scvmfs without cvmfs accepted" || ok "scvmfs requires cvmfs (nginx -t)"
exit $fail
