#!/usr/bin/env bash
# tests/cvmfs/spike_cas_hash.sh — determine the CVMFS CAS hashing convention
# empirically against a real Stratum-1. Downloads the manifest, extracts the
# root catalog hash, fetches the object, and hashes it (raw and inflated).
set -eu
S1="${1:-http://cvmfs-stratum-one.cern.ch/cvmfs/cvmfs-config.cern.ch}"
M="$(curl -sf "$S1/.cvmfspublished")"
ROOT="$(printf '%s' "$M" | sed -n 's/^C//p' | head -1)"
echo "repo manifest root catalog: $ROOT"
URL="$S1/data/${ROOT:0:2}/${ROOT:2}C"
curl -sf "$URL" -o /tmp/spike_obj.raw
RAW="$(sha1sum /tmp/spike_obj.raw | cut -d' ' -f1)"
python3 - <<'EOF'
import zlib, hashlib
raw = open("/tmp/spike_obj.raw","rb").read()
try:
    print("inflated sha1:", hashlib.sha1(zlib.decompress(raw)).hexdigest())
except Exception as e:
    print("inflate failed:", e)
EOF
echo "raw sha1:      $RAW"
echo "expected:      $ROOT"
echo "VERDICT: whichever line matches 'expected' is the hashing convention."
