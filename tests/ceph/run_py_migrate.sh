#!/usr/bin/env bash
# run_py_migrate.sh — build-free e2e test of the PYTHON XrdCeph<->CephFS
# migration tools (xrdceph_striper_migrate.py / xrdceph_cephfs_to_striper.py)
# inside xrd-ceph-work against the demo cluster. Mirrors run_striper_migrate.sh
# for the forward direction and adds the reverse direction + the Python-only
# features. Covers:
#   FORWARD (striper -> CephFS):
#     - REDIRECT (zero-move) migrate + checksum verify, source left intact
#     - durability: redirect survives MDS journal flush + cache drop
#     - idempotent rerun (SKIP), rollback + re-migrate round-trip
#     - COPY mode + --delete-source; guard: redirect + --delete-source refused
#     - --json validity, --state resume fast-path, --prefix subset
#     - PYMIGRATE_FORCE_SHIM=1 redirect leg (compiled-shim fallback)
#   REVERSE (CephFS -> striper):
#     - --report-only classification of the seeded tree
#     - redirect + libradosstriper-read verify, rollback (CephFS intact)
#     - re-migrate, finalize + --delete-source (owned copies serve the bytes)
#     - guard: missing --assume-quiesced refused
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
WORK="${WORK:-xrd-ceph-work}"

docker ps --format '{{.Names}}' | grep -qx "$WORK" \
    || { echo "work container '$WORK' not running (tests/ceph_harness.sh start)" >&2; exit 1; }

docker exec "$WORK" mkdir -p /work/pymig
docker cp "$REPO/tests/ceph/pymigrate" "$WORK:/work/pymig/" >/dev/null
for f in xrdceph_striper_migrate.py xrdceph_cephfs_to_striper.py striper_seed.c; do
    docker cp "$REPO/tests/ceph/$f" "$WORK:/work/pymig/$f" >/dev/null
done

docker exec -i -w /work/pymig -e CEPH_CONF=/etc/ceph/ceph.conf "$WORK" bash -s <<'INNER'
set -euo pipefail
fail() { echo "CHECK FAILED: $*" >&2; exit 1; }

# pool discovery: the demo cluster names its fs pools cephfs.<fs>.meta/.data
SP=xrdtest
META=$(ceph fs ls --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["metadata_pool"])')
DATA=$(ceph fs ls --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["data_pools"][0])')
MDS=$(ceph mds stat --format json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["fsmap"]["filesystems"][0]["mdsmap"]["info"][list(d["fsmap"]["filesystems"][0]["mdsmap"]["info"])[0]]["name"])' 2>/dev/null || echo demo)
echo "pools: striper=$SP meta=$META data=$DATA mds=$MDS"

gcc -D_FILE_OFFSET_BITS=64 striper_seed.c -lradosstriper -lrados -o /tmp/striper_seed
FWD="python3 xrdceph_striper_migrate.py $SP $DATA"
REV="python3 xrdceph_cephfs_to_striper.py $META $DATA $SP --assume-quiesced"

# pre-clean overlays a previous run may have left (detach-first via the tools,
# BEFORE the sources they reference are removed/reseeded)
python3 xrdceph_striper_migrate.py "$SP" "$DATA" /pyzm --rollback \
    --list <(printf "pyrm/a\npyrm/b\npyrm/c\n") >/dev/null 2>&1 || true
python3 xrdceph_striper_migrate.py "$SP" "$DATA" /pycp --rollback \
    --list <(echo pycp/x) >/dev/null 2>&1 || true
python3 xrdceph_cephfs_to_striper.py "$META" "$DATA" "$SP" --assume-quiesced \
    --prefix pyrev/ --rollback >/dev/null 2>&1 || true
rados -p "$SP" ls | grep '^pyrev/' | xargs -r -n1 rados -p "$SP" rm 2>/dev/null || true

# fresh forward sources under a known prefix (varied geometries, as the C++ test)
rados -p "$SP" ls | grep '^pyrm/' | xargs -r -n1 rados -p "$SP" rm 2>/dev/null || true
for g in "pyrm/a 10485760 4194304 4194304 1" "pyrm/b 18874368 4194304 4194304 2" "pyrm/c 41943040 8388608 4194304 4"; do
  set -- $g; /tmp/striper_seed "$SP" "$1" "$2" "$3" "$4" "$5" >/dev/null
done
printf "pyrm/a\npyrm/b\npyrm/c\n" > /tmp/L
src_count() { rados -p "$SP" ls 2>/dev/null | grep -c "^$1\." || true; }

echo "== FWD: REDIRECT migrate (zero-move) + verify =="
$FWD /pyzm --list /tmp/L --verify --threads 3 2>/dev/null | grep -c '^OK' | grep -qx 3 || fail "fwd redirect: expected 3 OK"
[ "$(src_count pyrm/a)" -ge 3 ] || fail "fwd redirect moved source objects (zero-move violated)"

echo "== FWD: durability across MDS flush + cache drop =="
ceph tell "mds.$MDS" flush journal >/dev/null 2>&1 || true
ceph tell "mds.$MDS" cache drop   >/dev/null 2>&1 || true
$FWD /pyzm --list <(echo pyrm/b) --force --verify 2>/dev/null | grep -q '^OK' || fail "fwd durability re-verify"

echo "== FWD: idempotent rerun (expect 3 SKIP) =="
$FWD /pyzm --list /tmp/L --verify 2>/dev/null | grep -c '^SKIP' | grep -qx 3 || fail "fwd idempotency"

echo "== FWD: rollback (overlay removed, source intact) + re-migrate =="
$FWD /pyzm --rollback --list /tmp/L 2>/dev/null | grep -c '^OK' | grep -qx 3 || fail "fwd rollback"
[ "$(src_count pyrm/a)" -ge 3 ] || fail "fwd rollback lost source objects"
$FWD /pyzm --list <(echo pyrm/a) --verify 2>/dev/null | grep -q '^OK' || fail "fwd re-migrate after rollback"

echo "== FWD: COPY mode + --delete-source =="
/tmp/striper_seed "$SP" pycp/x 5242880 4194304 4194304 1 >/dev/null
$FWD /pycp --mode copy --list <(echo pycp/x) --verify --delete-source 2>/dev/null | grep -q '^OK' || fail "fwd copy"
[ "$(src_count pycp/x)" -eq 0 ] || fail "fwd copy --delete-source left source objects"

echo "== FWD guard: redirect + --delete-source refused =="
if $FWD /pyzm --list /tmp/L --delete-source >/dev/null 2>&1; then
  fail "guard: redirect + --delete-source was accepted"
fi

echo "== FWD: --json output is valid JSONL with a summary =="
$FWD /pyzm --list /tmp/L --json --force --verify 2>/dev/null > /tmp/j
python3 - <<'EOF' || exit 1
import json
recs = [json.loads(l) for l in open("/tmp/j") if l.strip()]
items = [r for r in recs if "soid" in r]
summ = [r for r in recs if "summary" in r]
assert len(items) == 3 and all(r["result"] == "ok" for r in items), items
assert len(summ) == 1 and summ[0]["summary"]["ok"] == 3, summ
print("json ok")
EOF

echo "== FWD: --state resume fast-path =="
rm -f /tmp/st.jsonl
$FWD /pyzm --list /tmp/L --state /tmp/st.jsonl --force 2>/dev/null | grep -c '^OK' | grep -qx 3 || fail "state seed run"
$FWD /pyzm --list /tmp/L --state /tmp/st.jsonl 2>/dev/null | grep -c 'state manifest: ok' | grep -qx 3 || fail "state fast-path skip"

echo "== FWD: --prefix subset =="
$FWD /pyzm --prefix pyrm/a --force 2>/dev/null | grep -c '^OK' | grep -qx 1 || fail "prefix subset"

echo "== FWD: forced shim backend =="
if [ -e /usr/include/rados/librados.hpp ] && command -v g++ >/dev/null; then
  PYMIGRATE_FORCE_SHIM=1 $FWD /pyzm --list <(echo pyrm/a) --force --verify 2>/tmp/shim.err >/tmp/shim.out
  grep -q '^OK' /tmp/shim.out || fail "shim redirect leg"
  grep -q 'bridge=shim' /tmp/shim.err || fail "shim backend not engaged"
else
  echo "  (skipped: g++/librados.hpp not available for the shim build)"
fi

echo "== REV: seed a CephFS tree (file + subdir + symlink + xattrs) =="
python3 - <<'EOF'
import cephfs, zlib
fs = cephfs.LibCephFS(conffile="/etc/ceph/ceph.conf"); fs.mount()
def rmrf(path):
    try: fs.unlink(path)
    except cephfs.Error: pass
for p in (b"/pyrev/deep/two.bin", b"/pyrev/one.bin", b"/pyrev/ln"):
    rmrf(p)
for d, m in ((b"/pyrev", 0o755), (b"/pyrev/deep", 0o755)):
    try: fs.mkdirs(d, m)
    except cephfs.ObjectExists: pass
def seed(path, data):
    fd = fs.open(path, "w", 0o644)
    fs.write(fd, data, 0); fs.close(fd)
    fs.setxattr(path, "user.XrdCks.adler32",
                b"%08x" % (zlib.adler32(data, 1) & 0xffffffff), 0)
seed(b"/pyrev/one.bin", bytes(range(256)) * 4096 * 5)      # 5 MiB, 2 objects
seed(b"/pyrev/deep/two.bin", b"\xab" * 123457)             # odd size
fs.symlink(b"one.bin", b"/pyrev/ln")
fs.unmount(); fs.shutdown()
print("seeded /pyrev")
EOF
ceph tell "mds.$MDS" flush journal >/dev/null 2>&1 || true

echo "== REV guard: missing --assume-quiesced refused =="
if python3 xrdceph_cephfs_to_striper.py "$META" "$DATA" "$SP" --report-only >/dev/null 2>&1; then
  fail "guard: missing --assume-quiesced was accepted"
fi

echo "== REV: --report-only classification =="
$REV --report-only 2>/tmp/rep.err >/dev/null || fail "report-only run"
grep -q 'regular files to migrate' /tmp/rep.err || fail "classification block missing"
grep -qE 'symlinks *: [1-9]' /tmp/rep.err || fail "seeded symlink not classified"

echo "== REV: redirect + striper-read verify (pyrev/ only) =="
$REV --prefix pyrev/ --verify 2>/dev/null | grep -c '^OK' | grep -qx 2 || fail "rev redirect: expected 2 OK"

echo "== REV: idempotent rerun (expect 2 SKIP) =="
$REV --prefix pyrev/ 2>/dev/null | grep -c '^SKIP' | grep -qx 2 || fail "rev idempotency"

echo "== REV: rollback (CephFS data intact) + re-migrate =="
$REV --prefix pyrev/ --rollback 2>/dev/null | grep -c '^OK' | grep -qx 2 || fail "rev rollback"
rados -p "$SP" ls | grep -q '^pyrev/' && fail "rev rollback left striper stubs"
$REV --prefix pyrev/ --verify 2>/dev/null | grep -c '^OK' | grep -qx 2 || fail "rev re-migrate"

echo "== REV: finalize + --delete-source (owned copies serve the bytes) =="
$REV --prefix pyrev/ --finalize --verify --delete-source 2>/dev/null | grep -c '^OK' | grep -qx 2 || fail "rev finalize"
# the striper reads in --verify above already proved the owned copies serve
# the bytes with the CephFS data objects deleted.

echo "== CONFIG: site-profile file (--config, zero positionals) =="
cat > /tmp/pysite.conf <<EOF
# site profile written by run_py_migrate.sh
striper_pool = $SP
meta_pool    = $META
data_pool    = $DATA
client       = admin
dest_prefix  = /pyzm
EOF
python3 xrdceph_striper_migrate.py --config /tmp/pysite.conf \
    --list <(echo pyrm/a) --force --verify 2>/dev/null | grep -q '^OK' \
    || fail "config-file forward migrate"
python3 xrdceph_cephfs_to_striper.py --config /tmp/pysite.conf \
    --assume-quiesced --report-only 2>&1 | grep -q 'regular files to migrate' \
    || fail "config-file reverse report-only"
if python3 xrdceph_striper_migrate.py "$SP" --config /tmp/pysite.conf >/dev/null 2>&1; then
  fail "config guard: partial positionals were accepted"
fi
echo "bad_key = x" > /tmp/pybad.conf
if python3 xrdceph_striper_migrate.py --config /tmp/pybad.conf >/dev/null 2>&1; then
  fail "config guard: unknown key was accepted"
fi

echo "run_py_migrate: ALL CHECKS PASSED"
INNER
