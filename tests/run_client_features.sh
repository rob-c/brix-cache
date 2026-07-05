#!/usr/bin/env bash
# run_client_features.sh — e2e checks for the 2026-07-05 client feature set.
# Local-only sections always run; fleet sections auto-skip when no server on
# ${XRD_TEST_URL:-root://localhost:11094} answers.
#
# Routing note: brix_copy -r requires one remote + one local endpoint; local→local
# recursive is explicitly rejected ("unsupported copy direction").  Dry-run on a
# single non-recursive file works local→local because transfer_one short-circuits
# before calling brix_copy.  All recursive filter tests are therefore fleet-gated.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/client/bin"
URL="${XRD_TEST_URL:-root://localhost:11094}"
WORK="$(mktemp -d /tmp/client-features.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
have_fleet() { "$BIN/wait41" "$URL" 2>/dev/null >/dev/null; }

section_dryrun_filters() {
  echo "== dry-run (local) =="
  mkdir -p "$WORK/src/sub" "$WORK/dst"
  echo A >"$WORK/src/a.root"; echo B >"$WORK/src/b.log"; echo C >"$WORK/src/sub/c.root"

  # dry-run single file: transfer_one prints and returns 0 without calling brix_copy,
  # so local→local is fine and no destination file is created.
  "$BIN/xrdcp" --dry-run "$WORK/src/a.root" "$WORK/dst/a.root" >/dev/null
  check "dry-run leaves dst absent" '[ ! -e "$WORK/dst/a.root" ]'

  # recursive filter tests: local→local recursive is unsupported by brix_copy;
  # use a remote endpoint as one side.
  echo "== recursive filters (fleet) =="
  if ! have_fleet; then
    echo "  SKIP recursive filter tests (no fleet at $URL)"
    return
  fi

  # Upload the src tree to a remote scratch path (no filter — seed the full tree).
  RSRC="${URL}//tmp/cfeat-$$-src"
  "$BIN/xrdcp" -r -s -f "$WORK/src/" "$RSRC/" 2>/dev/null

  # exclude *.log: only .root files should arrive locally.
  mkdir -p "$WORK/dst_excl"
  "$BIN/xrdcp" -r -s --exclude '*.log' "$RSRC/" "$WORK/dst_excl" 2>/dev/null
  check "exclude: .root copied"  '[ -e "$WORK/dst_excl/a.root" ] && [ -e "$WORK/dst_excl/sub/c.root" ]'
  check "exclude: .log filtered" '[ ! -e "$WORK/dst_excl/b.log" ]'

  # include whitelist: only *.log should arrive.
  mkdir -p "$WORK/dst_incl"
  "$BIN/xrdcp" -r -s --include '*.log' "$RSRC/" "$WORK/dst_incl" 2>/dev/null
  check "include: only .log copied" '[ -e "$WORK/dst_incl/b.log" ] && [ ! -e "$WORK/dst_incl/a.root" ]'

  # security: exclude beats include — a.* excluded even though * is included.
  mkdir -p "$WORK/dst_both"
  "$BIN/xrdcp" -r -s --include '*' --exclude 'a.*' "$RSRC/" "$WORK/dst_both" 2>/dev/null
  check "exclude beats include" '[ ! -e "$WORK/dst_both/a.root" ] && [ -e "$WORK/dst_both/b.log" ]'

  # dry-run upload (root://) — must not create the remote directory.
  # The tree is local→root://, so copy_tree_upload is called via brix_copy; its
  # brix_mkdir is already guarded by !dry_run in copy_recursive.c. Verify that
  # no directory is left on the server after a dry-run walk.
  DRYUP_RPATH="/tmp/cfeat-$$-dryup"
  "$BIN/xrdcp" -r -s --dry-run "$WORK/src/" "${URL}//${DRYUP_RPATH}/" 2>/dev/null
  check "dry-run upload: remote dir not created" \
    '! "$BIN/xrdfs" "$URL" stat "$DRYUP_RPATH" >/dev/null 2>&1'
}

section_sync_modes() {
  echo "== sync modes (local) =="
  local S="$WORK/sync"
  mkdir -p "$S"
  # Same size, DIFFERENT content: the size gate alone cannot tell them apart.
  printf 'AAAA\n' >"$S/src"
  printf 'BBBB\n' >"$S/stale"

  # --sync (size mode): same size => skipped (transfer_one returns before
  # brix_copy, so local->local is fine and the stale bytes stay untouched).
  "$BIN/xrdcp" --sync "$S/src" "$S/stale" >/dev/null 2>&1
  check "--sync (size): same-size stale dst skipped" \
    '[ "$(cat "$S/stale")" = "BBBB" ]'

  # --sync-check cksum: content differs => the copy gate must OPEN. Local->local
  # can't actually copy, so observe the gate via --dry-run's "[dry-run] copy".
  check "--sync-check cksum: stale dst recopied (gate opens)" \
    '"$BIN/xrdcp" --sync-check cksum --dry-run "$S/src" "$S/stale" | grep -q "\[dry-run\] copy"'

  # --sync-check cksum on identical content => skipped (no dry-run line).
  cp "$S/src" "$S/same"
  check "--sync-check cksum: identical dst skipped" \
    '! "$BIN/xrdcp" --sync-check cksum --dry-run "$S/src" "$S/same" | grep -q "\[dry-run\] copy"'

  # --sync-check mtime: same size but src NEWER than dst => recopy.
  touch -d '2020-01-01 00:00:00' "$S/stale"
  check "--sync-check mtime: newer src recopied" \
    '"$BIN/xrdcp" --sync-check mtime --dry-run "$S/src" "$S/stale" | grep -q "\[dry-run\] copy"'

  # --sync-check mtime: dst newer than (or same age as) src => skipped.
  touch -d '2030-01-01 00:00:00' "$S/stale"
  check "--sync-check mtime: newer dst skipped" \
    '! "$BIN/xrdcp" --sync-check mtime --dry-run "$S/src" "$S/stale" | grep -q "\[dry-run\] copy"'

  # error case: a bogus comparison mode is a usage error (exit 50).
  "$BIN/xrdcp" --sync-check bogus "$S/src" "$S/stale" >/dev/null 2>&1
  check "--sync-check bogus exits 50" '[ "$?" -eq 50 ]'

  echo "== sync modes (fleet) =="
  if ! have_fleet; then
    echo "  SKIP fleet sync tests (no fleet at $URL)"
    return
  fi

  # Seed a remote file, then make a same-size different-content local copy.
  local RS="/tmp/cfeat-$$-sync"
  "$BIN/xrdcp" -s -f "$S/src" "${URL}/${RS}" 2>/dev/null
  printf 'BBBB\n' >"$S/dl"

  # --sync (size) download: same size => local stale bytes survive.
  "$BIN/xrdcp" -s --sync "${URL}/${RS}" "$S/dl" 2>/dev/null
  check "fleet --sync (size): stale local dst kept" '[ "$(cat "$S/dl")" = "BBBB" ]'

  # --sync-check cksum download: digests differ => REAL recopy, bytes replaced.
  "$BIN/xrdcp" -s --sync-check cksum "${URL}/${RS}" "$S/dl" 2>/dev/null
  check "fleet --sync-check cksum: stale dst recopied" '[ "$(cat "$S/dl")" = "AAAA" ]'

  # Recursive download honors --sync-check cksum via the walker (open-conn path).
  local RT="/tmp/cfeat-$$-synctree"
  mkdir -p "$S/tree"
  printf 'AAAA\n' >"$S/tree/f"
  "$BIN/xrdcp" -r -s -f "$S/tree/" "${URL}/${RT}/" 2>/dev/null
  mkdir -p "$S/out"
  printf 'BBBB\n' >"$S/out/f"
  "$BIN/xrdcp" -r -s --sync "${URL}/${RT}/" "$S/out" 2>/dev/null
  check "fleet -r --sync (size): stale tree file kept" '[ "$(cat "$S/out/f")" = "BBBB" ]'
  "$BIN/xrdcp" -r -s --sync-check cksum "${URL}/${RT}/" "$S/out" 2>/dev/null
  check "fleet -r --sync-check cksum: stale tree file recopied" '[ "$(cat "$S/out/f")" = "AAAA" ]'
}

main() {
  section_dryrun_filters
  section_sync_modes
  # (later tasks append sections + calls here)
  echo "client-features: $PASS pass, $FAIL fail"
  [ "$FAIL" -eq 0 ]
}
main "$@"
