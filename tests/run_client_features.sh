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

section_mirror_delete() {
  echo "== mirror delete (--delete) =="

  # Error case: --delete without --sync must exit 50.
  "$BIN/xrdcp" -r --delete "$WORK/src/" "$WORK/dst/" 2>/dev/null
  check "--delete without --sync exits 50" '[ "$?" -eq 50 ]'

  # Error case: --delete without -r must exit 50.
  "$BIN/xrdcp" --sync --delete "$WORK/src/a.root" "$WORK/dst/" 2>/dev/null
  check "--delete without -r exits 50" '[ "$?" -eq 50 ]'

  echo "== mirror delete (fleet) =="
  if ! have_fleet; then
    echo "  SKIP fleet mirror-delete tests (no fleet at $URL)"
    return
  fi

  # Seed the source tree on the remote (a.root, b.log, sub/c.root).
  local RSRC="${URL}//tmp/cfeat-$$-mdsrc"
  "$BIN/xrdcp" -r -s -f "$WORK/src/" "$RSRC/" 2>/dev/null

  # Upload direction: pre-seed an extra file on the remote dst, then run
  # xrdcp -r --sync --delete.  The extra must disappear; the seeded files survive.
  local RDST="${URL}//tmp/cfeat-$$-mddst"
  "$BIN/xrdcp" -s "$WORK/src/a.root" "${RDST}/a.root" 2>/dev/null
  "$BIN/xrdcp" -s "$WORK/src/b.log" "${RDST}/b.log" 2>/dev/null
  "$BIN/xrdcp" -s "$WORK/src/a.root" "${RDST}/extra.root" 2>/dev/null
  "$BIN/xrdcp" -r -s --sync --delete "$WORK/src/" "$RDST/" 2>/dev/null
  check "--delete upload: synced file survives" \
    '"$BIN/xrdfs" "$URL" stat "/tmp/cfeat-$$-mddst/a.root" >/dev/null 2>&1'
  check "--delete upload: extra removed" \
    '! "$BIN/xrdfs" "$URL" stat "/tmp/cfeat-$$-mddst/extra.root" >/dev/null 2>&1'

  # Security: excluded extra must NOT be deleted (it is outside the sync scope).
  local RDST2="${URL}//tmp/cfeat-$$-mddst2"
  "$BIN/xrdcp" -s "$WORK/src/a.root" "${RDST2}/a.root" 2>/dev/null
  "$BIN/xrdcp" -s "$WORK/src/a.root" "${RDST2}/keep.dat" 2>/dev/null
  "$BIN/xrdcp" -r -s --sync --delete --exclude 'keep.dat' "$WORK/src/" "$RDST2/" 2>/dev/null
  check "--delete upload: excluded extra survives" \
    '"$BIN/xrdfs" "$URL" stat "/tmp/cfeat-$$-mddst2/keep.dat" >/dev/null 2>&1'

  # --dry-run --delete: the extra file must still be present after the run.
  local RDST3="${URL}//tmp/cfeat-$$-mddst3"
  "$BIN/xrdcp" -s "$WORK/src/a.root" "${RDST3}/a.root" 2>/dev/null
  "$BIN/xrdcp" -s "$WORK/src/a.root" "${RDST3}/phantom.root" 2>/dev/null
  DRY_OUT=$("$BIN/xrdcp" -r -s --sync --delete --dry-run "$WORK/src/" "$RDST3/" 2>/dev/null)
  check "--dry-run --delete: prints delete line" \
    'echo "$DRY_OUT" | grep -q "\[dry-run\] delete"'
  check "--dry-run --delete: phantom file unchanged" \
    '"$BIN/xrdfs" "$URL" stat "/tmp/cfeat-$$-mddst3/phantom.root" >/dev/null 2>&1'

  # TODO(Task 10): clean scratch dirs with xrdfs rm -r once recursive delete is implemented
}

section_remove_source() {
  echo "== --remove-source =="
  local RS="$WORK/rs"
  mkdir -p "$RS"

  # Security: web/S3 source + --remove-source must exit 50.
  "$BIN/xrdcp" --remove-source "s3://bucket/obj" "$RS/" 2>/dev/null
  check "--remove-source s3:// exits 50" '[ "$?" -eq 50 ]'
  "$BIN/xrdcp" --remove-source "https://example.com/f" "$RS/" 2>/dev/null
  check "--remove-source https:// exits 50" '[ "$?" -eq 50 ]'

  # Dry-run + --remove-source: source must still exist and the message must include
  # "(then remove source)".  transfer_one short-circuits before brix_copy in
  # dry-run mode, so local->local is fine here (no actual I/O).
  echo "dry-run test" >"$RS/dry.txt"
  OUT=$("$BIN/xrdcp" --dry-run --remove-source "$RS/dry.txt" "$RS/dry_out.txt" 2>/dev/null)
  check "--dry-run --remove-source: src intact" '[ -e "$RS/dry.txt" ]'
  check "--dry-run --remove-source: prints (then remove source)" \
    'echo "$OUT" | grep -q "(then remove source)"'

  echo "== --remove-source (fleet) =="
  if ! have_fleet; then
    echo "  SKIP fleet --remove-source tests (no fleet at $URL)"
    return
  fi

  local RSBASE="/tmp/cfeat-$$-rs"

  # Upload with --remove-source: local source file must be gone after the
  # transfer, and the remote destination must be present and byte-exact.
  printf 'upload-move\n' >"$RS/up.txt"
  "$BIN/xrdcp" -s --remove-source "$RS/up.txt" "${URL}//${RSBASE}/up.txt" 2>/dev/null
  check "--remove-source upload: local src removed" '[ ! -e "$RS/up.txt" ]'
  check "--remove-source upload: remote dst exists" \
    '"$BIN/xrdfs" "$URL" stat "${RSBASE}/up.txt" >/dev/null 2>&1'

  # Download with --remove-source: remote source must be gone and local
  # destination must contain the original bytes.
  printf 'download-move\n' >"$RS/dl_seed.txt"
  "$BIN/xrdcp" -s -f "$RS/dl_seed.txt" "${URL}//${RSBASE}/dl.txt" 2>/dev/null
  "$BIN/xrdcp" -s --remove-source "${URL}//${RSBASE}/dl.txt" "$RS/dl_out.txt" 2>/dev/null
  check "--remove-source download: local dst has content" \
    '[ "$(cat "$RS/dl_out.txt")" = "download-move" ]'
  check "--remove-source download: remote src removed" \
    '! "$BIN/xrdfs" "$URL" stat "${RSBASE}/dl.txt" >/dev/null 2>&1'

  # Recursive upload with --remove-source: build a small tree (2 files, 1 subdir),
  # move it to remote with -r --remove-source, then verify local tree is gone,
  # remote files exist, and no spurious "could not remove source" warning.
  local RMVTREE="$RS/rmv-tree"
  mkdir -p "$RMVTREE/sub"
  printf 'file-1\n' >"$RMVTREE/f1.txt"
  printf 'file-2\n' >"$RMVTREE/f2.txt"
  printf 'file-sub\n' >"$RMVTREE/sub/f_sub.txt"
  RMVERR=$("$BIN/xrdcp" -r -s --remove-source "$RMVTREE/" "${URL}//${RSBASE}/rmvtree/" 2>&1)
  check "-r --remove-source: local tree removed" '[ ! -d "$RMVTREE" ]'
  check "-r --remove-source: remote file 1 exists" \
    '"$BIN/xrdfs" "$URL" stat "${RSBASE}/rmvtree/f1.txt" >/dev/null 2>&1'
  check "-r --remove-source: no spurious warning" \
    '! echo "$RMVERR" | grep -q "could not remove source"'
}

section_journal() {
  echo "== --journal / --resume =="
  local J="$WORK/jrn"
  mkdir -p "$J/src"

  # (d) --resume without --from must exit 50 — always local, no fleet needed
  "$BIN/xrdcp" --resume "$J/src/a.txt" "$J/src/" 2>/dev/null
  check "journal (d): --resume without --from exits 50" '[ "$?" -eq 50 ]'

  echo "== --journal / --resume (fleet) =="
  if ! have_fleet; then
    echo "  SKIP journal fleet tests (no fleet at $URL)"
    return
  fi

  # Batch copy requires one remote endpoint (local→local is unsupported).
  # Use root://localhost to copy local source files into a remote scratch dir.
  local JBASE="/tmp/cfeat-$$-jrn"
  local RDST="${URL}/${JBASE}"
  "$BIN/xrdfs" "$URL" mkdir "$JBASE" 2>/dev/null

  # seed 3 source files and a manifest listing them
  printf 'alpha\n'   > "$J/src/a.txt"
  printf 'bravo\n'   > "$J/src/b.txt"
  printf 'charlie\n' > "$J/src/c.txt"
  printf '%s\n' "$J/src/a.txt" "$J/src/b.txt" "$J/src/c.txt" > "$J/manifest.txt"

  # (a) first run: 3 files copied, journal written with 3 "ok " lines
  OUT=$("$BIN/xrdcp" --from "$J/manifest.txt" --journal "$J/j.journal" "$RDST/" 2>&1)
  check "journal (a): 3 copied, 0 skipped" \
    'echo "$OUT" | grep -q "3 copied, 0 skipped, 0 failed"'
  check "journal (a): journal has 3 ok lines" \
    '[ "$(grep -c "^ok " "$J/j.journal")" -eq 3 ]'

  # (b) add 4th file; rerun with same journal → 1 copied, 3 skipped
  printf 'delta\n' > "$J/src/d.txt"
  printf '%s\n' "$J/src/a.txt" "$J/src/b.txt" "$J/src/c.txt" "$J/src/d.txt" \
    > "$J/manifest.txt"
  OUT=$("$BIN/xrdcp" --from "$J/manifest.txt" --journal "$J/j.journal" "$RDST/" 2>&1)
  check "journal (b): 1 copied, 3 skipped" \
    'echo "$OUT" | grep -q "1 copied, 3 skipped, 0 failed"'
  check "journal (b): d.txt was uploaded" \
    '"$BIN/xrdfs" "$URL" stat "$JBASE/d.txt" >/dev/null 2>&1'

  # (c) prepend a corrupt line to the journal; rerun → 0 copied, 4 skipped
  #     hostile/malformed lines must be silently ignored (never crash)
  { printf 'garbage-not-an-ok-line\n'; cat "$J/j.journal"; } > "$J/j.journal.tmp"
  mv "$J/j.journal.tmp" "$J/j.journal"
  OUT=$("$BIN/xrdcp" --from "$J/manifest.txt" --journal "$J/j.journal" "$RDST/" 2>&1)
  check "journal (c): 0 copied, 4 skipped (corrupt line tolerated)" \
    'echo "$OUT" | grep -q "0 copied, 4 skipped, 0 failed"'
}

main() {
  section_dryrun_filters
  section_sync_modes
  section_mirror_delete
  section_remove_source
  section_journal
  echo "client-features: $PASS pass, $FAIL fail"
  [ "$FAIL" -eq 0 ]
}
main "$@"
