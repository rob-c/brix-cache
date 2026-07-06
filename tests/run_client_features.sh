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

  # Error case (no fleet, validated pre-transfer): --delete (mirror) and
  # --remove-source (move) are contradictory — together they destroy both trees.
  "$BIN/xrdcp" -r --sync --delete --remove-source "$WORK/src/" "$WORK/dst/" 2>/dev/null
  check "--delete + --remove-source exits 50" '[ "$?" -eq 50 ]'

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

  # Best-effort cleanup of scratch dirs created above.
  "$BIN/xrdfs" "$URL" rm -r "/tmp/cfeat-$$-mdsrc"  >/dev/null 2>&1 || true
  "$BIN/xrdfs" "$URL" rm -r "/tmp/cfeat-$$-mddst"  >/dev/null 2>&1 || true
  "$BIN/xrdfs" "$URL" rm -r "/tmp/cfeat-$$-mddst2" >/dev/null 2>&1 || true
  "$BIN/xrdfs" "$URL" rm -r "/tmp/cfeat-$$-mddst3" >/dev/null 2>&1 || true
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

section_xrdfs_rm() {
  echo "== xrdfs rm -r =="

  if ! have_fleet; then
    echo "  SKIP fleet rm -r tests (no fleet at $URL)"
    return
  fi

  # xrdfs one-shot connects before dispatch — exit-50 validation needs a live server
  # Error: missing path must exit 50.
  "$BIN/xrdfs" "$URL" rm 2>/dev/null
  check "rm: no path exits 50" '[ "$?" -eq 50 ]'

  # xrdfs one-shot connects before dispatch — exit-50 validation needs a live server
  # Security: rm -r / must exit 50 (export root guard).
  "$BIN/xrdfs" "$URL" rm -r / 2>/dev/null
  check "rm -r /: exits 50 (export root guard)" '[ "$?" -eq 50 ]'

  local BASE="/tmp/cfeat-$$-rm"

  # Build tree: BASE/a  BASE/sub/b
  "$BIN/xrdfs" "$URL" mkdir -p "${BASE}/sub" >/dev/null 2>&1
  printf 'hello\n' | "$BIN/xrdcp" - "${URL}//${BASE}/a"      >/dev/null 2>&1
  printf 'world\n' | "$BIN/xrdcp" - "${URL}//${BASE}/sub/b"  >/dev/null 2>&1

  # rm -r on a tree: succeeds and the root is gone.
  "$BIN/xrdfs" "$URL" rm -r "$BASE" >/dev/null 2>&1
  check "rm -r tree: exit 0" '[ "$?" -eq 0 ]'
  "$BIN/xrdfs" "$URL" stat "$BASE" >/dev/null 2>&1
  check "rm -r tree: root is gone" '[ "$?" -ne 0 ]'

  # Security: rm -r / must exit 50 even with a live fleet.
  "$BIN/xrdfs" "$URL" rm -r / 2>/dev/null
  check "rm -r /: fleet live, still exits 50" '[ "$?" -eq 50 ]'
  "$BIN/xrdfs" "$URL" stat / >/dev/null 2>&1
  check "rm -r /: root still accessible" '[ "$?" -eq 0 ]'

  # Error: missing path must exit nonzero.
  "$BIN/xrdfs" "$URL" rm -r "/tmp/cfeat-$$-rm-no-such" >/dev/null 2>&1
  check "rm -r missing: nonzero" '[ "$?" -ne 0 ]'

  # rm -r on a plain file deletes it.
  local FBASE="/tmp/cfeat-$$-rmf"
  printf 'data\n' | "$BIN/xrdcp" - "${URL}//${FBASE}" >/dev/null 2>&1
  "$BIN/xrdfs" "$URL" rm -r "$FBASE" >/dev/null 2>&1
  check "rm -r plain file: exit 0" '[ "$?" -eq 0 ]'
  "$BIN/xrdfs" "$URL" stat "$FBASE" >/dev/null 2>&1
  check "rm -r plain file: gone" '[ "$?" -ne 0 ]'

  # rm -r -v prints "removed" lines.
  local VBASE="/tmp/cfeat-$$-rmv"
  "$BIN/xrdfs" "$URL" mkdir -p "${VBASE}/d" >/dev/null 2>&1
  printf 'v\n' | "$BIN/xrdcp" - "${URL}//${VBASE}/d/f" >/dev/null 2>&1
  VOUT=$("$BIN/xrdfs" "$URL" rm -r -v "$VBASE" 2>/dev/null)
  check "rm -r -v: exit 0" '[ "$?" -eq 0 ]'
  check "rm -r -v: prints removed lines" \
    'echo "$VOUT" | grep -q "^removed "'

  # Symlink guard: rm -r must remove the LINK, not the target's contents.
  # Setup: dir A with a file, dir D containing a symlink B→A.
  # After rm -r D: D and B are gone, A and its file survive.
  local SBASE="/tmp/cfeat-$$-rmsym"
  local SA="${SBASE}/A"
  local SD="${SBASE}/D"
  "$BIN/xrdfs" "$URL" mkdir -p "$SA" >/dev/null 2>&1
  "$BIN/xrdfs" "$URL" mkdir -p "$SD" >/dev/null 2>&1
  printf 'precious\n' | "$BIN/xrdcp" - "${URL}//${SA}/file.txt" >/dev/null 2>&1
  # Try to create a symlink D/B→A.  Vendor ext (kXR_symlink) may be unsupported.
  SYMLINK_OUT=$("$BIN/xrdfs" "$URL" ln -s "$SA" "${SD}/B" 2>&1)
  SYMLINK_RC=$?
  if [ "$SYMLINK_RC" -eq 0 ]; then
    # Symlink created: rm -r D should succeed and leave A/file.txt intact.
    "$BIN/xrdfs" "$URL" rm -r "$SD" >/dev/null 2>&1
    check "rm -r dir-with-symlink: exit 0" '[ "$?" -eq 0 ]'
    "$BIN/xrdfs" "$URL" stat "$SD" >/dev/null 2>&1
    check "rm -r dir-with-symlink: D gone" '[ "$?" -ne 0 ]'
    "$BIN/xrdfs" "$URL" stat "${SA}/file.txt" >/dev/null 2>&1
    check "rm -r dir-with-symlink: A/file.txt intact" '[ "$?" -eq 0 ]'
    # Cleanup A.
    "$BIN/xrdfs" "$URL" rm -r "$SA" >/dev/null 2>&1 || true
  else
    echo "  SKIP symlink rm test (server does not support ln -s: $SYMLINK_OUT)"
  fi
  "$BIN/xrdfs" "$URL" rm -r "$SBASE" >/dev/null 2>&1 || true
}

section_xrdfs_json() {
  echo "== xrdfs --json (fleet) =="
  if ! have_fleet; then
    echo "  SKIP xrdfs json tests (no fleet at $URL)"
    return
  fi

  local BASE="/tmp/cfeat-$$-json"
  "$BIN/xrdfs" "$URL" mkdir -p "$BASE" >/dev/null 2>&1
  printf 'hello\n' | "$BIN/xrdcp" - "${URL}//${BASE}/sample.txt" >/dev/null 2>&1

  # stat -j: valid JSON with is_dir key
  OUT=$("$BIN/xrdfs" "$URL" stat -j "${BASE}/sample.txt" 2>/dev/null)
  check "stat -j: valid JSON with is_dir" \
    'echo "$OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d[\"is_dir\"] in (True,False)"'

  # ls -j: valid JSON array
  OUT=$("$BIN/xrdfs" "$URL" ls -j "$BASE" 2>/dev/null)
  check "ls -j: valid JSON array" \
    'echo "$OUT" | python3 -c "import sys,json; arr=json.load(sys.stdin); assert isinstance(arr, list)"'

  # du -j: valid JSON object with expected keys
  OUT=$("$BIN/xrdfs" "$URL" du -j "$BASE" 2>/dev/null)
  check "du -j: valid JSON with bytes/files/dirs" \
    'echo "$OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert \"bytes\" in d and \"files\" in d and \"dirs\" in d"'

  # security: upload a file whose name contains a double-quote, then verify ls -j
  # is still valid JSON (hostile names must not escape the array or break parsers).
  local WEIRD="${BASE}/we\"ird.txt"
  printf 'weird\n' | "$BIN/xrdcp" - "${URL}//${WEIRD}" >/dev/null 2>&1 || true
  if "$BIN/xrdfs" "$URL" stat "${WEIRD}" >/dev/null 2>&1; then
    OUT=$("$BIN/xrdfs" "$URL" ls -j "$BASE" 2>/dev/null)
    check "ls -j: hostile filename (double-quote) produces valid JSON" \
      'echo "$OUT" | python3 -c "import sys,json; json.load(sys.stdin)"'
  else
    echo "  skip: server rejects quote-in-name; hostile-name JSON check not exercisable"
  fi

  # error path: stat -j on a missing path must exit nonzero AND produce no JSON on stdout
  OUT=$("$BIN/xrdfs" "$URL" stat -j "${BASE}/no-such-file" 2>/dev/null)
  RC=$?
  check "stat -j missing: nonzero exit" '[ "$RC" -ne 0 ]'
  check "stat -j missing: no output on stdout" \
    '[ -z "$(printf "%s" "$OUT" | tr -d "[:space:]")" ]'
}

section_tail_follow() {
  echo "== tail -f (follow mode) =="
  if ! have_fleet; then
    echo "  SKIP tail -f tests (no fleet at $URL)"
    return
  fi

  local BASE="/tmp/cfeat-$$-tailf"
  local CAP="$WORK/tailf.cap"
  local ERR="$WORK/tailf.err"
  local RC

  # --- success: initial content + appended bytes reach stdout ---
  printf 'line1\nline2\n' | "$BIN/xrdcp" - "${URL}//${BASE}" >/dev/null 2>&1
  timeout 5 "$BIN/xrdfs" "$URL" tail -f "$BASE" >"$CAP" 2>"$ERR" &
  local FPID=$!
  sleep 1
  # Grow the file: upload a longer version so size strictly increases.
  printf 'line1\nline2\nline3_appended\n' | "$BIN/xrdcp" -f - "${URL}//${BASE}" >/dev/null 2>&1
  wait "$FPID" 2>/dev/null || true
  check "tail -f: appended line appears in output" 'grep -q "line3_appended" "$CAP"'

  # --- error: missing path exits nonzero quickly (before the timeout) ---
  timeout 3 "$BIN/xrdfs" "$URL" tail -f "${BASE}-missing" >/dev/null 2>/dev/null
  RC=$?
  check "tail -f missing: fast nonzero exit" '[ "$RC" -ne 0 ] && [ "$RC" -ne 124 ]'

  # --- truncation resilience: stderr notice + process outlives the truncation ---
  local CAP2="$WORK/tailf2.cap"
  local ERR2="$WORK/tailf2.err"
  printf 'aaa\nbbb\nccc\n' | "$BIN/xrdcp" -f - "${URL}//${BASE}" >/dev/null 2>&1
  timeout 5 "$BIN/xrdfs" "$URL" tail -f "$BASE" >"$CAP2" 2>"$ERR2" &
  local FPID2=$!
  sleep 1
  # Truncate: replace with a shorter file.
  printf 'x\n' | "$BIN/xrdcp" -f - "${URL}//${BASE}" >/dev/null 2>&1
  wait "$FPID2" 2>/dev/null; RC=$?
  check "tail -f truncation: stderr notice" 'grep -q "truncated" "$ERR2"'
  check "tail -f truncation: process ran to timeout (exit 124)" '[ "$RC" -eq 124 ]'

  # Cleanup
  "$BIN/xrdfs" "$URL" rm "$BASE" >/dev/null 2>&1 || true
}

section_cat_compress() {
  echo "== cat -z (codec validation) =="
  if ! have_fleet; then
    echo "  SKIP cat -z tests (no fleet at $URL)"
    return
  fi

  # xrdfs one-shot connects before dispatch — exit-50 validation needs a live server
  # Security: codec with injection chars must exit 50.
  "$BIN/xrdfs" "$URL" cat -z 'gz&evil=1' /some/path 2>/dev/null
  check "cat -z bad codec: exits 50" '[ "$?" -eq 50 ]'

  local FPATH="/tmp/cfeat-$$-catz"
  # Seed a small file with known content.
  printf 'hello compress\n' | "$BIN/xrdcp" - "${URL}//${FPATH}" >/dev/null 2>&1

  # Transparency contract: cat -z gzip must produce the same bytes as cat
  # (server either negotiates compression and inflates, or ignores the request).
  "$BIN/xrdfs" "$URL" cat "$FPATH" > "$WORK/catz.plain" 2>/dev/null
  "$BIN/xrdfs" "$URL" cat -z gzip "$FPATH" > "$WORK/catz.compr" 2>/dev/null
  check "cat -z gzip: byte-identical to plain cat" 'cmp -s "$WORK/catz.plain" "$WORK/catz.compr"'

  # Error path: missing file must exit nonzero.
  "$BIN/xrdfs" "$URL" cat -z gzip "/tmp/cfeat-$$-catz-nosuchfile" >/dev/null 2>&1
  check "cat -z gzip missing: nonzero exit" '[ "$?" -ne 0 ]'

  # Cleanup.
  "$BIN/xrdfs" "$URL" rm "$FPATH" >/dev/null 2>&1 || true
}

section_cksum_tree() {
  echo "== xrdcksum tree + check (local) =="
  local T="$WORK/ckst"
  mkdir -p "$T/src/sub" "$T/out"

  # Seed a 3-file tree with known content.
  printf 'alpha\n'   > "$T/src/a.dat"
  printf 'bravo\n'   > "$T/src/sub/b.dat"
  printf 'charlie\n' > "$T/src/sub/c.dat"

  # tree: produces a 3-line manifest.
  "$BIN/xrdcksum" tree "$T/src" -o "$T/manifest"
  check "tree: exit 0 on clean local tree" '[ "$?" -eq 0 ]'
  check "tree: manifest has 3 lines"       '[ "$(wc -l < "$T/manifest")" -eq 3 ]'
  # All lines must match the two-space format "<hex>  <rel>".
  check "tree: each line has two-space separator" \
    'grep -qE "^[0-9a-f]+  [^/]" "$T/manifest"'

  # check: all-OK exits 0.
  "$BIN/xrdcksum" check "$T/manifest" "$T/src"
  check "check: exit 0 when all match" '[ "$?" -eq 0 ]'

  # check: tamper one file → exit 1 and FAILED names the rel path.
  printf 'TAMPERED\n' > "$T/src/a.dat"
  local out
  out=$("$BIN/xrdcksum" check "$T/manifest" "$T/src" 2>/dev/null)
  local rc=$?
  check "check: exit 1 on mismatch"         '[ '"$rc"' -eq 1 ]'
  check "check: FAILED line names the file"  'echo "$out" | grep -q "^FAILED a.dat"'
  check "check: two OK lines for untampered" '[ "$(echo "$out" | grep -c "^OK ")" -eq 2 ]'

  # security-negative: inject an escaping rel path → malformed, exit 2, no file outside tree touched.
  local GUARD_FILE="$WORK/guard_$$"
  printf 'canary' > "$GUARD_FILE"
  # Build a manifest with a path-escape line appended.
  cp "$T/manifest" "$T/bad_manifest"
  printf '03e51f2a  ../../guard_%d\n' "$$" >> "$T/bad_manifest"
  "$BIN/xrdcksum" check "$T/bad_manifest" "$T/src" 2>/dev/null
  check "check: exit 2 on malformed manifest line" '[ "$?" -eq 2 ]'
  check "security: escape line rejected, guard file untouched" \
    '[ "$(cat "$GUARD_FILE")" = "canary" ]'

  # e2e --algo: generate manifest with crc32c, verify with same algo.
  # (Restore the original content; the tamper test above broke a.dat)
  printf 'alpha\n' > "$T/src/a.dat"
  "$BIN/xrdcksum" tree "$T/src" --algo crc32c -o "$T/algo_manifest"
  check "tree --algo crc32c: exit 0" '[ "$?" -eq 0 ]'
  check "tree --algo crc32c: manifest has 3 lines" \
    '[ "$(wc -l < "$T/algo_manifest")" -eq 3 ]'
  "$BIN/xrdcksum" check "$T/algo_manifest" "$T/src" --algo crc32c
  check "check --algo crc32c: exit 0 on clean tree" '[ "$?" -eq 0 ]'

  # security-negative: a file whose NAME embeds a newline must be skipped (not
  # written as a forged extra manifest line); the run warns + exits 2 and the
  # emitted manifest still parses cleanly line-by-line.
  local NL="$WORK/cknl"
  mkdir -p "$NL/src"
  printf 'ok\n' > "$NL/src/good.dat"
  # Build a filename containing a literal newline: "evil\n<forged hex>  hack".
  local BADNAME
  BADNAME="$(printf 'evil\n0000  hack')"
  printf 'x\n' > "$NL/src/$BADNAME" 2>/dev/null || true
  if [ -e "$NL/src/$BADNAME" ]; then
    "$BIN/xrdcksum" tree "$NL/src" -o "$NL/manifest" 2>/dev/null
    check "tree: newline-name run exits 2" '[ "$?" -eq 2 ]'
    check "tree: forged name not in manifest" \
      '! grep -q "hack" "$NL/manifest"'
    # Every manifest line must still match the "<hex>  <rel>" record shape.
    check "tree: manifest parses cleanly line-by-line" \
      '! grep -qvE "^[0-9a-f]+  " "$NL/manifest"'
  else
    echo "  SKIP newline-name test (filesystem rejected the name)"
  fi

  # Fleet-gated: remote tree output matches local manifest of identical content.
  echo "== xrdcksum tree (fleet, remote) =="
  if ! have_fleet; then
    echo "  SKIP remote tree tests (no fleet at $URL)"
    return
  fi

  local RDIR="/tmp/cfeat-$$-cktree"
  # Upload the original (pre-tamper) 3-file tree to the fleet.
  mkdir -p "$T/orig/sub"
  printf 'alpha\n'   > "$T/orig/a.dat"
  printf 'bravo\n'   > "$T/orig/sub/b.dat"
  printf 'charlie\n' > "$T/orig/sub/c.dat"
  "$BIN/xrdcp" -r "$T/orig/" "${URL}//${RDIR}/" >/dev/null 2>&1
  check "fleet tree: upload succeeded" '[ "$?" -eq 0 ]'

  # Generate remote manifest and local manifest, sort both, compare.
  "$BIN/xrdcksum" tree "${URL}//${RDIR}" -o "$T/remote_manifest"
  check "fleet tree: remote tree exits 0" '[ "$?" -eq 0 ]'

  "$BIN/xrdcksum" tree "$T/orig" -o "$T/local_manifest"
  sort "$T/remote_manifest" > "$T/remote_sorted"
  sort "$T/local_manifest"  > "$T/local_sorted"
  check "fleet tree: remote manifest matches local" \
    'cmp -s "$T/remote_sorted" "$T/local_sorted"'

  # Trailing-slash root: `tree root://.../dir/` must produce the SAME manifest
  # as the no-slash form (the root prefix strip must ignore trailing slashes).
  "$BIN/xrdcksum" tree "${URL}//${RDIR}/" -o "$T/remote_slash_manifest"
  check "fleet tree: trailing-slash root exits 0" '[ "$?" -eq 0 ]'
  sort "$T/remote_slash_manifest" > "$T/remote_slash_sorted"
  check "fleet tree: trailing slash == no slash" \
    'cmp -s "$T/remote_slash_sorted" "$T/remote_sorted"'

  # Cleanup remote scratch.
  "$BIN/xrdfs" "$URL" rm -r "$RDIR" >/dev/null 2>&1 || true
}

section_diag_json() {
  echo "== xrddiag --json =="

  # --- Replay fixture tests (no fleet needed: pure file decode) ---

  # Build a valid .xrdcap fixture with one M record + one F record.
  # Layout from capture.c:
  #   magic  : b"XRDCAP1\n"
  #   M record: 'M' klen:1 key[klen] vlen:2BE val[vlen]
  #   F record: 'F' dir:1 isreq:1 sid:2BE code:2BE wirelen:4BE wire[wirelen]
  python3 - "$WORK/fix.xrdcap" <<'EOF'
import struct, sys
with open(sys.argv[1], 'wb') as f:
    f.write(b"XRDCAP1\n")
    k, v = b"tool", b"fixture"
    f.write(b"M" + bytes([len(k)]) + k + struct.pack(">H", len(v)) + v)
    wire = bytes(24)   # one zeroed 24-byte request header
    f.write(b"F" + b">" + b"\x01" + struct.pack(">HHI", 1, 3000, len(wire)) + wire)
EOF
  "$BIN/xrddiag" replay "$WORK/fix.xrdcap" >/dev/null 2>/dev/null
  check "replay: valid fixture decodes (exit 0)" '[ "$?" -eq 0 ]'

  # Truncated fixture: write magic + a partial F record (4 bytes, missing the rest).
  # Must exit nonzero cleanly — not crash, not silently succeed.
  python3 - "$WORK/trunc.xrdcap" <<'EOF'
import sys
with open(sys.argv[1], 'wb') as f:
    f.write(b"XRDCAP1\n")
    f.write(b"F" + b">" + b"\x01" + b"\x00")   # dir + isreq + 1 byte of 2-byte sid
EOF
  "$BIN/xrddiag" replay "$WORK/trunc.xrdcap" >/dev/null 2>/dev/null
  check "replay: truncated fixture exits nonzero" '[ "$?" -ne 0 ]'

  # M-record truncation: magic + 'M' + a klen byte claiming more key bytes than
  # remain.  The reader (shared by replay + playback) must fread-skip the record
  # body and detect the short read, exiting nonzero — NOT silently succeed via an
  # fseek-past-EOF.  (The playback path re-issues over a live server; without a
  # fleet only the shared decode is exercised here.)
  python3 - "$WORK/mtrunc.xrdcap" <<'EOF'
import sys
with open(sys.argv[1], 'wb') as f:
    f.write(b"XRDCAP1\n")
    f.write(b"M" + bytes([16]) + b"key")   # klen=16 but only 3 key bytes follow
EOF
  "$BIN/xrddiag" replay "$WORK/mtrunc.xrdcap" >/dev/null 2>/dev/null
  check "replay: M-record-truncated fixture exits nonzero" '[ "$?" -ne 0 ]'

  # --- check --json with unreachable endpoint (no fleet needed) ---
  OUT=$("$BIN/xrddiag" check --json "root://localhost:1" 2>/dev/null)
  RC=$?
  check "check --json unreachable: nonzero exit" '[ "$RC" -ne 0 ]'
  check "check --json unreachable: no stdout on error" \
    '[ -z "$(printf "%s" "$OUT" | tr -d "[:space:]")" ]'

  # --- Fleet-gated checks ---
  echo "== xrddiag --json (fleet) =="
  if ! have_fleet; then
    echo "  SKIP xrddiag fleet JSON tests (no fleet at $URL)"
    return
  fi

  OUT=$("$BIN/xrddiag" check --json "$URL" 2>/dev/null)
  check "check --json fleet: valid JSON" \
    'echo "$OUT" | python3 -c "import sys,json; json.load(sys.stdin)"'
  check "check --json fleet: has connect_ok field" \
    'echo "$OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert \"connect_ok\" in d"'

  OUT=$("$BIN/xrddiag" topology --json "$URL" 2>/dev/null)
  check "topology --json fleet: valid JSON array" \
    'echo "$OUT" | python3 -c "import sys,json; arr=json.load(sys.stdin); assert isinstance(arr, list)"'
  check "topology --json fleet: element 0 has node field" \
    'echo "$OUT" | python3 -c "import sys,json; arr=json.load(sys.stdin); assert not arr or \"node\" in arr[0]"'
}

section_xrdfs_uring() {
  echo "== xrdfs download/upload --io-uring (fleet) =="
  if ! have_fleet; then
    echo "  SKIP xrdfs uring tests (no fleet at $URL)"
    return
  fi

  # Seed: upload a small file to the fleet with a known pattern.
  local RFILE="${URL}//tmp/cfeat-uring-$$"
  printf 'xrdfs-uring-test-data-1234567890\n' >"$WORK/uring_seed.dat"
  "$BIN/xrdfs" "$URL" upload "$WORK/uring_seed.dat" /tmp/cfeat-uring-$$ 2>/dev/null

  # --io-uring off: download must succeed and content must match the seed.
  "$BIN/xrdfs" "$URL" download --io-uring off /tmp/cfeat-uring-$$ "$WORK/dl_off.dat" 2>/dev/null
  check "download --io-uring off: exit 0"      '[ "$?" -eq 0 ]'
  check "download --io-uring off: byte-exact"  'cmp -s "$WORK/uring_seed.dat" "$WORK/dl_off.dat"'

  # --io-uring auto: download must succeed and be byte-identical to the off result.
  "$BIN/xrdfs" "$URL" download --io-uring auto /tmp/cfeat-uring-$$ "$WORK/dl_auto.dat" 2>/dev/null
  check "download --io-uring auto: exit 0"     '[ "$?" -eq 0 ]'
  check "download --io-uring auto: byte-exact" 'cmp -s "$WORK/dl_off.dat" "$WORK/dl_auto.dat"'

  # --io-uring bogus: treated as auto (falls through to XRDC_IO_URING_AUTO); must not
  # crash and the download must still succeed.
  "$BIN/xrdfs" "$URL" download --io-uring bogus /tmp/cfeat-uring-$$ "$WORK/dl_bogus.dat" 2>/dev/null
  check "download --io-uring bogus: exit 0 (treated as auto)" '[ "$?" -eq 0 ]'
  check "download --io-uring bogus: byte-exact" 'cmp -s "$WORK/uring_seed.dat" "$WORK/dl_bogus.dat"'

  # --io-uring on: either succeeds (kernel has uring support) or exits non-zero with no
  # partial/corrupt output file left at the final path (vfs_posix ON+unavailable contract).
  rm -f "$WORK/dl_on.dat"
  "$BIN/xrdfs" "$URL" download --io-uring on /tmp/cfeat-uring-$$ "$WORK/dl_on.dat" 2>/dev/null
  local ON_RC=$?
  if [ "$ON_RC" -eq 0 ]; then
    check "download --io-uring on: success → byte-exact" 'cmp -s "$WORK/uring_seed.dat" "$WORK/dl_on.dat"'
  else
    # Clean failure: the final output path must not exist (no partial write).
    check "download --io-uring on: clean fail → no partial output" \
      '[ ! -f "$WORK/dl_on.dat" ]'
  fi

  # upload --io-uring off: must succeed and the round-trip content must match.
  "$BIN/xrdfs" "$URL" upload --io-uring off "$WORK/uring_seed.dat" /tmp/cfeat-uring-up-$$ 2>/dev/null
  check "upload --io-uring off: exit 0" '[ "$?" -eq 0 ]'
  "$BIN/xrdfs" "$URL" download /tmp/cfeat-uring-up-$$ "$WORK/up_rt.dat" 2>/dev/null
  check "upload --io-uring off: round-trip byte-exact" 'cmp -s "$WORK/uring_seed.dat" "$WORK/up_rt.dat"'

  # Cleanup remote scratch files.
  "$BIN/xrdfs" "$URL" rm /tmp/cfeat-uring-$$    2>/dev/null || true
  "$BIN/xrdfs" "$URL" rm /tmp/cfeat-uring-up-$$ 2>/dev/null || true
}

main() {
  section_dryrun_filters
  section_sync_modes
  section_mirror_delete
  section_remove_source
  section_journal
  section_xrdfs_rm
  section_xrdfs_json
  section_tail_follow
  section_cat_compress
  section_cksum_tree
  section_diag_json
  section_xrdfs_uring
  echo "client-features: $PASS pass, $FAIL fail"
  [ "$FAIL" -eq 0 ]
}
main "$@"
