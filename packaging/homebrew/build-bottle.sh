#!/usr/bin/env bash
# Build a Homebrew ARM64 bottle and emit a release-ready formula with its hash.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
formula_source="$repo_root/Formula/brix-cache.rb"
tag="${1:-v$(sed -n 's/#define BRIX_SERVER_VERSION_BARE[[:space:]]*"\([^"]*\)".*/\1/p' "$repo_root/src/core/ident.h")}"
outdir="${2:-$repo_root/dist/homebrew}"
root_url="https://github.com/rob-c/brix-cache/releases/download/${tag}"
local_source="${BRIX_HOMEBREW_LOCAL_SOURCE:-0}"
brew_repo="$(brew --repository)"
tap_root="$brew_repo/Library/Taps/rob-c/homebrew-brix-cache-build"
tap_formula="$tap_root/Formula/brix-cache.rb"
formula_ref="rob-c/brix-cache-build/brix-cache"

case "$tag" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "error: expected a release tag such as v2.0.0, got: $tag" >&2; exit 1 ;;
esac

if [[ -e "$tap_root" ]]; then
    echo "error: temporary build tap already exists: $tap_root" >&2
    exit 1
fi

mkdir -p "$outdir"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/brix-bottle.XXXXXX")"
trap 'rm -rf "$workdir" "$tap_root"' EXIT

# Homebrew 7 rejects standalone formula paths. A minimal temporary tap is
# enough; it intentionally has no Git history and is removed on exit.
mkdir -p "$(dirname -- "$tap_formula")"
install -m644 "$formula_source" "$tap_formula"

# A release build fetches the published tag exactly as users will. Manual and
# workflow-dispatch builds can opt into the current checkout so the bottle is
# testable before that tag exists. Restore the release formula before merging
# bottle metadata so no file:// URL can escape into the published artifact.
if [[ "$local_source" == "1" ]]; then
    version="${tag#v}"
    source_archive="$workdir/brix-cache-${version}.tar.gz"
    tar \
        --exclude-vcs \
        --exclude='./.debbuild' \
        --exclude='./.rpmbuild' \
        --exclude='./.pytest_cache' \
        --exclude='./.venv*' \
        --exclude='./build' \
        --exclude='./dist' \
        --exclude='./client/bin' \
        --exclude='*.o' \
        --exclude='*.a' \
        --exclude='*.d' \
        --exclude='*.dylib' \
        -czf "$source_archive" -C "$repo_root" .
    source_sha="$(shasum -a 256 "$source_archive" | awk '{print $1}')"
    ruby -e '
      path, archive, sha, version = ARGV
      formula = File.read(path)
      formula.sub!(/^  url .*?\n      tag: .*?\n/m,
                   %(  url "file://#{archive}"\n  sha256 "#{sha}"\n  version "#{version}"\n))
      abort "failed to replace formula source" unless formula.include?("file://#{archive}")
      File.write(path, formula)
    ' "$tap_formula" "$source_archive" "$source_sha" "$version"
elif [[ "$local_source" != "0" ]]; then
    echo "error: BRIX_HOMEBREW_LOCAL_SOURCE must be 0 or 1" >&2
    exit 1
fi

brew install --build-bottle "$formula_ref"
brew test "$formula_ref"

cd "$workdir"
brew bottle --json --root-url "$root_url" "$formula_ref"
json_file="$(find . -maxdepth 1 -name '*.bottle.json' -print -quit)"
test -n "$json_file"
install -m644 "$formula_source" "$tap_formula"
brew bottle --merge --write --no-commit "$json_file"

bottle_file="$(find . -maxdepth 1 -name '*.bottle.tar.gz' -print -quit)"
test -n "$bottle_file"
release_filename="$(ruby -rjson -e '
    metadata = JSON.parse(File.read(ARGV.fetch(0))).values.fetch(0)
    puts metadata.fetch("bottle").fetch("tags").values.fetch(0).fetch("filename")
' "$json_file")"
case "$release_filename" in
    *.bottle.tar.gz) ;;
    *) echo "error: invalid bottle filename in $json_file: $release_filename" >&2; exit 1 ;;
esac
install -m644 "$bottle_file" "$outdir/$release_filename"
install -m644 "$json_file" "$outdir/"
install -m644 "$tap_formula" "$outdir/brix-cache.rb"

echo "Homebrew release artifacts written to: $outdir"
