# Homebrew packaging

`../../Formula/brix-cache.rb` packages the native client library and collision-safe
`brix-*` command names for Apple Silicon. It deliberately excludes the nginx
module (which must match one exact nginx build ABI), Linux-only Ceph tools, and
the optional macFUSE clients.

Build and test from source after the `v2.0.0` tag is available:

```sh
brew tap rob-c/brix-cache https://github.com/rob-c/brix-cache
brew install --build-bottle rob-c/brix-cache/brix-cache
brew test brix-cache
```

Create a bottle whose URL points at the matching GitHub release:

```sh
packaging/homebrew/build-bottle.sh v2.0.0
```

Before the tag is published, build and test the current checkout explicitly:

```sh
BRIX_HOMEBREW_LOCAL_SOURCE=1 packaging/homebrew/build-bottle.sh v2.0.0
```

Local-source mode is only an input substitution for the build. The emitted
formula is restored to the GitHub tag URL before its bottle block is merged.

The script writes the bottle, bottle metadata JSON, and a generated formula
containing the bottle checksum to `dist/homebrew/`. Upload all three files to
the GitHub release, then use the generated `brix-cache.rb` to update the tap's
`Formula/brix-cache.rb`. Users can then install the GitHub-hosted bottle with:

```sh
brew tap rob-c/brix-cache https://github.com/rob-c/brix-cache
brew install rob-c/brix-cache/brix-cache
```

macFUSE is intentionally separate because it is a privileged cask with a
kernel/system extension lifecycle. Users who need `xrootdfs` or `brixMount`
can install the `macfuse` cask and follow the macOS source-build instructions
in `docs/03-configuration/BUILD.md`.
