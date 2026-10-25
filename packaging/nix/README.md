# NixOS / Nix packaging

The repository flake is pinned to the supported NixOS 26.05 package set and
exposes native packages for `aarch64-linux` and `x86_64-linux`:

```bash
nix build .#brix-cache-client
nix build .#nginx-brix-cache
nix flake check
```

`brix-cache-client` contains the native library, command-line clients, FUSE
tools, compatibility command names, headers, completions, and manual pages.
`nginx-brix-cache` is Nixpkgs' nginx stable build with both BriX dynamic
modules compiled against that exact nginx source and dependency closure.
`nix develop` also exposes `nginx-brix-test-sdk`, a development-only copy of
that exact configured and fully built tree.  It retains generated headers and
addon objects so the native contract tests run against the packaged build
instead of skipping for a missing conventional `/tmp/nginx-*` build tree.
The development shell additionally carries the independent interoperability
tools used by the suite (GFAL2, the MinIO client, Squid, Varnish, Fail2ban, Helm,
nghttp2, Podman/rootless networking, RPM/DPKG/createrepo, Valgrind, and codec
CLIs).  Host capabilities still apply: FUSE tests need `/dev/fuse`, container
tests need usable namespaces, and Nixpkgs 26.05 does not provide the legacy
`globus-url-copy` GridFTP client.  The MinIO server is deliberately absent:
Nixpkgs marks its abandoned release insecure, so S3 server tests must use a
separately reviewed container image or another compatible test backend.
The composed Python interpreter also includes the optional S3/SigV4, xattr,
CRC32c, codec, and process/memory bindings; installing only their CLI tools
does not enable the corresponding Python interoperability tests.
The reference Python binding is the hash-pinned XRootD 6.2.0 binary wheel,
meeting the suite's declared 6.x baseline; the independent reference server
remains Nixpkgs' package. The shell includes the FUSE helper binary output,
and the server SDK opts into compiling its installed liburing backend. Runtime
I/O selection still defaults to the portable thread pool.

Authentication plugins are resolved within the wheel's own ABI-matched library
directory using packaged ELF runtime paths. The independent reference server's
5.x plugins must not be substituted for the Python client's 6.x plugins.
For an isolated interpreter build (without rebuilding nginx), use
`nix build .#devShells.aarch64-linux.default.testPython` (or `x86_64-linux`).
The shell includes libxslt so the retained nginx SDK can also be relinked.

For NixOS, add this flake to the system inputs and import its default module.
The module selects the ABI-matched `nginx-brix-cache` package; normal
`services.nginx` configuration remains under the operator's control.

The package deliberately uses Nixpkgs libraries rather than `/usr` libraries.
Consequently `nix-store --query --references` is the authoritative dependency
closure and no `LD_LIBRARY_PATH` setup should be required.
