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

For NixOS, add this flake to the system inputs and import its default module.
The module selects the ABI-matched `nginx-brix-cache` package; normal
`services.nginx` configuration remains under the operator's control.

The package deliberately uses Nixpkgs libraries rather than `/usr` libraries.
Consequently `nix-store --query --references` is the authoritative dependency
closure and no `LD_LIBRARY_PATH` setup should be required.
