# Site checksum plugins

A site whose clients negotiate a checksum algorithm the built-ins do not cover
(adler32, crc32, crc32c, crc64, crc64nvme, zcrc32, md5, sha1, sha256, sha512)
builds a small shared object against `src/core/compat/checksum_plugin_abi.h`
and registers it:

```nginx
stream {                    # or http { ... } — one registry per process
    brix_checksum_plugin fnv1a64 /usr/lib64/brix/brix_cks_fnv1a64.so;
    server {
        brix_checksum_default fnv1a64;   # optional: lead the Qconfig list
    }
}
```

The plugin then answers everywhere a built-in does: `kXR_query` checksum
requests (`xrdfs query checksum`, `?cks.type=<name>`), the `Qconfig chksum`
advertisement, and WebDAV `Want-Digest` / `Digest`. The host hex-encodes the
digest, so the plugin never touches the wire format.

## Contract

`checksum_plugin_abi.h` is plain C99 with no server headers. The object exports
one data symbol, `brix_cks_plugin`, whose fields the server validates at
`nginx -t` time (ABI version, name match, digest 1..64 bytes, state 1..4096
bytes, non-NULL `init`/`update`/`final`) before running an empty-input
self-test with the configured parms. Any mismatch refuses the configuration;
a plugin never reaches a worker half-loaded.

Rules the loader enforces:

- the path is absolute, a regular file, and not group- or world-writable;
- the name is 1..15 letters/digits and does not collide with a built-in, an
  alias (`crc64xz`), or an earlier plugin;
- at most eight plugins per process;
- a reload replaces the registry wholesale (nothing from the previous
  configuration survives).

`update` is called from worker threads with one private state per
computation: touch nothing but that state.

## Example: `brix_cks_fnv1a64.c`

FNV-1a 64-bit, 16 hex digits on the wire. Build and check:

```sh
cc -shared -fPIC -O2 -I../../src/core/compat -o brix_cks_fnv1a64.so brix_cks_fnv1a64.c
printf 'hello' | python3 -c 'import sys;h=0xcbf29ce484222325
for b in sys.stdin.buffer.read(): h=((h^b)*0x100000001b3)&(2**64-1)
print("%016x"%h)'      # a430d84680aabd0b must match `xrdfs query checksum f?cks.type=fnv1a64`
```

Optional parms: `basis=<16 hex digits>` overrides the offset basis.
