# CephFS-on-RADOS decode fixtures — Ceph reef 18.2.4

Real, byte-exact RADOS omap dentry values captured from the seeded CephFS on the
`xrd-ceph-demo` cluster (see `tests/ceph/cephfs_seed.c` for the tree). These are
the ground-truth inputs for the `cephfs_layout` decoder unit tests
(`src/fs/backend/rados/cephfs_layout.c`). Each `*.bin` is the **raw omap value**
of a `<name>_head` directory entry, which embeds the child's full inode.

| fixture | dir object (metadata pool) | omap key | child |
|---|---|---|---|
| `fx_root_top.bin`    | `1.00000000`           | `top.txt_head`   | `/top.txt`        (ino 0x10000000002, 15 B) |
| `fx_root_dir1.bin`   | `1.00000000`           | `dir1_head`      | `/dir1`           (ino 0x10000000000, dir)  |
| `fx_dir1_hello.bin`  | `10000000000.00000000` | `hello.txt_head` | `/dir1/hello.txt` (ino 0x100000001f7, 27 B) |
| `fx_dir1_sub.bin`    | `10000000000.00000000` | `sub_head`       | `/dir1/sub`       (ino 0x10000000001, dir)  |

## On-disk dentry value format (reef, type `'i'`)

Confirmed by hexdump of `fx_dir1_hello.bin`:

```
offset 0  : snapid_t  first        (u64 LE)          e.g. 02 00 00 00 00 00 00 00
offset 8  : char      type         ('i' = 0x69 primary, old; 'I'=0x49 new; 'L'/'l'=remote)
offset 9  : InodeStore frame        ENCODE_START: struct_v(u8) struct_compat(u8) struct_len(u32 LE)
                                     e.g. 02 01 e5 01 00 00  -> v2, compat1, len=0x1e5=485
offset 15 : InodeStore payload      inode_t (ENCODE_START) + symlink + dirfragtree + xattrs + ...
```

The child inode number lives inside the `inode_t` (NOT at a fixed offset — the
spike's hardcoded offset-31 read was reef-incidental and is replaced by a real
framed decode). The decoder walks: dentry header → InodeStore frame → inode_t
frame → fields.

## Regenerating

```bash
# on the demo cluster (after seeding + `ceph tell mds.<id> flush journal`):
rados -p cephfs_metadata getomapval <dir_oid> '<name>_head' /tmp/out.bin
docker cp xrd-ceph-demo:/tmp/out.bin tests/ceph/fixtures/reef-18.2.4/<name>.bin
```

## Ground-truth oracle

`ceph-dencoder` (decompress `/usr/bin/ceph-dencoder.gz` in the demo image) decodes
most types (`InodeStore`, `inode_t<std::allocator>`, `file_layout_t`,
`frag_info_t`, `inode_backtrace_t`) to JSON. Note: on this build it trips on an
old `file_layout_t` sub-encoding inside `InodeStore`; the decoder unit tests
therefore assert against the **known seed values** above (ino / size / type /
default 4 MiB layout), which is authoritative and version-independent. Use
`ceph-dencoder` as a cross-check for the fields it does decode.
