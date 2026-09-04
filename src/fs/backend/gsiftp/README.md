# `src/fs/backend/gsiftp/` — outbound `gsiftp://` storage driver

Kind **ORIGIN** (`src/core/types/fs_list.h`): an SD driver that backs a BriX export with a
*remote* FTP or GridFTP/gsiftp server (dCache, DPM/StoRM, Globus GridFTP,
XRootD-gsiftp), anonymously or with a static/per-user GSI proxy. This is the
**outbound** mirror of the phase-82 *inbound* gateway (`src/protocols/gridftp/`):
there BriX *accepts* gsiftp clients; here BriX *is* a gsiftp client.

Design: `docs/refactor/phase-91-gsiftp-storage-backend.md`.

## Seam

Everything here is auto-exempt from all three tiers of
`tools/ci/check_vfs_seam.py` (the `^src/fs/backend/` allow-regexes). All raw
socket / GridFTP syscalls stay inside this directory; anything above the SD seam
goes through `brix_vfs_*`. Physical locators (FTP paths) never leak above the
driver; the logical→physical join is re-checked here, never trusted from the
caller.

## Module map

The production v1 is split by transport concern and every native file stays
below the repository size cap:

| File | Concern |
|---|---|
| `gftp_reply.{c,h}` | Control-channel reply parser: 3-digit and multiline continuation framing, plus bounded 227/229 parsing. The data connector uses only the returned port and pins the address to the established control peer. |
| `gftp_mlsx.{c,h}` | MLSD/MLST fact-line parser (RFC 3659 §7): inverts `type=;size=;modify=;…` into size/type/UTC-mtime/name; rejects traversal (`/`) and control-byte names, drops overflowing numeric facts. |
| `gftp_control.c` / `gftp_data.c` | Deadline-bounded control I/O, protected-command framing, EPSV/PASV peer pinning, REST+RETR reads, STOR writes and bounded listing collection. |
| `gftp_auth.c` / `gftp_gsi.c` | Anonymous USER/PASS and client-role GSI `AUTH GSSAPI`/ADAT. GSI loads and verifies a proxy chain, performs the initiator handshake, and preserves VOMS attributes carried by that chain. |
| `sd_gsiftp.c` / `sd_gsiftp_internal.h` | Instance factory, vtable/capabilities, credential selection and confined logical-to-origin path joining. |
| `sd_gsiftp_io.c` | Open/close, SIZE/MLST metadata and bounded range reads. |
| `sd_gsiftp_ns.c` | MLSD iteration and DELE/RMD/MKD/RNFR/RNTO namespace operations, including `_cred` twins. |
| `sd_gsiftp_staged.c` | Whole-object staged writes: local spool, STOR to a unique temporary name, atomic RNFR/RNTO promotion and abort cleanup. |

The shipped data path is MODE S with `PROT C`/`DCAU N`. MODE E striping,
private data-channel protection, Kerberos, mTLS and configured password auth are
not silently emulated and are not advertised by the vtable. See the Phase-91
landing record for the deliberate v1 boundary.
