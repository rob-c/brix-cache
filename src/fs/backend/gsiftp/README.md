# `src/fs/backend/gsiftp/` — outbound `gsiftp://` storage driver

Kind **ORIGIN** (`fs_list.h`): an SD driver that backs a BriX export with a
*remote* GridFTP / gsiftp server (dCache, DPM/StoRM, Globus GridFTP,
XRootD-gsiftp), authenticating with the full WLCG credential matrix. This is the
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

Landed (phase-91 Wave-A protocol kernels — pure, no nginx/socket deps, unit
tested by `tests/c/gftp_parse_test.c`, fast-tier runner `gftp_parse`):

| File | Concern |
|---|---|
| `gftp_reply.{c,h}` | control-channel reply parser: 3-digit + multiline `-` continuation framing; SSRF-critical `227` (PASV/IPv4) and `229` (EPSV, RFC 2428) address decoders with per-octet bounds checks — the caller screens the extracted address through `net_target.h` before dialling. |
| `gftp_mlsx.{c,h}` | MLSD/MLST fact-line parser (RFC 3659 §7): inverts `type=;size=;modify=;…` into size/type/UTC-mtime/name; rejects traversal (`/`) and control-byte names, drops overflowing numeric facts. |

Planned (subsequent waves, per the phase-91 plan §3/§13): `sd_gsiftp.{c,h}`
(driver struct + `brix_sd_gsiftp_create` factory), `sd_gsiftp_io.c`,
`sd_gsiftp_ns.c`, `sd_gsiftp_ns_cred.c`, `sd_gsiftp_staged.c`, `gftp_session.c`,
`gftp_auth*.c`, `gftp_data.c`. The parser kernels above are consumed by
`gftp_session.c` (control loop) and `gftp_data.c` (data-channel address
resolution); they are wired into `./config` when that first consumer lands, so
the production binary carries no uncalled code today.
