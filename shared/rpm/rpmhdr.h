/* rpmhdr.h — clean-room RPM package header reader (phase-104 D12.2).
 *
 * WHAT: read one .rpm file's lead + signature header + main header and expose
 *       typed tag accessors — the primary.xml working set — plus the derived
 *       facts repodata emission needs (pkgid = sha256 of the whole file,
 *       header byte range, joined file paths). The payload is never decoded.
 * WHY:  clean-room mandate — no librpm linkage. The reader is the only place
 *       that understands the rpm.org container bytes; repomd_write.c and the
 *       brixrpm CLI consume it through this API.
 * HOW:  bounded loads: `il ≤ 4096`, `dl ≤ 64 MiB`, every index entry's
 *       offset/count validated against the data region before dereference,
 *       strings NUL-bounded within the region. Attacker-authored headers get
 *       a clean refusal, never a wild read — the D12 security-negative
 *       corpus (type confusion, count overflow, il=0xffffffff) pins this.
 */
#ifndef BRIX_RPM_RPMHDR_H
#define BRIX_RPM_RPMHDR_H

#include <stddef.h>
#include <stdint.h>

/* Bounds (also quoted in the phase doc's limits table). */
#define BRIX_RPM_IL_MAX 4096
#define BRIX_RPM_DL_MAX (64u << 20)

/* Main-header tags (rpm.org numbering) — the D12.2 working set. */
#define BRIX_RPMTAG_NAME              1000
#define BRIX_RPMTAG_VERSION           1001
#define BRIX_RPMTAG_RELEASE           1002
#define BRIX_RPMTAG_EPOCH             1003
#define BRIX_RPMTAG_SUMMARY           1004
#define BRIX_RPMTAG_DESCRIPTION       1005
#define BRIX_RPMTAG_BUILDTIME         1006
#define BRIX_RPMTAG_BUILDHOST         1007
#define BRIX_RPMTAG_SIZE              1009
#define BRIX_RPMTAG_VENDOR            1011
#define BRIX_RPMTAG_LICENSE           1014
#define BRIX_RPMTAG_PACKAGER          1015
#define BRIX_RPMTAG_GROUP             1016
#define BRIX_RPMTAG_URL               1020
#define BRIX_RPMTAG_ARCH              1022
#define BRIX_RPMTAG_FILESIZES         1028
#define BRIX_RPMTAG_FILEMODES         1030
#define BRIX_RPMTAG_FILEFLAGS         1037
#define BRIX_RPMTAG_SOURCERPM         1044
#define BRIX_RPMTAG_PROVIDENAME       1047
#define BRIX_RPMTAG_REQUIREFLAGS      1048
#define BRIX_RPMTAG_REQUIRENAME       1049
#define BRIX_RPMTAG_REQUIREVERSION    1050
#define BRIX_RPMTAG_CONFLICTFLAGS     1053
#define BRIX_RPMTAG_CONFLICTNAME      1054
#define BRIX_RPMTAG_CONFLICTVERSION   1055
#define BRIX_RPMTAG_CHANGELOGTIME     1080
#define BRIX_RPMTAG_CHANGELOGNAME     1081
#define BRIX_RPMTAG_CHANGELOGTEXT     1082
#define BRIX_RPMTAG_OBSOLETENAME      1090
#define BRIX_RPMTAG_PROVIDEFLAGS      1112
#define BRIX_RPMTAG_PROVIDEVERSION    1113
#define BRIX_RPMTAG_OBSOLETEFLAGS     1114
#define BRIX_RPMTAG_OBSOLETEVERSION   1115
#define BRIX_RPMTAG_DIRINDEXES        1116
#define BRIX_RPMTAG_BASENAMES         1117
#define BRIX_RPMTAG_DIRNAMES          1118
#define BRIX_RPMTAG_PAYLOADFORMAT     1124
#define BRIX_RPMTAG_PAYLOADCOMPRESSOR 1125

/* Signature-header tag (its own numbering space). */
#define BRIX_RPMSIGTAG_PAYLOADSIZE    1007

/* Dependency sense flags (REQUIREFLAGS/PROVIDEFLAGS bits). */
#define BRIX_RPMSENSE_LT     0x02u
#define BRIX_RPMSENSE_GT     0x04u
#define BRIX_RPMSENSE_EQ     0x08u
#define BRIX_RPMSENSE_RPMLIB 0x1000000u  /* rpmlib() tracking dep: never published */

/* FILEFLAGS bit. */
#define BRIX_RPMFILE_GHOST   64u

typedef struct brix_rpm_pkg_s brix_rpm_pkg_t;

/* Load lead + both headers, stream the rest of the file through sha256 for
 * the pkgid. NULL + err on any malformed byte (bad magic, signature type
 * != 5, bounds violation, NAME/VERSION/RELEASE/ARCH missing). */
brix_rpm_pkg_t *brix_rpm_open(const char *path, char *err, size_t errlen);
void            brix_rpm_close(brix_rpm_pkg_t *p);

/* The whole-file sha256 of `path` — the value brix_rpm_pkgid() reports, but
 * computed WITHOUT parsing a byte of the headers. It exists so a caller that
 * already holds a rendered result for this package (createrepo's --paranoid
 * memo check) can ask "are these still the same bytes?" for the price of the
 * read alone. `hex` takes 65 bytes. 0 ok / -1 with the reason in err. */
int brix_rpm_file_sha256(const char *path, char *hex, size_t hexlen,
                         char *err, size_t errlen);

/* Derived package facts. */
const char *brix_rpm_pkgid(const brix_rpm_pkg_t *p);      /* 64 lowercase hex */
int64_t     brix_rpm_size_bytes(const brix_rpm_pkg_t *p); /* whole-file bytes */
void        brix_rpm_header_range(const brix_rpm_pkg_t *p,
                                  int64_t *start, int64_t *end);

/* Tag accessors over the main header. STRING/I18NSTRING via _str (NULL when
 * absent; I18N returns the first — C-locale — string). INT16/INT32 via _u32
 * (0 ok / -1 absent-or-out-of-range; INT16 widened). STRING_ARRAY elements
 * via _stra (NULL past the end); sequential idx iteration is O(1) amortized.
 * Returned pointers alias reader-owned storage, valid until close. */
const char *brix_rpm_str(brix_rpm_pkg_t *p, uint32_t tag);
uint32_t    brix_rpm_count(brix_rpm_pkg_t *p, uint32_t tag);
int         brix_rpm_u32(brix_rpm_pkg_t *p, uint32_t tag, uint32_t idx,
                         uint32_t *out);
const char *brix_rpm_stra(brix_rpm_pkg_t *p, uint32_t tag, uint32_t idx);

/* Signature-header INT32 lookup (only PAYLOADSIZE is consumed today). */
int         brix_rpm_sig_u32(brix_rpm_pkg_t *p, uint32_t tag, uint32_t *out);

/* Joined file-list access: path = DIRNAMES[DIRINDEXES[i]] + BASENAMES[i].
 * 0 ok / -1 malformed (dangling dirindex, path overflow). mode is the u16
 * FILEMODES value; ghost is the FILEFLAGS bit. */
uint32_t    brix_rpm_nfiles(brix_rpm_pkg_t *p);
int         brix_rpm_file(brix_rpm_pkg_t *p, uint32_t i,
                          char *path, size_t pathlen,
                          uint32_t *mode, int *ghost);

/* Metadata paths may not traverse: 0 when the path contains a ".." component
 * (emitters skip the entry + warn), 1 when clean. */
int         brix_rpm_path_sane(const char *path);

#endif /* BRIX_RPM_RPMHDR_H */
