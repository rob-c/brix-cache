/* Shared cache/archive and client helper capacities.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

/*
 * Buffer sizes for shared utilities.
 * Used in shared/net/, shared/cache/, shared/oci/, shared/cvmfs/.
 *
 * BRIX_SHARED_PROXY_BUF_SIZE: Proxy environment buffer (1024 bytes)
 * BRIX_SHARED_PROXY_RESP_SIZE: Proxy connect response buffer (2048 bytes)
 * BRIX_SHARED_TAR_PATH_SIZE: TAR entry path buffer (4096 bytes)
 * BRIX_SHARED_TAR_LINK_SIZE: TAR linkname buffer (4096 bytes)
 * BRIX_SHARED_OCI_COPYBUF_SIZE: OCI copy buffer (64*1024 = 64 KB)
 * BRIX_SHARED_STARGZ_IOBUF_SIZE: Stargz I/O buffer (64*1024 = 64 KB)
 * BRIX_SHARED_STARGZ_TOC_CAP0: Initial stargz TOC capacity (64*1024 = 64 KB)
 * BRIX_SHARED_FLATTEN_COMPS_MAX: Maximum path components (2048)
 * BRIX_SHARED_FLATTEN_ENTRIES_DEFAULT: Default flatten entries (1024*1024 = 1M)
 */
#define BRIX_SHARED_PROXY_BUF_SIZE             1024          /* proxy env buffer      */
#define BRIX_SHARED_PROXY_RESP_SIZE            2048          /* proxy response buffer */
#define BRIX_SHARED_TAR_PATH_SIZE              4096          /* TAR path buffer       */
#define BRIX_SHARED_TAR_LINK_SIZE              4096          /* TAR linkname buffer   */
#define BRIX_SHARED_OCI_COPYBUF_SIZE           (64*1024)     /* 64 KB OCI copy buf    */
#define BRIX_SHARED_STARGZ_IOBUF_SIZE          (64*1024)     /* 64 KB stargz I/O buf  */
#define BRIX_SHARED_STARGZ_TOC_CAP0            (64*1024)     /* 64 KB initial TOC cap */
#define BRIX_SHARED_FLATTEN_COMPS_MAX          2048          /* max path components   */
#define BRIX_SHARED_FLATTEN_ENTRIES_DEFAULT    (1024*1024)   /* 1M default entries    */

/*
 * CAS (Content-Addressable Storage) constants.
 * Used in shared/cache/cas_*.c for hash tables and file operations.
 *
 * BRIX_SHARED_CAS_FSYNC_BATCH: FSync batch size (8*1024*1024 = 8 MB)
 * BRIX_SHARED_CAS_HASH_SEED: FNV-1a hash seed (1469598103934665603ull)
 * BRIX_SHARED_CAS_HASH_PRIME: FNV-1a hash prime (1099511628211ull)
 * BRIX_SHARED_CAS_INIT_TAB_CAP: Initial hash table capacity (1024)
 * BRIX_SHARED_CAS_INIT_KEYS_CAP: Initial keys capacity (65536)
 * BRIX_SHARED_CAS_GC_CAP0: Initial GC capacity (1024)
 */
#define BRIX_SHARED_CAS_FSYNC_BATCH            (8L*1024*1024) /* 8 MB fsync batch     */
#define BRIX_SHARED_CAS_HASH_SEED              1469598103934665603ull /* FNV-1a seed  */
#define BRIX_SHARED_CAS_HASH_PRIME             1099511628211ull     /* FNV-1a prime   */
#define BRIX_SHARED_CAS_INIT_TAB_CAP           1024          /* initial table cap     */
#define BRIX_SHARED_CAS_INIT_KEYS_CAP          65536         /* initial keys cap      */
#define BRIX_SHARED_CAS_GC_CAP0                1024          /* initial GC cap        */

/*
 * Permission constants for shared operations.
 * Used in shared/cache/, shared/oci/ for file/directory creation.
 *
 * BRIX_SHARED_PERM_PRIVATE: Private file (0600)
 * BRIX_SHARED_PERM_FILE: Standard file (0644)
 * BRIX_SHARED_PERM_DIR: Standard directory (0755)
 * BRIX_SHARED_PERM_DIR_TRAVERSE: Traverse directory (0711)
 */
#define BRIX_SHARED_PERM_PRIVATE               0600          /* private file          */
#define BRIX_SHARED_PERM_FILE                  0644          /* standard file         */
#define BRIX_SHARED_PERM_DIR                   0755          /* standard directory    */
#define BRIX_SHARED_PERM_DIR_TRAVERSE          0711          /* traverse directory    */

/*
 * Limit constants for shared operations.
 *
 * BRIX_SHARED_PORT_MAX: Maximum port number (65535)
 * BRIX_SHARED_TAR_PATH_MAX: Maximum TAR path length (4095 bytes)
 * BRIX_SHARED_HEX_BUFFER_SIZE: Hex encoding buffer (64 bytes for SHA256)
 */
#define BRIX_SHARED_PORT_MAX                   65535         /* maximum port          */
#define BRIX_SHARED_TAR_PATH_MAX               4095          /* max TAR path length   */
#define BRIX_SHARED_HEX_BUFFER_SIZE            64            /* hex encoding buffer   */

/*
 * Shared OCI module constants.
 * Used in shared/oci C files for OCI operations.
 *
 * BRIX_SHARED_OCI_FLATTEN_COPYBUF_SIZE: OCI flatten copy buffer (64*1024 = 64 KB)
 * BRIX_SHARED_OCI_FLATTEN_MAX_PATH: OCI flatten max path (4096 bytes)
 * BRIX_SHARED_OCI_STARGZ_PATH_BUF: Stargz path buffer (1100 bytes)
 * BRIX_SHARED_OCI_TAR_MODE_MASK: TAR mode mask (07777)
 */
#define BRIX_SHARED_OCI_FLATTEN_COPYBUF_SIZE (64*1024)     /* 64 KB flatten copybuf */
#define BRIX_SHARED_OCI_FLATTEN_MAX_PATH     4096          /* max flatten path      */
#define BRIX_SHARED_OCI_STARGZ_PATH_BUF      1100          /* stargz path buffer    */
#define BRIX_SHARED_OCI_TAR_MODE_MASK        07777         /* TAR mode mask         */

/*
 * Shared CAS module file permissions.
 * Used in shared/cache/cas_*.c for file creation.
 *
 * BRIX_SHARED_CAS_FILE_PERM: CAS file permission (0644)
 * BRIX_SHARED_CAS_TMP_PERM: CAS temp file permission (0644)
 * BRIX_SHARED_CAS_DIR_PERM: CAS directory permission (0755)
 * BRIX_SHARED_CAS_PACK_DIR_PERM: CAS pack directory permission (0755)
 * BRIX_SHARED_CAS_PRIVATE_PERM: CAS private file permission (0600)
 */
#define BRIX_SHARED_CAS_FILE_PERM            0644          /* CAS file perm         */
#define BRIX_SHARED_CAS_TMP_PERM             0644          /* CAS temp perm         */
#define BRIX_SHARED_CAS_DIR_PERM             0755          /* CAS directory perm    */
#define BRIX_SHARED_CAS_PACK_DIR_PERM        0755          /* CAS pack dir perm     */
#define BRIX_SHARED_CAS_PRIVATE_PERM         0600          /* CAS private perm      */

/*
 * Client module buffer sizes (bytes).
 * Used in client/ for test and utility buffers.
 *
 * BRIX_CLIENT_TEST_BUF_SIZE: Client test buffer (8192 bytes)
 * BRIX_CLIENT_TEST_URL_BUF_SIZE: Client test URL buffer (8300 bytes)
 */
#define BRIX_CLIENT_TEST_BUF_SIZE            8192          /* test buffer size      */
#define BRIX_CLIENT_TEST_URL_BUF_SIZE        8300          /* test URL buffer       */

/*
 * Client FTP module constants.
 * Used in client/tests/c/ftp_client_unit.c for FTP operations.
 *
 * BRIX_CLIENT_FTP_DEFAULT_PORT: FTP default port (2811 - GridFTP)
 * BRIX_CLIENT_FTP_DATA_PORT_MIN: FTP data port minimum (1024)
 * BRIX_CLIENT_FTP_DATA_PORT_MAX: FTP data port maximum (65535)
 */
#define BRIX_CLIENT_FTP_DEFAULT_PORT         2811          /* GridFTP port          */
#define BRIX_CLIENT_FTP_DATA_PORT_MIN        1024          /* data port minimum     */
#define BRIX_CLIENT_FTP_DATA_PORT_MAX        65535         /* data port maximum     */
