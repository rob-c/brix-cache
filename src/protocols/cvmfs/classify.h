/* classify.h — shim: the CVMFS URL classifier now lives in the shared core.
 *
 * WHAT: preserves the historical `#include "classify.h"` include sites in the
 *       nginx cvmfs:// module after the classifier moved to shared/cvmfs/grammar.
 * WHY:  keep server sources (handler.c, gate.c, module.c) compiling unchanged
 *       while the pure-C body is shared with the standalone FUSE client.
 * HOW:  forward to the shared header; the build adds -I $ngx_addon_dir/shared.
 */
#ifndef BRIX_CVMFS_CLASSIFY_SHIM_H
#define BRIX_CVMFS_CLASSIFY_SHIM_H
#include "cvmfs/grammar/classify.h"
#endif /* BRIX_CVMFS_CLASSIFY_SHIM_H */
