/* Compile-time constants and completion macros, grouped by subsystem.
 *
 * Requires: nginx, protocol, and metrics declarations before expanding
 * the corresponding macros. Existing users include this umbrella; the
 * private family headers retain their original macro spellings/values.
 */
#ifndef BRIX_TYPES_TUNABLES_H
#define BRIX_TYPES_TUNABLES_H

#include "core/compat/path.h"

/* Stringification macro for compile-time constants. */
#define BRIX_STRINGIFY_HELPER(x)  #x
#define BRIX_STRINGIFY(x)         BRIX_STRINGIFY_HELPER(x)

#include "tunables_core.h"
#include "tunables_io.h"
#include "tunables_storage.h"
#include "tunables_network.h"
#include "tunables_cluster.h"
#include "tunables_config.h"
#include "tunables_auth.h"
#include "tunables_tpc.h"
#include "tunables_root_wire.h"
#include "tunables_root_limits.h"
#include "tunables_webdav.h"
#include "tunables_s3.h"
#include "tunables_oci.h"
#include "tunables_shared.h"
#include "tunables_metrics.h"

#endif /* BRIX_TYPES_TUNABLES_H */
