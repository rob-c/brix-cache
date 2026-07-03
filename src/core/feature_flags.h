#ifndef NGX_BRIX_FEATURE_FLAGS_H
#define NGX_BRIX_FEATURE_FLAGS_H

/*
 * The nginx addon config script supplies explicit -DBRIX_WITH_* values when
 * optional features are disabled. Keep defaults enabled for direct test builds.
 */

#ifndef BRIX_WITH_WEBDAV
#define BRIX_WITH_WEBDAV 1
#endif

#ifndef BRIX_WITH_S3
#define BRIX_WITH_S3 1
#endif

#ifndef BRIX_WITH_DASHBOARD
#define BRIX_WITH_DASHBOARD 1
#endif

#ifndef BRIX_WITH_CACHE
#define BRIX_WITH_CACHE 1
#endif

#ifndef BRIX_WITH_TPC
#define BRIX_WITH_TPC 1
#endif

#endif /* NGX_BRIX_FEATURE_FLAGS_H */
