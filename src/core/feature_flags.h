#ifndef NGX_XROOTD_FEATURE_FLAGS_H
#define NGX_XROOTD_FEATURE_FLAGS_H

/*
 * The nginx addon config script supplies explicit -DXROOTD_WITH_* values when
 * optional features are disabled. Keep defaults enabled for direct test builds.
 */

#ifndef XROOTD_WITH_WEBDAV
#define XROOTD_WITH_WEBDAV 1
#endif

#ifndef XROOTD_WITH_S3
#define XROOTD_WITH_S3 1
#endif

#ifndef XROOTD_WITH_DASHBOARD
#define XROOTD_WITH_DASHBOARD 1
#endif

#ifndef XROOTD_WITH_CACHE
#define XROOTD_WITH_CACHE 1
#endif

#ifndef XROOTD_WITH_TPC
#define XROOTD_WITH_TPC 1
#endif

#endif /* NGX_XROOTD_FEATURE_FLAGS_H */
