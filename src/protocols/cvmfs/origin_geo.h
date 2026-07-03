/* origin_geo.h — geographic distance + rank helpers (pure C, no ngx types).
 *
 * WHAT: haversine great-circle distance and a stable argsort used to turn
 *       any per-endpoint metric (km, RTT µs) into sd_http ranks.
 * WHY:  one rank producer shared by the geo and rtt policies keeps the
 *       driver's consumption contract (sd_http_set_ranks) single-shaped.
 * HOW:  no allocation; standalone-testable with plain gcc.
 */
#ifndef BRIX_CVMFS_ORIGIN_GEO_H
#define BRIX_CVMFS_ORIGIN_GEO_H

double brix_cvmfs_haversine_km(double lat1, double lon1,
                                 double lat2, double lon2);

/* stable argsort: ranks[i] = position of endpoint i in ascending metric
 * order (rank 0 = best); equal metrics keep configured order. */
void   brix_cvmfs_rank_by_metric(const double *metric, int n, int *ranks);

#endif /* BRIX_CVMFS_ORIGIN_GEO_H */
