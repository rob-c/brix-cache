/* origin_geo.c — geographic distance + rank helpers (pure C).
 *
 * WHAT: haversine great-circle distance and a stable argsort used to turn
 *       any per-endpoint metric (km, RTT µs) into sd_http ranks.
 * WHY:  one rank producer shared by the geo and rtt policies keeps the
 *       driver's consumption contract (sd_http_set_ranks) single-shaped.
 * HOW:  no allocation, no ngx types; O(n²) insertion-style argsort is fine
 *       for n <= SD_HTTP_EP_MAX (8).
 */
#include "origin_geo.h"

#include <math.h>

#define CVMFS_EARTH_RADIUS_KM 6371.0

double
brix_cvmfs_haversine_km(double lat1, double lon1, double lat2, double lon2)
{
    double rl1 = lat1 * M_PI / 180.0, rl2 = lat2 * M_PI / 180.0;
    double dla = (lat2 - lat1) * M_PI / 180.0;
    double dlo = (lon2 - lon1) * M_PI / 180.0;
    double a = sin(dla / 2) * sin(dla / 2)
             + cos(rl1) * cos(rl2) * sin(dlo / 2) * sin(dlo / 2);

    return 2.0 * CVMFS_EARTH_RADIUS_KM * atan2(sqrt(a), sqrt(1.0 - a));
}

void
brix_cvmfs_rank_by_metric(const double *metric, int n, int *ranks)
{
    int i, j, better;

    for (i = 0; i < n; i++) {
        better = 0;
        for (j = 0; j < n; j++) {
            if (metric[j] < metric[i]
                || (metric[j] == metric[i] && j < i))
            {
                better++;
            }
        }
        ranks[i] = better;
    }
}
