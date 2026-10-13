/* Native Darwin success, error and counter-sanity checks for CMS sysload. */
#include "platform/platform_api.h"

#include <assert.h>
#include <errno.h>

int
main(void)
{
    brix_plat_sysload_t first;
    brix_plat_sysload_t second;

    errno = 0;
    assert(brix_plat_sysload_sample(NULL) == -1 && errno == EINVAL);
    assert(brix_plat_sysload_sample(&first) == 0);
    assert((first.have & BRIX_SYSLOAD_HAVE_LOAD) != 0);
    assert((first.have & BRIX_SYSLOAD_HAVE_MEMORY) != 0);
    assert((first.have & BRIX_SYSLOAD_HAVE_NET) != 0);
    assert((first.have & BRIX_SYSLOAD_HAVE_PAGING) != 0);
    assert(first.load1 >= 0.0);
    assert(first.total_memory > 0);
    assert(first.available_memory <= first.total_memory);

    assert(brix_plat_sysload_sample(&second) == 0);
    if ((first.have & second.have & BRIX_SYSLOAD_HAVE_PAGING) != 0) {
        assert(second.paging_events >= first.paging_events);
    }
    return 0;
}
