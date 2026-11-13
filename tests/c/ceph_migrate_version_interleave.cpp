/* Force a different object's read into the shared context between stat and
 * version lookup. The real Ceph objects and copy/redirect operations remain live. */
#include "xrdceph_striper_internal.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" uint64_t real_version(librados::IoCtx *)
    asm("__real__ZN8librados7v14_2_05IoCtx16get_last_versionEv");
extern "C" uint64_t interleaved_version(librados::IoCtx *)
    asm("__wrap__ZN8librados7v14_2_05IoCtx16get_last_versionEv");

uint64_t interleaved_version(librados::IoCtx *source)
{
    uint64_t original = real_version(source);
    const char *fault = getenv("BRIX_MIGRATE_VERSION_FAULT");
    if (fault == nullptr) { return original; }
    if (strcmp(fault, "stale") == 0) { return original + 1; }
    assert(strcmp(fault, "interleave") == 0);
    for (const char *key : {"dataset/empty.0000000000000000",
                            "dataset/large.0000000000000001"}) {
        uint64_t size = 0; time_t modified = 0;
        assert(stripermig::g_src.stat(key, &size, &modified) == 0);
        if (real_version(&stripermig::g_src) != original) {
            fprintf(stderr, "injected another object's read\n");
            return real_version(source);
        }
    }
    assert(false && "fixture must contain distinct object versions");
    return 0;
}
