#ifndef BB_DIRECT_MEMORY_LIMITS_H
#define BB_DIRECT_MEMORY_LIMITS_H
#include <stdint.h>
#include <stdlib.h>

/* The retail PS4 reports 5056 MiB, with an override for high-resolution patches. */
static inline uint64_t bb_configured_direct_memory_size(void) {
    const char *env = getenv("BB_DMEM_MB");
    const uint64_t mb = env ? strtoull(env, NULL, 10) : 0;
    return (mb >= 5056 && mb <= 16384 ? mb : 5056) * 1024 * 1024;
}
#endif
