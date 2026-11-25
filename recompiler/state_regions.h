#ifndef BB_EXPERIMENT_STATE_REGIONS_H
#define BB_EXPERIMENT_STATE_REGIONS_H
#include "guest_memory.h"

enum { BB_MAX_DATA_REGIONS = 64, BB_MAX_REGION_BYTES = 1024 * 1024 };

/* Sorted, nonempty data regions, disjoint from the separately supplied stack.
 * Buffers and descriptor records must remain alive for the whole invocation.
 * The caller supplies disjoint host allocations and thread-local fault records.
 */
typedef struct {
    BbGuestMemory *regions;
    uint64_t count;
    BbGuestMemory unmapped;
} BbGuestRegions;

int bb_regions_prepare(BbGuestRegions *, BbGuestMemory *);
BbGuestMemory *bb_regions_select(BbGuestRegions *, BbGuestMemory *, uint64_t, int);

#endif
