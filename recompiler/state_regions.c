#include "state_regions.h"

static int valid(const BbGuestMemory *region, uint64_t limit) {
    return region->byte_size <= limit &&
           region->guest_base <= UINT64_MAX - region->byte_size &&
           region->permissions <= 3 && (!region->byte_size || region->bytes);
}

static int contains(const BbGuestMemory *region, uint64_t address) {
    return address >= region->guest_base && address - region->guest_base < region->byte_size;
}

int bb_regions_prepare(BbGuestRegions *table, BbGuestMemory *stack) {
    if (!table || !stack || table->count > BB_MAX_DATA_REGIONS ||
        (table->count && !table->regions)) return 0;
    table->unmapped = (BbGuestMemory){0};
    stack->fault_address = stack->fault_offset = 0;
    for (uint64_t i = 0; i < table->count; ++i)
        table->regions[i].fault_address = table->regions[i].fault_offset = 0;
    if (!valid(stack, 512)) return 0;

    uint64_t previous_end = 0;
    const uint64_t stack_end = stack->guest_base + stack->byte_size;
    for (uint64_t i = 0; i < table->count; ++i) {
        const BbGuestMemory *region = &table->regions[i];
        if (!valid(region, BB_MAX_REGION_BYTES) || !region->byte_size ||
            region->guest_base < previous_end) return 0;
        previous_end = region->guest_base + region->byte_size;
        if (stack->byte_size && region->guest_base < stack_end &&
            stack->guest_base < previous_end) return 0;
    }
    return 1;
}

BbGuestMemory *bb_regions_select(BbGuestRegions *table, BbGuestMemory *stack,
                                 uint64_t address, int stack_fallback) {
    if (contains(stack, address)) return stack;
    uint64_t low = 0, high = table->count;
    while (low < high) {
        uint64_t middle = low + (high - low) / 2;
        BbGuestMemory *region = &table->regions[middle];
        if (address < region->guest_base) high = middle;
        else if (contains(region, address)) return region;
        else low = middle + 1;
    }
    return stack_fallback ? stack : &table->unmapped;
}
