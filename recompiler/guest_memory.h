/* Trusted host descriptor for one bounded guest region. CPU registers contain
 * guest integers; only bytes is a host pointer. Buffers, descriptor and CPU state
 * must be disjoint, and byte_size must fit the host allocation (maximum 64 here).
 * Permissions: read=1, write=2. Status: success=0, bounds=1, descriptor=2, denied=3.
 * fault_offset is the failing instruction's byte offset, not a dispatched RIP. */
#ifndef BB_EXPERIMENT_GUEST_MEMORY_H
#define BB_EXPERIMENT_GUEST_MEMORY_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    unsigned char *bytes;
    uint64_t guest_base, byte_size, permissions;
    uint64_t fault_address, fault_offset;
} BbGuestMemory;

_Static_assert(sizeof(BbGuestMemory) == 48, "guest mapping size");
_Static_assert(offsetof(BbGuestMemory, bytes) == 0, "mapping bytes offset");
_Static_assert(offsetof(BbGuestMemory, guest_base) == 8, "mapping base offset");
_Static_assert(offsetof(BbGuestMemory, byte_size) == 16, "mapping size offset");
_Static_assert(offsetof(BbGuestMemory, permissions) == 24, "mapping permissions offset");
_Static_assert(offsetof(BbGuestMemory, fault_address) == 32, "mapping fault address offset");
_Static_assert(offsetof(BbGuestMemory, fault_offset) == 40, "mapping fault offset offset");
#endif
