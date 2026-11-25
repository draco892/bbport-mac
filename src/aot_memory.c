/* Maps the native runtime's PS4 memory into the x86 guest engine. */
#include "aot_memory.h"
#include "direct_memory_limits.h"
#include "runtime.h"
#include <inttypes.h>
#include <stdio.h>
#include <sys/mman.h>

enum { GUEST_PAGE = 16384 };
#define ARENA_SIZE (UINT64_C(16) << 30)
#define INVALID UINT32_C(0x80020016)

static uc_engine *guest;
static void *arena;
static uc_err mirror_error;

BbMemoryImport bb_aot_memory_import(const char *name) {
    static const struct { const char *symbol; BbMemoryImport op; } exports[] = {
        {"sceKernelGetDirectMemorySize", BB_DIRECT_SIZE},
        {"sceKernelAllocateDirectMemory", BB_DIRECT_ALLOC},
        {"sceKernelMapDirectMemory", BB_DIRECT_MAP}, {"sceKernelMapNamedDirectMemory", BB_DIRECT_MAP_NAMED},
        {"sceKernelReleaseDirectMemory", BB_DIRECT_RELEASE},
        {"sceKernelMunmap", BB_MEMORY_UNMAP}, {"munmap", BB_MEMORY_UNMAP},
        {"sceKernelMprotect", BB_MEMORY_PROTECT},
        {"sceKernelReserveVirtualRange", BB_MEMORY_RESERVE},
        {"sceKernelMapFlexibleMemory", BB_FLEXIBLE_MAP},
        {"sceKernelMapNamedFlexibleMemory", BB_FLEXIBLE_MAP_NAMED},
        {"sceKernelReleaseFlexibleMemory", BB_MEMORY_UNMAP},
    };
    const char *symbol = runtime_symbol(name);
    if (!symbol) return BB_MEMORY_NONE;
    for (size_t i = 0; i < sizeof exports / sizeof *exports; ++i)
        if (!strcmp(symbol, exports[i].symbol)) return exports[i].op;
    return BB_MEMORY_NONE;
}

static uint32_t guest_rights(int prot) {
    return ((prot & 1) ? UC_PROT_READ : 0) | ((prot & 2) ? UC_PROT_WRITE : 0) |
           ((prot & 4) ? UC_PROT_EXEC : 0);
}

static uc_err forget(uint64_t address, uint64_t size) {
    uc_mem_region *regions = NULL;
    uint32_t count = 0;
    uc_err err = uc_mem_regions(guest, &regions, &count);
    const uint64_t end = address + size;
    for (uint32_t i = 0; !err && i < count; ++i) {
        const uint64_t first = regions[i].begin > address ? regions[i].begin : address;
        const uint64_t last = regions[i].end < end - 1 ? regions[i].end : end - 1;
        if (first <= last) err = uc_mem_unmap(guest, first, last - first + 1);
    }
    uc_free(regions);
    return err;
}

static void on_mapping(int op, uintptr_t address, uint64_t size, uint64_t phys,
                       int kind, int prot, int type, int shared) {
    (void)phys; (void)kind; (void)type; (void)shared;
    if (mirror_error) return;
    if (op == MIRROR_PROTECT) {
        mirror_error = uc_mem_protect(guest, address, size, guest_rights(prot));
    } else {
        mirror_error = forget(address, size);
        if (!mirror_error && op == MIRROR_MAP)
            mirror_error = uc_mem_map_ptr(guest, address, size, guest_rights(prot), (void *)address);
    }
    if (mirror_error)
        fprintf(stderr, "ARM64 memory mirror at %#" PRIxPTR ": %s\n", address, uc_strerror(mirror_error));
}

int bb_aot_memory_attach(uc_engine *engine) {
    void *region = mmap((void *)(uintptr_t)BB_USER_MIN, ARENA_SIZE, PROT_NONE,
                        MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    if (region == MAP_FAILED) return 0;
    if (runtime_memory_set_guest_arena((uintptr_t)region, ARENA_SIZE)) {
        munmap(region, ARENA_SIZE);
        return 0;
    }
    arena = region;
    guest = engine;
    runtime_memory_set_mirror_hook(on_mapping);
    return !mirror_error;
}

void bb_aot_memory_detach(void) {
    if (!arena) return;
    runtime_memory_set_mirror_hook(NULL);
    munmap(arena, ARENA_SIZE);
    arena = NULL;
    guest = NULL;
}

int bb_aot_memory_failed(void) { return mirror_error != UC_ERR_OK; }

unsigned char *bb_aot_memory_span(uint64_t address, uint64_t size, uint64_t access) {
    int prot, type;
    uintptr_t end;
    if (!runtime_memory_vma_info(address, &prot, &type, &end) ||
        (guest_rights(prot) & access) != access || size > end - address)
        return NULL;
    return (unsigned char *)(uintptr_t)address;
}

uint64_t bb_aot_memory_call(BbMemoryImport op, const char *name, const uint64_t a[6],
                            BbMemorySpan translate, void *ctx) {
    uintptr_t fn = runtime_memory_resolve(name);
    if (!fn) return INVALID;
    if (op == BB_DIRECT_SIZE) return ((uint64_t (ABI *)(void))fn)();
    if (op == BB_DIRECT_RELEASE) {
        const uint64_t size = bb_configured_direct_memory_size();
        if (a[0] > size || a[1] > size - a[0]) return INVALID;
        return (uint32_t)((int32_t (ABI *)(uint64_t, uint64_t))fn)(a[0], a[1]);
    }
    if (op == BB_MEMORY_UNMAP || op == BB_MEMORY_PROTECT) {
        const uint64_t start = (uintptr_t)arena;
        if (a[0] < start || a[0] >= start + ARENA_SIZE || a[1] > start + ARENA_SIZE - a[0])
            return INVALID;
    }
    if (op == BB_MEMORY_UNMAP) return (uint32_t)((int32_t (ABI *)(void *, uint64_t))fn)((void *)a[0], a[1]);
    if (op == BB_MEMORY_PROTECT)
        return (uint32_t)((int32_t (ABI *)(const void *, uint64_t, int))fn)((void *)a[0], a[1], (int)a[2]);

    unsigned char *slot = translate(ctx, op == BB_DIRECT_ALLOC ? a[5] : a[0], 8,
                                    op == BB_DIRECT_ALLOC ? 2 : 3);
    if (!slot) return INVALID;
    if (op == BB_DIRECT_ALLOC) {
        int64_t phys = 0;
        uint32_t error = (uint32_t)((int32_t (ABI *)(int64_t, int64_t, uint64_t, uint64_t, int, int64_t *))fn)
            ((int64_t)a[0], (int64_t)a[1], a[2], a[3], (int)a[4], &phys);
        if (!error) memcpy(slot, &phys, sizeof phys);
        return error;
    }
    void *address;
    memcpy(&address, slot, sizeof address);
    if ((op == BB_DIRECT_MAP || op == BB_DIRECT_MAP_NAMED) &&
        (a[4] > bb_configured_direct_memory_size() || a[1] > bb_configured_direct_memory_size() - a[4]))
        return INVALID;
    uint32_t error;
    if (op == BB_DIRECT_MAP) {
        error = (uint32_t)((int32_t (ABI *)(void **, uint64_t, int, int, int64_t, uint64_t))fn)
            (&address, a[1], (int)a[2], (int)a[3], (int64_t)a[4], a[5]);
    } else if (op == BB_DIRECT_MAP_NAMED) {
        error = (uint32_t)((int32_t (ABI *)(void **, uint64_t, int, int, int64_t, uint64_t, const char *))fn)
            (&address, a[1], (int)a[2], (int)a[3], (int64_t)a[4], a[5], NULL);
    } else if (op == BB_MEMORY_RESERVE) {
        error = (uint32_t)((int32_t (ABI *)(void **, uint64_t, int, uint64_t))fn)
            (&address, a[1], (int)a[2], a[3]);
    } else if (op == BB_FLEXIBLE_MAP_NAMED) {
        error = (uint32_t)((int32_t (ABI *)(void **, uint64_t, int, int, const char *))fn)
            (&address, a[1], (int)a[2], (int)a[3], NULL);
    } else {
        error = (uint32_t)((int32_t (ABI *)(void **, uint64_t, int, int))fn)
            (&address, a[1], (int)a[2], (int)a[3]);
    }
    if (!error) {
        slot = translate(ctx, a[0], 8, 2);
        if (!slot) return INVALID;
        memcpy(slot, &address, sizeof address);
    }
    return error;
}

static unsigned char *fixture_span(void *ctx, uint64_t address, uint64_t size, uint64_t access) {
    (void)access;
    return address < 3 && size == 8 ? (unsigned char *)ctx + address * 8 : NULL;
}

int bb_aot_memory_verify(void) {
    uint64_t slots[3] = {0};
    const uint64_t alloc[] = {0, UINT64_C(1) << 30, GUEST_PAGE, 0, 0, 0};
    if (bb_aot_memory_call(BB_DIRECT_ALLOC, "rTXw65xmLIA#p#J", alloc, fixture_span, slots)) return 0;
    const uint64_t phys = slots[0];
    uint64_t mapping[] = {1, GUEST_PAGE, 3, 0, phys, 0};
    if (bb_aot_memory_call(BB_DIRECT_MAP, "L-Q3LEjIbgA#p#J", mapping, fixture_span, slots)) return 0;
    mapping[0] = 2;
    if (bb_aot_memory_call(BB_DIRECT_MAP, "L-Q3LEjIbgA#p#J", mapping, fixture_span, slots)) return 0;
    const uint64_t marker = UINT64_C(0xa87364ca1234f9bc);
    unsigned char *first = bb_aot_memory_span(slots[1], sizeof marker, 2);
    uint64_t value = 0;
    if (!first) return 0;
    memcpy(first, &marker, sizeof marker);
    if (uc_mem_read(guest, slots[2], &value, sizeof value) || value != marker) return 0;
    const uint64_t protect[6] = {slots[2], GUEST_PAGE, 1};
    if (bb_aot_memory_call(BB_MEMORY_PROTECT, "vSMAm3cxYTY#p#J", protect, fixture_span, slots) ||
        bb_aot_memory_span(slots[2], sizeof marker, 2) || !bb_aot_memory_span(slots[2], sizeof marker, 1))
        return 0;
    const uint64_t unmap[6] = {slots[1], GUEST_PAGE};
    if (bb_aot_memory_call(BB_MEMORY_UNMAP, "cQke9UuBQOk#p#J", unmap, fixture_span, slots) ||
        uc_mem_read(guest, slots[1], &value, sizeof value) != UC_ERR_READ_UNMAPPED)
        return 0;
    const uint64_t release[6] = {phys, GUEST_PAGE};
    if (bb_aot_memory_call(BB_DIRECT_RELEASE, "MBuItvba6z8#p#J", release, fixture_span, slots) ||
        uc_mem_read(guest, slots[2], &value, sizeof value) != UC_ERR_READ_UNMAPPED)
        return 0;
    if (mirror_error) return 0;
    puts("Direct-memory probe verified aliases, protection, unmap and release");
    return 1;
}
