/* Differential harness for one allowlisted module import and RIP-relative fixtures. */
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include "cpu_state_layout.h"
#include "state_regions.h"
#include "runtime.h"
#include "real_nonleaf_image.h"
#ifdef ORIGINAL
#include <sys/mman.h>
#include <unistd.h>
#endif

#define DATA UINT64_C(0x400000000)
#define STACK (DATA + UINT64_C(0x10000))
#define TOKEN UINT64_C(0x700000001000)
#define FLAGS UINT64_C(0x8d5)

typedef struct GuestCond GuestCond;
static unsigned calls;
static int force_error;
#ifdef ORIGINAL
static BbGuestRegions *native_regions;
extern void native_fios_cond(BbCpuState *);
extern void native_rip_call(BbCpuState *);
extern void ss_native_capture(void);
extern void ss_native_import(void);
#else
extern void entry_fios_cond(BbCpuState *, BbGuestRegions *, BbGuestMemory *);
extern void entry_rip_call(BbCpuState *, BbGuestRegions *, BbGuestMemory *);
#endif

void runtime_wait_note(int kind, uint64_t ns) {
    (void)kind;
    (void)ns;
    assert(0 && "condition initialization must not wait");
}

static void put64(unsigned char *where, uint64_t value) { memcpy(where, &value, sizeof value); }
static uint64_t get64(const unsigned char *where) {
    uint64_t value;
    memcpy(&value, where, sizeof value);
    return value;
}

static unsigned char *guest_bytes(const BbGuestRegions *table, uint64_t address,
                                 size_t length, uint64_t permission) {
    for (uint64_t i = 0; i < table->count; ++i) {
        const BbGuestMemory *region = &table->regions[i];
        if (address < region->guest_base || length > region->byte_size ||
            address - region->guest_base > region->byte_size - length)
            continue;
        if ((region->permissions & permission) == permission)
            return region->bytes + (address - region->guest_base);
    }
    return NULL;
}

static int32_t cond_import(BbGuestRegions *table, uint64_t dst, uint64_t attr, uint64_t name) {
    ++calls;
    assert(dst == DATA && attr == 0 && name == NAME_ADDRESS);
    unsigned char *out = guest_bytes(table, dst, 8, 2);
    const char *str = (const char *)guest_bytes(table, name, sizeof module_name, 1);
    assert(out && str && !memcmp(str, module_name, sizeof module_name));

    int32_t (ABI *init)(GuestCond **, void **, const char *) =
        (void *)runtime_mutex_resolve(COND_INIT_NID);
    int32_t (ABI *destroy)(GuestCond **) = (void *)runtime_mutex_resolve("g+PZd2hiacg");
    assert(init && destroy);
    GuestCond *handle = NULL;
    const int32_t result = init(force_error ? NULL : &handle, NULL, str);
    if (!result) {
        assert(handle);
        /* The real handle is host-local. Compare a stable token in guest memory. */
        put64(out, TOKEN);
        assert(!destroy(&handle) && !handle);
    }
    return result;
}

#ifdef ORIGINAL
int32_t ss_native_import_c(uint64_t dst, uint64_t attr, uint64_t name) {
    return cond_import(native_regions, dst, attr, name);
}

static unsigned char *map_at(uint64_t address, size_t size) {
    unsigned char *buffer = mmap((void *)(uintptr_t)address, size, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(buffer != MAP_FAILED && (uintptr_t)buffer == address);
    return buffer;
}
#else
void bb_state_host_import(BbCpuState *state, BbGuestRegions *table, uint64_t target) {
    assert(target == PLT_OFFSET);
    /* An int32 return occupies EAX; only the ABI-defined result is compared. */
    state->gpr[0] = (uint32_t)cond_import(table, state->gpr[7], state->gpr[6], state->gpr[2]);
}
#endif

static BbCpuState input(uint64_t argument, unsigned offset, unsigned char *stack) {
    memset(stack, 0xa5, 512);
    put64(stack + 504, RETURN_ADDRESS);
    BbCpuState cpu = {.rip = IMAGE_BASE + offset, .rflags = 0x202};
    for (unsigned i = 0; i < 16; ++i)
        cpu.gpr[i] = UINT64_C(0x8123456789abcdef) ^ (argument + i);
    cpu.gpr[4] = STACK + 504;
    cpu.gpr[6] = argument;
    cpu.gpr[7] = DATA;
    return cpu;
}

static void check_return(const BbCpuState *before, const BbCpuState *after) {
    const unsigned preserved[] = {3, 5, 12, 13, 14, 15};
    assert(after->status == 0 && after->rip == RETURN_ADDRESS && after->gpr[4] == STACK + 512);
    for (size_t i = 0; i < sizeof preserved / sizeof preserved[0]; ++i)
        assert(before->gpr[preserved[i]] == after->gpr[preserved[i]]);
}

int main(void) {
    unsigned char local_data[16], local_stack[512];
    unsigned char *data = local_data, *stack = local_stack;
    unsigned char name[sizeof module_name];
    memcpy(name, module_name, sizeof name);
    unsigned char slot[16];
    put64(slot, UINT64_C(0xdedcba9876543210));
    put64(slot + 8, IMAGE_BASE + RIP_CALLEE_OFFSET);
#ifdef ORIGINAL
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    data = map_at(DATA, page);
    stack = map_at(STACK, page);
    const size_t image_size = (RETURN_OFFSET + 14 + page - 1) / page * page;
    unsigned char *image = map_at(IMAGE_BASE, image_size);
    memset(image, 0xcc, image_size);
    memcpy(image + FUNCTION_OFFSET, module_function, sizeof module_function);
    memcpy(image + PLT_OFFSET, module_plt, sizeof module_plt);
    memcpy(image + RIP_CALL_OFFSET, rip_call_code, sizeof rip_call_code);
    memcpy(image + RIP_CALLEE_OFFSET, rip_callee_code, sizeof rip_callee_code);
    memcpy(image + RIP_SLOT_OFFSET, slot, sizeof slot);
    memcpy(image + NAME_OFFSET, name, sizeof name);
    put64(image + GOT_OFFSET, (uintptr_t)ss_native_import);
    memcpy(image + RETURN_OFFSET, "\xff\x25\x00\x00\x00\x00", 6);
    put64(image + RETURN_OFFSET + 6, (uintptr_t)ss_native_capture);
    assert(mprotect(image, image_size, PROT_READ | PROT_EXEC) == 0);
#endif

    BbGuestMemory regions[] = {
        {.bytes = data, .guest_base = DATA, .byte_size = 16, .permissions = 3},
        {.bytes = slot, .guest_base = IMAGE_BASE + RIP_SLOT_OFFSET, .byte_size = sizeof slot, .permissions = 1},
        {.bytes = name, .guest_base = NAME_ADDRESS, .byte_size = sizeof name, .permissions = 1},
    };
    BbGuestRegions table = {.regions = regions, .count = sizeof regions / sizeof regions[0]};
#ifdef ORIGINAL
    native_regions = &table;
#else
    BbGuestMemory stack_region = {.bytes = stack, .guest_base = STACK, .byte_size = 512, .permissions = 3};
#endif
    const uint64_t arguments[] = {0, 1, UINT64_C(0x8000000000000000), UINT64_MAX};
    for (unsigned i = 0; i < sizeof arguments / sizeof arguments[0]; ++i) {
        memset(data, 0x5a, 16);
        const BbCpuState before = input(arguments[i], FUNCTION_OFFSET, stack);
        BbCpuState cpu = before;
        calls = 0;
#ifdef ORIGINAL
        native_fios_cond(&cpu);
#else
        entry_fios_cond(&cpu, &table, &stack_region);
#endif
        check_return(&before, &cpu);
        assert(calls == 1 && cpu.gpr[0] == 0 && (cpu.rflags & FLAGS) == 0x44);
        assert(get64(data) == TOKEN && get64(data + 8) == arguments[i]);
        assert(get64(stack + 488) == IMAGE_BASE + CONTINUATION_OFFSET);
        assert(get64(stack + 496) == before.gpr[5] && get64(stack + 504) == RETURN_ADDRESS);
        printf("fios[%u] rax=%" PRIx64 " rsp=%" PRIx64 " rip=%" PRIx64 " flags=%" PRIx64
               " data=%" PRIx64 ",%" PRIx64 " stack=%" PRIx64 ",%" PRIx64 ",%" PRIx64 "\n",
               i, cpu.gpr[0], cpu.gpr[4], cpu.rip, cpu.rflags & FLAGS, get64(data),
               get64(data + 8), get64(stack + 488), get64(stack + 496), get64(stack + 504));
    }

    const BbCpuState before = input(0, RIP_CALL_OFFSET, stack);
    BbCpuState cpu = before;
#ifdef ORIGINAL
    native_rip_call(&cpu);
#else
    entry_rip_call(&cpu, &table, &stack_region);
#endif
    check_return(&before, &cpu);
    assert(cpu.gpr[0] == (get64(slot) ^ UINT64_C(0xffffffffffffff80)));
    assert(cpu.gpr[8] == UINT64_C(0xfedcba97f6543210) && cpu.gpr[9] == UINT64_C(0x62fc962f));
    assert(get64(stack + 496) == IMAGE_BASE + RIP_CALL_OFFSET + 13);
    printf("rip_call rax=%" PRIx64 " r8=%" PRIx64 " r9=%" PRIx64 " flags=%" PRIx64 " return=%" PRIx64 "\n",
           cpu.gpr[0], cpu.gpr[8], cpu.gpr[9], cpu.rflags & FLAGS, get64(stack + 496));

#ifndef ORIGINAL
    /* Only AOT takes faulting paths here. The original success path uses real x86. */
    put64(slot + 8, IMAGE_BASE + RIP_CALLEE_OFFSET + 1);
    cpu = input(0, RIP_CALL_OFFSET, stack);
    entry_rip_call(&cpu, &table, &stack_region);
    assert(cpu.status == 5 && stack_region.fault_address == get64(slot + 8));
    regions[1].permissions = 0;
    cpu = input(0, RIP_CALL_OFFSET, stack);
    entry_rip_call(&cpu, &table, &stack_region);
    assert(cpu.status == 3 && regions[1].fault_address == IMAGE_BASE + RIP_SLOT_OFFSET);
    memset(data, 0x5a, 16);
    force_error = 1;
    cpu = input(42, FUNCTION_OFFSET, stack);
    calls = 0;
    entry_fios_cond(&cpu, &table, &stack_region);
    assert(cpu.status == 9 && cpu.rip == IMAGE_BASE + TRAP_OFFSET && calls == 1);
    assert(get64(data) == UINT64_C(0x5a5a5a5a5a5a5a5a) && get64(data + 8) == 42);
    regions[0].permissions = 1;
    cpu = input(43, FUNCTION_OFFSET, stack);
    calls = 0;
    entry_fios_cond(&cpu, &table, &stack_region);
    assert(cpu.status == 3 && cpu.rip == IMAGE_BASE + STORE_OFFSET && !calls && get64(data + 8) == 42);
    fputs("ARM64 checked failures: 4\n", stderr);
#endif
    return 0;
}
