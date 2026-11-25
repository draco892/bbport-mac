#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cpu_state_layout.h"
#include "state_regions.h"

#define RETURN_ADDRESS UINT64_C(0x600010000)
#define CODE_BASE UINT64_C(0x600000000)
#define STACK_BASE UINT64_C(0x100000)
#define DECLARE(name) extern void entry_##name(BbCpuState *, BbGuestRegions *, BbGuestMemory *)
DECLARE(vector);
DECLARE(aligned);
DECLARE(exchange);
DECLARE(trap);
DECLARE(partial);
DECLARE(nested_trap);
DECLARE(scalar_copy);

static void initialize(BbCpuState *state, BbGuestMemory *stack, uint64_t words[8]) {
    *state = (BbCpuState){0};
    state->gpr[4] = STACK_BASE;
    state->rflags = 0x202;
    state->mxcsr = UINT32_MAX; /* Integer SIMD/MOV do not consult MXCSR. */
    words[0] = RETURN_ADDRESS;
    *stack = (BbGuestMemory){.bytes = (unsigned char *)words, .guest_base = STACK_BASE,
                             .byte_size = 64, .permissions = 3};
}

static void vectors(void) {
    unsigned char first[32], middle[32], third[1024];
    memset(first, 0xff, sizeof first);
    memset(middle, 0x55, sizeof middle);
    memset(third, 0xcc, sizeof third);
    BbGuestMemory regions[] = {
        {.bytes = first, .guest_base = 0x1000, .byte_size = sizeof first, .permissions = 1},
        {.bytes = middle, .guest_base = 0x1020, .byte_size = sizeof middle, .permissions = 1},
        {.bytes = third, .guest_base = 0x3000, .byte_size = sizeof third, .permissions = 3},
    };
    BbGuestRegions table = {.regions = regions, .count = 3};
    BbGuestMemory stack;
    BbCpuState cpu;
    uint64_t words[8] = {0};
    initialize(&cpu, &stack, words);
    cpu.gpr[7] = 0x1001;
    cpu.gpr[6] = 0x3201;
    cpu.xmm[9][0] = cpu.xmm[9][1] = UINT64_C(0x0202020202020202);
    entry_vector(&cpu, &table, &stack);
    assert(cpu.status == 0 && cpu.rip == RETURN_ADDRESS && cpu.gpr[4] == STACK_BASE + 8);
#if defined(__x86_64__)
    unsigned char native[16], addend[16];
    memset(addend, 2, sizeof addend);
    __asm__ volatile("movdqu (%1), %%xmm8; movdqu (%2), %%xmm9; paddb %%xmm9, %%xmm8; movdqu %%xmm8, (%0)"
                     :: "r"(native), "r"(first + 1), "r"(addend) : "xmm8", "xmm9", "memory");
    assert(!memcmp(third + 513, native, sizeof native));
#endif
    assert(cpu.xmm[8][0] == UINT64_C(0x0101010101010101) && cpu.xmm[8][1] == cpu.xmm[8][0]);
    assert(cpu.rflags == 0x202 && cpu.mxcsr == UINT32_MAX);
    for (size_t i = 0; i < sizeof third; ++i) assert(third[i] == (i >= 513 && i < 529 ? 1 : 0xcc));

    initialize(&cpu, &stack, words);
    cpu.gpr[7] = 0x1011; /* Crosses adjacent mappings by one byte. */
    cpu.xmm[8][0] = 42;
    entry_vector(&cpu, &table, &stack);
    assert(cpu.status == 1 && cpu.rip == CODE_BASE && cpu.xmm[8][0] == 42);
    assert(regions[0].fault_address == 0x1011 && regions[0].fault_offset == 0);

    initialize(&cpu, &stack, words);
    cpu.gpr[7] = 0x1020;
    cpu.gpr[6] = 0x1000; /* Read-only destination, prior XMM write commits. */
    entry_vector(&cpu, &table, &stack);
    assert(cpu.status == 3 && cpu.rip == CODE_BASE + 10);
    assert(cpu.xmm[8][0] == UINT64_C(0x5555555555555555));
    assert(regions[0].fault_address == 0x1000 && regions[0].fault_offset == 10);

    initialize(&cpu, &stack, words);
    cpu.gpr[7] = 0x1001;
    cpu.xmm[8][0] = 42;
    entry_aligned(&cpu, &table, &stack);
    assert(cpu.status == 8 && cpu.rip == CODE_BASE + 256 && cpu.xmm[8][0] == 42);
    cpu.gpr[7] = 0x1020;
    entry_aligned(&cpu, &table, &stack);
    assert(cpu.status == 0 && cpu.xmm[8][0] == UINT64_C(0x5555555555555555));

    initialize(&cpu, &stack, words);
    cpu.gpr[7] = 0x2000;
    entry_aligned(&cpu, &table, &stack);
    assert(cpu.status == 1 && table.unmapped.fault_address == 0x2000);

    initialize(&cpu, &stack, words);
    cpu.gpr[7] = 0x1020;
    cpu.gpr[6] = 0x33f8;
    entry_scalar_copy(&cpu, &table, &stack);
    assert(cpu.status == 0 && cpu.gpr[0] == UINT64_C(0x5555555555555555));
    for (size_t i = 1016; i < sizeof third; ++i) assert(third[i] == 0x55);

    initialize(&cpu, &stack, words);
    regions[1].guest_base = 0x1010;
    cpu.rip = 123;
    entry_vector(&cpu, &table, &stack);
    assert(cpu.status == 2 && cpu.rip == 123 && cpu.gpr[4] == STACK_BASE);
    regions[1].guest_base = 0x1020;
    regions[2].guest_base = STACK_BASE - 1;
    entry_vector(&cpu, &table, &stack);
    assert(cpu.status == 2 && cpu.rip == 123);
}

enum { THREADS = 4, EXCHANGES = 1024 };
static uint64_t cell;
static uint64_t observed[THREADS][EXCHANGES];

static void *exchange_worker(void *arg) {
    unsigned id = *(unsigned *)arg;
    BbGuestMemory region = {.bytes = (unsigned char *)&cell, .guest_base = 0x2000,
                            .byte_size = 8, .permissions = 3};
    BbGuestRegions table = {.regions = &region, .count = 1};
    BbCpuState cpu;
    BbGuestMemory stack;
    uint64_t words[8] = {0};
    for (unsigned i = 0; i < EXCHANGES; ++i) {
        initialize(&cpu, &stack, words);
        cpu.gpr[7] = 0x2000;
        cpu.gpr[0] = (uint64_t)id * EXCHANGES + i + 1;
        entry_exchange(&cpu, &table, &stack);
        assert(cpu.status == 0 && cpu.rflags == 0x202);
        observed[id][i] = cpu.gpr[0];
    }
    return NULL;
}

static void atomics(void) {
    pthread_t threads[THREADS];
    unsigned ids[THREADS];
    for (unsigned i = 0; i < THREADS; ++i) {
        ids[i] = i;
        assert(pthread_create(&threads[i], NULL, exchange_worker, &ids[i]) == 0);
    }
    for (unsigned i = 0; i < THREADS; ++i) assert(pthread_join(threads[i], NULL) == 0);
    unsigned char seen[THREADS * EXCHANGES + 1] = {0};
    assert(cell <= THREADS * EXCHANGES);
    seen[cell] = 1;
    for (unsigned i = 0; i < THREADS; ++i) {
        for (unsigned j = 0; j < EXCHANGES; ++j) {
            uint64_t old = observed[i][j];
            assert(old <= THREADS * EXCHANGES && !seen[old]);
            seen[old] = 1;
        }
    }
    for (unsigned i = 0; i <= THREADS * EXCHANGES; ++i) assert(seen[i]);

    uint64_t data[2] = {7, 9}, words[8] = {0};
    BbGuestMemory region = {.bytes = (unsigned char *)data, .guest_base = 0x2000,
                            .byte_size = 16, .permissions = 2};
    BbGuestRegions table = {.regions = &region, .count = 1};
    BbGuestMemory stack;
    BbCpuState cpu;
    initialize(&cpu, &stack, words);
    cpu.gpr[0] = 4;
    cpu.gpr[7] = 0x2000;
    entry_exchange(&cpu, &table, &stack);
    assert(cpu.status == 3 && cpu.gpr[0] == 4 && data[0] == 7);
    region.permissions = 1;
    entry_exchange(&cpu, &table, &stack);
    assert(cpu.status == 3 && cpu.gpr[0] == 4 && data[0] == 7);
    region.permissions = 3;
    cpu.gpr[7] = 0x2001;
    entry_exchange(&cpu, &table, &stack);
    assert(cpu.status == 8 && cpu.gpr[0] == 4 && data[0] == 7 && data[1] == 9);
    cpu.gpr[7] = 0x2000;
    region.bytes++;
    region.byte_size = 8;
    entry_exchange(&cpu, &table, &stack);
    assert(cpu.status == 8 && cpu.gpr[0] == 4 && data[0] == 7 && data[1] == 9);
}

static void exceptions_and_partial_registers(void) {
    BbGuestRegions table = {0};
    BbGuestMemory stack;
    BbCpuState cpu;
    uint64_t words[8] = {0};
    initialize(&cpu, &stack, words);
    cpu.gpr[0] = 10;
    entry_trap(&cpu, &table, &stack);
    assert(cpu.status == 9 && cpu.rip == CODE_BASE + 3 * 256 + 3);
    assert(cpu.gpr[0] == 11 && cpu.gpr[4] == STACK_BASE);
    assert(words[0] == RETURN_ADDRESS);

    initialize(&cpu, &stack, words);
    cpu.gpr[4] = STACK_BASE + 16;
    words[2] = RETURN_ADDRESS;
    entry_nested_trap(&cpu, &table, &stack);
    assert(cpu.status == 9 && cpu.rip == CODE_BASE + 3 * 256 + 3);
    assert(cpu.gpr[0] == 1 && cpu.gpr[4] == STACK_BASE + 8);
    assert(words[1] == CODE_BASE + 5 * 256 + 5 && words[2] == RETURN_ADDRESS);

    initialize(&cpu, &stack, words);
    cpu.gpr[8] = UINT64_C(0x112233445566ff7f);
    cpu.gpr[9] = 1;
    entry_partial(&cpu, &table, &stack);
    assert(cpu.status == 0 && cpu.gpr[8] == UINT64_C(0x112233445566ff81));
    assert((cpu.rflags & 0x8d5) == 0x84);
}

int main(void) {
    vectors();
    atomics();
    exceptions_and_partial_registers();
    puts("PASS: mixed SIMD/GPR, region faults, precise UD2 and 4096 concurrent atomic exchanges");
    return 0;
}
