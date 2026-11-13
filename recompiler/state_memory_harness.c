#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef ORIGINAL
#include <sys/mman.h>
#include <unistd.h>
#endif
#include "cpu_state_layout.h"
#include "guest_memory.h"
#include "state_memory_functions.h"

typedef struct {
    BbCpuState state;
    uint64_t base, size, permissions, null_data;
    unsigned char bytes[96];
} Input;
_Static_assert(sizeof(Input) == 544, "input record size");
_Static_assert(offsetof(Input, bytes) == 448, "input memory offset");
#define DECLARE(name) extern void name(BbCpuState *, BbGuestMemory *);
STATE_MEMORY_FUNCTIONS(DECLARE)
#define ADDRESS(name) name,
static void (*functions[])(BbCpuState *, BbGuestMemory *) = {STATE_MEMORY_FUNCTIONS(ADDRESS)};

typedef struct { uint64_t control, status; } HostEnvironment;
static HostEnvironment read_host(void) {
    HostEnvironment result = {0, 0};
#if defined(__x86_64__)
    uint32_t value;
    __asm__ volatile("stmxcsr %0" : "=m"(value) :: "memory");
    result.control = value;
#else
    __asm__ volatile("mrs %0, fpcr\n\tmrs %1, fpsr" : "=r"(result.control), "=r"(result.status) :: "memory");
#endif
    return result;
}
static void write_host(HostEnvironment value) {
#if defined(__x86_64__)
    uint32_t control = (uint32_t)value.control;
    __asm__ volatile("ldmxcsr %0" :: "m"(control) : "memory");
#else
    __asm__ volatile("msr fpcr, %0\n\tmsr fpsr, %1" :: "r"(value.control), "r"(value.status) : "memory");
#endif
}

int main(void) {
    const uint64_t bases[2] = {UINT64_C(0x200000010), UINT64_C(0x400000010)};
    unsigned char local[96];
    unsigned char *arenas[2] = {local, local};
#ifdef ORIGINAL
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    for (unsigned i = 0; i < 2; ++i) {
        void *requested = (void *)(uintptr_t)(bases[i] - 16);
        void *mapped = mmap(requested, page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
        /* A hint is verified, never MAP_FIXED: do not overwrite other mappings. */
        if (mapped == MAP_FAILED) return 7;
        if (mapped != requested) { munmap(mapped, page); return 8; }
        arenas[i] = mapped;
    }
#endif
    const HostEnvironment original = read_host();
#if defined(__x86_64__)
    HostEnvironment seeded = {0x7fa1, 0};
#else
    HostEnvironment seeded = {0x400000, 0x15};
#endif
    Input input;
    size_t bytes;
    unsigned long snapshots = 0, inputs = 0, faults[4] = {0, 0, 0, 0};
    while ((bytes = fread(&input, 1, sizeof input, stdin))) {
        if (bytes != sizeof input) return 3;
        if (input.null_data > 1) return 4;
#ifdef ORIGINAL
        if (input.size && input.size <= 64 && input.base <= UINT64_MAX - input.size &&
            input.permissions <= 3 && !input.null_data && input.base != bases[0] && input.base != bases[1]) return 9;
#endif
        for (size_t f = 0; f < sizeof functions / sizeof functions[0]; ++f) {
            unsigned char *arena = arenas[input.base == bases[1]];
            memcpy(arena, input.bytes, sizeof input.bytes);
            struct { uint64_t head[2]; BbCpuState state; uint64_t tail[2]; } guarded = {
                {UINT64_C(0x1020304050607080), UINT64_C(0xfedcba9876543210)}, input.state,
                {UINT64_C(0x8877665544332211), UINT64_C(0x9876543210abcdef)}};
            struct { uint64_t head; BbGuestMemory mapping; uint64_t tail; } context = {
                UINT64_C(0x123456789abcdef0),
                {input.null_data ? NULL : arena + 16, input.base, input.size, input.permissions,
                 UINT64_C(0xdeadbeefdeadbeef), UINT64_C(0xfeedfacefeedface)}, UINT64_C(0xfedcba9876543210)};
#if defined(__aarch64__)
            seeded.status = UINT64_C(0x15) | ((uint64_t)((inputs + f) & 1) << 27);
#endif
            write_host(seeded);
            functions[f](&guarded.state, &context.mapping);
            HostEnvironment after = read_host();
            assert(after.control == seeded.control && after.status == seeded.status);
            assert(guarded.head[0] == UINT64_C(0x1020304050607080));
            assert(guarded.head[1] == UINT64_C(0xfedcba9876543210));
            assert(guarded.tail[0] == UINT64_C(0x8877665544332211));
            assert(guarded.tail[1] == UINT64_C(0x9876543210abcdef));
            assert(!memcmp(guarded.state.xmm, input.state.xmm, sizeof input.state.xmm));
            assert(guarded.state.rip == input.state.rip);
            assert(guarded.state.mxcsr == input.state.mxcsr);
            assert(!((guarded.state.rflags ^ input.state.rflags) & ~UINT64_C(0x8d5)));
            assert(guarded.state.reserved == input.state.reserved);
            assert(context.head == UINT64_C(0x123456789abcdef0));
            assert(context.tail == UINT64_C(0xfedcba9876543210));
            assert(context.mapping.bytes == (input.null_data ? NULL : arena + 16));
            assert(context.mapping.guest_base == input.base && context.mapping.byte_size == input.size);
            assert(context.mapping.permissions == input.permissions);
            assert(!memcmp(arena, input.bytes, 16) && !memcmp(arena + 80, input.bytes + 80, 16));
            assert(guarded.state.status <= 3);
            ++faults[guarded.state.status];
            if (fwrite(&guarded.state, sizeof guarded.state, 1, stdout) != 1 ||
                fwrite(&context.mapping.fault_address, 16, 1, stdout) != 1 ||
                fwrite(arena, 96, 1, stdout) != 1) return 5;
            ++snapshots;
        }
        ++inputs;
    }
    write_host(original);
#ifdef ORIGINAL
    for (unsigned i = 0; i < 2; ++i) munmap(arenas[i], page);
#endif
    fprintf(stderr, "PASS: %lu full CPU/memory snapshots from %lu inputs; success=%lu bounds=%lu descriptor=%lu denied=%lu; guards and host FP preserved\n",
            snapshots, inputs, faults[0], faults[1], faults[2], faults[3]);
    return ferror(stdin) || ferror(stdout);
}
