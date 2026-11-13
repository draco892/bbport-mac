/* Complete common-state snapshots for bounded register-only GPR fixtures. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cpu_state_layout.h"
#include "gpr_functions.h"

#define DECLARE(name) extern void name(BbCpuState *);
GPR_FUNCTIONS(DECLARE)
#define ADDRESS(name) name,
static void (*functions[])(BbCpuState *) = { GPR_FUNCTIONS(ADDRESS) };

typedef struct { uint64_t control, status; } HostEnvironment;
static HostEnvironment read_host(void) {
    HostEnvironment v = {0, 0};
#if defined(__x86_64__)
    uint32_t mxcsr;
    __asm__ volatile("stmxcsr %0" : "=m"(mxcsr) :: "memory");
    v.control = mxcsr;
#elif defined(__aarch64__)
    __asm__ volatile("mrs %0, fpcr\n\tmrs %1, fpsr" : "=r"(v.control), "=r"(v.status) :: "memory");
#else
#error unsupported development host
#endif
    return v;
}
static void write_host(HostEnvironment v) {
#if defined(__x86_64__)
    uint32_t mxcsr = (uint32_t)v.control;
    __asm__ volatile("ldmxcsr %0" :: "m"(mxcsr) : "memory");
#else
    __asm__ volatile("msr fpcr, %0\n\tmsr fpsr, %1" :: "r"(v.control), "r"(v.status) : "memory");
#endif
}

int main(void) {
    const HostEnvironment original = read_host();
#if defined(__x86_64__)
    HostEnvironment seeded = {0x7fa1, 0};
#else
    HostEnvironment seeded = {0x400000, 0x15};
#endif
    BbCpuState input;
    unsigned long count = 0, inputs = 0;
    size_t bytes;
    while ((bytes = fread(&input, 1, sizeof input, stdin))) {
        if (bytes != sizeof input) return 3;
        for (size_t f = 0; f < sizeof functions / sizeof functions[0]; ++f) {
#if defined(__aarch64__)
            seeded.status = UINT64_C(0x15) | ((uint64_t)((inputs + f) & 1) << 27);
#endif
            write_host(seeded);
            struct { uint64_t head[2]; BbCpuState state; uint64_t tail[2]; } guarded = {
                {UINT64_C(0x1020304050607080), UINT64_C(0xfedcba9876543210)}, input,
                {UINT64_C(0x8877665544332211), UINT64_C(0x9876543210abcdef)}};
            functions[f](&guarded.state);
            const HostEnvironment after = read_host();
            assert(after.control == seeded.control && after.status == seeded.status);
            assert(guarded.head[0] == UINT64_C(0x1020304050607080));
            assert(guarded.head[1] == UINT64_C(0xfedcba9876543210));
            assert(guarded.tail[0] == UINT64_C(0x8877665544332211));
            assert(guarded.tail[1] == UINT64_C(0x9876543210abcdef));
            assert(!memcmp(guarded.state.xmm, input.xmm, sizeof input.xmm));
            assert(guarded.state.rip == input.rip);
            assert(!((guarded.state.rflags ^ input.rflags) & ~UINT64_C(0x8d5)));
            assert(guarded.state.mxcsr == input.mxcsr);
            assert(guarded.state.reserved == input.reserved);
            assert(guarded.state.status == 0);
            if (fwrite(&guarded.state, sizeof guarded.state, 1, stdout) != 1) return 5;
            ++count;
        }
        ++inputs;
    }
    write_host(original);
    fprintf(stderr, "PASS: %lu complete state snapshots from %lu inputs; guards, non-GPR state and host FP environment preserved\n", count, inputs);
    return ferror(stdin) || ferror(stdout);
}
