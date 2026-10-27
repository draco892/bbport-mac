/* No host floating-point calculations: inputs and outputs are exact bit patterns. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "simd_functions.h"

typedef struct {
    uint64_t xmm[2][2];
    uint32_t mxcsr, status;
    uint64_t reserved;
} State;
_Static_assert(sizeof(State) == 48 && offsetof(State, mxcsr) == 32 &&
               offsetof(State, status) == 36, "guest-state layout");
typedef void (*Function)(State *);
#define DECLARE(name) extern void name(State *);
SIMD_FUNCTIONS(DECLARE)
#undef DECLARE
#define ADDRESS(name) name,
static Function functions[] = {SIMD_FUNCTIONS(ADDRESS)};
#undef ADDRESS

typedef struct { uint64_t a, b; } HostEnvironment;
static HostEnvironment read_host(void) {
    HostEnvironment v = {0, 0};
#if defined(__x86_64__)
    uint32_t mxcsr;
    __asm__ volatile("stmxcsr %0" : "=m"(mxcsr) :: "memory");
    v.a = mxcsr;
#elif defined(__aarch64__)
    __asm__ volatile("mrs %0, fpcr\n\tmrs %1, fpsr" : "=r"(v.a), "=r"(v.b) :: "memory");
#else
#error unsupported test host
#endif
    return v;
}
static void write_host(HostEnvironment v) {
#if defined(__x86_64__)
    uint32_t mxcsr = (uint32_t)v.a;
    __asm__ volatile("ldmxcsr %0" :: "m"(mxcsr) : "memory");
#else
    __asm__ volatile("msr fpcr, %0\n\tmsr fpsr, %1" :: "r"(v.a), "r"(v.b) : "memory");
#endif
}

int main(int argc, char **argv) {
    const HostEnvironment original = read_host();
#if defined(__x86_64__)
    const HostEnvironment seeded = {0x7fa1, 0};
#else
    const HostEnvironment seeded = {0x400000, 0x15};
#endif
    write_host(seeded);
    State input;
    unsigned long count = 0;
    const int negative = argc == 2 && !strcmp(argv[1], "--negative");
    if (argc > 1 && !negative) return 2;
    const uint32_t invalid[] = {0, 0x1f00, 0x1e80, 0x0f80, 0x11f80, 0x80001f80};
    size_t invalid_index = 0;
    for (;;) {
        if (negative) {
#ifdef ORIGINAL
            return 2; /* Never execute invalid FP modes as the x86 reference. */
#endif
            if (invalid_index == sizeof invalid / sizeof invalid[0]) break;
            memset(&input, 0xa5, sizeof input);
            input.mxcsr = invalid[invalid_index++];
        } else {
            const size_t bytes = fread(&input, 1, sizeof input, stdin);
            if (!bytes) break;
            if (bytes != sizeof input) return 3;
            if ((input.mxcsr & ~0xffffu) || (input.mxcsr & 0x1f80u) != 0x1f80u) return 4;
        }
        for (size_t f = 0; f < sizeof functions / sizeof functions[0]; ++f) {
            struct { uint64_t head[2]; State state; uint64_t tail[2]; } guarded = {
                {UINT64_C(0x1020304050607080), UINT64_C(0xfedcba9876543210)}, input,
                {UINT64_C(0x8877665544332211), UINT64_C(0x9876543210abcdef)}};
            functions[f](&guarded.state);
            const HostEnvironment after = read_host();
            assert(after.a == seeded.a && after.b == seeded.b);
            assert(guarded.head[0] == UINT64_C(0x1020304050607080));
            assert(guarded.head[1] == UINT64_C(0xfedcba9876543210));
            assert(guarded.tail[0] == UINT64_C(0x8877665544332211));
            assert(guarded.tail[1] == UINT64_C(0x9876543210abcdef));
            assert(guarded.state.reserved == input.reserved);
            if (negative) {
                State expected = input;
                expected.status = 1;
                assert(!memcmp(&expected, &guarded.state, sizeof expected));
            } else {
                assert(guarded.state.status == 0);
                if (fwrite(&guarded.state, sizeof guarded.state, 1, stdout) != 1) return 5;
            }
            ++count;
        }
    }
    write_host(original);
    fprintf(stderr, "PASS: %lu %s snapshots; state guards and host FP environment preserved\n",
            count, negative ? "rejection" : "valid");
    return ferror(stdin) || ferror(stdout);
}
