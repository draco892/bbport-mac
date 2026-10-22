/* Fixed guest code addresses in the x86 reference; explicit resolution in AOT. */
#define _DARWIN_C_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef ORIGINAL
#include <sys/mman.h>
#include <unistd.h>
#endif

#define STACK_BYTES 512
#define ROOT_RETURN UINT64_C(0xfffffffffffffff0)
#define RBX_SEED UINT64_C(0x1122334455667788)
#define RBP_SEED UINT64_C(0x8877665544332211)
typedef struct { uint64_t rax, b, rbx, rbp, sp, error, fault_address; } Cpu;
_Static_assert(sizeof(Cpu) == 56, "LLVM CPU layout");
#include "entries.h"

#ifdef ORIGINAL
extern void stack_original_call(void (*)(void), unsigned char *, uint64_t, Cpu *);
#else
extern void *resolve_guest_code(uint64_t);
#endif

static void put64(unsigned char *where, uint64_t value) {
    memcpy(where, &value, sizeof(value));
}

static int invoke(unsigned index, uint64_t a, uint64_t b, uint64_t first, uint64_t second,
                  uint64_t expected_error, int print) {
    _Alignas(16) unsigned char memory[96], before[96], guarded_stack[STACK_BYTES + 32];
    for (unsigned i = 0; i < sizeof(memory); ++i)
        memory[i] = (unsigned char)((a >> (8 * (i % 8))) ^ (b >> (8 * ((i + 3) % 8))) ^ (i * 37));
    put64(memory + 16, a);
    put64(memory + 16 + 32, first);
    put64(memory + 16 + 40, second);
    memcpy(before, memory, sizeof(memory));
    memset(guarded_stack, 0xa5, sizeof(guarded_stack));
    Cpu cpu = {0, b, RBX_SEED, RBP_SEED, 0, 0, 0};
#ifdef ORIGINAL
    stack_original_call((void (*)(void))(uintptr_t)(CODE_BASE + entry_offsets[index]), memory + 16, b, &cpu);
#else
    unsigned char *stack = guarded_stack + 16;
    cpu.sp = STACK_BYTES - 8;
    put64(stack + cpu.sp, ROOT_RETURN);
    entries[index](&cpu, memory + 16, stack, ROOT_RETURN);
    cpu.sp -= STACK_BYTES;
    for (unsigned i = 0; i < 16; ++i)
        if (guarded_stack[i] != 0xa5 || guarded_stack[16 + STACK_BYTES + i] != 0xa5) return 3;
#endif
    if (cpu.sp || cpu.rbx != RBX_SEED || cpu.rbp != RBP_SEED) return 4;
    if (memcmp(before, memory, 16) || memcmp(before + 80, memory + 80, 16)) return 5;
    if (cpu.error != expected_error || (cpu.error && cpu.fault_address != first)) return 6;
    /* Negative roots have no guest writes before the rejected call. */
    if (expected_error && memcmp(before, memory, sizeof(memory))) return 7;
    if (!expected_error && cpu.fault_address) return 8;
    if (print) {
        printf("%016" PRIx64 ":%016" PRIx64 ":%016" PRIx64 ":%016" PRIx64 ":%016" PRIx64 ":",
               cpu.rax, cpu.b, cpu.rbx, cpu.rbp, cpu.sp);
        for (unsigned i = 0; i < sizeof(memory); ++i) printf("%02x", memory[i]);
        putchar('\n');
    }
    return 0;
}

int main(int argc, char **argv) {
#ifdef ORIGINAL
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    const size_t size = (sizeof(original_image) + page - 1) / page * page;
    /* A hint, not MAP_FIXED: fail rather than replace any existing mapping. */
    void *image = mmap((void *)(uintptr_t)CODE_BASE, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON, -1, 0);
    if (image == MAP_FAILED) { perror("guest code mmap"); return 10; }
    if ((uintptr_t)image != CODE_BASE) {
        munmap(image, size);
        fprintf(stderr, "guest code address %#" PRIx64 " unavailable (mmap returned %p)\n",
                CODE_BASE, image);
        return 11;
    }
    memcpy(image, original_image, sizeof(original_image));
    if (mprotect(image, size, PROT_READ | PROT_EXEC)) { perror("guest code mprotect"); return 12; }
    if (argc != 1) return 13;
#else
    for (unsigned i = 0; i < ENTRY_COUNT; ++i) {
        uint64_t guest = CODE_BASE + entry_offsets[i];
        void *native = resolve_guest_code(guest);
        if (!native || (uintptr_t)native == guest || resolve_guest_code(guest + 1)) return 14;
    }
    if (resolve_guest_code(0)) return 15;
    if (argc == 2 && strcmp(argv[1], "--negative") == 0) {
        const uint64_t targets[] = {0, CODE_BASE + 0x100000, leaf_targets[0] + 1,
                                   CODE_BASE + entry_offsets[CALL_RAX_INDEX],
                                   (uint64_t)(uintptr_t)resolve_guest_code(leaf_targets[0])};
        unsigned count = 0;
        const unsigned roots[] = {CALL_RAX_INDEX, FAILURE_CHAIN_INDEX};
        for (unsigned r = 0; r < sizeof(roots) / sizeof(roots[0]); ++r)
            for (unsigned i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i) {
                int result = invoke(roots[r], 3, 7, targets[i], leaf_targets[1], i == 3 ? 2 : 1, 0);
                if (result) { fprintf(stderr, "negative root %u target %u failed: %d\n", r, i, result); return result; }
                ++count;
            }
        printf("PASS: %u invalid-target checks; stack/register restoration and unchanged memory\n", count);
        return 0;
    }
    if (argc != 1) return 16;
#endif
    uint64_t a, b;
    while (scanf("%" SCNx64 " %" SCNx64, &a, &b) == 2)
        for (unsigned first = 0; first < LEAF_COUNT; ++first)
            for (unsigned second = 0; second < LEAF_COUNT; ++second)
                for (unsigned f = 0; f < ENTRY_COUNT; ++f) {
                    int result = invoke(f, a, b, leaf_targets[first], leaf_targets[second], 0, 1);
                    if (result) { fprintf(stderr, "entry %u failed: %d\n", f, result); return result; }
                }
    return ferror(stdin) || ferror(stdout);
}
