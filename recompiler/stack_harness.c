/* Synthetic differential harness; no game files or runtime are loaded. */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define STACK_BYTES 512
#define RBX_SEED UINT64_C(0x1122334455667788)
#define RBP_SEED UINT64_C(0x8877665544332211)
#define ROOT_RETURN UINT64_C(0xfffffffffffffff0)
typedef struct { uint64_t rax, b, rbx, rbp, sp; } Cpu;
_Static_assert(sizeof(Cpu) == 40, "LLVM CPU layout");

/* The runner generates declarations and entry tables from the fixture map. */
#include "entries.h"

#ifdef ORIGINAL
extern void stack_original_call(void (*entry)(void), unsigned char *, uint64_t, Cpu *);
#endif

int main(void) {
    uint64_t a, b;
    while (scanf("%" SCNx64 " %" SCNx64, &a, &b) == 2) {
        for (unsigned f = 0; f < sizeof(entries) / sizeof(entries[0]); ++f) {
            _Alignas(16) unsigned char memory[96], before[96], guarded_stack[STACK_BYTES + 32];
            for (unsigned i = 0; i < sizeof(memory); ++i)
                memory[i] = (unsigned char)((a >> (8 * (i % 8))) ^
                    (b >> (8 * ((i + 3) % 8))) ^ (i * 37));
            for (unsigned i = 0; i < 8; ++i) memory[16 + i] = (unsigned char)(a >> (8 * i));
            memcpy(before, memory, sizeof(memory));
            memset(guarded_stack, 0xa5, sizeof(guarded_stack));
            Cpu cpu = {0, b, RBX_SEED, RBP_SEED, 0};
#ifdef ORIGINAL
            /* The bridge records real x86 RSP delta, RBX and RBP after CALL/RET. */
            stack_original_call(entries[f], memory + 16, b, &cpu);
#else
            unsigned char *stack = guarded_stack + 16;
            cpu.sp = STACK_BYTES - 8;
            uint64_t token = ROOT_RETURN;
            memcpy(stack + cpu.sp, &token, sizeof(token));
            entries[f](&cpu, memory + 16, stack, ROOT_RETURN);
            cpu.sp -= STACK_BYTES; /* Normalize to the original bridge's RSP delta. */
            for (unsigned i = 0; i < 16; ++i) {
                if (guarded_stack[i] != 0xa5 || guarded_stack[16 + STACK_BYTES + i] != 0xa5) {
                    fprintf(stderr, "translated stack guard corruption in fixture %u\n", f);
                    return 3;
                }
            }
#endif
            if (cpu.sp || cpu.rbx != RBX_SEED || cpu.rbp != RBP_SEED) {
                fprintf(stderr, "unbalanced stack or callee-saved registers in fixture %u\n", f);
                return 4;
            }
            if (memcmp(before, memory, 16) || memcmp(before + 80, memory + 80, 16)) {
                fprintf(stderr, "guest memory guard corruption in fixture %u\n", f);
                return 5;
            }
            printf("%016" PRIx64 ":%016" PRIx64 ":%016" PRIx64 ":%016" PRIx64 ":%016" PRIx64 ":",
                   cpu.rax, cpu.b, cpu.rbx, cpu.rbp, cpu.sp);
            for (unsigned i = 0; i < sizeof(memory); ++i) printf("%02x", memory[i]);
            putchar('\n');
        }
    }
    return ferror(stdin) || ferror(stdout);
}
