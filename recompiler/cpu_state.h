/* Experiment CPU-state ABI v1. Guest values, never native pointers.
 * GPR indices follow x86 encoding order: RAX, RCX, RDX, RBX, RSP, RBP,
 * RSI, RDI, R8..R15. A stored field does not imply execution support.
 * RIP denotes an explicit guest address; SIMD leaves preserve it.
 * x87/AVX, segment bases and exception delivery are outside this ABI. */
#ifndef BB_EXPERIMENT_CPU_STATE_H
#define BB_EXPERIMENT_CPU_STATE_H
#include <stdint.h>

typedef struct {
    uint64_t gpr[16];
    uint64_t xmm[16][2];
    uint64_t rip, rflags;
    uint32_t mxcsr, status;
    uint64_t reserved;
} BbCpuState;

#endif
