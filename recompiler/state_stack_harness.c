/* Full CPU/data/stack snapshots, plus whole-function x86 CALL/RET verification. */
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
#include "state_stack_entries.h"

typedef struct {
    BbCpuState state;
    uint64_t data_base, data_size, data_rights, data_null;
    uint64_t stack_base, stack_size, stack_rights, stack_null;
    unsigned char data[96], stack[544];
} Input;
_Static_assert(sizeof(Input) == 1120, "stack input size");
_Static_assert(offsetof(Input, data) == 480, "stack input data offset");
_Static_assert(offsetof(Input, stack) == 576, "stack input stack offset");

typedef struct { uint64_t control, status; } HostEnvironment;
static HostEnvironment read_host(void) {
    HostEnvironment v = {0, 0};
#if defined(__x86_64__)
    uint32_t value;
    __asm__ volatile("stmxcsr %0" : "=m"(value) :: "memory");
    v.control = value;
#else
    __asm__ volatile("mrs %0, fpcr\n\tmrs %1, fpsr" : "=r"(v.control), "=r"(v.status) :: "memory");
#endif
    return v;
}
static void write_host(HostEnvironment v) {
#if defined(__x86_64__)
    uint32_t value = (uint32_t)v.control;
    __asm__ volatile("ldmxcsr %0" :: "m"(value) : "memory");
#else
    __asm__ volatile("msr fpcr, %0\n\tmsr fpsr, %1" :: "r"(v.control), "r"(v.status) : "memory");
#endif
}
static void put64(unsigned char *where, uint64_t value) { memcpy(where, &value, 8); }
static void prepare_stack(unsigned char *stack, const Input *in) {
    const uint64_t sp = in->state.gpr[4];
    if (sp >= in->stack_base && sp - in->stack_base <= 504) {
        size_t offset = (size_t)(sp - in->stack_base);
        put64(stack + 16 + offset, SS_ROOT_RETURN);
        if (offset <= 496) put64(stack + 16 + offset + 8, in->state.gpr[6]);
        if (offset <= 488) put64(stack + 16 + offset + 16, in->state.gpr[2]);
    }
}

int main(void) {
    unsigned char local_data[96], local_stack[544];
    unsigned char *data = local_data, *stack = local_stack;
#ifdef ORIGINAL
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *mapped_data = mmap((void *)(uintptr_t)(SS_DATA_BASE - 16), page, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANON, -1, 0);
    void *mapped_stack = mmap((void *)(uintptr_t)(SS_STACK_BASE - 16), page, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapped_data == MAP_FAILED || mapped_stack == MAP_FAILED) return 10;
    if ((uintptr_t)mapped_data != SS_DATA_BASE - 16 || (uintptr_t)mapped_stack != SS_STACK_BASE - 16) return 11;
    data = mapped_data;
    stack = mapped_stack;
    const size_t image_size = (sizeof(ss_image) + page - 1) / page * page;
    void *image = mmap((void *)(uintptr_t)SS_CODE_BASE, image_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON, -1, 0);
    if (image == MAP_FAILED || (uintptr_t)image != SS_CODE_BASE) return 12;
    memcpy(image, ss_image, sizeof(ss_image));
    uint64_t capture = (uint64_t)(uintptr_t)&ss_native_capture;
    memcpy((unsigned char *)image + 0x10000 + 6, &capture, 8);
    if (mprotect(image, image_size, PROT_READ | PROT_EXEC)) return 13;
#endif
    const HostEnvironment original = read_host();
#if defined(__x86_64__)
    HostEnvironment seeded = {0x7fa1, 0};
#else
    HostEnvironment seeded = {0x400000, 0x15};
#endif
    Input input;
    size_t bytes;
    unsigned long count = 0, inputs = 0, native_checks = 0, outcomes[5] = {0, 0, 0, 0, 0};
    const unsigned saved[] = {3, 5, 12, 13, 14, 15};
    while ((bytes = fread(&input, 1, sizeof input, stdin))) {
        if (bytes != sizeof input) return 3;
        if (input.data_null > 1 || input.stack_null > 1) return 4;
#ifdef ORIGINAL
        const int data_valid = input.data_size <= 64 && input.data_base <= UINT64_MAX - input.data_size &&
            input.data_rights <= 3 && (!input.data_size || !input.data_null);
        const int stack_valid = input.stack_size <= 512 && input.stack_base <= UINT64_MAX - input.stack_size &&
            input.stack_rights <= 3 && (!input.stack_size || !input.stack_null);
        const int disjoint = !input.data_size || !input.stack_size ||
            input.data_base + input.data_size <= input.stack_base || input.stack_base + input.stack_size <= input.data_base;
        if (data_valid && stack_valid && disjoint &&
            ((input.data_size && input.data_base != SS_DATA_BASE) || (input.stack_size && input.stack_base != SS_STACK_BASE))) return 4;
#endif
        for (unsigned f = 0; f < SS_ENTRIES; ++f) {
            memcpy(data, input.data, 96);
            memcpy(stack, input.stack, 544);
            prepare_stack(stack, &input);
            unsigned char initial_stack[544];
            memcpy(initial_stack, stack, 544);
            struct { uint64_t head[2]; BbCpuState cpu; uint64_t tail[2]; } guarded = {
                {UINT64_C(0x0123456789abcdef), UINT64_C(0xfeedfacefeedface)}, input.state,
                {UINT64_C(0xfedcba9876543210), UINT64_C(0xdeadbeefdeadbeef)}};
            guarded.cpu.rip = SS_CODE_BASE + ss_offsets[f];
            BbGuestMemory dm = {input.data_null ? NULL : data + 16, input.data_base, input.data_size, input.data_rights, 0xa5, 0x5a};
            BbGuestMemory sm = {input.stack_null ? NULL : stack + 16, input.stack_base, input.stack_size, input.stack_rights, 0x5a, 0xa5};
#if defined(__aarch64__)
            seeded.status = UINT64_C(0x15) | ((uint64_t)((inputs + f) & 1) << 27);
#endif
            write_host(seeded);
            ss_entries[f](&guarded.cpu, &dm, &sm);
            HostEnvironment after = read_host();
            assert(after.control == seeded.control && after.status == seeded.status);
            assert(guarded.head[0] == UINT64_C(0x0123456789abcdef) && guarded.head[1] == UINT64_C(0xfeedfacefeedface));
            assert(guarded.tail[0] == UINT64_C(0xfedcba9876543210) && guarded.tail[1] == UINT64_C(0xdeadbeefdeadbeef));
            assert(!memcmp(guarded.cpu.xmm, input.state.xmm, sizeof input.state.xmm));
            assert(guarded.cpu.mxcsr == input.state.mxcsr && guarded.cpu.reserved == input.state.reserved);
            assert(!((guarded.cpu.rflags ^ input.state.rflags) & ~UINT64_C(0x8d5)));
            assert(!memcmp(data, input.data, 16) && !memcmp(data + 80, input.data + 80, 16));
            assert(!memcmp(stack, initial_stack, 16) && !memcmp(stack + 528, initial_stack + 528, 16));
            assert(dm.bytes == (input.data_null ? NULL : data + 16) && sm.bytes == (input.stack_null ? NULL : stack + 16));
            assert(dm.guest_base == input.data_base && dm.byte_size == input.data_size && dm.permissions == input.data_rights);
            assert(sm.guest_base == input.stack_base && sm.byte_size == input.stack_size && sm.permissions == input.stack_rights);
            assert(guarded.cpu.status <= 4);
            ++outcomes[guarded.cpu.status];
            if (!guarded.cpu.status) {
                assert(guarded.cpu.rip == SS_ROOT_RETURN);
                if (ss_abi[f]) {
                    assert(guarded.cpu.gpr[4] == input.state.gpr[4] + 8);
                    for (unsigned i = 0; i < sizeof saved / sizeof saved[0]; ++i)
                        assert(guarded.cpu.gpr[saved[i]] == input.state.gpr[saved[i]]);
                }
#ifdef ORIGINAL
                /* Replay every successful checked execution using original
                 * whole functions and real x86 CALL/RET at the guest addresses. */
                BbCpuState expected = guarded.cpu, native = input.state;
                unsigned char expected_data[96], expected_stack[544];
                memcpy(expected_data, data, 96);
                memcpy(expected_stack, stack, 544);
                memcpy(data, input.data, 96);
                memcpy(stack, initial_stack, 544);
                native.rip = SS_CODE_BASE + ss_offsets[f];
                write_host(seeded);
                ss_native_entries[f](&native);
                after = read_host();
                assert(after.control == seeded.control && after.status == seeded.status);
                if (memcmp(&native, &expected, sizeof native) || memcmp(data, expected_data, 96) || memcmp(stack, expected_stack, 544)) {
                    fprintf(stderr, "whole-native mismatch entry %u input %lu\n", f, inputs);
                    return 14;
                }
                ++native_checks;
#endif
            }
            if (fwrite(&guarded.cpu, sizeof guarded.cpu, 1, stdout) != 1 ||
                fwrite(&dm.fault_address, 16, 1, stdout) != 1 || fwrite(&sm.fault_address, 16, 1, stdout) != 1 ||
                fwrite(data, 96, 1, stdout) != 1 || fwrite(stack, 544, 1, stdout) != 1) return 5;
            ++count;
        }
        ++inputs;
    }
    write_host(original);
#ifdef ORIGINAL
    munmap(mapped_data, page); munmap(mapped_stack, page); munmap(image, image_size);
#endif
    fprintf(stderr, "PASS: %lu full snapshots from %lu inputs; success=%lu bounds=%lu descriptor=%lu denied=%lu return=%lu; whole-native=%lu; guards/host FP preserved\n",
            count, inputs, outcomes[0], outcomes[1], outcomes[2], outcomes[3], outcomes[4], native_checks);
    return ferror(stdin) || ferror(stdout);
}
