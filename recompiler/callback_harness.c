/* Synchronous scalar callback experiment. No game/runtime modules are loaded. */
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
extern void callback_host_bridge(void);
#else
extern void *resolve_guest_code(uint64_t);
#endif

typedef struct { uint64_t guest, handle; int active; } Binding;
typedef struct {
    Binding bindings[2];
    uint64_t next_handle, inner, error, fault, trace, calls, services;
    unsigned depth, peak, limit, policy; /* policy: 0 leaf, 1 outer reentry, 2 always reenter */
    uint64_t active_target[4];
    unsigned char *memory;
} Context;
static _Thread_local Context *active_context;

static uint64_t get64(const unsigned char *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static void put64(unsigned char *p, uint64_t v) { memcpy(p, &v, 8); }
static void event(Context *ctx, uint64_t kind, uint64_t target, uint64_t value) {
    ctx->trace = (ctx->trace ^ kind ^ (ctx->depth * 17) ^ target) * UINT64_C(0x100000001b3);
    ctx->trace = (ctx->trace ^ value) * UINT64_C(0x100000001b3);
}
static uint64_t fail(Context *ctx, uint64_t error, uint64_t fault) {
    if (!ctx->error) { ctx->error = error; ctx->fault = fault; }
    return ctx->error;
}
static int known(uint64_t guest) {
#ifdef ORIGINAL
    for (unsigned i = 0; i < ENTRY_COUNT; ++i) if (guest == CODE_BASE + entry_offsets[i]) return 1;
    return 0;
#else
    return resolve_guest_code(guest) != NULL;
#endif
}
static int allowed(uint64_t guest) {
    for (unsigned i = 0; i < CALLBACK_COUNT; ++i) if (guest == callback_targets[i]) return 1;
    return 0;
}
static uint64_t bind_callback(Context *ctx, uint64_t guest) {
    if (!known(guest)) { fail(ctx, 1, guest); return 0; }
    if (!allowed(guest)) { fail(ctx, 2, guest); return 0; }
    for (unsigned i = 0; i < 2; ++i) if (!ctx->bindings[i].active) {
        if (ctx->next_handle == UINT64_MAX) break;
        uint64_t handle = ++ctx->next_handle;
        ctx->bindings[i] = (Binding){guest, handle, 1};
        return handle;
    }
    fail(ctx, 3, 0);
    return 0;
}
static void unbind_callback(Context *ctx, uint64_t handle) {
    for (unsigned i = 0; i < 2; ++i)
        if (ctx->bindings[i].active && ctx->bindings[i].handle == handle) ctx->bindings[i].active = 0;
}

static Cpu invoke_callback(Context *ctx, uint64_t handle, uint64_t argument) {
    Cpu cpu = {0, argument, RBX_SEED, RBP_SEED, 0, 0, 0};
    uint64_t guest = 0;
    for (unsigned i = 0; i < 2; ++i)
        if (ctx->bindings[i].active && ctx->bindings[i].handle == handle) guest = ctx->bindings[i].guest;
    if (ctx->error) goto rejected;
    if (!guest) { fail(ctx, 3, handle); goto rejected; }
    if (!known(guest)) { fail(ctx, 1, guest); goto rejected; }
    if (!allowed(guest)) { fail(ctx, 2, guest); goto rejected; }
    if (!ctx->limit || ctx->limit > 4 || ctx->depth >= ctx->limit) { fail(ctx, 4, guest); goto rejected; }
    Context *previous = active_context;
    active_context = ctx;
    ctx->active_target[ctx->depth++] = guest;
    if (ctx->depth > ctx->peak) ctx->peak = ctx->depth;
    ++ctx->calls;
    event(ctx, 1, guest, argument); /* host -> guest */
#ifdef ORIGINAL
    stack_original_call((void (*)(void))(uintptr_t)guest, ctx->memory, argument, &cpu);
#else
    _Alignas(16) unsigned char guarded_stack[STACK_BYTES + 32];
    memset(guarded_stack, 0xa5, sizeof(guarded_stack));
    unsigned char *stack = guarded_stack + 16;
    cpu.sp = STACK_BYTES - 8;
    put64(stack + cpu.sp, ROOT_RETURN);
    typedef void (*Guest)(Cpu *, unsigned char *, unsigned char *, uint64_t);
    Guest native = (Guest)resolve_guest_code(guest);
    if ((uint64_t)(uintptr_t)native == guest) fail(ctx, 5, guest);
    else native(&cpu, ctx->memory, stack, ROOT_RETURN);
    cpu.sp -= STACK_BYTES;
    for (unsigned i = 0; i < 16; ++i)
        if (guarded_stack[i] != 0xa5 || guarded_stack[16 + STACK_BYTES + i] != 0xa5) fail(ctx, 5, guest);
#endif
    if (cpu.sp || cpu.rbx != RBX_SEED || cpu.rbp != RBP_SEED) fail(ctx, 5, guest);
    if (cpu.error) fail(ctx, cpu.error, cpu.fault_address);
    event(ctx, 4, guest, cpu.rax ^ cpu.b); /* guest -> host */
    --ctx->depth;
    active_context = previous;
rejected:
    cpu.error = ctx->error;
    cpu.fault_address = ctx->fault;
    return cpu;
}

/* Native C host import. AOT calls it directly; x86 reaches it via an ABI bridge. */
void host_service(Cpu *cpu, unsigned char *guest, unsigned char *stack, uint64_t expected) {
    Context *ctx = active_context;
    if (!ctx || !ctx->depth || guest != ctx->memory) { cpu->error = 5; return; }
#ifndef ORIGINAL
    if (cpu->sp > STACK_BYTES - 8 || cpu->sp % 16 != 8 || get64(stack + cpu->sp) != expected) {
        cpu->error = fail(ctx, 5, 0);
        return;
    }
#else
    (void)stack; (void)expected;
#endif
    const uint64_t saved_rbx = cpu->rbx, saved_rbp = cpu->rbp;
    const uint64_t target = ctx->active_target[ctx->depth - 1];
    ++ctx->services;
    event(ctx, 2, target, cpu->b); /* guest -> native host service */
    uint64_t next = cpu->b + UINT64_C(0x9e3779b97f4a7c15);
    uint64_t result = get64(guest) ^ next;
    if (ctx->policy == 2 || (ctx->policy == 1 && ctx->depth == 1)) {
        Cpu child = invoke_callback(ctx, ctx->inner, next);
        if (!child.error) { result += child.rax; next = child.b; }
    }
    if (!ctx->error) {
        put64(guest + 8, get64(guest + 8) + result);
        cpu->rax = result;
        cpu->b = next;
    } else {
        cpu->error = ctx->error;
        cpu->fault_address = ctx->fault;
    }
    event(ctx, 3, target, ctx->error ? 0 : result); /* host service -> guest */
    if (cpu->rbx != saved_rbx || cpu->rbp != saved_rbp) cpu->error = fail(ctx, 5, target);
#ifndef ORIGINAL
    cpu->sp += 8; /* Consume this imported call's validated guest return token. */
#endif
}

#ifndef ORIGINAL
static int negative_tests(void) {
    unsigned char memory[96], before[96];
    memset(memory, 0x27, sizeof(memory));
    put64(memory + 16, 3);
    put64(memory + 16 + 48, GUEST_LEAF_ADDRESS);
    memcpy(before, memory, sizeof(memory));
    const uint64_t bad[] = {0, callback_targets[0] + 1,
        (uint64_t)(uintptr_t)resolve_guest_code(callback_targets[0]), GUEST_HELPER_ADDRESS, HOST_IMPORT_ADDRESS};
    unsigned count = 0;
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        Context ctx = {.memory = memory + 16, .limit = 3};
        if (bind_callback(&ctx, bad[i]) || ctx.error != (i == 3 ? 2 : 1) || ctx.calls || ctx.services) return 20;
        ++count;
    }
    Context revoked = {.memory = memory + 16, .limit = 3};
    uint64_t old = bind_callback(&revoked, callback_targets[1]);
    unbind_callback(&revoked, old);
    if (invoke_callback(&revoked, old, 7).error != 3 || revoked.fault != old || revoked.calls) return 21;
    ++count;
    Context reused = {.memory = memory + 16, .limit = 3};
    old = bind_callback(&reused, callback_targets[1]);
    unbind_callback(&reused, old);
    uint64_t fresh = bind_callback(&reused, callback_targets[2]);
    if (!fresh || fresh == old || invoke_callback(&reused, old, 7).error != 3 || reused.fault != old || reused.calls) return 22;
    ++count;
    reused.error = reused.fault = 0;
    if (invoke_callback(&reused, fresh, 7).error || reused.calls != 1 || reused.depth || active_context) return 23;
    ++count;
    memcpy(memory, before, sizeof(memory));
    Context recursive = {.memory = memory + 16, .limit = 2, .policy = 2};
    uint64_t outer = bind_callback(&recursive, CALLBACK_CHAIN_ADDRESS);
    recursive.inner = bind_callback(&recursive, callback_targets[1]);
    Cpu rejected = invoke_callback(&recursive, outer, 7);
    if (rejected.error != 4 || rejected.sp || rejected.rbx != RBX_SEED || rejected.rbp != RBP_SEED ||
        recursive.depth || recursive.peak != 2 || recursive.fault != callback_targets[1] ||
        active_context || memcmp(before, memory, sizeof(memory))) return 24;
    ++count;
    recursive.error = recursive.fault = 0;
    recursive.policy = 0;
    Cpu recovered = invoke_callback(&recursive, outer, 7);
    if (recovered.error || recursive.depth || active_context) return 25;
    ++count;
    printf("PASS: %u callback rejection/recovery checks\n", count);
    return 0;
}
#endif

int main(int argc, char **argv) {
#ifdef ORIGINAL
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    const size_t size = (sizeof(original_image) + page - 1) / page * page;
    void *image = mmap((void *)(uintptr_t)CODE_BASE, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (image == MAP_FAILED) { perror("callback image mmap"); return 10; }
    if ((uintptr_t)image != CODE_BASE) { munmap(image, size); return 11; }
    memcpy(image, original_image, sizeof(original_image));
    unsigned char *thunk = (unsigned char *)image + HOST_IMPORT_OFFSET;
    thunk[0] = 0x48; thunk[1] = 0xb8;
    put64(thunk + 2, (uint64_t)(uintptr_t)callback_host_bridge);
    thunk[10] = 0xff; thunk[11] = 0xe0;
    if (mprotect(image, size, PROT_READ | PROT_EXEC)) { perror("callback image mprotect"); return 12; }
#else
    if (argc == 2 && strcmp(argv[1], "--negative") == 0) return negative_tests();
#endif
    if (argc != 1) return 13;
    uint64_t a, b;
    while (scanf("%" SCNx64 " %" SCNx64, &a, &b) == 2)
        for (unsigned outer = 0; outer < CALLBACK_COUNT; ++outer)
            for (unsigned inner = 0; inner < 3; ++inner)
                for (unsigned policy = 0; policy < 2; ++policy) {
                    _Alignas(16) unsigned char memory[96], before[96];
                    for (unsigned i = 0; i < sizeof(memory); ++i)
                        memory[i] = (unsigned char)((a >> (8 * (i % 8))) ^ (b >> (8 * ((i + 3) % 8))) ^ (i * 37));
                    put64(memory + 16, a);
                    put64(memory + 16 + 32, callback_targets[inner]);
                    put64(memory + 16 + 48, GUEST_LEAF_ADDRESS);
                    memcpy(before, memory, sizeof(memory));
                    Context ctx = {.memory = memory + 16, .limit = 3, .policy = policy};
                    uint64_t binding = bind_callback(&ctx, callback_targets[outer]);
                    ctx.inner = bind_callback(&ctx, callback_targets[inner]);
                    for (unsigned repeat = 0; repeat < 2; ++repeat) {
                        Cpu cpu = invoke_callback(&ctx, binding, b ^ (repeat ? UINT64_C(0xa5a5a5a55a5a5a5a) : 0));
                        if (cpu.error || ctx.depth || active_context ||
                            memcmp(before, memory, 16) || memcmp(before + 80, memory + 80, 16)) return 14;
                        /* Independent fixture expectations: require the nested paths to execute. */
                        const unsigned host_calls = outer == 0 ? 0 : outer == 3 ? 2 : 1;
                        const uint64_t expected_calls = (repeat + 1) * (1 + policy * host_calls);
                        const uint64_t expected_services = (repeat + 1) * host_calls * (1 + policy * (inner != 0));
                        if (ctx.calls != expected_calls || ctx.services != expected_services ||
                            ctx.peak != (policy && host_calls ? 2u : 1u)) return 15;
                        printf("%016" PRIx64 ":%016" PRIx64 ":%016" PRIx64 ":%016" PRIx64 ":%016" PRIx64 ":",
                               cpu.rax, cpu.b, cpu.rbx, cpu.rbp, cpu.sp);
                        printf("%016" PRIx64 ":%" PRIu64 ":%" PRIu64 ":%u:", ctx.trace, ctx.calls, ctx.services, ctx.peak);
                        for (unsigned i = 0; i < sizeof(memory); ++i) printf("%02x", memory[i]);
                        putchar('\n');
                    }
                    unbind_callback(&ctx, binding);
                    unbind_callback(&ctx, ctx.inner);
                }
    return ferror(stdin) || ferror(stdout);
}
