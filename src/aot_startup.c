/* Bounded startup on ARM64, with an x86 guest engine and typed host imports. */
#include "aot_startup.h"
#include "aot_entries.h"
#include "direct_memory_limits.h"
#include "runtime.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unicorn/unicorn.h>

enum { STACK_SIZE = 8 * 1024 * 1024, MAX_HANDLES = 1024, MAX_FINALIZERS = 1024 };
#define GUEST_FINALIZER (BB_AOT_SCRATCH_BASE + 0x1000)
#define OPAQUE_BASE UINT64_C(0x690000000)

typedef struct GuestAttr GuestAttr;
typedef struct GuestCond GuestCond;
typedef struct GuestMutex GuestMutex;
typedef struct ThreadAttr ThreadAttr;
typedef enum { MUTEX, MUTEX_ATTR, THREAD_ATTR, COND, MAIN_THREAD } HandleKind;
typedef struct { void *pointer; HandleKind kind; } HostHandle;
typedef struct {
    const BbBootImage *boot;
    BbGuestRegions *regions;
    uc_engine *engine;
    unsigned char *stack;
    uint64_t heap_api, finalizers[MAX_FINALIZERS];
    size_t finalizer_count, handle_count, aot_calls;
    HostHandle handles[MAX_HANDLES];
    int invalid_import, pending_aot, exit_requested;
    uint32_t exit_code;
} Startup;

static const int gpr[] = {
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
    UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
};

typedef enum {
    UNSUPPORTED, PROC_PARAM, HEAP_API, INIT_ENV, ATEXIT, LIBC_EXIT, TLS_ADDR, DIRECT_SIZE,
    MUTEX_INIT, MUTEX_LOCK, MUTEX_UNLOCK, MUTEX_ATTR_INIT, MUTEX_ATTR_TYPE, MUTEX_ATTR_DESTROY,
    COND_INIT, SELF, ATTR_INIT, ATTR_GET, ATTR_AFFINITY, ATTR_DESTROY,
    STACK_CANARY, NEED_LIBC,
} Import;

static Import import_kind(const char *name) {
    static const struct { const char *name; Import kind; } imports[] = {
        {"959qrazPIrg#p#J", PROC_PARAM}, {"p5EcQeEeJAE#p#J", HEAP_API},
        {"bzQExy189ZI#q#q", INIT_ENV}, {"8G2LB+A3rzg#q#q", ATEXIT}, {"uMei1W9uyNo#q#q", LIBC_EXIT},
        {"vNe1w4diLCs#p#J", TLS_ADDR}, {"cmo1RIYva9o#p#J", MUTEX_INIT},
        {"9UK1vLZQft4#p#J", MUTEX_LOCK}, {"tn3VlD0hG60#p#J", MUTEX_UNLOCK},
        {"F8bUHwAG284#p#J", MUTEX_ATTR_INIT}, {"iMp8QpE+XO4#p#J", MUTEX_ATTR_TYPE},
        {"smWEktiyyG0#p#J", MUTEX_ATTR_DESTROY}, {"2Tb92quprl0#p#J", COND_INIT},
        {"aI+OeCz8xrQ#p#J", SELF}, {"nsYoNRywwNg#p#J", ATTR_INIT},
        {"x1X76arYMxU#p#J", ATTR_GET}, {"8+s5BzZjxSg#p#J", ATTR_AFFINITY},
        {"62KCwEMmzcM#p#J", ATTR_DESTROY},
        {"pO96TwzOm5E#p#J", DIRECT_SIZE},
    };
    for (size_t i = 0; i < sizeof imports / sizeof *imports; ++i)
        if (!strcmp(name, imports[i].name)) return imports[i].kind;
    if (runtime_nid_is(name, "f7uOxY9mM1U")) return STACK_CANARY;
    if (runtime_nid_is(name, "ZT4ODD2Ts9o")) return NEED_LIBC;
    return UNSUPPORTED;
}

int bb_aot_startup_import(const char *name, uint64_t kind) {
    Import import = import_kind(name);
    return kind == 1 ? import > UNSUPPORTED && import < STACK_CANARY : import >= STACK_CANARY;
}

static uint64_t read_reg(uc_engine *u, int reg) {
    uint64_t value = 0;
    uc_reg_read(u, reg, &value);
    return value;
}

static void write_reg(uc_engine *u, int reg, uint64_t value) { uc_reg_write(u, reg, &value); }

static int inside(uint64_t base, uint64_t size, uint64_t at, uint64_t length) {
    return at >= base && length <= size && at - base <= size - length;
}

static unsigned char *span(const Startup *s, uint64_t address, uint64_t size, uint64_t permission) {
    if (inside(BB_AOT_STACK_BASE, STACK_SIZE, address, size))
        return s->stack + (address - BB_AOT_STACK_BASE);
    for (uint64_t i = 0; i < s->regions->count; ++i) {
        const BbGuestMemory *r = &s->regions->regions[i];
        if ((r->permissions & permission) == permission && inside(r->guest_base, r->byte_size, address, size))
            return r->bytes + (address - r->guest_base);
    }
    return NULL;
}

static int executable(const Startup *s, uint64_t address) {
    for (uint64_t i = 0; i < s->boot->segment_count; ++i) {
        const BbBootSegment *r = &s->boot->segments[i];
        if ((r->flags & 1) && inside(AOT_BASE + r->address, r->size, address, 1)) return 1;
    }
    return address == GUEST_FINALIZER;
}

static uint64_t load64(const unsigned char *p) {
    uint64_t value;
    memcpy(&value, p, sizeof value);
    return value;
}
static void store64(unsigned char *p, uint64_t value) { memcpy(p, &value, sizeof value); }

static uint64_t save_handle(Startup *s, void *ptr, HandleKind kind) {
    if (!ptr) return 0;
    for (size_t i = 0; i < s->handle_count; ++i)
        if (s->handles[i].pointer == ptr && s->handles[i].kind == kind) return OPAQUE_BASE + i * 8;
    if (s->handle_count == MAX_HANDLES) return 0;
    s->handles[s->handle_count] = (HostHandle){ptr, kind};
    return OPAQUE_BASE + 8 * s->handle_count++;
}

static HostHandle *handle(Startup *s, uint64_t token, HandleKind kind) {
    if (token < OPAQUE_BASE || (token - OPAQUE_BASE) % 8) return NULL;
    const uint64_t i = (token - OPAQUE_BASE) / 8;
    return i < s->handle_count && s->handles[i].kind == kind && s->handles[i].pointer
        ? &s->handles[i] : NULL;
}

#define ORBIS_EINVAL UINT32_C(0x80020016)
#define ORBIS_ENOMEM UINT32_C(0x8002000c)

/* Guest addresses are checked through the shared mappings. Host handles never enter guest RAM. */
static uint64_t dispatch(Startup *s, Import op, const char *name, uint64_t a, uint64_t b, uint64_t c) {
    if (op == PROC_PARAM) return AOT_BASE + s->boot->procparam;
    if (op == DIRECT_SIZE) return bb_configured_direct_memory_size();
    if (op == HEAP_API) {
        if (!span(s, a, 8, 1)) { s->invalid_import = 1; return 0; }
        s->heap_api = a;
        return 0;
    }
    if (op == INIT_ENV) return 0; /* The standard prepare step verifies the libc RET. */
    if (op == ATEXIT) {
        if (!executable(s, a) || s->finalizer_count == MAX_FINALIZERS) return UINT32_MAX;
        s->finalizers[s->finalizer_count++] = a;
        return 0;
    }
    if (op == LIBC_EXIT) {
        s->exit_requested = 1;
        s->exit_code = (uint32_t)a;
        return 0;
    }
    if (op == TLS_ADDR) {
        const unsigned char *index = span(s, a, 16, 1);
        if (index) {
            for (uint64_t i = 0; i < s->boot->module_count; ++i) {
                const BbBootModule *m = &s->boot->modules[i];
                if (m->tls_module && m->tls_module == load64(index) && load64(index + 8) < m->tls_memsz)
                    return UINT64_C(0x670000000) + m->tls_module * 0x200000 + load64(index + 8);
            }
        }
        s->invalid_import = 1;
        return 0;
    }
    if (op == SELF) {
        void *(ABI *self)(void) = (void *)runtime_thread_resolve(name);
        return save_handle(s, self(), MAIN_THREAD);
    }

    unsigned char *slot = span(s, op == ATTR_GET ? b : a, 8, 3);
    if (!slot) return ORBIS_EINVAL;
    uintptr_t fn = op >= ATTR_INIT ? runtime_thread_resolve(name) : runtime_mutex_resolve(name);
    if (!fn) { s->invalid_import = 1; return 0; }

    void *created = NULL;
    HandleKind kind = MUTEX;
    uint32_t status;
    switch (op) {
    case MUTEX_ATTR_INIT: {
        GuestAttr *attr = NULL;
        status = ((int32_t (ABI *)(GuestAttr **))fn)(&attr);
        created = attr;
        kind = MUTEX_ATTR;
        break;
    }
    case ATTR_INIT: {
        ThreadAttr *attr = NULL;
        status = ((int32_t (ABI *)(ThreadAttr **))fn)(&attr);
        created = attr;
        kind = THREAD_ATTR;
        break;
    }
    case MUTEX_INIT: {
        const unsigned char *attr_slot = b ? span(s, b, 8, 1) : NULL;
        HostHandle *attr = attr_slot ? handle(s, load64(attr_slot), MUTEX_ATTR) : NULL;
        if (b && !attr) return ORBIS_EINVAL;
        GuestAttr *native_attr = attr ? attr->pointer : NULL;
        GuestMutex *mutex = NULL;
        status = ((int32_t (ABI *)(GuestMutex **, GuestAttr **, const char *))fn)
            (&mutex, b ? &native_attr : NULL, NULL);
        created = mutex;
        break;
    }
    case COND_INIT: {
        if (b) { s->invalid_import = 1; return 0; }
        GuestCond *cond = NULL;
        (void)c; /* runtime_mutex ignores the name. */
        status = ((int32_t (ABI *)(GuestCond **, void **, const char *))fn)(&cond, NULL, NULL);
        created = cond;
        kind = COND;
        break;
    }
    case MUTEX_LOCK:
    case MUTEX_UNLOCK: {
        HostHandle *h = handle(s, load64(slot), MUTEX);
        if (!h && (op != MUTEX_LOCK || load64(slot) > 1)) return ORBIS_EINVAL;
        GuestMutex *mutex = h ? h->pointer : (GuestMutex *)(uintptr_t)load64(slot);
        status = ((int32_t (ABI *)(GuestMutex **))fn)(&mutex);
        if (h || status) return status;
        created = mutex;
        break;
    }
    case MUTEX_ATTR_TYPE:
    case MUTEX_ATTR_DESTROY: {
        HostHandle *h = handle(s, load64(slot), MUTEX_ATTR);
        if (!h) return ORBIS_EINVAL;
        GuestAttr *attr = h->pointer;
        if (op == MUTEX_ATTR_TYPE) return (uint32_t)((int32_t (ABI *)(GuestAttr **, int))fn)(&attr, (int)b);
        status = ((int32_t (ABI *)(GuestAttr **))fn)(&attr);
        if (!status) { h->pointer = NULL; store64(slot, 0); }
        return status;
    }
    case ATTR_GET:
    case ATTR_AFFINITY:
    case ATTR_DESTROY: {
        HostHandle *h = handle(s, load64(slot), THREAD_ATTR);
        if (!h) return ORBIS_EINVAL;
        ThreadAttr *attr = h->pointer;
        if (op == ATTR_GET) {
            HostHandle *thread = handle(s, a, MAIN_THREAD);
            if (!thread) return ORBIS_EINVAL;
            return (uint32_t)((int32_t (ABI *)(void *, ThreadAttr **))fn)(thread->pointer, &attr);
        }
        if (op == ATTR_AFFINITY) {
            unsigned char *out = span(s, b, 8, 2);
            uint64_t mask;
            if (!out) return ORBIS_EINVAL;
            status = ((int32_t (ABI *)(ThreadAttr **, uint64_t *))fn)(&attr, &mask);
            if (!status) store64(out, mask);
            return status;
        }
        status = ((int32_t (ABI *)(ThreadAttr **))fn)(&attr);
        if (!status) { h->pointer = NULL; store64(slot, 0); }
        return status;
    }
    default:
        s->invalid_import = 1;
        return 0;
    }
    if (!status) {
        const uint64_t token = save_handle(s, created, kind);
        if (!token) return ORBIS_ENOMEM;
        store64(slot, token);
    }
    return status;
}

static void on_import(uc_engine *u, uint64_t address, uint32_t size, void *context) {
    (void)size;
    Startup *s = context;
    const uint64_t delta = address - BB_AOT_IMPORT_BASE;
    const uint64_t idx = delta / BB_AOT_IMPORT_STRIDE;
    if (delta % BB_AOT_IMPORT_STRIDE || idx >= s->boot->import_count) {
        s->invalid_import = 1;
        uc_emu_stop(u);
        return;
    }
    const char *name = s->boot->names[idx];
    const uint64_t value = dispatch(s, import_kind(name), name, read_reg(u, UC_X86_REG_RDI),
                                   read_reg(u, UC_X86_REG_RSI), read_reg(u, UC_X86_REG_RDX));
    if (s->invalid_import || s->exit_requested) uc_emu_stop(u);
    else write_reg(u, UC_X86_REG_RAX, value);
}

static void on_translated_leaf(uc_engine *u, uint64_t address, uint32_t size, void *context) {
    (void)address;
    (void)size;
    Startup *s = context;
    const uint64_t sp = read_reg(u, UC_X86_REG_RSP);
    unsigned char *ret = span(s, sp, 8, 1);
    if (ret && load64(ret) == AOT_RETURN &&
        inside(BB_AOT_STACK_BASE, STACK_SIZE, sp, 8)) {
        s->pending_aot = 1;
        uc_emu_stop(u);
    }
}

static uc_err resume_translated_leaf(Startup *s) {
    uc_engine *u = s->engine;
    BbCpuState cpu = {.rip = read_reg(u, UC_X86_REG_RIP), .rflags = read_reg(u, UC_X86_REG_RFLAGS)};
    for (size_t i = 0; i < sizeof gpr / sizeof *gpr; ++i) cpu.gpr[i] = read_reg(u, gpr[i]);
    BbGuestMemory window = {.bytes = s->stack + (cpu.gpr[4] - BB_AOT_STACK_BASE),
                            .guest_base = cpu.gpr[4], .byte_size = 8, .permissions = 3};
    entry_libc_finish(&cpu, s->regions, &window);
    if (cpu.status || cpu.rip != AOT_RETURN) return UC_ERR_EXCEPTION;
    for (size_t i = 0; i < sizeof gpr / sizeof *gpr; ++i) write_reg(u, gpr[i], cpu.gpr[i]);
    const uint64_t defined = UINT64_C(0x8c5);
    const uint64_t previous = read_reg(u, UC_X86_REG_RFLAGS);
    write_reg(u, UC_X86_REG_RFLAGS, (previous & ~defined) | (cpu.rflags & defined));
    write_reg(u, UC_X86_REG_RIP, cpu.rip);
    ++s->aot_calls;
    return UC_ERR_OK;
}

static uint64_t round_guest_page(uint64_t n) { return (n + 4095) & ~UINT64_C(4095); }

static int map_guest(Startup *s) {
    uc_engine *u = s->engine;
    for (uint64_t i = 0; i < s->boot->segment_count; ++i) {
        const BbBootSegment *r = &s->boot->segments[i];
        if (!r->size) continue;
        unsigned rights = (r->flags & 1 ? UC_PROT_EXEC : 0) |
                          (r->flags & 2 ? UC_PROT_WRITE : 0) | (r->flags & 4 ? UC_PROT_READ : 0);
        if (uc_mem_map_ptr(u, AOT_BASE + r->address, round_guest_page(r->size), rights,
                           s->boot->image + r->address)) return 0;
    }
    for (uint64_t i = 0; i < s->regions->count; ++i) {
        const BbGuestMemory *r = &s->regions->regions[i];
        if (r->guest_base < AOT_RETURN || r->guest_base >= BB_AOT_SCRATCH_BASE) continue;
        if (uc_mem_map_ptr(u, r->guest_base, round_guest_page(r->byte_size),
                           UC_PROT_READ | UC_PROT_WRITE, r->bytes)) return 0;
    }
    if (uc_mem_map_ptr(u, BB_AOT_STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE, s->stack))
        return 0;

    const unsigned char ret = 0xc3;
    for (uint64_t i = 0; i < s->boot->import_count; ++i) {
        const uint64_t at = BB_AOT_IMPORT_BASE + i * BB_AOT_IMPORT_STRIDE;
        Import op = import_kind(s->boot->names[i]);
        if (op == UNSUPPORTED) continue;
        if (op == INIT_ENV) {
            const uint64_t bound = AOT_BASE + s->boot->bindings[i];
            const unsigned char *entry = span(s, bound, 1, 1);
            if (s->boot->binding_kinds[i] != 1 || !entry || !executable(s, bound) || *entry != ret)
                return 0;
        }
        if (op < STACK_CANARY) {
            if (uc_mem_map(u, at, 4096, UC_PROT_EXEC | UC_PROT_READ) ||
                uc_mem_write(u, at, &ret, sizeof ret)) return 0;
        } else {
            /* The native runtime uses a process-wide canary and an SDK marker. */
            const uint64_t value = op == NEED_LIBC ? 1 : UINT64_C(0xd47dc4bd57234b00);
            if (uc_mem_map(u, at, 4096, UC_PROT_READ) || uc_mem_write(u, at, &value, sizeof value))
                return 0;
        }
    }
    const char path[] = "/app0/eboot.bin";
    const uint64_t params[] = {1, BB_AOT_SCRATCH_BASE + 64, 0};
    return !uc_mem_map(u, BB_AOT_SCRATCH_BASE, 4096, UC_PROT_READ | UC_PROT_WRITE) &&
           !uc_mem_write(u, BB_AOT_SCRATCH_BASE, params, sizeof params) &&
           !uc_mem_write(u, BB_AOT_SCRATCH_BASE + 64, path, sizeof path) &&
           !uc_mem_map(u, GUEST_FINALIZER, 4096, UC_PROT_READ | UC_PROT_EXEC) &&
           !uc_mem_write(u, GUEST_FINALIZER, &ret, sizeof ret);
}

static uc_err call_guest(Startup *s, uint64_t pc, uint64_t arg0, uint64_t arg1) {
    const uint64_t sp = BB_AOT_STACK_BASE + STACK_SIZE - 8;
    store64(s->stack + STACK_SIZE - 8, AOT_RETURN);
    write_reg(s->engine, UC_X86_REG_RSP, sp);
    write_reg(s->engine, UC_X86_REG_RDI, arg0);
    write_reg(s->engine, UC_X86_REG_RSI, arg1);
    write_reg(s->engine, UC_X86_REG_RDX, 0);
    s->pending_aot = 0;
    const uc_err error = uc_emu_start(s->engine, pc, AOT_RETURN, 5000000, 3000000);
    return !error && s->pending_aot ? resume_translated_leaf(s) : error;
}

static int reached_return(const Startup *s) {
    return read_reg(s->engine, UC_X86_REG_RIP) == AOT_RETURN &&
           read_reg(s->engine, UC_X86_REG_RSP) == BB_AOT_STACK_BASE + STACK_SIZE;
}

static int run_finalizers(Startup *s) {
    unsigned remaining = MAX_FINALIZERS;
    while (s->finalizer_count && remaining--) {
        const uint64_t callback = s->finalizers[--s->finalizer_count];
        if (call_guest(s, callback, 0, 0) || !reached_return(s) ||
            s->invalid_import || s->exit_requested) return 0;
    }
    return !s->finalizer_count;
}

static int verify_x87(Startup *s) {
    /* fninit; fld1; fld1; faddp; fstp qword [rdi]; ret */
    const unsigned char check[] = {0xdb,0xe3,0xd9,0xe8,0xd9,0xe8,0xde,0xc1,0xdd,0x1f,0xc3};
    const uint64_t code = GUEST_FINALIZER + 16;
    const uint64_t data = BB_AOT_SCRATCH_BASE + 256;
    uint64_t bits = 0;
    if (uc_mem_write(s->engine, code, check, sizeof check) || call_guest(s, code, data, 0) ||
        !reached_return(s) || uc_mem_read(s->engine, data, &bits, sizeof bits) ||
        bits != UINT64_C(0x4000000000000000)) return 0;
    printf("Compatibility x87 probe returned 2.0\n");
    return 1;
}

static int verify_finalizers(Startup *s) {
    const uint64_t word = BB_AOT_SCRATCH_BASE + 264;
    const uint64_t entry = GUEST_FINALIZER + 64;
    /* movabs rax, word; shl qword [rax], 4; add byte [rax], n; ret */
    unsigned char code[] = {0x48,0xb8,0,0,0,0,0,0,0,0,0x48,0xc1,0x20,4,0x80,0x00,1,0xc3};
    store64(code + 2, word);
    if (uc_mem_write(s->engine, entry, code, sizeof code)) return 0;
    code[16] = 2;
    if (uc_mem_write(s->engine, entry + 32, code, sizeof code)) return 0;
    s->finalizers[s->finalizer_count++] = entry;
    s->finalizers[s->finalizer_count++] = entry + 32;
    uint64_t value = 0;
    if (!run_finalizers(s) || uc_mem_read(s->engine, word, &value, sizeof value) || value != 0x21)
        return 0;
    puts("Compatibility finalizer probe returned callbacks in LIFO order");
    return 1;
}

static void report_stop(const Startup *s, const char *phase, uc_err error) {
    const uint64_t rip = read_reg(s->engine, UC_X86_REG_RIP);
    const uint64_t index = (rip - BB_AOT_IMPORT_BASE) / BB_AOT_IMPORT_STRIDE;
    printf("%s stopped at guest RIP %#" PRIx64 " (%s)", phase, rip, uc_strerror(error));
    if (index < s->boot->import_count) printf(", import %s", s->boot->names[index]);
    puts("");
}

int bb_aot_startup(const BbBootImage *boot, BbGuestRegions *regions) {
    Startup s = {.boot = boot, .regions = regions};
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &s.engine);
    if (err) return 1;
    s.stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    int result = 1;
    uc_hook import_hook, leaf_hook;
    if (s.stack == MAP_FAILED || uc_ctl_set_cpu_model(s.engine, UC_CPU_X86_HASWELL) ||
        !map_guest(&s) || uc_hook_add(s.engine, &import_hook, UC_HOOK_CODE, on_import, &s,
                                     BB_AOT_IMPORT_BASE, BB_AOT_IMPORT_BASE + boot->import_count * BB_AOT_IMPORT_STRIDE - 1)) {
        fputs("ARM64 compatibility engine setup failed\n", stderr);
        goto done;
    }
    const uint64_t leaf = AOT_BASE + AOT_LIBC_FINISH;
    const unsigned char *leaf_bytes = span(&s, leaf, sizeof aot_libc_finish, 1);
    if (!leaf_bytes || !executable(&s, leaf) ||
        memcmp(leaf_bytes, aot_libc_finish, sizeof aot_libc_finish) ||
        uc_hook_add(s.engine, &leaf_hook, UC_HOOK_CODE, on_translated_leaf, &s, leaf, leaf)) {
        fputs("ARM64 translated libc leaf does not match the image\n", stderr);
        goto done;
    }
    write_reg(s.engine, UC_X86_REG_FS_BASE, regions->thread_pointer);
    write_reg(s.engine, UC_X86_REG_GS_BASE, regions->thread_pointer);
    write_reg(s.engine, UC_X86_REG_MXCSR, 0x1f80);
    if (!verify_x87(&s) || !verify_finalizers(&s)) {
        fputs("ARM64 compatibility instruction or callback probe failed\n", stderr);
        goto done;
    }

    for (uint64_t i = 0; i < boot->module_count; ++i) {
        const uint64_t entry = AOT_BASE + boot->modules[i].init;
        printf("Starting linked module %" PRIu64 " at %#" PRIx64 "\n", i, entry);
        err = call_guest(&s, entry, 0, 0);
        if (err || s.invalid_import || !reached_return(&s) || (uint32_t)read_reg(s.engine, UC_X86_REG_RAX)) {
            report_stop(&s, "Module initializer", err);
            goto done;
        }
        printf("Module %" PRIu64 " initializer returned 0\n", i);
    }
    printf("Translated module tail calls: %zu\n", s.aot_calls);
    printf("Entering eboot on ARM64 at guest RIP %#" PRIx64 "\n", AOT_BASE + boot->entry);
    err = call_guest(&s, AOT_BASE + boot->entry, BB_AOT_SCRATCH_BASE, GUEST_FINALIZER);
    report_stop(&s, "eboot", err);
    printf("Guest finalizers registered: %zu\n", s.finalizer_count);
    if (!err && s.exit_requested) {
        s.exit_requested = 0;
        if (run_finalizers(&s)) result = (int)(s.exit_code & 0xff);
    } else if (err == UC_ERR_FETCH_UNMAPPED) {
        const uint64_t rip = read_reg(s.engine, UC_X86_REG_RIP);
        if (inside(BB_AOT_IMPORT_BASE, boot->import_count * BB_AOT_IMPORT_STRIDE, rip, 1))
            result = 2; /* Reached an unmapped guest import after entering eboot. */
    }
done:
    uc_close(s.engine);
    if (s.stack != MAP_FAILED) munmap(s.stack, STACK_SIZE);
    return result;
}

/* The compatibility engine holds guest TLS and its own addressed mappings. */
void *runtime_low_map(size_t size, int prot) {
    void *p = mmap(NULL, size, prot, MAP_PRIVATE | MAP_ANON, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}
void runtime_thread_keys_cleanup(void) {}
void runtime_re_watch_now(uint64_t address) { (void)address; }
