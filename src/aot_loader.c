/* ARM64 loader for the statically translated entry registry. */
#include "boot_image.h"
#include "cpu_state.h"
#include "state_regions.h"
#include "runtime.h"
#include "aot_entries.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>

#if !defined(__APPLE__) || !defined(__aarch64__)
#error The AOT loader requires native macOS ARM64.
#endif

#define IMPORT_BASE UINT64_C(0x650000000)
#define STACK_BASE UINT64_C(0x660000000)
#define TLS_BASE UINT64_C(0x670000000)
#define SCRATCH_BASE UINT64_C(0x680000000)

typedef struct GuestCond GuestCond;
static BbBootImage boot;
static uint64_t imported_cond;
static const char *cond_name;
static GuestCond *cond_handle;

static void fail(const char *reason) {
    fprintf(stderr, "ARM64 loader: %s\n", reason);
    exit(1);
}

static uint64_t get64(const void *bytes) {
    uint64_t value;
    memcpy(&value, bytes, sizeof value);
    return value;
}

static void put64(void *bytes, uint64_t value) { memcpy(bytes, &value, sizeof value); }

static unsigned char *checked_span(BbGuestRegions *regions, uint64_t address,
                                   uint64_t size, uint64_t permission) {
    for (uint64_t i = 0; i < regions->count; ++i) {
        const BbGuestMemory *r = &regions->regions[i];
        if ((r->permissions & permission) == permission && address >= r->guest_base &&
            size <= r->byte_size && address - r->guest_base <= r->byte_size - size)
            return r->bytes + (address - r->guest_base);
    }
    return NULL;
}

void bb_state_host_import(BbCpuState *cpu, BbGuestRegions *regions, uint64_t target) {
    if (target != AOT_PLT || get64(boot.image + AOT_GOT) != imported_cond || !cond_name) {
        cpu->status = 5;
        return;
    }
    unsigned char *output = checked_span(regions, cpu->gpr[7], 8, 2);
    const unsigned char *name = checked_span(regions, cpu->gpr[2], sizeof aot_name, 1);
    if (!output || !name || cpu->gpr[6] || memcmp(name, aot_name, sizeof aot_name)) {
        cpu->status = 3;
        return;
    }
    int32_t (ABI *init)(GuestCond **, void **, const char *) =
        (void *)runtime_mutex_resolve(cond_name);
    if (!init || cond_handle) fail("condition variable bridge unavailable");
    uint32_t rc = (uint32_t)init(&cond_handle, NULL, (const char *)name);
    if (!rc) put64(output, SCRATCH_BASE + 16);
    cpu->gpr[0] = rc;
}

static void relocate(void) {
    uint64_t relative = 0, linked = 0, imports = 0;
    for (uint64_t i = 0; i < boot.reloc_count; ++i) {
        const BbBootReloc *r = &boot.relocs[i];
        uint64_t value;
        if (!r->kind) {
            if (r->value >= boot.size) fail("relative relocation outside guest image");
            value = AOT_BASE + r->value;
            ++relative;
        } else {
            const uint64_t binding = boot.bindings[r->value];
            const char *name = boot.names[r->value];
            if (r->target == AOT_GOT) {
                if (cond_name || r->kind != 1 || strcmp(name, AOT_COND_NAME) ||
                    !runtime_mutex_resolve(name))
                    fail("expected runtime import at translated PLT slot");
                cond_name = name;
                imported_cond = IMPORT_BASE + r->value * 4096;
                value = imported_cond;
                ++imports;
            } else if ((boot.capabilities & 1) && binding) {
                if (boot.binding_kinds[r->value] != r->kind ||
                    !bb_boot_mapped(boot.segments, boot.segment_count, binding, r->addend + 1))
                    fail("linked export kind/range mismatch");
                value = AOT_BASE + binding + r->addend;
                ++linked;
            } else {
                /* A guest import token is dispatched only through a registered bridge. */
                value = IMPORT_BASE + r->value * 4096 + r->addend;
                ++imports;
            }
        }
        put64(boot.image + r->target, value);
    }
    if (!cond_name) fail("translated import relocation missing");
    printf("Relocations: %" PRIu64 " relative, %" PRIu64 " linked, %" PRIu64 " import slots\n",
           relative, linked, imports);
}

static void add_region(BbGuestRegions *table, BbGuestMemory region) {
    if (table->count == BB_MAX_DATA_REGIONS) fail("too many guest memory regions");
    table->regions[table->count++] = region;
}

static int segment_order(const void *lhs, const void *rhs) {
    const BbBootSegment *a = lhs, *b = rhs;
    return (a->address > b->address) - (a->address < b->address);
}

static int executable(uint64_t offset, uint64_t length) {
    for (uint64_t i = 0; i < boot.segment_count; ++i) {
        const BbBootSegment *s = &boot.segments[i];
        if ((s->flags & 1) && offset >= s->address && length <= s->size &&
            offset - s->address <= s->size - length)
            return 1;
    }
    return 0;
}

static void tls_region(BbGuestRegions *regions, uint64_t address, uint64_t filesz,
                       uint64_t memsz, uint64_t id) {
    if (!memsz && id != 1) return;
    uint64_t size = memsz;
    const uint64_t base = TLS_BASE + id * 0x200000;
    if (id == 1) {
        const uint64_t align = boot.main_tls[3] ? boot.main_tls[3] : 16;
        const uint64_t aligned = (memsz + align - 1) & ~(align - 1);
        regions->thread_pointer = base + aligned;
        size = aligned + 256;
    }
    unsigned char *bytes = calloc(1, size);
    if (!bytes) fail("cannot allocate initial TLS");
    memcpy(bytes, boot.image + address, filesz);
    if (id == 1) put64(bytes + (regions->thread_pointer - base), regions->thread_pointer);
    add_region(regions, (BbGuestMemory){.bytes = bytes, .guest_base = base,
                                    .byte_size = size, .permissions = 3});
    printf("TLS image %" PRIu64 ": %" PRIu64 " initialized bytes, %" PRIu64 " bytes total\n",
           id, filesz, memsz);
}

int main(int argc, char **argv) {
    if (argc != 2) fail("usage: bb-probe-aot boot-linked.bin");
    int translated = 0;
    size_t flag_size = sizeof translated;
    if (!sysctlbyname("sysctl.proc_translated", &translated, &flag_size, NULL, 0) && translated)
        fail("expected a native ARM64 process");
    bb_boot_load(&boot, argv[1], 4096, malloc, fail);
    if (!boot.linked || !(boot.capabilities & 1) || boot.module_count != 2 ||
        boot.modules[1].base != AOT_MODULE_BASE || !executable(AOT_OFFSET, sizeof aot_body) ||
        !executable(AOT_PLT, sizeof aot_plt) || !executable(boot.entry, 1) ||
        memcmp(boot.image + AOT_OFFSET, aot_body, sizeof aot_body) ||
        memcmp(boot.image + AOT_PLT, aot_plt, sizeof aot_plt))
        fail("linked image does not match the translated entry registry");

    printf("Loaded native ARM64: %" PRIu64 " bytes, %" PRIu64 " segments, %" PRIu64
           " modules, startup entry %#" PRIx64 "\n",
           boot.size, boot.segment_count, boot.module_count, boot.entry);
    relocate();
    /* Recheck after relocation before dispatching any translated bytes. */
    if (memcmp(boot.image + AOT_OFFSET, aot_body, sizeof aot_body) ||
        memcmp(boot.image + AOT_PLT, aot_plt, sizeof aot_plt))
        fail("relocation altered translated code");

    qsort(boot.segments, boot.segment_count, sizeof *boot.segments, segment_order);
    BbGuestMemory mappings[BB_MAX_DATA_REGIONS];
    BbGuestRegions regions = {.regions = mappings, .region_limit = BB_BOOT_MAX_BYTES};
    for (uint64_t i = 0; i < boot.segment_count; ++i) {
        const BbBootSegment *s = &boot.segments[i];
        if (!s->size) continue;
        const uint64_t rights = ((s->flags & 4) ? 1 : 0) | ((s->flags & 2) ? 2 : 0);
        add_region(&regions, (BbGuestMemory){.bytes = boot.image + s->address,
                   .guest_base = AOT_BASE + s->address, .byte_size = s->size, .permissions = rights});
    }
    tls_region(&regions, boot.main_tls[0], boot.main_tls[1], boot.main_tls[2], 1);
    for (uint64_t i = 0; i < boot.module_count; ++i) {
        const BbBootModule *m = &boot.modules[i];
        if (!executable(m->init, 1)) fail("module initializer outside executable segment");
        if (m->tls_module) tls_region(&regions, m->tls_address, m->tls_filesz, m->tls_memsz, m->tls_module);
    }

    unsigned char result[24] = {0}, stack[512] = {0};
    add_region(&regions, (BbGuestMemory){.bytes = result, .guest_base = SCRATCH_BASE,
                                       .byte_size = sizeof result, .permissions = 3});
    BbGuestMemory guest_stack = {.bytes = stack, .guest_base = STACK_BASE,
                                 .byte_size = sizeof stack, .permissions = 3};
    BbCpuState cpu = {.rip = AOT_BASE + AOT_OFFSET, .rflags = 0x202};
    cpu.gpr[4] = STACK_BASE + sizeof stack - 8;
    const uint64_t argument = UINT64_C(0x89abcdef12345678);
    cpu.gpr[6] = argument;
    cpu.gpr[7] = SCRATCH_BASE;
    put64(stack + sizeof stack - 8, AOT_RETURN);
    entry_tls_self(&cpu, &regions, &guest_stack);
    if (cpu.status || cpu.gpr[0] != regions.thread_pointer || cpu.rip != AOT_RETURN)
        fail("translated initial TLS access failed");
    printf("AOT TLS self pointer %#" PRIx64 "\n", cpu.gpr[0]);
    cpu.gpr[4] -= 8;
    entry_fios_cond(&cpu, &regions, &guest_stack);
    if (cpu.status || cpu.rip != AOT_RETURN || cpu.gpr[4] != STACK_BASE + sizeof stack ||
        cpu.gpr[0] || !cond_handle || get64(result) != SCRATCH_BASE + 16 ||
        get64(result + 8) != argument) {
        fprintf(stderr, "Guest RIP %#" PRIx64 ", status %" PRIu32 "\n", cpu.rip, cpu.status);
        fail("translated module entry failed");
    }
    int32_t (ABI *destroy)(GuestCond **) = (void *)runtime_mutex_resolve("g+PZd2hiacg");
    if (!destroy || destroy(&cond_handle) || cond_handle) fail("condition variable cleanup failed");
    printf("AOT module entry %#" PRIx64 " returned through scePthreadCondInit\n", AOT_OFFSET);
    printf("Startup pending: module initializers and eboot entry require translated dispatch coverage\n");
    return 0;
}

/* This executable exercises initialization only, which never waits. */
void runtime_wait_note(int kind, uint64_t ns) {
    (void)kind;
    (void)ns;
    fail("unexpected runtime wait");
}
