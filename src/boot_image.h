#ifndef BB_BOOT_IMAGE_H
#define BB_BOOT_IMAGE_H
#include <stddef.h>
#include <stdint.h>

enum { BB_BOOT_MAX_MODULES = 16, BB_BOOT_MAX_BYTES = 512 * 1024 * 1024 };
typedef struct { uint64_t address, size, flags; } BbBootSegment;
typedef struct { uint64_t target, kind, value, addend; } BbBootReloc;
typedef struct { uint64_t base, size, init, tls_address, tls_memsz, tls_filesz, tls_module; } BbBootModule;

typedef struct {
    uint64_t size, entry, capabilities, procparam, main_tls[4];
    uint64_t segment_count, reloc_count, import_count, binding_count, module_count;
    int linked;
    BbBootModule modules[BB_BOOT_MAX_MODULES];
    BbBootSegment *segments;
    BbBootReloc *relocs;
    char (*names)[128];
    uint64_t *bindings, *binding_kinds;
    uint8_t *image;
} BbBootImage;

/* The failure callback terminates the process; allocate returns writable image storage. */
void bb_boot_load(BbBootImage *, const char *path, size_t page_size,
                  void *(*allocate)(size_t), void (*fail)(const char *));
int bb_boot_mapped(const BbBootSegment *, uint64_t count, uint64_t address, uint64_t bytes);
#endif
