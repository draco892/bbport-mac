#ifndef BB_AOT_MEMORY_H
#define BB_AOT_MEMORY_H
#include <stdint.h>
#include <unicorn/unicorn.h>

typedef enum {
    BB_MEMORY_NONE, BB_DIRECT_SIZE, BB_DIRECT_ALLOC, BB_DIRECT_MAP, BB_DIRECT_MAP_NAMED,
    BB_DIRECT_RELEASE, BB_MEMORY_UNMAP, BB_MEMORY_PROTECT, BB_MEMORY_RESERVE,
    BB_FLEXIBLE_MAP, BB_FLEXIBLE_MAP_NAMED
} BbMemoryImport;

typedef unsigned char *(*BbMemorySpan)(void *, uint64_t address, uint64_t size, uint64_t access);

BbMemoryImport bb_aot_memory_import(const char *);
int bb_aot_memory_attach(uc_engine *);
void bb_aot_memory_detach(void);
int bb_aot_memory_failed(void);
unsigned char *bb_aot_memory_span(uint64_t address, uint64_t size, uint64_t access);
uint64_t bb_aot_memory_call(BbMemoryImport, const char *, const uint64_t args[6], BbMemorySpan, void *);
int bb_aot_memory_verify(void);
#endif
