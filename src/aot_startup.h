#ifndef BB_AOT_STARTUP_H
#define BB_AOT_STARTUP_H
#include "boot_image.h"
#include "cpu_state.h"
#include "state_regions.h"

#define BB_AOT_IMPORT_BASE UINT64_C(0x650000000)
#define BB_AOT_STACK_BASE UINT64_C(0x660000000)
#define BB_AOT_SCRATCH_BASE UINT64_C(0x680000000)
#define BB_AOT_IMPORT_STRIDE UINT64_C(4096)

int bb_aot_startup_import(const char *name, uint64_t kind);
int bb_aot_startup(const BbBootImage *, BbGuestRegions *);
#endif
