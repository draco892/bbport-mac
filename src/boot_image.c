#include "boot_image.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t read64(FILE *f, void (*fail)(const char *)) {
    unsigned char b[8];
    if (fread(b, 1, 8, f) != 8) fail("truncated boot file");
    uint64_t n = 0;
    for (int i = 7; i >= 0; --i) n = (n << 8) | b[i];
    return n;
}

int bb_boot_mapped(const BbBootSegment *segments, uint64_t count, uint64_t address, uint64_t bytes) {
    for (uint64_t i = 0; i < count; ++i)
        if (address >= segments[i].address && bytes <= segments[i].size &&
            address - segments[i].address <= segments[i].size - bytes) return 1;
    return 0;
}

void bb_boot_load(BbBootImage *boot, const char *path, size_t page_size,
                  void *(*allocate)(size_t), void (*fail)(const char *)) {
    FILE *f = fopen(path, "rb");
    if (!f) fail("cannot open boot file; run prepare.py first");
    char magic[8];
    if (fread(magic, 1, 8, f) != 8 || (memcmp(magic, "BBPROBE1", 8) && memcmp(magic, "BBPROBE2", 8) && memcmp(magic,"BBPROBE3",8) && memcmp(magic,"BBPROBE4",8) && memcmp(magic,"BBPROBE5",8))) fail("bad boot file signature");
    uint64_t size = read64(f, fail), entry = read64(f, fail), ns = read64(f, fail), nr = read64(f, fail);
    uint64_t import_count = read64(f, fail);
    uint64_t capabilities = memcmp(magic, "BBPROBE1", 8) ? read64(f, fail) : 0;
    if (capabilities & ~UINT64_C(1)) fail("unknown runtime capabilities");
    if (!size || size > 512*1024*1024 || entry >= size || !ns || ns > 64 || nr > 1000000 || import_count > 100000)
        fail("boot file limits exceeded");
    int multi=!memcmp(magic,"BBPROBE5",8);
    int linked=!memcmp(magic,"BBPROBE3",8) || !memcmp(magic,"BBPROBE4",8) || multi;
    uint64_t module_count=0;
    BbBootModule *modules=boot->modules;
    uint64_t main_tls[4]={0};
    uint64_t nb=0,procparam=0;
    uint64_t *bindings=calloc(import_count ? import_count : 1,sizeof(*bindings));
    uint64_t *binding_kinds=calloc(import_count ? import_count : 1,sizeof(*binding_kinds));
    if (!bindings || !binding_kinds) fail("allocation failed");
    if (multi) {
        /* BBPROBE5: procparam, eboot TLS, module table, bindings (link_modules.py). */
        procparam=read64(f, fail);
        for (int i=0;i<4;++i) main_tls[i]=read64(f, fail);
        module_count=read64(f, fail);
        if (!module_count || module_count>BB_BOOT_MAX_MODULES) fail("invalid module count");
        for (uint64_t m=0;m<module_count;++m) {
            BbBootModule *x=&modules[m];
            x->base=read64(f, fail); x->size=read64(f, fail); x->init=read64(f, fail); x->tls_address=read64(f, fail);
            x->tls_memsz=read64(f, fail); x->tls_filesz=read64(f, fail); x->tls_module=read64(f, fail);
        }
        nb=read64(f, fail);
    } else if (linked) {
        BbBootModule *x=&modules[0];
        module_count=1;
        x->base=read64(f, fail); x->size=read64(f, fail); x->init=read64(f, fail);
        x->tls_address=read64(f, fail); x->tls_memsz=read64(f, fail); x->tls_filesz=read64(f, fail); x->tls_module=2; nb=read64(f, fail);
        procparam=read64(f, fail);
        if (!memcmp(magic,"BBPROBE4",8)) for (int i=0;i<4;++i) main_tls[i]=read64(f, fail);
    }
    if (linked) {
        if (main_tls[1]>main_tls[2] || main_tls[2]>1024*1024 || main_tls[0]>size ||
            main_tls[1]>size-main_tls[0] || (main_tls[3] & (main_tls[3]-1)) || main_tls[3]>4096)
            fail("invalid eboot TLS metadata");
        for (uint64_t m=0;m<module_count;++m) {
            BbBootModule *x=&modules[m];
            if (x->base>=size || !x->size || x->size>size-x->base || x->init<x->base || x->init-x->base>=x->size ||
                (x->tls_module && (x->tls_address>=size || x->tls_memsz>size-x->tls_address || x->tls_memsz>1024*1024 ||
                                   x->tls_filesz>x->tls_memsz || x->tls_module<2 || x->tls_module>7)))
                fail("invalid linked module metadata");
        }
        if (nb>import_count) fail("invalid binding count");
        for (uint64_t i=0;i<nb;++i) {
            uint64_t index=read64(f, fail),address=read64(f, fail),kind=read64(f, fail);
            int inside=0;
            for (uint64_t m=0;m<module_count;++m)
                if (address>=modules[m].base && address-modules[m].base<modules[m].size) inside=1;
            if (index>=import_count || !inside || (kind!=1 && kind!=2) || bindings[index]) fail("invalid native binding");
            bindings[index]=address; binding_kinds[index]=kind;
        }
    }
    BbBootSegment *segments = calloc(ns, sizeof(*segments));
    BbBootReloc *relocs = calloc(nr ? nr : 1, sizeof(*relocs));
    char (*names)[128] = calloc(import_count ? import_count : 1, sizeof(*names));
    if (!segments || !relocs || !names) fail("allocation failed");
    for (uint64_t i = 0; i < ns; ++i) {
        segments[i].address = read64(f, fail);
        segments[i].size = read64(f, fail);
        segments[i].flags = read64(f, fail);
        if (segments[i].address > size || segments[i].size > size - segments[i].address ||
            segments[i].address % page_size || segments[i].flags > 7) fail("bad segment");
    }
    if (fread(names, 128, import_count, f) != import_count) fail("truncated import names");
    for (uint64_t i = 0; i < import_count; ++i)
        if (!memchr(names[i], 0, 128)) fail("unterminated import name");
    for (uint64_t i = 0; i < nr; ++i) {
        relocs[i].target = read64(f, fail);
        relocs[i].kind = read64(f, fail);
        relocs[i].value = read64(f, fail);
        relocs[i].addend = read64(f, fail);
        if (!bb_boot_mapped(segments, ns, relocs[i].target, 8) || relocs[i].kind > 2 ||
            (relocs[i].kind && relocs[i].value >= import_count) ||
            (relocs[i].kind != 2 && relocs[i].addend) || relocs[i].addend >= page_size) fail("bad relocation");
    }
    for (uint64_t m=0;m<module_count;++m)
        if (!bb_boot_mapped(segments,ns,modules[m].init,1) || (modules[m].tls_module && !bb_boot_mapped(segments,ns,modules[m].tls_address,modules[m].tls_memsz)))
            fail("unmapped module metadata");
    if (module_count && !bb_boot_mapped(segments,ns,procparam,64)) fail("unmapped procparam");
    for (uint64_t i=0;i<import_count;++i) {
        if (!bindings[i]) continue;
        if (!bb_boot_mapped(segments,ns,bindings[i],1)) fail("unmapped native export");
        if (binding_kinds[i]==1) {
            int executable=0;
            for (uint64_t s=0;s<ns;++s)
                if ((segments[s].flags&1) && bindings[i]>=segments[s].address &&
                    bindings[i]-segments[s].address<segments[s].size) executable=1;
            if (!executable) fail("native function is not executable");
        }
    }
    uint8_t *image = allocate((size + page_size - 1) & ~(page_size - 1));
    if (!image) fail("allocation failed");
    if (fread(image, 1, size, f) != size || fgetc(f) != EOF) fail("incorrect memory image size");
    fclose(f);
    boot->size=size; boot->entry=entry; boot->capabilities=capabilities; boot->linked=linked;
    boot->module_count=module_count; boot->procparam=procparam; boot->binding_count=nb;
    memcpy(boot->main_tls, main_tls, sizeof(main_tls));
    boot->segments=segments; boot->segment_count=ns;
    boot->relocs=relocs; boot->reloc_count=nr;
    boot->names=names; boot->import_count=import_count;
    boot->bindings=bindings; boot->binding_kinds=binding_kinds;
    boot->image=image;
}
