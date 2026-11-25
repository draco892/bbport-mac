#include "runtime.h"

static const struct { const char *nid, *symbol; } import_names[]={
#include "import_names.inc"
#include "import_names_extra.inc"
};
/* Symbol name for an import (NID, with or without its library/module suffix), or NULL when it is
 * not known. The NID alone decides: it is the hash of the symbol's name, whatever library a game
 * imports it from. */
const char *runtime_symbol(const char *nid) {
    const size_t length=strcspn(nid,"#");
    for (size_t i=0;i<sizeof(import_names)/sizeof(*import_names);++i) {
        const char *entry=import_names[i].nid;
        if (!strncmp(nid,entry,length) && (entry[length]=='#' || entry[length]==0))
            return import_names[i].symbol;
    }
    return NULL;
}
/* Same symbol name means same contract whether imported from libkernel or
 * libScePosix, so newer modules resolve by name through runtime_symbol. */
uintptr_t runtime_lookup(const RuntimeExport *table,size_t count,const char *nid) {
    const char *symbol=runtime_symbol(nid);
    if (!symbol) return 0;
    for (size_t i=0;i<count;++i) if (!strcmp(symbol,table[i].name)) return (uintptr_t)table[i].function;
    return 0;
}
const char *runtime_import_name(const char *name) {
    const char *symbol=runtime_symbol(name);
    return symbol ? symbol : "name not resolved; see analysis.json import_name_hints";
}
