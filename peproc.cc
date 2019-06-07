#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

#include "pe-parse/pe-parser-library/include/parser-library/parse.h"

using namespace peparse;

typedef struct _SEARCH_PARAMS {
    char       *SymbolName;
    uint64_t    SymbolAddress;
} SEARCH_PARAMS, *PSEARCH_PARAMS;

static int SearchExports(void *user,
                         VA funcAddr,
                         std::string &mod,
                         std::string &func) {
    auto params  = static_cast<PSEARCH_PARAMS>(user);
    auto address = static_cast<std::uint64_t>(funcAddr);

    if (params->SymbolName == func) {
        params->SymbolAddress = address;
    }

    return 0;
}

extern "C" bool GetSymbolInfo64(char *Filename,
                                char *Export,
                                bool *Is64,
                                uint64_t *ImageBase,
                                uint64_t *Address)
{
    parsed_pe *p = ParsePEFromFile(Filename);
    SEARCH_PARAMS Parameters;

    if (p == NULL) {
        return false;
    }

    *Is64 = p->peHeader.nt.OptionalMagic != NT_OPTIONAL_32_MAGIC;

    *ImageBase = *Is64 ? p->peHeader.nt.OptionalHeader64.ImageBase
                       : p->peHeader.nt.OptionalHeader.ImageBase;

    Parameters.SymbolName = Export;
    Parameters.SymbolAddress = 0ULL;

    IterExpVA(p, SearchExports, &Parameters);

    *Address = Parameters.SymbolAddress;

    DestructParsedPE(p);

    if (Parameters.SymbolAddress)
        return true;

    return false;
}
