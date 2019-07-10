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

typedef struct _SECTION_PARAMS {
    char                *SectionName;
    uint64_t             SectionBase;
    image_section_header SectionHeader;
} SECTION_PARAMS, *PSECTION_PARAMS;

static int FindSection(void *user,
                       peparse::VA secBase,
                       std::string &secName,
                       peparse::image_section_header s,
                       peparse::bounded_buffer *data)
{
    auto params  = static_cast<PSECTION_PARAMS>(user);
    auto address = static_cast<std::uint64_t>(secBase);

    if (params->SectionName == secName) {
        params->SectionHeader = s;
        params->SectionBase = address;
    }

    return 0;
}

extern "C" bool GetSectionProperty(char *Filename,
                                   char *Section,
                                   char *Property,
                                   uint64_t *Result)
{
    SECTION_PARAMS Params;
    parsed_pe *p = ParsePEFromFile(Filename);

    if (p == NULL) {
        return false;
    }

    Params.SectionName = Section;
    Params.SectionBase = 0ULL;

    IterSec(p, FindSection, &Params);

    DestructParsedPE(p);

    if (Params.SectionBase == 0)
        return false;

    if (strcmp(Property, "VirtualAddress") == 0) {
        *Result = Params.SectionHeader.VirtualAddress;
    } else if (strcmp(Property, "PointerToRawData") == 0) {
        *Result = Params.SectionHeader.PointerToRawData;
    } else if (strcmp(Property, "SizeOfRawData") == 0){
        *Result = Params.SectionHeader.SizeOfRawData;
    } else if (strcmp(Property, "Characteristics")  == 0) {
        *Result = Params.SectionHeader.Characteristics;
    } else {
        return false;
    }

    return true;
}