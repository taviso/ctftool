#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#include <objbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <msctf.h>
#include <stdbool.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include "ntdll.h"
#include "ntalpctyp.h"
#include "ntalpc.h"

#include "ctfinternal.h"
#include "ctftool.h"
#include "util.h"

#pragma warning(disable: 6031 6308 28182)

// Calculate size for malloc of the existing params.
SIZE_T GetParamsSize(PCTF_MARSHAL_PARAM Base, ULONG Count)
{
    SIZE_T Size = Count * sizeof(CTF_MARSHAL_PARAM);

    for (ULONG i = 0; i < Count; i++) {
        Size += Base[i].Size;
    }

    return Size;
}

void MarshalParamsDumpData(PCTF_MARSHAL_PARAM Base, ULONG Index)
{
    LogMessage(stderr, "Dumping Marshal Parameter %u (Base %p, Type %#x, Size %#x, Offset %#x)",
                       Index,
                       Base,
                       Base[Index].TypeFlags,
                       Base[Index].Size,
                       Base[Index].Start);

    hexdump((PVOID)((PBYTE)(Base) + Base[Index].Start), Base[Index].Size);

    switch (Base[Index].TypeFlags & MARSHAL_TYPE_MASK) {
        default:
            LogMessage(stderr, "No support for decoding type %#x", Base[Index].TypeFlags);
            // fallthrough
        case MARSHAL_TYPE_STRUCT:
        case MARSHAL_TYPE_DATA: {
            GUID *GuidData = (PVOID)((PBYTE)(Base) + Base[Index].Start);
            WCHAR GuidString[64];

            // Just look at the hexdump above, I guess.
            LogMessage(stdout, "Marshalled Value %u, DATA", Index);

            // Well, I'll parse it for you if it's a GUID.
            if (Base[Index].Size == sizeof(GUID)) {
                StringFromGUID2(GuidData, GuidString, _countof(GuidString));
                LogMessage(stdout, "Possibly a GUID, %S", GuidString);
            }

            break;
        }

        // The value returned is the GUID followed by a Stub ID.
        case MARSHAL_TYPE_COM: {
            PCTF_MARSHAL_COMSTUB Stub = (PVOID)((PBYTE)(Base) + Base[Index].Start);
            WCHAR Interface[64];

            // This is a marshalled comstub
            assert(Base[Index].Size == sizeof(CTF_MARSHAL_COMSTUB));

            StringFromGUID2(&Stub->Interface, Interface, _countof(Interface));

            LogMessage(stdout, "Marshalled Value %u, COM %S, ID %u, Timestamp %#x",
                               Index,
                               Interface,
                               Stub->StubId,
                               Stub->Timestamp);
            break;
        }
        case MARSHAL_TYPE_LONG:
        case MARSHAL_TYPE_WORD:
        case MARSHAL_TYPE_INT: {
            PINT64 Value = (PVOID)((PBYTE)(Base) + Base[Index].Start);
            if (Base[Index].Size == sizeof(INT64)) {
                LogMessage(stdout, "Marshalled Value %u, INT %016llx", Index, *Value);
            } else {
                LogMessage(stderr, "Invalid INT Size %#x, Cannot decode.", Base[Index].Size);
            }
            break;
        }
    }
    return;
}
// Insert the data for param Index
PVOID MarshalParamsInsertData(PCTF_MARSHAL_PARAM Base,
                              ULONG Count,
                              ULONG Index,
                              DWORD TypeFlags,
                              PVOID Data,
                              SIZE_T Size,
                              BOOL FreeOrig)
{
    SIZE_T CurrentSize;

    // If Base is NULL, allocate space for headers.
    if (Base == NULL) {
        Base = calloc(Count, sizeof(CTF_MARSHAL_PARAM));
    }

    CurrentSize = GetParamsSize(Base, Count);
    Base = realloc(Base, CurrentSize + Size);
    Base[Index].Size = Size;
    Base[Index].TypeFlags = TypeFlags;
    Base[Index].Start = CurrentSize;

    // Duplicate the specified data.
    if (Data) {
        memcpy((PBYTE)(Base) + CurrentSize, Data, Size);
    }

    if (FreeOrig)
        free(Data);

    return Base;
}

void MarshalParamsFree(PCTF_MARSHAL_PARAM Base)
{
    free(Base);
}

// Translate a CTF command name into a string.
PCHAR GetCommandName(UCHAR Command)
{
    static char *MessageNames[UCHAR_MAX] = {
        [MSG_NOOP]              = "MSG_NOOP",
        [MSG_FINDPROPERTY]      = "MSG_FINDPROPERTY",
        [MSG_GETPROPERTY]       = "MSG_GETPROPERTY",
        [MSG_SETPROPERTY]       = "MSG_SETPROPERTY",
        [MSG_CALLSTUB]          = "MSG_CALLSTUB",
        [MSG_CREATESTUB]        = "MSG_CREATESTUB",
        [MSG_STUBCLEANUP]       = "MSG_STUBCLEANUP",
        [MSG_GETCLIENTINFO]     = "MSG_GETCLIENTINFO",
        [MSG_GETCLIENTINFOEX]   = "MSG_GETCLIENTINFOEX",
        [MSG_GETTHREADHWND]     = "MSG_GETTHREADHWND",
        [MSG_SETTHREADHWND]     = "MSG_SETTHREADHWND",
        [MSG_SETKBLAYOUT]       = "MSG_SETKBLAYOUT",
        [MSG_SETPROFILE]        = "MSG_SETPROFILE",
        [MSG_GETMONITORPID]     = "MSG_GETMONITORPID",
        [MSG_KEYEVENT]          = "MSG_KEYEVENT",
        [MSG_REMOVEINPUTPROFILE]= "MSG_REMOVEINPUTPROFILE",
        [MSG_SETRANGETEXT]      = "MSG_SETRANGETEXT",
        [MSG_REQUESTEDITSESSION]= "MSG_REQUESTEDITSESSION",
        [MSG_CANCELEDITSESSION] = "MSG_CANCELEDITSESSION",
        [MSG_ADDHOTKEY]         = "MSG_ADDHOTKEY",
        [MSG_REMOVEHOTKEY]      = "MSG_ADDHOTKEY",
    };

    return MessageNames[Command];
}

// Translate a name into a number.
INT GetCommandNum(PCHAR Command)
{
    for (INT i = 0; i < UCHAR_MAX; i++) {
        PCHAR Name = GetCommandName(i);
        if (Name && strcmp(Name, Command) == 0)
            return i;
    }

    return -1;
}

PCHAR GetMarshalFlagName(DWORD Flag)
{
    static struct {
        DWORD Flag;
        PCHAR Name;
    } FlagNames[] = {
        { MARSHAL_FLAG_INPUT, "MARSHAL_FLAG_INPUT" },
        { MARSHAL_FLAG_OUTPUT, "MARSHAL_FLAG_OUTPUT" },
        { MARSHAL_FLAG_ARRAY, "MARSHAL_FLAG_ARRAY" },
        { MARSHAL_FLAG_ALLOCATED, "MARSHAL_FLAG_ALLOCATED" },
        { MARSHAL_FLAG_PRESENT, "MARSHAL_FLAG_PRESENT" },
        { MARSHAL_TYPE_DATA, "MARSHAL_TYPE_DATA" },
        { MARSHAL_TYPE_COM, "MARSHAL_TYPE_COM" },
        { MARSHAL_TYPE_INT, "MARSHAL_TYPE_INT" },
        { MARSHAL_TYPE_STR, "MARSHAL_TYPE_STR" },
        { MARSHAL_TYPE_GDI, "MARSHAL_TYPE_GDI" },
        { MARSHAL_TYPE_ICON, "MARSHAL_TYPE_ICON" },
        { MARSHAL_TYPE_STRUCT, "MARSHAL_TYPE_STRUCT" },
        { MARSHAL_TYPE_LONG, "MARSHAL_TYPE_LONG" },
        { MARSHAL_TYPE_WORD, "MARSHAL_TYPE_WORD" },
        { MARSHAL_TYPE_MEM, "MARSHAL_TYPE_MEM" },
    };

    for (ULONG i = 0; i < _countof(FlagNames); i++) {
        if (FlagNames[i].Flag == Flag)
            return FlagNames[i].Name;
    }

    return NULL;
}

BOOL GetMarshalFlagsString(DWORD Flags, PCHAR Result, SIZE_T MaxSize)
{
    BOOL FirstFlag = true;

    ZeroMemory(Result, MaxSize);

    for (ULONG bit = 0; bit < 32; bit++) {
        if (Flags & (1 << bit)) {
            PCHAR Name = GetMarshalFlagName(1 << bit);
            PCHAR Current = strdup(Result);

            if (Name == NULL) {
                Name = "<INVALID>";
            }

            snprintf(Result, MaxSize, "%s%s%s", FirstFlag ? "" : "|", Current, Name);

            free(Current);

            FirstFlag = false;
        }
    }

    return true;
}

DWORD GetMarshalFlagNum(PCHAR Flag)
{
    for (ULONG bit = 0; bit < 32; bit++) {
        PCHAR Name = GetMarshalFlagName(1 << bit);
        if (Name && strcmp(Name, Flag) == 0)
            return 1 << bit;
    }

    return 0;
}

DWORD DecodeMarshalFlagsString(PCHAR MarshalFlags)
{
    DWORD Result = 0;
    PCHAR Token;
    DWORD Value;

    // Make a copy of the parameter we can change.
    MarshalFlags = strdup(MarshalFlags);

    Token = strtok(MarshalFlags, "| \t");
    Value = GetMarshalFlagNum(Token);

    if (Value == 0) {
        LogMessage(stderr, "Invalid flag %s ignored", Token);
    }

    while (Token = strtok(NULL, "| \t")) {
        Value = GetMarshalFlagNum(Token);

        if (Value == 0) {
            LogMessage(stderr, "Invalid flag %s ignored", Token);
        }

        Result |= Value;
    }

    free(MarshalFlags);
    return Result;
}
