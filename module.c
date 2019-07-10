#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdbool.h>
#include <psapi.h>
#include <shlwapi.h>

#include "util.h"

// Look, it works good enough. What other option is there, the Russinovich
// trick of extracting an embedded image?????

#ifdef _WIN64
// If you are trying to make this 64bit, you can just replace this whole file
// with return (UINT64) LoadLibrary(Module)
# error This code is unnescessary on 64bit.
#endif

#pragma warning(disable: 6387)

typedef struct _PROCESS_BASIC_INFORMATION64 {
    ULONGLONG Reserved1;
    ULONGLONG PebBaseAddress;
    ULONGLONG Reserved2[2];
    ULONGLONG UniqueProcessId;
    ULONGLONG Reserved3;
} PROCESS_BASIC_INFORMATION64;

typedef struct _PEB_LDR_DATA64 {
    ULONG Length;
    BOOLEAN Initialized;
    ULONGLONG SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

// Structure is cut down to ProcessHeap.
typedef struct _PEB64 {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    ULONGLONG Mutant;
    ULONGLONG ImageBaseAddress;
    ULONGLONG LoaderData;
    ULONGLONG ProcessParameters;
    ULONGLONG SubSystemData;
    ULONGLONG ProcessHeap;
} PEB64;

typedef struct _UNICODE_STRING64 {
    USHORT Length;
    USHORT MaximumLength;
    ULONGLONG Buffer;
} UNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    ULONGLONG BaseAddress;
    ULONGLONG EntryPoint;
    DWORD64 SizeOfImage;
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY64 HashTableEntry;
    ULONGLONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

NTSTATUS (NTAPI *NtWow64ReadVirtualMemory64)(
    IN HANDLE ProcessHandle,
    IN ULONGLONG BaseAddress,
    OUT PVOID Buffer,
    IN ULONG64 Size,
    OUT PULONG64 NumberOfBytesRead
);

NTSTATUS (NTAPI *NtWow64QueryInformationProcess64) (
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

BOOL FindModule(HANDLE Process, PCHAR Module, PULONGLONG BaseAddress)
{
    CHAR ModuleBaseName[MAX_PATH] = {0};
    WCHAR ModuleWideName[MAX_PATH] = {0};
    PROCESS_BASIC_INFORMATION64 ProcessInfo = {0};
    LDR_DATA_TABLE_ENTRY64 LdrTableEntry = {0};
    PEB_LDR_DATA64 PebLdrData;
    PEB64 Peb;
    ULONGLONG ListHead;
    ULONGLONG LdrEntryAddress;
    NTSTATUS Result;

    Result = NtWow64QueryInformationProcess64(Process,
                                         ProcessBasicInformation,
                                         &ProcessInfo,
                                         sizeof ProcessInfo,
                                         NULL);

    if (Result != 0) {
        fprintf(stderr, "Failed to query PEB address, %#x\n",Result);
        return false;
    }

    Result = NtWow64ReadVirtualMemory64(Process,
                                        ProcessInfo.PebBaseAddress,
                                        &Peb,
                                        sizeof Peb,
                                        NULL);
    if (Result != 0) {
        fprintf(stderr, "Failed to read PEB from %#llx, %#x\n",
                        ProcessInfo.PebBaseAddress,
                        Result);
        return false;
    }

    Result = NtWow64ReadVirtualMemory64(Process,
                                        Peb.LoaderData,
                                        &PebLdrData,
                                        sizeof PebLdrData,
                                        NULL);
    if (Result  != 0) {
        fprintf(stderr, "Failed to PEB LoaderData from %#llx, %#x\n", Peb.LoaderData, Result);
        return false;
    }

    ListHead = Peb.LoaderData
               + (offsetof(PEB_LDR_DATA64, InLoadOrderModuleList)
                - offsetof(PEB_LDR_DATA64, Length));

    for (LdrEntryAddress = PebLdrData.InLoadOrderModuleList.Flink;
         ListHead       != LdrTableEntry.InLoadOrderModuleList.Flink;
         LdrEntryAddress = LdrTableEntry.InLoadOrderModuleList.Flink) {
        Result = NtWow64ReadVirtualMemory64(Process,
                                            LdrEntryAddress,
                                            &LdrTableEntry,
                                            sizeof LdrTableEntry,
                                            NULL);
        if (Result != 0) {
            fprintf(stderr, "Failed to read a LDR List Entry from %#llx, %#x\n",
                            LdrEntryAddress,
                            Result);
            return false;
        }

        if (NtWow64ReadVirtualMemory64(Process,
                                       LdrTableEntry.BaseDllName.Buffer,
                                       ModuleWideName,
                                       LdrTableEntry.BaseDllName.MaximumLength,
                                       FALSE) != 0) {
            fprintf(stderr, "Failed to read module name from %#llx, %#x\n",
                            LdrTableEntry.BaseDllName.Buffer,
                            Result);
            return false;
        }

        PathRemoveExtensionW(ModuleWideName);

        // Translate to ANSI.
        snprintf(ModuleBaseName, sizeof ModuleBaseName, "%S", ModuleWideName);

        if (stricmp(ModuleBaseName, Module) == 0) {
            *BaseAddress = LdrTableEntry.BaseAddress;
            return true;
        }
    }

    return false;
}

// Look, I know this is hacky ;)
UINT64 QueryModuleHandle64(PCHAR Module)
{
    BOOL WoWStatus;
    DWORD Processes[4096];
    DWORD ProcessTableSize;
    ULONGLONG BaseAddress;

    if (!NtWow64ReadVirtualMemory64 || !NtWow64QueryInformationProcess64) {
        NtWow64ReadVirtualMemory64 = (PVOID) GetProcAddress(
            GetModuleHandle("NTDLL"),
            "NtWow64ReadVirtualMemory64");
        NtWow64QueryInformationProcess64 = (PVOID) GetProcAddress(
            GetModuleHandle("NTDLL"),
            "NtWow64QueryInformationProcess64");
    }

    // Get a list of all the system processes.
    if (EnumProcesses(Processes, sizeof Processes, &ProcessTableSize) == FALSE) {
        LogMessage(stderr, "Failed to EnumProcesses(), %#x", GetLastError());
        return 0;
    }

    ProcessTableSize /= sizeof *Processes;

    // For each process, try to get a handle, see if it's a 64bit process, and
    // if so, see if it has the requested module loaded.
    //
    // Yes, I know - "wtffff is Tavis doing"...let's see your solution smarty pants!
    for (DWORD i = 0; i < ProcessTableSize; i++) {
        BOOL Result;
        HANDLE Process;

        Process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                              FALSE,
                              Processes[i]);
        Result  = FALSE;

        if (Process != NULL) {
            if (IsWow64Process(Process, &WoWStatus) && !WoWStatus) {
                Result = FindModule(Process, Module, &BaseAddress);
            }

            CloseHandle(Process);

            if (Result) {
                return BaseAddress;
            }
        }
    }

    return 0;
}

INT64 FindGadgetOffset(PCHAR Module, PCHAR Gadget, SIZE_T GadgetLen)
{
    FILE *Input;
    INT64 Result = -1;
    CHAR ModulePath[MAX_PATH];
    CHAR Buffer[8192];
    CHAR *Ptr;
    PVOID OldValue;

    // Copy the name while we figure out where it is.
    strncpy(ModulePath, Module, MAX_PATH - 5);

    // Is it already fully qualified?
    if (PathIsRelative(Module)) {
        // This doesnt do anything if there already is an extension.
        PathAddExtension(ModulePath, ".DLL");

        // Check the usual places for it.
        PathFindOnPathA(ModulePath, NULL);
    }

    LogMessage(stdout, "Guessed %s => %s", Module, ModulePath);

    // Disable Redirection so we get the real files.
    Wow64DisableWow64FsRedirection(&OldValue);

    Input = fopen(ModulePath, "rb");

    // Restore Redirection.
    Wow64RevertWow64FsRedirection(OldValue);

    while (Input) {
        size_t count = fread(Buffer, 1, sizeof Buffer, Input);
        size_t offset = 0;

        //LogMessage(stderr, "fread() => %lu (offset %lu)", count, ftell(Input));

        if (count == 0)
            goto cleanup;

        for (Ptr = memchr(Buffer, *Gadget, count);
             Ptr;
             Ptr = memchr(Ptr + 1, *Gadget, count - (offset + 1))) {
            offset = Ptr - Buffer;

            // If this match spans a read, seek back so its at the start.
            if (count - offset < GadgetLen) {

                //LogMessage(stderr, "Not enough data, count %lu offset %lu, ftell %lu", count, offset, ftell(Input));

                // Make sure there was enough data to read.
                if (offset) {
                    //LogMessage(stderr, "rewind");
                    fseek(Input, -offset, SEEK_CUR);
                    break;
                }

                // Not enough data left.
                goto cleanup;
            }

            if (memcmp(Ptr, Gadget, GadgetLen) == 0) {
                //LogMessage(stderr, "match at %lu (ftell %lu)", offset, ftell(Input));
                Result = ftell(Input) - count + offset;
                goto cleanup;
            }
        }
    }

cleanup:
    if (Input) {
        fclose(Input);
    }
    return Result;
}