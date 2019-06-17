#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <assert.h>
#include <objbase.h>
#include <sddl.h>
#include <msctf.h>
#include <shlwapi.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include "ntdll.h"
#include "ntalpctyp.h"
#include "ntalpc.h"

#include "ctfinternal.h"
#include "ctftool.h"
#include "marshal.h"
#include "util.h"
#include "winutil.h"

#pragma warning(disable: 6011 6387)

// This just duplicates the logic that ctfmon uses for identifying Windows.
BOOL GetActiveThreadInfo(PDWORD ThreadId, HWND *Window, PDWORD ProcessId)
{
    HWND IMEWindow = 0;
    WCHAR ClassName[32] = {0};

    *Window = GetForegroundWindow();

    if (*Window) {
        RealGetWindowClassW(*Window, ClassName, _countof(ClassName) - 1);
        if (wcscmp(ClassName, L"ConsoleWindowClass") == 0) {
            //LogMessage(stdout, "The active window uses ConsoleWindowClass.");
            IMEWindow = ImmGetDefaultIMEWnd(*Window);
        }
    }
    if (IMEWindow) {
        *ThreadId = GetWindowThreadProcessId(IMEWindow, ProcessId);
    } else {
        *ThreadId = GetWindowThreadProcessId(*Window, ProcessId);
    }

    return *Window != NULL;
}

DWORD GetFocusThread(void)
{
    HWND Window;
    DWORD ThreadId;
    GetActiveThreadInfo(&ThreadId, &Window, NULL);
    return ThreadId;
}

#define MAX_PROCESS 16384

PVOID QueryImageName(DWORD ProcessId)
{
    CHAR ImageName[MAX_PATH];
    ULONG ReturnLength;
    PSYSTEM_PROCESS_INFORMATION ProcessArray, Current;
    PVOID ReturnValue = NULL;
    NTSTATUS Result;

    ReturnLength = MAX_PROCESS * sizeof(SYSTEM_PROCESS_INFORMATION);
    ProcessArray = malloc(ReturnLength);

    Result = NtQuerySystemInformation(SystemProcessInformation, ProcessArray, ReturnLength, &ReturnLength);

    if (Result != 0) {
      LogMessage(stderr, "Unexpected NtQuerySystemInformation() result, %#x", Result);
      return NULL;
    }

    for (Current = ProcessArray;; Current = (PVOID)((PBYTE)(Current) + Current->NextEntryOffset)) {
        #pragma warning(suppress: 4047)
        if (Current->UniqueProcessId == ProcessId) {
          snprintf(ImageName, sizeof ImageName, "%wZ", &Current->ImageName);
          ReturnValue = strdup(ImageName);
          break;
        }
        if (Current->NextEntryOffset == 0) {
          LogMessage(stderr, "QueryImageName, Unknown Process %u", ProcessId);
          break;
        }
    }
    free(ProcessArray);
    return ReturnValue;
}

// This finds the first process with matching ImageName, and returns it's SessionId.
DWORD GetSessionIdByImageName(PCHAR ImageName)
{
    CHAR CurrentImageName[MAX_PATH];
    ULONG ReturnLength;
    PSYSTEM_PROCESS_INFORMATION ProcessArray, Current;
    DWORD ReturnValue = 0;
    NTSTATUS Result;

    ReturnLength = MAX_PROCESS * sizeof(SYSTEM_PROCESS_INFORMATION);
    ProcessArray = malloc(ReturnLength);

    Result = NtQuerySystemInformation(SystemProcessInformation, ProcessArray, ReturnLength, &ReturnLength);

    if (Result != 0) {
      LogMessage(stderr, "Unexpected NtQuerySystemInformation() result, %#x", Result);
      return 0;
    }

    for (Current = ProcessArray;; Current = (PVOID)((PBYTE)(Current) + Current->NextEntryOffset)) {
      snprintf(CurrentImageName, sizeof CurrentImageName, "%wZ", &Current->ImageName);
        if (stricmp(CurrentImageName, ImageName) == 0) {
          ReturnValue = Current->SessionId;
          break;
        }
        if (Current->NextEntryOffset == 0) {
          LogMessage(stderr, "QuerySessionIdByImageName, Unknown Process %s", ImageName);
          break;
        }
    }
    free(ProcessArray);
    return ReturnValue;
}

UINT64 QueryModuleHandle32(PCHAR ModuleName)
{
    HMODULE Module = LoadLibrary(ModuleName);

    if (Module) {
        FreeLibrary(Module);
    }

    return (UINT64) Module;
}
