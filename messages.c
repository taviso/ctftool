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
#include "messages.h"

MSG LastMsg;

// In many scenarios, we might want the CTF server to post us messages intended
// for other threads. This thread just loops and reads messages.
// The last message received is accessible to ctftool commands.
DWORD WINAPI MessageHandlerThread(PVOID Parameter)
{
    BOOL Result;

    while (true) {
        Result = GetMessage(&LastMsg, NULL, 0, 0);
        if (Result != -1) {
            LogMessage(stdout, "Message Received:\n"
                               " hwnd:      %p\n"
                               " wParam:    %#x\n"
                               " lParam:    %#x\n"
                               " time:      %#x\n"
                               " pt:        %ld %ld\n",
                               LastMsg.hwnd,
                               LastMsg.wParam,
                               LastMsg.lParam,
                               LastMsg.time,
                               LastMsg.pt.x,
                               LastMsg.pt.y);
        } else {
            LogMessage(stdout, "GetMessage() returned an error, %#x", GetLastError());
        }
    }
}

//window thread
//wtc
