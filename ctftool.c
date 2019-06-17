#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#include <initguid.h>
#include <stdio.h>
#include <stdlib.h>
#include <msctf.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include "ntdll.h"
#include "ntalpctyp.h"
#include "ntalpc.h"

#include "wineditline/src/editline/readline.h"
#include "ctfinternal.h"
#include "ctftool.h"
#include "marshal.h"
#include "util.h"
#include "messages.h"
#include "command.h"

#pragma warning(disable : 4090 6011)

FARPROC AlpcInitializeMessageAttribute;
FARPROC AlpcGetMessageAttribute;
FARPROC GUIDFromString;

BOOL InitializeAlpcRoutines()
{
    HMODULE NtDll = GetModuleHandle("NTDLL");
    HMODULE Shell32 = LoadLibrary("SHELL32");

    if (NtDll == NULL)
        return FALSE;

    if (Shell32 == NULL)
        return FALSE;

    AlpcInitializeMessageAttribute = GetProcAddress(NtDll, "AlpcInitializeMessageAttribute");
    AlpcGetMessageAttribute = GetProcAddress(NtDll, "AlpcGetMessageAttribute");
    AlpcGetMessageAttribute = GetProcAddress(NtDll, "AlpcGetMessageAttribute");
    GUIDFromString = GetProcAddress(Shell32, MAKEINTRESOURCE(704));
    return TRUE;
}

BOOL GetServerPortName(PWCHAR Name, SIZE_T NameMax)
{
    WCHAR DesktopName[MAX_PATH];
    HDESK ThreadDesktop;
    DWORD NameLength;
    DWORD SessionId;

    // Note that it is not necessary to close this handle.
    ThreadDesktop = GetThreadDesktop(GetCurrentThreadId());

    // Find the SessionId from the PEB.
    SessionId = NtCurrentTeb()->ProcessEnvironmentBlock->SessionId;

    // Find the name of the current desktop.
    if (GetUserObjectInformationW(ThreadDesktop,
                                  UOI_NAME,
                                  DesktopName,
                                  sizeof DesktopName,
                                  &NameLength)) {
        _snwprintf(Name, NameMax / sizeof(WCHAR), L"\\BaseNamedObjects\\msctf.server%s%u",
                                                  DesktopName,
                                                  SessionId);
        return TRUE;
    }

    return FALSE;
}

HANDLE OpenAlpcPort(PWCHAR AlpcPortName, PPORT_MESSAGE ConnectMessage, SIZE_T MessageSize)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING PortName;
    ALPC_PORT_ATTRIBUTES PortAttributes;
    HANDLE AlpcHandle = INVALID_HANDLE_VALUE;
    ULONG BufferLength = 64;
    NTSTATUS Result;

    RtlInitUnicodeString(&PortName, AlpcPortName);
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    InitializeMessageHeader(ConnectMessage, MessageSize, LPC_CONNECTION_REQUEST);

    ZeroMemory(&PortAttributes, sizeof PortAttributes);

    PortAttributes.SecurityQos.Length = sizeof(PortAttributes.SecurityQos);
    PortAttributes.SecurityQos.ContextTrackingMode = TRUE;
    PortAttributes.MaxMessageLength = 512;
    PortAttributes.DupObjectTypes = 0x88000000;

    Result = NtAlpcConnectPort(&AlpcHandle,
                               &PortName,
                               &ObjectAttributes,
                               &PortAttributes,
                               0,
                               NULL,
                               ConnectMessage,
                               &BufferLength,
                               NULL,
                               NULL,
                               NULL);

    if (!NonInteractive) {
        LogMessage(stdout, "NtAlpcConnectPort(\"%S\") => %#x", AlpcPortName, Result);
    }

    return AlpcHandle;
}

NTSTATUS SendReceiveMarshalData(HANDLE AlpcHandle,
                                ULONG TypeFlags,
                                PCTF_MARSHAL_PARAM Params,
                                ULONG ParamCount,
                                DWORD DestinationThread)
{
    NTSTATUS Result;
    SIZE_T BufferLength;
    PCTF_MSGBASE SendReceiveBuffer;

    // We need enough space to append the Params, it has to be a contiguous buffer.
    BufferLength = sizeof(CTF_MSGBASE) + GetParamsSize(Params, ParamCount);

    // Allocate and initialize.
    SendReceiveBuffer = calloc(BufferLength, 1);

    // Append marshal parameters.
    memcpy(&SendReceiveBuffer[1], Params, GetParamsSize(Params, ParamCount));

    // Configure Message.
    SendReceiveBuffer->Message = TypeFlags;
    SendReceiveBuffer->SrcThreadId = ClientThreadId;
    SendReceiveBuffer->DstThreadId = DestinationThread;

    SendReceiveBuffer->ulNumParams  = ParamCount;
    SendReceiveBuffer->ulDataLength = GetParamsSize(Params, ParamCount);

    // Send the data.
    Result = SendReceivePortMessage(AlpcHandle,
                                    &SendReceiveBuffer->Header,
                                    BufferLength,
                                    NULL);

    // Check if the send worked.
    if (Result != 0) {
        goto cleanup;
    }

    // Copy the RPC result.
    Result = SendReceiveBuffer->Result;

    // The monitor leaks a stack pointer here.
    LeakedStackPointer = SendReceiveBuffer->pData;

    // Restore data so that caller can see any returned data.
    memcpy(Params, &SendReceiveBuffer[1], GetParamsSize(Params, ParamCount));

  cleanup:
    // All done with our copy.
    free(SendReceiveBuffer);
    return Result;
}

// I don't know what these are, so make them accessible via set.
UINT64 ProxyExtra1;
UINT64 ProxyExtra2;
UINT64 ProxyExtra3;

NTSTATUS SendReceiveProxyData(HANDLE AlpcHandle,
                              ULONG TypeFlags,
                              PCTF_MARSHAL_PARAM Params,
                              ULONG ParamCount,
                              PCTF_MARSHAL_COMSTUB Stub,
                              DWORD FunctionIndex,
                              DWORD DestinationThread)
{
    NTSTATUS Result;
    SIZE_T BufferLength;
    PCTF_MSGBASE SendReceiveBuffer;
    PCTF_MARSHAL_PARAM ParamPtr;
    CTF_PROXY_SIGNATURE ProxySignature  = {
        .FunctionIndex = FunctionIndex,
        .StubId = Stub->StubId,
        .Timestamp = Stub->Timestamp,
        .field_1C = ProxyExtra1,
        .field_20 = ProxyExtra2,
        .field_24 = ProxyExtra3,
    };

    // Copy the correct GUID over from the Stub.
    memcpy(&ProxySignature.Interface, &Stub->Interface, sizeof(GUID));

    // We need enough space to append the Params, it has to be a contiguous buffer.
    BufferLength = sizeof(CTF_MSGBASE) + sizeof(CTF_PROXY_SIGNATURE) + GetParamsSize(Params, ParamCount);

    // Allocate and initialize.
    SendReceiveBuffer = calloc(BufferLength, 1);

    // Append proxy parameters.
    ParamPtr = mempcpy(&SendReceiveBuffer[1], &ProxySignature, sizeof(CTF_PROXY_SIGNATURE));

    // Append marshalled parameters.
    memcpy(ParamPtr, Params, GetParamsSize(Params, ParamCount));

    // When parameters are Proxied, their base offset needs to adjusted because of the Proxy header.
    for (int i = 0; i < ParamCount; i++) {
        ParamPtr[i].Start += sizeof(CTF_PROXY_SIGNATURE);
    }

    // Configure Message.
    SendReceiveBuffer->Message = TypeFlags;
    SendReceiveBuffer->SrcThreadId = ClientThreadId;
    SendReceiveBuffer->DstThreadId = DestinationThread;

    // As far as I can tell, only this parameter is used.
    SendReceiveBuffer->ulDataLength = sizeof(ProxySignature) + GetParamsSize(Params, ParamCount);
    SendReceiveBuffer->ulNumParams = ParamCount;

    // Send the data.
    Result = SendReceivePortMessage(AlpcHandle,
                                    &SendReceiveBuffer->Header,
                                    BufferLength,
                                    NULL);

    if (Result != 0) {
        goto cleanup;
    }

    Result = SendReceiveBuffer->Result;

    // Restore the adjusted Base
    for (int i = 0; i < ParamCount; i++) {
        ParamPtr[i].Start -= sizeof(CTF_PROXY_SIGNATURE);
    }

    // Restore data so that caller can see any returned data.
    memcpy(Params, ParamPtr, GetParamsSize(Params, ParamCount));

  cleanup:
    // All done with our copy.
    free(SendReceiveBuffer);
    return Result;
}

NTSTATUS SendReceivePortMessage(HANDLE AlpcHandle,
                                PPORT_MESSAGE PortMessage,
                                ULONG BufferLength,
                                PLARGE_INTEGER Timeout)
{
    NTSTATUS Result;
    ULONG MessageAttributeSize;
    PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes = NULL;

    Result = AlpcInitializeMessageAttribute(0x60000000, NULL, 0, &MessageAttributeSize);

    if (Result != STATUS_BUFFER_TOO_SMALL) {
        LogMessage(stderr, "unexpected result from AlpcInitializeMessageAttribute()");
        goto cleanup;
    }

    ReceiveMessageAttributes = calloc(1, MessageAttributeSize);

    if (AlpcInitializeMessageAttribute(0x60000000,
                                       ReceiveMessageAttributes,
                                       MessageAttributeSize,
                                       &MessageAttributeSize) < 0) {
        LogMessage(stderr, "AlpcInitializeMessageAttribute failed");
        goto cleanup;
    }

    ReceiveMessageAttributes->ValidAttributes = 0;

    InitializeMessageHeader(PortMessage, BufferLength, 0);

    Result = NtAlpcSendWaitReceivePort(AlpcHandle,
                                       ALPC_MSGFLG_SYNC_REQUEST,
                                       PortMessage,
                                       NULL,
                                       PortMessage,
                                       &BufferLength,
                                       ReceiveMessageAttributes,
                                       Timeout);

cleanup:
    free(ReceiveMessageAttributes);
    return Result;
}

int main(int argc, char **argv)
{
    PCHAR CommandLine;
    ULONG Result = 1;
    HANDLE MessageThread;

    InitializeAlpcRoutines();

    MessageThread = CreateThread(NULL, 0, MessageHandlerThread, NULL, 0, NULL);

    if (MessageThread) {
        ClientThreadId = GetThreadId(MessageThread);
    }

    LogMessage(stdout, "An interactive ctf exploration tool by @taviso.");
    LogMessage(stdout, "Type \"help\" for available commands.");

    LogMessage(stdout, "Most commands require a connection, see \"help connect\".");

    read_history(".ctfhistory");

    do {
        CommandLine = readline("ctf> ");

        //  Check for EOF.
        if (CommandLine == NULL)
            break;

        // Save this to the history so that arrow keys work.
        add_history(CommandLine);

        Result = DispatchCommand(CommandLine);

        rl_free(CommandLine);
    } while (Result != 0);

    // Record all our commands.
    write_history(".ctfhistory");

    // Cleanup.
    if (PortHandle)
        CloseHandle(PortHandle);
    if (MessageWindow)
        DestroyWindow(MessageWindow);

    return 0;
}
