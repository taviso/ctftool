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
#include <string.h>
#include <shellapi.h>
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
#include "commanddoc.h"
#include "messages.h"
#include "winutil.h"
#include "command.h"

#pragma warning(disable: 4090 6387 28159 28278)

UINT64 DefaultThread;
UINT64 DefaultStub;
UINT64 RepeatDelay;
HANDLE PortHandle;
HWND MessageWindow;
UINT64 LeakedStackPointer;
UINT64 LastModuleBase;
UINT64 LastSymbolOffset;
ULONG NumStubs;
STUB_RECORD StubRecords[MAX_STUBS];
ULONG CountMarshalParams;
ULONGLONG LastCommandResult;
ULONGLONG LastRegistryValue;
ULONG CurrentMarshalParam;
PCTF_MARSHAL_PARAM MarshalParams;
UINT64 ClientThreadId;
UINT64 ClientFlags;
ULONG NonInteractive;
UINT64 LastGadget;
UINT64 LastSectionResult;
ULONGLONG UserRegisters[6];

COMMAND_HANDLER CommandHandlers[] = {
    { "help", 0, HelpDoc, "List available commands.", HelpHandler },
    { "exit", 0, ExitDoc, "Exit the shell.", ExitHandler },
    { "quit", 0, NULL, NULL, ExitHandler },
    { "q", 0, NULL, NULL, ExitHandler },
    { "connect", 0, ConnectDoc, "Connect to CTF ALPC Port.", ConnectHandler },
    { "info", 0, InfoDoc, "Query server informaiton.", InfoHandler },
    { "scan", 0, ScanDoc, "Enumerate connected clients.", ScanHandler },
    { "callstub", 3, CallStubDoc, "Ask a client to invoke a function.", CallStubHandler },
    { "createstub", 3, CreateStubDoc, "Ask a client to instantiate CLSID.", CreateStubHandler },
    { "hijack", 2, HijackDoc, "Attempt to hijack an ALPC server path.", HijackHandler },
    { "sendinput", 2, NULL, "Send keystrokes to thread.", NULL },
    { "setarg", 1, SetArgDoc, "Marshal a parameter.", SetArgHandler },
    { "getarg", 1, GetArgDoc, "Unmarshal a parameter.", GetArgHandler },
    { "wait", 1, WaitDoc, "Wait for a process and set it as the default thread.", WaitHandler },
    { "thread", 0, ThreadDoc, "Set the default thread.", ThreadHandler },
    { "sleep", 1, SleepDoc, "Sleep for specified milliseconds.", SleepHandler },
    { "forget", 0, ForgetDoc, "Forget all known stubs.", ForgetHandler },
    { "stack", 0, StackDoc, "Print the last leaked stack ptr.", StackHandler },
    { "marshal", 2, MarshalDoc, "Send command with marshalled parameters.", MarshalHandler },
    { "proxy", 3, CallStubDoc, "Send command with proxy parameters.", CallStubHandler },
    { "call", 2, CallDoc, "Send command without appended data.", CallHandler },
    { "window", 0, WindowDoc, "Create and register a message window.", WindowHandler },
    { "patch", 4, PatchDoc, "Patch a marshalled parameter.", PatchHandler },
    { "module", 1, ModuleDoc, "Print the base address of a module.", ModuleHandler },
    { "module64", 1, ModuleDoc, "Print the base address of a 64bit module.", ModuleHandler64 },
    { "editarg", 1, EditArgDoc, "Change the type of a marshalled parameter.", EditArgHandler },
    { "symbol", 1, SymbolDoc, "Lookup a symbol offset from ImageBase.", SymbolHandler },
    { "set", 0, SetDoc, "Change or dump various ctftool parameters.", SetHandler },
    { "add", 2, NULL, NULL, SetHandler },
    { "sub", 2, NULL, NULL, SetHandler },
    { "neg", 2, NULL, NULL, SetHandler },
    { "shl", 2, NULL, NULL, SetHandler },
    { "shr", 2, NULL, NULL, SetHandler },
    { "and", 2, NULL, NULL, SetHandler },
    { "or", 2, NULL, NULL, SetHandler },
    { "xor", 2, NULL, NULL, SetHandler },
    { "not", 2, NULL, NULL, SetHandler },
    { "eq", 2, NULL, NULL, SetHandler },
    { "show", 0, ShowDoc, "Show the value of special variables you can use.", ShowHandler },
    { "lock", 0, LockDoc, "Lock the workstation, switch to Winlogon desktop.", LockHandler },
    { "repeat", 2, RepeatDoc, "Repeat a command multiple times.", RepeatHandler },
    { "run", 1, RunDoc, "Run a command.", RunHandler },
    { "script", 1, ScriptDoc, "Source a script file.", ScriptHandler },
    { "print", 0, NULL, "Print a string.", PrintHandler },
    { "echo", 1, NULL, NULL, PrintHandler },
    { "consent", 0, ConsentDoc, "Invoke the UAC consent dialog.", ConsentHandler },
    { "reg", 3, RegDoc, "Lookup a DWORD in the registry.", RegHandler },
    { "gadget", 2, GadgetDoc, "Find the offset of a pattern in a file.", GadgetHandler },
    { "section", 3, SectionDoc, "Lookup property of PE section.", SectionHandler },
};

int CompareFirst(PCHAR a, PCHAR *b)
{
    return strcmpi(a, *b);
}

ULONGLONG DecodeIntegerParameter(PCHAR Value) {
    ULONGLONG Result;
    PCHAR ParseEnd;
    BOOL PrintHelp;
    SPECIAL_VARIABLE Variables[] = {
        { "thread", "The current default thread.", DefaultThread },
        { "stubid", "The last created stubid.", DefaultStub },
        { "tid", "The ctftool main thread id.", GetCurrentThreadId() },
        { "pid", "The ctftool process id.", GetCurrentProcessId() },
        { "sid", "The ctftool session id.", NtCurrentTeb()->ProcessEnvironmentBlock->SessionId },
        { "symbol", "The result of the last symbol lookup.", LastSymbolOffset },
        { "module", "The result of the last module lookup.", LastModuleBase },
        { "focusthread", "Owner of foreground window.", GetFocusThread() },
        { "hkl", "The current keyboard layout", (DWORD)(GetKeyboardLayout(GetCurrentThreadId())) & 0xffff },
        { "r0", "User defined register.", UserRegisters[0] },
        { "r1", "User defined register.", UserRegisters[1] },
        { "r2", "User defined register.", UserRegisters[2] },
        { "r3", "User defined register.", UserRegisters[3] },
        { "r4", "User defined register.", UserRegisters[4] },
        { "r5", "User defined register.", UserRegisters[5] },
        { "rc", "Return code of last run command.", LastCommandResult },
        { "regval", "The last value queried from the registry.", LastRegistryValue },
        { "gadget", "Result of the last gadget found.", LastGadget },
        { "secval", "Result of the last section property query.", LastSectionResult }
    };

    // Check if the caller is requesting help.
    PrintHelp = strcmp(Value, "help") == 0;

    // Check if this is a "special" value
    for (ULONG i = 0; i < _countof(Variables); i++) {
        if (strcmp(Value, "help") == 0) {
            LogMessage(stdout, "%-20s: %s", Variables[i].Name, Variables[i].Description);
        }
        if (strcmp(Value, Variables[i].Name) == 0) {
            return Variables[i].Value;
        }
    }

    // Not a special value, try to use strtoull().
    Result = strtoull(Value, &ParseEnd, 0);

    // If that worked, return result.
    if (*ParseEnd == '\0' || PrintHelp)
        return Result;

    // Failed, just use zero and print a warning.
    LogMessage(stderr, "Did not recognize %s as variable or integer, assuming zero.", Value);

    return Result;
};

ULONG ScriptHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    FILE *ScriptFile;
    PCHAR OriginalCommand;
    HIST_ENTRY *Hist;
    CHAR LineBuf[8192];

    ScriptFile = fopen(*Parameters, "r");
    Hist = history_get(history_length() - 1);
    OriginalCommand = strdup(Hist->line);

    if (ScriptFile) {
        NonInteractive++;
        while (fgets(LineBuf, sizeof LineBuf, ScriptFile)) {
            // Save this to the history so commands can access it.
            Hist = replace_history_entry(history_length() - 1, LineBuf, 0);

            // Exit command in a script just exits the script.
            if (DispatchCommand(LineBuf) == 0)
                break;
        }
    } else {
        LogMessage(stderr, "failed to open file %s", *Parameters);
    }

    NonInteractive--;

    // Restore real history entry.
    replace_history_entry(history_length() - 1, OriginalCommand, 0);
    free(OriginalCommand);

    return 1;
}

PCHAR GetOrigCommandLine(BOOL SkipCommand, ULONG SkipParameters)
{
    HIST_ENTRY *Hist = history_get(history_length() - 1);
    PCHAR CommandLine;

    // This is a hack, I just pull the command out of history.
    assert(Hist != NULL);
    assert(Hist->line);

    CommandLine = Hist->line;

    // Skip past any leading whitespace.
    CommandLine += strspn(CommandLine, " \t\n");

    if (SkipCommand) {
        CommandLine += strcspn(CommandLine, " \t\n");
        CommandLine += strspn(CommandLine, " \t\n");
    }

    for (ULONG i = 0; i < SkipParameters; i++) {
        CommandLine += strcspn(CommandLine, " \t\n");
        CommandLine += strspn(CommandLine, " \t\n");
    }

    return CommandLine;
}

ULONG RunHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    STARTUPINFO StartupInfo = { sizeof StartupInfo };
    PROCESS_INFORMATION ProcessInfo;
    PCHAR CommandLine = GetOrigCommandLine(TRUE, 0);
    PVOID OldValue;
    DWORD ReturnCode;

    // Disable Redirection so we get the real files.
    if (Wow64DisableWow64FsRedirection(&OldValue) == false) {
        LogMessage(stderr, "Could not disable redirection.");
    }

    if (CreateProcess(NULL, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo)) {
        WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
        GetExitCodeProcess(ProcessInfo.hProcess, &ReturnCode);
        CloseHandle(ProcessInfo.hProcess);
        CloseHandle(ProcessInfo.hThread);

        // Make result available as a variable.
        LastCommandResult = ReturnCode;
    } else {
        LogMessage(stderr, "Failed to create process %s.", CommandLine);
    }

    // Restore Redirection.
    Wow64RevertWow64FsRedirection(OldValue);

    return 1;
}

ULONG RepeatHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    HIST_ENTRY *Hist = history_get(history_length() - 1);
    ULONG Count = DecodeIntegerParameter(*Parameters);
    PCHAR CommandLine = GetOrigCommandLine(TRUE, 1);

    for (ULONG i = 0; i < Count; i++) {
        ULONG Result = DispatchCommand(CommandLine);

        if (Result == 0) {
            return Result;
        }

        // Customizable delay with the set command for debugging.
        Sleep(RepeatDelay);
    }
    return 1;
}

ULONG LockHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    INPUT kHotKeyInput[] = {
        { INPUT_KEYBOARD, .ki = { VK_ESCAPE, .dwFlags = 0 }},
        { INPUT_KEYBOARD, .ki = { VK_ESCAPE, .dwFlags = KEYEVENTF_KEYUP }},
    };

    LockWorkStation();

    // Wait a second for the UI to draw.
    Sleep(2000);

    // Hit `Esc` so that the login screen gets drawn.
    SendInput(_countof(kHotKeyInput), kHotKeyInput, sizeof(INPUT));
    return 1;
}

ULONG PrintHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    if (ParamCount && NonInteractive) {
        fprintf(stdout, "%s", GetOrigCommandLine(TRUE, 0));
    } else if (NonInteractive) {
        fprintf(stdout, "\n");
    } else {
        LogMessage(stdout, "%s", GetOrigCommandLine(TRUE, 0));
    }
    return 1;
}

ULONG ShowHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    if (ParamCount) {
        LogMessage(stdout, "%#llx", DecodeIntegerParameter(*Parameters));
    } else {
        DecodeIntegerParameter("help");
    }
    return 1;
}

ULONG SetHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    static const struct {
        PUINT64 Value;
        PCHAR   Name;
        PCHAR   Description;
    } TunableSettings[] = {
        { &DefaultThread, "default-dst-thread", "Destination threadid for commands." },
        { &ClientThreadId, "default-src-thread", "Source threadid for commands." },
        { &DefaultStub, "default-stub", "Default stubid for stub calls." },
        { &ClientFlags, "client-flags", "The client flags passed on connect." },
        { &ProxyExtra1, "proxy-extra-1", "Padding for proxy structure." },
        { &ProxyExtra2, "proxy-extra-2", "Padding for proxy structure." },
        { &ProxyExtra3, "proxy-extra-3", "Padding for proxy structure." },
        { &UserRegisters[0], "r0", "User register." },
        { &UserRegisters[1], "r1", "User register." },
        { &UserRegisters[2], "r2", "User register." },
        { &UserRegisters[3], "r3", "User register." },
        { &UserRegisters[4], "r4", "User register." },
        { &UserRegisters[5], "r5", "User register." },
        #pragma warning(suppress: 4047)
        { &MessageWindow, "connect-hwnd", "The HWND we pass in the connect message." },
        { &RepeatDelay, "repeat-delay", "Milliseconds to pause between repeat ops." },
    };

    for (ULONG Var = 0; Var < _countof(TunableSettings); Var++) {
        // If ParamCount is 2, then a value was specified.
        if (ParamCount == 2 && strcmp(TunableSettings[Var].Name, *Parameters) == 0) {
            if (strcmp(Command, "set") == 0) {
                *(TunableSettings[Var].Value) = DecodeIntegerParameter(Parameters[1]);
            } else if (strcmp(Command, "add") == 0) {
                *(TunableSettings[Var].Value) += DecodeIntegerParameter(Parameters[1]);
            } else if (strcmp(Command, "sub") == 0) {
                *(TunableSettings[Var].Value) -= DecodeIntegerParameter(Parameters[1]);
            } else if (strcmp(Command, "neg") == 0) {
                *(TunableSettings[Var].Value) = -DecodeIntegerParameter(Parameters[1]);
            } else if (strcmp(Command, "and") == 0) {
                *(TunableSettings[Var].Value) &= DecodeIntegerParameter(Parameters[1]);
            } else if (strcmp(Command, "shr") == 0) {
                *(TunableSettings[Var].Value) >>= DecodeIntegerParameter(Parameters[1]);
            } else if (strcmp(Command, "shl") == 0) {
                *(TunableSettings[Var].Value) <<= DecodeIntegerParameter(Parameters[1]);
            } else if (strcmp(Command, "or") == 0) {
                *(TunableSettings[Var].Value) |= DecodeIntegerParameter(Parameters[1]);
            } else if (strcmp(Command, "xor") == 0) {
                *(TunableSettings[Var].Value) ^= DecodeIntegerParameter(Parameters[1]);
            } else if (strcmp(Command, "not") == 0) {
                *(TunableSettings[Var].Value) = ~DecodeIntegerParameter(Parameters[1]);
            } else if (strcmp(Command, "eq") == 0) {
                *(TunableSettings[Var].Value) =
                    *(TunableSettings[Var].Value) == DecodeIntegerParameter(Parameters[1]);
            }
        }
        // No value, just print.
        if (ParamCount == 1 && strcmp(TunableSettings[Var].Name, *Parameters) == 0) {
            LogMessage(stdout, "%s", TunableSettings[Var].Description);
        }
        // No name, print everything.
        if (ParamCount == 0 || (strcmp(TunableSettings[Var].Name, *Parameters) == 0 && !NonInteractive)) {
            LogMessage(stdout, "%-20s = %#llx", TunableSettings[Var].Name, *(TunableSettings[Var].Value));
        }
    }
    return 1;
}

ULONG StackHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    if (LeakedStackPointer == 0) {
        LogMessage(stderr, "No stack pointer leaked yet, marshal some parameters.");
        return 1;
    }

    LogMessage(stdout, "%#llx", LeakedStackPointer);
    return 1;
}

ULONG ExitHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    return 0;
}

ULONG SleepHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    Sleep(DecodeIntegerParameter(*Parameters));
    return 1;
}

ULONG HelpHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    if (ParamCount == 0) {
        LogMessage(stdout, "Type `help <command>` for help with a specific command.");
        LogMessage(stdout, "Any line beginning with # is considered a comment.\n");
    }

    for (int i = 0; i < _countof(CommandHandlers); i++) {
        // List all commands.
        if (ParamCount == 0 && CommandHandlers[i].Description)
            LogMessage(stdout, "%-16s- %s", CommandHandlers[i].Command, CommandHandlers[i].Description);

        // Query specific command.
        if (ParamCount == 1 && stricmp(CommandHandlers[i].Command, *Parameters) == 0) {
            if (CommandHandlers[i].Description) {
                LogMessage(stdout, "%s\n", CommandHandlers[i].Description);
            } else {
                LogMessage(stdout, "%s is an alias", *Parameters);
            }

            // Show detailed help.
            if (CommandHandlers[i].LongDescription)
                LogMessage(stdout, "%s", CommandHandlers[i].LongDescription);

            // No need to keep searching.
            break;
        }
    }

    if (PortHandle == NULL)
        LogMessage(stdout, "Most commands require a connection, see \"help connect\".");

    return 1;
}

ULONG InfoHandler(PCHAR Commad, ULONG ParamCount, PCHAR *Parameters)
{
    CTF_MSGBASE Message;
    HRESULT Result;

    ZeroMemory(&Message, sizeof Message);

    Message.Message = MSG_GETMONITORPID;
    Message.SrcThreadId = ClientThreadId;

    Result = SendReceivePortMessage(PortHandle,
                                    &Message.Header,
                                    sizeof Message,
                                    NULL);
    if (Result != 0) {
        LogMessage(stdout, "The command failed with error %#x", Result);
        return 1;
    }

    LogMessage(stdout, "The server responded.");
    LogMessage(stdout, "\tMonitor PID: %u", Message.Params[0]);
    return 1;
}

ULONG ScanHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    UINT Count = 0;
    CTF_MSGBASE Message;
    HRESULT Result;
    HANDLE SnapshotHandle;
    HWND ClientWindow;
    LARGE_INTEGER Timeout = {
        .QuadPart = -100000LL,
    };
    THREADENTRY32 ThreadData = {
        .dwSize = sizeof(ThreadData),
    };

    SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (SnapshotHandle == INVALID_HANDLE_VALUE) {
        LogMessage(stderr, "failed to create tool snapshot");
        goto cleanup;
    }

    if (Thread32First(SnapshotHandle, &ThreadData) == false) {
        LogMessage(stderr, "failed to query system threads");
        goto cleanup;
    }

    do {
        ZeroMemory(&Message, sizeof Message);

        // Note that nothing is stopping clients lying.
        // MSG_GETCLIENTINFOEX accepts
        //  [0] ThreadId
        // MSG_GETCLIENTINFOEX returns
        //  [0] Client Flags
        //  [1] ProcessId
        //  [2] GetTickCount() generated by client when registering.

        Message.Message = MSG_GETCLIENTINFOEX;
        Message.SrcThreadId = ClientThreadId;
        Message.Params[0] = ThreadData.th32ThreadID;

        Result = SendReceivePortMessage(PortHandle,
                                        &Message.Header,
                                        sizeof Message,
                                        &Timeout);

        if (Result != 0) {
            LogMessage(stderr, "failed to send message to server, giving up, %#x", Result);
            goto cleanup;
        }

        if (Message.Result == 0) {
            PCHAR ImageName;
            ULONG Flags;
            HANDLE Process;

            Flags = Message.Params[0];

            // Ask what their HWND is.
            Message.Message = MSG_GETTHREADHWND;
            Message.SrcThreadId = ClientThreadId;
            Message.Params[0] = ThreadData.th32ThreadID;

            Result = SendReceivePortMessage(PortHandle,
                                            &Message.Header,
                                            sizeof Message,
                                            &Timeout);

            if (Result == 0 && Message.Result == 0) {
                #pragma warning(suppress: 4312)
                ClientWindow = (HWND) Message.Params[0];
            }

            // Figure out who owns this thread.
            ImageName = QueryImageName(ThreadData.th32OwnerProcessID);

            LogMessage(stdout, "Client %u, Tid %4u (Flags %#04x, Hwnd %p, Pid %u, %s)",
                               Count++,
                               ThreadData.th32ThreadID,
                               Flags,
                               ClientWindow,
                               ThreadData.th32OwnerProcessID,
                               ImageName);
        }
    } while(Thread32Next(SnapshotHandle, &ThreadData));

cleanup:
    if (SnapshotHandle != INVALID_HANDLE_VALUE) {
        #pragma warning(suppress: 6387)
        CloseHandle(SnapshotHandle);
    }
    return 1;
}

ULONG ForgetHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    NumStubs = 0;
    LogMessage(stdout, "All Stubs Forgotten.");
    return 1;
}

ULONG CreateStubHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    PCTF_MARSHAL_PARAM CreateParams;
    WCHAR WideParameter[128] = {0};
    PKNOWN_INTERFACE ClassName;
    ULONG CreateParamCount = 4;
    HRESULT Result;
    UINT64 InterfaceType;
    DWORD ThreadId;
    GUID *Interface;
    GUID ParsedClass = {0};

    // createstub thread type interface
    ThreadId        = DecodeIntegerParameter(Parameters[0]);
    InterfaceType   = DecodeIntegerParameter(Parameters[1]);

    ThreadId        = ThreadId ? ThreadId : DefaultThread;

    // First see if user specified a GUID.
    _snwprintf(WideParameter, _countof(WideParameter) - 1, L"{%hs}", Parameters[2]);

    #pragma warning(suppress: 6053)
    if (CLSIDFromString(WideParameter, &ParsedClass) == 0) {
        LogMessage(stdout, "parsed '%s' as a GUID", Parameters[2]);
        Interface = &ParsedClass;
    } else {
        ULONG NumInterfaces = _countof(KnownInterfaces);

        #pragma warning(push)
        #pragma warning(disable : 4090 4028)
        ClassName = lfind(Parameters[2],
                          KnownInterfaces,
                          &NumInterfaces,
                          sizeof(*KnownInterfaces),
                          CompareFirst);
        #pragma warning(pop)
        if (ClassName) {
            #pragma warning(suppress : 4090)
            Interface = ClassName->Interface;
        } else {
            LogMessage(stderr, "Cannot parse '%s' as a GUID or recognised interface.", Parameters[2]);
            LogMessage(stderr, "These are the interface names I know:");
            for (int i = 0; i < NumInterfaces; i++) {
                LogMessage(stderr, "\t%s", KnownInterfaces[i].Name);
            }
            return 1;
        }
    }

    CreateParams = MarshalParamsInsertData(NULL, CreateParamCount, 0, MARSHAL_FLAG_INPUT | MARSHAL_TYPE_INT, NULL, sizeof(UINT64), FALSE);
    CreateParams = MarshalParamsInsertData(CreateParams, CreateParamCount, 1, MARSHAL_FLAG_INPUT | MARSHAL_TYPE_INT, &InterfaceType, sizeof(UINT64), FALSE);
    CreateParams = MarshalParamsInsertData(CreateParams, CreateParamCount, 2, MARSHAL_FLAG_INPUT | MARSHAL_TYPE_DATA, Interface, sizeof(GUID), FALSE);
    CreateParams = MarshalParamsInsertData(CreateParams, CreateParamCount, 3, MARSHAL_FLAG_OUTPUT | MARSHAL_FLAG_ARRAY | MARSHAL_TYPE_COM, NULL, sizeof(UINT64), FALSE);

    Result = SendReceiveMarshalData(PortHandle,
                                    MSG_CREATESTUB | MSGFLAG_DATA_APPENDED,
                                    CreateParams,
                                    CreateParamCount,
                                    ThreadId);

    if (Result != 0) {
        LogMessage(stderr, "Command failed, returned %#x", Result);
        goto cleanup;
    }

    LogMessage(stderr, "Command succeeded, stub created");

    MarshalParamsDumpData(CreateParams, 3);

    if (NumStubs >= MAX_STUBS) {
        LogMessage(stderr, "Sorry, ran out of stub storage space, see `help forget`.");
        goto cleanup;
    }

    // Remember this stub so used doesnt have to type it all in.
    StubRecords[NumStubs].ThreadId = ThreadId;

    // Copy over the details.
    memcpy(&StubRecords[NumStubs].Stub,
           MarshalDataPtr(PVOID, CreateParams, 3),
           sizeof(CTF_MARSHAL_COMSTUB));

    // Record the last stubid seen.
    DefaultStub = StubRecords[NumStubs].Stub.StubId;

    // Done saving stubs.
    NumStubs++;

cleanup:
    MarshalParamsFree(CreateParams);
    return 1;
}

ULONG CallStubHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    DWORD ThreadId;
    DWORD StubId;
    DWORD FunctionNum;
    HRESULT Result;
    PCTF_MARSHAL_COMSTUB StubRecord;

    // callstub thread id functionnum
    ThreadId    = DecodeIntegerParameter(Parameters[0]);
    StubId      = DecodeIntegerParameter(Parameters[1]);
    FunctionNum = DecodeIntegerParameter(Parameters[2]);
    StubRecord  = NULL;
    ThreadId    = ThreadId ? ThreadId : DefaultThread;
    StubId      = StubId ? StubId : DefaultStub;

    // First search for this stub
    for (int i = 0; i < NumStubs; i++) {
        if (StubRecords[i].ThreadId == ThreadId
         && StubRecords[i].Stub.StubId == StubId) {
            StubRecord = &StubRecords[i].Stub;
            break;
         }
    }

    if (StubRecord == NULL) {
        LogMessage(stderr, "Sorry, I don't recognise stub %u for thread %u", StubId, ThreadId);
        return 1;
    }

    if (CurrentMarshalParam != CountMarshalParams) {
        LogMessage(stderr, "You haven't specified all %u parameters.", CountMarshalParams);
        return 1;
    }

    // Now we need to create the proxy data.
    Result = SendReceiveProxyData(PortHandle,
                                  MSG_CALLSTUB | MSGFLAG_DATA_APPENDED,
                                  MarshalParams,
                                  CountMarshalParams,
                                  StubRecord,
                                  FunctionNum,
                                  ThreadId);

    if (Result != 0) {
        if (NonInteractive == FALSE) {
            LogMessage(stderr,  "Sending the Proxy data failed, %#x", Result);
        }
        return 1;
    }

    LogMessage(stderr, "Command succeeded.");

    // Search through the parameters for any stubs we need to know about.
    for (ULONG Index = 0; Index < CountMarshalParams; Index++) {
        if (MarshalParams[Index].TypeFlags & MARSHAL_FLAG_OUTPUT) {
            LogMessage(stdout, "Parameter %u has the output flag set.", Index);

            MarshalParamsDumpData(MarshalParams, Index);

            // Remember this stub so user doesnt have to type it all in.
            if ((MarshalParams[Index].TypeFlags & MARSHAL_TYPE_MASK) == MARSHAL_TYPE_COM) {
                if (NumStubs >= MAX_STUBS) {
                    LogMessage(stderr, "Sorry, ran out of stub storage space, see `help forget`.");
                    continue;
                }

                StubRecords[NumStubs].ThreadId = ThreadId;

                // Copy over the details.
                memcpy(&StubRecords[NumStubs].Stub,
                       MarshalDataPtr(PVOID, MarshalParams, Index),
                       sizeof(CTF_MARSHAL_COMSTUB));

                // Record the last stubid seen.
                DefaultStub = StubRecords[NumStubs].Stub.StubId;

                // Done saving stubs.
                NumStubs++;

                LogMessage(stdout, "StubID %llu recorded.", DefaultStub);
            }
        }
    }

    return 1;
}

ULONG MarshalHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    DWORD ThreadId;
    DWORD MessageNum;
    HRESULT Result;

    // marshal thread message
    ThreadId    = DecodeIntegerParameter(*Parameters);
    ThreadId    = ThreadId ? ThreadId : DefaultThread;

    if (GetCommandNum(Parameters[1]) >= 0) {
        MessageNum = GetCommandNum(Parameters[1]);
    } else {
        MessageNum  = DecodeIntegerParameter(Parameters[1]);
    }

    if (CurrentMarshalParam != CountMarshalParams) {
        LogMessage(stderr, "You haven't specified all %u parameters, is that intentional?", CountMarshalParams);
    }

    // Send data to the server.
    Result = SendReceiveMarshalData(PortHandle,
                                    MessageNum | MSGFLAG_DATA_APPENDED,
                                    MarshalParams,
                                    CountMarshalParams,
                                    ThreadId);

    LogMessage(stderr, "Result: %#x, use `getarg` if you want to examine data",
                        Result);

    return 1;
}

ULONG SetArgHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    DWORD TypeFlags = 0;
    DWORD Size = 0;
    PVOID Value = NULL;

    // setarg count
    if (ParamCount == 1) {
        MarshalParamsFree(MarshalParams);

        CurrentMarshalParam = 0;
        CountMarshalParams  = DecodeIntegerParameter(*Parameters);
        MarshalParams       = NULL;

        if (NonInteractive == FALSE) {
            LogMessage(stderr, "New Parameter Chain, Length %u", CountMarshalParams);
        }
        return 1;
    }

    if (ParamCount < 2) {
        LogMessage(stderr, "Not enough parameters!");
        return 1;
    }

    if (CurrentMarshalParam >= CountMarshalParams) {
        LogMessage(stderr, "Sorry, you must declare how many params you need using setarg.");
        LogMessage(stderr, "This param would take you over the limit of %u you specified.", CountMarshalParams);
        return 1;
    }

    // Consume everything until the last parameter (the value)
    for (ULONG Position = 0; Position < ParamCount - 1; Position++) {
        DWORD DecodedFlag = GetMarshalFlagNum(Parameters[Position]);

        // Zero is a valid type, so check this round trips to validate.
        if (strcmp(GetMarshalFlagName(DecodedFlag), Parameters[Position]) == 0) {
            TypeFlags |= DecodedFlag;
        } else {
            TypeFlags |= DecodeIntegerParameter(Parameters[Position]);
        }
    }

    switch (TypeFlags & MARSHAL_TYPE_MASK) {
        default:
            LogMessage(stderr, "Type not supported yet, treating as data.");
            // fallthrough, maybe just treating it like data will work.
        case MARSHAL_TYPE_STRUCT:
        case MARSHAL_TYPE_DATA: {
            static GUID ParsedGuid;
            static BYTE HexBuf[MAX_BUF];
            WCHAR WideParameter[512] = {0};
            CHAR CurrentChar[3] = {0};
            PCHAR ByteString = Parameters[ParamCount - 1];
            ULONG ParamLength = strlen(ByteString);

            // First we try to parse it as a GUID, a very common case in CTF.
            // The format is 00000000-0000-0000-0000-000000000000
            _snwprintf(WideParameter, _countof(WideParameter) - 1, L"{%hs}", ByteString);

            #pragma warning(suppress: 6053)
            if (CLSIDFromString(WideParameter, &ParsedGuid) == 0) {
                Value = &ParsedGuid;
                Size = sizeof ParsedGuid;
                break;
            }

            // FIXME: dont handle spaces
            // Maybe it's a string, the format is "arbitrary data"
            if (ParamLength >= 2 && ByteString[0] == '"' && ByteString[ParamLength-1] == '"') {
                // It is a string, just strcpy the data. If you want special characters, use hex mode.
                Value = &ByteString[1];
                Size  = ParamLength - 2; // for the quotes.
                break;
            }

            // Maybe it's a string, but the user wants us to convert it to UTF-16
            if (ParamLength >= 3 && ByteString[0] == 'L' && ByteString[1] == '"' && ByteString[ParamLength-1] == '"') {
                _snwprintf(WideParameter, _countof(WideParameter), L"%hs", ByteString + 2);
                Value = WideParameter;
                Size  = (ParamLength - 3) * sizeof(WCHAR); // -3 for the quotes and 'L'
                break;
            }

            // The only other option is a hex buffer.
            if (strlen(ByteString) & 1) {
                LogMessage(stderr, "Parsing as a hex string, but you didn't specify enough characters!");
                return 1;
            }

            if (strlen(ByteString) > MAX_BUF * 2) {
                LogMessage(stderr, "Parsing as a hex string, but you specified too many characters!");
                return 1;
            }

            // Parse as a hex string, e.g. 41414141412eff00
            for (Size = 0; *ByteString;) {
                CurrentChar[0] = *ByteString++;
                CurrentChar[1] = *ByteString++;
                #pragma warning(suppress: 6328)
                if (sscanf(CurrentChar, "%hhx", &HexBuf[Size++]) != 1) {
                    LogMessage(stderr, "Parsing hex string but failed, I stopped at %s", CurrentChar);
                    return 1;
                }
            }

            Value = HexBuf;
            break;
        }
        case MARSHAL_TYPE_COM: {
            static CTF_MARSHAL_COMSTUB ComStub;
            DWORD StubId;

            StubId  = DecodeIntegerParameter(Parameters[ParamCount - 1]);
            Value   = &ComStub;
            Size    = sizeof(ComStub);

            // First search for this stub
            for (int i = 0; i < NumStubs; i++) {
                if (StubRecords[i].Stub.StubId == StubId) {
                    memcpy(&ComStub, &StubRecords[i].Stub, sizeof ComStub);
                    break;
                }
            }
            break;
        }
        case MARSHAL_TYPE_LONG:
        case MARSHAL_TYPE_WORD:
        case MARSHAL_TYPE_INT: {
            static UINT64 Number;
            Number  = DecodeIntegerParameter(Parameters[ParamCount - 1]);
            Value   = &Number;
            Size    = sizeof(UINT64);
            break;
        }
    }

    MarshalParams = MarshalParamsInsertData(MarshalParams,
                                            CountMarshalParams,
                                            CurrentMarshalParam,
                                            TypeFlags,
                                            Value,
                                            Size,
                                            FALSE);

    if (NonInteractive == FALSE) {
        MarshalParamsDumpData(MarshalParams, CurrentMarshalParam);
    }

    CurrentMarshalParam++;
    return 1;
}

ULONG GetArgHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    DWORD Index = DecodeIntegerParameter(Parameters[0]);
    if (Index >= CurrentMarshalParam) {
        LogMessage(stderr, "Bad index requested!");
        return 1;
    }
    MarshalParamsDumpData(MarshalParams, Index);
    return 1;
}

ULONG ModuleHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    LastModuleBase = QueryModuleHandle32(*Parameters);
    LogMessage(stdout, "%#llx", LastModuleBase);
    return 1;
}

ULONG ModuleHandler64(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    LastModuleBase = QueryModuleHandle64(*Parameters);
    LogMessage(stdout, "%#llx", LastModuleBase);
    return 1;
}

ULONG EditArgHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    DWORD Index = DecodeIntegerParameter(*Parameters);

    if (Index >= CurrentMarshalParam) {
        LogMessage(stderr, "Bad index requested!");
        return 1;
    }

    MarshalParams[Index].TypeFlags = DecodeIntegerParameter(Parameters[1]);
    MarshalParamsDumpData(MarshalParams, Index);
    return 1;
}

ULONG PatchHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    DWORD Index;
    DWORD Offset;
    DWORD Width;
    DWORD Shift;
    UINT64 Adjust;
    UINT64 Value;

    Width = Index = Offset = Value = Shift = Adjust = 0;

    switch (ParamCount) {
        case 6: Shift   = DecodeIntegerParameter(Parameters[5]);
        case 5: Adjust  = DecodeIntegerParameter(Parameters[4]);
        case 4: Index   = DecodeIntegerParameter(Parameters[0]);
                Offset  = DecodeIntegerParameter(Parameters[1]);
                Value   = DecodeIntegerParameter(Parameters[2]);
                Width   = DecodeIntegerParameter(Parameters[3]);
    }

    if (Index >= CurrentMarshalParam) {
        LogMessage(stderr, "Bad index requested!");
        return 1;
    }

    if (Offset + Width > MarshalParams[Index].Size) {
        LogMessage(stderr, "Bad offset or width, the parameter is only %#x bytes",
                           MarshalParams[Index].Size);
        return 1;
    }

    if (Width > 8) {
        LogMessage(stderr, "Sorry, maximum width supported is 8 bytes (QWORD)");
        return 1;
    }

    if (Shift > Width * CHAR_BIT) {
        LogMessage(stderr, "Shift parameter shifts out too many bits");
        return 1;
    }

    if (NonInteractive == FALSE) {
        LogMessage(stdout, "Dumping Original...");
        MarshalParamsDumpData(MarshalParams, Index);
    }

    Value  += Adjust;
    Value >>= Shift;

    memcpy((PBYTE)(MarshalParams) + MarshalParams[Index].Start + Offset, &Value, Width);

    if (NonInteractive == FALSE) {
        LogMessage(stdout, "Dumping New...");
        MarshalParamsDumpData(MarshalParams, Index);
    }

    return 1;
}

ULONG HijackHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    OBJECT_ATTRIBUTES ObjectAttributes;
    WCHAR PathName[MAX_PATH];
    UNICODE_STRING PortName;
    ALPC_PORT_ATTRIBUTES PortAttributes;
    HANDLE ServerHandle = INVALID_HANDLE_VALUE;
    ULONG BufferLength = sizeof(CTF_CONNECT_MSG);
    NTSTATUS Result;
    ULONG MessageAttributeSize;
    CTF_CONNECT_MSG ConnectMessage; 
    PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes = NULL;

    // Generate the requested portname.
     _snwprintf(PathName, _countof(PathName), L"\\BaseNamedObjects\\msctf.server%hs%llu",
                                              Parameters[0],
                                              DecodeIntegerParameter(Parameters[1]));



    // I copied the descriptor from msctf.dll
    ConvertStringSecurityDescriptorToSecurityDescriptor(
        "D:P(A;OICI;0x01;;;AU)(A;OICI;0x01;;;SY)(A;OICI;0x01;;;IU)(A;OICI;0x01;;;AC)(A;OICI;0x01;;;S-1-15-3-1024-1502825166-1963708345-2616377461-2562897074-4192028372-3968301570-1997628692-1435953622)",
        SDDL_REVISION,
        &SecurityDescriptor,
        NULL);

    RtlInitUnicodeString(&PortName, PathName);
    InitializeObjectAttributes(&ObjectAttributes, &PortName, 64, NULL, SecurityDescriptor);
    ZeroMemory(&PortAttributes, sizeof PortAttributes);
    PortAttributes.Flags = 0xA0000;
    PortAttributes.SecurityQos.ImpersonationLevel = 0;
    PortAttributes.MemoryBandwidth = 0;
    PortAttributes.MaxMessageLength = 512;
    PortAttributes.MaxPoolUsage = 0x20000;
    PortAttributes.MaxSectionSize = 0x20000;
    PortAttributes.MaxTotalSectionSize = 0x20000;
    PortAttributes.DupObjectTypes = 0x100000;
    PortAttributes.SecurityQos.Length = sizeof(PortAttributes.SecurityQos);
    PortAttributes.SecurityQos.ContextTrackingMode = TRUE;

    Result = NtAlpcCreatePort(&ServerHandle, &ObjectAttributes, &PortAttributes);

    LogMessage(stdout, "NtAlpcCreatePort(\"%S\") => %#x %p", PathName, Result, ServerHandle);

    if (AlpcInitializeMessageAttribute(0x60000000, NULL, 0, &MessageAttributeSize) != STATUS_BUFFER_TOO_SMALL) {   
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

    InitializeMessageHeader(&ConnectMessage.Header, BufferLength, 0);

    do {
        HANDLE ClientHandle = 0;
        BufferLength = sizeof(CTF_CONNECT_MSG);

        Result = NtAlpcSendWaitReceivePort(ServerHandle,
                                           0,
                                           NULL,
                                           NULL,
                                           &ConnectMessage.Header,
                                           &BufferLength,
                                           ReceiveMessageAttributes,
                                           NULL);
        LogMessage(stdout, "NtAlpcSendWaitReceivePort(\"%S\") => %#x %p", PathName, Result, ServerHandle);

        hexdump(&ConnectMessage, BufferLength);

        LogMessage(stdout, "A %#hhx message received", ConnectMessage.Header.u2.s2.Type);

        if ((ConnectMessage.Header.u2.s2.Type & 0xFF) == LPC_CONNECTION_REQUEST) {
            PCHAR ImageName = QueryImageName(ConnectMessage.ProcessId);
            LogMessage(stderr, "\tProcessID: %u, %s", ConnectMessage.ProcessId, ImageName);
            LogMessage(stderr, "\tThreadId: %u", ConnectMessage.ThreadId);
            LogMessage(stderr, "\tWindowID: %p", ConnectMessage.WindowId);
            free(ImageName);
        }

        // Reject the connection so things dont time out.
        NtAlpcAcceptConnectPort(&ClientHandle, ServerHandle, 0, 0, 0, 0, &ConnectMessage.Header, 0, 0);

        if (ClientHandle) {
            CloseHandle(ClientHandle);
        }
    } while (Result == 0);

cleanup:
    free(ReceiveMessageAttributes);

    return 1;
}

ULONG ConnectHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    DWORD SessionId;
    WCHAR PortName[MAX_PATH];
    CTF_CONNECT_MSG ConnectMessage;

    if (PortHandle) {
        LogMessage(stderr, "Closing existing ALPC Port Handle %p...", PortHandle);
        CloseHandle(PortHandle);
    }
 
    if (ParamCount == 2) {
        // The desktopname is usually "Default"
        SessionId = DecodeIntegerParameter(Parameters[1]);
        _snwprintf(PortName, _countof(PortName), L"\\BaseNamedObjects\\msctf.server%hs%u",
                                                *Parameters,
                                                SessionId);
    } else {
        // No parameters, connect to current desktop and session.
        if (GetServerPortName(PortName, sizeof PortName) == FALSE) {
            LogMessage(stderr, "Failed to lookup ctf server port.");
            return 1;
        }
    }

    LogMessage(stdout, "The ctf server port is located at %S", PortName);

    ZeroMemory(&ConnectMessage, sizeof ConnectMessage);
    ConnectMessage.ProcessId    = GetCurrentProcessId();
    ConnectMessage.ThreadId     = ClientThreadId;
    ConnectMessage.WindowId     = MessageWindow;
    ConnectMessage.TickCount    = GetTickCount();
    ConnectMessage.ClientFlags  = ClientFlags;

    do {
        PortHandle = OpenAlpcPort(PortName, &ConnectMessage.Header, sizeof ConnectMessage);

        // If the user specified a port, keep trying.
        if (PortHandle == INVALID_HANDLE_VALUE && ParamCount == 2) {
            LogMessage(stderr, "Waiting for the specified port to appear...");
            Sleep(5000);
        } else {
            break;
        }
    } while (true);

    LogMessage(stdout, "Connected to CTF server@%S, Handle %p", PortName, PortHandle);

    return 1;
}

ULONG WaitHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    UINT Count = 0;
    CTF_MSGBASE Message;
    HRESULT Result;
    HANDLE SnapshotHandle;
    HWND ClientWindow;
    DWORD Delay = 5000;
    LARGE_INTEGER Timeout = {
        .QuadPart = -100000LL,
    };
    THREADENTRY32 ThreadData = {
        .dwSize = sizeof(ThreadData),
    };

    // Optional Poll Delay
    if (ParamCount > 1) {
        Delay = DecodeIntegerParameter(Parameters[1]);
        LogMessage(stdout, "Poll delay set to %u milliseconds", Delay);
    }

    // wait notepad.exe
    do {
        SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

        if (SnapshotHandle == INVALID_HANDLE_VALUE) {
            LogMessage(stderr, "failed to create tool snapshot");
            goto cleanup;
        }
 
        if (Thread32First(SnapshotHandle, &ThreadData) == false) {
            LogMessage(stderr, "failed to query system threads");
            goto cleanup;
        }

        do {
            ZeroMemory(&Message, sizeof Message);

            // Note that nothing is stopping clients lying.
            // MSG_GETCLIENTINFOEX accepts
            //  [0] ThreadId
            // MSG_GETCLIENTINFOEX returns
            //  [0] Client Flags
            //  [1] ProcessId
            //  [2] GetTickCount() generated by client when registering.

            Message.Message = MSG_GETCLIENTINFOEX;
            Message.SrcThreadId = ClientThreadId;
            Message.Params[0] = ThreadData.th32ThreadID;

            Result = SendReceivePortMessage(PortHandle,
                                            &Message.Header,
                                            sizeof Message,
                                            &Timeout);

            if (Result != 0) {
                LogMessage(stderr, "failed to send message to server, %#x", Result);

                // No point continuing if the port is dead.
                switch (Result) {
                    case WAIT_TIMEOUT:
                        LogMessage(stderr, "timeout waiting for response from server.");
                        LogMessage(stderr, "recommend reconnecting with `connect`");
                        // fallthrough
                    case STATUS_PORT_DISCONNECTED:
                    case STATUS_INVALID_HANDLE:
                        goto cleanup;
                }
            }

            if (Message.Result == 0) {
                PCHAR ImageName = QueryImageName(ThreadData.th32OwnerProcessID);

                // Make sure this makes sense.
                if (Message.Params[1]) {
                    if (ThreadData.th32OwnerProcessID != Message.Params[1]) {
                        LogMessage(stderr, "Unexpected ProcessId %#x vs %#x (%s)",
                                            ThreadData.th32OwnerProcessID,
                                            Message.Params[1],
                                            ImageName);
                        free(ImageName);
                        continue;
                    }
                }

                if (ImageName && strcmp(ImageName, Parameters[0]) == 0) {
                    DefaultThread = ThreadData.th32ThreadID;
                    LogMessage(stdout, "Found new client %s, DefaultThread now %llu", ImageName, DefaultThread);
                    free(ImageName);
                    goto cleanup;
                }
                free(ImageName);
            }
        } while(Thread32Next(SnapshotHandle, &ThreadData));
        Sleep(Delay);
    } while (true);

cleanup:
    CloseHandle(SnapshotHandle);
    return 1;
}

ULONG SymbolHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    CHAR ModulePath[MAX_PATH] = {0};
    PCHAR Module = *Parameters;
    PCHAR Symbol = strchr(Module, '!');
    BOOL Is64;
    UINT64 ImageBase;
    UINT64 Address;
    PVOID OldValue;

    if (Symbol == NULL) {
        LogMessage(stderr, "Could not parse %s, use the format module!symbol.", Module);
        return 1;
    }

    // Split into tokens.
    *Symbol++ = '\0';

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
    if (Wow64DisableWow64FsRedirection(&OldValue) == false) {
        LogMessage(stderr, "Could not disable redirection.");
    }

    if (GetSymbolInfo64(ModulePath, Symbol, &Is64, &ImageBase, &Address)) {
        LogMessage(stdout, "%s is a %dbit module.", ModulePath, Is64 ? 64 : 32);
        LogMessage(stdout, "%s!%s@%#llx+%#llx", Module, Symbol, ImageBase, Address - ImageBase);

        LastSymbolOffset = Address - ImageBase;
    } else {
        LogMessage(stderr, "%s!%s Not found.", Module, Symbol);
    }

    // Restore Redirection.
    Wow64RevertWow64FsRedirection(OldValue);

    return 1;
}

ULONG ThreadHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    if (ParamCount) {
        DefaultThread = DecodeIntegerParameter(*Parameters);
    }
    LogMessage(stdout, "Default thread is %llu", DefaultThread);
    return 1;
}

static DWORD __stdcall BackgroundThread(LPVOID Parameter)
{
    ShellExecute(NULL, "runas", Parameter, 0, 0, SW_SHOWNORMAL);
    return 0;
}

ULONG ConsentHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    HANDLE RunasThread;

    if (ParamCount) {
        RunasThread = CreateThread(NULL, 0, BackgroundThread, *Parameters, 0, 0);
    } else {
        RunasThread = CreateThread(NULL, 0, BackgroundThread, "cmd", 0, 0);
    }

    CloseHandle(RunasThread);

    return 1;
}

ULONG RegHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    DWORD Value;
    DWORD Size;
    HKEY Root;
    PCHAR Subkey;
    LSTATUS Result;
    DWORD ValueType;

    Size      = sizeof Value;
    Value     = -1;
    ValueType = 0;

    // By making the subkey the last parameter we dont have to worry
    // about escaping special characters.
    Subkey = GetOrigCommandLine(TRUE, 2);

    // Strip any newline
    if (strchr(Subkey, '\n')) {
        *strchr(Subkey, '\n') = '\0';
    }

    if (strcmp(*Parameters, "HKLM") == 0) {
        Root = HKEY_LOCAL_MACHINE;
    } else if (strcmp(*Parameters, "HKCU") == 0) {
        Root = HKEY_CURRENT_USER;
    } else if (strcmp(*Parameters, "HKCR") == 0) {
        Root = HKEY_CLASSES_ROOT;
    } else {
        LogMessage(stderr, "Unsupported root name %s", *Parameters);
        return 1;
    }

    Result = RegGetValueA(Root,
                          Subkey,
                          Parameters[1],
                          RRF_RT_REG_DWORD,
                          &ValueType,
                          &Value,
                          &Size);

    if (Result == ERROR_UNSUPPORTED_TYPE && ValueType == REG_SZ) {
        CHAR    StrVal[32] = {0};
        PCHAR   EndChar;
        DWORD   StrSize;

        StrSize = sizeof StrVal;
        EndChar = NULL;

        Result = RegGetValueA(Root,
                              Subkey,
                              Parameters[1],
                              RRF_RT_REG_SZ,
                              NULL,
                              StrVal,
                              &StrSize);

        if (Result == ERROR_SUCCESS) {
            Value = strtoul(StrVal, &EndChar, 0);
            if (*StrVal == '\0' || *EndChar != '\0')
                Result = ERROR_UNSUPPORTED_TYPE;
        }
    }

    if (Result == ERROR_UNSUPPORTED_TYPE) {
        LogMessage(stdout, "The key is not a DWORD, Type %#x", ValueType);
    }

    if (Result != ERROR_SUCCESS) {
        LogMessage(stdout, "Failed to query %s, %#x", Subkey, Result);
        LastRegistryValue = -1;
        return 1;
    }

    LogMessage(stdout, "%s is %u", Parameters[1], Value);

    LastRegistryValue = Value;

    return 1;
}

ULONG WindowHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    CTF_MSGBASE Message;
    HWND Window;
    HRESULT Result;

    ZeroMemory(&Message, sizeof Message);

    Message.Message     = MSG_SETTHREADHWND;
    Message.SrcThreadId = ClientThreadId;
    Window              = CreateMessageWindow();
    Message.Params[0]   = (DWORD) Window;

    if (Window == NULL) {
        LogMessage(stderr, "failed to create window, %#x", GetLastError());
        return 1;
    }

    // Now register the window with monitor.
    Result = SendReceivePortMessage(PortHandle, &Message.Header, sizeof Message, NULL);

    if (Result != 0) {
        LogMessage(stderr, "failed to send message to server, %#x", Result);
        DestroyWindow(Window);
    }

    return 1;
}

ULONG SectionHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    CHAR ModulePath[MAX_PATH] = {0};
    BOOL Found;
    PVOID OldValue;

    // Copy the name while we figure out where it is.
    strncpy(ModulePath, *Parameters, MAX_PATH - 5);

    // Is it already fully qualified?
    if (PathIsRelative(*Parameters)) {
        // This doesnt do anything if there already is an extension.
        PathAddExtension(ModulePath, ".DLL");

        // Check the usual places for it.
        PathFindOnPathA(ModulePath, NULL);
    }

    // Disable Redirection so we get the real files.
    Wow64DisableWow64FsRedirection(&OldValue);

    Found = GetSectionProperty(ModulePath, Parameters[1], Parameters[2], &LastSectionResult);

    // Restore Redirection.
    Wow64RevertWow64FsRedirection(OldValue);

    if (Found) {
        LogMessage(stdout, "%s->%s->%s is %#08llx",
                           ModulePath,
                           Parameters[1],
                           Parameters[2],
                           LastSectionResult);
    } else {
        LogMessage(stdout, "Failed to lookup %s property.", Parameters[1]);
    }

    return 1;
}

ULONG GadgetHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    SIZE_T Size;
    INT64 Result;
    PBYTE ByteString = Parameters[1];
    BYTE HexBuf[MAX_BUF];

    if (strlen(ByteString) & 1) {
        LogMessage(stderr, "Parsing as a hex string, but you didn't specify enough characters!");
        return 1;
    }

    if (strlen(ByteString) > MAX_BUF * 2) {
        LogMessage(stderr, "Parsing as a hex string, but you specified too many characters!");
        return 1;
    }

    // Parse as a hex string, e.g. 41414141412eff00
    for (Size = 0; *ByteString;) {
        BYTE CurrentChar[3] = {0};
        CurrentChar[0] = *ByteString++;
        CurrentChar[1] = *ByteString++;
        #pragma warning(suppress: 6328)
        if (sscanf(CurrentChar, "%hhx", &HexBuf[Size++]) != 1) {
            LogMessage(stderr, "Parsing hex string but failed, I stopped at %s", CurrentChar);
            return 1;
        }
    }

    Result = FindGadgetOffset(*Parameters, HexBuf, Size);

    if (Result >= 0) {
        LogMessage(stderr, "Found Gadget %.6s... in module %s at offset %#llx", Parameters[1], Parameters[0], Result);
    } else {
        LogMessage(stderr, "Gadget %.6s... not found in module %s", Parameters[1], Parameters[0]);
    }

    LastGadget = Result;

    return 1;
}

ULONG CallHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters)
{
    CTF_MSGBASE Message;
    HRESULT Result;

    ZeroMemory(&Message, sizeof Message);

    Message.SrcThreadId = ClientThreadId;
    Message.DstThreadId = DecodeIntegerParameter(Parameters[0]);

    // Check if this is a protocol constant.
    if (GetCommandNum(Parameters[1]) >= 0) {
        Message.Message = GetCommandNum(Parameters[1]);
    } else {
        Message.Message = DecodeIntegerParameter(Parameters[1]);
    }

    switch (ParamCount) {
        case 6: {
            // Note that there is no fourth parameter in the protocol, but
            // there is slack space in the structure because one of the union
            // members is a pointer.
            #pragma warning(suppress: 6201 6386)
            Message.Params[3] = DecodeIntegerParameter(Parameters[5]);
        }
        case 5: Message.Params[2] = DecodeIntegerParameter(Parameters[4]);
        case 4: Message.Params[1] = DecodeIntegerParameter(Parameters[3]);
        case 3: Message.Params[0] = DecodeIntegerParameter(Parameters[2]);
    }

    // DstThreadId zero means monitor, but I also use it for default :(
    if (Message.DstThreadId == 0 && DefaultThread != 0) {
        Message.DstThreadId = DefaultThread;
    }

    LogMessage(stdout, "Message: %#x", Message.Message);
    LogMessage(stdout, "Parameters In [ %08x %08X %08X ]",
                        Message.Params[0],
                        Message.Params[1],
                        Message.Params[2]);

    Result = SendReceivePortMessage(PortHandle,
                                   &Message.Header,
                                    sizeof Message,
                                    NULL);

    if (Result != 0) {
        LogMessage(stderr, "failed to send message to server, %#x", Result);
        goto cleanup;
    }

    LogMessage(stdout, "Result: %#x", Message.Result);
    LogMessage(stdout, "Parameters Out: [ %08x %08X %08X ]",
                        Message.Params[0],
                        Message.Params[1],
                        Message.Params[2]);

    hexdump(&Message, sizeof Message);

cleanup:
    return 1;
}

ULONG DispatchCommand(PCHAR CommandLine)
{
    ULONG Result = 2;
    PCHAR Command;
    ULONG ParamCount;
    PCHAR Parameters[MAX_PARAM] = {0};
    ULONG TotalCommands = _countof(CommandHandlers);
    PCOMMAND_HANDLER Handler;

    // Check for comment
    if (*CommandLine == '#')
        return 1;

    // Make a copy of CommandLine we can modify.
    CommandLine = strdup(CommandLine);

    // Tokenize CommandLine.
    Command = strtok(CommandLine, " \t\n");
    for (ParamCount = 0; ParamCount < MAX_PARAM; ParamCount++) {
        if ((Parameters[ParamCount] = strtok(NULL, " \t\n")) == NULL)
            break;
    }

    // Find a handler.
    if (Command) {
        #pragma warning(push)
        #pragma warning(disable : 4090 4028)
        Handler = _lfind(Command,
                         CommandHandlers,
                         &TotalCommands,
                         sizeof(*CommandHandlers),
                         CompareFirst);
        #pragma warning(pop)

        if (Handler) {
            if (ParamCount >= Handler->MinParams) {
                Result = Handler->Callback(Command, ParamCount, Parameters);
            } else {
                LogMessage(stderr, "Command '%s' Requires at least %u Parameters",
                                    Command,
                                    Handler->MinParams);
            }
        } else {
            LogMessage(stderr, "Unrecognised Command '%s'", Command);
        }
    }

cleanup:
    free(CommandLine);
    return Result;
}

