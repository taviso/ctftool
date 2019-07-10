#ifndef __COMMAND_H
#define __COMMAND_H

#define MAX_PARAM 32
#define MAX_STUBS 32
#define MAX_BUF 8192

// We remember stub data so user only has to remember ID and thread.
typedef struct _STUB_RECORD {
    DWORD ThreadId;
    CTF_MARSHAL_COMSTUB Stub;
} STUB_RECORD, *PSTUB_RECORD;

typedef struct _COMMAND_HANDLER {
    PCHAR Command;
    ULONG MinParams;
    PCHAR LongDescription;
    PCHAR Description;
    ULONG (*Callback)(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
} COMMAND_HANDLER, *PCOMMAND_HANDLER;

typedef struct _SPECIAL_VARIABLE {
    PCHAR Name;
    PCHAR Description;
    ULONGLONG Value;
} SPECIAL_VARIABLE, *PSPECIAL_VARIABLE;

// If you specify a tid of 0, the DefaultThread is used, which can be set
// via wait or thread commands.
extern UINT64 DefaultThread;

// If you specify a stubid of 0, the last stub created is used (Note that
// msctf will never return a 0 stubid).
extern UINT64 DefaultStub;

// The handle to the monitor.
extern HANDLE PortHandle;

// We create a window to monitor RPC commands.
extern HWND MessageWindow;

// The monitor leaks a stack pointer on every marshal command.
// This might be useful in exploitation, so you can retrieve it if you want it.
extern UINT64 LeakedStackPointer;

extern UINT64 LastModuleBase;

extern UINT64 LastSymbolOffset;

// How many stubs we know about.
extern ULONG NumStubs;

// Known stubs.
extern STUB_RECORD StubRecords[MAX_STUBS];

// Total number of parameters in the current parameter chain.
extern ULONG CountMarshalParams;

// How many of the total parameters have been specified.
extern ULONG CurrentMarshalParam;

// Pointer to the current parameter chain.
extern PCTF_MARSHAL_PARAM MarshalParams;

// The ThreadID we are claiming to be, by default it's the truth, but you can
// lie if you like.
extern UINT64 ClientThreadId;

// The flags we set when we connect.
extern UINT64 ClientFlags;

// Set when we're running a script.
extern ULONG NonInteractive;

// Padding for the PROXY_SIGNATURE.
extern UINT64 ProxyExtra1;
extern UINT64 ProxyExtra2;
extern UINT64 ProxyExtra3;

// User specified variables for scripting.
extern ULONGLONG UserRegisters[6];

// The return code of the last process from "run"
extern ULONGLONG LastCommandResult;

// The last value looked up in the registry.
extern ULONGLONG LastRegistryValue;

ULONG ExitHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG HelpHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG ConnectHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG InfoHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG ScanHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG CreateStubHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG CallStubHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG SetArgHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG GetArgHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG HijackHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG WaitHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG ThreadHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG SleepHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG ForgetHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG StackHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG MarshalHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG ProxyHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG CallHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG PatchHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG ModuleHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG ModuleHandler64(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG EditArgHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG SymbolHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG SetHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG ShowHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG LockHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG RepeatHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG RunHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG ScriptHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG PrintHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG ConsentHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG RegHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG WindowHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG GadgetHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);
ULONG SectionHandler(PCHAR Command, ULONG ParamCount, PCHAR *Parameters);

ULONG DispatchCommand(PCHAR CommandLine);
int CompareFirst(PCHAR a, PCHAR *b);
ULONGLONG DecodeIntegerParameter(PCHAR Value);
HWND CreateMessageWindow();

#endif
