#ifndef __COMMANDDOC_H
#define __COMMANDDOC_H

#define THREAD_PARAM_HELP                                                      \
    "THREAD must be a client connected to the monitor, use \"scan\" to list\n" \
    "available clients. However, if THREAD is the special value 0 then the\n"  \
    "default thread is used, see \"thread\" and \"wait\" for details.\n\n"     \

#define GUID_PARAM_HELP                                                        \
    "GUID should be in the form 41414141-4141-4141-4141-414141414141.\n\n"

const static char HelpDoc[] =
    "Usage: help [COMMAND]\n"
    "Without any parameters, help lists all available commands and a brief\n"
    "description of usage. If COMMAND is specified, print detailed command\n"
    "usage information.";

const static char ExitDoc[] =
    "Usage: exit\n"
    "Immediately exit ctftool, aliases quit and q also work.";

const static char ConnectDoc[] =
    "Usage: connect [DESKTOPNAME SESSIONID]\n"
    "Without any parameters, connect to the ctf monitor for the current\n"
    "desktop and session. All subsequent commands will use this connection\n"
    "for communicating with the ctf monitor.\n\n"
    "If a connection is already open, the existing connection is closed first."
    "\n\n"
    "If DESKTOPNAME and SESSIONID are specified, a connection to ctf monitor\n"
    "for another desktop and session are opened, if it exists.\n"
    "If the specified port does not exist, wait until it does exist. This is\n"
    "so that you can wait for a session that hasn't started\n"
    "yet in a script.\n"
    "Examples\n"
    " Connect to the monitor for current desktop\n"
    "  ctf> connect\n"
    " Connect to a specific desktop and session.\n"
    "  ctf> connect Default 1";

const static char InfoDoc[] =
    "Usage: info\n"
    "Query and print all available information from the monitor.";

const static char ScanDoc[] =
    "Usage: scan\n"
    "Enumerate all threads connected to the monitor.\n"
    "Many commands require a client thread ID, scan lists these and the\n"
    "associated process.\n";

const static char CallStubDoc[] =
    "Usage: callstub THREAD STUBID FUNCTION\n"
    "Invoke a function on an instantiated COM object in the specified THREAD.\n"
    "\n"
    "Note: This command sends the current parameter chain to the server, see\n"
    "the \"setarg\" command for details, and run \"setarg 0\" if you want\n"
    "to discard any active parameters.\n\n"

    THREAD_PARAM_HELP

    "STUBID must be an id returned by the \"createstub\" command.\n"
    "However, if STUBID is 0, then the last created stub is used. This allows\n"
    "simple scripting, as you wont know the STUBID in advance.\n\n"

    "FUNCTION is an integer indicating which function you want the client to\n"
    "invoke.\n\n"

    "Examples\n"
    " Set the default thread to the first notepad.exe client connected, then\n"
    " create a stubid with createstub and a parameter chain with setarg and\n"
    " then call function index 3.\n"
    " Note the usage of 0 to use default thread and stub.\n\n"
    "  wait notepad.exe\n"
    "  createstub 0 4 IID_ITfInputProcessorProfileMgr\n"
    "  setarg 6\n"
    "  setarg 0x201 0x41414141\n"
    "  setarg 0x20001 0x41414142\n"
    "  setarg 0x1 ABABABAB-ABAB-ABAB-ABAB-ABABABABABAB\n"
    "  setarg 0x1 BCBCBCBC-BCBC-BCBC-BCBC-BCBCBCBCBCBC\n"
    "  setarg 0x10001 0x41414145\n"
    "  setarg 0x201 0x41414146\n"
    "  callstub 0 0 3";

const static char CreateStubDoc[] =
    "Usage: createstub THREAD TYPE GUID\n"
    "   or: createstub THREAD TYPE INTERFACENAME\n"
    "Ask a client to instantiate a COM object with specified CLSID.\n\n"

    "A stub is an instantiated COM object, you can call remote methods on it\n"
    "using \"callstub\", and pass it parameters with \"setarg\". If the\n"
    "command is successful, the client will give you a stubid, timestamp and\n"
    "the guid of the object created. These are required for interaction with\n"
    "the object, but ctfmon remembers them so you only need the stubid.\n\n"

    THREAD_PARAM_HELP

    "TYPE is an integer object subtype interpreted by the client, in the\n"
    "range 0 - 4 (I think?), some objects ignore this number but it is\n"
    "always required.\n\n"

    GUID_PARAM_HELP

    "Alternatively, you may specify INTERFACENAME instead of GUID, if you\n"
    "know it (e.g. IID_ITfInputProcessorProfileSubstituteLayout).\n"

    "Examples\n"
    " Use an interfacename to instantiate an object (subtype 4) in thread 1234\n"
    "  createstub 1234 4 IID_ITfInputProcessorProfileMgr\n"
    " Use a GUID to instantiate an object in the default thread\n"
    "  createstub 0 2 ABABABAB-ABAB-ABAB-ABAB-ABABABABABAB";

const static char HijackDoc[] =
    "Usage: hijack DESKTOPNAME SESSION\n"
    "Pretend to be the monitor for the specified DESKTOPNAME and SESSION,\n"
    "Dump information from connecting clients.\n"
    "Note that you will need to interrupt (ctrl-c) to stop.\n"
    "Examples\n"
    " Pretend to be the server for the next session\n"
    "  hijack Default 2\n";

const static char SetArgDoc[] =
    "Usage: setarg COUNT\n"
    "   or: setarg [TYPEFLAGS...] VALUE\n"
    "The ctf monitor and clients support the concept of marshaling and\n"
    "unmarshaling types across the ALPC transport. For example, you want to\n"
    "call an RPC with different params like ints, strings, guids, handles,\n"
    "etc. These all have to be marshalled by the sender, and unmarshalled by\n"
    "the receiver. The process is reversed to retrieve the result.\n\n"

    "In general, ctf clients and servers reuse the same buffer for responses.\n"
    "\n"
    "All commands that require marshalled parameters use the current chain\n"
    "created by setarg, there can only be one chain active at a time. You\n"
    "can query the existing chain with \"getarg\".\n\n"

    "COUNT is used to create a new chain of the specified length, discarding\n"
    "any existing chain. The size of the chain must be known in advance, and\n"
    "you cannot alter the size of an existing chain. ctftool warns you if you\n"
    "try to do this.\n\n"

    "TYPEFLAGS is the combined type and flags for this type, e.g. 0x201\n"
    "0x200 is an integer, and 0x01 specified an input. If more than one\n"
    "flag is specified, they are OR'd together. Some symbolic names are\n"
    "suported, such as MARSHAL_TYPE_COM.\n"

    "VALUE is the type-specific value for this parameter, e.g. an integer\n"
    "string or handle value.\n\n"

    "When specifying a type that accepts arbitrary data, setarg attempts to\n"
    "parse VALUE as a GUID, a string if it is surrouded by quotes, and then\n"
    "a sequence of hex bytes. An error is returned if the type cannot be parsed.\n"

    "Examples\n"
    " To create a parameter chain, first tell ctfmon how many entries there\n"
    " are. This must be known before you push values onto the chain.\n"
    "  ctf> setarg 2\n"
    "  New Parameter Chain, Length 2\n"
    " Now you have an empty chain of 2 parameters, you cant query them yet\n"
    " because the size isn't known, e.g.\n"
    "  ctf> setarg 2\n"
    "  New Parameter Chain, Length 2\n"
    "  ctf> getarg 0\n"
    "  Bad index requested!\n"
    " Now you can fill in the parameters, it must be in order.\n"
    "  ctf> setarg 0x201 0x12345\n"
    " This marshals an input integer, and sets it's value to 0x12345.\n\n"
    "I know this is complicated...sorry!\n";

static const char GetArgDoc[] =
    "Usage: getarg INDEX\n"
    "Print information about the marshalled parameter INDEX. This can be used\n"
    "for debugging paramters you created with \"setarg\", or dumping output\n"
    "parameters from the monitor.\n"
    "see \"setarg\" for more thorough documentation.\n";

static const char WaitDoc[] =
    "Usage: wait IMAGENAME [MILLISECONDS]\n"
    "Like the \"scan\" command, but halts execution until a client matching\n"
    "IMAGENAME connects, and then sets the default thread to the matching\n"
    "client. This can be used for scripting.\n\n"
    "If MILLISECONDS is specified, wait the specified time between\n"
    "polling for new clients (default=5000).\n"
    "Examples\n"
    " Wait for notepad to connect, then show that notepad is the new default\n"
    " thread.\n"
    "  ctf> wait notepad.exe\n"
    "  Found new client notepad.exe, DefaultThread now 6284\n"
    "  ctf> thread\n"
    "  Default thread is 6284\n";

static const char ThreadDoc[] =
    "Usage: thread\n"
    "Show the current default thread. This is the value used when you\n"
    "specify a thread id of zero to commands that require one.\n"
    "If you really want a destination thread of 0, for example to\n"
    "send commands to the monitor, use `thread 0`.\n";

static const char SleepDoc[] =
    "Usage: sleep MILLISECONDS\n"
    "Sleep the specified number of MILLISECONDS, useful for scripting.\n";

static const char ForgetDoc[] =
    "Usage: forget\n"
    "Reset all known stubs, for example, if you are no longer interested\n"
    "in this thread. This is useful when monitoring a new thread with\n"
    "\"wait\" while scripting.";

static const char StackDoc[] =
    "Usage: stack\n"
    "When you marshal parameters to the monitor, it uses some slack space\n"
    "in the PORT_MESSAGE to store a temporary pointer. That pointer is not\n"
    "cleared before it replies, so we can learn the stack address.\n\n"
    "On Windows, image randomization is per-boot, but stack randomization is\n"
    "per-exec, so this might be useful in exploitation.\n";

static const char CallDoc[] =
    "Usage: call THREAD MESSAGE [PARAM...]\n"
    "Send a command to the monitor without appended data. You can still set\n"
    "the message parameters, many commands require this.\n\n"

    THREAD_PARAM_HELP

    "MESSAGE is the number or name of the command you wish to send, with any\n"
    "required flags.\n\n"

    "PARAM are optional DWORD parameters that are part of the message\n"
    "structure. You can specify up to 3, others are ignored.\n"
    "Examples\n"
    " Find the pid of the monitor\n"
    "  ctf> thread 0\n"
    "  ctf> call 0 0x38\n";

static const char MarshalDoc[] =
    "Usage: marshal THREAD MESSAGE\n"
    "Send a command to the monitor with the current argument chain appended.\n"
    "See the commands `setarg` and `getarg` for controlling the current\n"
    "argument chain.\n"
    "You cannot specify message parameters, because the protocol for\n"
    "marshalled data doesnt have in-mesage parameters.\n\n"

    THREAD_PARAM_HELP

    "MESSAGE is the number or name of the command you wish to send, with any\n"
    "required flags.\n\n"
    "Examples\n"
    " Implement the `createstub` command manually.\n"
    "  ctf> setarg 4\n"
    "  ctf> setarg 0x201 0\n"
    "  ctf> setarg 0x201 4\n"
    "  ctf> setarg 1 71C6E74D-0F28-11D8-A82A-00065B84435C\n"
    "  ctf> setarg 0x106 00000000-0000-0000-0000-000000000000\n"
    "  ctf> marshal 0 11\n"
    "  Result: 0, use `getarg` if you want to examine data\n"
    "  ctf> getarg 3\n"
    "  Dumping Marshal Parameter 3 (Base 00929470, Type 0x106, Size 0x18, Offset 0x40)\n"
    "  000000: 4d e7 c6 71 28 0f d8 11 a8 2a 00 06 5b 84 43 5c  M..q(....*..[.C\\\n"
    "  000010: 02 00 00 00 67 68 ff 06                          ....gh..\n"
    "  Marshalled Value 3, COM {71C6E74D-0F28-11D8-A82A-00065B84435C}, ID 2, Timestamp 0x6ff6867\n"
    "\n"
    " Now you can see the monitor stack address if you like.\n"
    " ctf> stack\n";

static const char ModuleDoc[] =
    "Usage: module NAME\n"
    "   or  module64 NAME\n"
    "Load the specific module and print it's address. ASLR is per-boot\n"
    "in Windows, so this address will be valid in other clients with the module\n"
    "loaded.\n"
    "NAME is a module name, for example \"kernel32\".\n";

static const char PatchDoc[] =
    "Usage: patch INDEX OFFSET VALUE WIDTH [ADJUST [SHIFT]]\n"
    "Oh boy. If you need precise control over a marshalled parameter created\n"
    "with `setarg` then this command will let you modify them in such a way\n"
    "that would usually be illegal or or unsupported. You might want to do this\n"
    "for exploitation or testing.\n"
    "\n"
    "INDEX is the parameter number, it must be a valid index in the current\n"
    "parameter chain. See `getarg` and `setarg` for more.\n"
    "OFFSET is the byte index into the parameter you want to start modifying.\n"
    "VALUE is the new value you want to replace the current value. This can be\n"
    "a special value, see the \"show\" command for a complete list.\n"
    "WIDTH is the size in bytes you want written, any additional bits in VALUE\n"
    "are simply discarded.\n"
    "ADJUST and SHIFT are both optional parameters. ADJUST is added to VALUE\n"
    "before the patch operation, it is intended for scripting. SHIFT will right\n"
    "shift VALUE *after* ADJUST is added.\n"
    "If you want to use SHIFT without any adjustment, specify an ADJUST of zero.\n"
    "The purpose of SHIFT is you might want to reorder the bytes of a larger\n"
    "value, or distribute them differently for an exploit. With SHIFT you can\n"
    "extract one byte at a time and insert at a different OFFSET.\n"
    "\n"
    "Examples:\n"
    "Create a GUID parameter, and patch the first byte.\n"
    "  ctf> setarg 1\n"
    "  New Parameter Chain, Length 1\n"
    "  ctf> setarg 0 41414141-4141-4141-4141-414141414141\n"
    "  Marshalled Value 0, GUID {41414141-4141-4141-4141-414141414141}\n"
    "  ctf> patch 0 0 0 1\n"
    "  Dumping Original...\n"
    "  000000: 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA\n"
    "  Marshalled Value 0, GUID {41414141-4141-4141-4141-414141414141}\n"
    "  Dumping New...\n"
    "  000000: 00 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41  .AAAAAAAAAAAAAAA\n"
    "  Marshalled Value 0, GUID {41414100-4141-4141-4141-414141414141}\n";

static const char EditArgDoc[] =
    "Usage: editarg INDEX TYPE\n"
    "Change the type of parameter INDEX to TYPE\n"
    "See `setarg` and `getarg` for more information. See also `patcharg`.\n"
    "Note that you can create invalid parameters with this command, no attempt\n"
    "is made to validate what you enter.\n";

static const char SymbolDoc[] =
    "Usage: symbol MODULE!SYMBOL\n"
    "Attempt to find the offset of SYMBOL from MODULE base, see `module` and\n"
    "`module64` to find the module load address. This is non-trivial, because\n"
    "we handle 32bit and 64bit modules.\n\n"
    "This is not intended to be a debugger and doesnt handle everything!\n\n"
    "You can specify a module like KERNEL32 or a path like\n"
    "C:\\WINDOWS\\MODULE.DLL, and ctftool will attempt to do the right thing.\n"
    "Note that WoW redirection is disabled for this feature, so if you really\n"
    "want the 32 bit module on x64, use C:\\WINDOWS\\SYSWOW64\\MODULE.DLL.\n"
    "You might need this when exploiting with a 32bit WoW client on x64.\n"
    "The offset learned can be used in scripts with the `patch` command.\n";

static const char SetDoc[] =
    "Usage: set [VARIABLE [VALUE]]\n"
    "   or  add [VARIABLE [VALUE]]\n"
    "   or  sub [VARIABLE [VALUE]]\n"
    "   or  neg [VARIABLE [VALUE]]\n"
    "   or  shl [VARIABLE [VALUE]]\n"
    "   or  shr [VARIABLE [VALUE]]\n"
    "   or  and [VARIABLE [VALUE]]\n"
    "   or  or  [VARIABLE [VALUE]]\n"
    "   or  xor [VARIABLE [VALUE]]\n"
    "   or  not [VARIABLE [VALUE]]\n"
    "   or  eq  [VARIABLE [VALUE]]\n"
    "View or change ctftool variables.\n\n"
    "VARIABLE is the name of an internal variable. Run set without any parameters\n"
    "to see a list of variables available.\n\n"
    "You may optionally change the value by specifying a new VALUE.\n"
    "Additionally, There are 6 registers named r0-r5 that you may use for\n"
    "scripting.\n\n"
    "Examples:\n"
    "Simple arithmetic with user registers."
    "  ctf> set r0 0x41414141\n"
    "  r0                   = 0x41414141\n"
    "  ctf> set r1 0x02020202\n"
    "  r1                   = 0x2020202\n"
    "  ctf> or r0 r1\n"
    "  r0                   = 0x43434343\n"
    "  ctf> shr r0 4\n"
    "  r0                   = 0x4343434\n";

static const char ShowDoc[] =
    "Usage: show [NAME]\n"
    "Show the special variables you can use in commands. If NAME is specified,\n"
    "print its value.\n";

static const char LockDoc[] =
    "Usage: lock\n"
    "Unprivileged users can switch to the privileged Winlogon desktop and session\n"
    "using USER32!LockWorkstation. After executing this, a SYSTEM privileged\n"
    "ctfmon will spawn.\n";

static const char RepeatDoc[] = 
    "Usage: repeat N command [PARAMS...]\n"
    "Repeat command N times, PARAMS are interpreted by the command specified.\n\n"
    "There is a tunable setting called repeat-delay that can be changed with the\n"
    "set command which will pause between repeats, which is useful for debugging.\n";

static const char RunDoc[] = 
    "Usage: run [COMMAND]\n"
    "Launch a command. WoW64 redirection is disabled for the duration of this\n"
    "command to allow access to auto-escalate binaries like osk.exe on x64.\n"
    "You should use full SYSWOW64 paths if you need access to 32bit executables.";

static const char ScriptDoc[] =
    "Usage: script [FILENAME]\n"
    "The specified file is read and interpreted as commands. For the duration\n"
    "Of the script, verbosity is reduced.";

static const char ConsentDoc[] =
    "Usage: consent [COMMAND]\n"
    "Unprivileged users can trigger the UAC consent dialog, which is a highly\n"
    "privileged CTF client. This might be useful for privilege escalation.\n";

static const char RegDoc[] =
    "Usage: reg [HKLM|HKCU|HKCR] VALUE SUBKEY\n"
    "Lookup a DWORD value in the registry, and store it in the regval variable.\n"
    "This is intended for scripting.\n"
    "In addition, because it is so common, if VALUE is a REG_SZ and a valid\n"
    "integer, it will be automatically translated into a DWORD.\n";

static const char WindowDoc[] =
    "Usage: window\n"
    "Create and register a window with the monitor. This allows you to log\n"
    "window messages received from other ctf clients or servers.\n";

static const char GadgetDoc[] =
    "Usage: gadget MODULE BYTESTRING\n"
    "Find the first offset of BYTESTRING in MODULE. The result is stored in\n"
    "the gadget variable, as well as printed.\n\n"
    "Examples:\n"
    " ctf> gadget kernel32 413168c4\n";

static const char SectionDoc[] =
    "Usage: section MODULE SECTIONNAME PROPERTY\n"
    "Parse the section header of MODULE, find a section named SECTIONNAME and\n"
    "print the value of PROPERTY. PROPERTY should be a member of\n"
    "IMAGE_SECTION_HEADER, such as VirtualAddress.\n\n"
    "The result is stored in the secval variable for scripting.\n\n"
    "Examples:\n"
    " ctf> section kernel32 .text PointerToRawData\n";

#endif
