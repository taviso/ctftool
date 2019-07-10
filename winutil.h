#ifndef __WINUTIL_H
#define __WINUTIL_H

BOOL GetActiveThreadInfo(PDWORD ThreadId, HWND *Window, PDWORD ProcessId);
DWORD GetFocusThread(void);
PVOID QueryImageName(DWORD ProcessId);
UINT64 QueryModuleHandle64(PCHAR Module);
UINT64 QueryModuleHandle32(PCHAR Module);
INT64 FindGadgetOffset(PCHAR Module, PCHAR Gadget, SIZE_T GadgetLen);
DWORD GetSessionIdByImageName(PCHAR ImageName);

// This finds the ImageBase and offset of a symbol from a 64bit module, this is
// complicated because we're a 32bit process.
BOOL GetSymbolInfo64(PCHAR Filename,
                     PCHAR Export,
                     PBOOL Is64,
                     PULONGLONG ImageBase,
                     PULONGLONG Address);

BOOL GetSectionProperty(PCHAR Filename,
                        PCHAR Section,
                        PCHAR Property,
                        PULONGLONG Result);
#endif
