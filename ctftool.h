#ifndef __CTFTOOL_H
#define __CTFTOOL_H

HWND CreateMessageWindow();

NTSTATUS SendReceivePortMessage(HANDLE PortHandle,
                                PPORT_MESSAGE PortMessage,
                                ULONG BufferLength,
                                PLARGE_INTEGER Timeout);
NTSTATUS SendReceiveProxyData(HANDLE PortHandle,
                              ULONG TypeFlags,
                              PCTF_MARSHAL_PARAM Params,
                              ULONG ParamCount,
                              PCTF_MARSHAL_COMSTUB Stub,
                              DWORD FunctionIndex,
                              DWORD DestinationThread);
NTSTATUS SendReceiveMarshalData(HANDLE PortHandle,
                                ULONG TypeFlags,
                                PCTF_MARSHAL_PARAM Params,
                                ULONG ParamCount,
                                DWORD DestinationThread);

HANDLE OpenAlpcPort(PWCHAR AlpcPortName, PPORT_MESSAGE ConnectMessage, SIZE_T MessageSize);
BOOL InitializeAlpcRoutines();

extern FARPROC AlpcInitializeMessageAttribute;
extern FARPROC AlpcGetMessageAttribute;
extern FARPROC GUIDFromString;

#endif
