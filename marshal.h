#ifndef __MARSHAL_H
#define __MARSHAL_H

PVOID MarshalParamsInsertData(PCTF_MARSHAL_PARAM Base,
                              ULONG Count,
                              ULONG Index,
                              DWORD TypeFlags,
                              PVOID Data,
                              SIZE_T Size,
                              BOOL FreeOrig);

void MarshalParamsFree(PCTF_MARSHAL_PARAM Base);
void MarshalParamsDumpData(PCTF_MARSHAL_PARAM Base, ULONG Index);
SIZE_T GetParamsSize(PCTF_MARSHAL_PARAM Base, ULONG Count);

#define MarshalDataPtr(type, base, index) (type)((PBYTE)(base) + (base)[(index)].Start)

PCHAR GetCommandName(UCHAR Command);
INT GetCommandNum(PCHAR Command);
PCHAR GetMarshalFlagName(DWORD Flag);
BOOL GetMarshalFlagsString(DWORD Flags, PCHAR Result, SIZE_T MaxSize);
DWORD GetMarshalFlagNum(PCHAR Flag);
DWORD DecodeMarshalFlagsString(PCHAR MarshalFlags);

#endif
