#ifndef __CTFINTERNAL_H
#define __CTFINTERNAL_H

#define MSGFLAG_COMMAND         0x000FFFFF
#define MSGFLAG_DOCUMENT        0x00100000
#define MSGFLAG_DATAVIEW        0x04000000
#define MSGFLAG_IMESERVER       0x08000000
#define MSGFLAG_CACHED_REPLY    0x20000000
#define MSGFLAG_DATA_APPENDED   0x80000000

enum {
    MSG_NOOP = 0x01,
    MSG_FINDPROPERTY = 0x04,
    MSG_GETPROPERTY = 0x05,
    MSG_SETPROPERTY = 0x06,
    MSG_CALLSTUB = 0x0A,
    MSG_CREATESTUB = 0x0B,
    MSG_STUBCLEANUP = 0x0C,
    // MSG_GET??? = 0x15,
    // MSG_SET??? = 0x16,
    MSG_GETCLIENTINFO = 0x1B,
    MSG_GETCLIENTINFOEX = 0x19,
    MSG_GETTHREADHWND = 0x20,
    MSG_SETTHREADHWND = 0x21,
    //MSG_FIND??? = 0x22,
    //MSG_FIND??? = 0x23,
    MSG_SETKBLAYOUT = 0x24,
    MSG_SETPROFILE = 0x25,
    MSG_GETMONITORPID = 0x38,
    //...

    MSG_KEYEVENT = 0x68,

    // >= 0xC8 <= 0xDC are IME messages
    MSG_REMOVEINPUTPROFILE = 0xC9,
    MSG_SETRANGETEXT = 0xD1,
    MSG_REQUESTEDITSESSION = 0xD5,
    MSG_CANCELEDITSESSION = 0xD6,
    MSG_ADDHOTKEY = 0xDB,
    MSG_REMOVEHOTKEY = 0xDC,
};

typedef struct _CTF_MSGBASE {
    PORT_MESSAGE Header;
    DWORD Message;
    DWORD SrcThreadId;
    DWORD DstThreadId;
    DWORD Result;
    union {
        struct _CTF_MSGBASE_PARAM_MARSHAL {
            DWORD ulNumParams;
            DWORD ulDataLength;
            UINT64 pData;
        };
        DWORD Params[3];
    };
} CTF_MSGBASE, *PCTF_MSGBASE;

#define CLIENT_FLAG_IME 0x40000000

typedef struct _CTF_CONNECT_MSG {
    PORT_MESSAGE Header;
    DWORD ProcessId;
    DWORD ThreadId;
    DWORD TickCount;
    DWORD ClientFlags;
    union {
        UINT64 QuadWord;
        HWND WindowId;
    };
} CTF_CONNECT_MSG, *PCTF_CONNECT_MSG;


#define MARSHAL_FLAG_INPUT      0x00001
#define MARSHAL_FLAG_OUTPUT     0x00002
#define MARSHAL_FLAG_ARRAY      0x00004 // The value is the element count.
#define MARSHAL_FLAG_ALLOCATED  0x00020 // Set if you want space allocated for the array.
#define MARSHAL_FLAG_PRESENT    0x00010

#define MARSHAL_TYPE_MASK 0xfff00

enum {
    MARSHAL_TYPE_DATA   = 0x00000,  // Arbitrary sized data.
    MARSHAL_TYPE_COM    = 0x00100,  // COM Object StubID?
    MARSHAL_TYPE_INT    = 0x00200,  // 32bit integer? (size must still be 8)
    MARSHAL_TYPE_STR    = 0x00400,  // SysAllocString
    MARSHAL_TYPE_GDI    = 0x00800,  // GDI Resource
    MARSHAL_TYPE_ICON   = 0x02000,  // HICON
    MARSHAL_TYPE_STRUCT = 0x08000,
    MARSHAL_TYPE_LONG   = 0x10000,  // Dunno, some integer type (size == 8)
    MARSHAL_TYPE_WORD   = 0x20000,  // 16bit integer. (size must still be 8)
    MARSHAL_TYPE_MEM    = 0x40000,  // CoTaskMemAlloc
};

typedef struct _CTF_MARSHAL_PARAM {
    DWORD Start;
    DWORD Size;
    DWORD TypeFlags;
    DWORD Reserved;
} CTF_MARSHAL_PARAM, *PCTF_MARSHAL_PARAM;

typedef struct _CTF_MARSHAL_COMSTUB {
    GUID Interface;
    DWORD StubId;
    DWORD Timestamp;
} CTF_MARSHAL_COMSTUB, *PCTF_MARSHAL_COMSTUB;

typedef struct _CTF_PROXY_SIGNATURE {
    GUID Interface;
    DWORD FunctionIndex;
    DWORD StubId;
    DWORD Timestamp;
    DWORD field_1C; // I've never seen these fields used, but ctfmon is strict about the size of the signature.
    DWORD field_20; 
    DWORD field_24;
} CTF_PROXY_SIGNATURE, *PCTF_PROXY_SIGNATURE;

typedef struct _KNOWN_INTERFACE {
    const CHAR *Name;
    const GUID *Interface;
} KNOWN_INTERFACE, *PKNOWN_INTERFACE;

DEFINE_GUID(IID_IAICProxy, 0xC1A97C88,
            0xDE59, 0x470F,
            0xAD, 0xCB, 0xA6, 0xC9, 0x16, 0xFC, 0xA6, 0xC2);
DEFINE_GUID(IID_IAICEventSink, 0x70f2f87b,
            0x1319, 0x4156,
            0x8b, 0xfB, 0x69, 0xa3, 0x5c, 0x25, 0x0e, 0x31);
DEFINE_GUID(IID_IObjectWithSite, 0x0FC4801A3,
            0x2BA9,
            0x11CF,
            0xA2, 0x29, 0, 0xAA, 0, 0x3D, 0x73, 0x52);

static const KNOWN_INTERFACE KnownInterfaces[] = {
    { "IID_ITfInputProcessorProfileMgr", &IID_ITfInputProcessorProfileMgr },
    { "IID_ITfCompartmentMgr", &IID_ITfCompartmentMgr },
    { "IID_ITfCompartment", &IID_ITfCompartment },
    { "IID_ITfInputProcessorProfileMgr", &IID_ITfInputProcessorProfileMgr },
    { "IID_IEnumTfInputProcessorProfiles", &IID_IEnumTfInputProcessorProfiles },
    { "IID_IUnknown", &IID_IUnknown },
    { "IID_ITfInputProcessorProfiles", &IID_ITfInputProcessorProfiles },
    { "IID_ITfInputProcessorProfilesEx", &IID_ITfInputProcessorProfilesEx },
    { "IID_ITfInputProcessorProfileSubstituteLayout", &IID_ITfInputProcessorProfileSubstituteLayout },
    { "IID_ITfSource", &IID_ITfSource },
    { "IID_IAICProxy", &IID_IAICProxy },
    { "IID_IAICEventSink", &IID_IAICEventSink },
    { "IID_IObjectWithSite", &IID_IObjectWithSite },
    { "IID_ITfLangBarItemMgr", &IID_ITfLangBarItemMgr },
    { "IID_IEnumTfLangBarItems", &IID_IEnumTfLangBarItems },
};

#endif
