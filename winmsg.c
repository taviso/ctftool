#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <msctf.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include "ntdll.h"
#include "ntalpctyp.h"
#include "ntalpc.h"

#include "ctfinternal.h"
#include "ctftool.h"

#define LogMessage(s, f, ...) fprintf(s, f, __VA_ARGS__), fputc('\n', s)

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) 
{
    switch (uMsg) {
        case WM_GETMINMAXINFO:
        case WM_NCCREATE:
        case WM_NCCALCSIZE:
        case WM_CREATE:
        case WM_WINDOWPOSCHANGING:
        case WM_ACTIVATEAPP:
        case WM_NCACTIVATE:
        case WM_ACTIVATE:
        case WM_IME_SETCONTEXT:
        case WM_IME_NOTIFY:
        case WM_GETOBJECT:
        case WM_SETFOCUS:
        case WM_DESTROY:
        case WM_NCDESTROY:
        case 0x90: // WM_UAHDESTROYWINDOW
            break;
        default:
            LogMessage(stderr, "WindowProc(%p, %#x, %p, %p);", hwnd, uMsg, (PVOID)wParam, (PVOID) lParam);
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

HWND CreateMessageWindow()
{
    WNDCLASSEX WindowClass = {0};
    ATOM Atom;
    HWND MsgWindow;

    WindowClass.cbSize         = sizeof(WNDCLASSEX);
    WindowClass.lpfnWndProc    = WindowProc;
    WindowClass.lpszClassName  = "Class";

    Atom = RegisterClassEx(&WindowClass);
    MsgWindow = CreateWindowEx(0,
                               MAKEINTATOM(Atom),
                               "Message",
                               0,
                               0,
                               0,
                               128,
                               128,
                               0,
                               NULL,
                               NULL,
                               NULL);

    LogMessage(stdout, "message window %p", MsgWindow);
    return MsgWindow;
}
