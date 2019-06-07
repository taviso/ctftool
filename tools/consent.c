#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

#pragma comment(lib, "SHELL32")

int main(int argc, char **argv)
{
    ShellExecute(NULL, "runas", "cmd", 0, 0, SW_SHOWNORMAL);
}
