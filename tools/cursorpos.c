#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

#pragma comment(lib, "USER32")

int main(int argc, char **argv)
{
    POINT Point;

    while (true) {
        Sleep(1000);
        GetCursorPos(&Point);
        fprintf(stdout, "%#x x %#x\n", Point.x, Point.y);
    }
}
