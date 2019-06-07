#ifndef __UTIL_H
#define __UTIL_H

extern ULONG VerbosityLevel;

#define LogMessage(s, f, ...) fprintf(s, f, __VA_ARGS__), fputc('\n', s)
#define LogMessageLevel(l, s, f, ...) do {          \
    if ((l) >= VerbosityLevel) {                    \
        fprintf(s, f, __VA_ARGS__);                 \
        fputc('\n', s)                              \
    }                                               \
} while (false)

void hexdump(void *ptr, int buflen);
PVOID mempcpy(PVOID dest, const PVOID src, SIZE_T count);

#endif
