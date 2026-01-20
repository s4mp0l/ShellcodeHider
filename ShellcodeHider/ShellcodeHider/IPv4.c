#include "Common.h"

BOOL IPv4Obfuscation(PBYTE pShellcode, SIZE_T sShellcodeSize, char** ppIPv4Array, SIZE_T sNumberOfIPv4) {
    for (SIZE_T i = 0; i < sNumberOfIPv4; i++) {
        ppIPv4Array[i] = (char*)malloc(16);

        if (ppIPv4Array[i] == NULL) {
            return FALSE;
        }

        // each IP = 4 bytes
        PBYTE b1 = (i * 4 < sShellcodeSize) ? pShellcode[i * 4] : 0;
        PBYTE b2 = (i * 4 + 1 < sShellcodeSize) ? pShellcode[i * 4 + 1] : 0;
        PBYTE b3 = (i * 4 + 2 < sShellcodeSize) ? pShellcode[i * 4 + 2] : 0;
        PBYTE b4 = (i * 4 + 3 < sShellcodeSize) ? pShellcode[i * 4 + 3] : 0;

        sprintf_s(ppIPv4Array[i], 16, "%u.%u.%u.%u", (DWORD)b1, (DWORD)b2, (DWORD)b3, (DWORD)b4);
    }

    return TRUE;
}