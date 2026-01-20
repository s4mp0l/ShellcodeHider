#include "Common.h"

BOOL MacObfuscation(PBYTE pShellcode, SIZE_T sShellcodeSize, char** ppMacArray, SIZE_T sNumberOfMacs) {
    for (SIZE_T i = 0; i < sNumberOfMacs; i++) {
        ppMacArray[i] = (char*)malloc(18);

        if (ppMacArray[i] == NULL) {
            return FALSE;
        }

        BYTE b[6] = { 0 };
        for (int j = 0; j < 6; j++) {
            if (i * 6 + j < sShellcodeSize) {
                b[j] = pShellcode[i * 6 + j];
            }
        }

        sprintf_s(ppMacArray[i], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
            b[0], b[1], b[2], b[3], b[4], b[5]);
    }

    return TRUE;
}