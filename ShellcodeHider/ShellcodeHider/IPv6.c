#include "Common.h"

BOOL IPv6Obfuscation(PBYTE pShellcode, SIZE_T sShellcodeSize, char** ppIPv6Array, SIZE_T sNumberOfIPv6) {
    for (SIZE_T i = 0; i < sNumberOfIPv6; i++) {
        ppIPv6Array[i] = (char*)malloc(48);

        if (ppIPv6Array[i] == NULL) {
            return FALSE;
        }

        // 16 raw bytes for each IPv6 address
        BYTE b[16] = { 0 };
        for (int j = 0; j < 16; j++) {
            if (i * 16 + j < sShellcodeSize) {
                b[j] = pShellcode[i * 16 + j];
            }
        }

        sprintf_s(ppIPv6Array[i], 48, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    }

    return TRUE;
}