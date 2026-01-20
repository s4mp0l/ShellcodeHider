#include "Common.h"

BOOL UuidObfuscation(PBYTE pShellcode, SIZE_T sShellcodeSize, char** ppUuidArray, SIZE_T sNumberOfUuids) {
    for (SIZE_T i = 0; i < sNumberOfUuids; i++) {
        ppUuidArray[i] = (char*)malloc(37);

        if (ppUuidArray[i] == NULL) {
            return FALSE;
        }

        BYTE b[16] = { 0 };

        for (int j = 0; j < 16; j++) {
            if (i * 16 + j < sShellcodeSize) {
                b[j] = pShellcode[i * 16 + j];
            }
        }

        // UUID byte order: time_low reversed, time_mid reversed, time_hi_and_version reversed, rest normal
        sprintf_s(ppUuidArray[i], 37,
            "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            b[3], b[2], b[1], b[0],
            b[5], b[4],
            b[7], b[6],
            b[8], b[9], b[10], b[11],
            b[12], b[13], b[14], b[15]);
    }

    return TRUE;
}