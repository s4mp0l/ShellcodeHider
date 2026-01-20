#include "Common.h"

BOOL XorEncrypt(PBYTE pShellcode, SIZE_T sShellcodeSize, PBYTE pKey, size_t sKeySize) {
    for (size_t i = 0; i < sShellcodeSize; i++) {
        pShellcode[i] = (pShellcode[i] ^ pKey[i % sKeySize]) + i;
    }

    return TRUE;
}