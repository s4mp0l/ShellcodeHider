#include <string.h>
#include "Common.h"

// RC4 Key Scheduling Algorithm (KSA)
BOOL Rc4Initialize(PRC4_CTX pCtx, LPCBYTE pKey, SIZE_T sKeySize) {
    DWORD i = 0;
    DWORD j = 0;
    BYTE  bTemp = 0;

    if (!pCtx || !pKey || sKeySize == 0) {
        return FALSE;
    }

    pCtx->i = 0;
    pCtx->j = 0;

    // Permutation
    for (i = 0; i < 256; i++) {
        pCtx->S[i] = (BYTE)i;
    }

    // Key mixing
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + pCtx->S[i] + pKey[i % sKeySize]) % 256;

        bTemp = pCtx->S[i];
        pCtx->S[i] = pCtx->S[j];
        pCtx->S[j] = bTemp;
    }

    return TRUE;
}

// Pseudo-Random Generation Algorithm (PRGA) + XOR
BOOL Rc4Crypt(PRC4_CTX pCtx, LPCBYTE pInput, PBYTE pOutput, SIZE_T sSize) {
    DWORD i = pCtx->i;
    DWORD j = pCtx->j;
    BYTE  bTemp = 0;
    BYTE  bK = 0;

    while (sSize > 0) {
        i = (i + 1) % 256;
        j = (j + pCtx->S[i]) % 256;

        // Swap
        bTemp = pCtx->S[i];
        pCtx->S[i] = pCtx->S[j];
        pCtx->S[j] = bTemp;

        // Keystream byte
        bK = pCtx->S[(pCtx->S[i] + pCtx->S[j]) % 256];

        // XOR
        if (pInput && pOutput) {
            *pOutput = *pInput ^ bK;
            pInput++;
            pOutput++;
        }

        sSize--;
    }

    // Preserve state
    pCtx->i = i;
    pCtx->j = j;

    return TRUE;
}

BOOL Rc4SystemFunction033(PBYTE pShellcode, SIZE_T sShellcodeSize, LPCBYTE pKey, SIZE_T sKeySize) {
    fnSystemFunction033 pSystemFunction033 = NULL;

    NTSTATUS            ntStatus = 0;
    HMODULE             hAdvapi32 = NULL;

    USTRING             Key = { 0 };
    USTRING             Data = { 0 };

    // Load Advapi32.dll
    hAdvapi32 = LoadLibraryA("advapi32.dll");

    if (hAdvapi32 == NULL) {
        printf("[!] The ADVAPI32 handle could not be obtained. Error code: %lu\n", GetLastError());
        return FALSE;
    }

    pSystemFunction033 = (fnSystemFunction033)GetProcAddress(hAdvapi32, "SystemFunction033");

    if (pSystemFunction033 == NULL) {
        printf("[!] GetProcAddress(SystemFunction033) failed with error code: %lu\n", GetLastError());
        FreeLibrary(hAdvapi32);
        return FALSE;
    }

    Key.Length = (ULONG)sKeySize;
    Key.MaximumLength = (ULONG)sKeySize;
    Key.Buffer = (PVOID)pKey;

    Data.Length = (ULONG)sShellcodeSize;
    Data.MaximumLength = (ULONG)sShellcodeSize;
    Data.Buffer = (PVOID)pShellcode;

    ntStatus = pSystemFunction033(&Data, &Key);

    if (!NT_SUCCESS(ntStatus)) {
        printf("[!] SystemFunction033 failed with error code: 0x%08X\n", ntStatus);
        FreeLibrary(hAdvapi32);
        return FALSE;
    }

    FreeLibrary(hAdvapi32);
    return TRUE;
}