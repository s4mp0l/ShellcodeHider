#include <windows.h>
#include <stdio.h>

/*
    AES BCrypt library
*/

VOID PrintBCryptAesDecryptionRoutine() {
    printf("#include <windows.h>\n");
    printf("#include <stdio.h>\n");
    printf("#include <bcrypt.h>\n\n");
    printf("#pragma comment(lib, \"bcrypt.lib\")\n\n");
    printf("#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)\n");
    printf("#define KEY_SIZE    32\n");
    printf("#define IV_SIZE     16\n");

    printf("\n"
        "BOOL DecryptShellcodeBCrypt(\n"
        "    PBYTE   pCiphertext,\n"
        "    SIZE_T  sCiphertextSize,\n"
        "    PBYTE*  ppPlaintext,\n"
        "    SIZE_T* psPlaintextSize,\n"
        "    PBYTE   pKey,\n"
        "    PBYTE   pIv\n"
        ") {\n"
        "    BCRYPT_ALG_HANDLE   hAlg            = NULL;\n"
        "    BCRYPT_KEY_HANDLE   hKey            = NULL;\n"
        "    NTSTATUS            ntStatus        = 0;\n"
        "    DWORD               cbKeyObj        = 0;\n"
        "    DWORD               cbData          = 0;\n"
        "    DWORD               cbPlain         = 0;\n"
        "    PBYTE               pbKeyObject     = NULL;\n"
        "    PBYTE               pbIvWorking     = NULL;\n"
        "    BOOL                bSuccess        = FALSE;\n"
        "\n"
        "    *ppPlaintext     = NULL;\n"
        "    *psPlaintextSize = 0;\n"
        "\n"
        "    ntStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);\n"
        "    if (!NT_SUCCESS(ntStatus)) {\n"
        "        printf(\"[!] BCryptOpenAlgorithmProvider failed with NTSTATUS: 0x%%08X\\n\", ntStatus);\n"
        "        goto Cleanup;\n"
        "    }\n"
        "\n"
        "    ntStatus = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);\n"
        "    if (!NT_SUCCESS(ntStatus)) {\n"
        "        printf(\"[!] BCryptSetProperty failed with NTSTATUS: 0x%%08X\\n\", ntStatus);\n"
        "        goto Cleanup;\n"
        "    }\n"
        "\n"
        "    ntStatus = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(DWORD), &cbData, 0);\n"
        "    if (!NT_SUCCESS(ntStatus)) {\n"
        "        printf(\"[!] BCryptGetProperty failed with NTSTATUS: 0x%%08X\\n\", ntStatus);\n"
        "        goto Cleanup;\n"
        "    }\n"
        "\n"
        "    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);\n"
        "    if (!pbKeyObject) {\n"
        "        printf(\"[!] Memory allocation failed\\n\");\n"
        "        goto Cleanup;\n"
        "    }\n"
        "\n"
        "    ntStatus = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObj, pKey, KEY_SIZE, 0);\n"
        "    if (!NT_SUCCESS(ntStatus)) {\n"
        "        printf(\"[!] BCryptGenerateSymmetricKey failed with NTSTATUS: 0x%%08X\\n\", ntStatus);\n"
        "        goto Cleanup;\n"
        "    }\n"
        "\n"
        "    pbIvWorking = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_SIZE);\n"
        "    if (!pbIvWorking) {\n"
        "        printf(\"[!] Memory allocation failed\\n\");\n"
        "        goto Cleanup;\n"
        "    }\n"
        "    memcpy(pbIvWorking, pIv, IV_SIZE);\n"
        "\n"
        "    ntStatus = BCryptDecrypt(hKey, pCiphertext, (ULONG)sCiphertextSize, NULL, pbIvWorking, IV_SIZE, NULL, 0, &cbPlain, 0);\n"
        "    if (!NT_SUCCESS(ntStatus)) {\n"
        "        printf(\"[!] BCryptDecrypt[1] failed with NTSTATUS: 0x%%08X\\n\", ntStatus);\n"
        "        goto Cleanup;\n"
        "    }\n"
        "\n"
        "    *ppPlaintext = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlain);\n"
        "    if (!*ppPlaintext) {\n"
        "        printf(\"[!] Memory allocation failed\\n\");\n"
        "        goto Cleanup;\n"
        "    }\n"
        "\n"
        "    memcpy(pbIvWorking, pIv, IV_SIZE);\n"
        "\n"
        "    ntStatus = BCryptDecrypt(hKey, pCiphertext, (ULONG)sCiphertextSize, NULL, pbIvWorking, IV_SIZE, *ppPlaintext, cbPlain, &cbData, 0);\n"
        "    if (!NT_SUCCESS(ntStatus)) {\n"
        "        printf(\"[!] BCryptDecrypt[2] failed with NTSTATUS: 0x%%08X\\n\", ntStatus);\n"
        "        goto Cleanup;\n"
        "    }\n"
        "\n"
        "    *psPlaintextSize = cbPlain;\n"
        "    bSuccess = TRUE;\n"
        "\n"
        "Cleanup:\n"
        "    if (hKey)        BCryptDestroyKey(hKey);\n"
        "    if (hAlg)        BCryptCloseAlgorithmProvider(hAlg, 0);\n"
        "    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);\n"
        "    if (pbIvWorking) HeapFree(GetProcessHeap(), 0, pbIvWorking);\n"
        "\n"
        "    if (!bSuccess && *ppPlaintext) {\n"
        "        HeapFree(GetProcessHeap(), 0, *ppPlaintext);\n"
        "        *ppPlaintext     = NULL;\n"
        "        *psPlaintextSize = 0;\n"
        "    }\n"
        "\n"
        "    return bSuccess;\n"
        "}\n\n");
}

VOID PrintBCryptAesUsage() {
    printf("/* Simple snippet to see how shellcode is decrypted\n\n");
    printf("void PrintHex(LPCSTR szName, PBYTE pBytes, SIZE_T sSize) {\n");
    printf("    printf(\"unsigned char %%s[] = {\", szName);\n");
    printf("    for (SIZE_T i = 0; i < sSize; i++) {\n");
    printf("        if (i %% 16 == 0) {\n");
    printf("            printf(\"\\n\\t\");\n");
    printf("        }\n");
    printf("        printf(\"0x%%02X\", pBytes[i]);\n");
    printf("        if (i < sSize - 1) {\n");
    printf("            printf(\", \");\n");
    printf("        }\n");
    printf("    }\n");
    printf("    printf(\"\\n};\\n\\n\");\n");
    printf("}\n\n");
    printf("int main() {\n");
    printf("    PBYTE  pShellcode = NULL;\n");
    printf("    SIZE_T sShellcodeSize = 0;\n");
    printf("    SIZE_T sEncryptedShellcodeSize = 0;\n\n");
    printf("    sEncryptedShellcodeSize = sizeof(pEncryptedShellcode) / sizeof(pEncryptedShellcode[0]);\n\n");
    printf("    DecryptShellcodeBCrypt(pEncryptedShellcode, sEncryptedShellcodeSize, &pShellcode, &sShellcodeSize, pKey, pIv);\n");
    printf("    PrintHex(\"pDecryptedShellcode\", pShellcode, sShellcodeSize);\n");
    printf("}\n");
    printf("*/\n\n");
}

/*
    TinyAes Library
*/

VOID PrintTinyAesDecryptionRoutine() {
    printf("#include <windows.h>\n");
    printf("#include <stdio.h>\n");
    printf("#include \"aes.h\"\n\n");
    printf("#define CBC      1\n");
    printf("#define AES256   1\n");
    printf("#define KEY_SIZE 32\n");
    printf("#define IV_SIZE  16\n\n");
    printf("BOOL DecryptShellcode(PBYTE pEncryptedShellcode, SIZE_T sEncryptedShellcodeSize, PBYTE* ppDecryptedShellcode, SIZE_T* pszDecryptedShellcodeSize, PBYTE pKey, PBYTE pIv) {\n"
        "   struct AES_ctx ctx;\n\n"
        "   AES_init_ctx_iv(&ctx, pKey, pIv);\n\n"
        "   AES_CBC_decrypt_buffer(&ctx, pEncryptedShellcode, (SIZE_T)sEncryptedShellcodeSize);\n\n"
        "   *ppDecryptedShellcode = pEncryptedShellcode;\n"
        "   *pszDecryptedShellcodeSize = sEncryptedShellcodeSize;\n\n"
        "   return TRUE;\n"
        "}\n\n");
}

VOID PrintTinyAesUsage() {
    printf("/* Simple snippet to see how shellcode is decrypted\n\n");
    printf("void PrintHex(LPCSTR szName, PBYTE pBytes, SIZE_T sSize) {\n");
    printf("    printf(\"unsigned char %%s[] = {\", szName);\n");
    printf("    for (SIZE_T i = 0; i < sSize; i++) {\n");
    printf("        if (i %% 16 == 0) {\n");
    printf("            printf(\"\\n\\t\");\n");
    printf("        }\n");
    printf("        printf(\"0x%%02X\", pBytes[i]);\n");
    printf("        if (i < sSize - 1) {\n");
    printf("            printf(\", \");\n");
    printf("        }\n");
    printf("    }\n");
    printf("    printf(\"\\n};\\n\\n\");\n");
    printf("}\n\n");
    printf("int main() {\n");
    printf("    PBYTE  pShellcode = NULL;\n");
    printf("    SIZE_T sShellcodeSize = 0;\n");
    printf("    SIZE_T sEncryptedShellcodeSize = 0;\n\n");
    printf("    sEncryptedShellcodeSize = sizeof(pEncryptedShellcode) / sizeof(pEncryptedShellcode[0]);\n\n");
    printf("    DecryptShellcode(pEncryptedShellcode, sEncryptedShellcodeSize, &pShellcode, &sShellcodeSize, pKey, pIv);\n");
    printf("    PrintHex(\"pDecryptedShellcode\", pShellcode, sShellcodeSize);\n");
    printf("}\n");
    printf("*/\n\n");
}

/*
    ChaCha20 Encryption
*/

VOID PrintChaCha20DecryptionRoutine() {
    printf("#include <windows.h>\n");
    printf("#include <stdio.h>\n\n");
    printf("#define CHACHA20_KEY_SIZE     32\n");
    printf("#define CHACHA20_NONCE_SIZE   12\n");
    printf("#define CHACHA20_BLOCK_SIZE   64\n\n");
    printf("typedef struct _CHACHA20_CTX {\n");
    printf("    DWORD State[16];\n");
    printf("} CHACHA20_CTX, *PCHACHA20_CTX;\n\n");
    printf("static inline DWORD Pack4Le(LPCBYTE pb) {\n");
    printf("    return ((DWORD)pb[0])     |\n");
    printf("           ((DWORD)pb[1] << 8)  |\n");
    printf("           ((DWORD)pb[2] << 16) |\n");
    printf("           ((DWORD)pb[3] << 24);\n");
    printf("}\n\n");
    printf("static inline DWORD Rotl32(DWORD dwValue, int nShift) {\n");
    printf("    return (dwValue << nShift) | (dwValue >> (32 - nShift));\n");
    printf("}\n\n");
    printf("static inline VOID QuarterRound(PDWORD pa, PDWORD pb, PDWORD pc, PDWORD pd) {\n");
    printf("    *pa += *pb;  *pd ^= *pa;  *pd = Rotl32(*pd, 16);\n");
    printf("    *pc += *pd;  *pb ^= *pc;  *pb = Rotl32(*pb, 12);\n");
    printf("    *pa += *pb;  *pd ^= *pa;  *pd = Rotl32(*pd, 8);\n");
    printf("    *pc += *pd;  *pb ^= *pc;  *pb = Rotl32(*pb, 7);\n");
    printf("}\n\n");
    printf("VOID ChaCha20Init(PCHACHA20_CTX pCtx, PBYTE pKey, PBYTE pNonce, DWORD dwCounter) {\n");
    printf("    static const BYTE chacha20_constants[16] = \"expand 32-byte k\";\n\n");
    printf("    pCtx->State[0] = Pack4Le(&chacha20_constants[0]);\n");
    printf("    pCtx->State[1] = Pack4Le(&chacha20_constants[4]);\n");
    printf("    pCtx->State[2] = Pack4Le(&chacha20_constants[8]);\n");
    printf("    pCtx->State[3] = Pack4Le(&chacha20_constants[12]);\n\n");
    printf("    for (int i = 0; i < 8; i++) {\n");
    printf("        pCtx->State[4 + i] = Pack4Le(pKey + i * 4);\n");
    printf("    }\n\n");
    printf("    pCtx->State[12] = dwCounter;\n");
    printf("    pCtx->State[13] = Pack4Le(pNonce + 0);\n");
    printf("    pCtx->State[14] = Pack4Le(pNonce + 4);\n");
    printf("    pCtx->State[15] = Pack4Le(pNonce + 8);\n");
    printf("}\n\n");
    printf("VOID ChaCha20Block(PCHACHA20_CTX pCtx, PBYTE pOutput) {\n");
    printf("    DWORD WorkingState[16];\n");
    printf("    memcpy(WorkingState, pCtx->State, sizeof(WorkingState));\n\n");
    printf("    for (int i = 0; i < 10; i++) {\n");
    printf("        QuarterRound(&WorkingState[0], &WorkingState[4],  &WorkingState[8],  &WorkingState[12]);\n");
    printf("        QuarterRound(&WorkingState[1], &WorkingState[5],  &WorkingState[9],  &WorkingState[13]);\n");
    printf("        QuarterRound(&WorkingState[2], &WorkingState[6],  &WorkingState[10], &WorkingState[14]);\n");
    printf("        QuarterRound(&WorkingState[3], &WorkingState[7],  &WorkingState[11], &WorkingState[15]);\n\n");
    printf("        QuarterRound(&WorkingState[0], &WorkingState[5],  &WorkingState[10], &WorkingState[15]);\n");
    printf("        QuarterRound(&WorkingState[1], &WorkingState[6],  &WorkingState[11], &WorkingState[12]);\n");
    printf("        QuarterRound(&WorkingState[2], &WorkingState[7],  &WorkingState[8],  &WorkingState[13]);\n");
    printf("        QuarterRound(&WorkingState[3], &WorkingState[4],  &WorkingState[9],  &WorkingState[14]);\n");
    printf("    }\n\n");
    printf("    for (int i = 0; i < 16; i++) {\n");
    printf("        WorkingState[i] += pCtx->State[i];\n");
    printf("    }\n\n");
    printf("    memcpy(pOutput, WorkingState, CHACHA20_BLOCK_SIZE);\n");
    printf("    pCtx->State[12]++;\n");
    printf("}\n\n");
    printf("VOID ChaCha20Xor(PCHACHA20_CTX pCtx, PBYTE pInput, PBYTE pOutput, SIZE_T sSize) {\n");
    printf("    BYTE Keystream[CHACHA20_BLOCK_SIZE];\n");
    printf("    SIZE_T sOffset = 0;\n\n");
    printf("    while (sSize > 0) {\n");
    printf("        ChaCha20Block(pCtx, Keystream);\n\n");
    printf("        SIZE_T sThisBlock = (sSize > CHACHA20_BLOCK_SIZE) ? CHACHA20_BLOCK_SIZE : sSize;\n\n");
    printf("        for (SIZE_T i = 0; i < sThisBlock; i++) {\n");
    printf("            pOutput[sOffset + i] = pInput[sOffset + i] ^ Keystream[i];\n");
    printf("        }\n\n");
    printf("        sOffset += sThisBlock;\n");
    printf("        sSize -= sThisBlock;\n");
    printf("    }\n");
    printf("}\n\n");
}

VOID PrintChacha20Usage() {
    printf("/* Simple snippet to see how shellcode is decrypted\n\n");
    printf("void PrintHex(LPCSTR szName, PBYTE pBytes, SIZE_T sSize) {\n");
    printf("    printf(\"unsigned char %%s[] = {\", szName);\n");
    printf("    for (SIZE_T i = 0; i < sSize; i++) {\n");
    printf("        if (i %% 16 == 0) {\n");
    printf("            printf(\"\\n\\t\");\n");
    printf("        }\n");
    printf("        printf(\"0x%%02X\", pBytes[i]);\n");
    printf("        if (i < sSize - 1) {\n");
    printf("            printf(\", \");\n");
    printf("        }\n");
    printf("    }\n");
    printf("    printf(\"\\n};\\n\\n\");\n");
    printf("}\n\n");
    printf("int main() {\n");
    printf("    CHACHA20_CTX ctx = { 0 };\n");
    printf("    PBYTE  pShellcode = NULL;\n");
    printf("    SIZE_T sShellcodeSize = 0;\n\n");
    printf("    sShellcodeSize = sizeof(pEncryptedShellcode) / sizeof(pEncryptedShellcode[0]);\n\n");
    printf("    pShellcode = HeapAlloc(GetProcessHeap(), 0, sShellcodeSize);\n\n");
    printf("    ChaCha20Init(&ctx, pKey, pNonce, 1);\n");
    printf("    ChaCha20Xor(&ctx, pEncryptedShellcode, pShellcode, sShellcodeSize);\n");
    printf("    PrintHex(\"pDecryptedShellcode\", pShellcode, sShellcodeSize);\n");
    printf("}\n");
    printf("*/\n\n");
}

/*
    Rc4 Encryption
*/

VOID PrintRc4DecryptionRoutine() {
    printf("#include <windows.h>\n");
    printf("#include <stdio.h>\n\n");
    printf("#define RC4_KEY_SIZE    16\n\n");
    printf("typedef struct _RC4_CTX {\n");
    printf("    DWORD  i;\n");
    printf("    DWORD  j;\n");
    printf("    BYTE    S[256];\n");
    printf("} RC4_CTX, *PRC4_CTX;\n\n");
    printf("BOOL Rc4Initialize(PRC4_CTX pCtx, LPCBYTE pKey, SIZE_T sKeySize);\n");
    printf("BOOL Rc4Crypt(PRC4_CTX pCtx, LPCBYTE pInput, PBYTE pOutput, SIZE_T sSize);\n\n");

    printf("BOOL Rc4Initialize(PRC4_CTX pCtx, LPCBYTE pKey, SIZE_T sKeySize) {\n");
    printf("    DWORD i = 0;\n");
    printf("    DWORD j = 0;\n");
    printf("    BYTE  bTemp = 0;\n\n");
    printf("    if (!pCtx || !pKey || sKeySize == 0) {\n");
    printf("        return FALSE;\n");
    printf("    }\n\n");
    printf("    pCtx->i = 0;\n");
    printf("    pCtx->j = 0;\n\n");
    printf("    for (i = 0; i < 256; i++) {\n");
    printf("        pCtx->S[i] = (BYTE)i;\n");
    printf("    }\n\n");
    printf("    j = 0;\n");
    printf("    for (i = 0; i < 256; i++) {\n");
    printf("        j = (j + pCtx->S[i] + pKey[i %% sKeySize]) %% 256;\n");
    printf("        bTemp         = pCtx->S[i];\n");
    printf("        pCtx->S[i]    = pCtx->S[j];\n");
    printf("        pCtx->S[j]    = bTemp;\n");
    printf("    }\n\n");
    printf("    return TRUE;\n");
    printf("}\n\n");

    printf("BOOL Rc4Crypt(PRC4_CTX pCtx, LPCBYTE pInput, PBYTE pOutput, SIZE_T sSize) {\n");
    printf("    DWORD i = pCtx->i;\n");
    printf("    DWORD j = pCtx->j;\n");
    printf("    BYTE  bTemp = 0;\n");
    printf("    BYTE  bK    = 0;\n\n");
    printf("    while (sSize > 0) {\n");
    printf("        i = (i + 1) %% 256;\n");
    printf("        j = (j + pCtx->S[i]) %% 256;\n\n");
    printf("        bTemp       = pCtx->S[i];\n");
    printf("        pCtx->S[i]  = pCtx->S[j];\n");
    printf("        pCtx->S[j]  = bTemp;\n\n");
    printf("        bK = pCtx->S[(pCtx->S[i] + pCtx->S[j]) %% 256];\n\n");
    printf("        if (pInput && pOutput) {\n");
    printf("            *pOutput = *pInput ^ bK;\n");
    printf("            pInput++;\n");
    printf("            pOutput++;\n");
    printf("        }\n\n");
    printf("        sSize--;\n");
    printf("    }\n\n");
    printf("    pCtx->i = i;\n");
    printf("    pCtx->j = j;\n\n");
    printf("    return TRUE;\n");
    printf("}\n\n");
}

VOID PrintRc4Usage() {
    printf("/* Simple snippet to see how shellcode is decrypted\n\n");
    printf("void PrintHex(LPCSTR szName, PBYTE pBytes, SIZE_T sSize) {\n");
    printf("    printf(\"unsigned char %%s[] = {\", szName);\n");
    printf("    for (SIZE_T i = 0; i < sSize; i++) {\n");
    printf("        if (i %% 16 == 0) {\n");
    printf("            printf(\"\\n\\t\");\n");
    printf("        }\n");
    printf("        printf(\"0x%%02X\", pBytes[i]);\n");
    printf("        if (i < sSize - 1) {\n");
    printf("            printf(\", \");\n");
    printf("        }\n");
    printf("    }\n");
    printf("    printf(\"\\n};\\n\\n\");\n");
    printf("}\n\n");
    printf("int main() {\n");
    printf("    RC4_CTX ctx = { 0 };\n");
    printf("    PBYTE  pShellcode = NULL;\n");
    printf("    SIZE_T sShellcodeSize = 0;\n\n");
    printf("    sShellcodeSize = sizeof(pEncryptedShellcode) / sizeof(pEncryptedShellcode[0]);\n");
    printf("    pShellcode = HeapAlloc(GetProcessHeap(), 0, sShellcodeSize);\n\n");
    printf("    Rc4Initialize(&ctx, pKey, RC4_KEY_SIZE);\n");
    printf("    Rc4Crypt(&ctx, pEncryptedShellcode, pShellcode, sShellcodeSize);\n\n");
    printf("    PrintHex(\"pDecryptedShellcode\", pShellcode, sShellcodeSize);\n");
    printf("}\n");
    printf("*/\n\n");
}

/*
    Rc4 via SystemFunction033 Encryption
*/

VOID PrintSystemFunction033DecryptionRoutine() {
    printf("#include <windows.h>\n");
    printf("#include <stdio.h>\n\n");
    printf("#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)\n");
    printf("#define RC4_KEY_SIZE        16\n\n");

    printf("typedef struct _USTRING {\n");
    printf("    ULONG   Length;\n");
    printf("    ULONG   MaximumLength;\n");
    printf("    PVOID   Buffer;\n");
    printf("} USTRING, *PUSTRING;\n\n");

    printf("typedef NTSTATUS(NTAPI* fnSystemFunction033)(\n");
    printf("    PUSTRING    Data,\n");
    printf("    PUSTRING    Key\n");
    printf(");\n\n");

    printf("BOOL Rc4SystemFunction033(\n");
    printf("    PBYTE       pShellcode,\n");
    printf("    SIZE_T      sShellcodeSize,\n");
    printf("    LPCBYTE     pKey,\n");
    printf("    SIZE_T      sKeySize\n");
    printf(") {\n");
    printf("    NTSTATUS            ntStatus    = 0;\n");
    printf("    HMODULE             hAdvapi32   = NULL;\n");
    printf("    fnSystemFunction033 pSystemFunction033  = NULL;\n");
    printf("    USTRING             Key         = {0};\n");
    printf("    USTRING             Data        = {0};\n\n");

    printf("    hAdvapi32 = LoadLibraryA(\"advapi32.dll\");\n");
    printf("    if (hAdvapi32 == NULL) {\n");
    printf("        printf(\"[!] LoadLibraryA(advapi32.dll) failed with code error: 0x%%lu\\n\", GetLastError());\n");
    printf("        return FALSE;\n");
    printf("    }\n\n");

    printf("    pSystemFunction033 = (fnSystemFunction033)GetProcAddress(hAdvapi32, \"SystemFunction033\");\n");
    printf("    if (pSystemFunction033 == NULL) {\n");
    printf("        printf(\"[!] GetProcAddress(SystemFunction033) failed with code error: %%lu\\n\", GetLastError());\n");
    printf("        FreeLibrary(hAdvapi32);\n");
    printf("        return FALSE;\n");
    printf("    }\n\n");

    printf("    Key.Length        = (ULONG)sKeySize;\n");
    printf("    Key.MaximumLength = (ULONG)sKeySize;\n");
    printf("    Key.Buffer        = (PVOID)pKey;\n\n");

    printf("    Data.Length        = (ULONG)sShellcodeSize;\n");
    printf("    Data.MaximumLength = (ULONG)sShellcodeSize;\n");
    printf("    Data.Buffer        = (PVOID)pShellcode;\n\n");

    printf("    ntStatus = pSystemFunction033(&Data, &Key);\n");
    printf("    FreeLibrary(hAdvapi32);\n\n");

    printf("    if (!NT_SUCCESS(ntStatus)) {\n");
    printf("        printf(\"[!] SystemFunction033 failed with error code: 0x%%08X\\n\", ntStatus);\n");
    printf("        return FALSE;\n");
    printf("    }\n\n");

    printf("    return TRUE;\n");
    printf("}\n\n");
}

VOID PrintRc4SystemFunction033Usage() {
    printf("/* Simple snippet to see how shellcode is decrypted\n\n");
    printf("void PrintHex(LPCSTR szName, PBYTE pBytes, SIZE_T sSize) {\n");
    printf("    printf(\"unsigned char %%s[] = {\", szName);\n");
    printf("    for (SIZE_T i = 0; i < sSize; i++) {\n");
    printf("        if (i %% 16 == 0) {\n");
    printf("            printf(\"\\n\\t\");\n");
    printf("        }\n");
    printf("        printf(\"0x%%02X\", pBytes[i]);\n");
    printf("        if (i < sSize - 1) {\n");
    printf("            printf(\", \");\n");
    printf("        }\n");
    printf("    }\n");
    printf("    printf(\"\\n};\\n\\n\");\n");
    printf("}\n\n");
    printf("int main() {\n");
    printf("    SIZE_T sShellcodeSize = 0;\n\n");
    printf("    sShellcodeSize = sizeof(pShellcode) / sizeof(pShellcode[0]);\n");
    printf("    Rc4SystemFunction033(pShellcode, sShellcodeSize, pKey, RC4_KEY_SIZE);\n\n");
    printf("    PrintHex(\"pDecryptedShellcode\", pShellcode, sShellcodeSize);\n");
    printf("}\n");
    printf("*/\n\n");
}

/*
    Xor Encryption
*/

VOID PrintXorDecryptionRoutine() {
    printf("#include <windows.h>\n");
    printf("#include <stdio.h>\n\n");
    printf("#define XOR_KEY_SIZE 16\n\n");
    printf("BOOL XorDecrypt(PBYTE pShellcode, SIZE_T sShellcodeSize, PBYTE pKey, size_t sKeySize) {\n");
    printf("    for (size_t i = 0; i < sShellcodeSize; i++) {\n");
    printf("        pShellcode[i] = (pShellcode[i] - i) ^ pKey[i %% sKeySize];\n");
    printf("    }\n\n");
    printf("    return TRUE;\n");
    printf("}\n\n");
}

VOID PrintXorUsage() {
    printf("/* Simple snippet to see how shellcode is decrypted\n\n");
    printf("void PrintHex(LPCSTR szName, PBYTE pBytes, SIZE_T sSize) {\n");
    printf("    printf(\"unsigned char %%s[] = {\", szName);\n");
    printf("    for (SIZE_T i = 0; i < sSize; i++) {\n");
    printf("        if (i %% 16 == 0) {\n");
    printf("            printf(\"\\n\\t\");\n");
    printf("        }\n");
    printf("        printf(\"0x%%02X\", pBytes[i]);\n");
    printf("        if (i < sSize - 1) {\n");
    printf("            printf(\", \");\n");
    printf("        }\n");
    printf("    }\n");
    printf("    printf(\"\\n};\\n\\n\");\n");
    printf("}\n\n");
    printf("int main() {\n");
    printf("    SIZE_T sShellcodeSize = 0;\n\n");
    printf("    sShellcodeSize = sizeof(pShellcode) / sizeof(pShellcode[0]);\n\n");
    printf("    XorDecrypt(pShellcode, sShellcodeSize, pKey, XOR_KEY_SIZE);\n\n");
    printf("    PrintHex(\"pDecryptedShellcode\", pShellcode, sShellcodeSize);\n");
    printf("}\n");
    printf("*/\n\n");
}

/*
    IPv4 Obfuscation
*/

VOID PrintIPv4DeobfuscationRoutine() {
    printf("#include <windows.h>\n");
    printf("#include <stdio.h>\n\n");
    printf("#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)\n\n");
    printf("typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(\n");
    printf("    PCSTR       S,\n");
    printf("    BOOLEAN     Strict,\n");
    printf("    PCSTR*      Terminator,\n");
    printf("    PVOID       Addr\n");
    printf(");\n\n");

    printf("BOOL IPv4Deobfuscation(\n");
    printf("    char**      ppIPv4Array,\n");
    printf("    SIZE_T      sNumberOfIPv4,\n");
    printf("    PBYTE       pDeobfuscatedShellcode\n");
    printf(") {\n");
    printf("    PCSTR       Terminator  = NULL;\n");
    printf("    NTSTATUS    ntStatus    = 0;\n\n");
    printf("    HMODULE hNtdll = GetModuleHandle(TEXT(\"NTDLL\"));\n\n");
    printf("    if (hNtdll == NULL) {\n");
    printf("        printf(\"[!] The NTDLL handle could not be obtained. Code error: %%d \\n\", GetLastError());\n");
    printf("        return FALSE;\n");
    printf("    }\n\n");
    printf("    fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA =\n");
    printf("        (fnRtlIpv4StringToAddressA)GetProcAddress(hNtdll, \"RtlIpv4StringToAddressA\");\n\n");
    printf("    if (pRtlIpv4StringToAddressA == NULL) {\n");
    printf("        printf(\"[!] RtlIpv4StringToAddressA failed with code error: %%lu \\n\", GetLastError());\n");
    printf("        return FALSE;\n");
    printf("    }\n\n");
    printf("    for (SIZE_T i = 0; i < sNumberOfIPv4; i++) {\n");
    printf("        ntStatus = pRtlIpv4StringToAddressA(\n");
    printf("            ppIPv4Array[i],\n");
    printf("            FALSE,\n");
    printf("            &Terminator,\n");
    printf("            pDeobfuscatedShellcode\n");
    printf("        );\n\n");
    printf("        if (!NT_SUCCESS(ntStatus)) {\n");
    printf("            printf(\"[!] RtlIpv4StringToAddressA failed on index %%zu → 0x%%08X\\n\", i, ntStatus);\n");
    printf("            return FALSE;\n");
    printf("        }\n\n");
    printf("        pDeobfuscatedShellcode += 4;\n");
    printf("    }\n\n");
    printf("    return TRUE;\n");
    printf("}\n\n");
}

VOID PrintIPv4Usage() {
    printf("/* Simple snippet to see how shellcode is deobfuscated\n\n");
    printf("void PrintHex(LPCSTR szName, PBYTE pBytes, SIZE_T sSize) {\n");
    printf("    printf(\"unsigned char %%s[] = {\", szName);\n");
    printf("    for (SIZE_T i = 0; i < sSize; i++) {\n");
    printf("        if (i %% 16 == 0) {\n");
    printf("            printf(\"\\n\\t\");\n");
    printf("        }\n");
    printf("        printf(\"0x%%02X\", pBytes[i]);\n");
    printf("        if (i < sSize - 1) {\n");
    printf("            printf(\", \");\n");
    printf("        }\n");
    printf("    }\n");
    printf("    printf(\"\\n};\\n\\n\");\n");
    printf("}\n\n");
    printf("int main() {\n");
    printf("    PBYTE  pDeobfuscatedShellcode = NULL;\n");
    printf("    SIZE_T sShellcodeSize = 0;\n");
    printf("    SIZE_T sNumberOfIPv4 = 0;\n\n");
    printf("    sNumberOfIPv4 = sizeof(ppIPv4Array) / sizeof(ppIPv4Array[0]);\n");
    printf("    sShellcodeSize = sNumberOfIPv4 * 4;\n\n");
    printf("    pDeobfuscatedShellcode = HeapAlloc(GetProcessHeap(), 0, sShellcodeSize);\n\n");
    printf("    IPv4Deobfuscation(ppIPv4Array, sNumberOfIPv4, pDeobfuscatedShellcode);\n\n");
    printf("    PrintHex(\"pDeobfuscatedShellcode\", pDeobfuscatedShellcode, sShellcodeSize);\n");
    printf("}\n");
    printf("*/\n\n");
}

/*
    IPv6 Obfuscation
*/

VOID PrintIPv6DeobfuscationRoutine() {
    printf("#include <windows.h>\n");
    printf("#include <stdio.h>\n\n");
    printf("#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)\n\n");
    printf("typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(\n");
    printf("    PCSTR       S,\n");
    printf("    PCSTR*      Terminator,\n");
    printf("    PVOID       Addr\n");
    printf(");\n\n");

    printf("BOOL IPv6Deobfuscation(\n");
    printf("    char**      ppIPv6Array,\n");
    printf("    SIZE_T      sNumberOfIPv6,\n");
    printf("    PBYTE       pDeobfuscatedShellcode\n");
    printf(") {\n");
    printf("    PCSTR       Terminator = NULL;\n");
    printf("    HMODULE     hNtdll     = NULL;\n\n");
    printf("    hNtdll = GetModuleHandle(TEXT(\"NTDLL\"));\n\n");
    printf("    if (hNtdll == NULL) {\n");
    printf("        printf(\"[!] The NTDLL handle could not be obtained. Code error: %%lu\\n\", GetLastError());\n");
    printf("        return FALSE;\n");
    printf("    }\n\n");
    printf("    fnRtlIpv6StringToAddressA pRtlIpv6StringToAddressA =\n");
    printf("        (fnRtlIpv6StringToAddressA)GetProcAddress(hNtdll, \"RtlIpv6StringToAddressA\");\n\n");
    printf("    if (pRtlIpv6StringToAddressA == NULL) {\n");
    printf("        printf(\"[-] RtlIpv6StringToAddressA failed with code error: %%lu\\n\", GetLastError());\n");
    printf("        return FALSE;\n");
    printf("    }\n\n");
    printf("    for (SIZE_T i = 0; i < sNumberOfIPv6; i++) {\n");
    printf("        pRtlIpv6StringToAddressA(ppIPv6Array[i], &Terminator, pDeobfuscatedShellcode);\n");
    printf("        pDeobfuscatedShellcode = pDeobfuscatedShellcode + 16;\n");
    printf("    }\n\n");
    printf("    return TRUE;\n");
    printf("}\n\n");
}

VOID PrintIPv6Usage() {
    printf("/* Simple snippet to see how shellcode is deobfuscated\n\n");
    printf("void PrintHex(LPCSTR szName, PBYTE pBytes, SIZE_T sSize) {\n");
    printf("    printf(\"unsigned char %%s[] = {\", szName);\n");
    printf("    for (SIZE_T i = 0; i < sSize; i++) {\n");
    printf("        if (i %% 16 == 0) {\n");
    printf("            printf(\"\\n\\t\");\n");
    printf("        }\n");
    printf("        printf(\"0x%%02X\", pBytes[i]);\n");
    printf("        if (i < sSize - 1) {\n");
    printf("            printf(\", \");\n");
    printf("        }\n");
    printf("    }\n");
    printf("    printf(\"\\n};\\n\\n\");\n");
    printf("}\n\n");
    printf("int main() {\n");
    printf("    PBYTE  pDeobfuscatedShellcode = NULL;\n");
    printf("    SIZE_T sShellcodeSize = 0;\n");
    printf("    SIZE_T sNumberOfIPv6 = 0;\n\n");
    printf("    sNumberOfIPv6 = sizeof(ppIPv6Array) / sizeof(ppIPv6Array[0]);\n");
    printf("    sShellcodeSize = sNumberOfIPv6 * 16;\n\n");
    printf("    pDeobfuscatedShellcode = HeapAlloc(GetProcessHeap(), 0, sShellcodeSize);\n\n");
    printf("    IPv6Deobfuscation(ppIPv6Array, sNumberOfIPv6, pDeobfuscatedShellcode);\n\n");
    printf("    PrintHex(\"pDeobfuscatedShellcode\", pDeobfuscatedShellcode, sShellcodeSize);\n");
    printf("}\n");
    printf("*/\n\n");
}

/*
    Mac Obfuscation
*/

VOID PrintMacDeobfuscationRoutine() {
    printf("#include <windows.h>\n");
    printf("#include <stdio.h>\n\n");
    printf("#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)\n\n");
    printf("typedef NTSTATUS(NTAPI* fnRtlEthernetStringToAddressA)(\n");
    printf("    PCSTR       S,\n");
    printf("    PCSTR*      Terminator,\n");
    printf("    PVOID       Addr\n");
    printf(");\n\n");
    printf("BOOL MacDeobfuscation(\n");
    printf("    char**      ppMacArray,\n");
    printf("    SIZE_T      sNumberOfMacs,\n");
    printf("    PBYTE       pDeobfuscatedShellcode\n");
    printf(") {\n");
    printf("    PCSTR   Terminator = NULL;\n");
    printf("    HMODULE hNtdll     = NULL;\n\n");
    printf("    hNtdll = GetModuleHandle(TEXT(\"NTDLL\"));\n\n");
    printf("    if (hNtdll == NULL) {\n");
    printf("        printf(\"[!] GetModuleHandle(NTDLL) failed → %%lu\\n\", GetLastError());\n");
    printf("        return FALSE;\n");
    printf("    }\n\n");
    printf("    fnRtlEthernetStringToAddressA pRtlEthernetStringToAddressA =\n");
    printf("        (fnRtlEthernetStringToAddressA)GetProcAddress(hNtdll, \"RtlEthernetStringToAddressA\");\n\n");
    printf("    if (pRtlEthernetStringToAddressA == NULL) {\n");
    printf("        printf(\"[!] GetProcAddress(RtlEthernetStringToAddressA) failed → %%lu\\n\", GetLastError());\n");
    printf("        return FALSE;\n");
    printf("    }\n\n");
    printf("    for (SIZE_T i = 0; i < sNumberOfMacs; i++) {\n");
    printf("        NTSTATUS ntStatus = pRtlEthernetStringToAddressA(\n");
    printf("            ppMacArray[i],\n");
    printf("            &Terminator,\n");
    printf("            pDeobfuscatedShellcode\n");
    printf("        );\n\n");
    printf("        if (!NT_SUCCESS(ntStatus)) {\n");
    printf("            printf(\"[!] RtlEthernetStringToAddressA failed on index %%zu → 0x%%08X\\n\", i, ntStatus);\n");
    printf("            return FALSE;\n");
    printf("        }\n\n");
    printf("        pDeobfuscatedShellcode += 6;\n");
    printf("    }\n\n");
    printf("    return TRUE;\n");
    printf("}\n\n");
}

VOID PrintMacUsage() {
    printf("/* Simple snippet to see how shellcode is deobfuscated\n\n");
    printf("void PrintHex(LPCSTR szName, PBYTE pBytes, SIZE_T sSize) {\n");
    printf("    printf(\"unsigned char %%s[] = {\", szName);\n");
    printf("    for (SIZE_T i = 0; i < sSize; i++) {\n");
    printf("        if (i %% 16 == 0) {\n");
    printf("            printf(\"\\n\\t\");\n");
    printf("        }\n");
    printf("        printf(\"0x%%02X\", pBytes[i]);\n");
    printf("        if (i < sSize - 1) {\n");
    printf("            printf(\", \");\n");
    printf("        }\n");
    printf("    }\n");
    printf("    printf(\"\\n};\\n\\n\");\n");
    printf("}\n\n");
    printf("int main() {\n");
    printf("    PBYTE  pDeobfuscatedShellcode = NULL;\n");
    printf("    SIZE_T sShellcodeSize = 0;\n");
    printf("    SIZE_T sNumberOfMacs = 0;\n\n");
    printf("    sNumberOfMacs = sizeof(ppMacArray) / sizeof(ppMacArray[0]);\n");
    printf("    sShellcodeSize = sNumberOfMacs * 6;\n\n");
    printf("    pDeobfuscatedShellcode = HeapAlloc(GetProcessHeap(), 0, sShellcodeSize);\n\n");
    printf("    MacDeobfuscation(ppMacArray, sNumberOfMacs, pDeobfuscatedShellcode);\n\n");
    printf("    PrintHex(\"pDeobfuscatedShellcode\", pDeobfuscatedShellcode, sShellcodeSize);\n");
    printf("}\n");
    printf("*/\n\n");
}

/*
    Uuid Obfuscation
*/

VOID PrintUuidDeobfuscationRoutine() {
    printf("#include <windows.h>\n");
    printf("#include <stdio.h>\n\n");
    printf("#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)\n\n");
    printf("typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(\n");
    printf("    RPC_CSTR    StringUuid,\n");
    printf("    UUID*       Uuid\n");
    printf(");\n\n");
    printf("BOOL UuidDeobfuscation(\n");
    printf("    char**      ppUuidArray,\n");
    printf("    SIZE_T      sNumberOfUuids,\n");
    printf("    PBYTE       pDeobfuscatedShellcode\n");
    printf(") {\n");
    printf("    HMODULE             hRpcrt4         = NULL;\n");
    printf("    fnUuidFromStringA   pUuidFromStringA = NULL;\n\n");

    printf("    hRpcrt4 = LoadLibraryA(\"rpcrt4.dll\");\n");
    printf("    if (hRpcrt4 == NULL) {\n");
    printf("        printf(\"[!] LoadLibraryA(rpcrt4.dll) failed with error code: %%lu\\n\", GetLastError());\n");
    printf("        return FALSE;\n");
    printf("    }\n\n");

    printf("    pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(hRpcrt4, \"UuidFromStringA\");\n");
    printf("    if (pUuidFromStringA == NULL) {\n");
    printf("        printf(\"[!] GetProcAddress(UuidFromStringA) failed with error code: %%lu\\n\", GetLastError());\n");
    printf("        FreeLibrary(hRpcrt4);\n");
    printf("        return FALSE;\n");
    printf("    }\n\n");

    printf("    for (SIZE_T i = 0; i < sNumberOfUuids; i++) {\n");
    printf("        RPC_STATUS status = pUuidFromStringA(\n");
    printf("            (RPC_CSTR)ppUuidArray[i],\n");
    printf("            (UUID*)pDeobfuscatedShellcode\n");
    printf("        );\n\n");
    printf("        if (status != RPC_S_OK) {\n");
    printf("            printf(\"[!] UuidFromStringA failed with error code: 0x%%08X\\n\", status);\n");
    printf("            FreeLibrary(hRpcrt4);\n");
    printf("            return FALSE;\n");
    printf("        }\n\n");
    printf("        pDeobfuscatedShellcode += 16;\n");
    printf("    }\n\n");

    printf("    FreeLibrary(hRpcrt4);\n");
    printf("    return TRUE;\n");
    printf("}\n\n");
}

VOID PrintUuidUsage() {
    printf("/* Simple snippet to see how shellcode is deobfuscated\n\n");
    printf("void PrintHex(LPCSTR szName, PBYTE pBytes, SIZE_T sSize) {\n");
    printf("    printf(\"unsigned char %%s[] = {\", szName);\n");
    printf("    for (SIZE_T i = 0; i < sSize; i++) {\n");
    printf("        if (i %% 16 == 0) {\n");
    printf("            printf(\"\\n\\t\");\n");
    printf("        }\n");
    printf("        printf(\"0x%%02X\", pBytes[i]);\n");
    printf("        if (i < sSize - 1) {\n");
    printf("            printf(\", \");\n");
    printf("        }\n");
    printf("    }\n");
    printf("    printf(\"\\n};\\n\\n\");\n");
    printf("}\n\n");
    printf("int main() {\n");
    printf("    PBYTE  pDeobfuscatedShellcode = NULL;\n");
    printf("    SIZE_T sShellcodeSize = 0;\n");
    printf("    SIZE_T sNumberOfUuids = 0;\n\n");
    printf("    sNumberOfUuids = sizeof(ppUuidArray) / sizeof(ppUuidArray[0]);\n");
    printf("    sShellcodeSize = sNumberOfUuids * 16;\n\n");
    printf("    pDeobfuscatedShellcode = HeapAlloc(GetProcessHeap(), 0, sShellcodeSize);\n\n");
    printf("    UuidDeobfuscation(ppUuidArray, sNumberOfUuids, pDeobfuscatedShellcode);\n\n");
    printf("    PrintHex(\"pDeobfuscatedShellcode\", pDeobfuscatedShellcode, sShellcodeSize);\n");
    printf("}\n");
    printf("*/\n\n");
}

/*
    Timestamp Obfuscation
*/

VOID PrintTimestampDeobfuscationRoutine() {
    printf("#include <windows.h>\n");
    printf("#include <stdio.h>\n\n");
    printf("PBYTE TimestampDeobfuscation(\n");
    printf("    char**      ppTimestampArray,\n");
    printf("    SIZE_T      sNumberOfTimestamps,\n");
    printf("    SIZE_T*     sDeobfuscatedShellcodeSize\n");
    printf(") {\n");
    printf("    int*    pDigits         = NULL;\n");
    printf("    int     nDigitsCapacity = 0;\n");
    printf("    int     nNumDigits      = 0;\n");
    printf("    PBYTE   pNum            = NULL;\n");
    printf("    SIZE_T  sMaxLen         = 0;\n");
    printf("    SIZE_T  sCurrentLen     = 0;\n\n");

    printf("    *sDeobfuscatedShellcodeSize = 0;\n\n");

    printf("    if (ppTimestampArray == NULL || sNumberOfTimestamps == 0) {\n");
    printf("        return NULL;\n");
    printf("    }\n\n");

    printf("    nDigitsCapacity = (int)(sNumberOfTimestamps * 7) + 10;\n");
    printf("    pDigits = (int*)HeapAlloc(GetProcessHeap(), 0, nDigitsCapacity * sizeof(int));\n");
    printf("    if (pDigits == NULL) {\n");
    printf("        return NULL;\n");
    printf("    }\n\n");

    printf("    // Parse timestamps into digits\n");
    printf("    for (SIZE_T i = 0; i < sNumberOfTimestamps; i++) {\n");
    printf("        const char* szLine = ppTimestampArray[i];\n");
    printf("        if (szLine == NULL || *szLine == '\\0') {\n");
    printf("            continue;\n");
    printf("        }\n\n");

    printf("        int nYear, nMonth, nDay, nHour, nMin, nSec;\n");
    printf("        if (sscanf_s(szLine, \"%%d-%%d-%%d %%d:%%d:%%d\", &nYear, &nMonth, &nDay, &nHour, &nMin, &nSec) != 6) {\n");
    printf("            continue;\n");
    printf("        }\n\n");

    printf("        int nYearHi = nYear / 100;\n");
    printf("        int nYearLo = nYear %% 100;\n\n");

    printf("        // Append in order: sec, min, hour, day, month, year_lo, year_hi\n");
    printf("        if (nNumDigits + 7 > nDigitsCapacity) {\n");
    printf("            nDigitsCapacity *= 2;\n");
    printf("            int* pNewDigits = (int*)HeapReAlloc(GetProcessHeap(), 0, pDigits, nDigitsCapacity * sizeof(int));\n");
    printf("            if (pNewDigits == NULL) {\n");
    printf("                HeapFree(GetProcessHeap(), 0, pDigits);\n");
    printf("                return NULL;\n");
    printf("            }\n");
    printf("            pDigits = pNewDigits;\n");
    printf("        }\n\n");

    printf("        pDigits[nNumDigits++] = nSec;\n");
    printf("        pDigits[nNumDigits++] = nMin;\n");
    printf("        pDigits[nNumDigits++] = nHour;\n");
    printf("        pDigits[nNumDigits++] = nDay;\n");
    printf("        pDigits[nNumDigits++] = nMonth;\n");
    printf("        pDigits[nNumDigits++] = nYearLo;\n");
    printf("        pDigits[nNumDigits++] = nYearHi;\n");
    printf("    }\n\n");

    printf("    // Convert base-100 digits back to base-256 bytes\n");
    printf("    sMaxLen = (SIZE_T)(nNumDigits * 0.85) + 10;\n");
    printf("    pNum = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sMaxLen);\n");
    printf("    if (pNum == NULL) {\n");
    printf("        HeapFree(GetProcessHeap(), 0, pDigits);\n");
    printf("        return NULL;\n");
    printf("    }\n\n");

    printf("    sCurrentLen = 0;\n\n");

    printf("    for (int i = nNumDigits - 1; i >= 0; i--) {\n");
    printf("        int nDigit = pDigits[i];\n\n");

    printf("        // Multiply current num by 100\n");
    printf("        long long llCarry = 0;\n");
    printf("        for (SIZE_T j = 0; j < sCurrentLen; j++) {\n");
    printf("            long long llTemp = (long long)pNum[j] * 100 + llCarry;\n");
    printf("            pNum[j] = (BYTE)(llTemp %% 256);\n");
    printf("            llCarry = llTemp / 256;\n");
    printf("        }\n\n");

    printf("        while (llCarry > 0) {\n");
    printf("            if (sCurrentLen >= sMaxLen) {\n");
    printf("                sMaxLen *= 2;\n");
    printf("                PBYTE pNewNum = (PBYTE)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pNum, sMaxLen);\n");
    printf("                if (pNewNum == NULL) {\n");
    printf("                    HeapFree(GetProcessHeap(), 0, pNum);\n");
    printf("                    HeapFree(GetProcessHeap(), 0, pDigits);\n");
    printf("                    return NULL;\n");
    printf("                }\n");
    printf("                pNum = pNewNum;\n");
    printf("            }\n\n");

    printf("            pNum[sCurrentLen++] = (BYTE)(llCarry %% 256);\n");
    printf("            llCarry /= 256;\n");
    printf("        }\n\n");

    printf("        // Add the current digit\n");
    printf("        llCarry = nDigit;\n");
    printf("        for (SIZE_T j = 0; j < sCurrentLen; j++) {\n");
    printf("            long long llTemp = (long long)pNum[j] + llCarry;\n");
    printf("            pNum[j] = (BYTE)(llTemp %% 256);\n");
    printf("            llCarry = llTemp / 256;\n");
    printf("            if (llCarry == 0) break;\n");
    printf("        }\n\n");

    printf("        while (llCarry > 0) {\n");
    printf("            if (sCurrentLen >= sMaxLen) {\n");
    printf("                sMaxLen *= 2;\n");
    printf("                PBYTE pNewNum = (PBYTE)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pNum, sMaxLen);\n");
    printf("                if (pNewNum == NULL) {\n");
    printf("                    HeapFree(GetProcessHeap(), 0, pNum);\n");
    printf("                    HeapFree(GetProcessHeap(), 0, pDigits);\n");
    printf("                    return NULL;\n");
    printf("                }\n");
    printf("                pNum = pNewNum;\n");
    printf("            }\n\n");

    printf("            pNum[sCurrentLen++] = (BYTE)(llCarry %% 256);\n");
    printf("            llCarry /= 256;\n");
    printf("        }\n");
    printf("    }\n\n");

    printf("    HeapFree(GetProcessHeap(), 0, pDigits);\n\n");

    printf("    // Trim leading zeros\n");
    printf("    while (sCurrentLen > 0 && pNum[sCurrentLen - 1] == 0) {\n");
    printf("        sCurrentLen--;\n");
    printf("    }\n\n");

    printf("    // Reverse to correct byte order (MSB to LSB)\n");
    printf("    for (SIZE_T i = 0; i < sCurrentLen / 2; i++) {\n");
    printf("        BYTE bTemp = pNum[i];\n");
    printf("        pNum[i] = pNum[sCurrentLen - 1 - i];\n");
    printf("        pNum[sCurrentLen - 1 - i] = bTemp;\n");
    printf("    }\n\n");

    printf("    *sDeobfuscatedShellcodeSize = sCurrentLen;\n");
    printf("    return pNum;\n");
    printf("}\n\n");
}

VOID PrintTimestampUsage() {
    printf("/* Simple snippet to see how shellcode is deobfuscated\n\n");
    printf("void PrintHex(LPCSTR szName, PBYTE pBytes, SIZE_T sSize) {\n");
    printf("    printf(\"unsigned char %%s[] = {\", szName);\n");
    printf("    for (SIZE_T i = 0; i < sSize; i++) {\n");
    printf("        if (i %% 16 == 0) {\n");
    printf("            printf(\"\\n\\t\");\n");
    printf("        }\n");
    printf("        printf(\"0x%%02X\", pBytes[i]);\n");
    printf("        if (i < sSize - 1) {\n");
    printf("            printf(\", \");\n");
    printf("        }\n");
    printf("    }\n");
    printf("    printf(\"\\n};\\n\\n\");\n");
    printf("}\n\n");
    printf("int main() {\n");
    printf("    PBYTE  pDeobfuscatedShellcode = NULL;\n");
    printf("    SIZE_T sDeobfuscatedShellcodeSize = 0;\n");
    printf("    SIZE_T sNumberOfTimestamps = 0;\n\n");
    printf("    sNumberOfTimestamps = sizeof(ppTimestampArray) / sizeof(ppTimestampArray[0]);\n");
    printf("    pDeobfuscatedShellcode = TimestampDeobfuscation(ppTimestampArray, sNumberOfTimestamps, &sDeobfuscatedShellcodeSize);\n\n");
    printf("    PrintHex(\"pDeobfuscatedShellcode\", pDeobfuscatedShellcode, sDeobfuscatedShellcodeSize);\n");
    printf("}\n");
    printf("*/\n\n");
}