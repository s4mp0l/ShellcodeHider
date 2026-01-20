#include <windows.h>
#include <stdio.h>

int PrintHelp(char* _Argv0) {
    printf("\n");
    printf("   _____ _          _ _               _      _    _ _     _           \n");
    printf("  / ____| |        | | |             | |    | |  | (_)   | |          \n");
    printf(" | (___ | |__   ___| | | ___ ___   __| | ___| |__| |_  __| | ___ _ __ \n");
    printf("  \\___ \\| '_ \\ / _ \\ | |/ __/ _ \\ / _` |/ _ \\  __  | |/ _` |/ _ \\ '__|\n");
    printf("  ____) | | | |  __/ | | (_| (_) | (_| |  __/ |  | | | (_| |  __/ |   \n");
    printf(" |_____/|_| |_|\\___|_|_|\\___\\___/ \\__,_|\\___|_|  |_|_|\\__,_|\\___|_|   \n");
    printf("                                                                      \n");
    printf("                                                                      \n\n");
    printf("[+] Developed by @s4mp0l\n");
    printf("[i] Github: https://github.com/s4mp0l/ShellcodeHider\n");
    printf("[i] If you are interested in malware: https://github.com/s4mp0l/Malware-Development\n\n");

    printf("[!] Usage: %s -f <shellcode.bin> -m <encryption/obfuscation method>\n\n", _Argv0);
    printf("[i] Example[1]: %s -f shellcode.bin -m bcrypt-aes -o encrypted_output.bin\n", _Argv0);
    printf("[i] Example[2]: %s -f shellcode.bin -m ipv4\n\n", _Argv0);

    printf("[i] Supported methods:\n");
    printf("\t{ aes-bcrypt, tinyaes, chacha20, rc4, systemfunction033, xor, ipv4, ipv6, mac, uuid, timestamp }\n\n");

    printf("ShellcodeHider Usage:\n");
    printf("\t[ -f ] Filename: Your shellcode in raw format (eg shellcode.bin)\n");
    printf("\t[ -m ] Method: Encryption/Obfuscation method (eg xor, rc4, ipv4, uuid)\n");
    printf("\t[ -o ] Output: Name of the file in which the shellcode will be written - Optional (eg encrypted_output.bin)\n");
    
    printf("\n");

    return 1;
}

BOOL ReadShellcodeFile(LPCSTR szShellcodeFileName, PBYTE* ppShellcode, SIZE_T* pszShellcodeSize) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD  dwFileSize = 0;
    DWORD  lpNumberOfBytesRead = 0;
    PBYTE  pShellcodeFromFile = 0;

    hFile = CreateFileA(szShellcodeFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE || hFile == 0) {
        printf("[!] CreateFileA failed with error code: %lu\n", GetLastError());
        return FALSE;
    }

    dwFileSize = GetFileSize(hFile, NULL);

    if (dwFileSize == 0) {
        printf("[!] GetFileSize failed with error code: %lu\n", GetLastError());
        return FALSE;
    }

    pShellcodeFromFile = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwFileSize);

    if (pShellcodeFromFile == NULL) {
        printf("[!] Memory allocation failed\n");
        return FALSE;
    }

    ZeroMemory(pShellcodeFromFile, dwFileSize);

    if (!ReadFile(hFile, pShellcodeFromFile, dwFileSize, &lpNumberOfBytesRead, NULL)) {
        printf("[!] ReadFile failed with error code: %lu\n", GetLastError());
        return FALSE;
    }

    // save values
    *ppShellcode = pShellcodeFromFile;
    *pszShellcodeSize = lpNumberOfBytesRead;

    if (!CloseHandle(hFile)) {
        printf("[!] CloseHandle failed with error code: %lu\n", GetLastError());
    }

    if (*ppShellcode == NULL || *pszShellcodeSize == 0)
        return FALSE;

    return TRUE;
}

BOOL CreateShellcodeFile(LPCSTR szFile, PBYTE pShellcode, SIZE_T sShellcodeSize) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD  dwBytesWritten = 0;

    // Create file
    hFile = CreateFileA(szFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileA failed with error code: %lu\n", GetLastError());
        return FALSE;
    }

    // Write shellcode
    if (!WriteFile(hFile, pShellcode, (DWORD)sShellcodeSize, &dwBytesWritten, NULL)) {
        printf("[!] WriteFile failed: %lu\n", GetLastError());
        return FALSE;
    }

    if (dwBytesWritten != (DWORD)sShellcodeSize) {
        printf("[!] Incomplete write\n");
        return FALSE;
    }

    CloseHandle(hFile);

    return TRUE;
}

BOOL PadShellcode(INT MultipleOf, PBYTE pShellcode, SIZE_T sShellcodeSize, OUT PBYTE* ppPaddedShellcode, SIZE_T* psPaddedShellcodeSize) {
    PBYTE  pPadded = NULL;
    SIZE_T sPaddedSize = 0;

    if (MultipleOf == 0 || pShellcode == NULL || sShellcodeSize == 0 || ppPaddedShellcode == NULL) {
        return FALSE;
    }

    // calculating new size and allocating memory
    sPaddedSize = ((sShellcodeSize + MultipleOf - 1) / MultipleOf) * MultipleOf;
    pPadded = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPaddedSize);

    if (pPadded == NULL) {
        return FALSE;
    }

    // copy shellcode
    memcpy_s(pPadded, sPaddedSize, pShellcode, sShellcodeSize);

    // saving
    *ppPaddedShellcode     = pPadded;
    *psPaddedShellcodeSize = sPaddedSize;

    return TRUE;
}

VOID GenerateRandomKey(PBYTE pKey, SIZE_T sKeySize) {
    for (size_t i = 0; i < sKeySize; i++) {
        pKey[i] = rand() % 256;
    }
}

// pretty print byte array in C format
VOID PrintHex(LPCSTR szName, PBYTE pBytes, SIZE_T sSize) {
    printf("unsigned char %s[] = {", szName);
    for (SIZE_T i = 0; i < sSize; i++) {
        if (i % 16 == 0) {
            printf("\n\t");
        }
        printf("0x%02X", pBytes[i]);
        if (i < sSize - 1) {
            printf(", ");
        }
    }
    printf("\n};\n\n");
}

VOID PrintIPv4Array(LPCSTR szName, PBYTE* ppIPv4Array, SIZE_T sSize) {
    printf("unsigned char* %s[%zu] = {\n\t", szName, sSize);

    for (SIZE_T i = 0; i < sSize; i++) {
        if (i == sSize - 1) {
            printf("\"%s\"\n", ppIPv4Array[i]);
        }
        else {
            printf("\"%s\", ", ppIPv4Array[i]);
        }

        if ((i + 1) % 8 == 0 && i != sSize - 1) {
            printf("\n\t");
        }
    }

    printf("};\n\n");
}

VOID PrintIPv6Array(LPCSTR szName, PBYTE* ppIPv6Array, SIZE_T sSize) {
    printf("unsigned char* %s[%zu] = {\n\t", szName, sSize);

    for (SIZE_T i = 0; i < sSize; i++) {
        if (i == sSize - 1) {
            printf("\"%s\"\n", ppIPv6Array[i]);
        }
        else {
            printf("\"%s\", ", ppIPv6Array[i]);
        }

        if ((i + 1) % 8 == 0 && i != sSize - 1) {
            printf("\n\t");
        }
    }

    printf("};\n\n");
}

VOID PrintMacArray(LPCSTR szName, char** ppArray, SIZE_T sCount) {
    printf("unsigned char* %s[%zu] = {\n\t", szName, sCount);

    for (SIZE_T i = 0; i < sCount; i++) {
        if (i == sCount - 1) {
            printf("\"%s\"\n", ppArray[i]);
        }
        else {
            printf("\"%s\", ", ppArray[i]);
        }

        if ((i + 1) % 4 == 0 && i != sCount - 1) {
            printf("\n\t");
        }
    }

    printf("};\n\n");
}

VOID PrintUuidArray(LPCSTR szName, char** ppArray, SIZE_T sCount) {
    printf("unsigned char* %s[%zu] = {\n\t", szName, sCount);

    for (SIZE_T i = 0; i < sCount; i++) {
        if (i == sCount - 1) {
            printf("\"%s\"\n", ppArray[i]);
        }
        else {
            printf("\"%s\", ", ppArray[i]);
        }

        if ((i + 1) % 4 == 0 && i != sCount - 1) {
            printf("\n\t");
        }
    }

    printf("};\n\n");
}

VOID PrintTimestampArray(LPCSTR szName, char** ppArray, SIZE_T sCount) {
    printf("unsigned char* %s[%zu] = {\n\t", szName, sCount);

    for (SIZE_T i = 0; i < sCount; i++) {
        if (i == sCount - 1) {
            printf("\"%s\"\n", ppArray[i]);
        }
        else {
            printf("\"%s\", ", ppArray[i]);
        }

        if ((i + 1) % 4 == 0 && i != sCount - 1) {
            printf("\n\t");
        }
    }

    printf("};\n\n");
}