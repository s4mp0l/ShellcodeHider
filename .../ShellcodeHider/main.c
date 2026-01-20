#include "Utils.h"
#include "Common.h"
#include "getopt.h"

int main(int argc, char* argv[]) {
    /*
        Parsing arguments
    */

    // Default argument values
    LPCSTR       szShellcodeFileName = NULL;
    LPCSTR       szOutputFileName    = NULL;
    MethodType   Method              = MethodUnknown;
    INT          Opt                 = 0;

    // Parse arguments
    while ((Opt = getopt(argc, argv, "f:m:o::")) != -1) {
        switch (Opt) {

        case 'f':
            szShellcodeFileName = optarg;
            break;

        case 'm':
            if (strcmp(optarg, "aes-bcrypt") == 0) Method = MethodAesBCrypt;
            else if (strcmp(optarg, "tinyaes") == 0) Method = MethodTinyAes;
            else if (strcmp(optarg, "chacha20") == 0) Method = MethodChaCha20;
            else if (strcmp(optarg, "rc4") == 0) Method = MethodRc4;
            else if (strcmp(optarg, "systemfunction033") == 0) Method = MethodRc4SystemFunction033;
            else if (strcmp(optarg, "xor") == 0) Method = MethodXor;
            else if (strcmp(optarg, "ipv4") == 0) Method = MethodIPv4;
            else if (strcmp(optarg, "ipv6") == 0) Method = MethodIPv6;
            else if (strcmp(optarg, "mac") == 0) Method = MethodMac;
            else if (strcmp(optarg, "uuid") == 0) Method = MethodUuid;
            else if (strcmp(optarg, "timestamp") == 0) Method = MethodTimestamp;

            else {
                PrintHelp(argv[0]);
                printf("[!] Unknown method: %s\n\n", optarg);
                return 1;
            }

            break;

        case 'o':
            if (optarg != NULL) {
                PrintHelp(argv[0]);
                return 1;
            }

            else if (optind < argc && argv[optind][0] != '-') {
                // spaced arg like -o output.bin (and not another flag)
                szOutputFileName = argv[optind];
                optind++;  // skip this arg for next getopt calls
            }

            break;

        default:
            PrintHelp(argv[0]);
        }
    }

    // Print help
    if (szShellcodeFileName == NULL && Method == MethodUnknown && szOutputFileName) {
        PrintHelp(argv[0]);
        return 1;
    }

    // Check missing flags
    if (szShellcodeFileName == NULL || Method == MethodUnknown) {
        PrintHelp(argv[0]);
        return 1;
    }
    
    /*
        Initializing values
    */

    // Initializing shellcode and shellcode size
    PBYTE  pShellcode = NULL;
    SIZE_T sShellcodeSize = 0;

    // Read shellcode
    if (!ReadShellcodeFile(szShellcodeFileName, &pShellcode, &sShellcodeSize)) {
        printf("[!] Error trying to read the file\n");
        return 1;
    }

    // Initializing padded shellcode and padded shellcode size
    PBYTE  pPaddedShellcode = NULL;
    SIZE_T sPaddedShellcodeSize = 0;

    // Initializing encrypted shellcode and encrypted shellcode size
    PBYTE  pEncryptedShellcode = NULL;
    SIZE_T sEncryptedShellcodeSize = 0;

    // Initializing necessary values for Obfuscation Methods
    char** ppIPv4Array         = NULL;
    SIZE_T sNumberOfIPv4       = 0;

    char** ppIPv6Array         = NULL;
    SIZE_T sNumberOfIPv6       = 0;
    
    char** ppMacArray          = NULL;
    SIZE_T sNumberOfMacs       = 0;

    char** ppUuidArray         = NULL;
    SIZE_T sNumberOfUuids      = 0;

    char** ppTimestampArray    = NULL;
    SIZE_T sNumberOfTimestamps = 0;

    /*
        Encryption methods.

        Currently supported:
            - AES (BCrypt and TinyAes)
            - ChaCha20
            - Rc4 (Custom and SystemFunction033)
            - Xor 
    */

    // AesBCrypt (AES Encryption)
    if (Method == MethodAesBCrypt) {
        if (sShellcodeSize % 16 != 0) {
            if (!PadShellcode(16, pShellcode, sShellcodeSize, &pPaddedShellcode, &sPaddedShellcodeSize)) {
                return -1;
            }
        }

        // Key && IV
        BYTE    pKey[AES_KEY_SIZE] = { 0 };
        BYTE    pIv[AES_IV_SIZE]   = { 0 };

        // Generate random key
        srand((unsigned int)time(NULL));
        GenerateRandomKey(pKey, AES_KEY_SIZE);
        GenerateRandomKey(pIv, AES_IV_SIZE);

        if (!EncryptShellcodeBCrypt(pPaddedShellcode, sPaddedShellcodeSize, &pEncryptedShellcode, &sEncryptedShellcodeSize, pKey, pIv)) {
            printf("[!] Encryption failed\n");
            goto Cleanup;
        }

        printf("[+] Here is all you need to perform Aes Encryption using BCrypt library:\n\n");

        PrintBCryptAesDecryptionRoutine();
        PrintHex("pEncryptedShellcode", pEncryptedShellcode, sEncryptedShellcodeSize);
        PrintHex("pKey", pKey, AES_KEY_SIZE);
        PrintHex("pIv", pIv, AES_IV_SIZE);
        PrintBCryptAesUsage();

        if (szOutputFileName) {
            if (!CreateShellcodeFile(szOutputFileName, pEncryptedShellcode, sEncryptedShellcodeSize)) {
                printf("[!] CreateShellcodeFile failed\n");
                return 1;
            }
        }
    }

    // TinyAes (AES Encryption)
    if (Method == MethodTinyAes) {
        if (sShellcodeSize % 16 != 0) {
            if (!PadShellcode(16, pShellcode, sShellcodeSize, &pPaddedShellcode, &sPaddedShellcodeSize)) {
                return -1;
            }
        }

        // Key && IV
        BYTE    pKey[AES_KEY_SIZE] = { 0 };
        BYTE    pIv[AES_IV_SIZE]   = { 0 };

        // Generate random key
        srand((unsigned int)time(NULL));
        GenerateRandomKey(pKey, AES_KEY_SIZE);
        GenerateRandomKey(pIv, AES_IV_SIZE);

        if (!EncryptShellcodeTinyAes(&pPaddedShellcode, sPaddedShellcodeSize, pKey, pIv)) {
            printf("[!] Error trying to encrypt the shellcode\n");
            goto Cleanup;
        }

        printf("[+] Here is all you need to perform Aes Encryption using TinyAes:\n");
        printf("[i] Don't forget to download aes.c and aes.h in your project: https://github.com/kokke/tiny-AES-c\n\n");

        PrintTinyAesDecryptionRoutine();
        PrintHex("pEncryptedShellcode", pPaddedShellcode, sPaddedShellcodeSize);
        PrintHex("pKey", pKey, AES_KEY_SIZE);
        PrintHex("pIv", pIv, AES_IV_SIZE);
        PrintTinyAesUsage();

        if (szOutputFileName) {
            if (!CreateShellcodeFile(szOutputFileName, pPaddedShellcode, sPaddedShellcodeSize)) {
                printf("[!] CreateShellcodeFile failed\n");
                return 1;
            }
        }
    }

    // ChaCha20 Encryption
    if (Method == MethodChaCha20) {
        // ChaCha20 Context
        CHACHA20_CTX    ctx = { 0 };
        
        // Key && Nonce
        BYTE            pKey[CHACHA20_KEY_SIZE]     = { 0 };
        BYTE            pNonce[CHACHA20_NONCE_SIZE] = { 0 };

        // Generate random key
        srand((unsigned int)time(NULL));
        GenerateRandomKey(pKey, CHACHA20_KEY_SIZE);
        GenerateRandomKey(pNonce, CHACHA20_NONCE_SIZE);

        // Memory allocation
        pEncryptedShellcode = HeapAlloc(GetProcessHeap(), 0, sShellcodeSize);

        if (!ChaCha20Init(&ctx, pKey, pNonce, 1)) {
            printf("[!] ChaCha20 Initialization failed\n");
            goto Cleanup;
        }

        if (!ChaCha20Xor(&ctx, pShellcode, pEncryptedShellcode, sShellcodeSize)) {
            printf("[!] ChaCha20 Xor operation failed\n");
            goto Cleanup;
        }

        printf("[+] Here is all you need to perform ChaCha20 Encryption:\n\n");

        PrintChaCha20DecryptionRoutine();
        PrintHex("pEncryptedShellcode", pEncryptedShellcode, sShellcodeSize);
        PrintHex("pKey", pKey, CHACHA20_KEY_SIZE);
        PrintHex("pNonce", pNonce, CHACHA20_NONCE_SIZE);
        PrintChacha20Usage();

        if (szOutputFileName) {
            if (!CreateShellcodeFile(szOutputFileName, pEncryptedShellcode, sShellcodeSize)) {
                printf("[!] CreateShellcodeFile failed\n");
                return 1;
            }
        }
    }

    // Rc4 Encryption
    if (Method == MethodRc4) {
        // Rc4 Context
        RC4_CTX     ctx = { 0 };
    
        // Rc4 Key
        BYTE        pKey[RC4_KEY_SIZE] = { 0 };
    
        // Generate random key
        srand((unsigned int)time(NULL));
        GenerateRandomKey(pKey, RC4_KEY_SIZE);

        // Memory allocation
        pEncryptedShellcode = HeapAlloc(GetProcessHeap(), 0, sShellcodeSize);

        if (!Rc4Initialize(&ctx, pKey, RC4_KEY_SIZE)) {
            printf("[!] Rc4 Initialization failed\n");
            goto Cleanup;
        }

        if (!Rc4Crypt(&ctx, pShellcode, pEncryptedShellcode, sShellcodeSize)) {
            printf("[!] Rc4Crypt failed\n");
            goto Cleanup;
        }

        printf("[+] Here is all you need to perform Rc4 Encryption:\n\n");

        PrintRc4DecryptionRoutine();
        PrintHex("pEncryptedShellcode", pEncryptedShellcode, sShellcodeSize);
        PrintHex("pKey", pKey, RC4_KEY_SIZE);
        PrintRc4Usage();

        if (szOutputFileName) {
            if (!CreateShellcodeFile(szOutputFileName, pEncryptedShellcode, sShellcodeSize)) {
                printf("[!] CreateShellcodeFile failed\n");
                return 1;
            }
        }
    }

    // Rc4 Encryption via SystemFunction033
    if (Method == MethodRc4SystemFunction033) {
        // Rc4 Key
        BYTE    pKey[RC4_KEY_SIZE] = { 0 };
    
        // Generate random key
        srand((unsigned int)time(NULL));
        GenerateRandomKey(pKey, RC4_KEY_SIZE);

        if (!Rc4SystemFunction033(pShellcode, sShellcodeSize, pKey, RC4_KEY_SIZE)) {
            printf("[!] Encryption failed\n");
            goto Cleanup;
        }

        printf("[+] Here is all you need to perform Rc4 Encryption using SystemFunction033:\n\n");

        PrintSystemFunction033DecryptionRoutine();
        PrintHex("pShellcode", pShellcode, sShellcodeSize);
        PrintHex("pKey", pKey, RC4_KEY_SIZE);
        PrintRc4SystemFunction033Usage();

        if (szOutputFileName) {
            if (!CreateShellcodeFile(szOutputFileName, pShellcode, sShellcodeSize)) {
                printf("[!] CreateShellcodeFile failed\n");
                return 1;
            }
        }
    }

    // Xor Encryption
    if (Method == MethodXor) {
        // Xor Key
        BYTE   pKey[XOR_KEY_SIZE] = { 0 };

        // Generate random key
        srand((unsigned int)time(NULL));
        GenerateRandomKey(pKey, XOR_KEY_SIZE);

        if (!XorEncrypt(pShellcode, sShellcodeSize, pKey, XOR_KEY_SIZE)) {
            printf("[!] Encryption failed\n");
            goto Cleanup;
        }

        printf("[+] Here is all you need to perform Xor Encryption:\n\n");

        PrintXorDecryptionRoutine();
        PrintHex("pShellcode", pShellcode, sShellcodeSize);
        PrintHex("pKey", pKey, XOR_KEY_SIZE);
        PrintXorUsage();

        if (szOutputFileName) {
            if (!CreateShellcodeFile(szOutputFileName, pShellcode, sShellcodeSize)) {
                printf("[!] CreateShellcodeFile failed\n");
                return 1;
            }
        }
    }

    /*
        Obfuscation methods.

        Currently supported:
            - IPv4 Address
            - IPv6 Address
            - Mac Address
            - UUID format
            - Timestamp format
    */

    // IPv4 Obfuscation
    if (Method == MethodIPv4) {
        sNumberOfIPv4 = (sShellcodeSize + 3) / 4;

        ppIPv4Array = (char**)calloc(sNumberOfIPv4, sizeof(char*));

        if (ppIPv4Array == NULL) {
            printf("[!] Memory allocation failed\n");
            goto Cleanup;
        }

        if (!IPv4Obfuscation(pShellcode, sShellcodeSize, ppIPv4Array, sNumberOfIPv4)) {
            printf("[!] Obfuscation failed\n");
            goto Cleanup;
        }

        printf("[+] Here is all you need to perform IPv4 Obfuscation:\n\n");

        PrintIPv4DeobfuscationRoutine();
        PrintIPv4Array("ppIPv4Array", ppIPv4Array, sNumberOfIPv4);
        PrintIPv4Usage();
    }

    // IPv6 Obfuscation
    if (Method == MethodIPv6) {
        sNumberOfIPv6 = (sShellcodeSize + 15) / 16;

        ppIPv6Array = (char**)calloc(sNumberOfIPv6, sizeof(char*));

        if (ppIPv6Array == NULL) {
            printf("[!] Memory allocation failed\n");
            goto Cleanup;
        }

        if (!IPv6Obfuscation(pShellcode, sShellcodeSize, ppIPv6Array, sNumberOfIPv6)) {
            printf("[!] Obfuscation failed\n");
            goto Cleanup;
        }

        printf("[+] Here is all you need to perform IPv6 Obfuscation:\n\n");

        PrintIPv6DeobfuscationRoutine();
        PrintIPv6Array("ppIPv6Array", ppIPv6Array, sNumberOfIPv6);
        PrintIPv6Usage();
    }

    // Mac Obfuscation
    if (Method == MethodMac) {
        sNumberOfMacs = (sShellcodeSize + 5) / 6;
        ppMacArray = (char**)calloc(sNumberOfMacs, sizeof(char*));

        if (ppMacArray == NULL) {
            printf("[!] Memory allocation failed\n");
            goto Cleanup;
        }

        if (!MacObfuscation(pShellcode, sShellcodeSize, ppMacArray, sNumberOfMacs)) {
            printf("[!] Obfuscation failed\n");
            goto Cleanup;
        }

        printf("[+] Here is all you need to perform Mac Obfuscation:\n\n");

        PrintMacDeobfuscationRoutine();
        PrintMacArray("ppMacArray", ppMacArray, sNumberOfMacs);
        PrintMacUsage();
    }

    // Uuid Obfuscation
    if (Method == MethodUuid) {
        sNumberOfUuids = (sShellcodeSize + 15) / 16;
        ppUuidArray = (char**)calloc(sNumberOfUuids, sizeof(char*));

        if (ppUuidArray == NULL) {
            printf("[!] Memory allocation failed\n");
            goto Cleanup;
        }

        if (!UuidObfuscation(pShellcode, sShellcodeSize, ppUuidArray, sNumberOfUuids)) {
            printf("[!] UUID obfuscation failed\n");
            goto Cleanup;
        }

        printf("[+] Here is all you need to perform Uuid Obfuscation:\n\n");

        PrintUuidDeobfuscationRoutine();
        PrintUuidArray("ppUuidArray", ppUuidArray, sNumberOfUuids);
        PrintUuidUsage();
    }

    // Timestamp Obfuscation
    if (Method == MethodTimestamp) {
        ppTimestampArray = TimestampObfuscation(pShellcode, sShellcodeSize, &sNumberOfTimestamps);

        if (ppTimestampArray == NULL) {
            printf("[!] Timestamp obfuscation failed\n");
            goto Cleanup;
        }
        printf("[+] Here is all you need to perform Timestamp Obfuscation:\n\n");

        PrintTimestampDeobfuscationRoutine();
        PrintTimestampArray("ppTimestampArray", ppTimestampArray, sNumberOfTimestamps);
        PrintTimestampUsage();
    }

Cleanup:
    // Obfuscation buffers
    if (ppIPv4Array) {

        for (SIZE_T i = 0; i < sNumberOfIPv4; i++) {

            if (ppIPv4Array[i]) {
                free(ppIPv4Array[i]);
                ppIPv4Array[i] = NULL;
            }
        }

        free(ppIPv4Array);
    }

    if (ppIPv6Array) {

        for (SIZE_T i = 0; i < sNumberOfIPv6; i++) {

            if (ppIPv6Array[i]) {
                free(ppIPv6Array[i]);
                ppIPv6Array[i] = NULL;
            }
        }

        free(ppIPv6Array);
    }

    if (ppMacArray) {

        for (SIZE_T i = 0; i < sNumberOfMacs; i++) {

            if (ppMacArray[i]) {
                free(ppMacArray[i]);
                ppMacArray[i] = NULL;
            }
        }

        free(ppMacArray);
    }

    if (ppUuidArray) {

        for (SIZE_T i = 0; i < sNumberOfUuids; i++) {

            if (ppUuidArray[i]) {
                free(ppUuidArray[i]);
                ppUuidArray[i] = NULL;
            }
        }

        free(ppUuidArray);
    }

    if (ppTimestampArray) {

        for (SIZE_T i = 0; i < sNumberOfTimestamps; i++) {

            if (ppTimestampArray[i]) {
                HeapFree(GetProcessHeap(), 0, ppTimestampArray[i]);
                ppTimestampArray[i] = NULL;
            }
        }

        HeapFree(GetProcessHeap(), 0, ppTimestampArray);
    }

    // Shellcode buffers
    if (pShellcode) free(pShellcode);
    if (pPaddedShellcode) free(pPaddedShellcode);
    if (pEncryptedShellcode) HeapFree(GetProcessHeap(), 0, pEncryptedShellcode);

    return 0;
}
