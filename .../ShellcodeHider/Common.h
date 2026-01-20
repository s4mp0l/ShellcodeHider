#pragma once

#include <windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/*
    AES Encryption
*/

// BCrypt
#define AES_KEY_SIZE    32
#define AES_IV_SIZE     16

BOOL EncryptShellcodeBCrypt(PBYTE pPlaintext, SIZE_T  sPlaintextSize, PBYTE* ppCiphertext, SIZE_T* psCiphertextSize, PBYTE pKey, PBYTE pIv);

// TinyAes
#define CBC     1
#define AES256  1

BOOL EncryptShellcodeTinyAes(PBYTE* ppEncryptedShellcode, SIZE_T sEncryptedShellcodeSize, PBYTE pKey, PBYTE pIv);

/*
    ChaCha20 Encryption
*/

#define CHACHA20_KEY_SIZE     32
#define CHACHA20_NONCE_SIZE   12
#define CHACHA20_BLOCK_SIZE   64
#define CHACHA20_KEY_SIZE     32
#define CHACHA20_NONCE_SIZE   12

typedef struct _CHACHA20_CTX {
    DWORD State[16];
} CHACHA20_CTX, * PCHACHA20_CTX;

BOOL ChaCha20Init(PCHACHA20_CTX pCtx, PBYTE pKey, PBYTE pNonce, DWORD dwCounter);

VOID ChaCha20Block(PCHACHA20_CTX pCtx, PBYTE pOutput);

BOOL ChaCha20Xor(PCHACHA20_CTX pCtx, PBYTE pInput, PBYTE pOutput, SIZE_T sSize);

/*
    Rc4 Encryption
*/

// Custom Rc4
#define RC4_KEY_SIZE    16

typedef struct _RC4_CTX {
    DWORD  i;
    DWORD  j;
    BYTE    S[256];
} RC4_CTX, * PRC4_CTX;

BOOL Rc4Initialize(PRC4_CTX pCtx, LPCBYTE pKey, SIZE_T sKeySize);

BOOL Rc4Crypt(PRC4_CTX pCtx, LPCBYTE pInput, PBYTE pOutput, SIZE_T sSize);

// SystemFunction033
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define RC4_KEY_SIZE    16

// reference: https://doxygen.reactos.org/da/dab/structustring.html
typedef struct _USTRING {
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;
} USTRING, * PUSTRING;

// reference: https://doxygen.reactos.org/df/d13/sysfunc_8c.html#a66d55017b8625d505bd6c5707bdb9725
typedef NTSTATUS(NTAPI* fnSystemFunction033)(
    PUSTRING    pData,
    PUSTRING    pKey
    );

BOOL Rc4SystemFunction033(PBYTE pShellcode, SIZE_T sShellcodeSize, LPCBYTE pKey, SIZE_T sKeySize);

/*
    Xor Encryption
*/

#define XOR_KEY_SIZE 16

BOOL XorEncrypt(PBYTE pShellcode, SIZE_T sShellcodeSize, PBYTE pKey, size_t sKeySize);

/*
    IPv4 Obfuscation
*/

typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(
    PCSTR		S,
    BOOLEAN		Strict,
    PCSTR* Terminator,
    PVOID		Addr
    );

BOOL IPv4Obfuscation(PBYTE pShellcode, SIZE_T sShellcodeSize, char** ppIPv4Array, SIZE_T sNumberOfIPv4);

/*
    IPv6 Obfuscation
*/

typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
    PCSTR		S,
    PCSTR* Terminator,
    PVOID		Addr
    );

BOOL IPv6Obfuscation(PBYTE pShellcode, SIZE_T sShellcodeSize, char** ppIPv6Array, SIZE_T sNumberOfIPv6);

/*
    Mac Obfuscation
*/

typedef NTSTATUS(NTAPI* fnRtlEthernetStringToAddressA)(
    PCSTR       S,
    PCSTR* Terminator,
    PVOID       Addr
    );

BOOL MacObfuscation(PBYTE pShellcode, SIZE_T sShellcodeSize, char** ppMacArray, SIZE_T sNumberOfMacs);

/*
    Uuid Obfuscation
*/

typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
    RPC_CSTR    StringUuid,
    UUID* Uuid
    );

BOOL UuidObfuscation(PBYTE pShellcode, SIZE_T sShellcodeSize, char** ppUuidArray, SIZE_T sNumberOfUuids);

/*
    Timestamp Obfuscation
*/

char** TimestampObfuscation(PBYTE   pShellcode, SIZE_T  sShellcodeSize, SIZE_T* sNumberOfTimestamps);

/*
    Output
*/

VOID PrintBCryptAesDecryptionRoutine();
VOID PrintBCryptAesUsage();

VOID PrintTinyAesDecryptionRoutine();
VOID PrintTinyAesUsage();

VOID PrintChaCha20DecryptionRoutine();
VOID PrintChacha20Usage();

VOID PrintRc4DecryptionRoutine();
VOID PrintRc4Usage();

VOID PrintSystemFunction033DecryptionRoutine();
VOID PrintRc4SystemFunction033Usage();

VOID PrintXorDecryptionRoutine();
VOID PrintXorUsage();

VOID PrintIPv4DeobfuscationRoutine();
VOID PrintIPv4Usage();

VOID PrintIPv6DeobfuscationRoutine();
VOID PrintIPv6Usage();

VOID PrintMacDeobfuscationRoutine();
VOID PrintMacUsage();

VOID PrintUuidDeobfuscationRoutine();
VOID PrintUuidUsage();

VOID PrintTimestampDeobfuscationRoutine();
VOID PrintTimestampUsage();

/*
    Methods / Languages / Outputs
*/

typedef enum {
    MethodAesBCrypt,
    MethodTinyAes,
    MethodChaCha20,
    MethodRc4,
    MethodRc4SystemFunction033,
    MethodXor,
    MethodIPv4,
    MethodIPv6,
    MethodMac,
    MethodUuid,
    MethodTimestamp,
    MethodUnknown
} MethodType;

/*
typedef enum {
    OutputEncryptedShellcode,
    OutputDecryptionRoutine,
    OutputUnknown
} OutputType;
*/

/*
typedef enum {
    LangC,
    LangCSharp,
    LangPython,
    LangRust,
    LangGolang,
    LangPowerShell,
    LangVba,
    LangJava,
    LangRuby,
    LangJava,
    LangUnknown
} LanguageType;
*/