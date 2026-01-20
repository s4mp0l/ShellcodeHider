#include "aes.h"
#include "Common.h"

BOOL EncryptShellcodeTinyAes(PBYTE* ppEncryptedShellcode, SIZE_T sEncryptedShellcodeSize, PBYTE pKey, PBYTE pIv) {
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, pKey, pIv);

    AES_CBC_encrypt_buffer(&ctx, *ppEncryptedShellcode, (uint32_t)sEncryptedShellcodeSize);

    return TRUE;
}