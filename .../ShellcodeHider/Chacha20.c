#include <string.h>
#include "Common.h"

// Pack 4 bytes little-endian into DWORD
static inline DWORD Pack4Le(PBYTE pb) {
    return ((DWORD)pb[0]) |
        ((DWORD)pb[1] << 8) |
        ((DWORD)pb[2] << 16) |
        ((DWORD)pb[3] << 24);
}

// ROTL 32 bits
static inline DWORD Rotl32(DWORD dwValue, int nShift) {
    return (dwValue << nShift) | (dwValue >> (32 - nShift));
}

// ChaCha20 quarter round
static inline VOID QuarterRound(PDWORD pa, PDWORD pb, PDWORD pc, PDWORD pd) {
    *pa += *pb;  *pd ^= *pa;  *pd = Rotl32(*pd, 16);
    *pc += *pd;  *pb ^= *pc;  *pb = Rotl32(*pb, 12);
    *pa += *pb;  *pd ^= *pa;  *pd = Rotl32(*pd, 8);
    *pc += *pd;  *pb ^= *pc;  *pb = Rotl32(*pb, 7);
}

// Initialize ChaCha20 context
BOOL ChaCha20Init(PCHACHA20_CTX pCtx, PBYTE pKey, PBYTE pNonce, DWORD dwCounter) {
    static const BYTE chacha20_constants[16] = "expand 32-byte k";

    // Constants
    pCtx->State[0] = Pack4Le(&chacha20_constants[0]);
    pCtx->State[1] = Pack4Le(&chacha20_constants[4]);
    pCtx->State[2] = Pack4Le(&chacha20_constants[8]);
    pCtx->State[3] = Pack4Le(&chacha20_constants[12]);

    // Key
    for (int i = 0; i < 8; i++) {
        pCtx->State[4 + i] = Pack4Le(pKey + i * 4);
    }

    // Counter
    pCtx->State[12] = dwCounter;

    // Nonce
    pCtx->State[13] = Pack4Le(pNonce + 0);
    pCtx->State[14] = Pack4Le(pNonce + 4);
    pCtx->State[15] = Pack4Le(pNonce + 8);

    return TRUE;
}

// Generate block
VOID ChaCha20Block(PCHACHA20_CTX pCtx, PBYTE pOutput) {
    DWORD WorkingState[16];

    memcpy(WorkingState, pCtx->State, sizeof(WorkingState));

    for (int i = 0; i < 10; i++) {
        // Column rounds
        QuarterRound(&WorkingState[0], &WorkingState[4], &WorkingState[8], &WorkingState[12]);
        QuarterRound(&WorkingState[1], &WorkingState[5], &WorkingState[9], &WorkingState[13]);
        QuarterRound(&WorkingState[2], &WorkingState[6], &WorkingState[10], &WorkingState[14]);
        QuarterRound(&WorkingState[3], &WorkingState[7], &WorkingState[11], &WorkingState[15]);

        // Diagonal rounds
        QuarterRound(&WorkingState[0], &WorkingState[5], &WorkingState[10], &WorkingState[15]);
        QuarterRound(&WorkingState[1], &WorkingState[6], &WorkingState[11], &WorkingState[12]);
        QuarterRound(&WorkingState[2], &WorkingState[7], &WorkingState[8], &WorkingState[13]);
        QuarterRound(&WorkingState[3], &WorkingState[4], &WorkingState[9], &WorkingState[14]);
    }

    for (int i = 0; i < 16; i++) {
        WorkingState[i] += pCtx->State[i];
    }

    memcpy(pOutput, WorkingState, CHACHA20_BLOCK_SIZE);

    // Next block
    pCtx->State[12]++;
}

// Final XOR
BOOL ChaCha20Xor(PCHACHA20_CTX pCtx, PBYTE pInput, PBYTE pOutput, SIZE_T sSize) {
    BYTE Keystream[CHACHA20_BLOCK_SIZE];
    SIZE_T sOffset = 0;

    while (sSize > 0) {
        ChaCha20Block(pCtx, Keystream);

        SIZE_T sThisBlock = (sSize > CHACHA20_BLOCK_SIZE) ? CHACHA20_BLOCK_SIZE : sSize;

        for (SIZE_T i = 0; i < sThisBlock; i++) {
            pOutput[sOffset + i] = pInput[sOffset + i] ^ Keystream[i];
        }

        sOffset += sThisBlock;
        sSize -= sThisBlock;
    }

    return TRUE;
}