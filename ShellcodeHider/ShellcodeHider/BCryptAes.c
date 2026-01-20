#include <windows.h>﻿
#include <stdio.h>
#include <bcrypt.h>
#include "Common.h"

#pragma comment(lib, "bcrypt.lib")

/*
    Encrypt and Decrypt using BCrypt AES-256-CBC
*/

BOOL EncryptShellcodeBCrypt(
    PBYTE   pPlaintext,
    SIZE_T  sPlaintextSize,
    PBYTE* ppCiphertext,
    SIZE_T* psCiphertextSize,
    PBYTE   pKey,
    PBYTE   pIv
) {
    BCRYPT_ALG_HANDLE   hAlg = NULL;
    BCRYPT_KEY_HANDLE   hKey = NULL;
    NTSTATUS            ntStatus = 0;
    DWORD               cbKeyObj = 0;
    DWORD               cbData = 0;
    DWORD               cbCipher = 0;
    PBYTE               pbKeyObject = NULL;
    PBYTE               pbIvWorking = NULL;
    BOOL                bSuccess = FALSE;

    ntStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);

    if (!NT_SUCCESS(ntStatus)) {
        printf("[!] BCryptOpenAlgorithmProvider failed with NTSTATUS: 0x%08X\n", ntStatus);
        goto Cleanup;
    }

    ntStatus = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    if (!NT_SUCCESS(ntStatus)) {
        printf("[!] BCryptSetProperty failed with NTSTATUS: 0x%08X\n", ntStatus);
        goto Cleanup;
    }

    // Get key object size
    ntStatus = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(DWORD), &cbData, 0);

    if (!NT_SUCCESS(ntStatus)) {
        printf("[!] BCryptGetProperty failed with NTSTATUS: 0x%08X\n", ntStatus);
        goto Cleanup;
    }

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);

    if (!pbKeyObject) {
        printf("[!] Memory allocation failed\n");
        goto Cleanup;
    }

    ntStatus = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObj, pKey, AES_KEY_SIZE, 0);

    if (!NT_SUCCESS(ntStatus)) {
        printf("[!] BCryptGenerateSymmetricKey failed with NTSTATUS: 0x%08X\n", ntStatus);
        goto Cleanup;
    }

    // we have to do a fresh IV copy because BCryptEncrypt overwrites the IV buffer with the last encrypted block.
    // reference: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt
    pbIvWorking = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AES_IV_SIZE);

    if (!pbIvWorking) {
        printf("[!] Memory allocation failed\n");
        goto Cleanup;
    }

    memcpy(pbIvWorking, pIv, AES_IV_SIZE);

    // Get required output size
    ntStatus = BCryptEncrypt(hKey, pPlaintext, (ULONG)sPlaintextSize, NULL, pbIvWorking, AES_IV_SIZE, NULL, 0, &cbCipher, 0);

    if (!NT_SUCCESS(ntStatus)) {
        printf("[!] BCryptEncrypt[1] failed with NTSTATUS: 0x%08X\n", ntStatus);
        goto Cleanup;
    }

    *ppCiphertext = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipher);

    if (!*ppCiphertext) {
        printf("[!] Memory allocation failed\n");
        goto Cleanup;
    }

    // Reset IV before real encryption
    memcpy(pbIvWorking, pIv, AES_IV_SIZE);

    ntStatus = BCryptEncrypt(hKey, pPlaintext, (ULONG)sPlaintextSize, NULL, pbIvWorking, AES_IV_SIZE, *ppCiphertext, cbCipher, &cbData, 0);

    if (!NT_SUCCESS(ntStatus)) {
        printf("[!] BCryptEncrypt[2] failed with NTSTATUS: 0x%08X\n", ntStatus);
        goto Cleanup;
    }

    *psCiphertextSize = cbCipher;

    bSuccess = TRUE;

Cleanup:
    if (hKey)        BCryptDestroyKey(hKey);
    if (hAlg)        BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbIvWorking) HeapFree(GetProcessHeap(), 0, pbIvWorking);

    if (!bSuccess && *ppCiphertext) {
        HeapFree(GetProcessHeap(), 0, *ppCiphertext);
        *ppCiphertext = NULL;
    }

    return bSuccess;
}