#include "MemoryManager.h"
#include <iostream>
#include "skCrypter.h"

typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);
    
// Function to parse the export table and get function addresses
void* GetFunctionAddress(PVOID baseAddress, const char* functionName) {
    auto dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)baseAddress + dosHeader->e_lfanew);

    auto exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)baseAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto functions = (PDWORD)((PBYTE)baseAddress + exportDirectory->AddressOfFunctions);
    auto names = (PDWORD)((PBYTE)baseAddress + exportDirectory->AddressOfNames);
    auto ordinals = (PWORD)((PBYTE)baseAddress + exportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        const char* exportName = (const char*)baseAddress + names[i];
        if (_stricmp(exportName, functionName) == 0) {
            DWORD functionRVA = functions[ordinals[i]];
            return (PBYTE)baseAddress + functionRVA;
        }
    }
    return nullptr;
}

// Helper function to read a UNICODE_STRING from memory
std::wstring ReadUnicodeString(const UNICODE_STRING& unicodeString) {
    return std::wstring(unicodeString.Buffer, unicodeString.Length / sizeof(WCHAR));
}

MemoryManager::MemoryManager() {
    HMODULE ntdll = LoadLibraryW(skCrypt(L"ntdll.dll"));
    if (!ntdll) {
        // std::cerr << "Failed to load ntdll.dll." << std::endl;
        return;
    }

    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, skCrypt("NtQueryInformationProcess"));
    if (!NtQueryInformationProcess) {
        // std::cerr << "Failed to get NtQueryInformationProcess address." << std::endl;
        return;
    }

    HANDLE processHandle = GetCurrentProcess();
    PROCESS_BASIC_INFORMATION pbi;
    ZeroMemory(&pbi, sizeof(pbi));

    NTSTATUS status = NtQueryInformationProcess(processHandle, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
    if (status != 0) {
        // std::cerr << "Failed to get process information." << std::endl;
        return;
    }

    PEB* peb = pbi.PebBaseAddress;
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* moduleList = &ldr->InMemoryOrderModuleList;

    for (LIST_ENTRY* entry = moduleList->Flink; entry != moduleList; entry = entry->Flink) {
        LDR_DATA_TABLE_ENTRY* moduleEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        std::wstring dllName = ReadUnicodeString(moduleEntry->FullDllName);

        if (dllName.find(skCrypt(L"ntdll.dll")) != std::wstring::npos) {
            auto dllBase = moduleEntry->DllBase;
            pNtAllocateVirtualMemory = reinterpret_cast<PFN_NtAllocateVirtualMemory>(GetFunctionAddress(dllBase, skCrypt("NtAllocateVirtualMemory")));
            pNtFreeVirtualMemory = reinterpret_cast<PFN_NtFreeVirtualMemory>(GetFunctionAddress(dllBase, skCrypt("NtFreeVirtualMemory")));
            if (!pNtAllocateVirtualMemory || !pNtFreeVirtualMemory) {
                // std::cerr << "Failed to get addresses of Nt functions." << std::endl;
                return;
            }
            break;
        }
    }
    FreeLibrary(ntdll);
}

void* MemoryManager::AllocateMemory(void* preferredBaseAddress, SIZE_T size, DWORD initialProtection) {
    if (!pNtAllocateVirtualMemory) {
        // std::cerr << skCrypt("NtAllocateVirtualMemory function not loaded.") << std::endl;
        return nullptr;
    }

    PVOID baseAddress = preferredBaseAddress;
    SIZE_T regionSize = size;
    NTSTATUS status = pNtAllocateVirtualMemory(
        GetCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        initialProtection); // Use the initialProtection parameter

    if (status != STATUS_SUCCESS) {
        // std::cerr << skCrypt("Failed to allocate memory.") << std::endl;
        return nullptr;
    }

    return baseAddress;
}


void MemoryManager::RevertCodeSectionProtection(void* baseAddress, SIZE_T size, DWORD initialProtection) {
    DWORD oldProtection;
    if (!VirtualProtect(baseAddress, size, initialProtection, &oldProtection)) {
        // std::cerr << skCrypt("Failed to revert code section protection.") << std::endl;
        // Handle error
    }
}



bool MemoryManager::FreeMemory(void* address) {
    if (!pNtFreeVirtualMemory) {
        // std::cerr << skCrypt("NtFreeVirtualMemory function not loaded.") << std::endl;
        return false;
    }

    PVOID baseAddress = address;
    SIZE_T regionSize = 0; // Size is ignored with MEM_RELEASE
    NTSTATUS status = pNtFreeVirtualMemory(
        GetCurrentProcess(),
        &baseAddress,
        &regionSize,
        MEM_RELEASE);

    return status == STATUS_SUCCESS;
}
