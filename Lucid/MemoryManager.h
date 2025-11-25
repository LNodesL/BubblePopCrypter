#pragma once
#include <windows.h>
#include <winternl.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);
typedef NTSTATUS (NTAPI *PFN_NtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType);

/* new */
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

class MemoryManager {
private:
    PFN_NtAllocateVirtualMemory pNtAllocateVirtualMemory;
    PFN_NtFreeVirtualMemory pNtFreeVirtualMemory;

public:
    MemoryManager();
    void* AllocateMemory(SIZE_T size);
    void* AllocateMemory(void* preferredBaseAddress, SIZE_T size, DWORD initialProtection); // New method signature
    bool FreeMemory(void* address);
    void RevertCodeSectionProtection(void* baseAddress, SIZE_T size, DWORD initialProtection);
};
