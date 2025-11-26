#include <stdio.h>
#include "Lucid/MemoryManager.h"
#include "Lucid/Helpers.cpp"
#include "Program.h"

int main(int argc, char* argv[]) {

    char *mem = NULL;
    mem = (char *) malloc(100000000);
    if (mem != NULL) {
        memset(mem, 00, 100000000);
        free(mem);
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)programData;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(programData + dosHeader->e_lfanew);
        MemoryManager memMgr;
        PVOID baseAddress = memMgr.AllocateMemory((void*)ntHeaders->OptionalHeader.ImageBase, ntHeaders->OptionalHeader.SizeOfImage, PAGE_READWRITE);
        if (!baseAddress) {
            baseAddress = memMgr.AllocateMemory(nullptr, ntHeaders->OptionalHeader.SizeOfImage, PAGE_READWRITE);
            if (!baseAddress) {
                return 1;
            }
        }
        memcpy(baseAddress, programData, ntHeaders->OptionalHeader.SizeOfHeaders);
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            PVOID sectionDestination = (PBYTE)baseAddress + sectionHeader[i].VirtualAddress;
            memcpy(sectionDestination, programData + sectionHeader[i].PointerToRawData, sectionHeader[i].SizeOfRawData);
        }
        if (baseAddress != (PVOID)ntHeaders->OptionalHeader.ImageBase) {
            PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)baseAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            while (relocation->VirtualAddress) {
                if (relocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                    int count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    WORD* relocItem = (WORD*)((LPBYTE)relocation + sizeof(IMAGE_BASE_RELOCATION));
                    for (int i = 0; i < count; i++) {
                        if (relocItem[i] >> 12 == IMAGE_REL_BASED_DIR64) {
                            ULONGLONG* patchAddrHL = (ULONGLONG*)((LPBYTE)baseAddress + relocation->VirtualAddress + (relocItem[i] & 0xFFF));
                            *patchAddrHL += ((ULONGLONG)baseAddress - ntHeaders->OptionalHeader.ImageBase);
                        }
                    }
                }
                relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
            }
        }
        ProcessImportTable(baseAddress);
        LPVOID entryPoint = (PBYTE)baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint;
         memMgr.RevertCodeSectionProtection(baseAddress, ntHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
        ((void (*)(void))entryPoint)();
        memMgr.RevertCodeSectionProtection(baseAddress, ntHeaders->OptionalHeader.SizeOfImage, PAGE_READWRITE);
    }

    

    return 0;
}

