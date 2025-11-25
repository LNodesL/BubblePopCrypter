#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>

#define DEREF_32(name) *(DWORD_PTR *)(name)

void CreateProgramHeader(const PVOID vpointer, const DWORD size, const char* headerFileName) {
    std::ofstream headerFile(headerFileName, std::ios::out);
    if (!headerFile) {
        printf("Could not open header file for writing.\n");
        return;
    }

    headerFile << "#ifndef PROGRAM_H\n#define PROGRAM_H\n\n";
    headerFile << "unsigned char programData[] = {";
    for (DWORD i = 0; i < size; ++i) {
        if (i > 0) {
            headerFile << ", ";
        }
        if (i % 12 == 0) headerFile << "\n";
        headerFile << "0x" << std::hex << ((unsigned int)((unsigned char*)vpointer)[i]);
    }
    headerFile << "\n};\nunsigned int programDataSize = " << std::dec << size << ";\n";
    headerFile << "#endif // PROGRAM_H\n";

    printf("Program data saved to header file.\n");
}

int main() {
    char file[255];
    HANDLE handle;
    PVOID vpointer;
    DWORD size;
    DWORD byteread;

    printf("Enter file name: ");
    scanf("%s", file);

    handle = CreateFile(file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        printf("Error opening file.\n");
        return 1;
    }

    size = GetFileSize(handle, NULL);
    vpointer = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (!ReadFile(handle, vpointer, size, &byteread, NULL) || byteread != size) {
        printf("Error reading file.\n");
        CloseHandle(handle);
        return 1;
    }
    CloseHandle(handle);

    // Serialize the executable data to the program header file
    CreateProgramHeader(vpointer, size, "Program.h");
    VirtualFree(vpointer, 0, MEM_RELEASE);

    return 0;
}
