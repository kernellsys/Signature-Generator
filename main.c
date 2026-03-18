#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

void ApplySignature(const char* source, const char* target) {
    HANDLE hSrc = CreateFileA(source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hDst = CreateFileA(target, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    if (hSrc == INVALID_HANDLE_VALUE || hDst == INVALID_HANDLE_VALUE) {
        if (hSrc != INVALID_HANDLE_VALUE) CloseHandle(hSrc);
        if (hDst != INVALID_HANDLE_VALUE) CloseHandle(hDst);
        return;
    }

    IMAGE_DOS_HEADER dosH;
    DWORD read;
    if (!ReadFile(hSrc, &dosH, sizeof(dosH), &read, NULL)) return;

    SetFilePointer(hSrc, dosH.e_lfanew, NULL, FILE_BEGIN);
    IMAGE_NT_HEADERS64 ntH;
    ReadFile(hSrc, &ntH, sizeof(ntH), &read, NULL);

    DWORD sigRVA = ntH.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    DWORD sigSize = ntH.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

    if (sigRVA != 0 && sigSize > 0) {
        void* sigBuf = malloc(sigSize);
        SetFilePointer(hSrc, sigRVA, NULL, FILE_BEGIN);
        ReadFile(hSrc, sigBuf, sigSize, &read, NULL);

        DWORD fileEnd = SetFilePointer(hDst, 0, NULL, FILE_END);
        DWORD written;
        WriteFile(hDst, sigBuf, sigSize, &written, NULL);

        IMAGE_DOS_HEADER dDosH;
        SetFilePointer(hDst, 0, NULL, FILE_BEGIN);
        ReadFile(hDst, &dDosH, sizeof(dDosH), &read, NULL);

        SetFilePointer(hDst, dDosH.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), NULL, FILE_BEGIN);
        WORD magic;
        ReadFile(hDst, &magic, sizeof(magic), &read, NULL);

        DWORD offset;
        if (magic == 0x20B) offset = offsetof(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]);
        else offset = offsetof(IMAGE_NT_HEADERS32, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]);

        IMAGE_DATA_DIRECTORY newDir = { fileEnd, sigSize };
        SetFilePointer(hDst, dDosH.e_lfanew + offset, NULL, FILE_BEGIN);
        WriteFile(hDst, &newDir, sizeof(newDir), &written, NULL);
        free(sigBuf);
    }
    CloseHandle(hSrc);
    CloseHandle(hDst);
}

int main(int argc, char* argv[]) {
    char sysPath[MAX_PATH];
    GetSystemDirectoryA(sysPath, MAX_PATH);
    strcat(sysPath, "\\kernel32.dll");
    ApplySignature(sysPath, argv[1]);
    
    printf(" > Assinatura Aplicada");

    Sleep(2000);
    return 0;
}
