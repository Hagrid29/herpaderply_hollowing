#pragma once

#include <Windows.h>
#include "ntddk.h"
#include "ntdll_types.h"

#define HANDLE_DETACHED_PROCESS   (HANDLE)-1
#define HANDLE_CREATE_NEW_CONSOLE   (HANDLE)-2
#define HANDLE_CREATE_NO_WINDOW   (HANDLE)-3

#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)

//Functions:
extern NTSTATUS(NTAPI* NtCreateProcessEx)
(
    OUT PHANDLE     ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
    IN HANDLE   ParentProcess,
    IN ULONG    Flags,
    IN HANDLE SectionHandle     OPTIONAL,
    IN HANDLE DebugPort     OPTIONAL,
    IN HANDLE ExceptionPort     OPTIONAL,
    IN BOOLEAN  InJob
    );

extern NTSTATUS(NTAPI* RtlCreateProcessParametersEx)(
    _Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
    );

extern NTSTATUS(NTAPI* NtCreateThreadEx) (
    OUT  PHANDLE ThreadHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN  HANDLE ProcessHandle,
    IN  PVOID StartRoutine,
    IN  PVOID Argument OPTIONAL,
    IN  ULONG CreateFlags,
    IN  ULONG_PTR ZeroBits,
    IN  SIZE_T StackSize OPTIONAL,
    IN  SIZE_T MaximumStackSize OPTIONAL,
    IN  PVOID AttributeList OPTIONAL
    );

extern NTSTATUS(NTAPI* NtQueryInformationFile)
(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass
    );

extern NTSTATUS(NTAPI* NtQuerySystemInformation)
(
    //IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN unsigned long SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength
    );

extern NTSTATUS(NTAPI* NtSuspendProcess)
(
    IN HANDLE ProcessHandle
    );

extern NTSTATUS(NTAPI* NtResumeProcess)
(
    IN HANDLE ProcessHandle
    );

// Initialization function:

bool init_ntdll_func();
