#pragma once

#include <stdio.h>
#include <windows.h>
#include <iostream>

#include "ntddk.h"
#include "ntdll_undoc.h"


struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	ULONG Object;
	ULONG UniqueProcessId;
	ULONG HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	ULONG Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX HandleList[1];
};


struct GetFileHandlePathThreadParamStruct
{
	HANDLE hFile;
	char szPath[512];
};


HANDLE CopyFileHandle(HANDLE hProcess, const char* pTargetFileName, bool releaseFile);

void ClearContent(HANDLE hTargetFile);


