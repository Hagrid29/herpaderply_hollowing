#include "lockFileUtil.h"
#include <stdio.h>
#include <windows.h>
#include <iostream>

#include "ntddk.h"
#include "ntdll_undoc.h"

#pragma warning(disable : 4996) 

// modify from https://www.x86matthew.com/view_post?id=hijack_file_handle

SYSTEM_HANDLE_INFORMATION_EX* pGlobal_SystemHandleInfo = NULL;


DWORD WINAPI GetFileHandlePathThread(LPVOID lpArg)
{
	BYTE bFileInfoBuffer[2048];
	IO_STATUS_BLOCK IoStatusBlock;
	GetFileHandlePathThreadParamStruct* pGetFileHandlePathThreadParam = NULL;
	FILE_NAME_INFORMATION* pFileNameInfo = NULL;

	// get param
	pGetFileHandlePathThreadParam = (GetFileHandlePathThreadParamStruct*)lpArg;

	// get file path from handle
	memset((void*)&IoStatusBlock, 0, sizeof(IoStatusBlock));
	memset(bFileInfoBuffer, 0, sizeof(bFileInfoBuffer));
	if (NtQueryInformationFile(pGetFileHandlePathThreadParam->hFile, &IoStatusBlock, bFileInfoBuffer, sizeof(bFileInfoBuffer), FileNameInformation) != 0)
	{
		return 1;
	}

	// get FILE_NAME_INFORMATION ptr
	pFileNameInfo = (FILE_NAME_INFORMATION*)bFileInfoBuffer;

	// validate filename length
	if (pFileNameInfo->FileNameLength >= sizeof(pGetFileHandlePathThreadParam->szPath))
	{
		return 1;
	}

	// convert file path to ansi string
	wcstombs(pGetFileHandlePathThreadParam->szPath, pFileNameInfo->FileName, sizeof(pGetFileHandlePathThreadParam->szPath) - 1);

	return 0;
}


DWORD GetSystemHandleList()
{
	DWORD dwAllocSize = 0;
	DWORD dwStatus = 0;
	DWORD dwLength = 0;
	BYTE* pSystemHandleInfoBuffer = NULL;

	// free previous handle info list (if one exists)
	if (pGlobal_SystemHandleInfo != NULL)
	{
		free(pGlobal_SystemHandleInfo);
	}

	// get system handle list
	dwAllocSize = 0;
	for (;;)
	{
		if (pSystemHandleInfoBuffer != NULL)
		{
			// free previous inadequately sized buffer
			free(pSystemHandleInfoBuffer);
			pSystemHandleInfoBuffer = NULL;
		}

		if (dwAllocSize != 0)
		{
			// allocate new buffer
			pSystemHandleInfoBuffer = (BYTE*)malloc(dwAllocSize);
			if (pSystemHandleInfoBuffer == NULL)
			{
				return 1;
			}
		}

		// get system handle list
		dwStatus = NtQuerySystemInformation(64, (void*)pSystemHandleInfoBuffer, dwAllocSize, &dwLength);
		if (dwStatus == 0)
		{
			// success
			break;
		}
		else if (dwStatus == STATUS_INFO_LENGTH_MISMATCH)
		{
			// not enough space - allocate a larger buffer and try again (also add an extra 1kb to allow for additional handles created between checks)
			dwAllocSize = (dwLength + 1024);
		}
		else
		{
			// other error
			free(pSystemHandleInfoBuffer);
			return 1;
		}
	}

	// store handle info ptr
	pGlobal_SystemHandleInfo = (SYSTEM_HANDLE_INFORMATION_EX*)pSystemHandleInfoBuffer;

	return 0;
}


HANDLE CopyFileHandle(HANDLE hProcess, const char* pTargetFileName, bool releaseFile) {
	HANDLE hClonedFileHandle = NULL;
	DWORD dwFileHandleObjectType = 0;
	DWORD dwThreadExitCode = 0;
	DWORD dwThreadID = 0;
	HANDLE hThread = NULL;
	GetFileHandlePathThreadParamStruct GetFileHandlePathThreadParam;
	char* pLastSlash = NULL;
	DWORD dwCount = 0;


	// suspend target process
	if (NtSuspendProcess(hProcess) != 0)
	{
		printf("[X] failed to suspend process");
		NtResumeProcess(hProcess);
		CloseHandle(hProcess);
		return NULL;

	}


	printf("[+] Getting system handle list\n");
	// get system handle list
	if (GetSystemHandleList() != 0)
	{
		printf("[X] failed to get system handle list\n");
		NtResumeProcess(hProcess);
		CloseHandle(hProcess);
		return NULL;
	}


	for (DWORD i = 0; i < pGlobal_SystemHandleInfo->NumberOfHandles; i++)
	{
		// ensure this handle is a file handle object
		if (pGlobal_SystemHandleInfo->HandleList[i].ObjectTypeIndex != dwFileHandleObjectType)
		{
			continue;
		}


		// clone file handle
		if (DuplicateHandle(hProcess, (HANDLE)pGlobal_SystemHandleInfo->HandleList[i].HandleValue, GetCurrentProcess(), &hClonedFileHandle, 0, 0, DUPLICATE_SAME_ACCESS) == 0)
		{
			continue;
		}

		// get the file path of the current handle - do this in a new thread to prevent deadlocks
		memset((void*)&GetFileHandlePathThreadParam, 0, sizeof(GetFileHandlePathThreadParam));
		GetFileHandlePathThreadParam.hFile = hClonedFileHandle;
		hThread = CreateThread(NULL, 0, GetFileHandlePathThread, (void*)&GetFileHandlePathThreadParam, 0, &dwThreadID);
		if (hThread == NULL)
		{
			CloseHandle(hClonedFileHandle);
			continue;
		}

		// wait for thread to finish (1 second timeout)
		if (WaitForSingleObject(hThread, 1000) != WAIT_OBJECT_0)
		{
			// time-out - kill thread
			TerminateThread(hThread, 1);
			CloseHandle(hThread);
			CloseHandle(hClonedFileHandle);
			continue;
		}

		// close cloned file handle
		CloseHandle(hClonedFileHandle);

		// check exit code of temporary thread
		GetExitCodeThread(hThread, &dwThreadExitCode);
		if (dwThreadExitCode != 0)
		{
			// failed
			CloseHandle(hThread);
			continue;
		}

		// close thread handle
		CloseHandle(hThread);

		// get last slash in path
		pLastSlash = strrchr(GetFileHandlePathThreadParam.szPath, '\\');
		if (pLastSlash == NULL)
		{
			continue;
		}

		// check if this is the target filename
		pLastSlash++;
		//if (stricmp(pLastSlash, pTargetFileName) != 0)
		if (stricmp(pLastSlash, pTargetFileName) != 0)
		{
			continue;
		}

		printf("[+] Found remote file handle of \"%s\"\n", GetFileHandlePathThreadParam.szPath);
		dwCount++;


		printf("[+] Duplicating file handle to current process\n");
		HANDLE hTargetFile;
		if (!DuplicateHandle(hProcess, (HANDLE)pGlobal_SystemHandleInfo->HandleList[i].HandleValue, GetCurrentProcess(), &hTargetFile, 0, 0, DUPLICATE_SAME_ACCESS)) {
			printf("[X] Handle failed (%d)\n", GetLastError());
		}

		//release file handle on remote process, so can remove file
		if (releaseFile) {
			HANDLE hTmp;
			printf("[+] Releasing the file handle. You can manually remove the file\n");
			if (!DuplicateHandle(hProcess, (HANDLE)pGlobal_SystemHandleInfo->HandleList[i].HandleValue, GetCurrentProcess(), &hTmp, 0, 0, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS)) {
				printf("[X] Handle failed (%d)\n", GetLastError());
			}
		}

		return hTargetFile;

	}


	// ensure at least one matching file handle was found
	if (dwCount == 0)
	{
		printf("[X] No matching file handles found\n");
		CloseHandle(hProcess);

		return NULL;
	}

	return NULL;
}

void ClearContent(HANDLE hTargetFile) {

	// overwrite the payload
	printf("[+] Overwriting file content\n");

	// replace with whitespace
	const char* data = "\x0A";
	DWORD dwTargetAux, dwTargetOriginalSize, dwTargetFileSize = GetFileSize(hTargetFile, &dwTargetAux) - 4;
	DWORD bytesRemaining = dwTargetFileSize - sizeof(data);

	SetFilePointer(hTargetFile, 0, NULL, 0);
	while (bytesRemaining > sizeof(data)) {
		DWORD bytesWritten;
		WriteFile(hTargetFile, data, sizeof(data), &bytesWritten, NULL);
		SetFilePointer(hTargetFile, 0, NULL, 1);
		bytesRemaining = bytesRemaining - bytesWritten;
	}


	return;
}




