#include "hooks.h"
#include "APIhooklib.h"
#include <stdio.h>

extern HANDLE mutex;

VOID __stdcall before_hook_CreateFileA(
	_In_     LPCSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("---------\n");
	printf("CreateFileA: %s\n", lpFileName);
	ReleaseMutex(mutex);
}

VOID __stdcall after_hook_CreateFileA(
	_In_     LPCSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile,
	HANDLE returnValue
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("Return value of CreateFileA: 0x%x\n", returnValue);
	printf("---------\n");
	ReleaseMutex(mutex);
}

VOID __stdcall before_hook_CreateFileW(
	_In_     LPWSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("---------\n");
	printf("CreateFileW: %S\n", lpFileName);
	ReleaseMutex(mutex);
}

VOID __stdcall after_hook_CreateFileW(
	_In_     LPWSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile,
	HANDLE returnValue
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("Return value of CreateFileW: 0x%x\n", returnValue);
	printf("---------\n");
	ReleaseMutex(mutex);
}

VOID __stdcall before_hook_ReadFile(
	_In_        HANDLE       hFile,
	_Out_       LPVOID       lpBuffer,
	_In_        DWORD        nNumberOfBytesToRead,
	_Out_opt_   LPDWORD      lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("---------\n");
	printf("ReadFile: handle=0x%x, buffer=0x%08x, n_bytes=0x%x\n", hFile, lpBuffer, nNumberOfBytesToRead);
	ReleaseMutex(mutex);
}

VOID __stdcall after_hook_ReadFile(
	_In_        HANDLE       hFile,
	_Out_       LPVOID       lpBuffer,
	_In_        DWORD        nNumberOfBytesToRead,
	_Out_opt_   LPDWORD      lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped,
	BOOL returnValue
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("Return value of ReadFile: 0x%x, bytes_read=0x%x\n", returnValue, *lpNumberOfBytesRead);
	printf("---------\n");
	ReleaseMutex(mutex);
}

VOID __stdcall before_hook_WriteFile(
	_In_        HANDLE       hFile,
	_In_        LPCVOID      lpBuffer,
	_In_        DWORD        nNumberOfBytesToWrite,
	_Out_opt_   LPDWORD      lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
) {
	if (hFile == GetStdHandle(STD_OUTPUT_HANDLE)) return;
	WaitForSingleObject(mutex, INFINITE);
	printf("---------\n");
	printf("WriteFile: handle=0x%x, buffer=0x%08x, n_bytes=0x%x\n", hFile, lpBuffer, nNumberOfBytesToWrite);
	ReleaseMutex(mutex);
}

VOID __stdcall after_hook_WriteFile(
	_In_        HANDLE       hFile,
	_In_        LPCVOID      lpBuffer,
	_In_        DWORD        nNumberOfBytesToWrite,
	_Out_opt_   LPDWORD      lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped,
	BOOL returnValue
) {
	if (hFile == GetStdHandle(STD_OUTPUT_HANDLE)) return;
	WaitForSingleObject(mutex, INFINITE);
	printf("Return value of WriteFile: 0x%x, bytes_written=0x%x\n", returnValue, *lpNumberOfBytesWritten);
	printf("---------\n");
	ReleaseMutex(mutex);
}

VOID __stdcall before_hook_MoveFileA(
	_In_ LPCSTR lpExistingFileName,
	_In_ LPCSTR lpNewFileName
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("---------\n");
	printf("MoveFile: from=\"%s\", to=\"%s\"\n", lpExistingFileName, lpNewFileName);
	ReleaseMutex(mutex);
}

VOID __stdcall after_hook_MoveFileA(
	_In_ LPCTSTR lpExistingFileName,
	_In_ LPCTSTR lpNewFileName,
	BOOL returnValue
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("Return value of MoveFile: 0x%x\n", returnValue);
	printf("---------\n");
	ReleaseMutex(mutex);
}

VOID __stdcall before_hook_MoveFileExA(
	_In_ LPCSTR lpExistingFileName,
	_In_ LPCSTR lpNewFileName,
	_In_     DWORD   dwFlags
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("---------\n");
	printf("MoveFileExA: from=\"%s\", to=\"%s\"\n", lpExistingFileName, lpNewFileName);
	ReleaseMutex(mutex);
}

VOID __stdcall after_hook_MoveFileExA(
	_In_ LPCTSTR lpExistingFileName,
	_In_ LPCTSTR lpNewFileName,
	_In_     DWORD   dwFlags,
	BOOL returnValue
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("Return value of MoveFileExA: 0x%x\n", returnValue);
	printf("---------\n");
	ReleaseMutex(mutex);
}