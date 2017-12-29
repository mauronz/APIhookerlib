#include "hooks.h"
#include "APIhooklib.h"
#include <stdio.h>

extern HANDLE mutex;

LPSTR make_printable(BYTE *buffer, DWORD size) {
	char buffer2[5];
	LPSTR res = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY, 4 * size + 1);
	if (res == 0) {
		printf("Error %x\n", GetLastError());
		return NULL;
	}
	int j = 0;
	for (int i = 0; i < size; i++) {
		if (isprint(buffer[i]))
			res[j++] = buffer[i];
		else {
			sprintf_s(res + j, 5, "\\x%02x", buffer[i]);
			j += 4;
		}
	}
	return res;
}

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
	printf("[ CreateFileA ] filename=%s\n", lpFileName);
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
	printf("[ CreateFileA ret]: ret_value=0x%x\n", returnValue);
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
	printf("[ CreateFileW ] filename=%S\n", lpFileName);
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
	printf("[ CreateFileW ret]: ret_value=0x%x\n", returnValue);
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
	printf("[ ReadFile ] handle=0x%x, buffer=0x%08x, n_bytes=0x%x\n", hFile, lpBuffer, nNumberOfBytesToRead);
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
	DWORD size = *lpNumberOfBytesRead < 10 ? *lpNumberOfBytesRead : 10;
	printf("[ ReadFile ret ] ret_value=0x%x, bytes_read=0x%x, first_bytes=\"%s\"\n", returnValue, *lpNumberOfBytesRead, make_printable((BYTE *)lpBuffer, size));
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
	DWORD size = nNumberOfBytesToWrite < 10 ? nNumberOfBytesToWrite : 10;
	printf("[ WriteFile ] handle=0x%x, buffer=0x%08x, n_bytes=0x%x, first_bytes=\"%s\"\n", hFile, lpBuffer, nNumberOfBytesToWrite, make_printable((BYTE *)lpBuffer, size));
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
	printf("{ WriteFile ret ] ret:value=0x%x, bytes_written=0x%x\n", returnValue, *lpNumberOfBytesWritten);
	printf("---------\n");
	ReleaseMutex(mutex);
}

VOID __stdcall before_hook_MoveFileA(
	_In_ LPCSTR lpExistingFileName,
	_In_ LPCSTR lpNewFileName
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("---------\n");
	printf("[ MoveFile ]: from=\"%s\", to=\"%s\"\n", lpExistingFileName, lpNewFileName);
	ReleaseMutex(mutex);
}

VOID __stdcall after_hook_MoveFileA(
	_In_ LPCTSTR lpExistingFileName,
	_In_ LPCTSTR lpNewFileName,
	BOOL returnValue
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("[ MoveFile ]: ret_value=0x%x\n", returnValue);
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
	printf("[ MoveFileExA ] from=\"%s\", to=\"%s\"\n", lpExistingFileName, lpNewFileName);
	ReleaseMutex(mutex);
}

VOID __stdcall after_hook_MoveFileExA(
	_In_ LPCTSTR lpExistingFileName,
	_In_ LPCTSTR lpNewFileName,
	_In_     DWORD   dwFlags,
	BOOL returnValue
) {
	WaitForSingleObject(mutex, INFINITE);
	printf("[ MoveFileExA ] ret_value=0x%x\n", returnValue);
	printf("---------\n");
	ReleaseMutex(mutex);
}

VOID __stdcall before_hook_socket(
	int af,
	int type,
	int protocol) {
	printf("---------\n");
	printf("[ socket ]\n");
}

VOID __stdcall after_hook_socket(
	int af,
	int type,
	int protocol,
	SOCKET ret_value) {
	printf("[ socket ret ] ret_value=0x%x\n", ret_value);
	printf("---------\n");
}

VOID __stdcall before_hook_connect(
	_In_ SOCKET                s,
	_In_ const struct sockaddr *name,
	_In_ int                   namelen
) {
	struct sockaddr_in *inaddr = (struct sockaddr_in *)name;
	char *ip = inet_ntoa(inaddr->sin_addr);
	printf("---------\n");
	printf("[ connect ] ip=%s port=%d\n", ip, ntohs(inaddr->sin_port));
}

VOID __stdcall before_hook_send(
	_In_       SOCKET s,
	_In_ const char   *buf,
	_In_       int    len,
	_In_       int    flags
) {
	DWORD size = len < 10 ? len : 10;
	printf("---------\n");
	printf("[ send ] size=%d, first_bytes=\"%s\"\n", len, make_printable((BYTE *)buf, size));
}

VOID __stdcall before_hook_recv(
	_In_  SOCKET s,
	_Out_ char   *buf,
	_In_  int    len,
	_In_  int    flags
) {}

int __stdcall after_hook_recv(
	_In_  SOCKET s,
	_Out_ char   *buf,
	_In_  int    len,
	_In_  int    flags,
	int retvalue
) {
	if (retvalue == SOCKET_ERROR) {
		printf("socket error %x\n", WSAGetLastError());
		return SOCKET_ERROR;
	}
	if (retvalue) {
		DWORD size = retvalue < 10 ? retvalue : 10;
		LPSTR str = make_printable((BYTE *)buf, size);
		printf("[ recv ] size=%d, first_bytes=\"%s\"\n", retvalue, str);
		printf("---------\n");
		HeapFree(GetProcessHeap(), 0, str);
		sprintf_s(buf, len, "Nope!!\r\n");
	}	
	return 8;
}