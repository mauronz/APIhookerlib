#include <Windows.h>
#include <stdio.h>
#include <winsock.h>
#include "hooks.h"
#include "APIhooklib.h"

#pragma comment(lib, "Ws2_32.lib")

HANDLE mutex;

int main(int argc, char **argv) {

	if (argc < 2) {
		printf("Not enough arguments.\nUsage: %s program_path [program_args]");
		return 1;
	}

	LPSTR path = argv[1];
	BYTE *loaded_pe = APIhooklib::load_executable(path);
	if (!loaded_pe)
		return 1;
	APIhooklib::set_hook("kernel32.dll", "CreateFileA", 7, (FARPROC)before_hook_CreateFileA, (FARPROC)after_hook_CreateFileA, TRUE, FALSE);
	APIhooklib::set_hook("kernel32.dll", "CreateFileW", 7, (FARPROC)before_hook_CreateFileW, (FARPROC)after_hook_CreateFileW, TRUE, FALSE);
	APIhooklib::set_hook("kernel32.dll", "WriteFile", 5, (FARPROC)before_hook_WriteFile, (FARPROC)after_hook_WriteFile, TRUE, FALSE);
	APIhooklib::set_hook("kernel32.dll", "ReadFile", 5, (FARPROC)before_hook_ReadFile, (FARPROC)after_hook_ReadFile, TRUE, FALSE);
	APIhooklib::set_hook("kernel32.dll", "MoveFileA", 2, (FARPROC)before_hook_MoveFileA, (FARPROC)after_hook_MoveFileA, TRUE, FALSE);
	APIhooklib::set_hook("kernel32.dll", "MoveFileExA", 3, (FARPROC)before_hook_MoveFileExA, (FARPROC)after_hook_MoveFileExA, TRUE, FALSE);

	mutex = CreateMutexA(NULL, FALSE, NULL);

	CHAR *cmdline = GetCommandLineA();
	CHAR *cmdline2 = strchr(cmdline, ' ') + 2;
	strcpy_s(cmdline, strlen(cmdline), cmdline2);

	APIhooklib::run_loaded_executable(loaded_pe);
}