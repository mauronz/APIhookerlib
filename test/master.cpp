#include <Windows.h>
#include <stdio.h>

#include "hooks.h"
#include "APIhooklib.h"

HANDLE mutex;

int main(int argc, char **argv) {
	//comment

	LPSTR path = argv[1];
	BYTE *loaded_pe = APIhooklib::load_executable(path);
	if (!loaded_pe)
		return 1;
	APIhooklib::set_hook("kernel32.dll", "CreateFileA", 7, (FARPROC)before_hook_CreateFileA, (FARPROC)after_hook_CreateFileA, TRUE);
	APIhooklib::set_hook("kernel32.dll", "CreateFileW", 7, (FARPROC)before_hook_CreateFileW, (FARPROC)after_hook_CreateFileW, TRUE);
	//APIhooklib::set_hook("kernel32.dll", "WriteFile", 5, (FARPROC)before_hook_WriteFile, NULL, FALSE);
	APIhooklib::set_hook("kernel32.dll", "WriteFile", 5, (FARPROC)before_hook_WriteFile, (FARPROC)after_hook_WriteFile, TRUE);
	APIhooklib::set_hook("kernel32.dll", "ReadFile", 5, (FARPROC)before_hook_ReadFile, (FARPROC)after_hook_ReadFile, TRUE);
	APIhooklib::set_hook("kernel32.dll", "ReadFile", 5, (FARPROC)before_hook_ReadFile, (FARPROC)after_hook_ReadFile, TRUE);
	APIhooklib::set_hook("kernel32.dll", "MoveFileA", 2, (FARPROC)before_hook_MoveFileA, (FARPROC)after_hook_MoveFileA, TRUE);
	APIhooklib::set_hook("kernel32.dll", "MoveFileExA", 3, (FARPROC)before_hook_MoveFileExA, (FARPROC)after_hook_MoveFileExA, TRUE);

	mutex = CreateMutexA(NULL, FALSE, NULL);

	APIhooklib::run_loaded_executable(loaded_pe);
}