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
	APIhooklib::set_hook("ws2_32.dll", "socket", 3, (FARPROC)before_hook_socket, (FARPROC)after_hook_socket, TRUE, FALSE);
	APIhooklib::set_hook("ws2_32.dll", "connect", 3, (FARPROC)before_hook_connect, NULL, TRUE, FALSE);
	APIhooklib::set_hook("ws2_32.dll", "send", 4, (FARPROC)before_hook_send, NULL, TRUE, FALSE);
	APIhooklib::set_hook("ws2_32.dll", "recv", 4, NULL, (FARPROC)after_hook_recv, TRUE, TRUE);

	mutex = CreateMutexA(NULL, FALSE, NULL);

	CHAR *cmdline = GetCommandLineA();
	CHAR *cmdline2 = strchr(cmdline, ' ') + 2;
	strcpy(cmdline, cmdline2);

	APIhooklib::run_loaded_executable(loaded_pe);
}