#include <Windows.h>
#include <stdio.h>

#include "peconv.h"
#include "hook_engine.h"
#include "APIhooklib.h"

using namespace APIhooklib;

FARPROC APIhooklib::set_hook(LPSTR dll_name, LPSTR func_name, DWORD n_args, FARPROC before_hook, FARPROC after_hook, BOOL do_call) {
	LPVOID original = VirtualAlloc(NULL, 25, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	DWORD length, size, offset, tmp;

	BYTE head[] = "\x55\x89\xE5";  // push ebp; mov ebp, esp
	BYTE push_param[] = "\x8B\x45X\x50";  // mov eax, [ebp+X]; push eax
	BYTE call_func[] = "\xE8XXXX"; // call XXXX
	BYTE end[] = "\x89\xEC\x5D\xC2XX"; // mov esp,ebp; pop ebp; ret XX

	size = 3 + 6;
	if (before_hook)
		size += 4 * n_args + 5;
	if (do_call)
		size += 4 * n_args + 5;
	if (after_hook)
		size += 4 * n_args + 5 + 1 + 2;
	offset = 0;
	tmp = n_args * 4;
	memcpy(end + 4, &tmp, 2);

	LPBYTE stub = (LPBYTE)VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// fill stub with NOPs
	memset(stub, 0x90, size);


	memcpy(stub, head, 3);
	offset += 3;

	if (before_hook) {
		// Push params for before-hook
		for (int i = n_args - 1; i >= 0; i--) {
			push_param[2] = (BYTE)(i * 4 + 8);
			memcpy(stub + offset, push_param, 4);
			offset += 4;
		}

		// Call before-hook
		DWORD tmp = (DWORD)before_hook - ((DWORD)stub + offset) - 5;
		memcpy(call_func + 1, &tmp, 4);
		memcpy(stub + offset, call_func, 5);
		offset += 5;
	}
	
	if (do_call) {
		// Push params for function
		for (int i = n_args - 1; i >= 0; i--) {
			push_param[2] = (BYTE)(i * 4 + 8);
			memcpy(stub + offset, push_param, 4);
			offset += 4;
		}

		// Call fuction
		tmp = (DWORD)original - ((DWORD)stub + offset) - 5;
		memcpy(call_func + 1, &tmp, 4);
		memcpy(stub + offset, call_func, 5);
		offset += 5;
	}
	
	if (after_hook) {
		// Push return value to save it for later (push eax)
		stub[offset] = 0x50;
		offset++;

		// Push return value to pass it as parameter of after-hook
		stub[offset] = 0x50;
		offset++;

		// Push params for after-hook
		for (int i = n_args - 1; i >= 0; i--) {
			push_param[2] = (BYTE)(i * 4 + 8);
			memcpy(stub + offset, push_param, 4);
			offset += 4;
		}

		// Call after-hook
		tmp = (DWORD)after_hook - ((DWORD)stub + offset) - 5;
		memcpy(call_func + 1, &tmp, 4);
		memcpy(stub + offset, call_func, 5);
		offset += 5;

		// Pop return value from stack (pop eax)
		stub[offset] = 0x58;
		offset++;
	}

	memcpy(stub + offset, end, 6);
	offset += 6;

	HookFunction(dll_name, func_name, stub, original, &length);

	return (FARPROC)original;
}

PBYTE APIhooklib::load_executable(LPSTR path) {
	size_t v_size = 0;
	PBYTE loaded_pe = peconv::load_pe_executable(path, v_size, NULL);
	return loaded_pe;
}

VOID APIhooklib::run_loaded_executable(BYTE *loaded_pe) {
	ULONGLONG ep_exp_offset = (ULONGLONG)loaded_pe + peconv::get_entry_point_rva(loaded_pe);
	DWORD(*entrypoint)() = (DWORD(*)()) (ep_exp_offset);
	entrypoint();
}