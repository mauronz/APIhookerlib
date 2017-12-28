#include <Windows.h>

namespace APIhooklib {
	/*
	Set hooks for an API. Other than the dll and API names, the number of arguments is required.
	There are two types of hook, one that is executed before the API, and one immediately after it.
	It is possible to set only one or both the hooks (if the parameter is NULL the hook will not be set).
	IMPORTANT: Both functions MUST be __stdcall. 
	before_hook has the same prototype of the API, while after_hook has as additional last parameter the return value of the API.
	If do_call=TRUE, the API is called, otherwise it is bypassed. Note that if do_call=FALSE, the return value
	of the last executed hook will be returned to the caller.
	*/
	extern "C" FARPROC __declspec(dllexport) __cdecl set_hook(
		LPSTR dll_name, 
		LPSTR func_name, 
		DWORD n_args, 
		FARPROC before_hook, 
		FARPROC after_hook,
		BOOL do_call);

	extern "C" BOOL __declspec(dllexport) __cdecl remove_hook(LPSTR dll_name, LPSTR func_name);

	/*
	Load a PE file in memory (see libpeconv for more details).
	*/
	extern "C" PBYTE __declspec(dllexport) __cdecl load_executable(LPSTR path);

	/*
	Start execution of a previously loaded executable from its entrypoint.
	*/
	extern "C" VOID __declspec(dllexport) __cdecl run_loaded_executable(BYTE *loaded_pe);
}