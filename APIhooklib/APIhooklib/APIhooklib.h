#include <Windows.h>

extern "C" BOOL __declspec(dllexport) __cdecl set_hook(LPSTR dll_name, LPSTR func_name, DWORD n_args, FARPROC before_hook, FARPROC after_hook);
extern "C" PBYTE __declspec(dllexport) __cdecl load_executable(LPSTR path);
extern "C" VOID __declspec(dllexport) __cdecl run_loaded_executable(BYTE *loaded_pe);