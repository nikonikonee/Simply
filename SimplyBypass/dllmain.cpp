#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "hooks.hpp"

namespace {

using NtCreateThreadEx_t = LONG (NTAPI*)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

using NtWaitForSingleObject_t = LONG (NTAPI*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
using NtClose_t = LONG (NTAPI*)(HANDLE);

// hides the install thread from the debugger so simply's loop never sees its CREATE/EXIT
constexpr ULONG kHideFromDebugger = 0x00000004;

DWORD WINAPI install_hooks_thunk(LPVOID) {
    simply::bypass::install_hooks();
    return 0;
}

bool run_install_thread() {
    auto* ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    auto nt_create = reinterpret_cast<NtCreateThreadEx_t>(
        GetProcAddress(ntdll, "NtCreateThreadEx"));
    auto nt_wait = reinterpret_cast<NtWaitForSingleObject_t>(
        GetProcAddress(ntdll, "NtWaitForSingleObject"));
    auto nt_close = reinterpret_cast<NtClose_t>(
        GetProcAddress(ntdll, "NtClose"));
    if (!nt_create || !nt_wait || !nt_close) return false;

    HANDLE thread = nullptr;
    const LONG status = nt_create(
        &thread, THREAD_ALL_ACCESS, nullptr, GetCurrentProcess(),
        reinterpret_cast<PVOID>(&install_hooks_thunk), nullptr,
        kHideFromDebugger, 0, 0, 0, nullptr);
    if (status < 0 || !thread) return false;

    nt_wait(thread, FALSE, nullptr);
    nt_close(thread);
    return true;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID /*reserved*/) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(module);
            run_install_thread();
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
