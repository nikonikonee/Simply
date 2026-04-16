#include "peb_patcher.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstring>

#include "simply_log.hpp"

namespace simply {

namespace {

struct ProcessBasicInformation {
    std::int32_t ExitStatus;
    void*        PebBaseAddress;
    std::uintptr_t AffinityMask;
    std::int32_t BasePriority;
    std::uintptr_t UniqueProcessId;
    std::uintptr_t ParentPid;
};

using NtQueryInformationProcess_t = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// PEB offsets (x64)
constexpr std::size_t kPebBeingDebugged = 0x002;
constexpr std::size_t kPebNtGlobalFlag = 0x0BC;
constexpr std::size_t kPebProcessHeap = 0x030;
constexpr std::size_t kPebProcessParameters = 0x020;
constexpr std::size_t kPebOsBuildNumber = 0x120;

// RTL_USER_PROCESS_PARAMETERS offsets (x64)
constexpr std::size_t kRupStartingX = 0x088;
constexpr std::size_t kRupShowWindowFlagsEnd = 0x0AC;

// HEAP offsets (x64)
constexpr std::size_t kHeapFlags = 0x070;
constexpr std::size_t kHeapForceFlags = 0x074;

// FLG_* offsets (x64)
constexpr std::uint32_t kNtGlobalFlagDebugMask =
    0x00000010 |  // FLG_HEAP_ENABLE_TAIL_CHECK
    0x00000020 |  // FLG_HEAP_ENABLE_FREE_CHECK
    0x00000040;   // FLG_HEAP_VALIDATE_PARAMETERS

void* resolve_peb(HANDLE process) {
    static auto fn = reinterpret_cast<NtQueryInformationProcess_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!fn) {
        log::error("peb: NtQueryInformationProcess not resolved");
        return nullptr;
    }

    ProcessBasicInformation pbi{};
    ULONG ret_len = 0;
    const LONG status = fn(process, 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), &ret_len);
    if (status < 0) {
        log::error("peb: NtQueryInformationProcess returned 0x{:08x}", static_cast<std::uint32_t>(status));
        return nullptr;
    }
    return pbi.PebBaseAddress;
}

template <typename T>
bool read_remote(HANDLE process, std::uintptr_t addr, T& out) {
    SIZE_T n = 0;
    return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(addr), &out, sizeof(T), &n) && n == sizeof(T);
}

template <typename T>
bool write_remote(HANDLE process, std::uintptr_t addr, const T& value) {
    SIZE_T n = 0;
    return WriteProcessMemory(process, reinterpret_cast<LPVOID>(addr), &value, sizeof(T), &n) && n == sizeof(T);
}

}  // namespace

bool patch_peb(void* process_handle) {
    auto* process = static_cast<HANDLE>(process_handle);

    void* peb = resolve_peb(process);
    if (!peb) return false;

    const auto peb_addr = reinterpret_cast<std::uintptr_t>(peb);
    log::debug("peb @ 0x{:x}", peb_addr);

    bool all_ok = true;

    const std::uint8_t zero8 = 0;
    if (!write_remote(process, peb_addr + kPebBeingDebugged, zero8)) {
        log::warn("peb: failed to clear BeingDebugged");
        all_ok = false;
    }

    std::uint32_t flag = 0;
    if (read_remote(process, peb_addr + kPebNtGlobalFlag, flag)) {
        if (flag & kNtGlobalFlagDebugMask) {
            log::debug("peb: NtGlobalFlag 0x{:08x} -> 0x{:08x}", flag, flag & ~kNtGlobalFlagDebugMask);
        }
        flag &= ~kNtGlobalFlagDebugMask;
        if (!write_remote(process, peb_addr + kPebNtGlobalFlag, flag)) {
            log::warn("peb: failed to write NtGlobalFlag");
            all_ok = false;
        }
    } else {
        log::warn("peb: failed to read NtGlobalFlag");
        all_ok = false;
    }

    std::uintptr_t heap = 0;
    if (read_remote(process, peb_addr + kPebProcessHeap, heap) && heap != 0) {
        const std::uint32_t zero32 = 0;
        write_remote(process, heap + kHeapFlags, zero32);
        write_remote(process, heap + kHeapForceFlags, zero32);
        log::debug("peb: cleared heap flags @ 0x{:x}", heap);
    }

    // zero the StartupInfo block, inherited STARTF_USE* from the debugger would leak through to the child PEB
    std::uintptr_t params = 0;
    if (read_remote(process, peb_addr + kPebProcessParameters, params) && params != 0) {
        constexpr std::size_t kBlockBytes = kRupShowWindowFlagsEnd - kRupStartingX;
        std::uint8_t zeros[kBlockBytes] = {};
        SIZE_T n = 0;
        if (WriteProcessMemory(process, reinterpret_cast<LPVOID>(params + kRupStartingX), zeros, kBlockBytes, &n) && n == kBlockBytes) {
            log::debug("peb: cleared StartupInfo block @ 0x{:x}", params + kRupStartingX);
        } else {
            log::warn("peb: failed to clear StartupInfo block");
        }
    }

    // sync OsBuildNumber with host build, some loader shims rewrite it. PEB is at gs:[0x60] on x64
    auto* host_peb = reinterpret_cast<std::uint8_t*>(__readgsqword(0x60));
    const std::uint16_t host_build = *reinterpret_cast<std::uint16_t*>(host_peb + kPebOsBuildNumber);
    write_remote(process, peb_addr + kPebOsBuildNumber, host_build);

    if (all_ok) log::info("peb patched");
    return all_ok;
}

bool strip_debug_privilege(void* process_handle) {
    auto* process = static_cast<HANDLE>(process_handle);

    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        log::warn("token: OpenProcessToken failed (err {})", GetLastError());
        return false;
    }

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

    const BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    const DWORD err = GetLastError();
    CloseHandle(token);

    if (!ok || err == ERROR_NOT_ALL_ASSIGNED) {
        log::debug("token: SeDebugPrivilege not present (err {})", err);
        return true;
    }
    log::info("token: SeDebugPrivilege removed");
    return true;
}

}  // namespace simply
