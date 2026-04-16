#include "hooks.hpp"
#include "hooker.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>

namespace simply::bypass {

namespace {

using NtQueryInformationProcess_t = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSetInformationProcess_t   = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtSetInformationThread_t    = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtQuerySystemInformation_t  = NTSTATUS (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryObject_t             = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtYieldExecution_t          = NTSTATUS (NTAPI*)(VOID);
using NtCreateThreadEx_t          = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
using NtSetDebugFilterState_t     = NTSTATUS (NTAPI*)(ULONG, ULONG, BOOLEAN);
using NtClose_t                   = NTSTATUS (NTAPI*)(HANDLE);
using NtContinue_t                = NTSTATUS (NTAPI*)(PCONTEXT, BOOLEAN);
using RtlDispatchException_t      = BOOLEAN (NTAPI*)(PEXCEPTION_RECORD, PCONTEXT);
using DbgUiRemoteBreakin_t        = VOID (NTAPI*)(PVOID);
using NtUserFindWindowEx_t        = HWND (NTAPI*)(HWND, HWND, PUNICODE_STRING, PUNICODE_STRING, DWORD);
using NtUserBuildHwndList_t       = NTSTATUS (NTAPI*)(HANDLE, HWND, BOOL, BOOL, ULONG, ULONG, HWND*, ULONG*);
using NtUserQueryWindow_t         = HANDLE (NTAPI*)(HWND, ULONG);
using NtUserGetForegroundWindow_t = HWND (NTAPI*)(VOID);
using NtQuerySystemTime_t         = NTSTATUS (NTAPI*)(PLARGE_INTEGER);
using NtQueryPerformanceCounter_t = NTSTATUS (NTAPI*)(PLARGE_INTEGER, PLARGE_INTEGER);
using GetTickCount_t              = DWORD (WINAPI*)(VOID);
using GetTickCount64_t            = ULONGLONG (WINAPI*)(VOID);
using GetSystemTime_t             = VOID (WINAPI*)(LPSYSTEMTIME);
using GetLocalTime_t              = VOID (WINAPI*)(LPSYSTEMTIME);
using NtGetContextThread_t        = NTSTATUS (NTAPI*)(HANDLE, PCONTEXT);
using NtSetContextThread_t        = NTSTATUS (NTAPI*)(HANDLE, PCONTEXT);
using NtProtectVirtualMemory_t    = NTSTATUS (NTAPI*)(HANDLE, PVOID*, SIZE_T*, ULONG, PULONG);
using FindWindowA_t               = HWND (WINAPI*)(LPCSTR, LPCSTR);
using FindWindowW_t               = HWND (WINAPI*)(LPCWSTR, LPCWSTR);
using RegOpenKeyExA_t             = LONG (WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
using RegOpenKeyExW_t             = LONG (WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
using OutputDebugStringA_t        = VOID (WINAPI*)(LPCSTR);
using BlockInput_t                = BOOL (WINAPI*)(BOOL);

NtQueryInformationProcess_t real_NtQueryInformationProcess = nullptr;
NtSetInformationProcess_t   real_NtSetInformationProcess = nullptr;
NtSetInformationThread_t    real_NtSetInformationThread = nullptr;
NtQuerySystemInformation_t  real_NtQuerySystemInformation = nullptr;
NtQueryObject_t             real_NtQueryObject = nullptr;
NtYieldExecution_t          real_NtYieldExecution = nullptr;
NtCreateThreadEx_t          real_NtCreateThreadEx = nullptr;
NtSetDebugFilterState_t     real_NtSetDebugFilterState = nullptr;
NtClose_t                   real_NtClose = nullptr;
NtContinue_t                real_NtContinue = nullptr;
RtlDispatchException_t      real_RtlDispatchException = nullptr;
DbgUiRemoteBreakin_t        real_DbgUiRemoteBreakin = nullptr;
NtUserFindWindowEx_t        real_NtUserFindWindowEx = nullptr;
NtUserBuildHwndList_t       real_NtUserBuildHwndList = nullptr;
NtUserQueryWindow_t         real_NtUserQueryWindow = nullptr;
NtUserGetForegroundWindow_t real_NtUserGetForegroundWindow = nullptr;
NtQuerySystemTime_t         real_NtQuerySystemTime = nullptr;
NtQueryPerformanceCounter_t real_NtQueryPerformanceCounter = nullptr;
GetTickCount_t              real_GetTickCount = nullptr;
GetTickCount64_t            real_GetTickCount64 = nullptr;
GetSystemTime_t             real_GetSystemTime = nullptr;
GetLocalTime_t              real_GetLocalTime = nullptr;
NtGetContextThread_t        real_NtGetContextThread = nullptr;
NtSetContextThread_t        real_NtSetContextThread = nullptr;
NtProtectVirtualMemory_t    real_NtProtectVirtualMemory = nullptr;
FindWindowA_t               real_FindWindowA = nullptr;
FindWindowW_t               real_FindWindowW = nullptr;
RegOpenKeyExA_t             real_RegOpenKeyExA = nullptr;
RegOpenKeyExW_t             real_RegOpenKeyExW = nullptr;
OutputDebugStringA_t        real_OutputDebugStringA = nullptr;
BlockInput_t                real_BlockInput = nullptr;

// main image's .text, lazy. zero = not resolved yet
std::uintptr_t g_text_lo = 0;
std::uintptr_t g_text_hi = 0;

bool is_themida_section_name(const char* n) {
    return std::strcmp(n, ".themida") == 0 || std::strcmp(n, ".boot") == 0 || std::strcmp(n, ".winlice") == 0 || std::strcmp(n, "WinLicen") == 0;
}

void locate_text_region() {
    if (g_text_lo != 0) return;

    auto* base = reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr));
    if (!base) return;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    auto* section = IMAGE_FIRST_SECTION(nt);
    const std::uint8_t* fallback_va = nullptr;
    std::uint32_t fallback_size = 0;
    const std::uint8_t* text_va = nullptr;
    std::uint32_t text_size = 0;

    char name[9] = {};
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        std::memcpy(name, section->Name, 8);
        name[8] = '\0';
        if (is_themida_section_name(name)) continue;
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;

        const std::uint8_t* va = base + section->VirtualAddress;
        const std::uint32_t sz = section->Misc.VirtualSize;
        if (std::strcmp(name, ".text") == 0) { text_va = va; text_size = sz; break; }
        if (!fallback_va) { fallback_va = va; fallback_size = sz; }
    }

    if (!text_va) { text_va = fallback_va; text_size = fallback_size; }
    if (!text_va) return;

    g_text_lo = reinterpret_cast<std::uintptr_t>(text_va);
    g_text_hi = g_text_lo + text_size;
}

bool overlaps_text(std::uintptr_t addr, std::size_t size) {
    return g_text_lo != 0 && (addr + size) > g_text_lo && addr < g_text_hi;
}

constexpr ULONG kExecuteMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

constexpr ULONG kProcessDebugPort = 0x07;
constexpr ULONG kProcessDebugObjectHandle = 0x1E;
constexpr ULONG kProcessDebugFlags = 0x1F;
constexpr ULONG kProcessBreakOnTermination = 0x1D;

constexpr ULONG kThreadHideFromDebugger = 0x11;

constexpr ULONG kSystemKernelDebuggerInformation = 0x23;

constexpr ULONG kObjectAllTypesInformation = 0x03;
constexpr ULONG kObjectBasicInformation    = 0x00;

constexpr ULONG kThreadCreateFlagHideFromDebugger = 0x04;

constexpr NTSTATUS kStatusSuccess        = 0x00000000;
constexpr NTSTATUS kStatusInvalidHandle  = 0xC0000008;
constexpr NTSTATUS kStatusInvalidInfoClass = 0xC0000003;

/*
   winternl only ships PUBLIC_OBJECT_TYPE_INFORMATION (stub, missing the
   counts we need). full layout is in the WDK; we rely on TypeName + the
   first two count fields.
 */
struct OBJECT_TYPE_INFORMATION_FULL {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
};

bool contains_icase(const char* hay, const char* needle) {
    if (!hay || !needle) return false;
    const size_t hl = std::strlen(hay), nl = std::strlen(needle);
    if (nl > hl) return false;
    for (size_t i = 0; i + nl <= hl; ++i) {
        size_t j = 0;
        for (; j < nl; ++j) {
            char a = hay[i + j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + 32);
            if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + 32);
            if (a != b) break;
        }
        if (j == nl) return true;
    }
    return false;
}

bool contains_icase_w(const wchar_t* hay, const wchar_t* needle) {
    if (!hay || !needle) return false;
    const size_t hl = std::wcslen(hay), nl = std::wcslen(needle);
    if (nl > hl) return false;
    for (size_t i = 0; i + nl <= hl; ++i) {
        size_t j = 0;
        for (; j < nl; ++j) {
            wchar_t a = hay[i + j], b = needle[j];
            if (a >= L'A' && a <= L'Z') a = static_cast<wchar_t>(a + 32);
            if (b >= L'A' && b <= L'Z') b = static_cast<wchar_t>(b + 32);
            if (a != b) break;
        }
        if (j == nl) return true;
    }
    return false;
}

constexpr const char* kDebuggerNeedlesA[] = {
    "OLLYDBG", "Zeta Debugger", "Rock Debugger", "ObsidianGUI", "ImmunityDebugger",
    "WinDbgFrameClass", "x64dbg", "x32dbg", "Snowman", "PROCEXPL", "dbgview",
};

constexpr const wchar_t* kDebuggerNeedlesW[] = {
    L"OLLYDBG", L"x64dbg", L"x32dbg", L"ImmunityDebugger",
    L"WinDbgFrameClass", L"Zeta Debugger", L"PROCEXPL", L"dbgview",
};

constexpr const char* kBadRegKeysA[] = {
    "SOFTWARE\\Wine",
    "SOFTWARE\\Classes\\Applications\\OLLYDBG.EXE",
    "Software\\IDA",
    "Software\\Hex-Rays",
    "Software\\x64dbg",
};

constexpr const wchar_t* kBadRegKeysW[] = {
    L"SOFTWARE\\Wine",
    L"SOFTWARE\\Classes\\Applications\\OLLYDBG.EXE",
    L"Software\\IDA",
    L"Software\\Hex-Rays",
    L"Software\\x64dbg",
};

// -- hooks --

NTSTATUS NTAPI Hook_NtQueryInformationProcess(HANDLE ProcessHandle, ULONG InformationClass, PVOID Info, ULONG InfoLen, PULONG RetLen) {
    NTSTATUS status = real_NtQueryInformationProcess(ProcessHandle, InformationClass, Info, InfoLen, RetLen);
    if (status < 0 || Info == nullptr) return status;

    switch (InformationClass) {
        case kProcessDebugPort:
            if (InfoLen >= sizeof(HANDLE)) *static_cast<HANDLE*>(Info) = nullptr;
            break;
        case kProcessDebugObjectHandle:
            if (InfoLen >= sizeof(HANDLE)) *static_cast<HANDLE*>(Info) = nullptr;
            // themida reads STATUS_PORT_NOT_SET as "no debugger"
            status = 0xC0000353;
            break;
        case kProcessDebugFlags:
            if (InfoLen >= sizeof(ULONG)) *static_cast<ULONG*>(Info) = 1;
            break;
        default:
            break;
    }
    return status;
}

NTSTATUS NTAPI Hook_NtSetInformationThread(HANDLE ThreadHandle, ULONG InformationClass, PVOID Info, ULONG InfoLen) {
    // swallow HideFromDebugger so we keep seeing target threads
    if (InformationClass == kThreadHideFromDebugger) return 0;
    return real_NtSetInformationThread(ThreadHandle, InformationClass, Info, InfoLen);
}

NTSTATUS NTAPI Hook_NtGetContextThread(HANDLE Thread, PCONTEXT Ctx) {
    NTSTATUS status = real_NtGetContextThread(Thread, Ctx);
    if (status >= 0 && Ctx && (Ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) {
        Ctx->Dr0 = 0; Ctx->Dr1 = 0; Ctx->Dr2 = 0;
        Ctx->Dr3 = 0; Ctx->Dr6 = 0; Ctx->Dr7 = 0;
    }
    return status;
}

NTSTATUS NTAPI Hook_NtProtectVirtualMemory(HANDLE Process, PVOID* BaseAddress, SIZE_T* NumberOfBytes, ULONG NewProtect, PULONG OldProtect) {
    // strip execute on any request over .text so the DEP trap survives until the real jmp OEP
    locate_text_region();
    if (Process == GetCurrentProcess() && BaseAddress && *BaseAddress && NumberOfBytes) {
        const auto addr = reinterpret_cast<std::uintptr_t>(*BaseAddress);
        const auto size = static_cast<std::size_t>(*NumberOfBytes);
        if (overlaps_text(addr, size) && (NewProtect & kExecuteMask)) {
            NewProtect = (NewProtect & ~kExecuteMask) | PAGE_READWRITE;
        }
    }
    return real_NtProtectVirtualMemory(Process, BaseAddress, NumberOfBytes, NewProtect, OldProtect);
}

NTSTATUS NTAPI Hook_NtSetContextThread(HANDLE Thread, PCONTEXT Ctx) {
    // if themida tries to clobber DRx, drop the bit so it no-ops
    if (Ctx && (Ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) {
        Ctx->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
    }
    return real_NtSetContextThread(Thread, Ctx);
}

HWND WINAPI Hook_FindWindowA(LPCSTR cls, LPCSTR name) {
    for (const char* n : kDebuggerNeedlesA) {
        if ((cls && contains_icase(cls, n)) || (name && contains_icase(name, n))) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return nullptr;
        }
    }
    return real_FindWindowA(cls, name);
}

HWND WINAPI Hook_FindWindowW(LPCWSTR cls, LPCWSTR name) {
    for (const wchar_t* n : kDebuggerNeedlesW) {
        if ((cls && contains_icase_w(cls, n)) || (name && contains_icase_w(name, n))) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return nullptr;
        }
    }
    return real_FindWindowW(cls, name);
}

LONG WINAPI Hook_RegOpenKeyExA(HKEY root, LPCSTR sub, DWORD opt, REGSAM sam, PHKEY out) {
    for (const char* bad : kBadRegKeysA) {
        if (sub && contains_icase(sub, bad)) return ERROR_FILE_NOT_FOUND;
    }
    return real_RegOpenKeyExA(root, sub, opt, sam, out);
}

LONG WINAPI Hook_RegOpenKeyExW(HKEY root, LPCWSTR sub, DWORD opt, REGSAM sam, PHKEY out) {
    for (const wchar_t* bad : kBadRegKeysW) {
        if (sub && contains_icase_w(sub, bad)) return ERROR_FILE_NOT_FOUND;
    }
    return real_RegOpenKeyExW(root, sub, opt, sam, out);
}

NTSTATUS NTAPI Hook_NtSetInformationProcess(HANDLE Process, ULONG InfoClass, PVOID Info, ULONG InfoLen) {
    /*
     * ProcessBreakOnTermination asks the kernel to bugcheck on process
     * exit. themida uses it to catch debuggers that swallow termination.
     * pretend we set it.
     */
    if (InfoClass == kProcessBreakOnTermination) return kStatusSuccess;
    return real_NtSetInformationProcess(Process, InfoClass, Info, InfoLen);
}

NTSTATUS NTAPI Hook_NtQuerySystemInformation(ULONG InfoClass, PVOID Info, ULONG InfoLen, PULONG RetLen) {
    NTSTATUS status = real_NtQuerySystemInformation(InfoClass, Info, InfoLen, RetLen);
    if (status < 0 || Info == nullptr) return status;

    if (InfoClass == kSystemKernelDebuggerInformation && InfoLen >= 2) {
        // SYSTEM_KERNEL_DEBUGGER_INFORMATION { BOOLEAN Enabled; BOOLEAN NotPresent; }
        auto* p = static_cast<BOOLEAN*>(Info);
        p[0] = FALSE;  // KdDebuggerEnabled
        p[1] = TRUE;   // KdDebuggerNotPresent
    }
    return status;
}

NTSTATUS NTAPI Hook_NtQueryObject(HANDLE Handle, ULONG InfoClass, PVOID Info, ULONG InfoLen, PULONG RetLen) {
    NTSTATUS status = real_NtQueryObject(Handle, InfoClass, Info, InfoLen, RetLen);
    if (status < 0 || Info == nullptr) return status;

    /*
     * ObjectAllTypesInformation: themida walks the type table and checks
     * DebugObject's TotalNumberOfObjects. find that entry and zero the
     * counts. layout: { ULONG NumberOfTypes; OBJECT_TYPE_INFORMATION_FULL[] },
     * each entry followed by its TypeName.Buffer, pointer-aligned to the next.
     */
    if (InfoClass != kObjectAllTypesInformation) return status;
    if (InfoLen < sizeof(ULONG)) return status;

    auto* base = static_cast<std::uint8_t*>(Info);
    const ULONG num_types = *reinterpret_cast<ULONG*>(base);

    // first entry sits one pointer-slot in (ULONG count padded)
    auto* p = reinterpret_cast<std::uint8_t*>(
        (reinterpret_cast<std::uintptr_t>(base) + sizeof(void*) + sizeof(void*) - 1) &
        ~(static_cast<std::uintptr_t>(sizeof(void*)) - 1));

    for (ULONG i = 0; i < num_types; ++i) {
        auto* type = reinterpret_cast<OBJECT_TYPE_INFORMATION_FULL*>(p);
        if (type->TypeName.Buffer && type->TypeName.Length >= 22 &&
            std::wcsncmp(type->TypeName.Buffer, L"DebugObject", 11) == 0) {
            // after UNICODE_STRING (16 bytes on x64) come TotalNumberOfObjects and TotalNumberOfHandles
            auto* counts = reinterpret_cast<ULONG*>(p + sizeof(UNICODE_STRING));
            counts[0] = 0;
            counts[1] = 0;
        }

        // skip this entry's struct + inline TypeName, realign
        std::uint8_t* next = reinterpret_cast<std::uint8_t*>(type + 1) + type->TypeName.MaximumLength;
        next = reinterpret_cast<std::uint8_t*>(
            (reinterpret_cast<std::uintptr_t>(next) + sizeof(void*) - 1) &
            ~(static_cast<std::uintptr_t>(sizeof(void*)) - 1));
        p = next;
    }
    return status;
}

NTSTATUS NTAPI Hook_NtYieldExecution() {
    /*
     * themida times yield calls. STATUS_NO_YIELD_PERFORMED is what a
     * quiet no-debugger system returns, force it so the timing channel
     * collapses.
     */
    real_NtYieldExecution();  // still yield for fairness
    return 0x40000024;        // STATUS_NO_YIELD_PERFORMED
}

NTSTATUS NTAPI Hook_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    // strip HideFromDebugger so our debug loop still sees the new thread
    CreateFlags &= ~kThreadCreateFlagHideFromDebugger;
    return real_NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

VOID WINAPI Hook_OutputDebugStringA(LPCSTR /*str*/) {
    // themida checks GetLastError after OutputDebugString to see if a debugger ate the DBG_PRINTEXCEPTION_C. force 0 to fake no-debugger
    SetLastError(0);
}

BOOL WINAPI Hook_BlockInput(BOOL /*fBlockIt*/) {
    // returns FALSE under a debugger; force TRUE so themida sees a real desktop session
    return TRUE;
}

NTSTATUS NTAPI Hook_NtSetDebugFilterState(ULONG /*ComponentId*/, ULONG /*Level*/, BOOLEAN /*State*/) {
    // themida only checks the return code
    return kStatusSuccess;
}

/*
   synthetic monotonic clock shared by all timing hooks. anchored to the
   real wall clock at first query so absolute values look plausible, then
   advances 1ms per call so debugger slowdown is invisible.
 */
struct TimingState {
    std::atomic<bool> initialized{false};
    std::atomic<ULONGLONG> elapsed_ms{0};
    ULONGLONG base_filetime_100ns = 0;  // FILETIME at init
    LONGLONG base_qpc = 0;
    LONGLONG qpc_freq = 1;
    DWORD base_tick32 = 0;
    ULONGLONG base_tick64 = 0;

    void ensure_init() {
        if (initialized.load(std::memory_order_acquire)) return;

        LARGE_INTEGER ft{};
        if (real_NtQuerySystemTime) real_NtQuerySystemTime(&ft);
        base_filetime_100ns = static_cast<ULONGLONG>(ft.QuadPart);

        LARGE_INTEGER qpc{}, freq{};
        if (real_NtQueryPerformanceCounter) real_NtQueryPerformanceCounter(&qpc, &freq);
        base_qpc = qpc.QuadPart;
        qpc_freq = freq.QuadPart > 0 ? freq.QuadPart : 1;

        if (real_GetTickCount)   base_tick32 = real_GetTickCount();
        if (real_GetTickCount64) base_tick64 = real_GetTickCount64();

        initialized.store(true, std::memory_order_release);
    }

    ULONGLONG tick_ms() {
        ensure_init();
        return elapsed_ms.fetch_add(1, std::memory_order_relaxed) + 1;
    }
};

TimingState g_timing;

DWORD WINAPI Hook_GetTickCount() {
    return g_timing.base_tick32 + static_cast<DWORD>(g_timing.tick_ms());
}

ULONGLONG WINAPI Hook_GetTickCount64() {
    return g_timing.base_tick64 + g_timing.tick_ms();
}

NTSTATUS NTAPI Hook_NtQuerySystemTime(PLARGE_INTEGER SystemTime) {
    if (!SystemTime) return real_NtQuerySystemTime(SystemTime);
    SystemTime->QuadPart =
        static_cast<LONGLONG>(g_timing.base_filetime_100ns + g_timing.tick_ms() * 10000ULL);
    return kStatusSuccess;
}

NTSTATUS NTAPI Hook_NtQueryPerformanceCounter(PLARGE_INTEGER Counter, PLARGE_INTEGER Frequency) {
    if (!Counter) return real_NtQueryPerformanceCounter(Counter, Frequency);
    g_timing.ensure_init();
    const ULONGLONG ms = g_timing.tick_ms();
    Counter->QuadPart = g_timing.base_qpc + static_cast<LONGLONG>(ms * (g_timing.qpc_freq / 1000));
    if (Frequency) Frequency->QuadPart = g_timing.qpc_freq;
    return kStatusSuccess;
}

VOID WINAPI Hook_GetSystemTime(LPSYSTEMTIME st) {
    if (!st) return;
    const ULONGLONG synth = g_timing.base_filetime_100ns + g_timing.tick_ms() * 10000ULL;
    FILETIME ft{};
    ft.dwLowDateTime  = static_cast<DWORD>(synth);
    ft.dwHighDateTime = static_cast<DWORD>(synth >> 32);
    FileTimeToSystemTime(&ft, st);
}

VOID WINAPI Hook_GetLocalTime(LPSYSTEMTIME st) {
    if (!st) return;
    const ULONGLONG synth = g_timing.base_filetime_100ns + g_timing.tick_ms() * 10000ULL;
    FILETIME utc_ft{}, local_ft{};
    utc_ft.dwLowDateTime  = static_cast<DWORD>(synth);
    utc_ft.dwHighDateTime = static_cast<DWORD>(synth >> 32);
    FileTimeToLocalFileTime(&utc_ft, &local_ft);
    FileTimeToSystemTime(&local_ft, st);
}

NTSTATUS NTAPI Hook_NtContinue(PCONTEXT Ctx, BOOLEAN TestAlert) {
    // themida ends some paths via NtContinue with a CONTEXT that rewrites Dr0..Dr7 to kill debugger BPs. scrub before the kernel applies it
    if (Ctx && (Ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) {
        Ctx->Dr0 = 0; Ctx->Dr1 = 0; Ctx->Dr2 = 0;
        Ctx->Dr3 = 0; Ctx->Dr6 = 0; Ctx->Dr7 = 0;
        Ctx->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
    }
    return real_NtContinue(Ctx, TestAlert);
}

// bounded by Length so a bogus PUNICODE_STRING can't run us off the buffer
bool unicode_string_matches_debugger(PUNICODE_STRING us) {
    if (!us || !us->Buffer || us->Length == 0) return false;
    const std::size_t chars = us->Length / sizeof(wchar_t);
    for (const wchar_t* needle : kDebuggerNeedlesW) {
        const std::size_t nl = std::wcslen(needle);
        if (nl > chars) continue;
        for (std::size_t i = 0; i + nl <= chars; ++i) {
            std::size_t j = 0;
            for (; j < nl; ++j) {
                wchar_t a = us->Buffer[i + j];
                wchar_t b = needle[j];
                if (a >= L'A' && a <= L'Z') a = static_cast<wchar_t>(a + 32);
                if (b >= L'A' && b <= L'Z') b = static_cast<wchar_t>(b + 32);
                if (a != b) break;
            }
            if (j == nl) return true;
        }
    }
    return false;
}

HWND NTAPI Hook_NtUserFindWindowEx(HWND parent, HWND child, PUNICODE_STRING cls, PUNICODE_STRING name, DWORD type) {
    if (unicode_string_matches_debugger(cls) || unicode_string_matches_debugger(name)) {
        return nullptr;
    }
    return real_NtUserFindWindowEx(parent, child, cls, name, type);
}

NTSTATUS NTAPI Hook_NtUserBuildHwndList(HANDLE desk, HWND parent, BOOL children, BOOL hide_imm, ULONG threadId, ULONG bufSize, HWND* hwnds, ULONG* count) {
    // no per-HWND filter: GetClassName recurses through user32 and can deadlock from inside a syscall-stub hook. FindWindowEx above catches the common direct-lookup pattern
    return real_NtUserBuildHwndList(desk, parent, children, hide_imm, threadId, bufSize, hwnds, count);
}

HANDLE NTAPI Hook_NtUserQueryWindow(HWND wnd, ULONG index) {
    // same recursion concern, pass through
    return real_NtUserQueryWindow(wnd, index);
}

HWND NTAPI Hook_NtUserGetForegroundWindow() {
    return real_NtUserGetForegroundWindow();
}

/*
   KiUserExceptionDispatcher has no real call frame so a trampoline hook
   trashes the stack. RtlDispatchException is what it calls right after
   with a clean x64 ABI and the same CONTEXT* that __except filters see,
   so scrubbing DRx here makes themida's filters see zeros.
 */
BOOLEAN NTAPI Hook_RtlDispatchException(PEXCEPTION_RECORD ex, PCONTEXT Ctx) {
    if (Ctx) {
        Ctx->Dr0 = 0; Ctx->Dr1 = 0; Ctx->Dr2 = 0;
        Ctx->Dr3 = 0; Ctx->Dr6 = 0; Ctx->Dr7 = 0;
    }
    return real_RtlDispatchException(ex, Ctx);
}

VOID NTAPI Hook_DbgUiRemoteBreakin(PVOID Ctx) {
    // themida overwrites this prologue so an external DebugActiveProcess hits themida's termination stub. hooking first preserves the real prologue in our trampoline
    real_DbgUiRemoteBreakin(Ctx);
}

NTSTATUS NTAPI Hook_NtClose(HANDLE Handle) {
    /*
     * themida wraps NtClose(junk_handle) in __try/__except. under a
     * debugger the kernel raises STATUS_INVALID_HANDLE. validate via
     * NtQueryObject (returns status without raising) so we never hit
     * the real NtClose with a bad handle.
     */
    PUBLIC_OBJECT_BASIC_INFORMATION basic{};
    ULONG ret = 0;
    NTSTATUS qstat = real_NtQueryObject(Handle, kObjectBasicInformation, &basic, sizeof(basic), &ret);
    if (qstat == kStatusInvalidHandle) return kStatusInvalidHandle;
    return real_NtClose(Handle);
}

// -- install / uninstall --

template <typename Fn>
bool install_one(const wchar_t* module, const char* name, Fn hook, Fn& original_out) {
    HMODULE h = GetModuleHandleW(module);
    if (!h) return false;
    void* target = reinterpret_cast<void*>(GetProcAddress(h, name));
    if (!target) return false;
    return hooker::install(target, reinterpret_cast<void*>(hook),
                           reinterpret_cast<void**>(&original_out));
}

}  // namespace

bool install_hooks() {
    if (!hooker::initialize()) return false;

    bool ok = true;
    ok &= install_one(L"ntdll.dll",    "NtQueryInformationProcess", &Hook_NtQueryInformationProcess, real_NtQueryInformationProcess);
    ok &= install_one(L"ntdll.dll",    "NtSetInformationProcess",   &Hook_NtSetInformationProcess,   real_NtSetInformationProcess);
    ok &= install_one(L"ntdll.dll",    "NtSetInformationThread",    &Hook_NtSetInformationThread,    real_NtSetInformationThread);
    ok &= install_one(L"ntdll.dll",    "NtQuerySystemInformation",  &Hook_NtQuerySystemInformation,  real_NtQuerySystemInformation);
    ok &= install_one(L"ntdll.dll",    "NtQueryObject",             &Hook_NtQueryObject,             real_NtQueryObject);
    ok &= install_one(L"ntdll.dll",    "NtYieldExecution",          &Hook_NtYieldExecution,          real_NtYieldExecution);
    ok &= install_one(L"ntdll.dll",    "NtCreateThreadEx",          &Hook_NtCreateThreadEx,          real_NtCreateThreadEx);
    ok &= install_one(L"ntdll.dll",    "NtSetDebugFilterState",     &Hook_NtSetDebugFilterState,     real_NtSetDebugFilterState);
    ok &= install_one(L"ntdll.dll",    "NtClose",                   &Hook_NtClose,                   real_NtClose);
    ok &= install_one(L"ntdll.dll",    "NtContinue",                &Hook_NtContinue,                real_NtContinue);
    /*
     * RtlDispatchException hook removed. it fires on every user-mode
     * exception and themida's SEH-based unpacker reads DRx from the
     * dispatched CONTEXT as part of its handler branch logic, so zeroing
     * there trapped the unpacker in an AV retry loop. DRx scrubbing on
     * NtGetContext/NtSetContext/NtContinue covers the anti-debug paths.
     */
    ok &= install_one(L"ntdll.dll",    "DbgUiRemoteBreakin",        &Hook_DbgUiRemoteBreakin,        real_DbgUiRemoteBreakin);
    // win32u.dll direct syscall stubs. user32 wrappers are hooked above but a packer can skip them
    install_one(L"win32u.dll",  "NtUserFindWindowEx",        &Hook_NtUserFindWindowEx,        real_NtUserFindWindowEx);
    install_one(L"win32u.dll",  "NtUserBuildHwndList",       &Hook_NtUserBuildHwndList,       real_NtUserBuildHwndList);
    install_one(L"win32u.dll",  "NtUserQueryWindow",         &Hook_NtUserQueryWindow,         real_NtUserQueryWindow);
    install_one(L"win32u.dll",  "NtUserGetForegroundWindow", &Hook_NtUserGetForegroundWindow, real_NtUserGetForegroundWindow);
    // ntdll trampolines first so ensure_init() can call them from inside the kernel32 hook bodies on first fire
    ok &= install_one(L"ntdll.dll",    "NtQuerySystemTime",         &Hook_NtQuerySystemTime,         real_NtQuerySystemTime);
    ok &= install_one(L"ntdll.dll",    "NtQueryPerformanceCounter", &Hook_NtQueryPerformanceCounter, real_NtQueryPerformanceCounter);
    ok &= install_one(L"kernel32.dll", "GetTickCount",              &Hook_GetTickCount,              real_GetTickCount);
    ok &= install_one(L"kernel32.dll", "GetTickCount64",            &Hook_GetTickCount64,            real_GetTickCount64);
    ok &= install_one(L"kernel32.dll", "GetSystemTime",             &Hook_GetSystemTime,             real_GetSystemTime);
    ok &= install_one(L"kernel32.dll", "GetLocalTime",              &Hook_GetLocalTime,              real_GetLocalTime);
    ok &= install_one(L"ntdll.dll",    "NtGetContextThread",        &Hook_NtGetContextThread,        real_NtGetContextThread);
    ok &= install_one(L"ntdll.dll",    "NtSetContextThread",        &Hook_NtSetContextThread,        real_NtSetContextThread);
    ok &= install_one(L"ntdll.dll",    "NtProtectVirtualMemory",    &Hook_NtProtectVirtualMemory,    real_NtProtectVirtualMemory);
    ok &= install_one(L"user32.dll",   "FindWindowA",               &Hook_FindWindowA,               real_FindWindowA);
    ok &= install_one(L"user32.dll",   "FindWindowW",               &Hook_FindWindowW,               real_FindWindowW);
    ok &= install_one(L"user32.dll",   "BlockInput",                &Hook_BlockInput,                real_BlockInput);
    ok &= install_one(L"advapi32.dll", "RegOpenKeyExA",             &Hook_RegOpenKeyExA,             real_RegOpenKeyExA);
    ok &= install_one(L"advapi32.dll", "RegOpenKeyExW",             &Hook_RegOpenKeyExW,             real_RegOpenKeyExW);
    ok &= install_one(L"kernel32.dll", "OutputDebugStringA",        &Hook_OutputDebugStringA,        real_OutputDebugStringA);
    return ok;
}

void uninstall_hooks() {
    hooker::uninitialize();
}

}  // namespace simply::bypass
