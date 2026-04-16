#include "themida_capture.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "simply_log.hpp"

#pragma comment(lib, "psapi.lib")

namespace simply {

namespace {

constexpr std::array<std::string_view, 9> kPackerNames = {
    ".themida", ".boot", ".winlice", "WinLicen",
    ".vmp0", ".vmp1",
    ".mpress1", ".mpress2",
    ".enigma1"
};

// heavier VM-Macro dispatches can need a million+ single-steps to peel
constexpr std::uint32_t kMaxStepsPerStub = 2'000'000;

// total wall budget so a pathological binary can't pin the host forever
constexpr DWORD kTotalBudgetMs = 180'000;

struct SectionRange {
    std::uint32_t lo_rva;
    std::uint32_t hi_rva;
    bool          is_packer;
    bool          is_text;  // first executable non-packer section
};

template <typename T>
bool read_remote(HANDLE process, std::uint64_t addr, T& out) {
    SIZE_T n = 0;
    return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(addr), &out, sizeof(T), &n)
           && n == sizeof(T);
}

bool read_remote_bytes(HANDLE process, std::uint64_t addr, void* out, std::size_t len) {
    SIZE_T n = 0;
    return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(addr), out, len, &n)
           && n == len;
}

bool is_packer_name(const IMAGE_SECTION_HEADER& s) {
    char buf[9] = {};
    std::memcpy(buf, s.Name, 8);
    const std::string n = buf;
    return std::any_of(kPackerNames.begin(), kPackerNames.end(),
                       [&](std::string_view k) { return n == k; });
}

bool read_section_table(HANDLE process, std::uint64_t image_base, std::vector<SectionRange>& out_ranges, SectionRange& out_text) {
    IMAGE_DOS_HEADER dos{};
    if (!read_remote(process, image_base, dos)) return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;

    IMAGE_NT_HEADERS64 nt{};
    if (!read_remote(process, image_base + dos.e_lfanew, nt)) return false;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;

    const std::uint32_t section_count = nt.FileHeader.NumberOfSections;
    if (section_count == 0 || section_count > 96) return false;

    const std::uint64_t section_va = image_base + dos.e_lfanew + sizeof(DWORD)
                                   + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    std::vector<IMAGE_SECTION_HEADER> headers(section_count);
    if (!read_remote_bytes(process, section_va, headers.data(),
                           headers.size() * sizeof(IMAGE_SECTION_HEADER))) {
        return false;
    }

    out_ranges.clear();
    out_text = {};
    bool found_text = false;
    for (const auto& s : headers) {
        SectionRange r{};
        r.lo_rva = s.VirtualAddress;
        r.hi_rva = s.VirtualAddress + (std::max)(s.Misc.VirtualSize, s.SizeOfRawData);
        r.is_packer = is_packer_name(s);
        r.is_text = false;
        if (!found_text && (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) && !r.is_packer) {
            r.is_text = true;
            out_text = r;
            found_text = true;
        }
        out_ranges.push_back(r);
    }
    return found_text;
}

/*
   scan non-packer non-executable sections for 8-byte aligned qwords that
   land in a packer section. these are themida-poisoned api pointer slots:
   original code does `mov rax,[slot]; call rax`, the slot held the real
   api at compile time but themida overwrote it with a stub VA. we capture
   the stub like any other and the rebuild path adds an IMPORT descriptor
   with FirstThunk = slot's RVA, so the loader repopulates the slot with
   the real api next load.
 */
std::unordered_map<std::uint64_t, std::uint64_t>
collect_poisoned_slots(HANDLE process, std::uint64_t image_base, const std::vector<SectionRange>& all) {
    std::unordered_map<std::uint64_t, std::uint64_t> out;

    auto in_packer = [&](std::uint64_t rva) {
        for (const auto& r : all) {
            if (r.is_packer && rva >= r.lo_rva && rva < r.hi_rva) return true;
        }
        return false;
    };

    for (const auto& r : all) {
        // skip packer sections (stub bodies, their internal qwords aren't
        // iat slots) and skip .text (scanned separately for call sites)
        if (r.is_packer || r.is_text) continue;
        const std::uint32_t span = r.hi_rva - r.lo_rva;
        if (span == 0 || span > 64u * 1024 * 1024) continue;

        std::vector<std::uint8_t> buf(span);
        if (!read_remote_bytes(process, image_base + r.lo_rva, buf.data(), buf.size())) {
            continue;
        }

        for (std::uint32_t i = 0; i + 8 <= span; i += 8) {
            std::uint64_t qw = 0;
            std::memcpy(&qw, buf.data() + i, 8);
            if (qw < image_base) continue;
            const std::uint64_t target_rva = qw - image_base;
            if (!in_packer(target_rva)) continue;
            const std::uint64_t slot_va = image_base + r.lo_rva + i;
            out[slot_va] = qw;
        }
    }
    return out;
}

std::vector<std::uint64_t> collect_stub_sites(HANDLE process, std::uint64_t image_base, const SectionRange& text, const std::vector<SectionRange>& all) {
    std::vector<std::uint64_t> stubs;
    const std::uint32_t text_size = text.hi_rva - text.lo_rva;
    if (text_size == 0 || text_size > 64u * 1024 * 1024) return stubs;

    std::vector<std::uint8_t> buf(text_size);
    if (!read_remote_bytes(process, image_base + text.lo_rva, buf.data(), buf.size())) {
        log::warn("capture: failed to read .text from runtime");
        return stubs;
    }

    auto in_packer = [&](std::uint32_t rva) {
        for (const auto& r : all) {
            if (r.is_packer && rva >= r.lo_rva && rva < r.hi_rva) return true;
        }
        return false;
    };

    std::unordered_set<std::uint64_t> seen;
    for (std::uint32_t i = 0; i + 5 <= text_size; ++i) {
        const std::uint8_t op = buf[i];
        if (op != 0xE8 && op != 0xE9) continue;
        std::int32_t disp;
        std::memcpy(&disp, buf.data() + i + 1, 4);
        const std::uint64_t insn_end_rva = text.lo_rva + i + 5;
        const std::int64_t tgt_rva = static_cast<std::int64_t>(insn_end_rva) + disp;
        if (tgt_rva < 0) continue;
        const std::uint32_t t = static_cast<std::uint32_t>(tgt_rva);
        if (!in_packer(t)) continue;
        const std::uint64_t stub_va = image_base + t;
        if (seen.insert(stub_va).second) {
            stubs.push_back(stub_va);
        }
    }
    return stubs;
}

bool set_trap_flag(HANDLE thread) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread, &ctx)) return false;
    ctx.EFlags |= 0x100;  // TF
    ctx.ContextFlags = CONTEXT_CONTROL;
    return SetThreadContext(thread, &ctx) != 0;
}

bool read_rip_rsp(HANDLE thread, std::uint64_t& rip, std::uint64_t& rsp) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread, &ctx)) return false;
    rip = ctx.Rip;
    rsp = ctx.Rsp;
    return true;
}

struct ModuleRange {
    std::uint64_t base;
    std::uint64_t end;
    std::string   name;
};

// any loaded module other than the target image
std::vector<ModuleRange> system_module_ranges(HANDLE process, std::uint64_t target_base) {
    std::vector<ModuleRange> out;
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(process, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        return out;
    }
    const DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; ++i) {
        const std::uint64_t base = reinterpret_cast<std::uint64_t>(mods[i]);
        if (base == target_base) continue;
        MODULEINFO mi{};
        if (!GetModuleInformation(process, mods[i], &mi, sizeof(mi))) continue;
        char name[MAX_PATH] = {};
        GetModuleBaseNameA(process, mods[i], name, sizeof(name));
        out.push_back({base, base + mi.SizeOfImage, std::string(name)});
    }
    return out;
}

const ModuleRange* find_module(std::uint64_t rip, const std::vector<ModuleRange>& mods) {
    for (const auto& m : mods) {
        if (rip >= m.base && rip < m.end) return &m;
    }
    return nullptr;
}

bool rip_in_module(std::uint64_t rip, const std::vector<ModuleRange>& mods) {
    for (const auto& m : mods) {
        if (rip >= m.base && rip < m.end) return true;
    }
    return false;
}

/*
   single-step until RIP lands in a system DLL via a tail-jmp (stub's last
   act was `jmp <real_api>`, not `call <wrapper_helper>`). returns 0 on
   no-capture.

   gotchas:
     1. a freshly-resumed remote thread starts at ntdll!RtlUserThreadStart,
        not our requested start address (the OS bootstraps every thread
        through that wrapper). wait for RIP to enter the target image (our
        stub running) before treating system-DLL RIPs as captures.
     2. themida stubs commonly call scaffolding apis (Sleep(0), GetTickCount,
        anti-debug helpers) BEFORE the final dispatch jmp. naively returning
        the first system-DLL RIP catches the wrapper, not the target. anchor
        RSP at the moment we first observe RIP in user code, only accept
        system-DLL transitions where RSP matches that anchor (or is one
        slot below, allowing for a ret addr push some stubs leave on the
        stack). nested call wrappers push further down and fail this check.
 */
std::uint64_t step_until_exit(HANDLE process, HANDLE thread, DWORD remote_tid, const std::vector<ModuleRange>& sys_mods, std::uint64_t target_base, std::uint64_t target_end, DWORD deadline_tick) {
    DEBUG_EVENT ev{};
    std::uint32_t steps = 0;
    bool in_user_yet = false;
    bool prev_in_target = false;
    while (steps < kMaxStepsPerStub) {
        if (GetTickCount() > deadline_tick) {
            log::warn("capture: budget exhausted mid-stub");
            return 0;
        }
        if (!WaitForDebugEvent(&ev, 5'000)) {
            log::warn("capture: WaitForDebugEvent timed out (last err {})", GetLastError());
            return 0;
        }
        DWORD cs = DBG_CONTINUE;

        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const auto& er = ev.u.Exception.ExceptionRecord;
            if (ev.dwThreadId == remote_tid &&
                er.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                std::uint64_t rip = 0, rsp = 0;
                const bool got = read_rip_rsp(thread, rip, rsp);
                const bool in_target = got && rip >= target_base && rip < target_end;
                const bool in_sys = got && rip_in_module(rip, sys_mods);
                if (in_target && !in_user_yet) in_user_yet = true;
                /*
                 * classify only at the exact target->system transition.
                 * [rsp] inside target means stub pushed a return for a
                 * helper call (scaffolding, keep stepping). [rsp] outside
                 * target means stub did a tail jmp to the real api (capture).
                 */
                if (in_user_yet && in_sys && prev_in_target) {
                    std::uint64_t ret_addr = 0;
                    const bool ret_ok = read_remote(process, rsp, ret_addr);
                    const bool scaffolding =
                        ret_ok && ret_addr >= target_base && ret_addr < target_end;
                    if (!scaffolding) {
                        SuspendThread(thread);
                        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                        return rip;
                    }
                }
                prev_in_target = in_target;
                if (!set_trap_flag(thread)) {
                    log::warn("capture: SetThreadContext failed: {}", GetLastError());
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                    return 0;
                }
                ++steps;
                cs = DBG_CONTINUE;
            } else if (ev.dwThreadId == remote_tid) {
                log::debug("capture: remote thread fault 0x{:x} at 0x{:x}, abandoning",
                           er.ExceptionCode,
                           reinterpret_cast<std::uintptr_t>(er.ExceptionAddress));
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                return 0;
            } else {
                cs = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if (ev.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT &&
                   ev.dwThreadId == remote_tid) {
            return 0;
        } else if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            log::warn("capture: target exited mid-capture");
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            return 0;
        }

        if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cs)) {
            log::warn("capture: ContinueDebugEvent failed: {}", GetLastError());
            return 0;
        }
    }
    log::warn("capture: stub exceeded {} steps without leaving image", kMaxStepsPerStub);
    return 0;
}

std::uint64_t capture_one(HANDLE process_handle, std::uint64_t stub_va, const std::vector<ModuleRange>& sys_mods, std::uint64_t target_base, std::uint64_t target_end, DWORD deadline_tick) {
    DWORD tid = 0;
    HANDLE remote = CreateRemoteThread(
        process_handle, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(stub_va),
        nullptr, CREATE_SUSPENDED, &tid);
    if (!remote) {
        log::warn("capture: CreateRemoteThread for stub 0x{:x} failed: {}", stub_va, GetLastError());
        return 0;
    }

    // creating a thread under a debugger queues a CREATE_THREAD_DEBUG_EVENT,
    // pump it before we resume so the loop below sees only steps
    DEBUG_EVENT ev{};
    while (WaitForDebugEvent(&ev, 1'000)) {
        const bool is_create_for_us =
            ev.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT && ev.dwThreadId == tid;
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
        if (is_create_for_us) break;
        if (GetTickCount() > deadline_tick) {
            TerminateThread(remote, 0);
            CloseHandle(remote);
            return 0;
        }
    }

    if (!set_trap_flag(remote)) {
        log::warn("capture: failed to set TF on remote thread: {}", GetLastError());
        TerminateThread(remote, 0);
        CloseHandle(remote);
        return 0;
    }
    ResumeThread(remote);

    const std::uint64_t api_va = step_until_exit(process_handle, remote, tid, sys_mods, target_base, target_end, deadline_tick);

    TerminateThread(remote, 0);
    // drain the EXIT_THREAD from TerminateThread so the queue is clean
    while (WaitForDebugEvent(&ev, 500)) {
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
        if (ev.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT && ev.dwThreadId == tid) break;
    }
    CloseHandle(remote);
    return api_va;
}

}  // namespace

CaptureResult capture_api_landings(void* process_handle, std::uint64_t image_base, std::uint32_t size_of_image) {
    CaptureResult out;
    auto* process = static_cast<HANDLE>(process_handle);

    std::vector<SectionRange> ranges;
    SectionRange text{};
    if (!read_section_table(process, image_base, ranges, text)) {
        log::warn("capture: couldn't read section table from runtime");
        return out;
    }

    const auto call_sites = collect_stub_sites(process, image_base, text, ranges);
    out.slot_to_stub = collect_poisoned_slots(process, image_base, ranges);

    std::unordered_set<std::uint64_t> stub_set;
    for (auto v : call_sites) stub_set.insert(v);
    for (const auto& [slot, stub] : out.slot_to_stub) stub_set.insert(stub);

    if (stub_set.empty()) {
        log::info("capture: no stub call sites or poisoned slots found");
        return out;
    }
    log::info("capture: {} call site(s), {} poisoned slot(s) -> {} unique stub(s)", call_sites.size(), out.slot_to_stub.size(), stub_set.size());

    const std::vector<ModuleRange> sys_mods = system_module_ranges(process, image_base);
    if (sys_mods.empty()) {
        log::warn("capture: failed to enumerate system modules");
        return out;
    }
    const DWORD deadline = GetTickCount() + kTotalBudgetMs;
    const std::uint64_t target_end = image_base + size_of_image;

    std::uint32_t resolved = 0;
    const std::size_t total = stub_set.size();
    for (const auto stub_va : stub_set) {
        if (GetTickCount() > deadline) {
            log::warn("capture: total budget exceeded after {}/{} stubs", resolved, total);
            break;
        }
        const std::uint64_t api_va = capture_one(
            process, stub_va, sys_mods, image_base, target_end, deadline);
        if (api_va) {
            out.stub_to_api[stub_va] = api_va;
            ++resolved;
            const ModuleRange* mod = find_module(api_va, sys_mods);
            if (mod) {
                log::debug("capture: stub 0x{:x} -> api 0x{:x} ({}+0x{:x})", stub_va, api_va, mod->name, api_va - mod->base);
            } else {
                log::debug("capture: stub 0x{:x} -> api 0x{:x} (module unknown)", stub_va, api_va);
            }
        } else {
            log::warn("capture: stub 0x{:x} unresolved", stub_va);
        }
    }
    log::info("capture: resolved {}/{} stub(s)", resolved, total);
    return out;
}

}  // namespace simply
