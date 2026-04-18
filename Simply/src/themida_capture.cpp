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
#include <unordered_map>
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

// events per stub: one CC hit per entered export. scaffolding chains
// can easily ring up a few hundred, bound it so a pathological stub
// can't pin us
constexpr std::uint32_t kMaxEventsPerStub = 8192;

// wall budget per stub in case scaffolding does a blocking wait
constexpr DWORD kPerStubBudgetMs = 5'000;

// total wall budget so nothing pathological pins the host forever
constexpr DWORD kTotalBudgetMs = 60'000;

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

bool write_remote_byte(HANDLE process, std::uint64_t addr, std::uint8_t b) {
    SIZE_T n = 0;
    return WriteProcessMemory(process, reinterpret_cast<LPVOID>(addr), &b, 1, &n) && n == 1;
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

/*
   plant 0xCC at every exported function in every external module. themida
   stubs dispatch to real apis via tail-jmp; the api's first byte is the CC
   that raises EXCEPTION_BREAKPOINT and pins the landing in one event
   instead of millions of single-steps.

   forwarded exports (AddressOfFunctions entry that falls inside the export
   directory blob) are RVAs of forwarder strings, not code, so skip them.
 */
std::unordered_map<std::uint64_t, std::uint8_t>
plant_export_breakpoints(HANDLE process, const std::vector<ModuleRange>& mods) {
    std::unordered_map<std::uint64_t, std::uint8_t> out;
    for (const auto& m : mods) {
        IMAGE_DOS_HEADER dos{};
        if (!read_remote(process, m.base, dos)) continue;
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) continue;
        IMAGE_NT_HEADERS64 nt{};
        if (!read_remote(process, m.base + dos.e_lfanew, nt)) continue;
        if (nt.Signature != IMAGE_NT_SIGNATURE) continue;
        const auto& dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!dd.Size || !dd.VirtualAddress) continue;
        IMAGE_EXPORT_DIRECTORY exp{};
        if (!read_remote(process, m.base + dd.VirtualAddress, exp)) continue;
        if (!exp.NumberOfFunctions || exp.NumberOfFunctions > (1u << 20)) continue;
        std::vector<DWORD> rvas(exp.NumberOfFunctions);
        if (!read_remote_bytes(process, m.base + exp.AddressOfFunctions,
                               rvas.data(), rvas.size() * sizeof(DWORD))) continue;
        const DWORD exp_lo = dd.VirtualAddress;
        const DWORD exp_hi = dd.VirtualAddress + dd.Size;
        for (DWORD r : rvas) {
            if (!r) continue;
            if (r >= exp_lo && r < exp_hi) continue;  // forwarder string
            const std::uint64_t va = m.base + r;
            if (out.count(va)) continue;
            std::uint8_t orig = 0;
            if (!read_remote(process, va, orig)) continue;
            if (orig == 0xCC) continue;  // somebody else's trap, leave alone
            if (!write_remote_byte(process, va, 0xCC)) continue;
            out[va] = orig;
        }
    }
    FlushInstructionCache(process, nullptr, 0);
    return out;
}

void restore_export_breakpoints(HANDLE process,
                                const std::unordered_map<std::uint64_t, std::uint8_t>& bps) {
    for (const auto& [va, orig] : bps) {
        write_remote_byte(process, va, orig);
    }
    FlushInstructionCache(process, nullptr, 0);
}

// DR0 one-shot exec BP on stub entry so we can anchor rsp AT the stub's
// first byte without the ntdll bootstrap (which may hit planted CCs on
// its own way into stub) polluting the anchor.
bool arm_dr0(HANDLE thread, std::uint64_t va) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) return false;
    ctx.Dr0 = va;
    ctx.Dr6 = 0;
    // clear slot 0 fields (L0, G0, L/R type+len), set L0=1 (exec, len=1 -> all zeros)
    ctx.Dr7 &= ~(0x000F0003ULL);
    ctx.Dr7 |= 0x00000001ULL;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return SetThreadContext(thread, &ctx) != 0;
}

/*
   run the stub once and catch the landing via the planted CC carpet.

   flow:
     pre-anchor:
       spawn suspended at stub_va, arm DR0 at stub_va so we can pin the
       stub's actual entry rsp. any CC hits that come in during ntdll's
       bootstrap are nested by definition -> restore/TF/replant, don't
       classify.
     anchor:
       DR0 fires as SINGLE_STEP at RIP==stub_va. snapshot rsp, that's our
       anchor_rsp. clear DR0. switch phase.
     anchored:
       each CC hit at an api entry:
         rsp == anchor_rsp AND [rsp] outside target -> tail-jmp capture.
         else -> scaffolding or nested api->api:
           rewind RIP, restore original byte, set TF, continue. on the
           following SINGLE_STEP, replant CC at that va and clear pending.

   capture logic mirrors the original TF design: ret_addr in target vs not,
   just implemented on top of CC events. rsp equality gates out nested
   api->api transitions (inside Sleep calls NtDelayExecution) that'd
   otherwise look like tail-jmps.
 */
enum class Phase { PreAnchor, Anchored };

std::uint64_t capture_one(HANDLE process_handle, std::uint64_t stub_va,
                          const std::unordered_map<std::uint64_t, std::uint8_t>& bps,
                          std::uint64_t target_base, std::uint64_t target_end,
                          DWORD deadline_tick) {
    DWORD tid = 0;
    HANDLE remote = CreateRemoteThread(
        process_handle, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(stub_va),
        nullptr, CREATE_SUSPENDED, &tid);
    if (!remote) {
        log::warn("capture: CreateRemoteThread for stub 0x{:x} failed: {}", stub_va, GetLastError());
        return 0;
    }

    /*
       don't drain CREATE_THREAD_DEBUG_EVENT here. on CREATE_SUSPENDED it
       may not queue until ResumeThread, which burns the full 1s timeout
       for every stub. SetThreadContext works on suspended threads without
       the thread having entered the debugger's attention yet, so arm DR0
       now, resume, and handle CREATE_THREAD in the main event loop as a
       pass-through.
     */
    if (!arm_dr0(remote, stub_va)) {
        log::warn("capture: arm_dr0 failed on remote thread: {}", GetLastError());
        TerminateThread(remote, 0);
        CloseHandle(remote);
        return 0;
    }
    ResumeThread(remote);
    DEBUG_EVENT ev{};

    Phase phase = Phase::PreAnchor;
    std::uint64_t anchor_rsp = 0;
    std::uint64_t pending_replant = 0;
    std::uint32_t events = 0;
    std::uint64_t captured = 0;
    const DWORD per_stub_deadline = (std::min)(
        static_cast<DWORD>(GetTickCount() + kPerStubBudgetMs), deadline_tick);

    while (events < kMaxEventsPerStub && captured == 0) {
        if (GetTickCount() > per_stub_deadline) {
            log::debug("capture: per-stub budget exhausted for 0x{:x}", stub_va);
            break;
        }
        if (!WaitForDebugEvent(&ev, 1'000)) {
            // thread may be blocked in a scaffolding api; abandon this stub
            log::debug("capture: WaitForDebugEvent idle on stub 0x{:x}", stub_va);
            break;
        }
        DWORD cs = DBG_CONTINUE;

        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const auto& er = ev.u.Exception.ExceptionRecord;
            const std::uint64_t exc_addr =
                reinterpret_cast<std::uint64_t>(er.ExceptionAddress);
            const bool ours = (ev.dwThreadId == tid);

            if (ours && er.ExceptionCode == EXCEPTION_BREAKPOINT) {
                auto it = bps.find(exc_addr);
                if (it != bps.end()) {
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                    if (!GetThreadContext(remote, &ctx)) {
                        cs = DBG_CONTINUE;
                    } else {
                        // CC fired with RIP one past the byte; rewind so the
                        // restored instruction executes from its real head
                        ctx.Rip = exc_addr;

                        bool do_capture = false;
                        if (phase == Phase::Anchored && ctx.Rsp == anchor_rsp) {
                            std::uint64_t ret_addr = 0;
                            const bool ok = read_remote(process_handle, ctx.Rsp, ret_addr);
                            const bool scaffolding =
                                ok && ret_addr >= target_base && ret_addr < target_end;
                            if (!scaffolding) do_capture = true;
                        }

                        if (do_capture) {
                            captured = exc_addr;
                            // suspend before continue so the thread stays
                            // frozen at the BP after we release the debug
                            // wait; terminate then fires EXIT_THREAD cleanly
                            // without the CC-at-RIP retry loop
                            SuspendThread(remote);
                            ctx.ContextFlags = CONTEXT_CONTROL;
                            SetThreadContext(remote, &ctx);
                        } else {
                            // scaffolding (stub -> api) or nested (api -> api)
                            // or pre-anchor bootstrap CC: restore byte, TF, and
                            // replant after the one-step
                            write_remote_byte(process_handle, exc_addr, it->second);
                            ctx.EFlags |= 0x100;
                            ctx.ContextFlags = CONTEXT_CONTROL;
                            SetThreadContext(remote, &ctx);
                            pending_replant = exc_addr;
                        }
                    }
                } else {
                    // not one of ours; let the target's SEH see it
                    cs = DBG_EXCEPTION_NOT_HANDLED;
                }
                ++events;
            } else if (ours && er.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                if (phase == Phase::PreAnchor) {
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(remote, &ctx) && ctx.Rip == stub_va) {
                        // DR0 fired at stub entry, this is our anchor
                        anchor_rsp = ctx.Rsp;
                        phase = Phase::Anchored;
                        ctx.Dr0 = 0;
                        ctx.Dr6 = 0;
                        ctx.Dr7 &= ~(0x000F0003ULL);
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        SetThreadContext(remote, &ctx);
                    }
                }
                // TF fires after we restore a CC and step one instruction,
                // regardless of phase. replant if we have one pending.
                if (pending_replant) {
                    write_remote_byte(process_handle, pending_replant, 0xCC);
                    pending_replant = 0;
                }
                ++events;
            } else if (ours) {
                // remote thread took an unrelated fault: just bail
                log::debug("capture: stub 0x{:x} faulted 0x{:x} at 0x{:x}",
                           stub_va, er.ExceptionCode, exc_addr);
                cs = DBG_CONTINUE;
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cs);
                break;
            } else {
                cs = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if (ev.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT &&
                   ev.dwThreadId == tid) {
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            break;
        } else if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            log::warn("capture: target exited mid-capture");
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            CloseHandle(remote);
            return 0;
        }

        if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cs)) {
            log::warn("capture: ContinueDebugEvent failed: {}", GetLastError());
            break;
        }
    }

    // if we captured (or gave up) while a restore was outstanding, put the
    // CC back before any other thread could execute that api
    if (pending_replant) {
        write_remote_byte(process_handle, pending_replant, 0xCC);
        pending_replant = 0;
    }

    TerminateThread(remote, 0);
    while (WaitForDebugEvent(&ev, 100)) {
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
        if (ev.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT && ev.dwThreadId == tid) break;
    }
    CloseHandle(remote);
    return captured;
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

    const DWORD plant_start = GetTickCount();
    const auto bps = plant_export_breakpoints(process, sys_mods);
    if (bps.empty()) {
        log::warn("capture: couldn't plant any export breakpoints");
        return out;
    }
    log::info("capture: planted {} export breakpoints across {} module(s) in {}ms",
              bps.size(), sys_mods.size(), GetTickCount() - plant_start);

    /*
       strip PAGE_EXECUTE on .text for the duration of capture. main.cpp
       disarms the OEP DEP trap before calling us (the TF-step approach
       expected to walk through .text helpers freely); with the CC approach
       we run stubs at native speed between events, so a stub that tail-jmps
       into user code (the CRT bootstrap dispatcher among the poisoned
       slots will literally run main) would race the program to completion.
       strip exec here, treat an AV in our remote thread as "stub dispatched
       into user code" and abandon that stub. the AV is naturally handled
       by the generic unrelated-fault arm in capture_one.
     */
    const std::uint64_t text_va = image_base + text.lo_rva;
    const std::uint32_t text_size = text.hi_rva - text.lo_rva;
    DWORD old_text_prot = 0;
    const bool text_stripped = VirtualProtectEx(
        process, reinterpret_cast<LPVOID>(text_va), text_size,
        PAGE_READONLY, &old_text_prot) != 0;
    if (!text_stripped) {
        log::warn("capture: couldn't strip .text exec for guard: {}", GetLastError());
    }

    const DWORD deadline = GetTickCount() + kTotalBudgetMs;
    const std::uint64_t target_end = image_base + size_of_image;

    std::uint32_t resolved = 0;
    const std::size_t total = stub_set.size();
    const DWORD capture_start = GetTickCount();
    std::uint32_t consecutive_thread_failures = 0;
    for (const auto stub_va : stub_set) {
        if (GetTickCount() > deadline) {
            log::warn("capture: total budget exceeded after {}/{} stubs", resolved, total);
            break;
        }
        const std::uint64_t api_va = capture_one(
            process, stub_va, bps, image_base, target_end, deadline);
        if (api_va) {
            out.stub_to_api[stub_va] = api_va;
            ++resolved;
            consecutive_thread_failures = 0;
            const ModuleRange* mod = find_module(api_va, sys_mods);
            if (mod) {
                log::debug("capture: stub 0x{:x} -> api 0x{:x} ({}+0x{:x})", stub_va, api_va, mod->name, api_va - mod->base);
            } else {
                log::debug("capture: stub 0x{:x} -> api 0x{:x} (module unknown)", stub_va, api_va);
            }
        } else {
            log::warn("capture: stub 0x{:x} unresolved", stub_va);
            // CreateRemoteThread returning ACCESS_DENIED in a row means the
            // target is dying (one of our spawned stub threads called something
            // fatal). bail so we don't spin through the rest of the queue
            DWORD exit_code = 0;
            if (GetExitCodeProcess(process, &exit_code) && exit_code != STILL_ACTIVE) {
                log::warn("capture: target process exited (code 0x{:x}) after {}/{} stubs - bailing",
                          exit_code, resolved, total);
                break;
            }
            if (++consecutive_thread_failures >= 8) {
                log::warn("capture: {} consecutive remote-thread failures, target likely dying - bailing after {}/{} stubs",
                          consecutive_thread_failures, resolved, total);
                break;
            }
        }
    }
    log::info("capture: resolved {}/{} stub(s) in {}ms",
              resolved, total, GetTickCount() - capture_start);

    if (text_stripped) {
        DWORD tmp = 0;
        VirtualProtectEx(process, reinterpret_cast<LPVOID>(text_va), text_size,
                         old_text_prot, &tmp);
    }
    restore_export_breakpoints(process, bps);
    return out;
}

}  // namespace simply
