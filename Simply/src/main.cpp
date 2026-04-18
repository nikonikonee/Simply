#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include "debugger.hpp"
#include "dumper.hpp"
#include "injector.hpp"
#include "oep_finder.hpp"
#include "pe_inspector.hpp"
#include "peb_patcher.hpp"
#include "simply_log.hpp"
#include "themida_capture.hpp"

namespace {

constexpr std::string_view kVersion = "0.1.0";

void print_banner() {
    SetConsoleOutputCP(CP_UTF8);
    simply::log::info("\xe2\x96\x84\xe2\x96\x96\xe2\x96\x98     \xe2\x96\x9c   ");
    simply::log::info("\xe2\x96\x9a \xe2\x96\x8c\xe2\x96\x9b\xe2\x96\x9b\xe2\x96\x8c\xe2\x96\x9b\xe2\x96\x8c\xe2\x96\x90 \xe2\x96\x8c\xe2\x96\x8c");
    simply::log::info("\xe2\x96\x84\xe2\x96\x8c\xe2\x96\x8c\xe2\x96\x8c\xe2\x96\x8c\xe2\x96\x8c\xe2\x96\x99\xe2\x96\x8c\xe2\x96\x90\xe2\x96\x96\xe2\x96\x99\xe2\x96\x8c - v{}", kVersion);
    simply::log::info("      \xe2\x96\x8c   \xe2\x96\x84\xe2\x96\x8c");
}


void print_usage(const char* argv0) {
    std::cerr << "usage: " << argv0 << " <input.exe> <output.bin> [--verbose]\n";
}

// SimplyBypass.dll ships next to Simply.exe
std::filesystem::path bypass_dll_path() {
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n == MAX_PATH) return {};
    return std::filesystem::path(buf).parent_path() / L"SimplyBypass.dll";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    std::filesystem::path input = argv[1];
    std::filesystem::path output = argv[2];

    for (int i = 3; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--verbose" || arg == "-v") {
            simply::log::verbose = true;
        } else {
            std::cerr << "unknown argument: " << arg << '\n';
            return EXIT_FAILURE;
        }
    }

    print_banner();

    if (!std::filesystem::exists(input)) {
        simply::log::error("input not found: {}", input.string());
        return EXIT_FAILURE;
    }

    simply::log::info("input:  {}", input.string());
    simply::log::info("output: {}", output.string());

    auto info = simply::inspect_pe(input);
    if (!info) return EXIT_FAILURE;

    const std::filesystem::path dll = bypass_dll_path();
    if (dll.empty() || !std::filesystem::exists(dll)) {
        simply::log::error("bypass dll not found next to Simply.exe: {}", dll.string());
        return EXIT_FAILURE;
    }

    simply::Debugger dbg;
    if (!dbg.spawn(input)) return EXIT_FAILURE;

    simply::Injection injection{};
    HANDLE primary_thread = nullptr;
    simply::OepTrap trap{};
    std::uint64_t runtime_image_base = 0;
    std::uint64_t oep_va = 0;
    /*
     * EPV thunk bookkeeping. when classify_fault flags a virtualized prologue
     * we strip DEP, set TF, then expect a SINGLE_STEP after the JMP rel32
     * executes. that's our cue to re-arm DEP so the next .text fetch (post-VM)
     * fires as the real OEP. thunk_va lets us drop a defensive log if the same
     * thunk re-classifies as RealOep (shouldn't happen but cheap to guard)
     */
    bool pending_thunk_step = false;
    std::uint64_t thunk_va = 0;

    simply::DebuggerCallbacks cb{};

    cb.on_process_create = [&](const _CREATE_PROCESS_DEBUG_INFO& cpi) {
        primary_thread = cpi.hThread;
        SuspendThread(primary_thread);

        simply::patch_peb(dbg.process_handle());
        simply::strip_debug_privilege(dbg.process_handle());

        runtime_image_base = reinterpret_cast<std::uint64_t>(cpi.lpBaseOfImage);
        if (info->text_virtual_size > 0) {
            trap.text_base = runtime_image_base + info->text_rva;
            trap.text_size = info->text_virtual_size;
        }
        trap.image_base = runtime_image_base;
        trap.image_size = info->size_of_image;

        injection = simply::start_dll_injection(dbg.process_handle(), dll);
        if (!injection.started) {
            simply::log::error("bypass injection failed to start");
            return simply::StopReason::Abort;
        }
        return simply::StopReason::Continue;
    };

    cb.on_thread_exit = [&](const _EXIT_THREAD_DEBUG_INFO&, std::uint32_t tid) {
        if (!injection.started || tid != injection.remote_thread_id) {
            return simply::StopReason::Continue;
        }
        if (!simply::finalize_injection(dbg.process_handle(), injection)) {
            return simply::StopReason::Abort;
        }
        simply::arm_oep_trap(dbg.process_handle(), trap);
        if (primary_thread) ResumeThread(primary_thread);
        return simply::StopReason::Continue;
    };

    cb.on_exception = [&](const _EXCEPTION_DEBUG_INFO& ex, std::uint32_t tid) {
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);

        /*
         * claim pending TF steps from the EPV thunk path before classify_fault
         * sees them. classify_fault doesn't know about the thunk-step state
         * machine, so without this the SINGLE_STEP gets misread as Unrelated
         * and reflected into the target's SEH
         */
        if (pending_thunk_step &&
            ex.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
            pending_thunk_step = false;
            simply::set_trap_flag(thread, false);
            simply::arm_oep_trap(dbg.process_handle(), trap);
            simply::log::debug("oep: stepped past thunk 0x{:x}, re-armed DEP; awaiting real OEP", thunk_va);
            if (thread) CloseHandle(thread);
            return simply::StopReason::Handled;
        }

        const auto info = simply::classify_fault(ex, trap, dbg.process_handle(), thread);
        simply::StopReason reason = simply::StopReason::Continue;
        switch (info.kind) {
            case simply::OepFaultKind::RealOep:
                oep_va = info.fault_va;
                simply::log::info("OEP reached at 0x{:x}", oep_va);
                reason = simply::StopReason::OepReached;
                break;
            case simply::OepFaultKind::VirtualizedThunk:
                /*
                 * Themida Pro EPV: first .text fetch is a JMP into a runtime
                 * VM region. let the JMP execute (TF), re-arm DEP after it
                 * lands in the VM, and the post-VM fetch back into .text
                 * surfaces as the real OEP
                 */
                simply::log::info("OEP candidate at 0x{:x} is an EPV thunk -> 0x{:x}; stepping through VM", info.fault_va, info.return_va);
                simply::disarm_oep_trap(dbg.process_handle(), trap);
                if (!simply::set_trap_flag(thread, true)) {
                    simply::log::error("oep: failed to set TF, cannot bypass virtualized OEP");
                    reason = simply::StopReason::Abort;
                    break;
                }
                pending_thunk_step = true;
                thunk_va = info.fault_va;
                reason = simply::StopReason::Handled;
                break;
            case simply::OepFaultKind::VmSubcall:
                // VM called into .text, let it run and re-arm once it returns to .themida
                simply::disarm_oep_trap(dbg.process_handle(), trap);
                simply::set_return_bp(dbg.process_handle(), trap, thread, info.return_va);
                reason = simply::StopReason::Handled;
                break;
            case simply::OepFaultKind::ReturnBp:
                simply::clear_return_bp(dbg.process_handle(), trap, thread);
                simply::arm_oep_trap(dbg.process_handle(), trap);
                reason = simply::StopReason::Handled;
                break;
            case simply::OepFaultKind::Unrelated:
                // leave reason = Continue so the target's SEH sees the fault
                break;
        }
        if (thread) CloseHandle(thread);
        return reason;
    };

    const auto result = dbg.run(cb);
    switch (result) {
        case simply::RunResult::OepReached: {
            simply::CaptureResult capture;
            /*
             * freeze every existing thread in the target before releasing the
             * OEP exception. SuspendThread on cpi.hThread alone didn't hold
             * the target, either the handle was stale or a sibling thread was
             * executing main. enumerate and suspend them all
             */
            std::vector<HANDLE> pinned;
            {
                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (snap == INVALID_HANDLE_VALUE) {
                    simply::log::error("snapshot failed: {}", GetLastError());
                    TerminateProcess(dbg.process_handle(), 1);
                    return EXIT_FAILURE;
                }
                THREADENTRY32 te{}; te.dwSize = sizeof(te);
                if (Thread32First(snap, &te)) {
                    do {
                        if (te.th32OwnerProcessID != dbg.process_id()) continue;
                        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                        if (!h) continue;
                        if (SuspendThread(h) == static_cast<DWORD>(-1)) {
                            CloseHandle(h);
                            continue;
                        }
                        pinned.push_back(h);
                    } while (Thread32Next(snap, &te));
                }
                CloseHandle(snap);
            }
            simply::log::debug("capture: suspended {} existing thread(s)", pinned.size());
            // disarm DEP so a remote thread straying into .text doesn't fault mid-step
            simply::disarm_oep_trap(dbg.process_handle(), trap);
            /*
             * snapshot the entire image NOW, before capture runs anything. capture
             * spawns remote threads that can crash the target (themida watchdogs,
             * stub bodies that ExitProcess out of context, etc). taking the bytes
             * here means the dump survives even if capture takes the process down.
             * threads are still suspended so .data is pristine for the snapshot.
             */
            std::vector<std::uint8_t> image_snapshot = simply::snapshot_image(
                dbg.process_handle(), runtime_image_base, info->size_of_image);
            /*
             * snapshot the loaded modules + their export tables here too. if
             * capture kills the target, EnumProcessModulesEx fails 299 against
             * a dead handle and the entire IAT pipeline silently no-ops,
             * leaving runtime API VAs baked into the dumped code. taking it
             * before capture means rebuild_iat / extend / rebind all still
             * work on a dead process.
             */
            simply::ModuleSnapshotPtr module_snap = simply::snapshot_modules(dbg.process_handle());
            if (!module_snap) {
                simply::log::error("failed to snapshot target modules; cannot rebuild imports");
                for (HANDLE h : pinned) CloseHandle(h);
                TerminateProcess(dbg.process_handle(), 1);
                return EXIT_FAILURE;
            }
            if (!dbg.release_pending(DBG_CONTINUE)) {
                simply::log::warn("couldn't release OEP fault, skipping capture");
            } else {
                capture = simply::capture_api_landings(dbg.process_handle(), runtime_image_base, info->size_of_image);
            }
            for (HANDLE h : pinned) CloseHandle(h);
            if (!simply::dump_image(*module_snap, std::move(image_snapshot), runtime_image_base, info->image_base, info->size_of_image, oep_va, output, &capture)) {
                TerminateProcess(dbg.process_handle(), 1);
                return EXIT_FAILURE;
            }
            // primary thread is suspended and we've drained the OEP event; detach would zombie
            TerminateProcess(dbg.process_handle(), 0);
            break;
        }
        case simply::RunResult::ProcessExited:
            simply::log::warn("process exited before OEP");
            break;
        case simply::RunResult::Error:
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
