#include "debugger.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>

#include "simply_log.hpp"

namespace simply {

Debugger::Debugger() = default;

Debugger::~Debugger() { detach(); }

bool Debugger::spawn(const std::filesystem::path& target) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::error_code ec;
    std::filesystem::path abs = std::filesystem::absolute(target, ec);
    if (ec) abs = target;

    const std::wstring app = abs.wstring();
    std::wstring cmdline = app;
    const std::wstring cwd = abs.parent_path().wstring();

    // DEBUG_ONLY_THIS_PROCESS so we don't get dragged into themida's child processes
    BOOL ok = CreateProcessW(app.c_str(), cmdline.data(), nullptr, nullptr, FALSE, DEBUG_ONLY_THIS_PROCESS, nullptr, cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    if (!ok) {
        log::error("CreateProcessW failed: {}", GetLastError());
        return false;
    }

    process_handle_ = pi.hProcess;
    thread_handle_ = pi.hThread;
    process_id_ = pi.dwProcessId;
    thread_id_ = pi.dwThreadId;
    attached_ = true;

    log::info("spawned pid={} tid={}", process_id_, thread_id_);
    return true;
}

namespace {

const char* exception_name(DWORD code) {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:    return "ACCESS_VIOLATION";
        case EXCEPTION_BREAKPOINT:          return "BREAKPOINT";
        case EXCEPTION_SINGLE_STEP:         return "SINGLE_STEP";
        case EXCEPTION_ILLEGAL_INSTRUCTION: return "ILLEGAL_INSTRUCTION";
        case EXCEPTION_PRIV_INSTRUCTION:    return "PRIV_INSTRUCTION";
        case EXCEPTION_GUARD_PAGE:          return "GUARD_PAGE";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:  return "INT_DIVIDE_BY_ZERO";
        case DBG_CONTROL_C:                 return "DBG_CONTROL_C";
        case 0x406D1388:                    return "SET_THREAD_NAME";
        default:                            return "UNKNOWN";
    }
}

}  // namespace

RunResult Debugger::run(const DebuggerCallbacks& callbacks) {
    if (!attached_) {
        log::error("debugger: run() called without a spawned process");
        return RunResult::Error;
    }

    DEBUG_EVENT ev{};
    bool seen_initial_breakpoint = false;

    while (true) {
        if (!WaitForDebugEvent(&ev, INFINITE)) {
            log::error("WaitForDebugEvent failed: {}", GetLastError());
            return RunResult::Error;
        }

        DWORD continue_status = DBG_EXCEPTION_NOT_HANDLED;
        StopReason stop = StopReason::Continue;

        switch (ev.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT: {
                log::debug("CREATE_PROCESS pid={} image_base=0x{:x}", ev.dwProcessId, reinterpret_cast<std::uintptr_t>(ev.u.CreateProcessInfo.lpBaseOfImage));
                if (callbacks.on_process_create) {
                    stop = callbacks.on_process_create(ev.u.CreateProcessInfo);
                }
                if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
                continue_status = DBG_CONTINUE;
                break;
            }

            case LOAD_DLL_DEBUG_EVENT: {
                log::debug("LOAD_DLL base=0x{:x}", reinterpret_cast<std::uintptr_t>(ev.u.LoadDll.lpBaseOfDll));
                if (callbacks.on_dll_load) stop = callbacks.on_dll_load(ev.u.LoadDll);
                if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
                continue_status = DBG_CONTINUE;
                break;
            }

            case UNLOAD_DLL_DEBUG_EVENT:
                continue_status = DBG_CONTINUE;
                break;

            case EXCEPTION_DEBUG_EVENT: {
                const auto& er = ev.u.Exception.ExceptionRecord;
                const bool first_chance = ev.u.Exception.dwFirstChance != 0;
                log::debug("EXCEPTION {} at 0x{:x} first_chance={}", exception_name(er.ExceptionCode), reinterpret_cast<std::uintptr_t>(er.ExceptionAddress), first_chance);

                if (er.ExceptionCode == EXCEPTION_BREAKPOINT && !seen_initial_breakpoint) {
                    seen_initial_breakpoint = true;
                    continue_status = DBG_CONTINUE;
                } else if (callbacks.on_exception) {
                    stop = callbacks.on_exception(ev.u.Exception, ev.dwThreadId);
                    // Handled means we own it, anything else lets target SEH run (themida needs it)
                    continue_status = (stop == StopReason::Handled) ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
                }
                break;
            }

            case EXIT_PROCESS_DEBUG_EVENT:
                log::info("target exited with code {}", ev.u.ExitProcess.dwExitCode);
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                return RunResult::ProcessExited;

            case EXIT_THREAD_DEBUG_EVENT:
                if (callbacks.on_thread_exit) {
                    stop = callbacks.on_thread_exit(ev.u.ExitThread, ev.dwThreadId);
                }
                continue_status = DBG_CONTINUE;
                break;

            case CREATE_THREAD_DEBUG_EVENT:
            case OUTPUT_DEBUG_STRING_EVENT:
            case RIP_EVENT:
            default:
                continue_status = DBG_CONTINUE;
                break;
        }

        // leave the OEP fault un-continued so we can dump memory before releasing it
        if (stop == StopReason::OepReached) {
            pending_pid_ = ev.dwProcessId;
            pending_tid_ = ev.dwThreadId;
            has_pending_continue_ = true;
            return RunResult::OepReached;
        }

        if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continue_status)) {
            log::error("ContinueDebugEvent failed: {}", GetLastError());
            return RunResult::Error;
        }

        if (stop == StopReason::Abort) return RunResult::Error;
    }
}

bool Debugger::release_pending(DWORD continue_status) {
    if (!has_pending_continue_) return true;
    if (!ContinueDebugEvent(pending_pid_, pending_tid_, continue_status)) {
        log::error("release_pending: ContinueDebugEvent failed: {}", GetLastError());
        return false;
    }
    has_pending_continue_ = false;
    return true;
}

void Debugger::detach() {
    if (!attached_) return;
    if (has_pending_continue_) {
        ContinueDebugEvent(pending_pid_, pending_tid_, DBG_CONTINUE);
        has_pending_continue_ = false;
    }
    if (process_id_ != 0) DebugActiveProcessStop(process_id_);
    if (thread_handle_) { CloseHandle(thread_handle_); thread_handle_ = nullptr; }
    if (process_handle_) { CloseHandle(process_handle_); process_handle_ = nullptr; }
    attached_ = false;
}

}  // namespace simply
