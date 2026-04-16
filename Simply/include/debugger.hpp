#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>

struct _CREATE_PROCESS_DEBUG_INFO;
struct _LOAD_DLL_DEBUG_INFO;
struct _EXCEPTION_DEBUG_INFO;
struct _EXIT_THREAD_DEBUG_INFO;
struct _DEBUG_EVENT;

namespace simply {

enum class RunResult {
    OepReached,
    ProcessExited,
    Error,
};

enum class StopReason {
    // DBG_EXCEPTION_NOT_HANDLED so target SEH runs (themida needs it)
    Continue,
    // DBG_CONTINUE, only for faults we caused ourselves
    Handled,
    OepReached,
    Abort,
};

struct DebuggerCallbacks {
    std::function<StopReason(const _CREATE_PROCESS_DEBUG_INFO&)> on_process_create;
    std::function<StopReason(const _LOAD_DLL_DEBUG_INFO&)> on_dll_load;
    std::function<StopReason(const _EXCEPTION_DEBUG_INFO&, std::uint32_t thread_id)> on_exception;
    std::function<StopReason(const _EXIT_THREAD_DEBUG_INFO&, std::uint32_t thread_id)> on_thread_exit;
};

class Debugger {
public:
    Debugger();
    ~Debugger();

    Debugger(const Debugger&) = delete;
    Debugger& operator=(const Debugger&) = delete;

    bool spawn(const std::filesystem::path& target);
    RunResult run(const DebuggerCallbacks& callbacks);
    void detach();

    void* process_handle() const { return process_handle_; }
    std::uint32_t process_id() const { return process_id_; }
    std::uint32_t thread_id() const { return thread_id_; }

    // releases the OEP fault that run() left un-continued. caller must suspend the primary thread first
    bool release_pending(unsigned long continue_status);

    bool has_pending() const { return has_pending_continue_; }
    std::uint32_t pending_pid() const { return pending_pid_; }
    std::uint32_t pending_tid() const { return pending_tid_; }

private:
    void* process_handle_ = nullptr;
    void* thread_handle_ = nullptr;
    std::uint32_t process_id_ = 0;
    std::uint32_t thread_id_ = 0;
    bool attached_ = false;

    bool has_pending_continue_ = false;
    std::uint32_t pending_pid_ = 0;
    std::uint32_t pending_tid_ = 0;
};

}  // namespace simply
