#include "oep_finder.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "simply_log.hpp"

namespace simply {

bool arm_oep_trap(void* process_handle, OepTrap& trap) {
    if (trap.text_base == 0 || trap.text_size == 0) {
        log::error("oep: trap range is empty, cannot arm");
        return false;
    }

    auto* process = static_cast<HANDLE>(process_handle);
    DWORD old = 0;
    const BOOL ok = VirtualProtectEx(process, reinterpret_cast<LPVOID>(trap.text_base), trap.text_size, PAGE_READWRITE, &old);
    if (!ok) {
        log::error("oep: VirtualProtectEx failed: {}", GetLastError());
        return false;
    }
    trap.armed = true;
    log::debug("oep: armed trap at 0x{:x} size=0x{:x} (was prot=0x{:x})",
               trap.text_base, trap.text_size, old);
    return true;
}

bool disarm_oep_trap(void* process_handle, OepTrap& trap) {
    auto* process = static_cast<HANDLE>(process_handle);
    DWORD old = 0;
    const BOOL ok = VirtualProtectEx(process, reinterpret_cast<LPVOID>(trap.text_base), trap.text_size, PAGE_EXECUTE_READ, &old);
    trap.armed = false;
    if (!ok) {
        log::warn("oep: disarm VirtualProtectEx failed: {}", GetLastError());
        return false;
    }
    return true;
}

bool set_return_bp(void* process_handle, OepTrap& trap, void* thread_handle, std::uint64_t addr) {
    (void)process_handle;
    auto* thread = static_cast<HANDLE>(thread_handle);
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) {
        log::warn("oep: set_return_bp: GetThreadContext failed: {}", GetLastError());
        return false;
    }
    ctx.Dr0 = addr;
    // DR7: enable L0, clear RW0/LEN0 so length=1 type=exec
    ctx.Dr7 = (ctx.Dr7 & ~static_cast<DWORD64>(0xF0003)) | 0x1;
    ctx.Dr6 = 0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!SetThreadContext(thread, &ctx)) {
        log::warn("oep: set_return_bp: SetThreadContext failed: {}", GetLastError());
        return false;
    }
    trap.bp_addr = addr;
    trap.bp_active = true;
    return true;
}

bool clear_return_bp(void* process_handle, OepTrap& trap, void* thread_handle) {
    (void)process_handle;
    if (!trap.bp_active) return true;
    auto* thread = static_cast<HANDLE>(thread_handle);
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) {
        log::warn("oep: clear_return_bp: GetThreadContext failed: {}", GetLastError());
        trap.bp_active = false;
        return false;
    }
    ctx.Dr0 = 0;
    ctx.Dr7 &= ~static_cast<DWORD64>(0xF0003);
    ctx.Dr6 = 0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!SetThreadContext(thread, &ctx)) {
        log::warn("oep: clear_return_bp: SetThreadContext failed: {}", GetLastError());
    }
    trap.bp_active = false;
    return true;
}

bool set_trap_flag(void* thread_handle, bool enable) {
    auto* thread = static_cast<HANDLE>(thread_handle);
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread, &ctx)) {
        log::warn("oep: set_trap_flag: GetThreadContext failed: {}", GetLastError());
        return false;
    }
    if (enable) {
        ctx.EFlags |= 0x100;
    } else {
        ctx.EFlags &= ~static_cast<DWORD>(0x100);
    }
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!SetThreadContext(thread, &ctx)) {
        log::warn("oep: set_trap_flag: SetThreadContext failed: {}", GetLastError());
        return false;
    }
    return true;
}

OepFaultInfo classify_fault(const _EXCEPTION_DEBUG_INFO& ex, const OepTrap& trap, void* process_handle, void* thread_handle) {
    OepFaultInfo out{};
    const auto& er = ex.ExceptionRecord;

    // HW BP hits surface as SINGLE_STEP, not BREAKPOINT. RIP is AT the BP so no rewind
    if (trap.bp_active && er.ExceptionCode == EXCEPTION_SINGLE_STEP) {
        const auto addr = reinterpret_cast<std::uint64_t>(er.ExceptionAddress);
        if (addr == trap.bp_addr) {
            out.kind = OepFaultKind::ReturnBp;
            out.fault_va = addr;
            return out;
        }
    }

    if (!trap.armed) return out;
    if (er.ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return out;
    if (er.NumberParameters < 2) return out;

    const ULONG_PTR access_type = er.ExceptionInformation[0];
    const ULONG_PTR fault_va    = er.ExceptionInformation[1];
    if (access_type != 8) return out;  // not a DEP fault
    if (fault_va < trap.text_base || fault_va >= trap.text_base + trap.text_size) return out;

    out.fault_va = fault_va;

    auto* process = static_cast<HANDLE>(process_handle);
    auto* thread  = static_cast<HANDLE>(thread_handle);

    /*
     * Themida Pro EPV plants a JMP rel32 at the OEP that lands in a runtime
     * VM allocation past SizeOfImage; the prologue body lives in the VM, not
     * in .text. without this peek we'd freeze the snapshot at the thunk and
     * emit a dump whose entry-point jumps into a region that no longer exists
     * outside the live process
     */
    {
        unsigned char insn[5] = {};
        SIZE_T got = 0;
        if (ReadProcessMemory(process, reinterpret_cast<LPCVOID>(fault_va),
                              insn, sizeof(insn), &got) && got == sizeof(insn)
            && insn[0] == 0xE9) {
            std::int32_t disp = static_cast<std::int32_t>(
                static_cast<std::uint32_t>(insn[1]) |
                (static_cast<std::uint32_t>(insn[2]) << 8) |
                (static_cast<std::uint32_t>(insn[3]) << 16) |
                (static_cast<std::uint32_t>(insn[4]) << 24));
            const std::uint64_t tgt = fault_va + 5 + static_cast<std::int64_t>(disp);
            if (tgt < trap.text_base || tgt >= trap.text_base + trap.text_size) {
                out.kind = OepFaultKind::VirtualizedThunk;
                out.return_va = tgt;
                log::debug("oep: virtualized thunk at 0x{:x} -> 0x{:x} (outside .text)",
                           fault_va, tgt);
                return out;
            }
        }
    }

    /*
     * peek [rsp] to tell a real OEP apart from a VM sub-call. EPV virtualizes
     * the prologue, and the VM also does ordinary calls into .text (e.g.
     * __security_init_cookie) which look identical without this check
     */
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(thread, &ctx)) {
        log::warn("oep: GetThreadContext failed, treating as OEP");
        out.kind = OepFaultKind::RealOep;
        return out;
    }

    std::uint64_t ret_addr = 0;
    SIZE_T n = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(ctx.Rsp),
                           &ret_addr, sizeof(ret_addr), &n) || n != sizeof(ret_addr)) {
        log::warn("oep: ReadProcessMemory([rsp]=0x{:x}) failed, treating as OEP", ctx.Rsp);
        out.kind = OepFaultKind::RealOep;
        return out;
    }

    const std::uint64_t image_lo = trap.image_base;
    const std::uint64_t image_hi = trap.image_base + trap.image_size;
    const std::uint64_t text_lo  = trap.text_base;
    const std::uint64_t text_hi  = trap.text_base + trap.text_size;

    const bool ret_in_image = ret_addr >= image_lo && ret_addr < image_hi;
    const bool ret_in_text  = ret_addr >= text_lo  && ret_addr < text_hi;

    if (ret_in_image && !ret_in_text) {
        // in the module but outside .text means themida runtime, VM called into .text
        out.kind = OepFaultKind::VmSubcall;
        out.return_va = ret_addr;
        log::debug("oep: VM sub-call fault at 0x{:x}, ret 0x{:x} in themida", fault_va, ret_addr);
        return out;
    }

    // return outside the module (kernel32 etc.) or inside .text itself; real OEP transfer
    out.kind = OepFaultKind::RealOep;
    return out;
}

}  // namespace simply
